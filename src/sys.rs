//! Putting the settings into effect on the box: WireGuard (wg-quick), the firewall (nft) and packet forwarding.

use crate::state::{self, BoxConfig, Device, Paths};
use anyhow::{bail, Context, Result};
use std::process::Command;

pub const SYSCTL_FILE: &str = "/etc/sysctl.d/60-syphon-vpn.conf";

pub fn is_root() -> bool {
    Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("could not run {cmd} (is it installed?)"))?;
    if !out.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Write the WireGuard and firewall files from the settings (nothing is restarted).
pub fn write_files(p: &Paths, c: &BoxConfig, devices: &[Device]) -> Result<()> {
    state::write_private(&p.wg_conf, crate::render::server_conf(c, devices).as_bytes())?;
    state::write_private(&p.firewall(), crate::render::firewall(c, devices).as_bytes())?;
    Ok(())
}

/// A device's app just put its own key in place: change the running WireGuard and firewall without touching anyone else.
pub fn swap_live(p: &Paths, old: &str, d: &Device) -> Result<()> {
    let psk = p.dir.join(format!("psk-{}", d.ip));
    state::write_private(&psk, format!("{}\n", d.psk).as_bytes())?;
    let _ = run("wg", &["set", crate::IFACE, "peer", old, "remove"]);
    let r = run("wg", &["set", crate::IFACE, "peer", &d.public_key, "preshared-key", &psk.to_string_lossy(), "allowed-ips", &format!("{}/32", d.ip)]);
    let _ = std::fs::remove_file(&psk);
    r?;
    run("nft", &["add", "element", "inet", "syphon_vpn", "enrolled", &format!("{{ {} }}", d.ip)])?;
    Ok(())
}

/// Write every file from the settings and make the running system match.
pub fn apply(p: &Paths, c: &BoxConfig, devices: &[Device]) -> Result<()> {
    write_files(p, c, devices)?;
    std::fs::write(SYSCTL_FILE, crate::render::SYSCTL)?;
    run("sysctl", &["-q", "-p", SYSCTL_FILE])?;
    run("nft", &["-f", &p.firewall().to_string_lossy()])?;
    let _ = run("systemctl", &["enable", "--quiet", "syphon-vpn-firewall.service"]);
    let unit = format!("wg-quick@{}", crate::IFACE);
    let active = Command::new("systemctl").args(["is-active", "--quiet", &unit]).status().map(|s| s.success()).unwrap_or(false);
    if active {
        // change the devices without dropping the ones that are connected
        let stripped = run("wg-quick", &["strip", crate::IFACE])?;
        let tmp = p.dir.join("live.conf");
        state::write_private(&tmp, stripped.as_bytes())?;
        let r = run("wg", &["syncconf", crate::IFACE, &tmp.to_string_lossy()]);
        let _ = std::fs::remove_file(&tmp);
        r?;
    } else {
        run("systemctl", &["enable", "--now", "--quiet", &unit])?;
    }
    // the welcome desk, where new devices' apps put their own key in place
    let _ = run("systemctl", &["enable", "--now", "--quiet", "syphon-vpn-welcome.service"]);
    Ok(())
}

/// How many packets reached the box's WireGuard port since its firewall was last loaded (None: unknown). Zero while
/// devices try to connect means nothing reaches the box: the router's port forward is the place to look.
pub fn packets_in() -> Option<u64> {
    counter("wg_in")
}

/// Packets counted so far by one of the box's firewall counters.
pub fn counter(name: &str) -> Option<u64> {
    let out = run("nft", &["list", "counter", "inet", "syphon_vpn", name]).ok()?;
    parse_counter(&out)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn parse_counter(out: &str) -> Option<u64> {
    let mut it = out.split_whitespace();
    while let Some(w) = it.next() {
        if w == "packets" {
            return it.next()?.parse().ok();
        }
    }
    None
}

/// When each device last connected (seconds since 1970, 0 = never), by public key.
pub fn handshakes() -> Vec<(String, i64)> {
    let Ok(out) = run("wg", &["show", crate::IFACE, "dump"]) else { return vec![] };
    parse_dump(&out)
}

pub fn parse_dump(out: &str) -> Vec<(String, i64)> {
    // first line is the interface; then: public-key, preshared-key, endpoint, allowed-ips, latest-handshake, rx, tx, keepalive
    out.lines().skip(1).filter_map(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        (f.len() >= 5).then(|| (f[0].to_string(), f[4].parse().unwrap_or(0)))
    }).collect()
}

/// This box's address on the home network (the one its default route uses), for the instructions.
pub fn lan_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?; // nothing is sent; this only asks which address leads out
    Some(s.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_connection_of_each_device_is_read() {
        let dump = "PRIV\tPUB\t51820\toff\nDEV1=\tPSK\t198.51.100.4:4444\t10.77.0.2/32\t1792800000\t100\t200\t25\nDEV2=\tPSK\t(none)\t10.77.0.3/32\t0\t0\t0\t25\n";
        assert_eq!(parse_dump(dump), vec![("DEV1=".into(), 1792800000), ("DEV2=".into(), 0)]);
    }

    #[test]
    fn the_arrival_counter_is_read() {
        let out = "table inet syphon_vpn {\n\tcounter wg_in {\n\t\tpackets 42 bytes 6720\n\t}\n}\n";
        assert_eq!(parse_counter(out), Some(42));
        assert_eq!(parse_counter("nothing"), None);
    }
}
