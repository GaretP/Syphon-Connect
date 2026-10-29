//! The box's settings and its list of devices.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BoxConfig {
    /// the Syphon server's name (from the server itself)
    pub name: String,
    /// how the box is reached from the internet: a dynamic DNS name (or a fixed address) and the forwarded UDP port
    pub endpoint_host: String,
    pub port: u16,
    /// the Syphon server on the home network
    pub node_ip: Ipv4Addr,
    pub node_port: u16,
    /// the VPN's own small network: the box is .1, devices get .2 and up
    pub subnet: Ipv4Addr,
    pub private_key: String,
    pub public_key: String,
    /// the Syphon server's network card, for waking it (given by Syphon over the link, or set by hand)
    #[serde(default)]
    pub node_mac: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    pub name: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub psk: String,
    pub created: i64,
    /// true once the Syphon app on the device has put its own key in place (until then the device can only reach the
    /// box's welcome desk, not the Syphon server)
    #[serde(default)]
    pub enrolled: bool,
    /// the one-time welcome token (hashed), until the app has used it
    #[serde(default)]
    pub token_hash: Option<String>,
    /// when an unused welcome code stops working
    #[serde(default)]
    pub expires: i64,
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
    pub wg_conf: PathBuf,
}

impl Paths {
    pub fn system() -> Paths {
        Paths { dir: PathBuf::from("/etc/syphon-vpn"), wg_conf: PathBuf::from(format!("/etc/wireguard/{}.conf", crate::IFACE)) }
    }
    pub fn under(root: &Path) -> Paths {
        Paths { dir: root.join("syphon-vpn"), wg_conf: root.join(format!("{}.conf", crate::IFACE)) }
    }
    pub fn config(&self) -> PathBuf {
        self.dir.join("box.json")
    }
    pub fn devices(&self) -> PathBuf {
        self.dir.join("devices.json")
    }
    pub fn firewall(&self) -> PathBuf {
        self.dir.join("firewall.nft")
    }
}

/// Write a file only its owner can read, atomically.
pub fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, p)?;
    Ok(())
}

pub fn load_config(p: &Paths) -> Result<BoxConfig> {
    let raw = std::fs::read(p.config()).context("This box is not set up yet. Run: sudo syphon-vpn init")?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn save_config(p: &Paths, c: &BoxConfig) -> Result<()> {
    write_private(&p.config(), &serde_json::to_vec_pretty(c)?)
}

pub fn load_devices(p: &Paths) -> Result<Vec<Device>> {
    match std::fs::read(p.devices()) {
        Ok(raw) => Ok(serde_json::from_slice(&raw)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}

pub fn save_devices(p: &Paths, d: &[Device]) -> Result<()> {
    write_private(&p.devices(), &serde_json::to_vec_pretty(d)?)
}

/// How a welcome token is kept: hashed, so the file alone does not let anyone in.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(format!("syphon-vpn-welcome|{}", token.trim()).as_bytes()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A fresh one-time token.
pub fn new_token() -> String {
    let mut b = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex(&b)
}

/// How long a welcome code may wait for the app.
pub const WELCOME_DAYS: i64 = 7;

impl BoxConfig {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.endpoint_host, self.port)
    }
    pub fn box_ip(&self) -> Ipv4Addr {
        let o = self.subnet.octets();
        Ipv4Addr::new(o[0], o[1], o[2], 1)
    }
    pub fn node_url(&self) -> String {
        format!("http://{}:{}", self.node_ip, self.node_port)
    }
}

/// The next free address for a device (.2 to .254 of the VPN's network).
pub fn next_ip(c: &BoxConfig, devices: &[Device]) -> Result<Ipv4Addr> {
    let o = c.subnet.octets();
    (2..=254u8).map(|n| Ipv4Addr::new(o[0], o[1], o[2], n)).find(|ip| !devices.iter().any(|d| d.ip == *ip)).ok_or_else(|| anyhow!("The VPN is full (253 devices). Remove some first."))
}

/// Device names become comments in the WireGuard file: keep them to plain words.
pub fn clean_name(s: &str) -> Result<String> {
    let n: String = s.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).filter(|c| c.is_alphanumeric() || " -_.'".contains(*c)).collect();
    let n = n.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(40).collect::<String>();
    if n.is_empty() {
        bail!("Give the device a name, like \"Mia's phone\".");
    }
    Ok(n)
}

/// "home.example.net", "home.example.net:51820" or "203.0.113.7:51820".
pub fn parse_endpoint(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse::<u16>().map_err(|_| anyhow!("\"{p}\" is not a port number"))?),
        _ => (s.to_string(), default_port),
    };
    if host.is_empty() || host.contains(' ') || host.contains('/') {
        bail!("Give the address the box is reached at from the internet, like home.example.net (a dynamic DNS name) or your public IP address.");
    }
    Ok((host, port))
}

/// "192.168.1.20" or "192.168.1.20:8096".
pub fn parse_node(s: &str) -> Result<(Ipv4Addr, u16)> {
    let s = s.trim().trim_start_matches("http://").trim_end_matches('/');
    let (ip, port) = match s.split_once(':') {
        Some((i, p)) => (i, p.parse::<u16>().map_err(|_| anyhow!("\"{p}\" is not a port number"))?),
        None => (s, 8096),
    };
    let ip: Ipv4Addr = ip.parse().map_err(|_| anyhow!("Give the Syphon server's home-network address, like 192.168.1.20"))?;
    if !ip.is_private() {
        bail!("{ip} is not a home-network address. Give the Syphon server's address on your network, like 192.168.1.20");
    }
    Ok((ip, port))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample() -> BoxConfig {
        BoxConfig { name: "Living Room".into(), endpoint_host: "home.example.net".into(), port: 51820, node_ip: "192.168.1.20".parse().unwrap(), node_port: 8096, subnet: "10.77.0.0".parse().unwrap(), private_key: "x".into(), public_key: "y".into(), node_mac: None }
    }

    #[test]
    fn addresses_are_handed_out_in_order_and_reused_after_removal() {
        let c = sample();
        let mut d: Vec<Device> = vec![];
        for i in 0..3 {
            let ip = next_ip(&c, &d).unwrap();
            d.push(Device { name: format!("d{i}"), ip, public_key: String::new(), psk: String::new(), created: 0, enrolled: true, token_hash: None, expires: 0 });
        }
        assert_eq!(d.iter().map(|x| x.ip.to_string()).collect::<Vec<_>>(), vec!["10.77.0.2", "10.77.0.3", "10.77.0.4"]);
        d.remove(1);
        assert_eq!(next_ip(&c, &d).unwrap().to_string(), "10.77.0.3");
    }

    #[test]
    fn inputs_are_understood_however_they_are_typed() {
        assert_eq!(parse_endpoint("home.example.net", 51820).unwrap(), ("home.example.net".into(), 51820));
        assert_eq!(parse_endpoint("203.0.113.7:4000", 51820).unwrap(), ("203.0.113.7".into(), 4000));
        assert!(parse_endpoint("", 51820).is_err());
        assert_eq!(parse_node("192.168.1.20").unwrap(), ("192.168.1.20".parse().unwrap(), 8096));
        assert_eq!(parse_node("http://192.168.1.20:9000/").unwrap(), ("192.168.1.20".parse().unwrap(), 9000));
        assert!(parse_node("8.8.8.8").is_err());
        assert_eq!(clean_name("  Mia's phone\n[evil]").unwrap(), "Mia's phone evil");
        assert!(clean_name("[]").is_err());
    }

    #[test]
    fn files_are_private() {
        let d = std::env::temp_dir().join(format!("syphon-vpn-state-{}", std::process::id()));
        let p = Paths::under(&d);
        save_config(&p, &sample()).unwrap();
        assert_eq!(load_config(&p).unwrap(), sample());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(p.config()).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(d);
    }
}
