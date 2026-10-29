//! Waking the Syphon server. When a device on the VPN opens a connection to the server (a new TCP connection, counted
//! by the box's firewall) and the server doesn't answer, the box sends it a wake-on-LAN packet. A device that only
//! keeps its tunnel alive (keep-alives, handshakes) never wakes it, so a server nobody uses still gets to sleep.
//!
//! The packet goes straight to the server's address (UDP port 9), not as a broadcast: broadcasts don't cross from
//! one VLAN to another. The router in between needs a permanent entry for the sleeping server's network card
//! ("static ARP"), so it can still deliver the packet while the server can't answer for its address.

use anyhow::{bail, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// "AA-BB-CC-DD-EE-FF" or "aa:bb:cc:dd:ee:ff" → "aa:bb:cc:dd:ee:ff"
pub fn parse_mac(s: &str) -> Result<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit())) {
        bail!("\"{}\" is not a network card address. It looks like aa:bb:cc:dd:ee:ff", s.trim());
    }
    let mac = parts.join(":").to_lowercase();
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
        bail!("{mac} is not a real network card address");
    }
    Ok(mac)
}

/// The wake-on-LAN "magic packet": six 0xFF bytes, then the card's address sixteen times.
pub fn magic_packet(mac: &str) -> Result<Vec<u8>> {
    let mac = parse_mac(mac)?;
    let bytes: Vec<u8> = mac.split(':').map(|p| u8::from_str_radix(p, 16).expect("checked")).collect();
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&bytes);
    }
    Ok(p)
}

/// Send the wake packet to the server (a few times: it's a single unanswered UDP packet).
pub fn send(node: Ipv4Addr, mac: &str) -> Result<()> {
    let p = magic_packet(mac)?;
    let s = UdpSocket::bind("0.0.0.0:0")?;
    for i in 0..3 {
        for port in [9u16, 7] {
            let _ = s.send_to(&p, SocketAddrV4::new(node, port));
        }
        if i < 2 {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    Ok(())
}

/// Is the server answering on its web port?
pub fn awake(node: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(node, port)), Duration::from_millis(600)).is_ok()
}

/// Watch for devices opening connections to the server, and wake it when it doesn't answer. Runs until stopped.
pub fn watch(p: crate::state::Paths) {
    let mut last_count: Option<u64> = None;
    let mut last_sent: Option<Instant> = None;
    loop {
        std::thread::sleep(Duration::from_millis(700));
        let Some(n) = crate::sys::counter("to_node") else { continue };
        let grew = last_count.map(|c| n > c).unwrap_or(false);
        last_count = Some(n);
        if !grew || last_sent.map(|t| t.elapsed() < Duration::from_secs(8)).unwrap_or(false) {
            continue;
        }
        let Ok(c) = crate::state::load_config(&p) else { continue };
        let Some(mac) = c.node_mac.clone() else { continue };
        if awake(c.node_ip, c.node_port) {
            continue;
        }
        match send(c.node_ip, &mac) {
            Ok(()) => {
                last_sent = Some(Instant::now());
                eprintln!("syphon-vpn: a device wants Syphon and it isn't answering: sent it a wake packet ({mac} at {})", c.node_ip);
                let _ = std::fs::write(p.dir.join("last-wake"), format!("{}\n", crate::sys::unix_now()));
            }
            Err(e) => eprintln!("syphon-vpn: could not send the wake packet: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_read_however_they_are_written() {
        assert_eq!(parse_mac("AA-BB-CC-dd-ee-0f").unwrap(), "aa:bb:cc:dd:ee:0f");
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err() && parse_mac("gg:bb:cc:dd:ee:ff").is_err() && parse_mac("00:00:00:00:00:00").is_err());
    }

    #[test]
    fn the_magic_packet_is_six_ffs_then_the_address_sixteen_times() {
        let p = magic_packet("01:02:03:04:05:06").unwrap();
        assert_eq!(p.len(), 6 + 16 * 6);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert!(p[6..].chunks(6).all(|c| c == [1, 2, 3, 4, 5, 6]));
    }
}
