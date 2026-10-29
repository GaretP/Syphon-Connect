//! Finding the Syphon server on the home network (the same question the Syphon app asks: UDP 8095).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub name: String,
    pub ip: Ipv4Addr,
    pub port: u16,
}

pub fn find(wait: Duration) -> Vec<Found> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return vec![] };
    let _ = sock.set_broadcast(true);
    for t in [SocketAddr::from((Ipv4Addr::BROADCAST, 8095)), SocketAddr::from((Ipv4Addr::LOCALHOST, 8095))] {
        let _ = sock.send_to(b"SYPHON-DISCOVER 1", t);
    }
    let end = Instant::now() + wait;
    let mut out: Vec<Found> = vec![];
    let mut buf = [0u8; 1024];
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        let _ = sock.set_read_timeout(Some(left.max(Duration::from_millis(1))));
        let Ok((n, from)) = sock.recv_from(&mut buf) else { break };
        if let Some(f) = parse(&buf[..n], from) {
            if !out.contains(&f) {
                out.push(f);
            }
        }
    }
    out
}

pub fn parse(data: &[u8], from: SocketAddr) -> Option<Found> {
    let v: serde_json::Value = serde_json::from_slice(data).ok()?;
    if v["syphon"].as_u64() != Some(1) {
        return None;
    }
    let std::net::IpAddr::V4(ip) = from.ip() else { return None };
    let port = v["port"].as_u64().filter(|p| *p > 0 && *p < 65536)? as u16;
    Some(Found { name: v["name"].as_str().unwrap_or("Syphon").chars().take(80).collect(), ip, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_read() {
        let f = parse(br#"{"syphon":1,"name":"Living Room","port":8096}"#, "192.168.1.20:8095".parse().unwrap()).unwrap();
        assert_eq!(f, Found { name: "Living Room".into(), ip: "192.168.1.20".parse().unwrap(), port: 8096 });
        assert!(parse(b"nope", "192.168.1.20:8095".parse().unwrap()).is_none());
    }
}
