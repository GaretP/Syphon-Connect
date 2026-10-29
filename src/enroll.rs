//! The welcome desk: a tiny web service on the box's VPN address. A new device arrives with the one-time welcome key and
//! token from its code, hands over the public key its Syphon app made for itself, and from then on connects with that
//! key only. The welcome key and token are spent; the app's private key never leaves the device.

use crate::state::{self, Device, Paths};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Swap a waiting device's welcome key for the app's own. Returns the device as it now is, and the key it replaced.
pub fn enroll(devices: &mut [Device], token: &str, public_key: &str, at: i64) -> Result<(Device, String)> {
    crate::keys::decode(public_key).map_err(|_| anyhow!("that is not a WireGuard public key"))?;
    let h = state::token_hash(token);
    if devices.iter().any(|d| d.public_key == public_key) {
        bail!("that key is already in use");
    }
    let d = devices.iter_mut().find(|d| !d.enrolled && d.token_hash.as_deref() == Some(h.as_str())).ok_or_else(|| anyhow!("this code was already used, has been removed, or is not from this box"))?;
    if d.expires < at {
        bail!("this code has expired; ask for a new one");
    }
    let old = std::mem::replace(&mut d.public_key, public_key.to_string());
    d.enrolled = true;
    d.token_hash = None;
    Ok((d.clone(), old))
}

/// Remove welcome codes nobody used in time. Returns how many.
pub fn prune(devices: &mut Vec<Device>, at: i64) -> usize {
    let before = devices.len();
    devices.retain(|d| d.enrolled || d.expires >= at);
    before - devices.len()
}

/// One request at the desk: `POST /enroll` with `{"token": …, "public_key": …}`.
/// Returns the answer, and the swap to make on the running system once the answer is on its way (the answer travels
/// back through the welcome key, so that key must stay until it has gone).
pub fn handle(p: &Paths, body: &[u8]) -> Result<(Value, String, Device)> {
    let v: Value = serde_json::from_slice(body).map_err(|_| anyhow!("bad request"))?;
    let token = v["token"].as_str().unwrap_or("");
    let public_key = v["public_key"].as_str().unwrap_or("");
    let c = state::load_config(p)?;
    let mut devices = state::load_devices(p)?;
    let (d, old) = enroll(&mut devices, token, public_key, now())?;
    state::save_devices(p, &devices)?;
    crate::sys::write_files(p, &c, &devices)?;
    Ok((json!({ "ok": true, "address": format!("{}/32", d.ip), "node": c.node_url(), "name": c.name }), old, d))
}

pub(crate) fn respond_text(s: &mut TcpStream, code: u16, body: &str) {
    let reason = match code { 200 => "OK", 403 => "Forbidden", 404 => "Not Found", _ => "Error" };
    let _ = write!(s, "HTTP/1.1 {code} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
}

fn respond(s: &mut TcpStream, code: u16, v: &Value) {
    let body = v.to_string();
    let reason = match code { 200 => "OK", 400 => "Bad Request", 404 => "Not Found", 429 => "Too Many Requests", _ => "Error" };
    let _ = write!(s, "HTTP/1.1 {code} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
}

pub(crate) fn read_request(s: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = vec![];
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            bail!("closed");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 8192 {
            bail!("too large");
        }
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_string();
            let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|x| x.trim().parse().unwrap_or(0))).unwrap_or(0);
            if len > 4096 {
                bail!("too large");
            }
            let mut body = buf[i + 4..].to_vec();
            while body.len() < len {
                let n = s.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
            let line = head.lines().next().unwrap_or("").to_string();
            return Ok((line, body));
        }
    }
}

/// Run the desk until stopped. `live` also updates the running WireGuard and firewall (off in tests of the logic only).
pub fn serve(p: &Paths, listen: &str, live: bool) -> Result<()> {
    let l = TcpListener::bind(listen).map_err(|e| anyhow!("could not open the welcome desk on {listen}: {e}"))?;
    eprintln!("syphon-vpn: welcome desk on {listen}");
    let mut failures: Vec<i64> = vec![];
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        // codes nobody used in time are removed now and then
        if let Ok(mut devices) = state::load_devices(p) {
            if prune(&mut devices, now()) > 0 {
                let _ = state::save_devices(p, &devices);
                if let Ok(c) = state::load_config(p) {
                    let _ = crate::sys::write_files(p, &c, &devices);
                }
            }
        }
        let Ok((line, body)) = read_request(&mut s) else { continue };
        failures.retain(|t| now() - t < 60);
        if failures.len() >= 10 {
            respond(&mut s, 429, &json!({ "error": "too many tries; wait a minute" }));
            continue;
        }
        if !line.starts_with("POST /enroll ") {
            respond(&mut s, 404, &json!({ "error": "not here" }));
            continue;
        }
        let answer = {
            let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
            handle(p, &body)
        };
        match answer {
            Ok((v, old, d)) => {
                respond(&mut s, 200, &v);
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
                if live {
                    // give the answer a moment to reach the app before its welcome key goes away
                    std::thread::sleep(Duration::from_millis(1500));
                    if let Err(e) = crate::sys::swap_live(p, &old, &d) {
                        eprintln!("syphon-vpn: could not switch {} to its own key: {e:#}", d.name);
                    }
                }
            }
            Err(e) => {
                failures.push(now());
                respond(&mut s, 400, &json!({ "error": e.to_string() }));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(token: &str, expires: i64) -> Device {
        Device { name: "Mia's laptop".into(), ip: "10.77.0.2".parse().unwrap(), public_key: crate::keys::pair().1, psk: crate::keys::psk(), created: 0, enrolled: false, token_hash: Some(state::token_hash(token)), expires }
    }

    #[test]
    fn a_code_works_once_and_only_in_time() {
        let mut d = vec![waiting("tok", 1000)];
        let (_, app_pub) = crate::keys::pair();
        assert!(enroll(&mut d, "wrong", &app_pub, 10).is_err());
        assert!(enroll(&mut d, "tok", "not a key", 10).is_err());
        assert!(enroll(&mut d, "tok", &app_pub, 2000).unwrap_err().to_string().contains("expired"));
        let (got, old) = enroll(&mut d, "tok", &app_pub, 10).unwrap();
        assert!(got.enrolled && got.public_key == app_pub && old != app_pub && got.token_hash.is_none());
        let (_, again) = crate::keys::pair();
        assert!(enroll(&mut d, "tok", &again, 11).is_err(), "spent");
    }

    #[test]
    fn unused_codes_are_cleared_after_a_while() {
        let mut enrolled = waiting("a", 0);
        enrolled.enrolled = true;
        let mut d = vec![waiting("b", 50), waiting("c", 500), enrolled];
        assert_eq!(prune(&mut d, 100), 1);
        assert_eq!(d.len(), 2);
    }
}
