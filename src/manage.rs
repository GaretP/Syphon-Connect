//! The management link: Syphon (the owner's settings, at home) sees, adds and removes this box's devices over the home
//! network, so nobody has to log in to the box for that.
//!
//! * `sudo syphon-vpn link` prints a link code (`SYPHON-VPNBOX-1:` + base64url of `{"v":1,"name":…,"box":"ip:port",
//!   "key":…}`) to paste into Syphon once. The key is a fresh 32-byte secret kept in `/etc/syphon-vpn/manage.key`.
//! * Every request and every answer is sealed with that key (XChaCha20-Poly1305), carries the time and a fresh nonce,
//!   and an answer is bound to its request: nothing can be read, changed or replayed on the network.
//! * Only the Syphon server's own address may talk to it (checked here and in the box's firewall).

use crate::state::{self, BoxConfig, Device, Paths};
use crate::AppCode;
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, TcpListener};

pub const PORT: u16 = 51822;
pub const LINK_PREFIX: &str = "SYPHON-VPNBOX-1:";
const AAD_REQ: &[u8] = b"syphon-vpn-manage request v1";
const AAD_RESP: &str = "syphon-vpn-manage response v1|";
/// how far a request's clock may be from the box's
const MAX_SKEW: i64 = 120;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn key_path(p: &Paths) -> std::path::PathBuf {
    p.dir.join("manage.key")
}

/// The link key: read it, or make one (also when `fresh`, which cuts off any Syphon linked before).
pub fn key(p: &Paths, fresh: bool) -> Result<[u8; 32]> {
    if !fresh {
        if let Ok(s) = std::fs::read_to_string(key_path(p)) {
            if let Ok(v) = b64().decode(s.trim()) {
                if let Ok(k) = <[u8; 32]>::try_from(v.as_slice()) {
                    return Ok(k);
                }
            }
        }
    }
    let mut k = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
    state::write_private(&key_path(p), format!("{}\n", b64().encode(k)).as_bytes())?;
    Ok(k)
}

/// The key only if linking was set up (`syphon-vpn link`).
fn existing_key(p: &Paths) -> Option<[u8; 32]> {
    let s = std::fs::read_to_string(key_path(p)).ok()?;
    b64().decode(s.trim()).ok()?.try_into().ok()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LinkCode {
    pub v: u32,
    pub name: String,
    /// where Syphon reaches the box on the home network, "192.168.1.30:51822"
    #[serde(rename = "box")]
    pub addr: String,
    pub key: String,
}

pub fn link_code(c: &BoxConfig, box_lan_ip: &str, k: &[u8; 32]) -> String {
    let l = LinkCode { v: 1, name: c.name.clone(), addr: format!("{box_lan_ip}:{PORT}"), key: b64().encode(k) };
    format!("{LINK_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&l).expect("serialises")))
}

pub fn decode_link(s: &str) -> Result<LinkCode> {
    let damaged = || anyhow!("The link code is damaged. Copy it again, all of it.");
    let body = s.trim().strip_prefix(LINK_PREFIX).ok_or_else(|| anyhow!("That is not a link code from a VPN box. It starts with {LINK_PREFIX}"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim()).map_err(|_| damaged())?;
    let l: LinkCode = serde_json::from_slice(&raw).map_err(|_| damaged())?;
    if l.v != 1 {
        bail!("This link code is from a newer VPN box. Update Syphon.");
    }
    l.addr.parse::<std::net::SocketAddr>().map_err(|_| damaged())?;
    let k = b64().decode(&l.key).map_err(|_| damaged())?;
    if k.len() != 32 {
        return Err(damaged());
    }
    Ok(l)
}

/// Seal: 24-byte random nonce, then the ciphertext.
pub fn seal(k: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut n = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    let c = XChaCha20Poly1305::new(k.into()).encrypt(XNonce::from_slice(&n), Payload { msg: plain, aad }).expect("seals");
    [n.to_vec(), c].concat()
}

pub fn open(k: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 24 + 16 {
        bail!("too short");
    }
    XChaCha20Poly1305::new(k.into()).decrypt(XNonce::from_slice(&data[..24]), Payload { msg: &data[24..], aad }).map_err(|_| anyhow!("not sealed with the link key"))
}

/// The answer's associated data names the request's nonce, so an answer can't be swapped for another.
pub fn response_aad(req_nonce: &str) -> Vec<u8> {
    format!("{AAD_RESP}{req_nonce}").into_bytes()
}

/// Seal a request (what Syphon sends). Returns the body and the nonce its answer is bound to.
pub fn seal_request(k: &[u8; 32], cmd: &str, name: Option<&str>) -> (String, String) {
    let mut n = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    let nonce: String = n.iter().map(|b| format!("{b:02x}")).collect();
    let plain = json!({ "ts": now(), "nonce": nonce, "cmd": cmd, "name": name }).to_string();
    (b64().encode(seal(k, AAD_REQ, plain.as_bytes())), nonce)
}

/// Open the answer to a request.
pub fn open_response(k: &[u8; 32], nonce: &str, body: &str) -> Result<Value> {
    let raw = b64().decode(body.trim()).map_err(|_| anyhow!("the VPN box's answer is damaged"))?;
    let plain = open(k, &response_aad(nonce), &raw).map_err(|_| anyhow!("the VPN box's answer is not sealed with the link key (linked to a different box?)"))?;
    Ok(serde_json::from_slice(&plain)?)
}

// ---- what can be done, shared with the command line ----

/// Let a new device in: a waiting entry and the one-time code for its Syphon app.
pub fn add_device(p: &Paths, name: &str, at: i64) -> Result<(Vec<Device>, Device, String)> {
    let c = state::load_config(p)?;
    let mut devices = state::load_devices(p)?;
    let name = state::clean_name(name)?;
    if devices.iter().any(|d| d.name.eq_ignore_ascii_case(&name)) {
        bail!("a device called \"{name}\" is already in. Remove it first, or pick another name.");
    }
    let ip = state::next_ip(&c, &devices)?;
    let (private, public) = crate::keys::pair();
    let token = state::new_token();
    let d = Device { name: name.clone(), ip, public_key: public, psk: crate::keys::psk(), created: at, enrolled: false, token_hash: Some(state::token_hash(&token)), expires: at + state::WELCOME_DAYS * 86400 };
    devices.push(d.clone());
    state::save_devices(p, &devices)?;
    let code = crate::encode_code(&AppCode { v: 1, name: c.name.clone(), endpoint: c.endpoint(), server_public: c.public_key.clone(), psk: d.psk.clone(), private, token, welcome: format!("{}:{}", c.box_ip(), crate::WELCOME_PORT), address: format!("{}/32", d.ip), node: c.node_url() });
    Ok((devices, d, code))
}

pub fn remove_device(p: &Paths, name: &str) -> Result<Vec<Device>> {
    let mut devices = state::load_devices(p)?;
    let before = devices.len();
    devices.retain(|d| !d.name.eq_ignore_ascii_case(name.trim()));
    if devices.len() == before {
        bail!("no device called \"{}\"", name.trim());
    }
    state::save_devices(p, &devices)?;
    Ok(devices)
}

/// Each device: name, VPN address, and where it stands ("connected" in the last 3 minutes, "ok", "waiting", "expired").
pub fn device_list(devices: &[Device], handshakes: &[(String, i64)], at: i64) -> Vec<Value> {
    devices
        .iter()
        .map(|d| {
            let last = handshakes.iter().find(|(k, _)| *k == d.public_key).map(|(_, t)| *t).unwrap_or(0);
            let state = if !d.enrolled {
                if d.expires < at { "expired" } else { "waiting" }
            } else if last > 0 && at - last < 180 {
                "connected"
            } else {
                "ok"
            };
            json!({ "name": d.name, "ip": d.ip.to_string(), "state": state, "last": last, "created": d.created, "expires": if d.enrolled { 0 } else { d.expires } })
        })
        .collect()
}

/// Carry out one opened request.
pub fn handle(p: &Paths, live: bool, req: &Value) -> Result<Value> {
    let at = now();
    let commit = |c: &BoxConfig, d: &[Device]| if live { crate::sys::apply(p, c, d) } else { crate::sys::write_files(p, c, d) };
    let name = req["name"].as_str().unwrap_or("");
    match req["cmd"].as_str().unwrap_or("") {
        "status" => {
            let c = state::load_config(p)?;
            let devices = state::load_devices(p)?;
            Ok(json!({ "ok": true, "name": c.name, "endpoint": c.endpoint(), "node": c.node_url(), "devices": devices.len(), "packets_in": crate::sys::packets_in(), "wakes": c.node_mac.is_some(), "version": env!("CARGO_PKG_VERSION") }))
        }
        "list" => {
            let devices = state::load_devices(p)?;
            Ok(json!({ "ok": true, "devices": device_list(&devices, &crate::sys::handshakes(), at), "packets_in": crate::sys::packets_in() }))
        }
        "add" => {
            let (devices, d, code) = add_device(p, name, at)?;
            commit(&state::load_config(p)?, &devices)?;
            Ok(json!({ "ok": true, "name": d.name, "code": code, "expires": d.expires }))
        }
        "set_wake" => {
            let mac = crate::wake::parse_mac(name)?;
            let mut c = state::load_config(p)?;
            if c.node_mac.as_deref() != Some(mac.as_str()) {
                c.node_mac = Some(mac);
                state::save_config(p, &c)?;
            }
            Ok(json!({ "ok": true }))
        }
        "remove" => {
            let devices = remove_device(p, name)?;
            commit(&state::load_config(p)?, &devices)?;
            Ok(json!({ "ok": true }))
        }
        _ => bail!("unknown request"),
    }
}

/// Listen for Syphon on the home network until stopped.
pub fn serve(p: Paths, listen: String, live: bool) {
    let l = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("syphon-vpn: could not open the management link on {listen}: {e}");
            return;
        }
    };
    eprintln!("syphon-vpn: management link on {listen}");
    let mut seen: Vec<(String, i64)> = vec![];
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let Ok(peer) = s.peer_addr() else { continue };
        // only the Syphon server itself
        let allowed: Option<IpAddr> = state::load_config(&p).ok().map(|c| IpAddr::V4(c.node_ip));
        let plain_peer = match peer.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            o => o,
        };
        if allowed != Some(plain_peer) {
            continue; // dropped without an answer
        }
        let Ok((line, body)) = crate::enroll::read_request(&mut s) else { continue };
        let Some(k) = existing_key(&p) else {
            crate::enroll::respond_text(&mut s, 403, "This VPN box is not linked to Syphon yet. On the box run: sudo syphon-vpn link");
            continue;
        };
        if !line.starts_with("POST /manage ") {
            crate::enroll::respond_text(&mut s, 404, "not here");
            continue;
        }
        let opened = b64().decode(String::from_utf8_lossy(&body).trim()).ok().and_then(|raw| open(&k, AAD_REQ, &raw).ok()).and_then(|pl| serde_json::from_slice::<Value>(&pl).ok());
        let Some(req) = opened else {
            crate::enroll::respond_text(&mut s, 403, "Not sealed with this box's link key. Link Syphon again: on the box run sudo syphon-vpn link");
            continue;
        };
        let at = now();
        let nonce = req["nonce"].as_str().unwrap_or("").to_string();
        seen.retain(|(_, t)| at - t < 2 * MAX_SKEW);
        let ts = req["ts"].as_i64().unwrap_or(0);
        let answer = if (at - ts).abs() > MAX_SKEW {
            json!({ "ok": false, "error": "the clocks of Syphon and the VPN box differ by more than two minutes; check the time on both" })
        } else if nonce.len() < 16 || seen.iter().any(|(n, _)| *n == nonce) {
            json!({ "ok": false, "error": "this request was already handled" })
        } else {
            seen.push((nonce.clone(), at));
            let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
            handle(&p, live, &req).unwrap_or_else(|e| json!({ "ok": false, "error": e.to_string() }))
        };
        let sealed = b64().encode(seal(&k, &response_aad(&nonce), answer.to_string().as_bytes()));
        crate::enroll::respond_text(&mut s, 200, &sealed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_code_round_trips_and_damage_is_refused() {
        let c = crate::state::tests::sample();
        let k = [7u8; 32];
        let code = link_code(&c, "192.168.1.30", &k);
        let l = decode_link(&format!(" {code}\n")).unwrap();
        assert_eq!((l.addr.as_str(), b64().decode(&l.key).unwrap()), ("192.168.1.30:51822", k.to_vec()));
        assert!(decode_link("SYPHON-VPN-1:abc").is_err());
        assert!(decode_link(&code[..code.len() - 6]).is_err());
    }

    #[test]
    fn sealed_messages_need_the_key_and_answers_are_bound_to_their_request() {
        let k = [9u8; 32];
        let (body, nonce) = seal_request(&k, "list", None);
        let raw = b64().decode(&body).unwrap();
        let req: Value = serde_json::from_slice(&open(&k, AAD_REQ, &raw).unwrap()).unwrap();
        assert_eq!((req["cmd"].as_str(), req["nonce"].as_str()), (Some("list"), Some(nonce.as_str())));
        assert!(open(&[1u8; 32], AAD_REQ, &raw).is_err(), "another key can't open it");
        let mut bent = raw.clone();
        *bent.last_mut().unwrap() ^= 1;
        assert!(open(&k, AAD_REQ, &bent).is_err(), "a changed message is refused");
        let ans = b64().encode(seal(&k, &response_aad(&nonce), br#"{"ok":true}"#));
        assert_eq!(open_response(&k, &nonce, &ans).unwrap()["ok"], true);
        assert!(open_response(&k, "another-request-nonce", &ans).is_err(), "an answer to another request is refused");
    }

    #[test]
    fn devices_are_listed_with_where_they_stand() {
        let mk = |n: &str, enrolled: bool, expires: i64| Device { name: n.into(), ip: "10.77.0.2".parse().unwrap(), public_key: format!("{n}="), psk: String::new(), created: 0, enrolled, token_hash: None, expires };
        let d = vec![mk("a", true, 0), mk("b", true, 0), mk("c", false, 2000), mk("d", false, 500)];
        let l = device_list(&d, &[("a=".into(), 900)], 1000);
        let states: Vec<&str> = l.iter().map(|x| x["state"].as_str().unwrap()).collect();
        assert_eq!(states, ["connected", "ok", "waiting", "expired"]);
    }
}
