//! syphon-vpn: the Syphon VPN box. A small always-on device at home runs WireGuard; phones, laptops and the Syphon app
//! connect to it from anywhere and reach the Syphon server's web app (and nothing else on the home network).
//!
//! Layout on the box (all root-only):
//! * `/etc/syphon-vpn/box.json`     the box's settings and its WireGuard key
//! * `/etc/syphon-vpn/devices.json` the devices allowed in (their public keys only; private keys are shown once)
//! * `/etc/wireguard/syphon0.conf`  written from the two files above
//! * `/etc/syphon-vpn/firewall.nft` what VPN devices may reach: the Syphon server's web port, nothing else

pub mod discover;
pub mod enroll;
pub mod keys;
pub mod manage;
pub mod render;
pub mod state;
pub mod sys;
pub mod wake;

use anyhow::{bail, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const IFACE: &str = "syphon0";
/// One change to the devices at a time (the welcome desk and the management link run side by side).
pub static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// The welcome desk inside the VPN (on the box's VPN address), where the app swaps its one-time key for its own.
pub const WELCOME_PORT: u16 = 51821;

/// What the Syphon app needs to connect through the box: `SYPHON-VPN-1:` then base64url of this. Only the Syphon app can
/// use it: the key in it is a one-time welcome key that reaches nothing but the box's welcome desk, where the app hands
/// over a key it made itself (and never shows anyone). After that the code is spent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AppCode {
    pub v: u32,
    /// the Syphon server's name, for the app to show
    pub name: String,
    /// where the box is reached from the internet: "home.example.net:51820"
    pub endpoint: String,
    pub server_public: String,
    pub psk: String,
    /// the one-time welcome key (replaced by the app's own key on first contact)
    pub private: String,
    /// the one-time welcome token
    pub token: String,
    /// the box's welcome desk inside the VPN, "10.77.0.1:51821" (the app's tunnel includes it)
    pub welcome: String,
    /// this device's address inside the VPN, "10.77.0.5/32"
    pub address: String,
    /// the Syphon server's web app as seen through the VPN, "http://192.168.1.20:8096"
    pub node: String,
}

pub const CODE_PREFIX: &str = "SYPHON-VPN-1:";

pub fn encode_code(c: &AppCode) -> String {
    format!("{CODE_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(c).expect("serialises")))
}

pub fn decode_code(s: &str) -> Result<AppCode> {
    let body = s.trim().strip_prefix(CODE_PREFIX).ok_or_else(|| anyhow::anyhow!("This is not a Syphon VPN code (it starts with {CODE_PREFIX})"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim()).map_err(|_| anyhow::anyhow!("The code is damaged. Copy it again, all of it."))?;
    let c: AppCode = serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("The code is damaged. Copy it again, all of it."))?;
    if c.v != 1 {
        bail!("This code is from a newer Syphon VPN box. Update the app.");
    }
    if c.token.len() != 48 || !c.token.chars().all(|x| x.is_ascii_hexdigit()) {
        bail!("The code is damaged. Copy it again, all of it.");
    }
    for k in [&c.server_public, &c.psk, &c.private] {
        if keys::decode(k).is_err() {
            bail!("The code is damaged. Copy it again, all of it.");
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_code_round_trips_and_damage_is_refused() {
        let (p, _) = keys::pair();
        let (s, _) = keys::pair();
        let c = AppCode { v: 1, name: "Living Room".into(), endpoint: "home.example.net:51820".into(), server_public: keys::public_of(&s).unwrap(), psk: keys::psk(), private: p, token: "ab".repeat(24), welcome: "10.77.0.1:51821".into(), address: "10.77.0.2/32".into(), node: "http://192.168.1.20:8096".into() };
        let code = encode_code(&c);
        assert_eq!(decode_code(&format!(" {code}\n")).unwrap(), c);
        assert!(decode_code("hello").is_err());
        assert!(decode_code(&code[..code.len() - 8]).is_err());
        let mut newer = c.clone();
        newer.v = 2;
        assert!(decode_code(&encode_code(&newer)).unwrap_err().to_string().contains("newer"));
    }
}
