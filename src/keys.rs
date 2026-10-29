//! WireGuard keys: Curve25519, written as standard base64 (the format `wg` uses).

use anyhow::{bail, Result};
use base64::Engine;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn decode(s: &str) -> Result<[u8; 32]> {
    let v = b64().decode(s.trim())?;
    if v.len() != 32 {
        bail!("a WireGuard key is 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// A new key pair: (private, public).
pub fn pair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (b64().encode(secret.to_bytes()), b64().encode(public.as_bytes()))
}

pub fn public_of(private: &str) -> Result<String> {
    let secret = StaticSecret::from(decode(private)?);
    Ok(b64().encode(PublicKey::from(&secret).as_bytes()))
}

/// A preshared key: an extra symmetric layer on top of the key exchange.
pub fn psk() -> String {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    b64().encode(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_look_like_wireguard_keys_and_match() {
        let (private, public) = pair();
        assert_eq!(private.len(), 44);
        assert_eq!(public_of(&private).unwrap(), public);
        // the documented test vector: RFC 7748 section 6.1, Alice
        let alice = b64().encode(hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        assert_eq!(decode(&public_of(&alice).unwrap()).unwrap(), hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert!(decode("short").is_err());
    }

    fn hex32(h: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
}
