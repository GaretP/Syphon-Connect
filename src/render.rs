//! The files the box runs on, written from its settings: the WireGuard interface, a device's own WireGuard file, and the
//! firewall that keeps VPN devices to the Syphon server's web port.

use crate::state::{BoxConfig, Device};

/// The box's WireGuard interface (read by `wg-quick`).
pub fn server_conf(c: &BoxConfig, devices: &[Device]) -> String {
    let mut s = format!(
        "# Written by syphon-vpn. Change devices with \"syphon-vpn add/remove\", not by hand.\n[Interface]\nAddress = {}/24\nListenPort = {}\nPrivateKey = {}\n",
        c.box_ip(),
        c.port,
        c.private_key
    );
    for d in devices {
        s += &format!("\n# {}\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}/32\n", d.name, d.public_key, d.psk, d.ip);
    }
    s
}

/// The tunnel a device's Syphon app sets up (also used by the tests, as a WireGuard file). Only the Syphon server and
/// the box's welcome desk go through it; everything else the device does stays on its own connection.
pub fn client_conf(c: &BoxConfig, d: &Device, private: &str) -> String {
    format!(
        "# Syphon ({}) through your VPN box. Open {} while this is on.\n[Interface]\nPrivateKey = {}\nAddress = {}/32\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {}\nAllowedIPs = {}/32, {}/32\nPersistentKeepalive = 25\n",
        c.name,
        c.node_url(),
        private,
        d.ip,
        c.public_key,
        d.psk,
        c.endpoint(),
        c.node_ip,
        c.box_ip()
    )
}

/// The firewall (nftables). VPN devices may open the Syphon server's web port and nothing else: not the rest of the
/// home network, not the box itself, not the internet. Their requests reach the server from the box's own address, which
/// is how the server knows they came through the VPN.
pub fn firewall(c: &BoxConfig, devices: &[Device]) -> String {
    let net = format!("{}/24", c.subnet);
    let i = crate::IFACE;
    let enrolled: Vec<String> = devices.iter().filter(|d| d.enrolled).map(|d| d.ip.to_string()).collect();
    let elements = if enrolled.is_empty() { String::new() } else { format!("\n    elements = {{ {} }}", enrolled.join(", ")) };
    format!(
        r#"# Written by syphon-vpn: what devices on the VPN may reach.
table inet syphon_vpn
delete table inet syphon_vpn
table inet syphon_vpn {{
  # devices whose Syphon app has put its own key in place; only these reach the Syphon server
  set enrolled {{
    type ipv4_addr;{elements}
  }}
  # packets that reached the WireGuard port from outside (shown by "syphon-vpn status")
  counter wg_in {{
  }}
  # new connections from devices to the Syphon server (used to wake it)
  counter to_node {{
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
    # a device opening a connection to Syphon (keep-alives don't count): the box wakes a sleeping Syphon server
    iifname "{i}" ip saddr @enrolled ip daddr {node} tcp dport {port} tcp flags & (syn | ack) == syn counter name "to_node"
    iifname "{i}" ip saddr @enrolled ip daddr {node} tcp dport {port} ct state new,established,related accept
    iifname "{i}" drop
    oifname "{i}" ct state established,related accept
    oifname "{i}" drop
  }}
  chain input {{
    type filter hook input priority 0; policy accept;
    udp dport {wgport} counter name "wg_in"
    # the management link: only the Syphon server may talk to it
    tcp dport {manage} ip saddr != {node} drop
    iifname "{i}" ct state established,related accept
    iifname "{i}" icmp type echo-request accept
    # the welcome desk, where the Syphon app swaps the one-time key from its code for a key of its own
    iifname "{i}" ip saddr {net} ip daddr {boxip} tcp dport {welcome} accept
    iifname "{i}" drop
  }}
}}
table ip syphon_vpn_nat
delete table ip syphon_vpn_nat
table ip syphon_vpn_nat {{
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    ip saddr {net} ip daddr {node} tcp dport {port} masquerade
  }}
}}
"#,
        node = c.node_ip,
        port = c.node_port,
        boxip = c.box_ip(),
        welcome = crate::WELCOME_PORT,
        wgport = c.port,
        manage = crate::manage::PORT,
    )
}

/// The box passes packets between the VPN and the home network.
pub const SYSCTL: &str = "# Written by syphon-vpn: pass VPN traffic on to the Syphon server\nnet.ipv4.ip_forward = 1\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (BoxConfig, Device) {
        let c = BoxConfig { name: "Living Room".into(), endpoint_host: "home.example.net".into(), port: 51820, node_ip: "192.168.1.20".parse().unwrap(), node_port: 8096, subnet: "10.77.0.0".parse().unwrap(), private_key: "SERVERPRIV=".into(), public_key: "SERVERPUB=".into(), node_mac: None };
        let d = Device { name: "Mia's phone".into(), ip: "10.77.0.2".parse().unwrap(), public_key: "DEVPUB=".into(), psk: "PSK=".into(), created: 0, enrolled: true, token_hash: None, expires: 0 };
        (c, d)
    }

    #[test]
    fn the_box_and_a_device_agree_on_keys_and_addresses() {
        let (c, d) = sample();
        let s = server_conf(&c, &[d.clone()]);
        assert!(s.contains("Address = 10.77.0.1/24") && s.contains("ListenPort = 51820") && s.contains("PrivateKey = SERVERPRIV="));
        assert!(s.contains("# Mia's phone\n[Peer]\nPublicKey = DEVPUB=\nPresharedKey = PSK=\nAllowedIPs = 10.77.0.2/32"));
        let k = client_conf(&c, &d, "DEVPRIV=");
        assert!(k.contains("PrivateKey = DEVPRIV=") && k.contains("Address = 10.77.0.2/32") && k.contains("PublicKey = SERVERPUB="));
        assert!(k.contains("Endpoint = home.example.net:51820") && k.contains("PresharedKey = PSK="));
        assert!(k.contains("AllowedIPs = 192.168.1.20/32, 10.77.0.1/32"), "only the Syphon server and the welcome desk go through the tunnel");
        assert!(!k.contains("SERVERPRIV"), "the box's own key never leaves it");
    }

    #[test]
    fn vpn_devices_reach_the_web_port_only_once_their_app_has_its_own_key() {
        let (c, d) = sample();
        let mut waiting = d.clone();
        waiting.ip = "10.77.0.3".parse().unwrap();
        waiting.enrolled = false;
        let f = firewall(&c, &[d, waiting]);
        assert!(f.contains(r#"iifname "syphon0" ip saddr @enrolled ip daddr 192.168.1.20 tcp dport 8096 ct state new,established,related accept"#));
        assert!(f.contains("elements = { 10.77.0.2 }"), "only the device that finished its welcome: {f}");
        assert!(f.contains("ip daddr 10.77.0.1 tcp dport 51821 accept"), "the welcome desk");
        assert!(!firewall(&c, &[]).contains("elements"), "an empty set has no elements line");
        let accept = f.find("tcp dport 8096 ct state").unwrap();
        let drop = f.find("iifname \"syphon0\" drop").unwrap();
        assert!(accept < drop, "the one allowed thing comes before the drop");
        assert!(f.contains("masquerade") && f.contains("chain input") && f.contains("delete table inet syphon_vpn"));
        assert!(f.contains(r#"tcp flags & (syn | ack) == syn counter name "to_node""#), "new connections to Syphon are counted, for waking it");
        assert!(f.contains("counter wg_in") && f.contains(r#"udp dport 51820 counter name "wg_in""#), "arrivals on the WireGuard port are counted");
        assert!(f.contains("tcp dport 51822 ip saddr != 192.168.1.20 drop"), "only the Syphon server reaches the management link");
    }
}
