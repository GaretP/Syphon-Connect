// syphon-vpn: the Syphon VPN box. See README.md.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::io::Write;
use syphon_vpn::state::{self, BoxConfig, Device, Paths};
use syphon_vpn::{discover, keys, sys};

#[derive(Parser)]
#[command(name = "syphon-vpn", version, about = "Fast access to your Syphon from anywhere, through a WireGuard VPN box at home")]
struct Cli {
    /// keep the box's files under this folder instead of /etc (for tests)
    #[arg(long, global = true, hide = true)]
    root: Option<std::path::PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this box (once)
    Init {
        /// how the box is reached from the internet: a dynamic DNS name or public IP, optionally with the port
        #[arg(long)]
        endpoint: Option<String>,
        /// the Syphon server's home-network address (found by itself when left out)
        #[arg(long)]
        node: Option<String>,
        /// the UDP port forwarded to this box on your router
        #[arg(long, default_value_t = 51820)]
        port: u16,
        /// the VPN's own small network
        #[arg(long, default_value = "10.77.0.0")]
        subnet: String,
    },
    /// Let a device in: prints a one-time code for its Syphon app (only the Syphon app can use it)
    Add { name: String },
    /// The welcome desk, where a new device's Syphon app puts its own key in place (run by its service)
    #[command(hide = true)]
    Serve {
        /// where to listen (default: the box's VPN address)
        #[arg(long)]
        listen: Option<String>,
        /// where the management link for Syphon listens (default: every home-network address, port 51822)
        #[arg(long)]
        manage: Option<String>,
        /// only update the files, not the running WireGuard and firewall (for tests)
        #[arg(long, hide = true)]
        files_only: bool,
    },
    /// The devices that may connect, and when each last did
    List,
    /// A link code for Syphon's settings, so Syphon can manage this box's devices
    Link {
        /// make a new link key (the old link stops working)
        #[arg(long)]
        new: bool,
    },
    /// Wake the Syphon server now (to try waking it)
    Wake,
    /// Set the Syphon server's network card address for waking it (Syphon gives it by itself once linked; "" clears it)
    WakeMac { mac: String },
    /// Stop a device from connecting
    Remove { name: String },
    /// Change how the box is reached from the internet (devices added before keep the old one: add them again)
    Endpoint { endpoint: String },
    /// Change the Syphon server's address on the home network
    Node { node: String },
    /// Rewrite every file and restart what needs it
    Apply,
    /// What this box is doing
    Status,
}

fn ask(q: &str) -> Result<String> {
    print!("{q}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    if std::io::stdin().read_line(&mut s)? == 0 {
        bail!("no answer (nothing to type into). Run it again in a terminal, or give the answer on the command line, for example: sudo ./install.sh --endpoint 203.0.113.7");
    }
    Ok(s.trim().to_string())
}

/// Ask until the answer is usable: a wrong answer explains itself and asks again, instead of ending the setup.
fn ask_until<T>(q: &str, check: impl Fn(&str) -> Result<T>) -> Result<T> {
    loop {
        let a = ask(q)?;
        match check(&a) {
            Ok(v) => return Ok(v),
            Err(e) => println!("\n  {e}\n"),
        }
    }
}

const ENDPOINT_HELP: &str = "How is this box reached from the internet?

  Type ONE of these (not the words, the address itself):
    - a dynamic DNS name, for example  myhome.duckdns.org   (best: keeps working when your address changes)
    - your home's public IP address, for example  203.0.113.7

  Your public IP is the one your internet provider gives your router, NOT a 192.168.x.x / 10.x.x.x address.
  To see it, open https://ifconfig.me on any device at home, or on the SRX300 run:  show interfaces ge-0/0/0 terse
  (use the port your internet cable is in). Note: most home connections get a new public IP now and then;
  then change it here with  sudo syphon-vpn endpoint NEW-ADDRESS  and add devices again. A DuckDNS name avoids that.
";

/// An endpoint answer: a DNS name or a public IP, optionally with :port.
fn check_endpoint(a: &str, port: u16) -> Result<(String, u16)> {
    let lower = a.trim().to_ascii_lowercase();
    if lower.is_empty() {
        bail!("Type the address itself, for example 203.0.113.7 or myhome.duckdns.org");
    }
    if ["public ip", "public", "ip", "dns", "dns name", "dynamic dns", "public ip address"].contains(&lower.as_str()) {
        bail!("Type the address itself, not the kind: for example 203.0.113.7 (your public IP) or myhome.duckdns.org (a DNS name).");
    }
    let (host, port) = state::parse_endpoint(a, port)?;
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
            bail!("{ip} is an address inside your home network. The box needs the address the internet sees: your public IP (see https://ifconfig.me) or a DuckDNS name.");
        }
        if ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]) {
            bail!("{ip} is a carrier-grade NAT address (100.64-127.x.x): your provider shares one public address between many customers, so nobody can reach your home from outside on it. Ask your provider for a public IPv4 address (in Germany often called \"echte IPv4\" or \"public IPv4\"), then run this again.");
        }
    } else if !host.contains('.') {
        bail!("\"{host}\" is not a full name. A DNS name looks like myhome.duckdns.org; an IP looks like 203.0.113.7.");
    }
    Ok((host, port))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn ago(t: i64) -> String {
    if t == 0 {
        return "never".into();
    }
    let d = (now() - t).max(0);
    match d {
        0..=89 => format!("{d} s ago"),
        90..=5399 => format!("{} min ago", d / 60),
        5400..=129599 => format!("{} h ago", d / 3600),
        _ => format!("{} days ago", d / 86400),
    }
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("syphon-vpn: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    if cli.root.is_none() && !sys::is_root() {
        bail!("run this as root: sudo syphon-vpn …");
    }
    let p = match &cli.root { Some(r) => Paths::under(r), None => Paths::system() };
    let test = cli.root.is_some();
    // in tests only the files are written; on a real box the running system is updated too
    let commit = |p: &Paths, c: &BoxConfig, d: &[Device]| if test { sys::write_files(p, c, d) } else { sys::apply(p, c, d) };
    match cli.cmd {
        Cmd::Init { endpoint, node, port, subnet } => {
            if p.config().exists() {
                bail!("this box is already set up. Change it with \"syphon-vpn endpoint\" or \"syphon-vpn node\", or see \"syphon-vpn status\".");
            }
            let subnet: std::net::Ipv4Addr = subnet.parse().map_err(|_| anyhow::anyhow!("the subnet is an address like 10.77.0.0"))?;
            // the Syphon server: given, or found on the network
            let (node_ip, node_port, name) = match node {
                Some(n) => {
                    let (ip, port) = state::parse_node(&n)?;
                    (ip, port, "Syphon".to_string())
                }
                None => {
                    println!("Looking for your Syphon server on this network…");
                    let found = discover::find(std::time::Duration::from_millis(1500));
                    match found.as_slice() {
                        [one] => {
                            println!("Found {} at {}:{}", one.name, one.ip, one.port);
                            (one.ip, one.port, one.name.clone())
                        }
                        [] => {
                            println!("No Syphon server answered on this network (it may be off, or on another VLAN).");
                            let (ip, port) = ask_until("Type the Syphon server's home-network address (for example 192.168.1.20): ", state::parse_node)?;
                            (ip, port, "Syphon".to_string())
                        }
                        many => {
                            for (i, f) in many.iter().enumerate() {
                                println!("  {}) {} at {}:{}", i + 1, f.name, f.ip, f.port);
                            }
                            let f = ask_until("Which one? Type its number: ", |a| a.trim().parse::<usize>().ok().and_then(|i| many.get(i.wrapping_sub(1))).ok_or_else(|| anyhow::anyhow!("Type one of the numbers above.")))?;
                            (f.ip, f.port, f.name.clone())
                        }
                    }
                }
            };
            let (endpoint_host, port) = match endpoint {
                Some(e) => check_endpoint(&e, port)?,
                None => {
                    println!("\n{ENDPOINT_HELP}");
                    ask_until("Address: ", |a| check_endpoint(a, port))?
                }
            };
            let (private_key, public_key) = keys::pair();
            let c = BoxConfig { name, endpoint_host, port, node_ip, node_port, subnet, private_key, public_key, node_mac: None };
            state::save_config(&p, &c)?;
            state::save_devices(&p, &[])?;
            commit(&p, &c, &[])?;
            let me = sys::lan_ip().unwrap_or_else(|| "this box".into());
            println!(
                "\nThe VPN box is running.\n\nWhat to do next:\n  1. On your router (the SRX300), forward UDP port {port} from the internet to {me}.\n  2. {two}\n  3. Give {me} a fixed address on your network (a DHCP reservation).\n  4. Link Syphon to this box:  sudo syphon-vpn link  and paste the code in Syphon (owner, at home): Settings > Node > Outside access.\n     Syphon then treats visitors through this box as outside, and you can add and remove devices there.\n  5. Let a device's Syphon app in: in Syphon's settings, or here with  sudo syphon-vpn add \"Mia's laptop\"",
                port = c.port,
                two = if c.endpoint_host.parse::<std::net::IpAddr>().is_ok() {
                    format!("Devices connect to {}. If your provider changes that address, run: sudo syphon-vpn endpoint NEW-ADDRESS (a DuckDNS name avoids this).", c.endpoint_host)
                } else {
                    format!("Make sure {} points at your home's public address (your router's or DuckDNS's updater keeps it right).", c.endpoint_host)
                }
            );
        }
        Cmd::Add { name } => {
            let c = state::load_config(&p)?;
            // a one-time welcome key: it only reaches the box's welcome desk, where the app swaps it for a key of its own
            let (devices, d, code) = syphon_vpn::manage::add_device(&p, &name, now()).map_err(|e| anyhow::anyhow!("{e}"))?;
            let name = d.name.clone();
            commit(&p, &c, &devices)?;
            if test {
                println!("{code}");
                return Ok(());
            }
            println!("\nA code for \"{name}\". Paste it into the Syphon app on that device: App settings > Away from home (or \"I'm away from home\" on first start).\n\n{code}\n");
            println!("It works once, only in the Syphon app, and only for the next {} days. On first contact the app puts a key of its own in place, which never leaves the device; the code is then spent.", state::WELCOME_DAYS);
            println!("To cut the device off later: sudo syphon-vpn remove \"{name}\"");
        }
        Cmd::Serve { listen, manage, files_only } => {
            let c = state::load_config(&p)?;
            let listen = listen.unwrap_or_else(|| format!("{}:{}", c.box_ip(), syphon_vpn::WELCOME_PORT));
            // the management link for Syphon, on the home network (only answers once linked: syphon-vpn link)
            let (p2, live) = (p.clone(), !files_only);
            let manage_at = manage.unwrap_or_else(|| format!("0.0.0.0:{}", syphon_vpn::manage::PORT));
            std::thread::spawn(move || syphon_vpn::manage::serve(p2, manage_at, live));
            // wake a sleeping Syphon server when a device wants it
            if !files_only {
                let p3 = p.clone();
                std::thread::spawn(move || syphon_vpn::wake::watch(p3));
            }
            syphon_vpn::enroll::serve(&p, &listen, !files_only)?;
        }
        Cmd::List => {
            let devices = state::load_devices(&p)?;
            if devices.is_empty() {
                println!("No devices yet. Let one in with: sudo syphon-vpn add \"Mia's phone\"");
            }
            let hs = sys::handshakes();
            for d in devices {
                let last = hs.iter().find(|(k, _)| *k == d.public_key).map(|(_, t)| *t).unwrap_or(0);
                let state = if d.enrolled { format!("last connected {}", ago(last)) } else if d.expires < now() { "code expired (remove it, or add it again)".into() } else { format!("waiting for its app (code works until {} days from when it was made)", state::WELCOME_DAYS) };
                println!("{:<28} {:<14} {}", d.name, d.ip, state);
            }
        }
        Cmd::Remove { name } => {
            let c = state::load_config(&p)?;
            let devices = syphon_vpn::manage::remove_device(&p, &name).map_err(|e| anyhow::anyhow!("{e} (see: syphon-vpn list)"))?;
            commit(&p, &c, &devices)?;
            println!("\"{}\" can no longer connect.", name.trim());
        }
        Cmd::Wake => {
            let c = state::load_config(&p)?;
            let mac = c.node_mac.clone().ok_or_else(|| anyhow::anyhow!("the box doesn't know the Syphon server's network card yet. Link Syphon (sudo syphon-vpn link), or set it: sudo syphon-vpn wake-mac aa:bb:cc:dd:ee:ff"))?;
            syphon_vpn::wake::send(c.node_ip, &mac)?;
            println!("Sent a wake packet to {mac} at {}. Waiting for it to answer…", c.node_ip);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(60) {
                if syphon_vpn::wake::awake(c.node_ip, c.node_port) {
                    println!("{} is answering ({} s).", c.name, start.elapsed().as_secs());
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            bail!("{} did not answer within a minute. Check that wake-on-LAN is on in its BIOS, and the router's permanent entry for its card (see Syphon > Settings > Device > Sleep).", c.name);
        }
        Cmd::WakeMac { mac } => {
            let mut c = state::load_config(&p)?;
            c.node_mac = if mac.trim().is_empty() { None } else { Some(syphon_vpn::wake::parse_mac(&mac)?) };
            state::save_config(&p, &c)?;
            println!("{}", c.node_mac.as_deref().map(|m| format!("The box wakes the Syphon server through {m}.")).unwrap_or_else(|| "The box no longer wakes the Syphon server.".into()));
        }
        Cmd::Link { new } => {
            let c = state::load_config(&p)?;
            let k = syphon_vpn::manage::key(&p, new)?;
            let me = sys::lan_ip().unwrap_or_else(|| "BOX-ADDRESS".into());
            let code = syphon_vpn::manage::link_code(&c, &me, &k);
            if test {
                println!("{code}");
                return Ok(());
            }
            println!("\nA link code for Syphon. In Syphon (owner, at home): Settings > Node > Outside access > Link a VPN box, and paste:\n\n{code}\n");
            println!("Syphon can then see, add and remove this box's devices, and knows to treat visitors from {me} as outside.");
            println!("Only the Syphon server at {} can use the link. To cut off an old link: sudo syphon-vpn link --new (then paste the new code).", c.node_ip);
            if new {
                println!("\nThe old link no longer works.");
            }
        }
        Cmd::Endpoint { endpoint } => {
            let mut c = state::load_config(&p)?;
            let (h, port) = check_endpoint(&endpoint, c.port)?;
            c.endpoint_host = h;
            c.port = port;
            state::save_config(&p, &c)?;
            commit(&p, &c, &state::load_devices(&p)?)?;
            println!("Devices added from now on connect to {}. Devices added before keep the old address in their settings: add them again.", c.endpoint());
        }
        Cmd::Node { node } => {
            let mut c = state::load_config(&p)?;
            let (ip, port) = state::parse_node(&node)?;
            c.node_ip = ip;
            c.node_port = port;
            state::save_config(&p, &c)?;
            commit(&p, &c, &state::load_devices(&p)?)?;
            println!("VPN devices now reach the Syphon server at {}. Devices added before point at the old address: add them again.", c.node_url());
        }
        Cmd::Apply => {
            let c = state::load_config(&p)?;
            commit(&p, &c, &state::load_devices(&p)?)?;
            println!("Done.");
        }
        Cmd::Status => {
            let c = state::load_config(&p)?;
            let devices = state::load_devices(&p)?;
            let hs = sys::handshakes();
            let up = std::process::Command::new("systemctl").args(["is-active", "--quiet", &format!("wg-quick@{}", syphon_vpn::IFACE)]).status().map(|s| s.success()).unwrap_or(false);
            println!("Syphon server:    {} at {}", c.name, c.node_url());
            println!("Reached at:       {} (UDP, forward it to {} on your router)", c.endpoint(), sys::lan_ip().unwrap_or_else(|| "this box".into()));
            println!("VPN running:      {}", if up { "yes" } else { "no (start it with: sudo syphon-vpn apply)" });
            println!("Devices:          {} ({} connected in the last 3 minutes)", devices.len(), devices.iter().filter(|d| hs.iter().any(|(k, t)| *k == d.public_key && now() - *t < 180)).count());
            match sys::packets_in() {
                Some(0) => println!("Packets arriving: 0 since the firewall was loaded. If a device is trying to connect right now, nothing reaches this box:\n                  check the port forward (UDP {} to {}) on your router, and that the device's network doesn't block outgoing UDP.", c.port, sys::lan_ip().unwrap_or_else(|| "this box".into())),
                Some(n) => println!("Packets arriving: {n} on UDP {} since the firewall was loaded (the port forward works)", c.port),
                None => println!("Packets arriving: unknown (the firewall isn't loaded; run: sudo syphon-vpn apply)"),
            }
            let last_wake = std::fs::read_to_string(p.dir.join("last-wake")).ok().and_then(|s| s.trim().parse::<i64>().ok());
            println!("Waking Syphon:    {}", match &c.node_mac {
                Some(m) => format!("through {m}{}", last_wake.map(|t| format!(", last wake packet sent {}", ago(t))).unwrap_or_default()),
                None => "not set up (Syphon gives the box its card's address once linked)".into(),
            });
            println!("Syphon link:      {}", if syphon_vpn::manage::key_path(&p).exists() { "set up (sudo syphon-vpn link shows the code again)" } else { "not set up (sudo syphon-vpn link)" });
        }
    }
    Ok(())
}
