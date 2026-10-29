# Syphon VPN box

Fast access to your Syphon from anywhere. A small always-on device at home (a Raspberry Pi is plenty) runs WireGuard. The Syphon app connects to it from outside, and they reach the Syphon server's web app. They reach nothing else on your home network. WireGuard runs at the speed of your home connection, unlike Tor. Tor stays where it works well: the mesh between houses and grabbing.

It is its own project and its own device. Nothing of it runs on the Syphon server.

## What it does

- **Only the Syphon server.** VPN devices may open the Syphon server's web port and nothing else. The rest of your home network, the box itself and the internet through your connection are all blocked by the box's firewall. Devices also only send Syphon's traffic through the tunnel; everything else they do stays on their own connection.
- **The server knows who came through it.** Requests from VPN devices reach the server from the box's own address. That is how the server tells them apart from people actually at home: they are treated as "from outside", with the same sign-in rules as now (approval or two-step code the first time, no Vault, no owner-only home settings).
- **Only the Syphon app.** There is no QR code or file for the WireGuard app. A device gets a one-time code that only the Syphon app knows how to use (see below).
- **Device by device.** Each device has its own key and an extra preshared key. Removing a device cuts it off at once.
- **Quiet from outside.** WireGuard does not answer anything that does not carry a valid key, so the forwarded port looks closed to scanners.

## Set it up

1. **The box:** a small Debian, Ubuntu or Raspberry Pi OS device on the same network as the Syphon server. Give it a fixed address (a DHCP reservation on the SRX300).
2. **A name for your home:** your public address usually changes now and then, so use a dynamic DNS name (for example a free DuckDNS name). Keep it up to date with your router's dynamic DNS feature or the provider's small update script. A fixed public IP also works.
3. **Install:** on the box, run `sudo ./install.sh --endpoint yourname.duckdns.org`. It installs WireGuard and nftables, builds the program and sets the box up. It finds the Syphon server on the network by itself. If it can't, it asks for the address.
4. **Forward one port** on the SRX300: UDP 51820 from the internet to the box. Here is an example; adjust the zone names, the public address and the box's address to yours:

       set security zones security-zone trust address-book address syphon-vpn-box 192.168.1.30/32
       set applications application wireguard protocol udp destination-port 51820
       set security nat destination pool syphon-vpn address 192.168.1.30/32 port 51820
       set security nat destination rule-set from-internet from zone untrust
       set security nat destination rule-set from-internet rule wg match destination-address <your public IP>/32
       set security nat destination rule-set from-internet rule wg match destination-port 51820
       set security nat destination rule-set from-internet rule wg match protocol udp
       set security nat destination rule-set from-internet rule wg then destination-nat pool syphon-vpn
       set security policies from-zone untrust to-zone trust policy syphon-vpn match source-address any destination-address syphon-vpn-box application wireguard
       set security policies from-zone untrust to-zone trust policy syphon-vpn then permit

   If the Syphon server and the box are on different VLANs, also allow the box to reach the server on TCP 8096.
5. **Link Syphon to the box:** run `sudo syphon-vpn link` and paste the code in Syphon (owner, at home) under Settings > Node > Outside access. Syphon then:
   - treats visitors through the box as coming from outside, and
   - lists the box's devices, makes codes for new ones and removes old ones, so you don't have to log in to the box for that.

   **Until Syphon is linked (or the box's address is typed under Outside access), don't let anyone else in.** The server would otherwise take VPN visitors for people at home.

   The link only works for the Syphon server's own address, and everything on it is sealed with a key only the box and Syphon have (XChaCha20-Poly1305, time-stamped and never accepted twice), so nobody else on your network can read or use it. `sudo syphon-vpn link --new` makes a new key and cuts off the old link.

## Let devices in

    sudo syphon-vpn add "Mia's laptop"

This prints a code starting with `SYPHON-VPN-1:`. Paste it into the Syphon app on that device: App settings > Away from home, or "I'm away from home" on first start. The code works once and expires after 7 days.

What happens with the code:

1. The code holds a **one-time welcome key**. With it, the app can reach exactly one thing: the box's welcome desk inside the VPN. It can't reach the Syphon server or anything else.
2. The app makes **a key of its own**, which never leaves the device, and hands the public half to the welcome desk along with the code's one-time token.
3. The box swaps the welcome key for the app's key and lets that device through to the Syphon server. The code is now spent: nobody can use it again, not even with the welcome key.

So a code that leaks after it was used is worthless. A code that leaks before it was used lets in one device, which then shows in `syphon-vpn list`; remove it and add the real one again.

Other commands:

    sudo syphon-vpn list             who may connect, who is still waiting, and when each last connected
    sudo syphon-vpn remove "Mia's laptop"
    sudo syphon-vpn status           what the box is doing, including how many packets reach its port
    sudo syphon-vpn wake             wake the Syphon server now
    sudo syphon-vpn endpoint new.duckdns.org    when the box's internet name changes
    sudo syphon-vpn node 192.168.1.21           when the Syphon server's address changes

## Waking a sleeping Syphon server

When Syphon sleeps (Syphon: Settings > Device > Sleep), the box wakes it as soon as a device opens a connection to it and it doesn't answer. A device that only keeps its tunnel up doesn't wake it, so an app left open on a laptop won't stop the server from sleeping. The Syphon app then shows "Waking…" until the server answers.

- **The server's card address:** Syphon gives it to the box over the link. Without the link: `sudo syphon-vpn wake-mac aa:bb:cc:dd:ee:ff`.
- **Try it:** `sudo syphon-vpn wake` sends a wake packet and waits for the server to answer. `sudo syphon-vpn status` shows when the box last sent one.
- **On the router:** the wake packet goes straight to the server's address (UDP 9), not as a broadcast, because broadcasts don't cross VLANs. A router between them needs a permanent entry for the sleeping server's card ("static ARP") and must allow UDP 9 from the box to the server. Syphon's Sleep panel shows the SRX300 lines with the right addresses.

## When a device can't connect

1. In the Syphon app: App settings > Away from home > **Test the VPN connection**. It says at which step it stops.
2. On the box: `sudo syphon-vpn status`.
   - **Packets arriving: 0** while the device is trying: nothing reaches the box. Check the port forward on your router (UDP 51820 to the box's address), and that the device's own network doesn't block outgoing UDP. Some VPN services and guest Wi-Fi networks do.
   - **Packets arriving, but the device is "waiting for its app"** in `sudo syphon-vpn list`: the code never finished. Remove the device and add it again.
   - **Packets arriving and the device connected**, but Syphon doesn't answer: check the Syphon server's address with `sudo syphon-vpn status`, and change it with `sudo syphon-vpn node NEW-ADDRESS`.
3. Testing from home doesn't prove much. Many routers can't send traffic out to their own public address and back in. Use a phone hotspot.

## Good to know

- At home, the Syphon app talks to the server directly and leaves the tunnel off.
- **The welcome desk** listens only inside the VPN (10.77.0.1, TCP 51821) and gives up after 10 wrong tries a minute. Nothing about it is open to the internet.
- **An honest limit:** no software can fully prove the other side is the real Syphon app. Someone who studies the app could imitate the welcome step with a code you gave them. What it guarantees is that the WireGuard app alone can't use a code, a used code is worthless, and every device is listed and removable.
- **Changing the endpoint or server address:** devices added before keep the old one in their settings, so add them again.
- **Files:** settings live in `/etc/syphon-vpn` (root only). WireGuard reads `/etc/wireguard/syphon0.conf`, and the firewall lives in `/etc/syphon-vpn/firewall.nft`. All three are written by the program.
- **Waking a sleeping server:** that comes later, on top of this.

## Tested

- **Unit tests:** settings, keys (checked against the published X25519 test vector and against `wg pubkey`), file contents, codes and the welcome step (wrong token, expired code, reuse).
- **`tests/netns_e2e.sh`** (run as root) builds a real tunnel between three network namespaces with real WireGuard and the box's real firewall. It checks that:
  - the welcome key alone does not reach the Syphon server
  - the welcome desk takes the device's own key, and with it the device reaches the server's web port, and the server sees the box's address
  - the server's other ports and the box itself are unreachable
  - the code works only once, and the spent welcome key no longer connects
  - the box counts the packets reaching its port, and only the Syphon server may use the management link
  - a device that only keeps its tunnel up doesn't wake the server, opening Syphon while it sleeps sends a correct wake packet to its card, and an awake server gets none
  - a removed device is cut off
- **Not tested:** real routers and real dynamic DNS. The Syphon app's side is played by a script in the test; the app itself learns this in its next update.

License: AGPL-3.0-only.
