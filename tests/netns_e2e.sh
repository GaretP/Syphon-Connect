#!/usr/bin/env bash
# A real tunnel between three network namespaces, run as root: a device on the "internet", the VPN "box", and the
# Syphon "node" on the home network. The box is set up with syphon-vpn itself, with real WireGuard (wireguard-go when
# the kernel has none), the box's real firewall and its welcome desk. The device does what the Syphon app does.
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
ok() { echo "  ok   $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
T="$(mktemp -d)"; chmod 700 "$T"
cleanup() {
  for n in client box node; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $n 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
cargo build -q --offline || exit 1
VPN="$PWD/target/debug/syphon-vpn --root $T/box"

for n in client box node; do ip netns add $n; ip -n $n link set lo up; done
ip link add c0 netns client type veth peer name b0 netns box
ip link add b1 netns box type veth peer name n0 netns node
ip -n client addr add 203.0.113.2/24 dev c0; ip -n client link set c0 up
ip -n box addr add 203.0.113.1/24 dev b0; ip -n box link set b0 up
ip -n box addr add 192.168.50.1/24 dev b1; ip -n box link set b1 up
ip -n node addr add 192.168.50.20/24 dev n0; ip -n node link set n0 up
cat >"$T/web.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(self.client_address[0].encode())
    def log_message(self, *a): pass
http.server.HTTPServer((sys.argv[1], int(sys.argv[2])), H).serve_forever()
PY
ip netns exec node python3 "$T/web.py" 192.168.50.20 8096 & WEB=$!
ip netns exec node python3 "$T/web.py" 192.168.50.20 2222 &
ip netns exec box python3 "$T/web.py" 192.168.50.1 8080 &

# the box, set up the way a user would
$VPN init --endpoint 203.0.113.1 --node 192.168.50.20 >/dev/null && ok "the box is set up" || bad "the box is set up"
CODE="$($VPN add "test laptop")"
[[ "$CODE" == SYPHON-VPN-1:* ]] && ok "a device gets a one-time code" || bad "a device gets a one-time code ($CODE)"
chmod 600 "$T/box/syphon0.conf"
ip netns exec box sysctl -q -w net.ipv4.ip_forward=1
ip netns exec box nft -f "$T/box/syphon-vpn/firewall.nft" && ok "the firewall loads" || bad "the firewall loads"
ip netns exec box wg-quick up "$T/box/syphon0.conf" >"$T/box.log" 2>&1 && ok "the box's WireGuard comes up" || { bad "the box's WireGuard comes up"; cat "$T/box.log"; }
ip netns exec box $VPN serve >"$T/desk.log" 2>&1 &
sleep 1

# the device, doing what the Syphon app does: read the code, connect with the welcome key, hand over its own key
python3 - "$CODE" "$T" <<'PY'
import sys, json, base64
code, t = sys.argv[1], sys.argv[2]
b = code.split(":", 1)[1]; c = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
node_ip = c["node"].split("//")[1].split(":")[0]; desk_ip = c["welcome"].split(":")[0]
def conf(priv):
    return f"[Interface]\nPrivateKey = {priv}\nAddress = {c['address']}\n\n[Peer]\nPublicKey = {c['server_public']}\nPresharedKey = {c['psk']}\nEndpoint = {c['endpoint']}\nAllowedIPs = {node_ip}/32, {desk_ip}/32\nPersistentKeepalive = 25\n"
open(f"{t}/welcome0.conf", "w").write(conf(c["private"]))
open(f"{t}/code.json", "w").write(json.dumps(c))
PY
chmod 600 "$T/welcome0.conf"
ip netns exec client wg-quick up "$T/welcome0.conf" >/dev/null 2>&1 && ok "the device connects with its welcome key" || bad "the device connects with its welcome key"
sleep 1
ip netns exec client curl -s -m 4 http://192.168.50.20:8096/ >/dev/null && bad "the welcome key alone does not reach the Syphon server" || ok "the welcome key alone does not reach the Syphon server"
OWN="$(wg genkey)"; OWNPUB="$(echo "$OWN" | wg pubkey)"; TOKEN="$(python3 -c "import json;print(json.load(open('$T/code.json'))['token'])")"
R="$(ip netns exec client curl -s -m 8 -X POST -H 'content-type: application/json' -d "{\"token\":\"$TOKEN\",\"public_key\":\"$OWNPUB\"}" http://10.77.0.1:51821/enroll)"
[[ "$R" == *'"ok":true'* ]] && ok "the welcome desk takes the device's own key" || { bad "the welcome desk takes the device's own key ($R)"; cat "$T/desk.log"; }
sleep 2  # the box switches keys just after answering
ip netns exec client wg-quick down "$T/welcome0.conf" >/dev/null 2>&1
sed "s#^PrivateKey = .*#PrivateKey = $OWN#" "$T/welcome0.conf" >"$T/own0.conf"; chmod 600 "$T/own0.conf"
ip netns exec client wg-quick up "$T/own0.conf" >/dev/null 2>&1
sleep 1
who="$(ip netns exec client curl -s -m 8 http://192.168.50.20:8096/)"
[[ "$who" == "192.168.50.1" ]] && ok "with its own key the device reaches the Syphon server, which sees the box's address" || bad "own key reaches the Syphon server (got '$who')"
ip netns exec client curl -s -m 4 http://192.168.50.20:2222/ >/dev/null && bad "another port on the server is blocked" || ok "another port on the server is blocked"
ip netns exec client curl -s -m 4 http://192.168.50.1:8080/ >/dev/null && bad "the box itself is not reachable" || ok "the box itself is not reachable"
R2="$(ip netns exec client curl -s -m 8 -X POST -d "{\"token\":\"$TOKEN\",\"public_key\":\"$(wg genkey | wg pubkey)\"}" http://10.77.0.1:51821/enroll)"
[[ "$R2" == *error* ]] && ok "the code works only once" || bad "the code works only once ($R2)"
ip netns exec client wg-quick down "$T/own0.conf" >/dev/null 2>&1
ip netns exec client wg-quick up "$T/welcome0.conf" >/dev/null 2>&1
ip netns exec client curl -s -m 4 http://10.77.0.1:51821/enroll >/dev/null && bad "the spent welcome key no longer connects" || ok "the spent welcome key no longer connects"
ip netns exec client wg-quick down "$T/welcome0.conf" >/dev/null 2>&1
grep -q '"enrolled": true' "$T/box/syphon-vpn/devices.json" && grep -q "elements = { 10.77.0.2 }" "$T/box/syphon-vpn/firewall.nft" && ! grep -q "$(python3 -c "import json;print(json.load(open('$T/code.json'))['private'])")" "$T/box/syphon0.conf" \
  && ok "the box's files now hold the device's own key, and the welcome key is gone" || bad "the box's files are updated"
n="$(ip netns exec box nft list counter inet syphon_vpn wg_in | awk '/packets/ {print $2}')"
[[ "${n:-0}" -gt 0 ]] && ok "the box counts what reaches its WireGuard port ($n packets)" || bad "arrival counter ($n)"
ip netns exec box nft list ruleset | grep -q "tcp dport 51822 ip saddr != 192.168.50.20 drop" && ok "only the Syphon server may use the management link" || bad "management link rule"
# waking: a sleeping Syphon server (stand-in: its web server is stopped, a listener takes wake packets)
NODEMAC="$(ip -n node link show n0 2>/dev/null | awk '/ether/ {print $2}')"
$VPN wake-mac "$NODEMAC" >/dev/null && ok "the box takes the server's card address" || bad "wake-mac"
cat >"$T/wol.py" <<'PY2'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], 9))
while True:
    d, a = s.recvfrom(2048); open(sys.argv[2], "a").write(d.hex() + "\n")
PY2
ip netns exec node python3 "$T/wol.py" 192.168.50.20 "$T/wol.log" &
kill $WEB; sleep 0.5
ip netns exec client wg-quick up "$T/own0.conf" >/dev/null 2>&1
sleep 6
[[ ! -s "$T/wol.log" ]] && ok "a device that only keeps its tunnel up does not wake the server" || bad "an idle tunnel woke the server"
ip netns exec client curl -s -m 3 http://192.168.50.20:8096/ >/dev/null
sleep 2
WANT="ffffffffffff$(printf '%s' "$NODEMAC" | tr -d ':' | sed 's/.*/&&&&&&&&&&&&&&&&/')"
grep -qx "$WANT" "$T/wol.log" 2>/dev/null && ok "opening Syphon while it sleeps sends a wake packet to its card" || bad "no wake packet ($(head -c 80 "$T/wol.log" 2>/dev/null))"
n1=$(wc -l <"$T/wol.log"); ip netns exec node python3 "$T/web.py" 192.168.50.20 8096 & sleep 0.5
ip netns exec client curl -s -m 3 http://192.168.50.20:8096/ >/dev/null; sleep 2
[[ $(wc -l <"$T/wol.log") -eq $n1 ]] && ok "an awake server gets no wake packets" || bad "woke an awake server"
ip netns exec client wg-quick down "$T/own0.conf" >/dev/null 2>&1
# removing the device cuts it off
$VPN remove "test laptop" >/dev/null && ip netns exec box wg syncconf syphon0 <(ip netns exec box wg-quick strip "$T/box/syphon0.conf") && ip netns exec box nft -f "$T/box/syphon-vpn/firewall.nft"
ip netns exec client wg-quick up "$T/own0.conf" >/dev/null 2>&1
ip netns exec client curl -s -m 4 http://192.168.50.20:8096/ >/dev/null && bad "a removed device is cut off" || ok "a removed device is cut off"
ip netns exec client wg-quick down "$T/own0.conf" >/dev/null 2>&1
ip netns exec box wg-quick down "$T/box/syphon0.conf" >/dev/null 2>&1
echo; echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
