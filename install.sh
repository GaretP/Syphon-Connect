#!/usr/bin/env bash
# Syphon VPN box installer for a small always-on Debian, Ubuntu or Raspberry Pi OS device at home.
#
#   sudo ./install.sh                                   (asks how the box is reached from the internet)
#   sudo ./install.sh --endpoint home.duckdns.org [--node 192.168.1.20] [--port 51820]
set -euo pipefail
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint|--node|--port) ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "I did not understand \"$1\"." >&2; exit 2 ;;
  esac
done
LOG="/tmp/syphon-vpn-install.log"
say() { printf '%s\n' "$*"; }
die() { printf '\nSomething went wrong: %s\n' "$*" >&2; [[ -s "$LOG" ]] && printf 'The details are in %s\n' "$LOG" >&2; exit 1; }
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then exec sudo -E bash "$0" "$@"; fi
  die "please run this as an administrator: sudo ./install.sh"
fi
cd "$(dirname "$0")"
: >"$LOG"
command -v apt-get >/dev/null 2>&1 || die "this installer is for Debian, Ubuntu and Raspberry Pi OS (it needs apt)."

say "[1/3] Installing WireGuard, the firewall and the build tools (a few minutes)"
export DEBIAN_FRONTEND=noninteractive
apt-get update >>"$LOG" 2>&1 || die "apt could not update"
apt-get install -y wireguard-tools nftables build-essential pkg-config curl ca-certificates >>"$LOG" 2>&1 || die "apt could not install what the box needs"

say "[2/3] Building syphon-vpn (up to 10 minutes on a small device)"
if ! command -v cargo >/dev/null 2>&1; then
  [[ -x "$HOME/.cargo/bin/cargo" ]] || { curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh >>"$LOG" 2>&1 && sh /tmp/rustup.sh -y --profile minimal >>"$LOG" 2>&1; } || die "Rust could not be installed"
  export PATH="$HOME/.cargo/bin:$PATH"
fi
cargo build --release --locked >>"$LOG" 2>&1 || die "the build failed"
install -m 0755 target/release/syphon-vpn /usr/local/bin/syphon-vpn
install -m 0644 systemd/syphon-vpn-firewall.service /etc/systemd/system/syphon-vpn-firewall.service
install -m 0644 systemd/syphon-vpn-welcome.service /etc/systemd/system/syphon-vpn-welcome.service
systemctl daemon-reload
# a box set up before keeps running the old program until its service restarts
systemctl try-restart syphon-vpn-welcome.service 2>/dev/null || true

say "[3/3] Setting up the VPN"
if [[ -f /etc/syphon-vpn/box.json ]]; then
  /usr/local/bin/syphon-vpn apply
  say "This box was already set up; it is updated and running."
else
  /usr/local/bin/syphon-vpn init "${ARGS[@]}"
fi
