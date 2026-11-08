#!/usr/bin/env bash
# Set the ports the host's own sshd listens on, e.g. to free port 22 for a
# decoy. Run as root on the server:
#
#   scripts/ssh-port.sh 22 2222   # listen on both while testing
#   scripts/ssh-port.sh 2222      # then move off 22
#
# Ports go in the main sshd_config (the DigitalOcean droplet agent reads the
# first Port line there, so the web Droplet Console follows). On Ubuntu the
# ssh.socket unit is generated from sshd_config, so it is regenerated and
# restarted; open sessions stay up. Also open the new port in the cloud
# firewall before moving off the old one.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 PORT [PORT...]" >&2; exit 2; }
for p in "$@"; do
  [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "bad port: $p" >&2; exit 2; }
done

conf=/etc/ssh/sshd_config
cp -p "$conf" "$conf.bak-$(date -u +%Y%m%dT%H%M%SZ)"
# Drop existing Port lines, then put ours at the top so they come first.
tmp=$(mktemp)
{
  echo "# Ports set by scripts/ssh-port.sh"
  for p in "$@"; do echo "Port $p"; done
  grep -vE '^\s*#?\s*Port\s+[0-9]+\s*$|^# Ports set by scripts/ssh-port.sh$' "$conf"
} >"$tmp"
install -m 644 "$tmp" "$conf"
rm -f "$tmp"

sshd -t
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
  systemctl daemon-reload
  systemctl restart ssh.socket
else
  systemctl restart ssh
fi
sleep 1

ok=1
for p in "$@"; do
  if ss -ltn "sport = :$p" | grep -q LISTEN; then
    echo "PASS  sshd listening on $p"
  else
    echo "FAIL  sshd not listening on $p"; ok=0
  fi
done
if ! systemctl restart droplet-agent 2>/dev/null; then
  echo "note  no droplet-agent (not on DigitalOcean, or console disabled)"
fi
[ "$ok" = 1 ]
