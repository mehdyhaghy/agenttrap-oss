#!/usr/bin/env bash
# Fail2ban-style protection for the public ports, in the kernel via nftables.
#
# The relays' own rate limit (internal/relay) and the spoke's per-source event
# limit protect the backend, the queue and the database, but a flooding source
# still gets a TCP handshake and keeps trying. This drops packets from a source
# that sustains a flood, so it sees timeouts and backs off — the traffic stops.
#
# Two tiers, because a decoy port and a web port tolerate very different rates:
#   * STRICT_PORTS (raw decoys, e.g. SSH 22, Redis 6379): banned after a low
#     sustained rate — nothing legitimate connects to these.
#   * WEB_PORTS (80, 443): banned only after a genuine connection flood, so
#     normal browsers, agents and crawlers (which we want to keep observing)
#     are never touched. Keep-alive means a legitimate client makes few
#     connections even for many requests; per-request flooding on one
#     connection is handled by the spoke's event limit instead.
#
# Safety, given the droplet's firewall history:
#   * The real sshd on 2222 is never matched, so management access cannot be
#     affected.
#   * A source is banned only after sustaining a flood; low-volume connections
#     — including the DigitalOcean Droplet Console — never approach the limit,
#     so this cannot lock anything out the way an allowlist rule would.
#   * This is host nftables, not a cloud provider firewall: it is portable to
#     any Linux host and depends on no provider feature.
#   * Bans auto-expire (default 1h) and re-apply if the flood resumes.
#   * It lives in its own table (inet agenttrap_decoy); Docker's rules are
#     untouched.
#
# Usage:
#   sudo ./decoy-firewall.sh            install / update and enable on boot
#   sudo ./decoy-firewall.sh --status   show the rule and currently banned IPs
#   sudo ./decoy-firewall.sh --remove   tear everything down
#
# Tunables (env): STRICT_PORTS, STRICT_RATE, STRICT_BURST, WEB_PORTS, WEB_RATE,
# WEB_BURST, BAN_TIMEOUT, EXEMPT (comma-separated).
set -euo pipefail

STRICT_PORTS="${STRICT_PORTS:-${DECOY_PORTS:-22 6379 5432}}"
STRICT_RATE="${STRICT_RATE:-${RATE:-30/hour}}"
STRICT_BURST="${STRICT_BURST:-${BURST:-20}}"
WEB_PORTS="${WEB_PORTS:-80 443}"
WEB_RATE="${WEB_RATE:-600/minute}"
WEB_BURST="${WEB_BURST:-300}"
BAN_TIMEOUT="${BAN_TIMEOUT:-1h}"
EXEMPT="${EXEMPT:-}" # operator address; comma-separated IPv4

NFT_FILE=/etc/nftables.d/agenttrap-decoy.nft
UNIT=agenttrap-decoy-firewall.service
UNIT_FILE="/etc/systemd/system/${UNIT}"

case "${1:-}" in
--remove)
	systemctl disable --now "$UNIT" 2>/dev/null || true
	rm -f "$UNIT_FILE" "$NFT_FILE"
	systemctl daemon-reload 2>/dev/null || true
	nft delete table inet agenttrap_decoy 2>/dev/null || true
	echo "removed: decoy firewall table, nft file and systemd unit"
	exit 0
	;;
--status)
	echo "== rule =="
	nft list table inet agenttrap_decoy 2>/dev/null || echo "not installed"
	echo "== banned sources =="
	nft list set inet agenttrap_decoy flood4 2>/dev/null | sed -n '/elements/,/}/p' || true
	nft list set inet agenttrap_decoy flood6 2>/dev/null | sed -n '/elements/,/}/p' || true
	exit 0
	;;
"") ;;
*)
	echo "unknown option: $1" >&2
	exit 2
	;;
esac

[[ $EUID -eq 0 ]] || {
	echo "run as root (sudo)" >&2
	exit 1
}

# portset "22 6379" -> "{ 22, 6379 }"
portset() {
	read -ra p <<<"${1//,/ }"
	printf '{ %s }' "$(
		IFS=,
		echo "${p[*]}"
	)"
}
STRICT_SET="$(portset "$STRICT_PORTS")"
WEB_SET="$(portset "$WEB_PORTS")"
ALL_SET="$(portset "$STRICT_PORTS $WEB_PORTS")"

# Accept rules for exempt sources across every managed port.
EXEMPT_RULES=""
IFS=',' read -ra ips <<<"$EXEMPT"
for ip in "${ips[@]}"; do
	ip="$(echo "$ip" | xargs)"
	[[ -n "$ip" ]] && EXEMPT_RULES+="		ip saddr ${ip} tcp dport ${ALL_SET} counter accept
"
done

# ban_rules PORTSET RATE BURST -> the v4/v6 rate-triggered ban rules.
ban_rules() {
	local set="$1" rate="$2" burst="$3"
	cat <<EOF
		meta nfproto ipv4 tcp dport ${set} tcp flags & (fin|syn|rst|ack) == syn \\
			limit rate over ${rate} burst ${burst} packets \\
			add @flood4 { ip saddr } counter drop
		meta nfproto ipv6 tcp dport ${set} tcp flags & (fin|syn|rst|ack) == syn \\
			limit rate over ${rate} burst ${burst} packets \\
			add @flood6 { ip6 saddr } counter drop
EOF
}

mkdir -p /etc/nftables.d
# The empty-then-delete pattern makes the reload idempotent: it clears any
# previous version of our table without erroring when it does not yet exist.
cat >"$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
table inet agenttrap_decoy {}
delete table inet agenttrap_decoy

table inet agenttrap_decoy {
	set flood4 { type ipv4_addr; flags dynamic, timeout; timeout ${BAN_TIMEOUT}; }
	set flood6 { type ipv6_addr; flags dynamic, timeout; timeout ${BAN_TIMEOUT}; }

	# Runs after conntrack, before Docker's DNAT (priority -100), so a dropped
	# packet never reaches the relay or edge proxy.
	chain prerouting {
		type filter hook prerouting priority -150; policy accept;

${EXEMPT_RULES}		# Already-banned sources: drop before anything else.
		tcp dport ${ALL_SET} ip saddr @flood4 counter drop
		tcp dport ${ALL_SET} ip6 saddr @flood6 counter drop

		# Decoy ports: strict rate.
$(ban_rules "$STRICT_SET" "$STRICT_RATE" "$STRICT_BURST")
		# Web ports: only a genuine connection flood.
$(ban_rules "$WEB_SET" "$WEB_RATE" "$WEB_BURST")
	}
}
EOF

nft -f "$NFT_FILE"

cat >"$UNIT_FILE" <<EOF
[Unit]
Description=AgentTrap public-port rate-ban (nftables)
After=docker.service nftables.service
Wants=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${NFT_FILE}
ExecStop=/usr/sbin/nft delete table inet agenttrap_decoy

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$UNIT" >/dev/null 2>&1 || systemctl enable "$UNIT"

echo "installed: rate-ban on decoy ports [${STRICT_PORTS}] >${STRICT_RATE}, web ports [${WEB_PORTS}] >${WEB_RATE}, ban ${BAN_TIMEOUT}"
echo "real sshd on 2222 is untouched. remove with: sudo $0 --remove"
nft list table inet agenttrap_decoy
