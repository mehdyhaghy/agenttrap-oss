#!/bin/sh
# Keeps container logs across restarts, redeploys and reboots.
#
# docker-compose.yml sends every container's output to journald (tag = the
# container name). By default the journal may live only in /run, which is
# lost on reboot; this makes it persistent under /var/log/journal and caps its
# size and age so a flood of access logs cannot fill the disk.
#
# Usage:
#   sudo ./persistent-logs.sh            install / update (idempotent)
#   sudo ./persistent-logs.sh --status   show journal usage, boots and container logs
#
# Tunables (env): JOURNAL_MAX_USE (default 2G), JOURNAL_RETENTION (default 90day).
#
# Reading logs afterwards:
#   docker compose logs --since 1h hub
#   journalctl CONTAINER_NAME=agenttrap-hub-1 --since yesterday
#   journalctl CONTAINER_TAG=agenttrap-spoke-1 -b -1    # previous boot
#   journalctl -u docker --since today                   # the Docker daemon itself
set -eu

JOURNAL_MAX_USE=${JOURNAL_MAX_USE:-2G}
JOURNAL_RETENTION=${JOURNAL_RETENTION:-90day}
CONF_DIR=/etc/systemd/journald.conf.d
CONF="$CONF_DIR/agenttrap.conf"

status() {
	echo "== journal"
	journalctl --disk-usage
	if [ -d /var/log/journal ] && [ -n "$(ls -A /var/log/journal 2>/dev/null)" ]; then
		echo "  persistent: yes (/var/log/journal)"
	else
		echo "  persistent: NO (journal lives in /run and is lost on reboot)"
	fi
	[ -f "$CONF" ] && sed 's/^/  /' "$CONF"
	echo "== boots kept"
	journalctl --list-boots --no-pager 2>/dev/null | tail -5
	echo "== container logs"
	echo "  docker logging driver (hub): $(docker inspect -f '{{.HostConfig.LogConfig.Type}}' agenttrap-hub-1 2>/dev/null || echo 'hub not running')"
	for c in agenttrap-hub-1 agenttrap-spoke-1 agenttrap-pingap-1; do
		n=$(journalctl CONTAINER_NAME="$c" --since -24h -q --no-pager 2>/dev/null | wc -l | tr -d ' ')
		echo "  $c: $n journal line(s) in the last 24h"
	done
	journalctl CONTAINER_NAME=agenttrap-hub-1 -n 3 -q --no-pager 2>/dev/null | cut -c1-200
}

case "${1:-}" in
--status)
	status
	exit 0
	;;
"") ;;
*)
	echo "usage: $0 [--status]" >&2
	exit 2
	;;
esac

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

mkdir -p /var/log/journal "$CONF_DIR"
want=$(printf '%s\n' \
	"# Managed by agenttrap scripts/persistent-logs.sh" \
	"[Journal]" \
	"Storage=persistent" \
	"SystemMaxUse=$JOURNAL_MAX_USE" \
	"MaxRetentionSec=$JOURNAL_RETENTION" \
	"RateLimitIntervalSec=0")
if [ "$(cat "$CONF" 2>/dev/null)" != "$want" ]; then
	printf '%s\n' "$want" >"$CONF"
	systemd-tmpfiles --create --prefix /var/log/journal
	systemctl restart systemd-journald
	# Move what is still in /run into the persistent store.
	journalctl --flush
	echo "journald: persistent, max $JOURNAL_MAX_USE, kept $JOURNAL_RETENTION"
else
	echo "journald: already persistent, max $JOURNAL_MAX_USE, kept $JOURNAL_RETENTION"
fi
echo "Containers pick up the journald log driver when recreated: docker compose up -d --force-recreate"
