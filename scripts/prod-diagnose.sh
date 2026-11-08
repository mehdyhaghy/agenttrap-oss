#!/bin/sh
# Read-only health and log-pattern summary of a running deployment. Run on the
# server from the app directory and paste the output back:
#   cd /opt/agenttrap/app && ./scripts/prod-diagnose.sh 2>&1 | tee /tmp/agenttrap-diag.txt
# Changes nothing and prints no secrets. Works with json-file or journald logs.
# Window (env): SINCE (default 24h).
set -u
cd "$(dirname "$0")/.." || exit 1
SINCE=${SINCE:-24h}
dc() { docker compose "$@"; }
sql() { dc exec -T postgres psql -U agenttrap -d agenttrap -tA -F ' | ' -c "$1" 2>/dev/null; }
hdr() { printf '\n== %s\n' "$1"; }
ind() { sed 's/^/  /'; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

hdr "host"
echo "  $(date -u '+%Y-%m-%d %H:%M UTC')  $(uptime | sed 's/^ *//')"
df -h / /var/lib/docker 2>/dev/null | awk 'NR==1 || !seen[$0]++' | ind
free -m | head -2 | ind

hdr "containers (state, restarts, started)"
for id in $(dc ps -aq); do
  docker inspect -f '{{.Name}}  {{.State.Status}}  restarts={{.RestartCount}}  started={{.State.StartedAt}}  log={{.HostConfig.LogConfig.Type}}' "$id"
done | sed 's#^/##' | sort | ind

hdr "logging"
echo "  docker default driver: $(docker info --format '{{.LoggingDriver}}' 2>/dev/null)"
if [ -d /var/log/journal ] && [ -n "$(ls -A /var/log/journal 2>/dev/null)" ]; then
  echo "  journal persistent: yes  ($(journalctl --disk-usage 2>/dev/null | sed 's/.*take up //'))"
else
  echo "  journal persistent: NO (lost on reboot)"
fi
echo "  boots kept: $(journalctl --list-boots --no-pager 2>/dev/null | grep -c .)"

hdr "ingestion"
health=$(curl -sS --max-time 10 -H "Authorization: Bearer $(cat secrets/admin_token)" http://10.90.0.5:9090/admin/health 2>&1)
echo "$health" | head -c 1500 | ind; echo
qroot=$(docker volume inspect agenttrap_spokedata --format '{{.Mountpoint}}' 2>/dev/null)/spoke/queue
echo "  queued batches: $(find "$qroot" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')   rejected: $(find "$qroot/rejected" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"

# One pass over each service's logs for the window.
svcs=$(dc config --services 2>/dev/null)
for s in $svcs; do
  dc logs --no-color --no-log-prefix --since "$SINCE" "$s" >"$TMP/$s.log" 2>/dev/null
done

hdr "log volume and levels (last $SINCE)"
printf '  %-12s %8s %6s %6s\n' service lines ERROR WARN
for s in $svcs; do
  f="$TMP/$s.log"
  printf '  %-12s %8s %6s %6s\n' "$s" "$(wc -l <"$f" | tr -d ' ')" \
    "$(grep -ciE '"level":"ERROR"|\bERROR\b' "$f")" "$(grep -ciE '"level":"WARN"|\bWARN(ING)?\b' "$f")"
done
echo "  hub 'ingest failed': $(grep -c 'ingest failed' "$TMP/hub.log" 2>/dev/null)   spoke 'shipping to hub failed': $(grep -c 'shipping to hub failed' "$TMP/spoke.log" 2>/dev/null)"

hdr "top error/warn messages (normalized)"
for s in $svcs; do
  grep -hiE '"level":"(ERROR|WARN)"|\b(ERROR|WARN|panic|fatal)\b' "$TMP/$s.log" 2>/dev/null | sed "s/^/$s: /"
done |
  sed -E 's/"time":"[^"]*",?//; s/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?//g;
          s/([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?/<ip>/g; s/[0-9a-f]{8,}/<hex>/g; s/[0-9]+/<n>/g' |
  cut -c1-180 | sort | uniq -c | sort -rn | head -15 | ind

hdr "app log messages (top 15, hub + spoke)"
cat "$TMP/hub.log" "$TMP/spoke.log" 2>/dev/null | grep -oE '"msg":"[^"]*"' | sort | uniq -c | sort -rn | head -15 | ind

# Pingap access log (combined): ip - - [date] "METHOD path proto" status bytes "ref" "ua"
acc="$TMP/access.log"
grep -E '"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|PROPFIND|[A-Z]+) [^"]* HTTP/[0-9.]+"' "$TMP/pingap.log" 2>/dev/null >"$acc"
hdr "web access (pingap, last $SINCE): $(wc -l <"$acc" | tr -d ' ') requests"
echo "  status codes:"
sed -nE 's/.*"[A-Z]+ [^"]*" ([0-9]{3}) .*/\1/p' "$acc" | sort | uniq -c | sort -rn | head -10 | ind
echo "  methods:"
sed -nE 's/.*"([A-Z]+) [^"]* HTTP[^"]*".*/\1/p' "$acc" | sort | uniq -c | sort -rn | head -8 | ind
echo "  top 20 paths (query stripped):"
sed -nE 's/.*"[A-Z]+ ([^" ?]*)[^"]* HTTP[^"]*".*/\1/p' "$acc" | cut -c1-100 | sort | uniq -c | sort -rn | head -20 | ind
echo "  top 10 user agents:"
sed -nE 's/.*"([^"]*)"[[:space:]]*$/\1/p' "$acc" | cut -c1-110 | sort | uniq -c | sort -rn | head -10 | ind
echo "  top 15 sources:"
grep -oE '^[^"]*' "$acc" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f]*:[0-9a-f:]+' | head -n 1000000 |
  awk '{print $1}' | sort | uniq -c | sort -rn | head -15 | ind
echo "  probe families:"
for p in '\.php' '/\.env' '/wp-' '/cgi-bin' '/\.git' 'PHP_SESSION_UPLOAD_PROGRESS|PHPSESSID' '/actuator|/solr|/jenkins' '/(admin|manager|phpmyadmin)'; do
  printf '    %-42s %s\n' "$p" "$(grep -ciE "\"[A-Z]+ [^\"]*($p)" "$acc")"
done
echo "  POST requests: $(grep -c '"POST ' "$acc")"

hdr "events by protocol and kind (last $SINCE, from the database)"
sql "select protocol, kind, count(*), count(distinct source) as sources from events where ts > now() - interval '$SINCE' group by 1,2 order by 3 desc limit 25" | ind
echo "  multipart POSTs recorded: $(sql "select count(*) from events where ts > now() - interval '$SINCE' and method='POST' and detail->>'content_type' ilike 'multipart%'")"
echo "  decoy relays (ssh/redis/postgres) connections and sources:"
sql "select protocol, count(*) filter (where kind='connect') as connects, count(*) filter (where kind='auth') as auths, count(*) filter (where kind='throttled') as throttled, count(distinct source) as sources from events where ts > now() - interval '$SINCE' and protocol in ('ssh','redis','postgres') group by 1" | ind
echo "  exploit attempts recognized by modules:"
sql "select coalesce(detail->>'cve', detail->>'module', '?'), count(*), count(distinct source) from events where ts > now() - interval '$SINCE' and kind='exploit' group by 1 order by 2 desc limit 10" | ind
echo "  incidents active: $(sql "select string_agg(severity || '=' || n, ' ') from (select severity, count(*) n from incidents where last_seen > now() - interval '$SINCE' group by 1) x")"
echo "  events per hour (last 12h):"
sql "select to_char(date_trunc('hour', ts), 'MM-DD HH24:00'), count(*) from events where ts > now() - interval '12 hours' group by 1 order by 1" | ind

hdr "decoy firewall"
if [ -x scripts/decoy-firewall.sh ]; then
  scripts/decoy-firewall.sh --status 2>&1 | head -40 | ind
fi

hdr "host log signals (last $SINCE)"
echo "  OOM kills: $(journalctl -k --since "-$SINCE" -q --no-pager 2>/dev/null | grep -ci 'out of memory\|oom-kill')"
echo "  docker daemon errors: $(journalctl -u docker --since "-$SINCE" -q --no-pager 2>/dev/null | grep -c 'level=error')"
journalctl -u docker --since "-$SINCE" -q --no-pager 2>/dev/null | grep 'level=error' | sed -E 's/.*msg="([^"]*)".*/\1/' |
  sed -E 's/[0-9a-f]{12,}/<id>/g' | sort | uniq -c | sort -rn | head -5 | ind
echo "  last reboot: $(who -b 2>/dev/null | sed 's/^ *//')"
