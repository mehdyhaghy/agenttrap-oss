#!/bin/sh
# Checks a running single-node deployment. Run on the server from the repo root:
#   ./scripts/verify-deploy.sh
# Then send a request from ANOTHER machine and run it again to confirm that the
# real client IP and a JA4 fingerprint are recorded.
set -u
cd "$(dirname "$0")/.."
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }
dc() { docker compose "$@"; }
sql() { dc exec -T postgres psql -U agenttrap -d agenttrap -tAc "$1" 2>/dev/null; }

echo "== containers"
for s in postgres hub spoke pingap ja4-sensor resolver; do
  st=$(dc ps --format '{{.Service}} {{.State}}' | awk -v s="$s" '$1==s{print $2}')
  [ "$st" = "running" ] && ok "$s running" || bad "$s is '${st:-missing}'"
done

echo "== build tooling"
docker buildx version >/dev/null 2>&1 && ok "BuildKit (docker-buildx) installed" || bad "docker-buildx missing: builds use the legacy builder (run scripts/provision.sh)"

echo "== sensor privileges"
pid=$(docker inspect -f '{{.State.Pid}}' "$(dc ps -q ja4-sensor)" 2>/dev/null)
capeff=$(awk '/^CapEff/{print $2}' "/proc/$pid/status" 2>/dev/null)
[ "$capeff" = "0000000000002000" ] && ok "ja4-sensor has only CAP_NET_RAW" || bad "ja4-sensor CapEff=$capeff (want 0000000000002000)"
dc logs ja4-sensor 2>&1 | grep -q 'ja4 sensor running' && ok "ja4-sensor started" || bad "ja4-sensor did not start (see: docker compose logs ja4-sensor)"

echo "== exposure"
ports=$(ss -ltnH | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|127\.0\.0\.5)' | sed 's/.*://' | sort -un | tr '\n' ' ')
echo "  public listening ports: $ports"
# Internal ports that must never be reachable from the internet.
for p in 8443 9090 8080 8081; do
  echo " $ports " | grep -q " $p " && bad "port $p is listening publicly" || ok "port $p not public"
done
# Decoy ports 22/6379/5432 ARE public by design, but they must reach the decoy
# relays, never the real database or cache. The real Postgres publishes no port
# (only on the internal core network); the public 5432 is the pg-relay decoy.
pgpub=$(dc port postgres 5432 2>/dev/null)
case "$pgpub" in
"" | :0 | 0.0.0.0:0) ok "real Postgres publishes no public port" ;;
*) bad "real Postgres is published to the host ($pgpub) — it must stay on the internal core network" ;;
esac
pgnets=$(docker inspect "$(dc ps -q postgres)" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
echo " $pgnets " | grep -qE ' agenttrap_(edge|facade) ' && bad "real Postgres is on an edge/facade network: $pgnets" || ok "real Postgres is only on internal networks ($pgnets)"
echo " $pgnets " | grep -q ' agenttrap_core ' && ok "real Postgres is on the core network" || bad "real Postgres not on core network"

echo "== isolation"
for n in core hubnet facade enrichnet; do
  docker run --rm --network "agenttrap_$n" busybox:1.37 wget -q -T 4 -O /dev/null http://1.1.1.1 >/dev/null 2>&1 \
    && bad "network $n can reach the internet" || ok "network $n has no internet egress"
done
# The resolver has internet access, so it must not share a network with PostgreSQL.
docker inspect "$(dc ps -q resolver)" -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | grep -q agenttrap_core \
  && bad "resolver is on the core network (can reach PostgreSQL)" || ok "resolver is isolated from PostgreSQL"
# The spoke runs the SSH/Redis/Postgres decoys; it must not reach the real DB.
docker inspect "$(dc ps -q spoke)" -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | grep -q agenttrap_core \
  && bad "spoke is on the core network (decoys could reach the real database)" || ok "spoke (decoys) is isolated from the real database"
code=$(docker run --rm --network agenttrap_facade busybox:1.37 wget -q -S -O /dev/null --post-data '{}' http://spoke:8081/sensor/tls 2>&1 | awk '/HTTP\//{print $2; exit}')
[ "$code" = "403" ] && ok "spoke rejects sensor reports from other containers" || bad "fake sensor report got '$code' (want 403)"

echo "== cloud decoy"
# Test the aws and k8s surfaces over real HTTPS through Pingap (the way a client
# reaches them): the spoke redirects plain HTTP to HTTPS, so an internal HTTP
# probe only sees a 301. The AWS endpoint must answer as S3 and refuse an
# unsigned request the way private buckets do; the Kubernetes API must serve
# /version to anyone but require the token for resources.
awshdr=$(curl -sS --max-time 12 -D - -o /dev/null https://aws.demogpu.example/ 2>/dev/null)
echo "$awshdr" | grep -qi 'server: AmazonS3' && ok "aws.demogpu.example answers as S3 over HTTPS (not nginx)" || bad "aws decoy not answering as S3 (check spoke/pingap/DNS)"
echo "$awshdr" | grep -qE ' 403( |$)' && ok "unsigned S3 access denied (buckets are private)" || bad "aws decoy did not deny an unsigned request"
kubever=$(curl -sS --max-time 12 https://k8s.demogpu.example/version 2>/dev/null)
echo "$kubever" | grep -q 'gitVersion' && ok "k8s.demogpu.example serves the API version over HTTPS" || bad "k8s decoy not answering /version (check spoke/pingap/DNS)"
kubecode=$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://k8s.demogpu.example/api/v1/secrets 2>/dev/null)
[ "$kubecode" = "401" ] && ok "unauthenticated k8s secret list is refused (401)" || bad "k8s decoy did not require a token for secrets (got ${kubecode:-none})"

echo "== data"
echo "  events: $(sql 'select count(*) from events')   tls_hello: $(sql "select count(*) from events where kind='tls_hello'")   incidents: $(sql 'select count(*) from incidents')"
echo "  recent sources (should be real client IPs, not private Docker addresses):"
sql "select '    ' || source || '  ' || coalesce(detail->>'ja4','-') || '  ' || left(user_agent,30) from events where kind='request' order by ts desc limit 5"
bridge=$(sql "select count(*) from events where kind='request' and source ~ '^[0-9.]+\$' and source::inet <<= any('{10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}'::inet[]) and ts > now() - interval '1 hour'")
[ "${bridge:-0}" = "0" ] && ok "no private addresses recorded as clients in the last hour" || bad "$bridge requests recorded with a private (Docker) address as client IP"

echo "== logs"
drv=$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$(dc ps -q hub)" 2>/dev/null)
[ "$drv" = "journald" ] && ok "container logs go to journald (kept across redeploys)" || bad "hub log driver is '${drv:-unknown}' (want journald: docker compose up -d --force-recreate)"
grep -qs '^Storage=persistent' /etc/systemd/journald.conf.d/agenttrap.conf && [ -d /var/log/journal ] \
  && ok "journal is persistent ($(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]?B?' | head -1) used)" \
  || bad "journal is not persistent: logs are lost on reboot (run scripts/persistent-logs.sh)"

echo "== ingestion"
# A stalled spoke->hub pipeline makes everything else undercount silently.
qroot=$(docker volume inspect agenttrap_spokedata --format '{{.Mountpoint}}' 2>/dev/null)/spoke/queue
if [ -d "$qroot" ]; then
  queued=$(find "$qroot" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')
  held=$(find "$qroot/rejected" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  [ "$queued" -lt 30 ] && ok "spoke queue drained ($queued batch(es) waiting)" || bad "$queued event batches stuck on the spoke (hub not accepting them?)"
  [ "$held" -eq 0 ] && ok "no batches refused by the hub" || bad "$held refused batch(es) set aside in $qroot/rejected — an ingest bug to read"
else
  bad "spoke queue directory not found ($qroot)"
fi
recent=$(dc logs --since 10m hub 2>/dev/null | grep -c '"ingest failed"')
[ "$recent" -eq 0 ] && ok "no ingest failures in the hub log (10 min)" || bad "$recent ingest failures in the hub log in the last 10 minutes"
health=$(curl -sS --max-time 10 -H "Authorization: Bearer $(cat secrets/admin_token)" http://10.90.0.5:9090/admin/health 2>/dev/null)
case "$health" in
  *'"ok":true'*) ok "hub reports ingestion healthy" ;;
  *) bad "hub ingest health: ${health:-no answer from the admin API}" ;;
esac

age=$(sql "select extversion from pg_extension where extname='age'")
[ -n "$age" ] && ok "graph extension Apache AGE $age installed" || bad "Apache AGE missing: postgres is not the deploy/postgres image"
links=$(sql "select count(*) from links.\"LINK\"")
[ -n "$links" ] && ok "link graph has $links edges" || bad "link graph not created (see hub log: 'link graph disabled')"

bdir=${BACKUP_DIR:-/opt/agenttrap/backups}
newest=$(ls -t "$bdir"/agenttrap-*.dump 2>/dev/null | head -1)
if [ -n "$newest" ] && [ -n "$(find "$newest" -mmin -1560)" ] && [ -f "${newest%.dump}.state.tar.gz" ]; then
  ok "backup pair from the last 26 hours ($(basename "$newest" .dump))"
else
  bad "no database + state backup pair in the last 26 hours in $bdir (run scripts/backup.sh)"
fi
if grep -q "restore check passed" /var/log/agenttrap-restore-check.log 2>/dev/null &&
   ! tail -3 /var/log/agenttrap-restore-check.log | grep -q FAIL; then
  ok "last weekly restore test passed"
else
  echo "  NOTE  no weekly restore test yet (Sundays 05:11 UTC; run scripts/restore.sh check)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
