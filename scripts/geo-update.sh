#!/bin/sh
# Refreshes the DB-IP Lite City geolocation database used by the attack map.
# DB-IP publishes a new free database monthly; a weekly run keeps it current
# without manual steps. DB-IP Lite is CC-BY-4.0 (the map carries the "IP
# geolocation by DB-IP" attribution). The hub reopens the file on restart.
set -eu
app=$(cd "$(dirname "$0")/.." && pwd)
GEO_DIR=${GEO_DIR:-/opt/agenttrap/geo}
dest="$GEO_DIR/dbip-city-lite.mmdb"
mkdir -p "$GEO_DIR"

# Try the current month, then the previous one (early in a month the new file
# may not be published yet), writing to a temp file in the same directory so
# the swap into place is atomic.
tmp=$(mktemp "$GEO_DIR/.dbip.XXXXXX")
trap 'rm -f "$tmp" "$tmp.gz"' EXIT
ok=0
for m in "$(date -u +%Y-%m)" "$(date -u -d '1 month ago' +%Y-%m 2>/dev/null || echo '')"; do
  [ -n "$m" ] || continue
  url="https://download.db-ip.com/free/dbip-city-lite-$m.mmdb.gz"
  if curl -fsSL --max-time 600 "$url" -o "$tmp.gz" && gunzip -f "$tmp.gz"; then
    mv "$tmp" "$dest"
    ok=1
    echo "installed dbip-city-lite $m ($(du -h "$dest" | cut -f1))"
    break
  fi
done
[ "$ok" = 1 ] || { echo "geo-update: could not download a database" >&2; exit 1; }

# The hub mmaps the database at startup, so restart it to pick up the new file.
cd "$app" && docker compose restart hub >/dev/null 2>&1 && echo "hub restarted with the refreshed geolocation database"
