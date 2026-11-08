# Attack-map geolocation database

The admin attack map geolocates attacker IPs with **DB-IP Lite City** in MMDB
format. The file is not committed (it is ~40 MB and updated monthly) and is not
baked into the image — it is a host file mounted read-only into the hub, like
the TLS certs and secrets. When it is absent the map is simply disabled; nothing
else changes.

DB-IP Lite is licensed **CC-BY-4.0**, so the admin UI shows an "IP geolocation
by DB-IP" attribution. Do not remove it.

## Setup

Download the current month's free database (the "IP to City Lite" MMDB) from
https://db-ip.com/db/download/ip-to-city-lite and place it here as
`dbip-city-lite.mmdb`:

```sh
# example (check the site for the current month's URL)
curl -L -o dbip-city-lite.mmdb.gz https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz
gunzip dbip-city-lite.mmdb.gz
```

**Production:** keep the file outside the git checkout (which `git archive`
overwrites on every deploy). Put it at `/opt/agenttrap/geo/dbip-city-lite.mmdb`
and set `GEO_DIR=/opt/agenttrap/geo` in `/opt/agenttrap/app/.env`, then
`docker compose up -d hub`. A monthly cron can refresh it.

The hub reads `AGENTTRAP_GEO_DB` (default `/geo/dbip-city-lite.mmdb`, the mount
point of `GEO_DIR`).
