#!/bin/sh
# Writes a dated snapshot of the exports (STIX 2.1, DNSBL zone, CSV, JSON
# Lines) to /opt/agenttrap/exports. Operator traffic is excluded. Runs a
# one-off container on the host network, like digest.sh.
set -eu
cd "$(dirname "$0")/.."
out=/opt/agenttrap/exports
mkdir -p "$out" && chmod 700 "$out" && chown 65532:65532 "$out"
exec docker run --rm --network host \
  -v "$PWD/secrets/admin_token:/run/secrets/admin_token:ro" -v "$out:/exports" \
  -e AGENTTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token \
  agenttrap:dev export --out /exports "$@"
