#!/bin/sh
# Weekly cleanup of build cache and unused images left by deploys.
set -eu
# BuildKit (docker-buildx) cache; the legacy builder's cache is not prunable.
docker builder prune -f --filter until=72h >/dev/null
# Images unused for a week, including old build bases (re-pulled when needed).
docker image prune -a -f --filter until=168h >/dev/null
df -h / | tail -1
