#!/bin/sh
# Nightly backup, kept 7 days on the server. Each run writes a pair:
#   agenttrap-<stamp>.dump          the database (pg_dump custom format)
#   agenttrap-<stamp>.state.tar.gz  what is not in the database: hub PKI and
#                                   pack signing key, spoke identity and queue,
#                                   secrets/, .env, TLS certificates, notifier state
# Restore with scripts/restore.sh. Copy the pair somewhere off the server as
# well: a lost droplet takes these with it. Both files hold secrets (0600).
#
# The link graph (Apache AGE) is left out of the dump: AGE graphs do not
# survive pg_restore, and the hub rebuilds the graph from events when it
# finds it empty. stdin is closed on every docker call so the script never
# swallows a caller's input.
set -eu
umask 077
cd "$(dirname "$0")/.."
. ./scripts/lib.sh

dir=${BACKUP_DIR:-/opt/agenttrap/backups}
mkdir -p "$dir" && chmod 700 "$dir"
stamp=$(date -u +%Y-%m-%dT%H%MZ)
db="$dir/agenttrap-$stamp.dump"
state="$dir/agenttrap-$stamp.state.tar.gz"
work=$(mktemp -d)
trap 'rm -rf "$work" "$db.tmp" "$state.tmp"' EXIT

docker compose exec -T postgres pg_dump -U agenttrap -Fc --exclude-extension=age -N links agenttrap \
  </dev/null > "$db.tmp"
# A dump that pg_restore cannot read end to end is not a backup.
docker compose exec -T postgres pg_restore --list < "$db.tmp" > /dev/null

mkdir -p "$work/volumes" "$work/files"
for v in $STATE_VOLUMES; do
  save_volume "$v" "$work/volumes/$v.tar.gz"
done
cp -a secrets .env "$work/files/"
for d in pingap state; do
  if [ -d "$ROOT/$d" ]; then cp -a "$ROOT/$d" "$work/files/$d"; fi
done
tar -czf "$state.tmp" -C "$work" volumes files

mv "$db.tmp" "$db" && mv "$state.tmp" "$state"
find "$dir" -name 'agenttrap-*' -mtime +7 -delete
echo "backup: $db ($(du -h "$db" | cut -f1)), $state ($(du -h "$state" | cut -f1))"
