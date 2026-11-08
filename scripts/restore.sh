#!/bin/sh
# Restores backups written by backup.sh.
#
#   restore.sh check [DUMP]        restore DUMP (default: newest) into a scratch
#                                  database, report row counts, drop it. Safe
#                                  to run any time; cron runs it weekly.
#   restore.sh db DUMP --yes       replace the live database with DUMP. Takes a
#                                  backup of the current state first.
#   restore.sh state STATE --yes   put back PKI, spoke identity, secrets/, .env,
#                                  certificates and notifier state (new server,
#                                  or lost volumes). Stops the stack first.
#
# New server, from a backup pair (see README "Backup and restore"):
#   scripts/provision.sh; copy the app to /opt/agenttrap/app; copy the pair
#   to /opt/agenttrap/backups; then
#   scripts/restore.sh state <stamp>.state.tar.gz --yes
#   docker compose up -d --build postgres
#   scripts/restore.sh db <stamp>.dump --yes
#
# The hub rebuilds the link graph from the restored events on its own.
set -eu
umask 077
cd "$(dirname "$0")/.."
. ./scripts/lib.sh
dir=${BACKUP_DIR:-/opt/agenttrap/backups}

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
psql_admin() { docker compose exec -T postgres psql -U agenttrap -d postgres -v ON_ERROR_STOP=1 -qtA "$@"; }
counts() {
  docker compose exec -T postgres psql -U agenttrap -d "$1" -qtA -F ' ' -c "
    SELECT 'events', count(*), coalesce(max(ts)::text, '-') FROM events
    UNION ALL SELECT 'spokes', count(*), '' FROM spokes
    UNION ALL SELECT 'incidents', count(*), '' FROM incidents
    UNION ALL SELECT 'operators', count(*), '' FROM operators
    UNION ALL SELECT 'replay_chunks', count(*), '' FROM replay_chunks" </dev/null
}
newest() { ls -t "$dir"/agenttrap-*.dump 2>/dev/null | head -1; }
# resolve FILE: a path, or a name inside the backup directory
resolve() {
  if [ -f "$1" ]; then echo "$1"; elif [ -f "$dir/$1" ]; then echo "$dir/$1"; else echo "no such backup: $1" >&2; exit 1; fi
}

mode=${1:-}
case "$mode" in
check)
  dump=$(resolve "${2:-$(newest)}")
  scratch="restorecheck_$$"
  trap 'psql_admin -c "DROP DATABASE IF EXISTS $scratch WITH (FORCE)" </dev/null >/dev/null 2>&1 || true' EXIT
  psql_admin -c "CREATE DATABASE $scratch" </dev/null
  docker compose exec -T postgres pg_restore -U agenttrap -d "$scratch" --exit-on-error --no-owner < "$dump"
  echo "restore check: $dump"
  counts "$scratch" | sed 's/^/  /'
  n=$(counts "$scratch" | awk '$1 == "spokes" { print $2 }')
  [ "${n:-0}" -gt 0 ] || { echo "FAIL: no spokes in the restored database" >&2; exit 1; }
  echo "restore check passed"
  ;;
db)
  [ "${3:-}" = "--yes" ] || usage
  dump=$(resolve "$2")
  docker compose up -d postgres </dev/null
  until docker compose exec -T postgres pg_isready -U agenttrap -d postgres </dev/null >/dev/null 2>&1; do sleep 2; done
  if psql_admin -c "SELECT 1 FROM pg_database WHERE datname = 'agenttrap'" </dev/null | grep -q 1; then
    echo "backing up the current state first"
    scripts/backup.sh
  fi
  echo "stopping the services that write to the database"
  docker compose stop hub spoke ja4-sensor </dev/null
  psql_admin -c "DROP DATABASE IF EXISTS agenttrap WITH (FORCE)" -c "CREATE DATABASE agenttrap OWNER agenttrap" </dev/null
  docker compose exec -T postgres pg_restore -U agenttrap -d agenttrap --exit-on-error --no-owner < "$dump"
  # The role's password lives in the cluster, not the dump: match secrets/.
  printf "ALTER ROLE agenttrap PASSWORD :'pw';\n" |
    docker compose exec -T postgres psql -U agenttrap -d postgres -v ON_ERROR_STOP=1 -q -v pw="$(cat secrets/db_password)"
  echo "restored $dump:"
  counts agenttrap | sed 's/^/  /'
  docker compose up -d </dev/null
  echo "services started; the hub rebuilds the link graph from events. Check with scripts/verify-deploy.sh"
  ;;
state)
  [ "${3:-}" = "--yes" ] || usage
  archive=$(resolve "$2")
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  tar -xzf "$archive" -C "$work"
  [ -d "$work/volumes" ] && [ -d "$work/files/secrets" ] || { echo "not a state archive: $archive" >&2; exit 1; }
  echo "stopping the stack (volumes are kept)"
  docker compose stop </dev/null
  for v in $STATE_VOLUMES; do
    if [ -f "$work/volumes/$v.tar.gz" ]; then load_volume "$v" "$work/volumes/$v.tar.gz"; echo "  volume $v restored"; fi
  done
  stamp=$(date -u +%Y%m%dT%H%MZ)
  for f in secrets .env; do
    if [ -e "$f" ]; then mv "$f" "$f.pre-restore-$stamp"; fi
    cp -a "$work/files/$f" "$f"
    echo "  $f restored"
  done
  for d in pingap state; do
    if [ -d "$work/files/$d" ]; then
      mkdir -p "$ROOT"
      if [ -d "$ROOT/$d" ]; then mv "$ROOT/$d" "$ROOT/$d.pre-restore-$stamp"; fi
      cp -a "$work/files/$d" "$ROOT/$d"
      echo "  $ROOT/$d restored"
    fi
  done
  echo "state restored. Next: scripts/restore.sh db <dump> --yes (or docker compose up -d if the database is intact)"
  ;;
*)
  usage
  ;;
esac
