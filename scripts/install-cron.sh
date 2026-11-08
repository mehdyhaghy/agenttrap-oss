#!/bin/sh
# Installs the backup (daily 03:17 UTC), restore test (Sundays 05:11 UTC),
# cleanup (Sundays 04:23 UTC), export
# snapshot (daily 06:55 UTC), findings digest (daily 07:05 UTC),
# ingest alert + contact-form forwarding (every 5 minutes) and attack-map geolocation refresh
# (Sundays 05:40 UTC) jobs.
set -eu
app=$(cd "$(dirname "$0")/.." && pwd)
cat > /etc/cron.d/agenttrap <<CRON
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 3 * * * root $app/scripts/backup.sh >> /var/log/agenttrap-backup.log 2>&1
23 4 * * 0 root $app/scripts/prune.sh >> /var/log/agenttrap-prune.log 2>&1
11 5 * * 0 root $app/scripts/restore.sh check >> /var/log/agenttrap-restore-check.log 2>&1
55 6 * * * root $app/scripts/export.sh >> /var/log/agenttrap-export.log 2>&1
5 7 * * * root $app/scripts/digest.sh >> /var/log/agenttrap-digest.log 2>&1
*/5 * * * * root $app/scripts/notify.sh >> /var/log/agenttrap-notify.log 2>&1
40 5 * * 0 root $app/scripts/geo-update.sh >> /var/log/agenttrap-geo.log 2>&1
CRON
chmod 644 /etc/cron.d/agenttrap
echo "installed /etc/cron.d/agenttrap"
