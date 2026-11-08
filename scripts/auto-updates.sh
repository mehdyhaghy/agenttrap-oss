#!/usr/bin/env bash
# Nightly unattended upgrades with automatic reboot when needed. Run as root
# on the server (idempotent):
#
#   scripts/auto-updates.sh
#
# Package lists refresh at 02:30 and upgrades run at 03:00 US Central time
# (America/Chicago, so it follows CST/CDT). Security and regular Ubuntu
# updates are installed, which includes Docker (docker.io comes from the
# Ubuntu archive). If an upgrade needs a reboot, the server reboots right
# after it; every container has restart: unless-stopped and comes back.
# The nightly backup (03:17 UTC) does not overlap.
set -euo pipefail

apt-get install -y -q unattended-upgrades >/dev/null

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat >/etc/apt/apt.conf.d/52agenttrap-unattended <<'EOF'
// Set by scripts/auto-updates.sh. Adds regular updates to the security
// origins in 50unattended-upgrades and reboots when an upgrade needs it.
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "now";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Dpkg::Options {
	"--force-confdef";
	"--force-confold";
};
EOF

timer() { # unit, time
  mkdir -p "/etc/systemd/system/$1.timer.d"
  cat >"/etc/systemd/system/$1.timer.d/agenttrap.conf" <<EOF
# Set by scripts/auto-updates.sh
[Timer]
OnCalendar=
OnCalendar=*-*-* $2 America/Chicago
RandomizedDelaySec=0
Persistent=true
EOF
}
timer apt-daily 02:30
timer apt-daily-upgrade 03:00
systemctl daemon-reload
systemctl restart apt-daily.timer apt-daily-upgrade.timer

echo "== timers"
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager | head -3
echo "== dry run"
unattended-upgrade --dry-run -d 2>&1 | grep -E "Allowed origins|Packages that will be upgraded|No packages found" | head -3
