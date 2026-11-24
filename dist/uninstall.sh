#!/bin/sh
# Remove capsule from a Linux host:   sudo sh dist/uninstall.sh [--purge]
# Without --purge it removes the program, the systemd unit and the AppArmor
# profile, and leaves your settings and data alone. With --purge it also
# deletes /etc/capsule (including the host's secret and trusted keys) and
# /var/lib/capsule (including all volume data, snapshots and the log).
set -eu
[ "$(id -u)" = 0 ] || { echo "run this as root (sudo)"; exit 1; }
if [ -n "$(capsule ps 2>/dev/null | tail -n +2)" ]; then
  echo "capsules are still running; stop them first (capsule ps, capsule kill, systemctl stop 'capsule@*')"
  exit 1
fi
systemctl disable --now capsule-helper.socket capsule-orders.timer 2>/dev/null || true
rm -f /usr/local/bin/capsule /etc/systemd/system/capsule@.service /etc/systemd/system/capsule-orders.service \
  /etc/systemd/system/capsule-orders.timer /etc/systemd/system/capsule-helper.socket /etc/systemd/system/capsule-helper@.service \
  /etc/systemd/user/capsule-orders.service /etc/systemd/user/capsule-orders.timer
systemctl daemon-reload 2>/dev/null || true
if [ -f /etc/apparmor.d/capsule ]; then
  apparmor_parser -R /etc/apparmor.d/capsule 2>/dev/null || true
  rm -f /etc/apparmor.d/capsule
fi
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/capsule /var/lib/capsule /run/capsule /run/capsule-helper
  echo "removed capsule, its settings and its data"
else
  echo "removed capsule; settings in /etc/capsule and data in /var/lib/capsule were kept"
fi
