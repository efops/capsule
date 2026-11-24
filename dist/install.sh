#!/bin/sh
# Install capsule on a Linux host:   sudo sh dist/install.sh <path to the capsule binary>
# Puts the binary in /usr/local/bin, creates the directories capsule uses,
# installs the systemd units (the helper's socket is turned on; the timer that
# makes a host obey orders is not, until you enable it), and on hosts with AppArmor the profile that lets
# capsule run without root. Safe to run again to upgrade.
set -eu
[ "$(id -u)" = 0 ] || { echo "run this as root (sudo)"; exit 1; }
[ $# = 1 ] && [ -f "$1" ] || { echo "usage: sudo sh dist/install.sh <path to the capsule binary>"; exit 1; }
HERE=$(dirname "$(realpath "$0")")

[ "$(realpath "$1")" = /usr/local/bin/capsule ] || install -D -m 755 "$1" /usr/local/bin/capsule
install -d -m 755 /etc/capsule /etc/capsule/trust.d /etc/capsule/peers.d /etc/capsule/grants.d /etc/capsule/revoked.d \
  /etc/capsule/policy.d /etc/capsule/recovery.d /etc/capsule/apps
install -d -m 700 /var/lib/capsule
install -d -m 755 /var/lib/capsule/apps

install -d -m 755 /etc/capsule/operators.d
# Members of this group may use the helper: fast tunnels, sized and encrypted
# volumes, the encrypted store and ports below 1024, all without root.
getent group capsule >/dev/null 2>&1 || groupadd --system capsule 2>/dev/null || true

if [ -d /etc/systemd/system ]; then
  for unit in capsule@.service capsule-orders.service capsule-orders.timer capsule-helper.socket capsule-helper@.service; do
    install -m 644 "$HERE/systemd/$unit" "/etc/systemd/system/$unit"
  done
  # The same timer for a user who runs capsules without root: systemctl --user enable --now capsule-orders.timer
  install -d -m 755 /etc/systemd/user
  install -m 644 "$HERE/systemd/capsule-orders.service" "$HERE/systemd/capsule-orders.timer" /etc/systemd/user/
  systemctl daemon-reload 2>/dev/null || true
  if getent group capsule >/dev/null 2>&1; then
    systemctl enable --now capsule-helper.socket 2>/dev/null || true
  fi
fi
if [ -d /etc/apparmor.d ] && command -v apparmor_parser >/dev/null 2>&1; then
  install -m 644 "$HERE/apparmor/capsule" /etc/apparmor.d/capsule
  apparmor_parser -r /etc/apparmor.d/capsule
fi
echo "installed $(/usr/local/bin/capsule version)"
