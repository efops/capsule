#!/bin/sh
# The whole path a user takes, on a Linux host with systemd and internet access:
#   sudo sh test/e2e.sh /usr/local/bin/capsule
# Builds a capsule from a real distribution rootfs, runs it, then runs it as a
# service that is published on a host port and restarted when it exits.
# It installs a test key, app and unit under /etc and /var/lib and removes
# them again, so run it on a test machine.
set -eu
CAPSULE=$(realpath "$1")
REPO=$(dirname "$(dirname "$(realpath "$0")")")
case $(uname -m) in aarch64) ARCH=aarch64 ;; *) ARCH=x86_64 ;; esac
ALPINE=https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/$ARCH/alpine-minirootfs-3.20.3-$ARCH.tar.gz
W=$(mktemp -d)
cleanup() {
  systemctl stop capsule@e2e 2>/dev/null || true
  rm -rf "$W" /var/lib/capsule/apps/e2e /etc/capsule/apps/e2e.env /etc/capsule/trust.d/e2e.pub
}
trap cleanup EXIT
cd "$W"

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

wget -q -O alpine.tar.gz "$ALPINE" || curl -fsSL -o alpine.tar.gz "$ALPINE" || fail "could not download $ALPINE"
"$CAPSULE" keygen e2e
"$CAPSULE" init -rootfs alpine.tar.gz e2e >/dev/null
[ -x e2e/rootfs/bin/busybox ] || fail "init did not unpack the rootfs"
pass "init builds a capsule from a distribution rootfs tarball"

"$CAPSULE" seal -key e2e.key e2e >/dev/null
out=$("$CAPSULE" run -trust e2e.pub e2e)
[ "$out" = "hello from e2e" ] || fail "starter capsule did not run: $out"
pass "starter capsule seals and runs"

cat > e2e/capsule.json <<JSON
{"name":"e2e","command":["/bin/sh","-c","cat /etc/alpine-release > /tmp/v; exec nc -lk -p 8080 -e cat /tmp/v"],
 "publish":[8080],"limits":{"memory":"64M","cpus":1,"pids":64}}
JSON
"$CAPSULE" inspect -trust e2e.pub e2e | grep -q "would refuse: capsule.json was changed" || fail "inspect did not explain the stale seal"
"$CAPSULE" seal -key e2e.key e2e >/dev/null
"$CAPSULE" inspect -trust e2e.pub e2e | grep -q "would run it" || fail "inspect does not say the sealed capsule would run"
pass "inspect explains why a capsule would or would not run"

# Install it the way an operator would: trusted key, app directory, service.
install -D -m 644 e2e.pub /etc/capsule/trust.d/e2e.pub
mkdir -p /var/lib/capsule/apps /etc/capsule/apps
cp -a e2e /var/lib/capsule/apps/e2e
echo 'CAPSULE_ARGS=-publish 127.0.0.1:18300:8080' > /etc/capsule/apps/e2e.env
install -D -m 644 "$REPO/dist/systemd/capsule@.service" /etc/systemd/system/capsule@.service
systemctl daemon-reload
systemctl start capsule@e2e
sleep 3
answer() { busybox nc -w 3 127.0.0.1 18300 2>/dev/null || true; }
[ "$(answer)" = 3.20.3 ] || fail "service is not answering on its published port: $(systemctl status capsule@e2e --no-pager 2>&1 | tail -5)"
pass "runs as a systemd service and answers on its published port"

"$CAPSULE" kill "$("$CAPSULE" ps | grep '^e2e-' | cut -d' ' -f1)"
sleep 6
[ "$(answer)" = 3.20.3 ] || fail "service was not restarted after its capsule exited"
pass "systemd restarts it after the capsule exits"

systemctl stop capsule@e2e
sleep 1
"$CAPSULE" ps | grep -q '^e2e-' && fail "capsule still running after the service was stopped"
[ "$(systemctl is-failed capsule@e2e || true)" != failed ] || fail "a requested stop left the service marked failed"
pass "stopping the service stops the capsule cleanly"

"$CAPSULE" log | tail -1 | grep -q "chain intact" || fail "host log does not verify"
pass "every run above is in the host's signed log"
echo "all checks passed"
