#!/bin/sh
# The latency profile: dedicated cores, locked memory, huge pages and a
# network interface of the capsule's own. Root only, on a host with at least
# four cores:
#   sudo sh test/latency.sh /usr/local/bin/capsule
# It checks that the profile is applied, not how fast anything is: that
# needs real hardware.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
[ "$(id -u)" = 0 ] || { echo "run this as root"; exit 1; }
[ "$(nproc)" -ge 4 ] || { echo "needs at least four cores"; exit 1; }
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data" CAPSULE_RUN="$W/run"
cleanup() {
  set +e
  for id in $("$CAPSULE" ps | grep -E '^(fast|plain)' | cut -d' ' -f1); do "$CAPSULE" kill "$id"; done
  pkill -P $$ 2>/dev/null; wait
  ip link del lat0 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }
mkdir -p conf
"$CAPSULE" keygen dev >/dev/null
capsule() { # $1 = name, $2 = script, $3 = extra manifest fields
  rm -rf "$1"; mkdir -p "$1/rootfs/bin"; cp "$BUSYBOX" "$1/rootfs/bin/busybox"
  for a in sh cat grep sleep ip mount echo; do ln -s busybox "$1/rootfs/bin/$a"; done
  printf '{"name":"%s","command":["/bin/sh","-c","%s"],"limits":{"memory":"32M","pids":16}%s}\n' "$1" "$2" "${3:-}" > "$1/capsule.json"
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
}
run() { "$CAPSULE" run -trust "$W/dev.pub" "$1" 2>&1; }
ALLOWED='grep Cpus_allowed_list /proc/self/status | tr -dc 0-9,-'

capsule fast "$ALLOWED" ',"latency":{"cores":1}'
run fast | grep -q 'has set no cores aside' && pass "dedicated cores are refused on a host that has set none aside" || fail "no latency file: $(run fast)"

echo 'cores 2-3   # kept for latency-critical capsules' > conf/latency
[ "$(run fast)" = 2 ] && pass "a capsule asking for one core is pinned to one of the reserved cores" || fail "pinned to: $(run fast)"
capsule plain "$ALLOWED"
[ "$(run plain)" = 0-1 ] && pass "an ordinary capsule is kept off every reserved core" || fail "ordinary capsule may use: $(run plain)"

capsule fast "$ALLOWED; sleep 30" ',"latency":{"cores":1}'
run fast > one.out & 
for i in 1 2 3 4 5 6 7 8 9 10; do "$CAPSULE" ps | grep -q '^fast-' && break; sleep 0.5; done
capsule fast2 "$ALLOWED" ',"latency":{"cores":1}'
[ "$(run fast2)" = 3 ] && pass "a second one gets a different core: no two share" || fail "second capsule got: $(run fast2), first: $(cat one.out)"
capsule fast3 "$ALLOWED" ',"latency":{"cores":2}'
run fast3 | grep -q '1 of this host.s 2 are free' && pass "a capsule is refused when too few reserved cores are free" || fail "over-asking: $(run fast3)"
id=$("$CAPSULE" ps | grep '^fast-' | cut -d' ' -f1)
[ "$(cat /sys/fs/cgroup/capsule/$id/cpu.max | cut -d' ' -f1)" = max ] && pass "dedicated cores carry no CPU quota: the program is never paused" || fail "cpu.max: $(cat /sys/fs/cgroup/capsule/$id/cpu.max)"
"$CAPSULE" kill "$id"; wait || true
[ "$(run fast3)" = 2-3 ] && pass "cores are free again when their capsule ends" || fail "after release: $(run fast3)"

capsule fast 'grep locked /proc/self/limits | grep -c unlimited.*unlimited' ',"latency":{"memory_lock":true}'
[ "$(run fast)" = 1 ] && pass "memory_lock lets the program lock all its memory in RAM" || fail "memlock limit: $(run fast)"
capsule plain 'grep locked /proc/self/limits | grep -c unlimited.*unlimited'
[ "$(run plain)" = 1 ] && fail "an ordinary capsule may also lock unlimited memory"
pass "an ordinary capsule keeps the usual limit"

capsule fast 'mount | grep -c hugetlbfs' ',"latency":{"hugepages":true}'
[ "$(run fast)" = 1 ] && pass "hugepages gives the capsule the host's huge pages at /dev/hugepages" || fail "hugepages: $(run fast)"

ip link add lat0 type dummy
capsule fast 'ip addr show lat0 | grep -c inet.10.9.8.7/24; ip route | grep -c default.via.10.9.8.1; ip link | grep -c ^[0-9]' ',"latency":{"nic":{"name":"lat0","address":"10.9.8.7/24","gateway":"10.9.8.1"}}'
out=$(run fast | tr '\n' ' ')
[ "$out" = "1 1 2 " ] && pass "a network interface is handed to the capsule, addressed and routed, beside only its loopback" || fail "nic: $out"
ip link show lat0 >/dev/null 2>&1 && pass "the interface is back on the host when the capsule ends" || fail "the interface did not come back"
capsule fast 'sleep 20' ',"latency":{"nic":{"name":"lat0"}}'
run fast >/dev/null &
for i in 1 2 3 4 5 6 7 8 9 10; do "$CAPSULE" ps | grep -q '^fast-' && break; sleep 0.5; done
ip link show lat0 >/dev/null 2>&1 && fail "the host can still see an interface a capsule holds"
pass "while the capsule runs, the host no longer has the interface"
"$CAPSULE" kill "$("$CAPSULE" ps | grep '^fast-' | cut -d' ' -f1)"; wait || true
capsule fast 'echo hi' ',"latency":{"nic":{"name":"nosuch0"}}'
run fast | grep -q 'no network interface nosuch0' && pass "asking for an interface the host does not have is refused" || fail "missing nic: $(run fast)"
if [ -c /dev/net/tun ]; then
  capsule fast 'grep -c /dev/net/tun /proc/self/mountinfo' ',"latency":{"devices":["/dev/net/tun"]}'
  [ "$(run fast)" = 1 ] && pass "a device file the manifest names is there for the capsule to open" || fail "device: $(run fast)"
  capsule plain 'grep -c /dev/net/tun /proc/self/mountinfo'
  [ "$(run plain)" = 0 ] && pass "an ordinary capsule has no such device" || fail "an ordinary capsule has the device"
fi
capsule fast 'echo hi' ',"latency":{"devices":["/dev/nosuchdevice0"]}'
run fast | grep -q 'not a device on this host' && pass "a device the host does not have is refused" || fail "missing device: $(run fast)"
echo "all latency checks passed"
