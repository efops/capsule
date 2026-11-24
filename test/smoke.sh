#!/bin/sh
# End-to-end check on a Linux host. Works as root and as an ordinary user:
#   sudo sh test/smoke.sh /usr/local/bin/capsule
#        sh test/smoke.sh /usr/local/bin/capsule
# Needs a static busybox on the host (Debian/Ubuntu: apt-get install busybox-static).
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
if [ "$(id -u)" = 0 ]; then RUNDIR=/run/capsule; else RUNDIR=$XDG_RUNTIME_DIR/capsule; fi
W=$(mktemp -d)
trap 'pkill -P $$ 2>/dev/null || true; chmod -R u+rwx "$W" 2>/dev/null; rm -rf "$W"' EXIT # also stops helpers a failed check left running
cd "$W"
# Keep this test's host secret, store, log and counters out of the real ones.
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data"

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

mkdir -p app/rootfs/bin
cp "$BUSYBOX" app/rootfs/bin/busybox
for a in sh cat ls echo id hostname ps mount touch sleep ip head tail wc grep mkdir nc cp dd rm; do ln -s busybox app/rootfs/bin/$a; done
printf '#!/bin/sh\necho published-ok\n' > app/rootfs/bin/reply
chmod 755 app/rootfs/bin/reply

manifest() { # $1 = shell script to run inside the capsule, $2 = extra manifest fields
  cat > app/capsule.json <<EOF
{"name":"smoke","command":["/bin/sh","-c","$1"],"limits":{"memory":"32M","cpus":0.5,"pids":16}${2:-}}
EOF
}
run() { "$CAPSULE" run -trust "$W/dev.pub" app 2>&1; }
seal() { "$CAPSULE" seal -key dev.key -host self.host -host other.host app >/dev/null; }

"$CAPSULE" keygen dev
"$CAPSULE" keygen other
# This host, and a second one that exists only as a key, to seal capsules for.
"$CAPSULE" host -export > self.host
CAPSULE_CONFIG="$W/otherhost" "$CAPSULE" host -export > other.host

manifest "echo hello"
run | grep -q "not sealed" || fail "unsealed capsule was not refused"
pass "unsealed capsule refused"

"$CAPSULE" seal -key other.key app >/dev/null
run | grep -q "does not trust" || fail "untrusted signer was not refused"
pass "untrusted signer refused"

seal
[ "$(run)" = hello ] || fail "sealed capsule did not run: $(run)"
pass "sealed capsule runs"

echo x > app/rootfs/bin/extra
run | grep -q "rootfs was changed" || fail "tampered rootfs was not refused"
rm app/rootfs/bin/extra
pass "tampered rootfs refused"

sed -i 's/echo hello/echo pwned/' app/capsule.json
run | grep -q "capsule.json was changed" || fail "tampered manifest was not refused"
pass "tampered manifest refused"

check() { # $1 = description, $2 = script, $3 = expected output, $4 = extra manifest fields
  manifest "$2" "${4:-}"
  seal
  out=$(run || true)
  [ "$out" = "$3" ] || fail "$1 (got: $out)"
  pass "$1"
}

check "command is PID 1 in its own pid namespace" 'echo $$' 1
check "hostname is the capsule name" 'hostname' smoke
check "root filesystem is read-only" 'touch /x 2>/dev/null && echo writable || echo readonly' readonly
check "/tmp is writable" 'touch /tmp/x && echo yes' yes
check "host filesystem is not visible" 'ls / | wc -l' 4
check "only loopback exists in the network namespace" 'ip -o link | wc -l' 1
check "no capabilities" 'cat /proc/self/status | while read k v; do case $k in CapEff:|CapBnd:|CapPrm:) echo $v;; esac; done' "0000000000000000
0000000000000000
0000000000000000"
check "mount is blocked" 'mount -t tmpfs none /tmp 2>/dev/null && echo mounted || echo blocked' blocked
check "host sysctls are read-only" 'echo 1 2>/dev/null > /proc/sys/kernel/sysrq && echo writable || echo readonly' readonly
check "sysrq-trigger is read-only" 'echo h 2>/dev/null > /proc/sysrq-trigger && echo writable || echo readonly' readonly

# A manifest allow list: enough for a shell, but not mkdir.
ALLOW='"read","write","openat","open","close","fstat","newfstatat","stat","lseek","mmap","munmap","mprotect","brk","ioctl","fcntl","dup2","dup3","rt_sigaction","rt_sigprocmask","rt_sigreturn","sigaltstack","getpid","getppid","getuid","geteuid","getgid","getegid","getcwd","chdir","uname","arch_prctl","set_tid_address","set_robust_list","rseq","prlimit64","getrandom","futex","readlink","readlinkat","clone","fork","vfork","wait4","exit","pipe","pipe2","getdents64","faccessat","access"'
check "default profile allows mkdir" 'mkdir /tmp/d 2>/dev/null && echo made || echo blocked' made
check "manifest allow list blocks what it leaves out" 'mkdir /tmp/d 2>/dev/null && echo made || echo blocked' blocked ",\"syscalls\":[$ALLOW]"

check "memory under the limit is fine" 'head -c 8m /dev/zero | tail -c 8m >/dev/null; echo status=$?' status=0
manifest 'head -c 48m /dev/zero | tail -c 48m >/dev/null; echo status=$?'
seal
# The kernel kills tail, and sometimes the shell with it, which ends the capsule.
set +e; out=$(run); code=$?; set -e
echo "$out" | grep -q status=137 || [ "$code" = 137 ] || fail "process over the memory limit was not killed (exit $code, got: $out)"
pass "memory over the limit is killed"

manifest 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do sleep 1 & done; wait'
seal
run | grep -q "fork" || fail "pid limit did not stop a fork loop"
pass "pid limit holds"

manifest "exit 7"
seal
set +e; "$CAPSULE" run -trust dev.pub app; code=$?; set -e
[ "$code" = 7 ] || fail "exit status was $code, want 7"
pass "exit status 7"

manifest "while :; do :; done"
seal
"$CAPSULE" run -trust dev.pub app &
sleep 4
id=$("$CAPSULE" ps | grep smoke- | head -1 | cut -d' ' -f1)
[ -n "$id" ] || fail "ps did not list the running capsule"
pass "ps lists $id"
usec=$(grep usage_usec "$(readlink "$RUNDIR/$id.cg")/cpu.stat" | cut -d' ' -f2)
[ "$usec" -gt 1000000 ] && [ "$usec" -lt 2800000 ] || fail "busy loop used ${usec}us of CPU in 4s, want about 2000000"
pass "cpu limit holds (${usec}us of CPU in 4s at 0.5 cores)"
cg=$(readlink "$RUNDIR/$id.cg")
"$CAPSULE" resize -memory 64M -cpus 1 "$id"
[ "$(cat "$cg/memory.max")" = 67108864 ] && [ "$(cat "$cg/cpu.max")" = "100000 100000" ] || fail "resize did not change the running capsule's limits"
pass "resize changes limits while it runs"
"$CAPSULE" prune | grep -q "kept 1 in use" || fail "prune did not keep the running capsule's rootfs"
[ -d "$(readlink "$RUNDIR/$id.rootfs")" ] || fail "prune deleted a rootfs that is in use"
pass "prune keeps a rootfs that is in use"
"$CAPSULE" kill "$id"
set +e; wait $!; code=$?; set -e
[ "$code" = 137 ] || fail "killed capsule exited $code, want 137"
"$CAPSULE" ps | grep -q smoke- && fail "capsule still listed after kill"
[ -z "$(ls -A "$RUNDIR")" ] || fail "run state left behind in $RUNDIR"
pass "kill stops it and nothing is left behind"

"$CAPSULE" prune >/dev/null
[ -z "$(ls "$CAPSULE_DATA/store")" ] || fail "prune left unused rootfs copies behind"
pass "prune removes unused rootfs copies"

# ---- sealed run policy ----
refused() { # $1 = description, $2 = policy JSON, $3 = text the refusal must contain
  manifest "echo hello" ",\"policy\":$2"
  seal
  out=$(run || true)
  echo "$out" | grep -q "$3" || fail "$1 (got: $out)"
  pass "$1"
}
HOST=$("$CAPSULE" host | grep ^id | tr -s ' ' | cut -d' ' -f2)
SIGN=$("$CAPSULE" host | grep ^sign | tr -s ' ' | cut -d' ' -f2)
OTHERHOST=$(CAPSULE_CONFIG="$W/otherhost" "$CAPSULE" host | grep ^id | tr -s ' ' | cut -d' ' -f2)

refused "time lock: refused before not_before" '{"not_before":"2099-01-01T00:00:00Z"}' "time-locked until 2099"
refused "time lock: refused after expires" '{"expires":"2001-01-01T00:00:00Z"}' "expired at 2001"
manifest "echo hello" ",\"policy\":{\"hosts\":[\"$OTHERHOST\"]}"
"$CAPSULE" seal -key dev.key app 2>&1 | grep -q "host file was not given" || fail "sealed for a host without having its key"
pass "host list: cannot seal for a host whose key was not supplied"
refused "host list: refused on a host that is not listed" "{\"hosts\":[\"$OTHERHOST\"]}" "not authorised"
check "policy that holds lets it run" 'echo hello' hello ",\"policy\":{\"not_before\":\"2001-01-01T00:00:00Z\",\"expires\":\"2099-01-01T00:00:00Z\",\"hosts\":[\"$HOST\"]}"

manifest "echo hello" ',"policy":{"max_runs":1}'
seal
[ "$(run)" = hello ] || fail "first of one permitted run did not happen"
run | grep -q "already ran 1 of 1" || fail "second run was not refused by max_runs"
pass "max_runs: one run allowed, the second refused"

"$CAPSULE" keygen alice; "$CAPSULE" keygen bob
APPROVERS="{\"approvals\":{\"required\":2,\"signers\":[\"$(cat alice.id)\",\"$(cat bob.id)\",\"$(cat dev.id)\"]}}"
refused "approvals: refused with none" "$APPROVERS" "has 0 of 2 required approvals"
"$CAPSULE" approve -key alice.key app >/dev/null
"$CAPSULE" approve -key other.key app >/dev/null # not one of the listed signers
"$CAPSULE" approve -key alice.key app >/dev/null # the same signer twice counts once
run | grep -q "has 1 of 2 required approvals" || fail "an unlisted or repeated approval was counted"
pass "approvals: unlisted and repeated signers do not count"
"$CAPSULE" approve -key bob.key app >/dev/null
[ "$(run)" = hello ] || fail "capsule with 2 of 2 approvals did not run"
pass "approvals: runs once 2 of 3 signers approve"
manifest "echo changed" ",\"policy\":$APPROVERS"
seal
run | grep -q "has 0 of 2 required approvals" || fail "approvals carried over to a different seal"
pass "approvals: do not carry over to a changed capsule"

manifest "echo hello"
seal
[ "$(run)" = hello ] || fail "capsule did not run before revocation"
"$CAPSULE" revoke app
run | grep -q "revoked" || fail "revoked seal still ran"
pass "revoke: this exact seal no longer runs"

# ---- encrypted for named hosts ----
echo MARKER-PLAINTEXT > app/rootfs/marker
manifest "cat /marker" ",\"policy\":{\"hosts\":[\"$HOST\"]}"
seal
grep -q MARKER-PLAINTEXT app/rootfs.enc && fail "rootfs.enc contains plaintext"
mv app/rootfs plain
"$CAPSULE" prune >/dev/null
[ "$(run)" = MARKER-PLAINTEXT ] || fail "authorised host could not run the encrypted capsule: $(run)"
pass "encrypted capsule runs on a listed host, from rootfs.enc alone"
if [ "$(id -u)" = 0 ]; then
  # With root, the capsule is decrypted once into an encrypted store on disk.
  img=$(ls "$CAPSULE_DATA"/sealed/*.img 2>/dev/null | head -1)
  [ -n "$img" ] || fail "the encrypted store was not created"
  sync
  grep -aq MARKER-PLAINTEXT "$img" && fail "the store on disk holds the capsule's contents in the clear"
  mount | grep -q "$CAPSULE_DATA/sealed" && fail "the store was left mounted, and so readable, after the run"
  [ -z "$(ls "$CAPSULE_DATA/store")" ] && [ -z "$(ls -A "$RUNDIR")" ] || fail "decrypted rootfs was left behind outside the encrypted store"
  mv app/rootfs.enc enc.aside # a second start must not need to decrypt again
  [ "$(run)" = MARKER-PLAINTEXT ] || fail "a second start decrypted again instead of using the store: $(run)"
  mv enc.aside app/rootfs.enc
  pass "decrypted once into an encrypted store on disk: no plaintext on disk, and later starts reuse it"
else
  [ -z "$(ls "$CAPSULE_DATA/store")" ] && [ -z "$(ls -A "$RUNDIR")" ] || fail "decrypted rootfs was left behind"
  pass "decrypted rootfs is held in memory only and removed after the run"

  # While one runs: its memory is barred from swap. And if its supervisor is
  # killed outright, the decrypted copy is cleared by the next capsule command.
  mv plain app/rootfs # sealing needs the files back
  manifest "sleep 60" ",\"policy\":{\"hosts\":[\"$HOST\"]}"
  seal
  mv app/rootfs plain
  "$CAPSULE" run -trust dev.pub app >/dev/null 2>&1 &
  sleep 3
  id=$("$CAPSULE" ps | grep smoke- | cut -d' ' -f1)
  scope=$(dirname "$(readlink "$RUNDIR/$id.cg")")
  [ "$(cat "$scope/supervisor/memory.swap.max")" = 0 ] || fail "the supervisor holding the decrypted capsule may be swapped to disk: $(cat "$scope/supervisor/memory.swap.max")"
  pass "decrypted capsule in memory: barred from swap"
  ls -d "$RUNDIR"/plain-*/ >/dev/null 2>&1 || fail "test expected the decrypted copy to be in the run folder"
  pkill -KILL -f "capsule run -trust dev.pub app" || true
  wait 2>/dev/null || true
  sleep 1
  ls -d "$RUNDIR"/plain-*/ >/dev/null 2>&1 || fail "test expected the decrypted copy to outlive a killed supervisor until cleaned"
  "$CAPSULE" ps >/dev/null
  ls -d "$RUNDIR"/plain-* >/dev/null 2>&1 && fail "the decrypted copy of a killed capsule was not removed: $(ls "$RUNDIR")"
  [ -z "$(ls -A "$RUNDIR")" ] || fail "run state left behind after cleaning up a killed capsule: $(ls -A "$RUNDIR")"
  pass "decrypted capsule in memory: removed after its supervisor is killed"
  mv plain app/rootfs
  manifest "cat /marker" ",\"policy\":{\"hosts\":[\"$HOST\"]}"
  seal
  mv app/rootfs plain
fi
"$CAPSULE" prune >/dev/null # drop the stored copy, so the next start has to decrypt again
size=$(wc -c < app/rootfs.enc)
dd if=/dev/zero of=app/rootfs.enc bs=1 count=4 seek=$((size / 2)) conv=notrunc 2>/dev/null
run | grep -q "does not decrypt" || fail "tampered rootfs.enc was not refused: $(run)"
pass "tampered rootfs.enc refused"
mv plain app/rootfs
manifest "cat /marker" ",\"policy\":{\"hosts\":[\"$OTHERHOST\"]}"
seal
sed -i "s|\"hosts\":\[\"$OTHERHOST\"\]|\"hosts\":[\"$HOST\"]|" app/capsule.json # try to add this host afterwards
run | grep -q "capsule.json was changed" || fail "host list could be edited after sealing"
pass "host list cannot be edited after sealing"
rm -f app/rootfs.enc app/rootfs/marker

# ---- signed revocation, for every host ----
manifest "echo hello" ',"hostname":"fleet"'
seal
mkdir -p "$CAPSULE_CONFIG/revoked.d"
"$CAPSULE" revoke -key other.key app > "$CAPSULE_CONFIG/revoked.d/untrusted.json"
[ "$(run)" = hello ] || fail "revocation signed by an untrusted key was honoured"
"$CAPSULE" revoke -key dev.key app > "$CAPSULE_CONFIG/revoked.d/trusted.json"
run | grep -q "revoked" || fail "signed revocation was not honoured"
pass "revoke -key: a notice signed by a trusted key stops the seal; an untrusted one does not"

# ---- timed unlocks ----
check "unlock: settings switch on once their time has come" 'echo A=$A B=$B' "A=on B=" \
  ',"unlock":[{"at":"2001-01-01T00:00:00Z","env":{"A":"on"}},{"at":"2099-01-01T00:00:00Z","env":{"B":"on"}}]'

# ---- publish and egress ----
manifest "nc -ll -p 8080 -e /bin/reply" ',"publish":[8080]'
seal
run_bg() { "$CAPSULE" run -trust "$W/dev.pub" "$@" app > bg.out 2>&1 & }
run_bg -publish 127.0.0.1:18081:9090
wait $! || true
grep -q "does not allow publishing port 9090" bg.out || fail "published a port the manifest does not list: $(cat bg.out)"
pass "publish: a port the manifest does not list is refused"
run_bg -publish 127.0.0.1:18080:8080
sleep 2
[ "$(busybox nc -w 3 127.0.0.1 18080)" = published-ok ] || fail "could not reach the published port: $(cat bg.out)"
"$CAPSULE" kill "$("$CAPSULE" ps | grep smoke- | cut -d' ' -f1)"
wait $! || true
pass "publish: host port reaches the capsule"

printf '#!/bin/sh\necho outside-ok\n' > outside.sh; chmod 755 outside.sh
busybox nc -ll -p 18090 -e "$W/outside.sh" & OUTSIDE=$!
check "egress: reaches a listed outside host and nothing else" \
  'nc -w 3 ip6-localhost 18090 2>/dev/null || echo blocked; nc -w 3 ip6-localhost 18091 2>/dev/null || echo blocked; nc -w 3 127.0.0.1 18090 2>/dev/null || echo blocked' \
  "outside-ok
blocked
blocked" ',"egress":[{"host":"ip6-localhost","port":18090}]'
kill $OUTSIDE

if [ "$(id -u)" != 0 ]; then
  manifest "echo hello" ',"hostname":"nosystemd"'
  seal
  out=$(systemd-run --user --scope --quiet -p Delegate=yes /usr/bin/env PATH=/nonexistent "$CAPSULE" run -trust "$W/dev.pub" app 2>&1)
  [ "$out" = hello ] || fail "did not run in a delegated cgroup without systemd-run: $out"
  pass "runs without systemd-run when its cgroup is already delegated"
fi

# ---- volumes: state that outlives the capsule ----
VOL=',"volumes":[{"name":"data","path":"/data"}]'
manifest 'echo line >> /data/log; wc -l < /data/log' "$VOL"
seal
first=$(run); second=$(run)
[ "$first" = 1 ] && [ "$second" = 2 ] || fail "volume data did not persist between runs (got: $first then $second)"
pass "volume: data persists between runs"
manifest 'cat /data/log 2>/dev/null | wc -l' "$VOL" # a new version of the capsule, sealed again
seal
out=$(run)
[ "$out" = 2 ] || fail "volume data did not carry over to a newly sealed version (got: $out)"
pass "volume: data carries over to a newly sealed version"
[ "$("$CAPSULE" run -trust dev.pub -instance b app 2>&1)" = 0 ] || fail "a second instance saw the first instance's data"
pass "volume: each instance has its own data"
check "volume: files in it cannot be executed" 'cp /bin/busybox /data/echo; /data/echo ran 2>/dev/null || echo blocked' blocked "$VOL"
check "volume: can be executable when the manifest says so" 'cp /bin/busybox /code/echo; /code/echo ran' ran ',"volumes":[{"name":"code","path":"/code","exec":true}]'
manifest 'sleep 30' "$VOL"
seal
"$CAPSULE" run -trust dev.pub app >/dev/null 2>&1 &
sleep 2
run | grep -q "in use by another running instance" || fail "two instances were allowed to share one volume"
"$CAPSULE" volumes -rm smoke 2>&1 | grep -q "is running" || fail "volume data of a running capsule could be deleted"
"$CAPSULE" kill "$("$CAPSULE" ps | grep smoke- | cut -d' ' -f1)"; wait $! || true
pass "volume: one running instance at a time, and no deleting while it runs"
"$CAPSULE" volumes | grep -q "^smoke .*data" || fail "volumes does not list the data"
"$CAPSULE" volumes -rm smoke && "$CAPSULE" volumes -rm smoke-b
"$CAPSULE" volumes | grep -q "^smoke" && fail "volume data was not deleted"
pass "volumes: lists and deletes kept data"

# ---- sized volumes: a hard limit, encryption at rest, snapshots (root only) ----
if [ "$(id -u)" = 0 ]; then
  SIZED=',"volumes":[{"name":"disk","path":"/data","size":"16M"}]'
  check "sized volume: keeps data" 'echo MARKER-IN-THE-CLEAR-123 > /data/note; cat /data/note' MARKER-IN-THE-CLEAR-123 "$SIZED"
  check "sized volume: writes stop at its size" 'dd if=/dev/zero of=/data/big bs=1M count=32 2>/dev/null && echo fits || echo full; rm -f /data/big' full "$SIZED"
  grep -aq MARKER-IN-THE-CLEAR-123 "$CAPSULE_DATA/volumes/smoke/disk.img" || fail "test cannot find plain data in an unencrypted volume, so it could not tell encryption apart"

  ENC=',"volumes":[{"name":"safe","path":"/data","size":"16M","encrypt":true}]'
  check "encrypted volume: usable by the capsule" 'echo MARKER-ENCRYPTED-456 > /data/secret-file-name-789; cat /data/secret-file-name-789' MARKER-ENCRYPTED-456 "$ENC"
  check "encrypted volume: readable again on the next run" 'cat /data/secret-file-name-789' MARKER-ENCRYPTED-456 "$ENC"
  sync
  grep -aq MARKER-ENCRYPTED-456 "$CAPSULE_DATA/volumes/smoke/safe.img" && fail "an encrypted volume holds its contents in the clear on disk"
  grep -aq secret-file-name-789 "$CAPSULE_DATA/volumes/smoke/safe.img" && fail "an encrypted volume holds file names in the clear on disk"
  pass "encrypted volume: neither contents nor file names are readable on disk"

  manifest 'echo first > /data/state; sleep 30' "$ENC"
  seal
  "$CAPSULE" run -trust dev.pub app >/dev/null 2>&1 &
  sleep 2
  snap=$("$CAPSULE" volumes -snapshot smoke) || fail "could not snapshot a running capsule's sized volume"
  "$CAPSULE" kill "$("$CAPSULE" ps | grep smoke- | cut -d' ' -f1)"; wait $! || true
  check "volume changes after the snapshot" 'echo second > /data/state; cat /data/state' second "$ENC"
  "$CAPSULE" volumes -restore smoke "$snap" || fail "could not restore the snapshot"
  check "snapshot: taken while running, restores the data as it was" 'cat /data/state' first "$ENC"
  "$CAPSULE" volumes | grep -q "^smoke .*safe" || fail "volumes does not list a sized volume"

  # Another host cannot open the encrypted volume until a host that can grants it the key.
  CAPSULE_CONFIG="$W/otherhost" "$CAPSULE" run -trust dev.pub app 2>&1 | grep -q "holds no key" || fail "a host without the key opened an encrypted volume"
  "$CAPSULE" volumes -grant smoke other.host | grep -q "granted 1" || fail "could not grant the volume to another host"
  [ "$(CAPSULE_CONFIG="$W/otherhost" "$CAPSULE" run -trust dev.pub app 2>&1 | tail -1)" = first ] || fail "the granted host could not read the encrypted volume"
  pass "encrypted volume: closed to another host until it is granted the key, then readable there"
  "$CAPSULE" volumes -rm smoke
else
  manifest 'echo hi' ',"volumes":[{"name":"disk","path":"/data","size":"16M"}]'
  seal
  run | grep -q "needs root" || fail "a sized volume was accepted without root: $(run)"
  pass "sized volume: refused without root, with the reason"
fi

# A rootfs cannot steer the runtime's own setup out to the host through a symlink.
mkdir victim
mv app/rootfs/etc etc.bak 2>/dev/null || true
ln -s "$W/victim" app/rootfs/etc
manifest 'echo started' ',"egress":[{"host":"ip6-localhost","port":18090}]'
seal
run | grep -q "cannot be used as a directory" || fail "a rootfs whose /etc is a symlink to the host was accepted: $(run)"
[ -z "$(ls -A victim)" ] || fail "the runtime wrote into a host directory through a rootfs symlink"
rm app/rootfs/etc; [ -d etc.bak ] && mv etc.bak app/rootfs/etc
ln -s "$W/victim" app/rootfs/data
manifest 'echo started' "$VOL"
seal
run | grep -q "cannot be used as a directory" || fail "a volume was mounted through a rootfs symlink to the host: $(run)"
[ -z "$(ls -A victim)" ] || fail "a volume mount reached a host directory through a rootfs symlink"
rm app/rootfs/data
"$CAPSULE" volumes -rm smoke 2>/dev/null || true
pass "a symlink in the rootfs cannot redirect setup or a volume onto the host"

# ---- publish to the shared store, fetch on another host ----
echo "file://$W/store" > "$CAPSULE_CONFIG/ledger"
mkdir -p "$W/otherhost"; echo "file://$W/store" > "$W/otherhost/ledger"
elsewhere() { CAPSULE_CONFIG="$W/otherhost" CAPSULE_DATA="$W/otherdata" "$CAPSULE" "$@" 2>&1; }
manifest "echo release-one" ',"hostname":"dist"'
seal
"$CAPSULE" publish -key dev.key app >/dev/null || fail "could not publish"
cp "$W/store/capsules/smoke/current" pointer.one
elsewhere fetch -trust "$W/dev.pub" smoke | grep -q "installed smoke" || fail "another host could not fetch the published capsule: $(elsewhere fetch -trust "$W/dev.pub" smoke)"
[ "$(elsewhere run -trust "$W/dev.pub" "$W/otherdata/apps/smoke")" = release-one ] || fail "the fetched capsule did not run"
elsewhere fetch -trust "$W/dev.pub" smoke | grep -q "up to date" || fail "fetching again did not report it is up to date"
pass "publish and fetch: a capsule published from one host installs and runs on another"
manifest "echo release-two" ',"hostname":"dist"'
seal
"$CAPSULE" publish -key dev.key app >/dev/null
elsewhere fetch -trust "$W/dev.pub" smoke >/dev/null
[ "$(elsewhere run -trust "$W/dev.pub" "$W/otherdata/apps/smoke")" = release-two ] || fail "fetch did not move to the newer release"
pass "fetch: moves to a newer release"
cp pointer.one "$W/store/capsules/smoke/current" # whoever controls the store offers the old release again
elsewhere fetch -trust "$W/dev.pub" smoke | grep -q "refusing to go back" || fail "fetch accepted an older release than the one it had"
"$CAPSULE" publish -key other.key -trust dev.pub app >/dev/null # a release signed by a key the other host does not trust
elsewhere fetch -trust "$W/dev.pub" smoke | grep -q "not signed by a key this host trusts" || fail "fetch accepted a release from an untrusted key"
pass "fetch: refuses an older release, and one signed by an untrusted key"
rm "$CAPSULE_CONFIG/ledger" "$W/otherhost/ledger"

# ---- CUE: build file, host rules, fleet layout ----
cat > built.cue <<CUE
_greeting: "hello from cue"
capsule: {name: "built", command: ["/bin/sh", "-c", "cat /etc/greeting"], limits: {memory: "32M", pids: 16}}
rootfs: {from: "app/rootfs", files: "/etc/greeting": contents: "\\(_greeting)\\n"}
CUE
"$CAPSULE" build -key dev.key built.cue >/dev/null
out=$("$CAPSULE" run -trust "$W/dev.pub" built 2>&1)
[ "$out" = "hello from cue" ] || fail "capsule built from a CUE file did not run: $out"
pass "build: a CUE file becomes a sealed capsule that runs"
sed 's/limits:/limts:/' built.cue > typo.cue
"$CAPSULE" build -o typo typo.cue 2>&1 | grep -q "limts: field not allowed" || fail "a misspelt field in a build file was accepted"
pass "build: a misspelt field is an error"

mkdir -p "$CAPSULE_CONFIG/policy.d"
echo 'capsule: limits: cpus: number' > "$CAPSULE_CONFIG/policy.d/org.cue"
"$CAPSULE" run -trust "$W/dev.pub" built 2>&1 | grep -q "capsule.limits.cpus: must be set" || fail "host rule did not refuse a capsule without a CPU limit"
rm "$CAPSULE_CONFIG/policy.d/org.cue"
pass "host rules: a sealed, trusted capsule that breaks this host's rules is refused"

cat > fleet.cue <<CUE
hosts: {"host-a": address: "10.0.0.5", "host-b": {}}
deploy: [for h, _ in hosts {capsule: "built", host: h, instance: "1", publish: ["8080:8080"]}]
CUE
"$CAPSULE" render -o deploy fleet.cue | grep -q "systemctl enable --now capsule@built-1" || fail "render did not print how to start the services"
grep -q -- "-instance 1 -publish 8080:8080" deploy/host-b/etc/capsule/apps/built-1.env || fail "render did not write the run flags"
[ "$("$CAPSULE" verify -trust dev.pub deploy/host-a/var/lib/capsule/apps/built-1)" = ok ] || fail "rendered capsule does not verify"
pass "render: a fleet file becomes one ready-to-copy directory per host"

# ---- drand time lock (needs internet) ----
soon=$(date -u -d "+25 seconds" +%Y-%m-%dT%H:%M:%SZ)
manifest "echo unlocked" ",\"policy\":{\"not_before\":\"$soon\",\"timelock\":true}"
if out=$("$CAPSULE" seal -key dev.key app 2>&1); then
  grep -q '"timelock"' app/capsule.seal && [ -f app/rootfs.enc ] || fail "time-locked capsule was not encrypted to a drand round"
  mv app/rootfs plain
  run | grep -q "time-locked" || fail "time-locked capsule ran early"
  sleep 32
  [ "$(run)" = unlocked ] || fail "time-locked capsule did not open after its time: $(run)"
  mv plain app/rootfs
  pass "time lock: sealed to a drand round, opens only after it is published"
else
  echo "skip time lock: $out"
fi

# ---- record ----
manifest "echo hello" ',"hostname":"receipt"' # differs from the seal revoked above
seal
"$CAPSULE" run -trust dev.pub -receipt receipt.json app >/dev/null
want="sha256:$(printf 'hello\n' | sha256sum | cut -d' ' -f1)"
"$CAPSULE" receipt -host "$SIGN" receipt.json | grep -q "output   $want" || fail "receipt does not carry the hash of the capsule's output"
"$CAPSULE" receipt -host "$(cat other.id)" receipt.json 2>&1 | grep -q "not signed by that host" || fail "receipt accepted for the wrong host"
sed -i 's/"exit": 0/"exit": 1/' receipt.json
"$CAPSULE" receipt -host "$SIGN" receipt.json 2>&1 | grep -q "not signed by that host" || fail "edited receipt was accepted"
pass "receipt: proves which seal ran and what it output; edits are detected"

"$CAPSULE" log | tail -1 | grep -q "chain intact" || fail "log does not verify: $("$CAPSULE" log | tail -1)"
"$CAPSULE" log | grep -q "refused.*time-locked" || fail "refusals are not in the log"
cp "$CAPSULE_DATA/log.jsonl" log.bak
sed -i '0,/"event":"refused"/s//"event":"allowed"/' "$CAPSULE_DATA/log.jsonl"
cmp -s log.bak "$CAPSULE_DATA/log.jsonl" && fail "test did not manage to edit the log"
"$CAPSULE" log 2>&1 | grep -q "log has been altered" || fail "edited log entry was not detected"
sed '2d' log.bak > "$CAPSULE_DATA/log.jsonl"
"$CAPSULE" log 2>&1 | grep -q "log has been altered" || fail "deleted log entry was not detected"
pass "log: records runs and refusals; edits and deletions are detected"

cp log.bak "$CAPSULE_DATA/log.jsonl"

# A collector off the host gets every entry as it is written.
cat > collect.sh <<COLLECT
#!/bin/sh
len=0
while IFS= read -r line; do
  line=\$(printf '%s' "\$line" | tr -d '\r')
  [ -z "\$line" ] && break
  case "\$line" in [Cc]ontent-[Ll]ength:*) len=\${line#*: };; esac
done
head -c "\$len" >> "$W/collected.jsonl"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
COLLECT
chmod 755 collect.sh
echo "http://127.0.0.1:18099/" > "$CAPSULE_CONFIG/log-forward"
manifest "echo hello" ',"hostname":"forward"'
seal
run | grep -q "log collector" || fail "ran although the log collector was unreachable"
busybox nc -ll -p 18099 -e "$W/collect.sh" & COLLECTOR=$!
sleep 1
[ "$(run)" = hello ] || fail "did not run with a log collector: $(run)"
kill $COLLECTOR
tail -n 2 "$CAPSULE_DATA/log.jsonl" | cmp -s - collected.jsonl || fail "collector did not receive the run and exit entries"
rm "$CAPSULE_CONFIG/log-forward"
pass "log-forward: entries reach a collector as written; no collector, no run"

# The clock cannot be proven, but a clock set back behind the record is noticed.
echo '{"seq":999,"time":"2099-06-01T00:00:00Z","event":"run"}' >> "$CAPSULE_DATA/log.jsonl"
refused "time lock: refused when the clock is behind the host's own record" '{"expires":"2099-01-01T00:00:00Z"}' "behind its own record"

echo "all checks passed"
