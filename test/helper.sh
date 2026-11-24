#!/bin/sh
# The helper: what a user without root gains from it, and what it refuses.
# Run as an ordinary user who is in the "capsule" group, on a host where
# dist/install.sh has been run:
#   sh test/helper.sh /usr/local/bin/capsule
#   (straight after being added to the group: sg capsule -c "sh test/helper.sh /usr/local/bin/capsule")
# Needs busybox-static, python3 and sudo (only to look at what root keeps on disk).
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
[ "$(id -u)" != 0 ] || { echo "run this as an ordinary user"; exit 1; }
[ -S /run/capsule-helper.sock ] && [ -w /run/capsule-helper.sock ] || { echo "the helper's socket is not open to this user (is the user in the capsule group?)"; exit 1; }
W=$(mktemp -d)
ME=$(id -u)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data" CAPSULE_RUN="$W/run"
cleanup() {
  set +e
  for id in $("$CAPSULE" ps | grep -E '^(help|a|b)-' | cut -d' ' -f1); do "$CAPSULE" kill "$id"; done
  pkill -P $$ 2>/dev/null
  wait
  sleep 1
  sudo rm -rf "/var/lib/capsule/users/$ME/volumes/help" "/var/lib/capsule/users/$ME/volumes/help-b"
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

mkdir -p app/rootfs/bin cards
cp "$BUSYBOX" app/rootfs/bin/busybox
for a in sh cat echo sleep nc dd rm ls; do ln -s busybox app/rootfs/bin/$a; done
printf '#!/bin/sh\necho published-ok\n' > app/rootfs/bin/reply
chmod 755 app/rootfs/bin/reply
"$CAPSULE" keygen dev >/dev/null
"$CAPSULE" host -export > self.host
HOSTID=$("$CAPSULE" host | sed -n 's/^id *//p')
manifest() { printf '{"name":"help","command":["/bin/sh","-c","%s"],"limits":{"memory":"32M","pids":16}%s}\n' "$1" "${2:-}" > app/capsule.json; }
seal() { "$CAPSULE" seal -key dev.key -host self.host app >/dev/null; }
run() { "$CAPSULE" run -trust "$W/dev.pub" "$@" app 2>&1; }

# ---- sized and encrypted volumes ----
SIZED=',"volumes":[{"name":"disk","path":"/data","size":"16M"}]'
manifest 'echo MARKER-IN-THE-CLEAR-123 > /data/note; cat /data/note' "$SIZED"; seal
[ "$(run)" = MARKER-IN-THE-CLEAR-123 ] || fail "sized volume without root: $(run)"
manifest 'cat /data/note' "$SIZED"; seal
[ "$(run)" = MARKER-IN-THE-CLEAR-123 ] || fail "sized volume did not keep its data: $(run)"
pass "sized volume without root: usable, and keeps its data"
manifest 'dd if=/dev/zero of=/data/big bs=1M count=32 2>/dev/null && echo fits || echo full; rm -f /data/big' "$SIZED"; seal
[ "$(run)" = full ] && pass "sized volume: writes stop at its size" || fail "sized volume has no limit: $(run)"
sleep 1
mount | grep -q "/run/capsule-helper/$ME/volumes" && fail "a volume was left mounted after its capsule ended"
pass "the volume is unmounted when the capsule ends"
IMG="/var/lib/capsule/users/$ME/volumes/help"
[ ! -r "$IMG/disk.img" ] && sudo test -f "$IMG/disk.img" && pass "its image is kept where the user cannot read or replace it" || fail "the volume image is within the user's reach"
sudo grep -aq MARKER-IN-THE-CLEAR-123 "$IMG/disk.img" || fail "test cannot find plain data in an unencrypted volume"

ENC=',"volumes":[{"name":"safe","path":"/data","size":"16M","encrypt":true}]'
manifest 'echo MARKER-ENCRYPTED-456 > /data/secret-name-789; cat /data/secret-name-789' "$ENC"; seal
[ "$(run)" = MARKER-ENCRYPTED-456 ] || fail "encrypted volume without root: $(run)"
manifest 'cat /data/secret-name-789' "$ENC"; seal
[ "$(run)" = MARKER-ENCRYPTED-456 ] || fail "encrypted volume not readable on the next run: $(run)"
sync; sleep 1
sudo grep -aq MARKER-ENCRYPTED-456 "$IMG/safe.img" && fail "an encrypted volume holds its contents in the clear"
sudo grep -aq secret-name-789 "$IMG/safe.img" && fail "an encrypted volume holds file names in the clear"
pass "encrypted volume without root: neither contents nor names are readable on disk"

manifest 'sleep 30' "$SIZED"; seal
run >/dev/null &
for i in 1 2 3 4 5 6 7 8 9 10; do "$CAPSULE" ps | grep -q '^help-' && break; sleep 0.5; done
out=$(python3 - <<PY
import socket, json
s = socket.socket(socket.AF_UNIX); s.connect("/run/capsule-helper.sock")
s.send(json.dumps({"op": "volume", "unit": "help", "name": "disk", "size": "16M"}).encode())
s.settimeout(20); print(s.recv(8192).decode())
PY
)
echo "$out" | grep -q 'in use' && pass "a volume a capsule is using cannot be opened a second time" || fail "double open: $out"
"$CAPSULE" kill "$("$CAPSULE" ps | grep '^help-' | cut -d' ' -f1)"; wait || true

# ---- the encrypted store ----
echo MARKER-PLAINTEXT > app/rootfs/marker
manifest 'cat /marker' ",\"policy\":{\"hosts\":[\"$HOSTID\"]}"; seal
mv app/rootfs plain
out=$(run)
[ "$out" = MARKER-PLAINTEXT ] || fail "encrypted capsule without root: $out"
STORE=$(sudo sh -c "ls /var/lib/capsule/users/$ME/sealed/*.img" 2>/dev/null | head -1)
[ -n "$STORE" ] || fail "the encrypted store was not used"
sync
sudo grep -aq MARKER-PLAINTEXT "$STORE" && fail "the store on disk holds the capsule's contents in the clear"
sleep 1
mount | grep -q "/run/capsule-helper/$ME/sealed" && fail "the store was left mounted after the run"
[ -z "$(ls -A "$CAPSULE_RUN" 2>/dev/null)" ] || fail "decrypted files were left in memory-backed run state"
mv app/rootfs.enc enc.aside
out=$(run)
mv enc.aside app/rootfs.enc
[ "$out" = MARKER-PLAINTEXT ] && pass "encrypted capsule without root: decrypted once into the encrypted store, not into memory" || fail "second start decrypted again: $out"
sudo rm -f "$STORE" "${STORE%.img}.lock"
mv plain app/rootfs; rm -f app/rootfs.enc app/marker

# ---- a port below 1024 ----
manifest 'nc -ll -p 8080 -e /bin/reply' ',"publish":[8080]'; seal
run -publish 127.0.0.1:81:8080 > bg.out &
for i in 1 2 3 4 5 6 7 8 9 10; do [ "$(busybox nc -w 2 127.0.0.1 81 2>/dev/null)" = published-ok ] && break; sleep 0.5; done
[ "$(busybox nc -w 3 127.0.0.1 81)" = published-ok ] && pass "a port below 1024 is published without root" || fail "low port: $(cat bg.out)"
"$CAPSULE" kill "$("$CAPSULE" ps | grep '^help-' | cut -d' ' -f1)"; wait || true

# ---- kernel tunnels ----
mesh() { # $1 = dir, $2 = name, $3 = script, $4 = peers
  mkdir -p "$1/rootfs/bin"; cp "$BUSYBOX" "$1/rootfs/bin/busybox"
  for a in sh echo nc sleep; do ln -sf busybox "$1/rootfs/bin/$a"; done
  printf '#!/bin/sh\necho over-the-tunnel\n' > "$1/rootfs/bin/reply"; chmod 755 "$1/rootfs/bin/reply"
  printf '{"name":"%s","command":["/bin/sh","-c","%s"],"network":"mesh","mesh":{"peers":[%s]},"limits":{"memory":"32M","pids":16}}\n' "$2" "$3" "$4" > "$1/capsule.json"
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
  key=$("$CAPSULE" identity "$2" | grep ^key | tr -s ' ' | cut -d' ' -f2)
  kem=$("$CAPSULE" identity "$2" | grep ^kem | tr -s ' ' | cut -d' ' -f2)
  "$CAPSULE" card -key dev.key -name "$2" -mesh-key "$key" -kem "$kem" ${5:+-endpoint "$5"} > "cards/$2.card"
}
mesh a a 'nc -ll -p 7000 -e /bin/reply' '{"name":"b","in":[7000]}' 127.0.0.1:51901
mesh b b 'for i in 1 2 3 4 5 6 7 8 9 10; do nc -w 2 a 7000 && exit 0; sleep 1; done; echo no-answer' '{"name":"a","out":[7000]}'
"$CAPSULE" run -trust "$W/dev.pub" -peers cards -listen 51901 a > a.out 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10; do "$CAPSULE" ps | grep -q '^a-' && break; sleep 0.5; done
out=$("$CAPSULE" run -trust "$W/dev.pub" -peers cards b 2>&1 | grep -v '^capsule:' || true)
[ "$out" = over-the-tunnel ] || fail "mesh without root through the helper: $out / $(cat a.out)"
pid=$(head -1 "$(readlink "$W"/run/a-*.cg)/cgroup.procs")
kind=$(nsenter -t "$pid" -U --preserve-credentials -n ip -d link show wg0 2>&1 || true)
echo "$kind" | grep -q wireguard && pass "mesh without root runs on the kernel's WireGuard" || fail "the tunnel is not the kernel's: $kind"
"$CAPSULE" kill "$("$CAPSULE" ps | grep '^a-' | cut -d' ' -f1)"; wait || true

# ---- what the helper refuses ----
ask() { python3 - "$1" "${2:-}" <<'PY'
import socket, json, sys, os, array
s = socket.socket(socket.AF_UNIX); s.connect("/run/capsule-helper.sock")
anc = []
if sys.argv[2]:
    fd = os.open(sys.argv[2], os.O_RDONLY)
    anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
s.sendmsg([sys.argv[1].encode()], anc)
s.settimeout(20); print(s.recv(8192).decode())
PY
}
ask '{"op":"tunnel"}' /proc/self/ns/net | grep -q 'does not belong to you' && pass "refuses to put a tunnel in the host's own network" || fail "tunnel into the host network: $(ask '{"op":"tunnel"}' /proc/self/ns/net)"
ask '{"op":"tunnel"}' /proc/self/ns/mnt | grep -q 'not a network namespace' && pass "refuses anything that is not a network namespace" || fail "tunnel with a wrong file"
ask '{"op":"volume","unit":"../../etc","name":"x","size":"1M"}' | grep -q 'not a volume name' && pass "refuses a volume name that is a path" || fail "path as volume name"
ask '{"op":"listen","addr":"127.0.0.1:8080"}' | grep -q 'only opens ports below 1024' && pass "refuses ports a user can open alone" || fail "high port"
ask '{"op":"sh","name":"id"}' | grep -q 'not something the helper does' && pass "has no request that runs a command" || fail "unknown request"
ask '{"op":"store","hash":"../x"}' | grep -q 'not a sealed rootfs' && pass "refuses a store name that is a path" || fail "path as store name"
CAPSULE_HELPER=off; export CAPSULE_HELPER
manifest 'echo hi' "$SIZED"; seal
run | grep -q 'needs root or the capsule helper' && pass "without the helper, a sized volume is refused as before" || fail "helper off: $(run)"
echo "all helper checks passed"
