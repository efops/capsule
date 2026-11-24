#!/bin/sh
# Runs the commands of docs/GUIDE.md, in the guide's order, on a real host:
#   sudo sh test/guide.sh <path to the capsule binary>
# It installs capsule the way the guide says, so run it on a test machine. It
# needs internet access (for a small Alpine root filesystem), systemd, and
# busybox for the host-side `nc`. It removes what it creates when it ends.
set -eu
BINARY=$(realpath "$1")
REPO=$(dirname "$(dirname "$(realpath "$0")")")
case $(uname -m) in aarch64) ARCH=aarch64 ;; *) ARCH=x86_64 ;; esac
W=$(mktemp -d)
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  systemctl stop capsule@notes 2>/dev/null || true
  pkill -TERM -P $$ 2>/dev/null || true
  sleep 2
  for id in $(capsule ps 2>/dev/null | tail -n +2 | cut -d' ' -f1); do capsule kill "$id" 2>/dev/null || true; done
  sleep 1
  for v in notes vault web ask shop shop-r1 shop-r2; do capsule volumes -rm "$v" 2>/dev/null || true; done
  rm -rf /var/lib/capsule/apps/notes /var/lib/capsule/apps/hello /etc/capsule/apps/notes.env /etc/capsule/trust.d/dev.pub \
    /etc/capsule/ledger /etc/capsule/delegation /etc/capsule/policy.d/team.cue /etc/capsule/peers.d/*.card /var/lib/capsule/guide-ledger
  rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT
cd "$W"
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }
ask() { busybox nc -w 3 127.0.0.1 "$1" 2>/dev/null || true; }

# ---- 2. Install ----
sh "$REPO/dist/install.sh" "$BINARY" >/dev/null
capsule version | grep -q '^capsule ' || fail "capsule is not installed"
pass "2. install"

# ---- 3. Your first capsule ----
capsule keygen dev
install -m 644 dev.pub /etc/capsule/trust.d/dev.pub
curl -fsSLO "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/$ARCH/alpine-minirootfs-3.20.3-$ARCH.tar.gz"
capsule init -rootfs "alpine-minirootfs-3.20.3-$ARCH.tar.gz" hello >/dev/null
capsule seal -key dev.key hello >/dev/null
[ "$(capsule run hello)" = "hello from hello" ] || fail "the first capsule did not run"
capsule inspect hello | grep -q "would run it" || fail "inspect does not say it would run"
sed -i 's/hello from hello/changed/' hello/capsule.json
capsule run hello 2>&1 | grep -q "capsule.json was changed after sealing" || fail "a changed capsule was not refused"
capsule seal -key dev.key hello >/dev/null
[ "$(capsule run hello)" = changed ] || fail "the resealed capsule did not run"
pass "3. first capsule: init, seal, run, refused when changed, runs when resealed"

# ---- 4. A service that keeps data ----
cp -a hello notes
cat > notes/capsule.json <<'JSON'
{
  "name": "notes",
  "command": ["/bin/sh", "-c", "date >> /data/visits; exec nc -lk -p 8080 -e cat /data/visits"],
  "publish": [8080],
  "volumes": [{"name": "data", "path": "/data"}],
  "limits": {"memory": "64M", "cpus": 1, "pids": 64}
}
JSON
capsule seal -key dev.key notes >/dev/null
capsule run -publish 127.0.0.1:8080:8080 notes & sleep 3
[ "$(ask 8080 | wc -l)" = 1 ] || fail "the service did not answer on its published port"
id=$(capsule ps | grep '^notes-' | cut -d' ' -f1)
capsule resize -memory 128M "$id"
capsule ps | grep '^notes-' | grep -q "128.0M" || fail "resize is not visible in ps"
capsule kill "$id"; wait || true
capsule run -publish 127.0.0.1:8080:8080 notes & sleep 3
[ "$(ask 8080 | wc -l)" = 2 ] || fail "the volume did not keep its data between runs"
capsule kill "$(capsule ps | grep '^notes-' | cut -d' ' -f1)"; wait || true
capsule volumes | grep -q '^notes .*data' || fail "volumes does not list the data"
capsule log | tail -1 | grep -q "chain intact" || fail "the log does not verify"
pass "4. a service: published port, ps, resize, kill, data kept in a volume, log"

# ---- 5. Run it as a system service ----
cp -a notes /var/lib/capsule/apps/notes
echo 'CAPSULE_ARGS=-publish 127.0.0.1:8080:8080' > /etc/capsule/apps/notes.env
systemctl start capsule@notes
sleep 4
[ "$(ask 8080 | wc -l)" = 3 ] || fail "the systemd service is not answering: $(systemctl status capsule@notes --no-pager 2>&1 | tail -4)"
systemctl stop capsule@notes
pass "5. systemd service, with the same data"

# ---- 6. Conditions: approvals and a time lock ----
capsule keygen alice; capsule keygen bob
cp -a hello vault
cat > vault/capsule.json <<JSON
{
  "name": "vault",
  "command": ["/bin/sh", "-c", "echo opened"],
  "policy": {"approvals": {"required": 2, "signers": ["$(cat alice.id)", "$(cat bob.id)"]}}
}
JSON
capsule seal -key dev.key vault >/dev/null
capsule run vault 2>&1 | grep -q "has 0 of 2 required approvals" || fail "ran without approvals"
capsule approve -key alice.key vault >/dev/null
capsule approve -key bob.key vault >/dev/null
[ "$(capsule run vault)" = opened ] || fail "did not run with both approvals"
sed -i 's/"policy": {/"policy": {"not_before": "2099-01-01T00:00:00Z", /' vault/capsule.json
capsule seal -key dev.key vault >/dev/null
capsule run vault 2>&1 | grep -q "time-locked until 2099" || fail "a time-locked capsule was not refused"
pass "6. policy: two approvals needed, then a time lock"

# ---- 7. Two capsules talking over the mesh ----
capsule delegate -key dev.key -host "$(capsule host | awk '/^sign/{print $2}')" web ask > /etc/capsule/delegation
for n in web ask; do cp -a hello $n; done
cat > web/capsule.json <<'JSON'
{
  "name": "web",
  "command": ["/bin/sh", "-c", "echo hello from web > /tmp/page; exec nc -lk -p 8080 -e cat /tmp/page"],
  "network": "mesh",
  "mesh": {"peers": [{"name": "ask", "in": [8080]}]}
}
JSON
cat > ask/capsule.json <<'JSON'
{
  "name": "ask",
  "command": ["/bin/sh", "-c", "sleep 3; nc -w 3 web 8080"],
  "network": "mesh",
  "mesh": {"peers": [{"name": "web", "out": [8080]}]}
}
JSON
capsule seal -key dev.key web >/dev/null; capsule seal -key dev.key ask >/dev/null
capsule run -listen 51820 -advertise 127.0.0.1 web & sleep 3
[ "$(capsule run ask)" = "hello from web" ] || fail "one capsule could not reach the other over the mesh"
capsule kill "$(capsule ps | grep '^web-' | cut -d' ' -f1)"; wait || true
pass "7. mesh: one capsule calls another by name"

# ---- 8. Scaling ----
cp -a hello shop
cat > shop/capsule.json <<'JSON'
{
  "name": "shop",
  "command": ["/bin/sh", "-c", "cat /proc/sys/kernel/random/uuid > /tmp/id; exec nc -lk -p 8080 -e cat /tmp/id"],
  "publish": [8080],
  "limits": {"memory": "64M", "cpus": 1, "pids": 64},
  "scale": {"min": 2, "max": 4, "cpu": 70, "memory_max": "256M"}
}
JSON
capsule seal -key dev.key shop >/dev/null
capsule run -publish 127.0.0.1:8081:8080 shop 2>/dev/null & SHOP=$!
sleep 7
[ "$(capsule ps | grep -c '^shop-')" = 2 ] || fail "scale did not start two replicas"
[ "$(for i in 1 2 3 4; do ask 8081; done | sort -u | wc -l)" = 2 ] || fail "the published port did not reach both replicas"
kill -TERM $SHOP; wait $SHOP || true
pass "8. scale: two replicas behind one published port"

# ---- 9. More than one host: the ledger, publish and fetch ----
echo "file:///var/lib/capsule/guide-ledger" > /etc/capsule/ledger
capsule ledger check | grep -q "verdict: safe" || fail "the ledger check did not pass"
capsule publish -key dev.key notes >/dev/null
rm -rf /var/lib/capsule/apps/notes
capsule fetch notes | grep -q "installed notes" || fail "fetch did not install the published capsule"
capsule witness >/dev/null || fail "witness failed"
capsule log -ledger | tail -1 | grep -q "published and matching" || fail "the log does not match what was published"
pass "9. ledger: check, publish, fetch, witness"

# ---- 10. Building from a CUE file ----
cat > built.cue <<'CUE'
_greeting: "built from CUE"
capsule: {
	name: "built"
	command: ["/bin/sh", "-c", "cat /etc/greeting"]
	limits: {memory: "64M", pids: 32}
}
rootfs: {
	from: "hello/rootfs"
	files: "/etc/greeting": contents: "\(_greeting)\n"
}
CUE
capsule build -key dev.key built.cue >/dev/null
[ "$(capsule run built)" = "built from CUE" ] || fail "the CUE-built capsule did not run"
echo 'capsule: limits: memory: string' > /etc/capsule/policy.d/team.cue
capsule run web 2>&1 | grep -q "capsule.limits.memory: must be set" || fail "the host rule did not refuse a capsule with no memory limit"
[ "$(capsule run built)" = "built from CUE" ] || fail "the host rule refused a capsule that does set a memory limit"
rm /etc/capsule/policy.d/team.cue
pass "10. CUE: build file, and a host rule that refuses a capsule"

echo "all checks passed"
