#!/bin/sh
# Measures what capsule itself costs, as root on a Linux host:
#   sudo sh test/bench.sh
# It reports start-up time, the memory and idle CPU of the supervising
# process, disk used by stored copies, and how the log grows. Needs capsule
# installed, curl, and the examples' downloads (about 250 MB the first time).
set -eu
REPO=$(dirname "$(dirname "$(realpath "$0")")")
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data"
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  pkill -TERM -P $$ 2>/dev/null || true
  sleep 2
  for id in $(capsule ps 2>/dev/null | tail -n +2 | cut -d' ' -f1); do capsule kill "$id" 2>/dev/null || true; done
  sleep 1
  chmod -R u+rwx "$W" 2>/dev/null; rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT
cd "$W"
capsule keygen dev
T="-trust $W/dev.pub"
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
row() { printf '%-58s %s\n' "$1" "$2"; }

for e in python-web python-job java-web; do sh "$REPO/examples/build.sh" $e dev.key >/dev/null; done
OUT="$REPO/examples/out"

# A capsule that does nothing, on each root filesystem, so only capsule's own work is timed.
variant() { # $1 = new name, $2 = source capsule, $3 = command as JSON
  rm -rf "$1"; mkdir "$1"; cp -a "$2/rootfs" "$1/rootfs"
  echo "{\"name\":\"$1\",\"command\":$3,\"limits\":{\"memory\":\"64M\",\"pids\":32}}" > "$1/capsule.json"
  capsule seal -key dev.key "$1" >/dev/null
}
variant small "$OUT/pyweb" '["/bin/true"]'; rm -rf small/rootfs/opt; capsule seal -key dev.key small >/dev/null
variant medium "$OUT/pyweb" '["/bin/true"]'
variant large "$OUT/javaweb" '["/bin/true"]'
variant idle "$OUT/pyweb" '["/bin/sleep","600"]'; rm -rf idle/rootfs/opt; capsule seal -key dev.key idle >/dev/null

echo "== start-up: time for 'capsule run' of a capsule that exits at once =="
for c in small medium large; do
  size=$(du -sm $c/rootfs | cut -f1)
  t=$(date +%s%N); capsule run $T $c; first=$(ms $t)
  best=999999
  for _ in 1 2 3 4 5; do t=$(date +%s%N); capsule run $T $c; n=$(ms $t); [ $n -lt $best ] && best=$n; done
  row "$c (${size}M rootfs): first run, then best of 5 repeats" "${first}ms, ${best}ms"
done

echo "== the supervising process of an idle capsule =="
i=0; while [ $i -lt 10 ]; do capsule run $T -instance n$i idle & i=$((i + 1)); done
sleep 5
kb() { grep "^$2:" /proc/$1/smaps_rollup | tr -s ' ' | cut -d' ' -f2; }
total=0; dirty=0; n=0
for pid in $(pgrep -f "capsule run $T -instance n"); do
  total=$((total + $(kb $pid Pss))); dirty=$((dirty + $(kb $pid Private_Dirty))); n=$((n + 1)); one=$pid
done
row "memory per capsule, with $n running (their share of everything)" "$(( total / n / 1024 )).$(( total / n % 1024 * 10 / 1024 ))M"
row "  of which memory only that supervisor uses" "$(( dirty / n / 1024 )).$(( dirty / n % 1024 * 10 / 1024 ))M"
row "threads" "$(ls /proc/$one/task | wc -l)"
ticks() { cut -d' ' -f14,15 /proc/$one/stat | tr ' ' '+' | bc; }
a=$(ticks); sleep 20; b=$(ticks)
row "CPU used by one supervisor while idle for 20s" "$(( (b - a) * 10 ))ms"
for id in $(capsule ps | grep '^idle-' | cut -d' ' -f1); do capsule kill "$id"; done; wait || true

echo "== the autoscaler of an idle scaled capsule =="
rm -rf scaled; mkdir scaled; cp -a idle/rootfs scaled/rootfs
echo '{"name":"scaled","command":["/bin/sleep","600"],"limits":{"memory":"64M","cpus":1,"pids":32},"scale":{"min":2,"max":4,"cpu":70,"memory_max":"256M"}}' > scaled/capsule.json
capsule seal -key dev.key scaled >/dev/null
capsule run $T scaled 2>/dev/null & sleep 6
one=$(pgrep -f "capsule run $T scaled" | head -1)
a=$(ticks); sleep 20; b=$(ticks)
row "CPU used watching 2 replicas for 20s" "$(( (b - a) * 10 ))ms"
row "its memory (private)" "$(( $(kb $one Private_Dirty) / 1024 )).$(( $(kb $one Private_Dirty) % 1024 * 10 / 1024 ))M"
kill -TERM $one; wait || true

echo "== disk: verified copies kept in the store =="
capsule prune >/dev/null
stored() { du -sm "$CAPSULE_DATA/store" | cut -f1; }
capsule run $T "$OUT/pyjob" >/dev/null 2>&1 || true
row "one Python capsule (a 140M runtime plus its code)" "$(stored)M"
variant other "$OUT/pyjob" '["/bin/true"]'; echo different > other/rootfs/app/job.py; capsule seal -key dev.key other >/dev/null
capsule run $T other
row "... plus a second capsule on the same runtime" "$(stored)M"
echo '# changed' >> other/rootfs/app/job.py; capsule seal -key dev.key other >/dev/null
capsule run $T other
row "... plus a new version of that one (one file changed)" "$(stored)M"

echo "== the log =="
before=$(wc -c < "$CAPSULE_DATA/log.jsonl"); lines=$(wc -l < "$CAPSULE_DATA/log.jsonl")
row "bytes per entry (the first of a file also carries the host's key)" "$(( (before - $(head -1 "$CAPSULE_DATA/log.jsonl" | wc -c)) / (lines - 1) ))"
i=0; while [ $i -lt 150 ]; do capsule run $T small; i=$((i + 1)); done
best=999999
for _ in 1 2 3 4 5; do t=$(date +%s%N); capsule run $T small; n=$(ms $t); [ $n -lt $best ] && best=$n; done
row "start-up of the small capsule after $(wc -l < "$CAPSULE_DATA/log.jsonl") log entries" "${best}ms"
