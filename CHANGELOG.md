# Changelog

## 0.3.1

### Added

- `/run/capsule/heard`: how many other instances of its cell a supervisor hears. A standby can only notice its holder going silent once it has heard it, and this shows when that is so.
- `test/fleet.sh`: a tissue on three separate machines, driven over SSH (#11).

### Tested on real machines

Three 2-CPU servers (Ubuntu 26.04, kernel 7.0, x86-64) on a private network, with the ledger first in a folder shared over NFS and then in an S3-compatible object store.

- Every single-host suite passes on that kernel and release, a newer pair than the project had been run on. The latency suite was not run: it needs four cores.
- The object store passes `capsule ledger check`: create-once held in every race.
- One order was answered by all three machines in 9 to 11 seconds, each picking it up on its own timer.
- A tissue placed two instances on two machines in 7 to 12 seconds.
- A caller on the third machine reached both instances through WireGuard tunnels between the machines.
- One machine was rebooted. With the ledger in the object store the standby was running its instance 20 to 26 seconds later, in four runs. The rebooted machine did not start a third copy.
- A hot standby on another machine took over after 102 to 117 ms of silence, with `detect` at 100 ms.
- A drained machine's cell restarted on another machine with the same data 12 to 22 seconds later.

### Found

- **A ledger on NFS needs `noac,lookupcache=none`.** With default caching the hosts did not see each other's orders for up to a minute. `capsule ledger check` cannot detect this, as it runs on one host.
- **NFS can stall a takeover by its lease time.** In one run with the ledger on NFS, the surviving machines' reads hung for about 90 seconds after the third was rebooted, and the takeover took 112 seconds. That is NFS version 4 holding the dead client's state. It did not happen with the object store.
- **Tunnels form more slowly when cards are shared over NFS**, because a change made by another host is seen by polling every 2 seconds. A caller that starts and connects at once may at first see only some of the instances.
- **A standby that has not yet heard its holder does not take over.** One run froze the holder before the two had heard each other, and nothing happened. That is intended, but it was invisible; `/run/capsule/heard` now shows it.

### Known issues and limits

- Cards for the mesh still need a folder the hosts share; they do not travel through the ledger.
- Everything listed under 0.3.0 still applies.

## 0.3.0

### Added

- **Takeover in milliseconds** (#4). A cell with a hot standby and `detect` (for example `"50ms"`) has its instances watch each other directly over the mesh. The standby promotes itself the moment the holder falls silent, with no ledger and no timer on the path. Measured with `detect` at 100 ms: 99 to 118 ms on the arm64 test machine, 260 to 297 ms on the emulated x86-64 one.
- **Roles** (#4). A program in a tissue reads `/run/capsule/role`: `holder`, `standby`, or `holder promoted`.
- **Strict takeover is enforced by the supervisor** (#4). A strict cell's own supervisor stops it when its lease runs out unrenewed, even if nothing else on the host is running.
- **Data follows its cell** (#6). `snapshot` on a cell with volumes ships encrypted copies of them, and a host taking the cell over restores the latest first.
- **Draining a host**: `"drain": true` hands over everything a host holds, with a last snapshot of any data, before it is taken out of the tissue.
- **Devices for the latency profile** (#5): `latency.devices` gives a capsule device files of the host, which with huge pages and locked memory is what a kernel-bypass network stack asks for.
- `/etc/capsule/advertise`: a host's address for the mesh, set once for every capsule it runs.

### Known issues and limits

- **Millisecond takeover needs the mesh.** The instances reach each other through their tunnels, so the cell must use `network: mesh` or `cell`, and the hosts must share their cards. A warm standby still waits for a lease to lapse.
- **A promoted standby and a slow holder can overlap.** If the holder was only stalled and comes back within its lease, both believed they were the holder for that moment. The tissue then makes the standby a standby again. Use `takeover: strict` where that must never happen.
- **A crash loses up to one snapshot interval.** Snapshots are periodic copies, not replication. A drain loses nothing.
- **Live snapshots need a sized volume.** A plain volume is copied only when its cell is stopped, which a drain does; a cell on plain volumes that crashes stays pinned to its host.
- **Encrypted volumes** come back on another host only if that host can open them (`recovery.d`, or `capsule volumes -grant`).
- **Taking a host out without draining it** leaves its cells with data unable to move, and its last leases are simply ignored.
- **The latency profile is still unbenchmarked**, needs root, and no kernel-bypass stack has been run in a capsule (#9).
- **Tested against a shared-directory ledger, on one machine playing several hosts.**
- Everything listed under 0.2.0 that is not named above still applies.

## 0.2.0

### Added

- **The tissue: orchestration without a scheduler** (#2, #3, #4, #7). An operator signs which cells must be alive; hosts keep it true between them, with no control plane and no leader.
  - Cells are grown because something needs them, read from the sealed manifests, and stopped when nothing does.
  - A vacant slot goes to a host by a draw from the drand beacon: unpredictable beforehand, the same for every host, and checkable afterwards.
  - Slots are held by leases with terms. A lapsed lease is taken over; the old holder stands down when it sees the higher term.
  - Warm and hot standbys; per cell, fast or strict takeover.
  - New releases roll out a few instances at a time in an order the beacon picks. A release that does not stay up is put back and held back on every host.
  - Signed limits: a maximum per cell, a budget for the tissue, and what each host offers. Placement load is computed from leases and sealed limits, never self-reported.
  - `capsule tissue`, `capsule tissue status`, `capsule tend`.
- **Latency profile** (#5): `latency` in the manifest gives a capsule dedicated cores with no CPU quota, memory from their NUMA node, the right to lock memory, huge pages, and a host network interface of its own.
- `capsule publish` now also keeps a signed history of releases, which is what lets a tissue skip a release that failed.

### Changed

- `capsule-orders.service` also runs `capsule tend`.
- A capsule started by an order or a tissue counts as up only if it stays up, not if it is seen for an instant.

### Fixed

- A mesh capsule failed to start ("installing firewall: numerical result out of range") if a peer it connects out to had no instance yet.
- Restarting a capsule's unit could fail with "already loaded" when systemd had not yet cleared the stopped unit.
- The scale test left one supervisor running after the suite.

### Known issues and limits

- **Not instant.** Hosts act on a 5-second timer. Placement takes a few seconds; taking over from a dead host takes one lease plus a pass (about 35 seconds by default, 12 to 15 with `"lease": 4`). Millisecond failure detection between a holder and its standby is not built (#4 stays open).
- **Cells with volumes do not move.** They only come back on the host that has their data. Shipping snapshots to a standby is not built (#6 stays open).
- **Hot standbys are not told their role.** Both copies run identically; the program must cope with that.
- **Latency profile is unbenchmarked.** It is tested for being applied, on virtual machines. Kernel-bypass stacks (DPDK, OpenOnload) are not supported, and the profile needs root (#5 stays open).
- **Strict takeover depends on the host's timer.** The stop happens on the next pass after the lease can no longer be renewed, not inside the capsule's supervisor.
- **Capsules published with 0.1.0 must be published again** before a tissue can plan with them.
- **Tested against a shared-directory ledger only.** The tissue was not exercised on S3, Vault or Artifactory, or between separate machines.
- Everything listed under 0.1.0 still applies.

## 0.1.0

First release: sealed capsules, the kernel sandbox, hybrid post-quantum signatures and key wraps, policy, the mesh and cells, the fleet ledger, scaling, signed orders in place of SSH, and the helper for running without root.

### Known limits

- Orders give no interactive terminal and do not maintain the host's own operating system.
- Orders were exercised against a shared-directory ledger only.
- Root on a host can read a running capsule's memory.
