# Changelog

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
