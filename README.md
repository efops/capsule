# capsule

A runtime that runs nothing unless it is sealed, trusted and allowed.

<a href="https://www.buymeacoffee.com/efkanisazade"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy me a coffee" height="40"></a>

A capsule is a plain directory: a manifest, a root filesystem and a signature
over both. `capsule run` checks the signature against keys the host trusts,
checks the conditions sealed into the manifest, and only then starts the
program in a kernel sandbox. There is no daemon, no image format and no
registry: `capsule run` is the capsule's parent process, and everything else
is files.

**New here? Start with [docs/GUIDE.md](docs/GUIDE.md)**, a step-by-step
walkthrough. Then:

| Document | For |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Requirements, installing, upgrading, removing |
| [docs/GUIDE.md](docs/GUIDE.md) | Learning capsule from the first run to a fleet |
| [docs/CLI.md](docs/CLI.md) | Every command and option |
| [examples/](examples/README.md) | Python and Java applications to build and run |

This README is the design reference.

## Cryptography

Everything is hybrid: a classical scheme and a post-quantum one together, so
an attacker must break both.

| Use | Schemes |
|---|---|
| Signatures: seals, approvals, revocations, cards, delegations, the host log | Ed25519 and ML-DSA-65; both must verify |
| Wrapping an encrypted capsule's key for a host | X25519 and ML-KEM-768; both shared secrets feed the wrapping key |
| Encrypting the rootfs itself | AES-256-GCM |

Hybrid public keys are about 2 KB, so manifests name keys by **id**, the
SHA-256 of the public key. `capsule keygen dev` writes `dev.key` (private),
`dev.pub` (give this to hosts) and `dev.id` (put this in manifests).

Mesh and cell traffic uses the kernel's WireGuard with an ML-KEM-768 secret
mixed in as its preshared key (see Post-quantum tunnels), for cards that
carry an ML-KEM key. One part is not post-quantum: `timelock` and ticks rely
on the drand network's own cryptography.

## Requirements

- Linux 5.11 or later with cgroup v2. Tested on Ubuntu 25.04 (kernel 6.14, arm64) and Ubuntu 24.04 (kernel 6.8, x86-64).
- Go 1.26 to build.
- For mesh networking: the WireGuard and nftables kernel modules.
- Without root: a systemd user session (or a cgroup already delegated to you). On Ubuntu 24.04 and later, also the AppArmor profile that `make install` installs. Membership of the `capsule` group adds what otherwise needs root (see "Without root" below).
- For orders: systemd, and `nsenter` (util-linux) for `exec`.

`keygen`, `init`, `build`, `render`, `seal`, `approve`, `verify`, `inspect`, `card` and `delegate` also work on macOS, so capsules can be built and signed on a laptop.

## Install

```sh
make linux                                        # on a machine with Go
sudo sh dist/install.sh bin/capsule-linux-amd64   # on the host; or -arm64
```

The script installs the binary, the systemd units, the AppArmor profile where
needed, the `capsule` group, and creates `/etc/capsule` and `/var/lib/capsule`.

## Quick start

```sh
# 1. A signing key. Hosts run only what a key they trust has sealed.
capsule keygen dev
sudo cp dev.pub /etc/capsule/trust.d/

# 2. A capsule, from any root filesystem: a directory or a tarball.
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
capsule init -rootfs alpine-minirootfs-3.20.3-x86_64.tar.gz hello

# 3. Seal it, and run it.
capsule seal -key dev.key hello
sudo capsule run hello          # or without sudo, in a user namespace
```

Change anything in `hello/` and `run` refuses until it is sealed again.
`capsule inspect hello` says whether this host would run a capsule, and if
not, why.

## Building and deploying from CUE

Capsules and fleets can be declared in [CUE](https://cuelang.org). The schema
is built in and closed, so a misspelt field is an error with a file and line.

**A build file** declares the manifest and how to assemble the rootfs:

```cue
_port: 8080
capsule: {
	name: "web"
	command: ["/usr/bin/server", "--port", "\(_port)"]
	publish: [_port]
	limits: {memory: "256M", cpus: 1, pids: 256}
}
rootfs: {
	from:   "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz"
	sha256: "<hash of that file>"   // required for a URL; the download is refused if it differs
	files: {
		"/usr/bin/server": {source: "dist/server", mode: 0o755}
		"/etc/app.conf":   contents: "port=\(_port)\n"
	}
}
```

```sh
capsule build -key dev.key web.cue        # writes ./web, sealed
```

`rootfs.add` lays further archives or folders over the base, in order, before
`files`: a language runtime, then your application. Each entry is
`{from, sha256?, to, strip}`, where `strip` drops leading folders that a
runtime's archive wraps everything in.

What gets sealed is the rendered `capsule.json`, never the template, so the
signed artifact stays plain JSON anyone can read.

**Rules** are CUE files of the same shape. Pass them to `build -rules`, and
install them on a host in `/etc/capsule/policy.d/` to have that host refuse
any capsule that breaks them, however validly it is sealed:

```cue
capsule: limits: {memory: string, pids: int}   // both must be set
capsule: network: *"none" | "mesh"             // no host networking here
```

**A fleet file** says which sealed capsules run where:

```cue
hosts: {"web-1": address: "10.0.0.5", "web-2": address: "10.0.0.6"}
deploy: [for h, _ in hosts {capsule: "web", host: h, listen: 51820, publish: ["8080:8080"]}]
```

```sh
capsule render -o deploy fleet.cue
```

This writes one directory per host, laid out as that host's own filesystem,
and prints the `rsync` and `systemctl` commands to put it there and start it.

## The manifest

`capsule.json` is everything a capsule is allowed to be and do. Unknown
fields are rejected.

```json
{
  "name": "web",
  "command": ["/usr/bin/server", "--port", "8080"],
  "env": {"MODE": "production"},
  "limits": {"memory": "256M", "cpus": 1, "pids": 256},
  "publish": [8080],
  "egress": [{"host": "api.example.com", "port": 443}],
  "network": "mesh",
  "mesh": {"peers": [{"name": "db", "out": [5432]}, {"name": "gateway", "in": [8080]}]},
  "policy": {
    "not_before": "2026-12-01T00:00:00Z",
    "expires": "2027-12-01T00:00:00Z",
    "max_runs": 0,
    "hosts": ["<host id>"],
    "approvals": {"required": 2, "signers": ["<key id>", "<key id>", "<key id>"]}
  },
  "unlock": [{"at": "2027-01-01T00:00:00Z", "env": {"FEATURE_X": "on"}}],
  "syscalls": ["read", "write", "..."]
}
```

| Field | Meaning |
|---|---|
| `name`, `command`, `env`, `hostname` | What runs. |
| `limits` | cgroup limits. `capsule resize` changes them on a running capsule. |
| `network` | `none` (default: loopback only), `host`, or `mesh`. |
| `publish` | Ports the host operator may expose with `run -publish hostport:capsuleport`. |
| `egress` | Outside hosts the capsule may reach, by name and port. Nothing else is reachable. |
| `mesh.peers` | Other capsules, by name, and the TCP (`in`, `out`) and UDP (`in_udp`, `out_udp`) ports allowed each way. |
| `policy` | Conditions that must hold before it runs; see below. |
| `unlock` | Environment variables that apply once their time has come. |
| `volumes` | Directories that persist between runs. Everything else is read-only or discarded. |
| `scale` | Run as replicas that grow and shrink with load, and grow memory when needed. |
| `syscalls` | An allow list that narrows the default profile. |

## What the sandbox does

- Own PID, mount, network, IPC and hostname namespaces.
- Read-only root filesystem, with a private writable `/tmp`.
- No capabilities, no new privileges, and a syscall allow list. Calls not on it fail as if the kernel lacked them, including calls newer than this build.
- cgroup limits on memory, CPU and process count.
- The rootfs that runs is a verified private copy, not the directory you pointed at. A killed supervisor is cleaned up after, tunnel included, by the next capsule command on the host.

## Policy

All of it is inside the signed manifest, so it cannot be edited after sealing.

| Policy | Effect |
|---|---|
| `not_before`, `expires` | Refused outside the window. |
| `timelock` | With `not_before`: the rootfs is encrypted to a future round of the public [drand](https://drand.love) network. Nobody, root included, can decrypt it before that round is published. Sealing and the first run after unlock need internet access. |
| `hosts` | Host ids (`capsule host` prints one). The rootfs is encrypted to these hosts; only they can decrypt it, and the plaintext never reaches the disk (see below). Sealing needs each host's public file: run `capsule host -export > web-1.host` on the host and pass `-host web-1.host` to `seal` or `build`. |
| `approvals` | Needs M of N signers, listed by key id, to run `capsule approve`. An approval covers one exact seal and can expire. |
| `max_runs` | Refused after N runs on a host; with `fleet`, after N runs across all hosts. |
| `permits` | Key ids allowed to issue run permits. A host then needs a permit naming it: `capsule permit -key <key> -host <host id> -runs 2 <dir>`. Checked offline. |
| `fleet` | Run count and revocation go through the fleet ledger; the capsule is refused if the ledger cannot be reached. |

`capsule revoke <dir>` stops one exact seal on this host.
`capsule revoke -key <key> <dir>` prints a signed notice that stops it on every
host whose `/etc/capsule/revoked.d/` receives it; with `-publish` it goes into
the fleet ledger instead and applies everywhere at once.

## The fleet ledger

Some facts need the whole fleet to agree: how many times something has run,
what has been revoked, and what each host's record looked like. Three layers
cover this, and a capsule uses only what its policy asks for.

| Layer | Gives | Needs |
|---|---|---|
| Permits | A run limit per host, checked with no network | Nothing |
| Witnessing | A record no single host can rewrite unnoticed | A ledger |
| Run slots and published revocations | A true fleet-wide count; revocation everywhere at once | A ledger, reachable at start |

A ledger is a shared store, named by one URL in `/etc/capsule/ledger`:

```
file:///mnt/shared/capsule                              a shared directory
s3://bucket/prefix?region=eu-west-1                     AWS S3
s3://bucket/prefix?endpoint=https://store.internal:9000 any S3-compatible store
vault://vault.internal:8200/secret/capsule              Vault KV version 2
artifactory://acme.jfrog.io/artifactory/capsule-ledger  a generic repository in Artifactory
```

Credentials come from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`,
`VAULT_TOKEN`, or `ARTIFACTORY_TOKEN` (or `ARTIFACTORY_USER` and
`ARTIFACTORY_PASSWORD`), in the environment or in `/etc/capsule/ledger.env`.

The store is asked for one thing: create a key only if it does not exist.
Everything put in it is signed, so it must stay available and keep what it is
given, but it is never trusted to tell the truth. A run slot is a key that can
be created once, which is why two hosts can never both take the same one.

**Check a store before relying on it.** Not every S3-compatible store applies
"create only if absent" atomically. One tested here told up to 9 of 12
simultaneous writers that each had created the same key, and kept only the
last value. So a claimed run slot is always read back, and counts only if the
stored value is the claimant's own. For S3-compatible endpoints that read-back
waits one second by default (`settle=` in the URL changes it). To measure a
store:

```sh
capsule ledger check
```

It races writers for fresh keys and reports whether create-once held, whether
the read-back resolved every race to one winner, and what `settle` to keep. A
shared directory, Vault and AWS S3 itself are atomic and need no pause.

Artifactory has no conditional upload, so it also relies on the read-back
unless the ledger's credentials are denied the Delete/Overwrite permission on
the repository, in which case Artifactory refuses a second upload itself. The
Artifactory backend has been tested against an imitation server only; run
`capsule ledger check` against yours before relying on it.

**Witnessing.** Each host publishes a signed statement of its log after every
entry, and co-signs the newest statement of every other host. A host that
later rewrites its log contradicts statements others have already signed:

```sh
capsule witness         # publish and co-sign now; `capsule run` also does this after each run
capsule log -ledger     # check a log against what its host published
```

A witness also remembers what it saw, so it reports published entries that
have since been removed from the store or replaced.

**When the ledger is unreachable**, a capsule with `fleet` is refused, because
the alternative is guessing. Every other capsule runs and prints a warning.

**Distributing capsules.** The same store carries capsules between machines.
`capsule publish -key <key> <dir>` uploads a sealed capsule, named by its
seal, and signs a pointer saying it is the current release.
`capsule fetch <name>` on a host installs it into `/var/lib/capsule/apps/`.
Fetch accepts only a release signed by a trusted key, checks the capsule
against its seal, and refuses a release older than one it has already
fetched. The systemd unit fetches before each start. A bucket, Artifactory or
a shared directory can hold capsules; Vault cannot.

## Networking

A capsule starts with loopback and nothing else. Three things can open it up,
all declared in the manifest:

- **Publish.** `run -publish 8080:8080` forwards a host port into the capsule.
- **Egress.** Each listed outside host resolves, inside the capsule, to a loopback address that the supervisor forwards to the real host. TLS runs end to end from the application.
- **Mesh.** The capsule's only interface is a WireGuard tunnel, so all traffic between capsules is encrypted and tied to a key.

### Mesh

A peer is a name, not a machine. Which machines currently run `db` comes from
**cards**: small signed statements that a mesh key is an instance of a name,
kept in `/etc/capsule/peers.d/`.

- A capsule reaches a peer by name. The kernel sends each new connection to one of that peer's live instances at random.
- Instances that stop serving get no new connections. Capsule first reads what the kernel already knows (an instance that is accepting or answering this capsule's connections is plainly up) and opens a check connection only when that leaves doubt: at once if it is sending and nothing comes back, every two seconds for an instance that is down, and at a gap lengthening to thirty seconds for one that is idle and healthy.
- Cards are re-read while capsules run, so instances come and go with no reseal and no restart.

Cards can be signed by hand (`capsule card`), or a host can issue its own once
a trusted key has delegated the names to it:

```sh
capsule delegate -key dev.key -host "$(sudo capsule host | awk '/^sign/{print $2}')" web db \
  | sudo tee /etc/capsule/delegation
sudo capsule run -listen 51820 -advertise 10.0.0.5 web   # writes its card, removes it on exit
```

Share `peers.d` between hosts (NFS, rsync, a synced repository) and instances
discover each other. The directory does not need to be trusted: cards are
verified against trusted keys.

Two replicas on one host need different `-instance` labels and `-listen` ports.

### Cells

`"network": "cell"` uses the same tunnels and cards, but replaces port lists
with named **receptors**: a cell `offers` services to named cells and
`needs` services from them.

- **Each receptor is carried on a mesh port derived from its name,** so nobody chooses or coordinates port numbers. `capsule inspect` shows it.
- **Port to port, the kernel carries it.** A need with a `port` resolves, by name, to the offering cell's service address. The caller's firewall rewrites the connection to a live instance and to the receptor's port in one step, the same balancing step the mesh uses. The offering cell's firewall admits it by the caller's address, which only the holder of that cell's key can send from, and rewrites it to the port the program listens on. No capsule process is in the path.
- **The supervisor carries only what the kernel cannot.** It listens on every receptor's port as well, and the firewall hands a receptor to the program directly only while the program is seen listening for it on every address (checked every two seconds). Until then, and for a program that listens on IPv4 only, the supervisor accepts the connection and joins it to the program. It always does so for socket files (`/run/cell/need/<name>`, `/run/cell/offer/<name>`), for offers with a grant, and for `proxy_protocol`. Those bytes are moved between sockets inside the kernel (`splice`), not copied into the supervisor.
- **What the program may send.** Its own packets may go only to instances of a cell it needs, on the port of a receptor it needs by `port`. Everything else that leaves must carry a mark that only the supervisor can set.
- **An offer can demand a grant:** a statement signed by a trusted key that cell A may use receptor R of cell B from one tick to another (`capsule grant`). Supervisors exchange these on a control channel, a UDP port of the cell's mesh address: the caller's sends each instance a hello per need with the grant it holds, at the start (it waits up to a second for the answers before the program runs), when its grants or the instances change, and every thirty seconds. The offering supervisor records until when each caller is covered, turns away connections and datagrams from callers that are not, and closes connections when their cover runs out.
- **Ticks are drand rounds.** A supervisor fetches the latest round, verifies its signature against the chain's key, and counts forward on the monotonic clock, refreshing in the background every five minutes. Without the beacon it uses the host clock, bounded below by the last proven tick, which is kept in the data folder.
- **A cell with no `port` anywhere may not create network sockets.** Its syscall filter then allows `socket()` for local sockets only.

### Post-quantum tunnels

WireGuard's key exchange is not post-quantum, but it mixes in an optional
preshared key, and capsule fills that with an ML-KEM-768 secret per pair of
instances.

- A card may carry the instance's ML-KEM key (`capsule identity` prints it; self-issued cards always include it). It is covered by the card's signature.
- For each pair, the instance with the lower mesh key encapsulates a fresh secret to the other's ML-KEM key and writes the ciphertext to `<a>-<b>.psk` in the cards folder. Both derive the preshared key from the secret, both mesh keys and the epoch.
- The maker replaces it every epoch (1200 ticks, an hour). Sessions already established continue; the next handshake uses the new key. The cards folder is watched with inotify, so on one host the other side follows within milliseconds; changes arriving another way are found by a two-second poll.
- The maker keeps its copy of the secret under the data folder, root-only, so a restart reuses it.
- A handshake between ends holding different secrets fails silently and WireGuard waits five seconds to retry, so the ends coordinate. The end that takes a secret up writes `<a>-<b>.psk.ack`; the maker, at its start, waits up to a fifth of a second for that before any traffic is sent, which covers a peer on the same host. If a tunnel may have been tried too early, exactly one end restarts it once both hold the secret: the taker if the maker's card has an endpoint, otherwise the maker.
- If the cards folder cannot be written, or a card has no ML-KEM key, that tunnel is WireGuard alone, as before.
- A forged `.psk` file can only make a tunnel fail to connect, which anyone able to write to the cards folder could already do by deleting cards.

## State

A capsule's root filesystem is read-only and its `/tmp` is discarded when it
stops. State lives in volumes:

```json
"volumes": [{"name": "data", "path": "/var/lib/app"}]
```

- A volume belongs to the capsule's **name**, not to one seal, so data carries over when you seal and run a new version.
- With `run -instance <label>`, each instance gets its own. Only one running instance may hold a set of volumes at a time.
- It is mounted without device files or setuid, and without execute permission unless the volume says `"exec": true`.
- Data is kept in `/var/lib/capsule/volumes/<name>/`. `capsule volumes` lists it; `capsule volumes -rm <name>` deletes it, and refuses while the capsule runs.

Give a volume a `size` and it becomes its own small filesystem, which adds
three things (and needs root, or the helper for a user in the `capsule` group):

```json
"volumes": [{"name": "data", "path": "/var/lib/app", "size": "10G", "encrypt": true}]
```

- **A hard limit.** Writes fail once it is full; it takes disk space only as it fills.
- **Encryption at rest**, with `"encrypt": true`. File contents and file names are encrypted by the filesystem with a key derived from the host secret, so the volume is unreadable off that host.
- **Snapshots while running.** `capsule volumes -snapshot <name>` freezes the volume for the moment of the copy and prints the snapshot's name; `capsule volumes -restore <name> <snapshot>` puts it back once the capsule is stopped. A plain directory volume can be snapshotted only while stopped.

An encrypted volume's key is random and stored beside it, wrapped for each
host allowed to open it: the host that made it, any hosts in
`/etc/capsule/recovery.d/` at that time, and any added later with
`capsule volumes -grant <name> <host file>`. Losing one host therefore does
not lose the data, as long as another holds the key.

Volume contents are your application's data and are not part of the seal.
Snapshots are kept in `/var/lib/capsule/snapshots/`; copy them off the host
for a real backup, and back up the host secret with them if they are encrypted.

## Scaling

**By hand.** `capsule resize -memory 1G -cpus 2 <id>` changes a running
capsule's limits. Running more copies, each with its own `-instance` label,
adds capacity; on the mesh, callers find them through their cards.

**Automatically.** Add a `scale` section and `capsule run` keeps a set of
replicas instead of one capsule:

```json
"limits": {"memory": "256M", "cpus": 1},
"scale": {"min": 1, "max": 4, "cpu": 70, "cooldown": "30s", "memory_max": "1G"}
```

| Setting | Effect |
|---|---|
| `min`, `max` | How many replicas on this host. |
| `cpu` | Add a replica when average CPU use stays above this percentage of `limits.cpus`; remove one when it stays below half of it. |
| `cooldown` | Minimum time between changes. Default 30s. |
| `memory_max` | When a replica reaches 85% of its memory limit, raise the limit by half, up to this. |
| `restart` | When a replica exits: `always` start it again (default), only `on-failure`, or `never`. With the last two, the run ends once every replica has finished. |
| `balance` | How a published port is shared: `least-connections` (default), `round-robin` or `random`. |
| `fleet` | Scale together with the other hosts running this capsule. |

Each replica has its own volumes. CPU is sampled every two seconds, and it
takes three samples above target to add a replica and five well below to
remove one. Memory is watched four times a second, and a soft limit just
below the hard one makes the kernel slow a capsule down, not kill it, in the
moments before its limit is raised.

**Reaching the replicas.** Two ways, and they can be combined:

- `run -publish 8080:8080` gives all replicas one host port. The autoscaler
  hands each connection to a replica as `balance` says, passing over any that
  is not answering. This needs neither the mesh nor root.
- On the mesh, each replica registers its own card and callers reach it
  within seconds. That needs root and the host to be delegated the capsule's
  name (see Mesh).

**Across hosts.** With `"fleet": true` and a ledger, every host running the
capsule shares its load, and they scale as one:

- The next replica goes to the host that has the fewest; one is taken from the host that has the most.
- Each host works that out from the same shared figures and only the named host acts, so two hosts do not both jump at once.
- `min` may be 0, for a host that only takes overflow. The fleet never scales itself below one replica in total.

Only hosts that a trusted key has delegated the capsule's name to are
counted, so a machine that merely has write access to the ledger cannot steer
scaling. The capsule must be installed on each host that is to take part;
`capsule fetch` does that from the ledger (below). The policy is sealed in
the manifest.

**How callers spread their connections** is chosen per peer in the caller's manifest:

```json
"mesh": {"peers": [{"name": "db", "out": [5432], "balance": "failover"}]}
```

| `balance` | Each new connection goes to |
|---|---|
| `random` (default) | a random live instance |
| `round-robin` | each live instance in turn |
| `sticky` | the same instance every time for this caller, while it lives |
| `least-connections` | the instance holding the fewest of this caller's open connections, re-counted every two seconds |
| `failover` | the one instance every caller agrees on, moving on only when it dies |

`failover` suits a single-writer service such as a primary database.

## Orchestration: the tissue

A tissue keeps a set of cells alive across a fleet with no scheduler, no
control plane and no leader. An operator signs one file naming the roots,
how many of each may live and which hosts may carry them. Each host then
applies three rules by itself, from the same public facts, on the timer that
already pulls orders (`capsule tend`):

- **Need.** A cell lives because it is a root or because a living cell needs it; needs are read from the sealed manifests (`needs`, and mesh peers with `out` ports). What nothing needs is stopped. A cell that is only needed gets one instance: nothing grows past a number an operator signed.
- **Draw.** A vacant slot goes to the host with the lowest `hash(beacon signature, slot, host id)`, scaled by the host's signed weight. The drand beacon's signature for a round cannot be known before it is published and is the same for everyone, so every host computes the same winner without talking to the others, placement cannot be steered towards a chosen host, and each lease records the round so the draw can be checked afterwards. Of the two best-placed hosts, the one that has committed less takes it.
- **Lease.** A slot is a ledger key that can be created once per term, renewed by a signed pulse every pass. A lease that lapses is taken with the next term; a host that sees a higher term than its own stops its copy.

```sh
capsule tissue -key ops.key prod.json
capsule tissue status
```

What follows from those:

- **Failover.** A host that stops renewing loses its slots after one lease. With `standby: warm` the runner-up of the same draw already has the capsule fetched and verified and goes first; with `standby: hot` it is already running it.
- **Milliseconds where asked.** With `standby: hot` and `detect: "50ms"`, the supervisors of a cell's instances send each other a datagram over the mesh every fifth of that time. A standby that hears nothing for the whole of it promotes itself at once by rewriting `/run/capsule/role`, which the program watches; the lease follows on the next pass. Neither the ledger nor the timer is on that path. Measured on the test machines: 103 to 118 ms from the holder's supervisor freezing to the standby's role changing, with `detect` at 100 ms.
- **Data follows its cell.** With `snapshot: "5m"`, a holder ships its volumes that often: frozen and copied, encrypted under a fresh key, the key wrapped with the hybrid wrap for every host of the tissue. A host that takes the cell over verifies and restores the latest snapshot first. Draining a host (`"drain": true`) stops the cell, ships a last snapshot and gives the slot up at once, so a planned move loses nothing.
- **Split brain is a choice per cell.** `takeover: fast` keeps running when the ledger cannot be reached, because nothing can take its slot meanwhile either, but a host cut off alone may overlap with its replacement until it is back. `takeover: strict` stops the cell just before its lease runs out, and it is the capsule's own supervisor that does so, from a deadline each renewal moves forward: it holds even if nothing else on the host is running.
- **Generations.** A new release is rolled out `step` instances at a time in an order fixed by the beacon round of its publication. An instance must stay up to count; if it does not, the previous release is put back, the host records a signed halt, and every host skips that release.
- **Load.** Hosts are never asked how busy they are for placement: what a host has committed is the sum of the sealed limits of the leases it holds, compared with what the tissue says it offers. Growth between `min` and `max` follows the instances' own CPU use, one step per epoch, inside the tissue's `budget`.
- **Trust.** The tissue needs operator signatures (`tissue 2` in `/etc/capsule/orders` for two). Every lease and pulse is signed by its host and checked against the host keys in the tissue, so a writer to the ledger can hide or delay facts but not invent them. A host never goes back to an older tissue.
- **The beacon is not a dependency.** A round's signature proves itself, so one host that can reach drand shares it through the ledger. With no beacon at all hosts still agree, from a value derived from the round number, and such leases are marked unproven.

### Latency profile

`"latency"` in the manifest is for programs that measure themselves in
microseconds. It only changes how the capsule is set up; after start nothing
of capsule is on the program's path.

| Field | Effect |
|---|---|
| `cores` | Whole cores from the host's reserved set (`/etc/capsule/latency`: `cores 2-7`), exclusive to the capsule, no CPU quota, memory from the cores' NUMA node. Ordinary capsules are confined to the other cores |
| `memory_lock` | `RLIMIT_MEMLOCK` is lifted, so the program can `mlockall` |
| `hugepages` | `hugetlbfs` mounted at `/dev/hugepages` |
| `nic` | A host network interface moved into the capsule's network and configured there; returned when the capsule ends |
| `devices` | Host device files bound into the capsule's `/dev`, for stacks that bypass the kernel |

A tissue places such a cell only on hosts that offer the cores and the
interface.

## Operating it

```sh
capsule ps                          # running capsules, with usage and limits
capsule kill <id>
capsule resize -memory 1G -cpus 2 <id>
capsule log                         # every run, exit and refusal; verifies the chain
capsule prune                       # delete stored rootfs copies nothing uses
```

**As a service.** Put the capsule in `/var/lib/capsule/apps/<name>` and:

```sh
echo 'CAPSULE_ARGS=-publish 8080:8080' | sudo tee /etc/capsule/apps/<name>.env
sudo systemctl enable --now capsule@<name>
```

systemd restarts it if it fails. That is the supervision model: there is no
capsule daemon to keep alive.

**Orders: no SSH.** A host can be operated without anyone logging in to it,
and without it listening on any port. An operator signs an order for one of
a fixed set of actions (`fetch`, `run`, `stop`, `resize`, `revoke`, `ps`,
`log`, `exec`) and puts it in the fleet ledger; each named host pulls it,
checks it, carries it out once and publishes a signed receipt.

```sh
sudo install -m 644 ops.pub /etc/capsule/operators.d/   # on the host: whose orders it obeys
sudo systemctl enable --now capsule-orders.timer        # look every 5 seconds
capsule order -key ops.key -host web-1.host -wait 30s run hello    # from anywhere with the ledger
```

- **No action runs a command on the host.** `exec` runs one inside a running capsule: it joins the capsule's namespaces and cgroup, drops every capability and applies the capsule's own system call filter before the command starts, so it can do nothing the capsule's program could not. It is off until `/etc/capsule/orders` turns it on.
- **Operators are their own set of keys** (`operators.d`), separate from the keys trusted to sign capsules. `/etc/capsule/orders` says how many of them must sign each action (`exec 2`, `run 2`, `* 1`, or `off`); `capsule order -o`, `order sign` and `order send` collect the signatures.
- **An order cannot be reused.** Its signature covers the hosts it names and a span of ticks (at most a day); a host marks an order before acting on it, so it is carried out at most once even if the host is interrupted; a lapsed order put back in the ledger is refused by the beacon's tick.
- **Results are sealed** with the hybrid key wrap to the machine that wrote the order, and signed by the host. The ledger holds ciphertext only.
- **Operators' orders and their outcomes go in the host's signed log.** Orders from anyone else are refused and leave nothing there, so whoever can write to the ledger cannot fill the record.
- **The ledger stays untrusted.** Its writers can delay or delete orders, not forge, alter or redirect them.
- **There is no daemon.** A systemd timer runs `capsule orders`, which looks once and exits; each look is one list request to the ledger. A started capsule is handed to systemd (`capsule@<name>`, or a transient unit without root).

What orders do not do: maintain the host's own operating system, or give an
interactive terminal. Keep unattended upgrades or replaceable hosts for the
first and the machine's console for emergencies.

**Without root.** An ordinary user can seal, run, limit, mesh and scale
capsules. What the kernel reserves for root is done for members of the
`capsule` group by a helper: `capsule-helper.socket` has systemd start the
same binary as root for one request, and it exits when the request is over
(a volume or store stays mounted exactly as long as the capsule holds its
connection, and is unmounted however the capsule ended). There is no setuid
program. The helper accepts four requests and no paths or commands:

| Request | What the user gains | What the helper checks |
|---|---|---|
| tunnel | Mesh and cells on the kernel's WireGuard | The network namespace passed belongs to a user namespace that user created. It sets only the port (1024 and up); the tunnel's key never reaches it |
| volume | Volumes with a `size`, and `encrypt` | Names are plain names; the image is one it made, kept where the user cannot write; one capsule at a time |
| store | An encrypted capsule decrypted once to an encrypted store on disk, instead of into memory at every start | The same |
| listen | Publishing on ports below 1024 | The port is below 1024; it hands back the listening socket and nothing else |

Group members can therefore take low ports and disk space under
`/var/lib/capsule/users/`. Snapshots and removal of a user's sized volumes
are root's: `sudo CAPSULE_DATA=/var/lib/capsule/users/<uid> capsule volumes`.

**Receipts.** `run -receipt out.json` writes a host-signed statement of which
seal ran, when, its exit status and a hash of its output.
`capsule receipt -host <signing key id> out.json` checks one.

**Log size.** Each entry carries a hybrid signature, about 4.9 KB in all. The
host's full key is written only on the first entry of a file. At 64 MB the
file is set aside as `log-<last entry>.jsonl` and a new one continues the
same chain; `capsule log` checks the current file and `capsule log -all` the
whole history across files.

**Log forwarding.** Put a URL in `/etc/capsule/log-forward` and every log entry
is posted there before the run starts; if the collector cannot be reached, the
run is refused. `capsule log -file <copy>` verifies a copy anywhere.

## Files

| Path | Purpose |
|---|---|
| `/etc/capsule/trust.d/*.pub` | Keys whose seals, cards and revocations this host accepts. |
| `/etc/capsule/host.key` | The host's one secret. Its decryption key, signing key and mesh keys derive from it. |
| `/etc/capsule/peers.d/`, `revoked.d/` | Signed cards and revocations; may be shared directories. |
| `/etc/capsule/grants.d/` | Signed grants this host presents when its cells call others. |
| `/etc/capsule/policy.d/*.cue` | Rules every capsule run on this host must satisfy. |
| `/etc/capsule/delegation`, `log-forward` | Optional, described above. |
| `/etc/capsule/operators.d/*.pub`, `orders` | Keys whose orders this host obeys, and how many must sign each action. |
| `/etc/capsule/ledger`, `ledger.env` | The fleet ledger's URL and its credentials. |
| `/var/lib/capsule/` | Verified rootfs copies, run counters, the log, and `apps/`. |

Without root the same files live under `~/.config/capsule` and
`~/.local/share/capsule`. `CAPSULE_CONFIG`, `CAPSULE_DATA` and `CAPSULE_RUN` override them.

## What capsule itself costs

Measured by `test/bench.sh` on a 4-core arm64 virtual machine; your numbers
will differ, the proportions should not.

| | Cost |
|---|---|
| Starting a capsule that has run before | 17 to 50 ms, whether its root filesystem is 9 MB or 350 MB |
| Starting one for the first time | About 0.5 s per 150 MB of root filesystem, to copy and verify it |
| Memory per running capsule | About 6 MB for its supervising process, with ten running |
| CPU of an idle capsule's supervisor | None measurable |
| The autoscaler of a scaled capsule | About 4 MB, and 10 ms of CPU per 20 s |
| Disk for a second capsule on the same runtime, or a new version | Only the files that differ |
| The host's log | About 4.9 KB per entry, two entries per run; set aside in 64 MB files |
| A running encrypted capsule | No extra memory with root or the helper; its full size in RAM without either |
| Mesh health checks from an idle caller | 4 connections a minute per instance, not 30 |

How it stays small:

- **A check that passed is remembered.** Verifying a root filesystem means reading all of it. Afterwards capsule keeps a fingerprint of the tree taken from file metadata alone (paths, sizes, times, inodes) and re-reads the contents only if that changes, and once a day regardless.
- **Each distinct file is stored once.** The store keeps files in a pool named by content and hard-links them into each root filesystem, so capsules sharing a runtime, successive versions of one capsule, and every replica share the same bytes on disk and in the page cache.
- **Supervisors sleep.** A capsule's supervisor waits on its child and nothing else, and returns the memory it used for start-up. The autoscaler is woken by the kernel when a replica nears its memory limit, not by a timer.
- **Nothing sits in the data path** on the mesh: packets go through the kernel's WireGuard and firewall. Published ports and egress are copied by the kernel between sockets.
- **One process per capsule and no daemon.** Nothing runs when no capsule does.

- **An encrypted capsule is decrypted once.** With root, it goes into a small filesystem of its own, encrypted with a key derived from the host secret and mounted only while a capsule is using it. On disk there is only ciphertext, later starts and all replicas share the one copy, and no RAM is spent holding it. `capsule prune` removes stores nothing is using.

Where it is not frugal: without root and without the helper, an encrypted capsule is still
decrypted into memory on every start, costing its full size in RAM while it
runs. That copy is kept off the disk: the supervisor sets its own swap limit
to zero, so the kernel cannot write those pages to swap, and where that
cannot be set on a host with swap, `run` says so. If the supervisor is killed
outright, the copy stays in memory until the next `capsule` command of any
kind, which removes it. The binary is about 31 MB, most of it the CUE and drand libraries,
which costs disk but not memory.

## What it does not protect against

- **Root on the host.** Root can read a running capsule's memory and alter the host's own state. Closing that needs confidential-computing hardware.
- **A wrong clock, for `expires`.** `not_before` can be made cryptographic with `timelock`. `expires` still uses the host's clock: a clock set back behind the host's own log is refused, but a host cannot prove what time it is.
- **A stored copy altered without changing any file's size, time or inode.** The stored copy is re-read in full once a day, not on every run. The store is writable only by its owner, so this is the same boundary as root on the host.
- **A rewritten log, unless it is published or forwarded.** Whoever holds the host secret can rewrite the local log. With a ledger, other hosts co-sign it and a rewrite is caught; without one, forward it or keep the head hash `capsule log` prints somewhere else.
- **A fleet-wide count without a ledger.** Permits divide runs between hosts in advance. A single shared count needs `fleet` and a reachable ledger.
- **A ledger whose operator deletes everything.** Witnesses notice entries they saw being removed, but a store wiped before anyone witnessed it leaves nothing to compare against. Use object versioning or a retention lock on the store.

Other limits: autoscaling goes by CPU and memory only, and you choose which
hosts run a capsule; least-connections on the mesh counts only the caller's
own connections, refreshed every two seconds, not the instance's total load;
sized and encrypted volumes need root or the helper; with neither, mesh and
cell tunnels run in the supervisor (wireguard-go on a tun interface inside
the capsule's network, which the supervisor owns) because only root may
create a kernel WireGuard device in the host's network, and that is slower;
a tissue reacts on a timer (seconds to place, about a lease to take over
from a dead host) except for hot standbys with `detect`; data follows a
cell by periodic snapshot, not replication, so a crash loses up to one
interval; the latency profile is checked for being applied, not
benchmarked, and no kernel-bypass stack has been run in a capsule;
the helper is root code reachable by a group, small and fixed in what it
accepts but a boundary to keep reviewed; orders give no interactive terminal
and no way to maintain the host's operating system; health checks
are TCP connects, so peers reached only over UDP are not checked; publish and
egress forward TCP only and add no request-level features such as retries;
receipts are a host's signature, not a zero-knowledge proof.

## Tests

```sh
go test .                                       # unit tests; most run on macOS too
CAPSULE_NETWORK_TESTS=1 go test -run Timelock . # against the live drand network
```

The unit tests cover sealing, encryption, archive unpacking, policy, the log,
cards, CUE builds and, on Linux, the syscall filter, which is run through an
interpreter for every known syscall.

On a Linux test machine with `busybox-static` and `nftables` installed:

```sh
make test
```

`test/cell.sh` covers cells: needs by name and port and by socket file,
offers on a port and on a socket, the kernel carrying port-to-port traffic by
itself, a program that listens on IPv4 only, spreading over instances, a
program trying to reach what it does not need, cells not named by an offer,
grants that are missing, untrusted, made out to someone else, in date,
expired and renewed, a connection cut when its grant runs out, datagram
receptors, a sockets-only cell, tunnel secrets rotating every 15 seconds
throughout, and ticks without the beacon. It and `test/mesh.sh` run both
with root (the kernel's WireGuard) and without (the tunnel in the
supervisor).

`test/tissue.sh` plays three hosts on one machine, as root and without:
growth from needs, placement on different hosts, the draw, a warm and a hot
standby, takeover with a new term and the old holder standing down, rolling
out a release, holding back one that does not come up, tissues that are
forged or replayed, a strict cell cut off from the ledger, and a host
leaving. `test/latency.sh` checks dedicated cores, memory locking, huge
pages and an interface handed to a capsule.

`test/takeover.sh` covers what a tissue does for cells that must not be
missed or that keep data: roles, a hot standby taking over in milliseconds
when the holder's supervisor is frozen, a strict cell stopped by its own
supervisor with nothing else running, data restored on another host after a
drain and after a crash, and the snapshot being unreadable in the ledger.

`test/order.sh` covers orders, as root and without: every action, the
signatures an action needs, exec's confinement inside the capsule, sealed
results, and orders that are replayed, lapsed, altered, misaddressed or
signed by an outsider. `test/helper.sh` covers the helper as a user in the
`capsule` group: sized and encrypted volumes, the encrypted store, a low
port, a kernel tunnel, and the requests the helper refuses.

`test/smoke.sh` covers sealing, the sandbox, limits, policy, encryption,
volumes, publish, egress and the log, as root and as an ordinary user.
`test/scale.sh` covers autoscaling, `test/guide.sh` runs the beginner's
guide's commands in order, `test/examples.sh` builds and runs the examples,
`test/bench.sh` measures capsule's own overhead, and `test/ledger.sh` the fleet ledger against real
servers (it downloads them). `test/mesh.sh`
covers the mesh. `test/e2e.sh` builds a capsule from an Alpine rootfs and runs
it as a systemd service.

## License

Apache License 2.0. See [LICENSE](LICENSE).
