# Capsule: installation and beginner's guide

This guide takes you from nothing to running, scaling and sharing capsules.
You need to be comfortable in a Linux terminal; you do not need to know
containers.

Sections 2 to 10 are a walkthrough. Every command in them is run, in this
order, by `test/guide.sh`, so if something here does not work on your machine
that script will show where. Sections 11 onward are reference.

Related documents:

- [INSTALL.md](INSTALL.md): requirements, installing, upgrading and removing, in detail.
- [CLI.md](CLI.md): every command and every option.
- [../examples/](../examples/README.md): Python and Java applications to build and run.

## Contents

1. [What a capsule is](#1-what-a-capsule-is)
2. [Install](#2-install)
3. [Your first capsule](#3-your-first-capsule)
4. [A service that keeps data](#4-a-service-that-keeps-data)
5. [Run it as a system service](#5-run-it-as-a-system-service)
6. [Conditions before it runs](#6-conditions-before-it-runs)
7. [Capsules talking to each other](#7-capsules-talking-to-each-other)
8. [Scaling](#8-scaling)
9. [More than one host](#9-more-than-one-host)
10. [Building from a file](#10-building-from-a-file)
11. [Running without root](#11-running-without-root)
12. [Keeping data safe](#12-keeping-data-safe)
13. [The manifest, field by field](#13-the-manifest-field-by-field)
14. [Commands](#14-commands)
15. [Where things live](#15-where-things-live)
16. [When something is refused](#16-when-something-is-refused)
17. [What capsule does not do](#17-what-capsule-does-not-do)

## 1. What a capsule is

A capsule is a folder with three things in it:

| File | What it is |
|---|---|
| `capsule.json` | The **manifest**: what to run and everything it is allowed to do |
| `rootfs/` | The **root filesystem**: the program and the files it needs |
| `capsule.seal` | The **seal**: a signature over the other two |

`capsule run` starts the program only if the seal was made by a key the
machine trusts and nothing has changed since. It then runs it in a sandbox:
its own view of processes, files and network, no special privileges, and
limits on memory and CPU.

Three ideas run through everything:

- **Nothing runs unless it is sealed and trusted.** Change one byte and it is refused until you seal it again.
- **The manifest is the whole truth.** Network access, data, limits and conditions are all declared there and covered by the seal.
- **There is no background service.** `capsule run` is the capsule's parent process. Stop it and the capsule stops.

Some words used below:

- **Host**: a machine that runs capsules.
- **Key**: made by `capsule keygen`. It gives you three files: `name.key` (private, keep it safe), `name.pub` (give to hosts so they trust you) and `name.id` (a short name for the key, used inside manifests).
- **Seal id**: the name of one exact sealed capsule. Approvals, permits and revocations refer to it.

## 2. Install

### What you need

- A Linux host, kernel 5.11 or newer, with cgroup v2 and systemd. Ubuntu 24.04 and 25.04 are tested, on x86-64 and arm64.
- Go 1.26 to build. You can build on a different machine, including a Mac.
- For the walkthrough: `curl`, and `busybox` for a small network client (`sudo apt-get install -y busybox-static`).

### Build

On the machine that has Go:

```sh
cd capsule
make linux        # writes bin/capsule-linux-amd64 and bin/capsule-linux-arm64
```

On a Mac, `make build` also gives you `bin/capsule` for building and signing
capsules locally. Running them needs Linux.

### Install on the host

Copy the `capsule` folder (or at least `bin/` and `dist/`) to the host, then:

```sh
sudo sh dist/install.sh bin/capsule-linux-amd64     # or -arm64
capsule version
```

This puts the binary in `/usr/local/bin`, creates `/etc/capsule` and
`/var/lib/capsule`, installs the systemd unit, and on Ubuntu installs the
AppArmor profile that running without root needs. Run it again to upgrade.

## 3. Your first capsule

**Make a key and tell the host to trust it.**

```sh
capsule keygen dev
sudo install -m 644 dev.pub /etc/capsule/trust.d/dev.pub
```

**Get a root filesystem.** Any folder or tarball of a Linux filesystem will
do. Alpine's is about 3 MB:

```sh
curl -fsSLO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
```

(Use `aarch64` in both places on an arm64 host.)

**Create, seal and run.**

```sh
capsule init -rootfs alpine-minirootfs-3.20.3-x86_64.tar.gz hello
capsule seal -key dev.key hello
sudo capsule run hello
```

You should see `hello from hello`. `init` wrote a starter `hello/capsule.json`;
open it to see how small a manifest can be.

**See the seal working.** Edit the command in `hello/capsule.json`, then:

```sh
sudo capsule run hello
# capsule: refusing to run: capsule.json was changed after sealing
capsule seal -key dev.key hello
sudo capsule run hello        # runs again
```

**Ask before running.** `capsule inspect hello` describes a capsule and ends
with either `would run it` or `would refuse:` and the reason. It is the first
thing to reach for when something will not start.

## 4. A service that keeps data

Copy the first capsule and give it a new manifest:

```sh
cp -a hello notes
```

`notes/capsule.json`:

```json
{
  "name": "notes",
  "command": ["/bin/sh", "-c", "date >> /data/visits; exec nc -lk -p 8080 -e cat /data/visits"],
  "publish": [8080],
  "volumes": [{"name": "data", "path": "/data"}],
  "limits": {"memory": "64M", "cpus": 1, "pids": 64}
}
```

Three new things:

- **`publish`** lists ports you are allowed to open to the host. Nothing is reachable unless listed.
- **`volumes`** is where data lives. Everything else in a capsule is read-only or thrown away when it stops.
- **`limits`** caps memory, CPU cores and number of processes.

Seal and run it, opening port 8080 on the host:

```sh
capsule seal -key dev.key notes
sudo capsule run -publish 127.0.0.1:8080:8080 notes
```

From another terminal:

```sh
busybox nc 127.0.0.1 8080          # prints one line: when it started
sudo capsule ps                    # running capsules, memory and limits
sudo capsule resize -memory 128M notes-1a2b3c4d   # use the id from ps
sudo capsule kill notes-1a2b3c4d
```

Run it again and ask again: there are now two lines. The data outlived the
capsule. It also survives sealing a new version, because a volume belongs to
the capsule's **name**, not to one seal.

```sh
sudo capsule volumes               # what data is kept, and how big
sudo capsule log                   # every run, exit and refusal on this host
```

The log's last line says `chain intact`. Each entry is signed and linked to
the one before, so an edited or deleted entry is detected.

## 5. Run it as a system service

Put the capsule where services live, say which flags to run it with, and
start it:

```sh
sudo cp -a notes /var/lib/capsule/apps/notes
echo 'CAPSULE_ARGS=-publish 127.0.0.1:8080:8080' | sudo tee /etc/capsule/apps/notes.env
sudo systemctl enable --now capsule@notes
```

systemd now starts it at boot and restarts it if it fails.
`sudo systemctl stop capsule@notes` stops it cleanly. To update, copy the new
sealed folder over the old one and restart the service.

## 6. Conditions before it runs

A `policy` section lists conditions that must hold before a capsule runs.
They are inside the seal, so nobody can loosen them afterwards.

**Two people must approve.** Make two more keys and name them in the manifest
by id:

```sh
capsule keygen alice
capsule keygen bob
cp -a hello vault
```

`vault/capsule.json` (paste the contents of `alice.id` and `bob.id`):

```json
{
  "name": "vault",
  "command": ["/bin/sh", "-c", "echo opened"],
  "policy": {"approvals": {"required": 2, "signers": ["<alice.id>", "<bob.id>"]}}
}
```

```sh
capsule seal -key dev.key vault
sudo capsule run vault
# capsule: refusing to run: has 0 of 2 required approvals
capsule approve -key alice.key vault
capsule approve -key bob.key vault
sudo capsule run vault             # opened
```

An approval covers one exact seal. Change the capsule and it needs approving
again.

**Other conditions**, all under `policy`:

| Setting | Effect |
|---|---|
| `"not_before": "2027-01-01T00:00:00Z"` | Refused before this time |
| `"expires": "2028-01-01T00:00:00Z"` | Refused after this time |
| `"timelock": true` | With `not_before`: encrypted so that nobody, the host's administrator included, can open it early. Needs internet when sealing and at first run |
| `"max_runs": 3` | Refused after three runs on a host |
| `"hosts": ["<host id>"]` | Only these hosts can decrypt and run it (see section 12) |
| `"permits": ["<key id>"]` | A host needs a permit from one of these keys (see section 9) |

**Take something back.** `sudo capsule revoke vault` stops that exact seal
from ever running on this host again.

## 7. Capsules talking to each other

By default a capsule has no network at all. There are three ways to open it,
each declared in the manifest:

| Way | Manifest | Use it for |
|---|---|---|
| Publish | `"publish": [8080]` and `run -publish` | Letting the host or the outside in |
| Egress | `"egress": [{"host": "api.example.com", "port": 443}]` | Letting the capsule out to named hosts only |
| Mesh | `"network": "mesh"` | Capsule-to-capsule, encrypted, by name |

### The mesh

On the mesh, a capsule's only network is an encrypted tunnel to the capsules
its manifest names. Each instance has a **card**: a signed note saying "this
key is an instance of `web`, and here is where to reach it". Cards live in
`/etc/capsule/peers.d/`.

The simplest setup lets the host issue cards itself. Do this once per host,
naming the capsules it may run:

```sh
capsule delegate -key dev.key -host "$(sudo capsule host | awk '/^sign/{print $2}')" web ask \
  | sudo tee /etc/capsule/delegation
```

Now two capsules. `web/capsule.json`:

```json
{
  "name": "web",
  "command": ["/bin/sh", "-c", "echo hello from web > /tmp/page; exec nc -lk -p 8080 -e cat /tmp/page"],
  "network": "mesh",
  "mesh": {"peers": [{"name": "ask", "in": [8080]}]}
}
```

`ask/capsule.json`:

```json
{
  "name": "ask",
  "command": ["/bin/sh", "-c", "sleep 3; nc -w 3 web 8080"],
  "network": "mesh",
  "mesh": {"peers": [{"name": "web", "out": [8080]}]}
}
```

`in` lists ports the peer may connect to here; `out` lists ports this capsule
may connect to there. Both sides must agree.

```sh
for n in web ask; do cp -a hello $n; done      # then write the two manifests above
capsule seal -key dev.key web
capsule seal -key dev.key ask
sudo capsule run -listen 51820 -advertise 127.0.0.1 web &
sudo capsule run ask                           # hello from web
```

`-listen` is the UDP port of this instance's tunnel. `-advertise` is the
address other hosts should use to reach this one; use the host's real
address when there is more than one host.

With root the tunnels are the kernel's WireGuard. Without root the mesh
still works: the same protocol then runs inside capsule itself, which is
slower, since each packet passes through that process. The two kinds talk to
each other, so hosts can be mixed.

**Tunnels that resist quantum computers.** `capsule identity` also prints a
`kem` key. Put it on the card with `-kem` (cards a host issues for itself
always carry it) and every tunnel to that instance mixes in a second secret,
exchanged with ML-KEM, on top of WireGuard's own. Both would have to be
broken to read the traffic. The secret is replaced every hour without
interrupting connections. It travels, encrypted, as a small `.psk` file
beside the cards, so the cards folder must be writable by the hosts. Each
side tells the other when it holds the new secret, so a tunnel is not tried
before both ends agree.

### Choosing how connections are spread

When a peer has several instances, the caller's manifest picks how to spread
connections:

```json
{"name": "web", "out": [8080], "balance": "round-robin"}
```

| `balance` | Each new connection goes to |
|---|---|
| `random` (default) | a random live instance |
| `round-robin` | each live instance in turn |
| `least-connections` | the instance holding the fewest of this caller's open connections |
| `sticky` | always the same instance for this caller |
| `failover` | one instance that all callers agree on, until it dies |

Instances that stop serving are skipped within a few seconds. Capsule
notices from the traffic itself where it can, and opens a check connection
only when it cannot tell.

### Cells: named openings instead of ports

A mesh capsule still thinks in addresses and port numbers, and its program
can open any connection its manifest allows. A **cell** goes further. Its
program has no way onto the network at all. It is handed a ready-made
opening, a **receptor**, for each thing it uses, and its supervisor answers
for each thing it offers.

A cell that offers a database, and a second service only some may use:

```json
{
  "name": "store",
  "command": ["/bin/server"],
  "network": "cell",
  "offers": [
    {"name": "db", "to": ["web", "reports"], "port": 5432},
    {"name": "admin", "to": ["web"], "grant": true}
  ]
}
```

and one that uses them:

```json
{
  "name": "web",
  "command": ["/bin/web"],
  "network": "cell",
  "needs": [
    {"name": "db", "from": "store", "port": 5432},
    {"name": "admin", "from": "store"}
  ]
}
```

There are no port numbers to agree on between the two. `web` uses `db` in
either of two ways:

- **A socket file:** `/run/cell/need/db`. Connecting to it is connecting to `store`'s `db`.
- **A name and port,** if the need has `port`: software that speaks TCP connects to `db:5432` as usual. The port is whatever the program expects; it does not have to match anything on `store`.

`store` serves `db` in either of two ways:

- **A port,** if the offer has `port`: the program listens as usual.
- **A socket file:** without `port`, the program listens on `/run/cell/offer/admin`.

Cards, `-listen`, `-advertise` and `balance` work exactly as on the mesh,
and traffic between hosts is still WireGuard. What changes:

| | Mesh | Cell |
|---|---|---|
| The program can send to another capsule | on the ports listed | only to a receptor it needs by `port`; nothing else |
| The program can create network sockets | yes | only if a need or offer uses `port`; otherwise none at all |
| What is allowed is written as | port numbers | names |
| The receiving side knows the caller | by address | by cell name, checked before the program sees the connection |
| Access can expire by itself | no | yes, with a grant |

**What carries the traffic.** Where the need and the offer both have a
`port`, and the serving program listens on every address (most do), the
kernel carries each connection from one program to the other and no capsule
process touches it, exactly as on the mesh. Capsule's own process steps in
only where something has to be done that the kernel cannot do: joining a
socket file to the network, reaching a program that listens on IPv4 only,
enforcing a grant, or adding the `proxy_protocol` line. It works this out by
itself; nothing has to be configured.

**Datagrams.** Add `"udp": true` and a `port` to both the offer and the
need, and the receptor carries UDP instead of a stream.

**Socket files only.** If no need or offer in a cell uses `port` (and it
has no `publish` or `egress`), the program is not allowed to create a
network socket of any kind, not even on its own loopback. It can only use
the socket files it was given.

Add `"proxy_protocol": true` to an offer and each connection reaches the
program with a PROXY protocol line in front, carrying the calling cell's
address, which is derived from its key.

**Grants.** An offer with `"grant": true` asks for more than being on the
`to` list: the calling host must also hold a signed grant that is in date.

```sh
capsule grant -key dev.key -receptor admin -of store -to web -for 24h \
  | sudo tee /etc/capsule/grants.d/admin.grant      # on web's host
```

`web`'s host presents the grant to each instance of `store` when `web`
starts, whenever the folder changes, and every half minute; `store`'s host
checks it against its trusted keys. When it runs out, `web` is refused until a new one
is put in the folder, and connections that were let in on it are closed.
Nothing is restarted, and nothing has to be revoked. Give short grants and
renew them from a job you control.

**Ticks.** A grant's life is counted in ticks. A tick is one round of the
public drand beacon, three seconds, so every host counts the same way.
A host asks the beacon for its latest round, checks the signature, and
counts on from there with a clock that setting the system time does not
move. Turning a host's clock back therefore does not revive an expired
grant. If the beacon cannot be reached, the host's own clock is used
instead, but never earlier than the last tick the beacon proved on this
host, which is kept on disk. `capsule tick` shows the current tick and which
of the two it came from.

Cells work with or without root, like the mesh.

## 8. Scaling

**By hand.** `capsule resize` changes limits on a running capsule. To add
capacity, run more copies, each with its own label:
`sudo capsule run -instance 2 notes`. Each instance has its own data.

**Automatically.** Add a `scale` section and `capsule run` keeps a set of
replicas for you. `shop/capsule.json`:

```json
{
  "name": "shop",
  "command": ["/bin/sh", "-c", "cat /proc/sys/kernel/random/uuid > /tmp/id; exec nc -lk -p 8080 -e cat /tmp/id"],
  "publish": [8080],
  "limits": {"memory": "64M", "cpus": 1, "pids": 64},
  "scale": {"min": 2, "max": 4, "cpu": 70, "memory_max": "256M"}
}
```

```sh
cp -a hello shop                   # then write the manifest above
capsule seal -key dev.key shop
sudo capsule run -publish 127.0.0.1:8081:8080 shop
```

`capsule ps` shows two replicas. Ask port 8081 a few times and the two take
turns answering: one published port is shared by all replicas.

| `scale` setting | Effect |
|---|---|
| `min`, `max` | How many replicas |
| `cpu` | Add a replica when average CPU stays above this percent of the CPU limit; remove one when it stays below half |
| `memory_max` | Raise a replica's memory limit as it fills, up to this |
| `cooldown` | Shortest time between changes (default `30s`) |
| `restart` | When a replica exits: `always` (default), `on-failure`, or `never` |
| `balance` | Sharing the published port: `least-connections` (default), `round-robin`, `random` |
| `fleet` | Scale together with other hosts (section 9) |

For a job that should run once and finish, use `"restart": "on-failure"`.

## 9. More than one host

Some things need all your hosts to agree: how many times something has run,
what has been revoked, which version is current. They agree through a
**ledger**: a shared place that every host can reach. It can be:

```
file:///mnt/shared/capsule                              a shared folder
s3://bucket/prefix?region=eu-west-1                     AWS S3
s3://bucket/prefix?endpoint=https://store.example:9000  any S3-compatible store
vault://vault.example:8200/secret/capsule               HashiCorp Vault
artifactory://acme.jfrog.io/artifactory/capsule-ledger  Artifactory
```

Put one line in `/etc/capsule/ledger` on each host. Passwords go in
`/etc/capsule/ledger.env` as `AWS_ACCESS_KEY_ID=...`, `VAULT_TOKEN=...` and so
on. Everything written to the ledger is signed, so the store is never trusted
to tell the truth; it only has to stay available.

**Check the store first.**

```sh
echo "file:///var/lib/capsule/guide-ledger" | sudo tee /etc/capsule/ledger
sudo capsule ledger check
```

It ends with a verdict. Some stores do not handle two hosts writing at the
same instant correctly; this tells you, and what setting makes them safe.

**Send a capsule to every host.** On the machine where you seal:

```sh
sudo capsule publish -key dev.key notes
```

On each host:

```sh
sudo capsule fetch notes           # installs into /var/lib/capsule/apps/notes
```

`fetch` only installs a release signed by a key the host trusts, checks the
capsule against its seal, and refuses to go back to an older release. The
systemd service runs `fetch` before each start, so restarting the service
picks up a new release. (Vault cannot hold capsules; use the other kinds.)

**What else the ledger gives you:**

| Feature | How |
|---|---|
| A run limit across all hosts | `"policy": {"max_runs": 3, "fleet": true}` |
| Revoking everywhere at once | `capsule revoke -key dev.key -publish <dir>` |
| Hosts checking each other's logs | `capsule witness` (also done after every run), then `capsule log -ledger` |
| Scaling across hosts | `"scale": {..., "fleet": true}`: the next replica goes to the host with the fewest. Each host must be delegated the capsule's name (section 7) |

A capsule marked `fleet` is refused when the ledger cannot be reached. Others
run and print a warning.

**Without a ledger**, you can still limit runs per host with permits. Put
`"permits": ["<key id>"]` in the policy, then give each host its share:

```sh
capsule permit -key dev.key -host <host id> -runs 2 <dir>
```

`sudo capsule host` prints a host's id.

### Orders: operating hosts without logging in

With a ledger in place you do not need SSH to run your fleet, and a host
does not need to listen on any port. You sign an **order**; the host fetches
it from the ledger, checks it, carries it out once, and answers with a
signed receipt.

An order is one of a fixed list of actions. There is no order that runs a
command on the host.

| Action | Does on the host |
|---|---|
| `fetch <name>` | Installs the current release |
| `run <name>` | Fetches it if it can, then starts it as a systemd service |
| `stop <name>` | Stops it |
| `resize <name> memory=512M cpus=2 pids=256` | Changes a running capsule's limits |
| `revoke <seal id>` | Never runs that seal there again |
| `ps` | Lists what is running |
| `log [lines]` | Returns the end of the host's signed record |
| `exec <name> -- <command>` | Runs a command **inside** a running capsule, with exactly the capsule's own confinement |

**Set a host up to obey.** Operators are separate from the keys that sign
capsules. On each host:

```sh
capsule keygen ops                                    # on your workstation, once
sudo install -m 644 ops.pub /etc/capsule/operators.d/ # on the host
sudo systemctl enable --now capsule-orders.timer      # look for orders every 5 seconds
sudo capsule host -export > web-1.host                # give this file to the operators
```

**Send an order** from any machine that has the same `ledger` setting. It
needs the ledger's credentials, not access to the host:

```sh
capsule order -key ops.key -host web-1.host -wait 30s run hello
# sent order sha256:5d0c... to 1 host(s)
# host r1Cs...: ok
# started hello-9f3a2c11

capsule order -key ops.key -host web-1.host -host web-2.host -wait 30s ps
```

`-wait` waits for the answers. Without it, read them later with
`capsule order result <id>`.

**What makes it safe:**

| Property | How |
|---|---|
| Only your operators can give orders | Each order carries hybrid signatures; the host checks them against `operators.d` |
| An order cannot be replayed | It names its hosts, is good for a span of ticks (`-for`, default 10 minutes, at most a day), and a host carries each one out at most once |
| Sensitive actions can need several people | `/etc/capsule/orders` says how many operators must sign each action |
| Results are private | Each answer is encrypted to the machine that wrote the order. The ledger holds only ciphertext |
| Everything is on the record | Every order from an operator, and its outcome, goes in the host's signed log |
| The ledger is not trusted | Whoever can write to it can delay or delete orders, but cannot forge, alter or redirect one |

**Requiring more than one signature.** `exec` is off until you turn it on.
In `/etc/capsule/orders`:

```
exec 2      # two operators must sign
run  2
*    1      # everything else: one
```

Use `off` in place of a number to refuse an action outright. Then:

```sh
capsule order -key alice.key -host web-1.host -o fix.order exec hello -- /bin/ls /data
capsule order sign -key bob.key fix.order      # Bob reads it and adds his signature
capsule order send -wait 30s fix.order
```

**What it replaces, and what it does not.** Deploying, starting, stopping,
resizing, revoking, inspecting and debugging inside a capsule all work this
way. Maintaining the host's own operating system does not: update hosts with
their own unattended upgrades or by replacing the machine, and keep the
machine's console for emergencies. There is no interactive terminal; `exec`
runs one command and returns what it printed (up to 64 KB, one minute unless
you pass `timeout=`).

### The tissue: a fleet that looks after itself

Orders tell one host to do one thing. A **tissue** tells the whole fleet what
must be alive, and the hosts keep it true between them. There is no
scheduler and no control plane to run: each host, on the timer that already
pulls orders, reads the same facts from the ledger and does its own part.

You write one file. Name the roots; what they need is found from their
manifests.

```json
{
  "name": "prod",
  "cells": {
    "web": {"root": true, "min": 2, "max": 4, "standby": "warm"}
  },
  "hosts": [
    {"file": "web-1.host", "memory": "8G"},
    {"file": "web-2.host", "memory": "8G"},
    {"file": "web-3.host", "memory": "8G", "labels": ["ssd"]}
  ]
}
```

```sh
capsule publish -key dev.key web          # and db, and whatever else web needs
capsule tissue -key ops.key prod.json     # sign it and put it in the ledger
capsule tissue status                     # what is alive, where, and why there
```

If `web` needs `db`, a `db` is grown without being listed. If nothing needs
it any more, it is stopped.

**How a host is chosen.** Every three seconds the public drand beacon
publishes a number nobody could know beforehand. For each empty place, every
host hashes that number with the place and its own id; the lowest wins. So
every host works out the same winner without asking anyone, nobody can
arrange for your capsule to land on a host they control, and `tissue status`
shows the round that decided each placement, which anyone can check again.

**How a place is kept.** The winner takes a lease in the ledger and renews
it on every pass. If it stops renewing, the lease lapses and the next host
in the draw takes the place with a higher term. A host that finds a higher
term than its own stops its copy.

| Setting | Meaning |
|---|---|
| `root` | Alive whether or not anything needs it |
| `min`, `max` | Instances, each on its own host. It grows towards `max` while every instance is busy and shrinks back when all are idle. A cell you do not list gets exactly one |
| `on` | Labels a host must carry |
| `standby` | `warm`: the runner-up keeps the capsule fetched and checked, and starts it the moment the lease lapses. `hot`: it runs there too |
| `detect` | With a hot standby on the mesh: the silence after which the standby takes over by itself, such as `"50ms"` |
| `snapshot` | For a cell with volumes: how often a copy of them is sent on, such as `"5m"`, so that the cell can come back on another host |
| `takeover` | `fast` (default): keep running if the ledger is out of reach. `strict`: stop as the lease runs out, so there are never two |
| `step` | Instances replaced at a time when you publish a new release (default 1) |
| `lease` (top level) | Ticks a renewal lasts. Default 10, half a minute |
| `budget` (top level) | `memory` and `cpus` the whole tissue may commit |
| hosts: `drain` | Empty this host: it takes nothing new and hands over what it holds. Do this before taking a host out of the tissue |
| hosts: `weight`, `memory`, `cpus` | Its share of draws, and what it offers. A host is never given more than it offers, worked out from the leases it holds and each capsule's sealed limits, not from what the host reports |

**New releases roll out by themselves.** `capsule publish` a new version and
the instances are replaced a few at a time, in an order the beacon picks. If
a replaced instance does not stay up, the previous release is put back, and
that release is held back on every host until you publish another.

**Cells that must not be missed.** Give the cell a hot standby and a
`detect` time. The two copies then watch each other directly, over the mesh,
every few milliseconds. When the standby stops hearing the holder it takes
over at once, without waiting for the ledger or a timer: in our tests about
110 ms after the holder fell silent, with `"detect": "100ms"`. A program
finds out which it is by reading `/run/capsule/role`: `holder`, `standby`,
or `holder promoted` when it has just stepped up. If the holder was only
slow and comes back, the tissue makes the standby a standby again, so for a
moment both may believe they are the holder; mark the cell
`"takeover": "strict"` if that must never happen and you would rather wait.

**Cells that keep data.** A cell with volumes stays on the host that has its
data, unless you give it `"snapshot": "5m"`. Its holder then sends an
encrypted copy of the volumes to the ledger's store that often, and a host
that takes the cell over restores the latest copy before starting it.

- When a host is **drained**, the cell is stopped, a last copy is sent, and the next host starts from exactly where it left off: nothing is lost.
- When a host **dies**, the next one starts from the last copy: at most one interval is lost.
- A copy can only be taken while the cell runs if the volume has a `size` (which needs root or the helper); a plain volume is copied only when the cell is stopped, which a drain does.

**What to expect.**

- A host acts when its timer fires, every 5 seconds. Placement takes a few seconds; taking over from a dead host takes one lease plus one pass (about 35 seconds by default, 12 to 15 with `"lease": 4`).
- For no gap at all, run two or more instances, or a `hot` standby: the mesh already sends callers only to instances that answer.
- A cell with volumes and no `snapshot` only comes back on the host that has its data.
- The tissue file needs an operator's signature, like an order; `/etc/capsule/orders` can require several with a `tissue 2` line.

## 10. Building from a file

Instead of making folders by hand, describe a capsule in a
[CUE](https://cuelang.org) file. `built.cue`:

```cue
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
```

```sh
capsule build -key dev.key built.cue
sudo capsule run built             # built from CUE
```

- `from` can be a folder, a tarball, or an `https://` URL. A URL needs a `sha256`, and the download is refused if it does not match.
- `add` lays more archives or folders over the base, for a language runtime or your application: `add: [{from: "python.tar.gz", to: "/opt"}]`. The [examples](../examples/README.md) build Python and Java applications this way.
- `files` adds files: `contents` for text, or `source` to copy one from disk. `mode: 0o755` makes it executable.
- A misspelt field is an error naming the file and line.

**Rules for a host.** A CUE file in `/etc/capsule/policy.d/` makes the host
refuse any capsule that breaks it, however validly sealed:

```sh
echo 'capsule: limits: memory: string' | sudo tee /etc/capsule/policy.d/team.cue
```

Now every capsule must declare a memory limit. The same file works at build
time with `capsule build -rules team.cue`.

**Describing many hosts.** `capsule render fleet.cue` turns a list of hosts
and capsules into one folder per host, and prints the commands to copy each
into place.

## 11. Running without root

Most of capsule works as an ordinary user: drop the `sudo`.

```sh
capsule run -trust dev.pub hello
```

A few things only root may do on Linux. For those, `install.sh` sets up a
**helper**: a root service that systemd starts for one request when an
ordinary user's capsule asks, and that is gone afterwards. To let a user use
it, add them to the `capsule` group:

```sh
sudo usermod -aG capsule alice      # takes effect at alice's next login
```

| | Any user | User in the `capsule` group | Still needs root |
|---|---|---|---|
| Sealing, running, limits, plain volumes | yes | yes | |
| Mesh and cells | yes, slower: the tunnel runs in capsule itself | yes, on the kernel's WireGuard | |
| Volumes with a `size` or `encrypt` | no | yes | Snapshots of them, `volumes -rm` |
| Encrypted capsules | decrypted into memory each start | decrypted once into an encrypted store on disk | |
| Publish | ports 1024 and up | any port | |
| Scaling | behind a published port | behind a published port | Scaling across the mesh |

The helper takes four fixed requests and nothing else: no paths, no
commands. It only mounts disk images it made itself, in folders the user
cannot write to, and only puts a tunnel into a network that user's own
capsule owns. Being in the group does let a user listen on ports below 1024
and use disk space under `/var/lib/capsule/users/`, so add people you would
trust with that. Set `CAPSULE_HELPER=off` to run without it.

Your files then live in `~/.config/capsule` and `~/.local/share/capsule`
instead of `/etc/capsule` and `/var/lib/capsule`. You need a normal login
session (so systemd can give you a resource group), and on Ubuntu 24.04 or
newer the AppArmor profile that `install.sh` installs. Keys in
`~/.config/capsule/trust.d/` are trusted for what you run, like `-trust`.

## 12. Keeping data safe

**A volume with a size** is its own small filesystem:

```json
"volumes": [{"name": "data", "path": "/data", "size": "10G", "encrypt": true}]
```

- `size` is a hard cap; it only takes disk space as it fills. It needs `mkfs.ext4` (package `e2fsprogs`) on the host.
- `encrypt` encrypts file contents and names on disk.

**Snapshots.**

```sh
sudo capsule volumes -snapshot notes               # prints the snapshot's name
sudo capsule volumes -restore notes 20270101T120000Z   # capsule must be stopped
```

A sized volume can be snapshotted while the capsule runs. A plain one only
while it is stopped. Snapshots are in `/var/lib/capsule/snapshots/`; copy them
to another machine for a real backup.

**Do not lose an encrypted volume with its host.** Its key is stored beside
it, wrapped for each host allowed to open it. Add a second host before you
need it:

```sh
sudo capsule host -export > host-b.host            # on the second host
sudo capsule volumes -grant notes host-b.host      # on the first
```

Or put host files in `/etc/capsule/recovery.d/` and every new encrypted volume
includes them from the start.

**Capsules only some hosts can open.** List host ids under `policy.hosts`.
Sealing then needs each host's file and encrypts the root filesystem to them.
On the host it is decrypted once into an encrypted store, so its contents
never sit readable on disk. Without root it is decrypted into memory on each
start instead; that memory is barred from swap, and if the capsule is killed
outright the next `capsule` command clears it:

```sh
capsule seal -key dev.key -host host-a.host -host host-b.host <dir>
```

**Back up `/etc/capsule/host.key`.** It is the host's one secret. Its
identity, its log signatures and its ability to open what was encrypted for
it all come from that file.

**Keep your `.key` files off the hosts.** A host needs only your `.pub`.

## 13. The manifest, field by field

| Field | Meaning |
|---|---|
| `name` | Lowercase letters, digits and dashes. Volumes, cards and services are keyed by it |
| `command` | The program and its arguments |
| `env` | Environment variables |
| `hostname` | Hostname inside; defaults to the name |
| `limits` | `memory` (`"256M"`), `cpus` (`1.5`), `pids` |
| `volumes` | `name`, `path`, and optionally `size`, `encrypt`, `exec` |
| `publish` | Ports that may be opened with `run -publish` |
| `egress` | Outside hosts it may reach: `host` and `port` |
| `network` | `none` (default), `host` (the host's own network), `mesh`, or `cell` |
| `offers` | For a cell: `name`, `to`, and optionally `port`, `udp`, `grant`, `proxy_protocol` |
| `needs` | For a cell: `name`, `from`, and optionally `port`, `udp`, `balance` |
| `mesh.peers` | `name`, `in`, `out`, `in_udp`, `out_udp`, `balance` |
| `policy` | `not_before`, `expires`, `timelock`, `max_runs`, `fleet`, `hosts`, `approvals`, `permits` |
| `scale` | `min`, `max`, `cpu`, `memory_max`, `cooldown`, `restart`, `balance`, `fleet` |
| `unlock` | Environment variables that switch on at a set time: `at` and `env` |
| `syscalls` | A list that narrows which kernel calls are allowed |
| `latency` | For programs where microseconds matter: `cores`, `memory_lock`, `hugepages`, `nic`, `devices` (see below) |

An unknown field is an error, so a typo cannot silently turn a setting off.

**The latency profile.** For a program that measures itself in microseconds,
capsule can step out of its way once it has started. All of it needs root.

```json
"latency": {
  "cores": 2,
  "memory_lock": true,
  "hugepages": true,
  "nic": {"name": "eth1", "address": "10.0.0.5/24", "gateway": "10.0.0.1"},
  "devices": ["/dev/vfio/vfio"]
}
```

| Field | What the capsule gets |
|---|---|
| `cores` | That many whole cores from the set in `/etc/capsule/latency`, shared with no other capsule and with no CPU quota to pause it. Memory comes from the same NUMA node. Cannot be combined with `limits.cpus` |
| `memory_lock` | The right to lock all its memory in RAM (`mlockall`) |
| `hugepages` | The host's huge pages, at `/dev/hugepages` |
| `nic` | One of the host's network interfaces, moved into the capsule and set up there. The host does not have it while the capsule runs |
| `devices` | Device files of the host, there for the capsule to open with the host's own permissions on them. This is what a network stack that bypasses the kernel needs, together with huge pages and locked memory |

In a tissue, such a cell is only placed on hosts that list the cores and the
interface: `{"file": "fast-1.host", "cores": 6, "nics": ["eth1"]}`.

This is about removing what would slow a program down, and it is tested for
being applied, not for speed: real numbers need your own hardware. The
pieces a kernel-bypass stack (DPDK, OpenOnload) asks for are all here, but no
such stack has been run in a capsule by us.

## 14. Commands

**Making capsules**

| Command | Does |
|---|---|
| `capsule keygen <name>` | Make a key: `.key`, `.pub`, `.id` |
| `capsule init [-rootfs <dir or tarball>] <dir>` | Start a capsule folder |
| `capsule build -key <key> <file.cue>` | Build and seal from a CUE file |
| `capsule seal -key <key> [-host <file>]... <dir>` | Seal a folder |
| `capsule verify <dir>` | Check a seal |
| `capsule inspect <dir>` | Describe it, and say whether this host would run it |
| `capsule approve -key <key> <dir>` | Add an approval |
| `capsule permit -key <key> -host <id> -runs N <dir>` | Let one host run it N times |
| `capsule render <fleet.cue>` | Lay out a set of hosts |

**Running**

| Command | Does |
|---|---|
| `capsule run [flags] <dir>` | Check everything, then run |
| `capsule ps` | List running capsules |
| `capsule kill <id>` | Stop one |
| `capsule resize [-memory] [-cpus] [-pids] <id>` | Change limits live |
| `capsule volumes` | List, `-rm`, `-snapshot`, `-restore`, `-grant` |
| `capsule log [-all] [-ledger]` | Show and verify this host's record |
| `capsule prune` | Delete stored copies nothing uses |

`run` flags: `-trust <pub>`, `-publish [addr:]hostport:capsuleport`,
`-instance <label>`, `-receipt <file>`, and for the mesh `-listen <port>`,
`-advertise <ip>`, `-peers <dir>`.

**The host and the fleet**

| Command | Does |
|---|---|
| `capsule host [-export]` | Print this host's ids, or its public host file |
| `capsule revoke [-key <key> [-publish]] <dir>` | Stop a seal here, or everywhere |
| `capsule delegate -key <key> -host <id> <name>...` | Let a host issue its own cards |
| `capsule card ...` | Sign one card by hand |
| `capsule identity <name>` | An instance's mesh key and address on this host |
| `capsule ledger check` | Test the shared store |
| `capsule publish -key <key> <dir>` | Upload a release |
| `capsule fetch <name>` | Install the current release |
| `capsule witness` | Publish this host's log and co-sign the others' |
| `capsule receipt -host <id> <file>` | Check a run receipt from another host |
| `capsule order -key <key> -host <host file>... <action>` | Sign an order and send it to hosts through the ledger |
| `capsule order sign`, `send`, `result` | Add a signature to an order file, send it, read the answers |
| `capsule orders` | On a host: carry out the orders waiting for it (run by `capsule-orders.timer`) |
| `capsule tissue -key <key> <file>` | Sign a tissue and publish it: what the fleet must keep alive |
| `capsule tissue status` | What is alive, where, and which draw put it there |
| `capsule tend` | On a host: do its part of the tissue (run by the same timer) |

## 15. Where things live

| Path | What |
|---|---|
| `/etc/capsule/trust.d/*.pub` | Keys this host trusts |
| `/etc/capsule/host.key` | The host's secret. **Back it up** |
| `/etc/capsule/peers.d/` | Mesh cards; may be a folder shared between hosts |
| `/etc/capsule/grants.d/` | Grants this host presents when its cells call others |
| `/etc/capsule/delegation` | Names this host may issue cards for |
| `/etc/capsule/operators.d/*.pub` | Keys whose orders this host obeys |
| `/etc/capsule/orders` | How many operators must sign each kind of order |
| `/etc/capsule/latency` | Cores this host keeps for latency-critical capsules |
| `/etc/capsule/policy.d/*.cue` | Rules every capsule here must satisfy |
| `/etc/capsule/ledger`, `ledger.env` | The shared store and its credentials |
| `/etc/capsule/recovery.d/*.host` | Hosts that can also open new encrypted volumes |
| `/etc/capsule/apps/<name>.env` | Flags for the `capsule@<name>` service |
| `/var/lib/capsule/apps/` | Capsules run as services |
| `/var/lib/capsule/volumes/` | Volume data |
| `/var/lib/capsule/snapshots/` | Snapshots |
| `/var/lib/capsule/log.jsonl` | The host's record |
| `/var/lib/capsule/users/<uid>/` | Sized volumes and encrypted stores the helper keeps for users without root |

## 16. When something is refused

Every refusal starts `capsule: refusing to run:` and says why. Run
`capsule inspect <dir>` to see the same reason without starting anything.

| Message | Meaning and fix |
|---|---|
| `capsule is not sealed` | Run `capsule seal` |
| `no trusted keys` | Put a `.pub` in `/etc/capsule/trust.d/`, or pass `-trust` |
| `sealed by a key this host does not trust` | The host does not have the signer's `.pub` |
| `capsule.json was changed after sealing` / `rootfs was changed after sealing` | Seal it again |
| `has 1 of 2 required approvals` | More signers must run `capsule approve` |
| `time-locked until ...` / `expired at ...` | Outside its allowed window |
| `this host is not authorised to run it` | The host's id is not in `policy.hosts` |
| `this seal has been revoked` | Someone revoked this exact seal; seal a new version |
| `already ran N of N permitted times` | The run limit is used up |
| `this host holds no valid permit to run it` | Issue one with `capsule permit` |
| `host rule X does not allow it` | A file in `/etc/capsule/policy.d/` forbids it |
| `the volumes of X are in use by another running instance` | Give the second copy `-instance <label>` |
| `rootfs /etc cannot be used as a directory` | The root filesystem has a symlink where capsule must place a folder |
| `this capsule needs the fleet ledger` | It is marked `fleet`; configure `/etc/capsule/ledger` |
| `creating a tunnel interface (is /dev/net/tun available?)` | Without root the mesh needs the `tun` device: `sudo modprobe tun` |
| `no cgroup this user may manage` | Without root you need a normal login session |

If a capsule starts and then dies: `capsule log` shows its exit status.
Status 137 usually means it hit its memory limit; raise `limits.memory` or
add `scale.memory_max`.

## 17. What capsule does not do

- **It does not protect a capsule from the host's own administrator.** Root on a host can read a running capsule's memory. That needs special hardware.
- **It has no image registry and no layers.** Capsules are folders; `publish` and `fetch` move them through storage you already have.
- **Sized or encrypted volumes need root or the helper** (section 11). The mesh and cells need neither, but with neither their tunnels run in capsule's own process and are slower.
- **Orders do not maintain the host itself.** There is no remote shell on a host, by design; operating system updates need their own mechanism. `exec` runs one command inside a capsule, not an interactive terminal.
- **Some cell traffic passes through capsule's own process:** socket files, programs that listen on IPv4 only, and offers with a grant or `proxy_protocol`. Port-to-port traffic otherwise goes straight through the kernel.
- **Autoscaling goes by CPU and memory**, not by request rate or queue length.
- **A tissue is not instant, except where you ask.** Hosts act on a timer, so placement takes seconds and taking over from a dead host takes about a lease. A hot standby with `detect` takes over in milliseconds.
- **Data follows by snapshot, not by replication.** A cell that keeps data and dies loses what it wrote since its last snapshot.
- **`expires` trusts the host's clock.** `not_before` can be made tamper-proof with `timelock`; `expires` cannot.
- **Time locks are not post-quantum.** Seals, approvals, encrypted capsules and, with `kem` keys on the cards, mesh and cell traffic are.

See `README.md` for design notes and the full list of limits.
