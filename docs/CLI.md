# capsule command reference

Every command and every option. For a walkthrough, see [GUIDE.md](GUIDE.md);
for the manifest's fields, see section 13 there.

## Conventions

- **Options come before the folder or name.** `capsule run -publish 8080:8080 notes` works; `capsule run notes -publish 8080:8080` does not.
- **`<dir>`** is a capsule folder: `capsule.json`, `rootfs/` and, once sealed, `capsule.seal`.
- **`<id>`** is a running capsule's id from `capsule ps`, such as `notes-1a2b3c4d`.
- **Options marked "repeatable"** can be given more than once.
- **Linux only:** `run`, `ps`, `kill`, `resize`, `volumes`, `prune` and `identity`. Everything else also works on macOS.
- Run a command with `-h` to see its options.

**Exit status**

| Status | Meaning |
|---|---|
| `0` | Success. For `run`: the capsule exited with 0, or you stopped `capsule run` with a termination signal (as `systemctl stop` does) |
| `1` | Refused, or an error, or missing arguments. The reason is printed |
| `2` | Unknown command or unknown option |
| other | For `run`: the capsule's own exit status. `137` means it was killed, usually for exceeding its memory limit or by `capsule kill` |

## Commands at a glance

| Making capsules | Running | This host and the fleet |
|---|---|---|
| [`keygen`](#keygen) | [`run`](#run) | [`host`](#host) |
| [`init`](#init) | [`ps`](#ps) | [`revoke`](#revoke) |
| [`build`](#build) | [`kill`](#kill) | [`delegate`](#delegate) |
| [`seal`](#seal) | [`resize`](#resize) | [`card`](#card) |
| [`verify`](#verify) | [`volumes`](#volumes) | [`identity`](#identity) |
| [`inspect`](#inspect) | [`log`](#log) | [`ledger check`](#ledger-check) |
| [`approve`](#approve) | [`receipt`](#receipt) | [`publish`](#publish) |
| [`permit`](#permit) | [`prune`](#prune) | [`fetch`](#fetch) |
| [`render`](#render) | [`version`](#version) | [`witness`](#witness) |
| | | [`grant`](#grant), [`tick`](#tick) |
| | | [`order`](#order), [`orders`](#orders) |
| | | [`tissue`](#tissue), [`tend`](#tend) |

## Making capsules

### keygen

```
capsule keygen <name>
```

Makes a signing key and writes three files:

| File | Use |
|---|---|
| `<name>.key` | Private. Signs seals, approvals, permits, cards. Keep it off hosts |
| `<name>.pub` | Public. Put it in a host's `/etc/capsule/trust.d/` to be trusted there |
| `<name>.id` | A short name for the key. Use it inside manifests (`policy.approvals.signers`, `policy.permits`) |

It refuses to overwrite an existing `.key`.

### init

```
capsule init [-rootfs <dir or tarball>] <dir>
```

Creates a capsule folder with a starter manifest.

| Option | Meaning |
|---|---|
| `-rootfs <path>` | Fill the root filesystem from a folder or a `.tar` / `.tar.gz` archive. Without it, `rootfs/` starts empty |

Device files in an archive are skipped; a capsule gets its own `/dev`.

### build

```
capsule build [-o <dir>] [-key <file>] [-force] [-rules <file.cue>]... [-host <file>]... <file.cue>
```

Builds a capsule from a CUE build file: assembles the root filesystem,
writes the manifest, and seals it if given a key.

| Option | Meaning |
|---|---|
| `-o <dir>` | Where to write the capsule. Default: a folder named after the capsule |
| `-key <file>` | Seal the result with this private key |
| `-force` | Replace the output folder if it exists |
| `-rules <file.cue>` | A CUE file of rules the capsule must satisfy. Repeatable |
| `-host <file>` | A host file from `capsule host -export`, one for each id in `policy.hosts`. Repeatable |

In the build file, `rootfs` takes:

| Field | Meaning |
|---|---|
| `from` | The base: a folder, a `.tar` / `.tar.gz`, or an `https://` URL |
| `sha256` | The base's hash. Required for a URL |
| `add` | A list of further archives or folders laid over the base, each `{from, sha256?, to, strip}`. `to` is where it goes (default `/`); `strip` drops that many leading folders from each entry |
| `files` | Single files: `"/path": contents: "text"` or `"/path": {source: "file", mode: 0o755}` |

Paths are relative to the build file. Downloads are kept in your cache folder
and reused.

### seal

```
capsule seal -key <file> [-host <file>]... <dir>
```

Hashes the root filesystem and the manifest and signs them, writing
`capsule.seal`. Seal again after any change.

| Option | Meaning |
|---|---|
| `-key <file>` | The private key to sign with. Required |
| `-host <file>` | A host file from `capsule host -export`. Needed once for each id in `policy.hosts`. Repeatable |

If the policy lists `hosts` or sets `timelock`, sealing also writes
`rootfs.enc`, the encrypted root filesystem. `timelock` needs internet access.

### verify

```
capsule verify [-trust <pub>]... <dir>
```

Checks that the seal was made by a trusted key and that nothing has changed.
Prints `ok` or the reason it failed.

| Option | Meaning |
|---|---|
| `-trust <pub>` | Trust this public key file as well as those in `/etc/capsule/trust.d/`. Repeatable |

### inspect

```
capsule inspect [-trust <pub>]... <dir>
```

Describes a capsule (command, network, limits, policy, seal, approvals) and
ends with `this host  would run it` or `would refuse:` and why. It starts
nothing.

| Option | Meaning |
|---|---|
| `-trust <pub>` | As for `verify`. Repeatable |

### approve

```
capsule approve -key <file> [-days N] <dir>
```

Adds this key's approval of the sealed capsule to `capsule.approvals`. It
counts only if the key's id is listed in `policy.approvals.signers`.

| Option | Meaning |
|---|---|
| `-key <file>` | The approver's private key. Required |
| `-days N` | The approval lapses after N days. Default: never |

An approval covers one exact seal. Approving twice with one key counts once.

### permit

```
capsule permit -key <file> -host <host id> [-runs N] [-days N] <dir>
```

Lets one host run a sealed capsule a number of times, adding to
`capsule.permits`. Used when the manifest sets `policy.permits`.

| Option | Meaning |
|---|---|
| `-key <file>` | A private key whose id is listed in `policy.permits`. Required |
| `-host <id>` | The host's id, from `capsule host`. Required |
| `-runs N` | How many runs. Default 1 |
| `-days N` | The permit lapses after N days. Default: never |

Several permits for one host add up.

### render

```
capsule render [-o <dir>] [-rules <file.cue>]... <fleet.cue>
```

Turns a CUE fleet file (which sealed capsules run on which hosts) into one
folder per host, laid out as that host's filesystem, and prints the commands
to copy each into place and start it.

| Option | Meaning |
|---|---|
| `-o <dir>` | Output folder. Default `deploy` |
| `-rules <file.cue>` | Rules the fleet file must satisfy. Repeatable |

## Running

### run

```
capsule run [-trust <pub>]... [-publish [addr:]hostport:capsuleport]... [-instance <label>]
            [-receipt <file>] [-listen <port>] [-advertise <ip>] [-peers <dir>]
            [-grants <dir>] <dir>
```

Checks the seal and the policy, then runs the capsule in its sandbox. It
stays in the foreground: its output is the capsule's output, and stopping it
(Ctrl-C, or `kill`) stops the capsule.

| Option | Meaning |
|---|---|
| `-trust <pub>` | Trust this public key file as well. Repeatable |
| `-publish [addr:]hostport:capsuleport` | Open a host port onto a port inside the capsule. The capsule port must be listed in the manifest's `publish`. Without `addr` it listens on all addresses. Repeatable |
| `-instance <label>` | Run as a separate instance with its own volumes and mesh identity. Needed to run two copies on one host |
| `-receipt <file>` | Write a host-signed receipt of this run, including a hash of what the capsule printed |
| `-listen <port>` | Mesh: the host UDP port for this instance's tunnel. Default: one is picked |
| `-advertise <ip>` | Mesh: this host's address, put on the card this instance issues for itself so peers know where to connect |
| `-peers <dir>` | Mesh: the folder of peer cards. Default `/etc/capsule/peers.d` |
| `-grants <dir>` | Cell: the folder of grants this host presents when its cells call others. Default `/etc/capsule/grants.d` |

With a `scale` section in the manifest, `run` keeps a set of replicas going
instead of one capsule, and a published port is shared between them.

Without root, `run` works in a user namespace. For a user in the `capsule`
group the helper supplies the kernel's WireGuard, sized and encrypted
volumes, the encrypted store and ports below 1024. For any other user the
mesh and cells use a tunnel that runs inside capsule, which is slower, and
sized volumes are refused.

### ps

```
capsule ps
```

Lists this user's running capsules: id, process count, memory in use, memory
limit and CPU limit. Use `sudo capsule ps` for capsules started with `sudo`.

### kill

```
capsule kill <id>
```

Stops every process in a capsule at once. Its `run` then exits with 137.

### resize

```
capsule resize [-memory <size>] [-cpus <n>] [-pids <n>] <id>
```

Changes a running capsule's limits. The change lasts until it stops; the
manifest's values apply again at the next start.

| Option | Meaning |
|---|---|
| `-memory <size>` | New memory limit, such as `512M` or `2G` |
| `-cpus <n>` | New CPU limit in cores, such as `1.5` |
| `-pids <n>` | New limit on the number of processes |

### volumes

```
capsule volumes
capsule volumes -rm <name>
capsule volumes -snapshot <name>
capsule volumes -restore <name> <snapshot>
capsule volumes -grant <name> <host file>
```

With no option, lists the data capsules keep on this host and its size.
`<name>` is the capsule's name, or `name-label` for an instance started with
`-instance`.

| Option | Meaning |
|---|---|
| `-rm <name>` | Delete all of that capsule's volume data. Refused while it runs |
| `-snapshot <name>` | Copy its data to a dated snapshot and print the snapshot's name. Works while running for volumes with a `size` |
| `-restore <name> <snapshot>` | Replace its data with a snapshot. The capsule must be stopped |
| `-grant <name> <host file>` | Let another host open its encrypted volumes. The host file comes from `capsule host -export` on that host |

### log

```
capsule log [-all] [-host <id>] [-file <path>] [-hostfile <file>] [-ledger]
```

Prints this host's record of every run, exit and refusal, and checks that no
entry has been changed, removed or reordered.

| Option | Meaning |
|---|---|
| `-all` | Also go through the files set aside by rotation, oldest first, and check the chain across them. Without it only the current file is read |
| `-host <id>` | Also require every entry to be signed by the host whose signing key id this is |
| `-file <path>` | Check a copy of a log instead of this host's own |
| `-hostfile <file>` | The host file (`capsule host -export`) of the host that wrote the log. Needed for a copy that does not begin with a file's first entry, which is the one that carries the host's key |
| `-ledger` | Also check the log against what its host published to the fleet ledger, and report how many other hosts co-signed it |

The log is kept in `log.jsonl` in the data folder. When it reaches 64 MB
(`CAPSULE_LOG_MAX` bytes, if set) it is renamed `log-<last entry>.jsonl` and a
new file carries on the same chain.

### receipt

```
capsule receipt -host <id> <file>
```

Checks a run receipt made by `run -receipt` on another host and prints what
it states: which capsule and seal ran, when it finished, its exit status and
the hash of its output.

| Option | Meaning |
|---|---|
| `-host <id>` | The signing key id of the host the receipt must come from (the `sign` line of `capsule host` there). Required |

### prune

```
capsule prune
```

Deletes stored copies of root filesystems that no running capsule is using,
pooled files nothing links to any more, and the encrypted stores of encrypted
capsules that are not running. All are recreated when next needed.

### version

```
capsule version
```

## This host and the fleet

### host

```
capsule host [-export]
```

Prints this host's two ids: `id` (used in `policy.hosts` and for permits) and
`sign` (the key that signs its log, receipts and self-issued cards). The
first use creates the host's secret.

| Option | Meaning |
|---|---|
| `-export` | Print the host file instead: the public keys someone needs to seal a capsule for this host or grant it a volume. Contains nothing secret |

### revoke

```
capsule revoke <dir>
capsule revoke -key <file> [-publish] <dir>
```

Stops one exact seal from running again. Without options, on this host only.

| Option | Meaning |
|---|---|
| `-key <file>` | Sign a revocation for every host, and print it. Save it into each host's `/etc/capsule/revoked.d/` as a `.json` file |
| `-publish` | With `-key`: put the revocation in the fleet ledger instead, where every host sees it at once |

### delegate

```
capsule delegate -key <file> -host <signing key id> <name>...
```

Prints a delegation letting a host issue its own mesh cards, and share its
load for fleet scaling, for the named capsules. Save it as
`/etc/capsule/delegation` on that host.

| Option | Meaning |
|---|---|
| `-key <file>` | A private key the other hosts trust. Required |
| `-host <id>` | The host's signing key id: the `sign` line of `capsule host`. Required |

### grant

```
capsule grant -key <file> -receptor <name> -of <cell> -to <cell> [-for <duration>]
```

Prints a grant letting one cell use a receptor that another offers with
`"grant": true`. Save it as a `.grant` file in `/etc/capsule/grants.d/` on
the host of the cell that calls. It is good from now for the given time,
counted in ticks, and then stops working by itself: new connections are
refused and ones it let in are closed.

| Option | Meaning |
|---|---|
| `-key <file>` | A private key the offering cell's host trusts. Required |
| `-receptor <name>` | The receptor's name. Required |
| `-of <cell>` | The cell that offers it. Required |
| `-to <cell>` | The cell that may use it. Required |
| `-for <duration>` | How long it lasts, such as `30m` or `24h`. Default `24h` |

### tick

```
capsule tick
```

Prints the current tick, and whether it came from the drand beacon (checked
by signature) or, when the beacon cannot be reached, from this host's clock.
In the second case it is never earlier than the last tick the beacon proved
on this host.

### card

```
capsule card -key <file> -name <name> -mesh-key <key> [-kem <key>] [-endpoint <ip:port>]
```

Prints one signed mesh card by hand, for hosts that have no delegation. Save
it in `/etc/capsule/peers.d/` as a `.card` file on each host that should know
the instance.

| Option | Meaning |
|---|---|
| `-key <file>` | A private key the hosts trust. Required |
| `-name <name>` | The capsule's name. Required |
| `-mesh-key <key>` | The instance's mesh key, from `capsule identity`. Required |
| `-kem <key>` | The instance's `kem` key, from `capsule identity`. Tunnels to it then also carry an ML-KEM secret, replaced hourly, so they resist quantum computers |
| `-endpoint <ip:port>` | Where the instance's tunnel listens. Leave out for a capsule that only makes connections |

### identity

```
capsule identity [-instance <label>] <name>
```

Prints the mesh key, address and kem key that a capsule of this name has on
this host.

| Option | Meaning |
|---|---|
| `-instance <label>` | For an instance started with `run -instance` |

### ledger check

```
capsule ledger [-writers N] [-rounds N] check
```

Tests whether the store named in `/etc/capsule/ledger` can be trusted with
fleet-wide run limits, by having several writers race to create the same
keys. It ends with a verdict, and removes what it wrote.

| Option | Meaning |
|---|---|
| `-writers N` | How many writers race for each key. Default 12 |
| `-rounds N` | How many keys to race for. Default 5 |

### publish

```
capsule publish -key <file> [-trust <pub>]... <dir>
```

Uploads a sealed capsule to the fleet's shared store and marks it as the
current release of its name.

| Option | Meaning |
|---|---|
| `-key <file>` | Signs the release. Hosts must trust this key to fetch it. Required |
| `-trust <pub>` | Trust this public key when checking the capsule before upload. Repeatable |

### fetch

```
capsule fetch [-o <dir>] [-trust <pub>]... <name>
```

Installs the current release of a capsule from the shared store, or replaces
an older one. It refuses a release not signed by a trusted key, one older
than this host has already fetched, and a capsule that does not match its
seal.

| Option | Meaning |
|---|---|
| `-o <dir>` | Install here. Default `/var/lib/capsule/apps/<name>` |
| `-trust <pub>` | Trust this public key as well. Repeatable |

### witness

```
capsule witness
```

Publishes this host's log to the fleet ledger and co-signs the newest entry
of every other host. It reports, and exits with 1, if another host's
published record has been altered or removed since this host last saw it.
`capsule run` does the same after every run; use `witness` from a timer on
hosts that start capsules rarely.

### order

```
capsule order -key <file> -host <host file>... [-for 10m] [-wait 30s] [-o <file>] <action>
capsule order sign -key <file> <order file>
capsule order send [-wait 30s] <order file>
capsule order result [-wait 30s] <order file or id>
```

Signs an order and sends it through the fleet ledger to the hosts named.
Works on any machine that has the `ledger` setting, macOS included.

| Action | Does on each host |
|---|---|
| `fetch <name>` | Installs the current release |
| `run <name>` | Fetches if it can, then starts the capsule as a systemd service |
| `stop <name>` | Stops it |
| `resize <name> [memory=512M] [cpus=2] [pids=256]` | Changes a running capsule's limits |
| `revoke <seal id>` | Never runs that seal again |
| `ps` | Lists running capsules |
| `log [lines]` | The end of the host's signed record (default 20, at most 1000) |
| `exec <name> [instance=<label>] [timeout=30s] -- <command>...` | Runs a command inside a running capsule |

| Option | Meaning |
|---|---|
| `-key <file>` | The operator's private key. Required |
| `-host <host file>` | A host to carry it out, from `capsule host -export`. Repeatable |
| `-for <duration>` | How long the order stays good. Default 10m, at most 24h |
| `-wait <duration>` | Wait this long for the answers and print them |
| `-o <file>` | Write the order to a file instead of sending it, for others to `sign` |

`result` exits with 1 if any host refused, failed or has not answered. The
answers can be read only on the machine that wrote the order.

### orders

```
capsule orders
```

On a host: looks once in the ledger for orders addressed to it, carries out
those signed by enough of the keys in `operators.d`, publishes a signed
answer to each, and exits. `capsule-orders.timer` runs it every 5 seconds.
`/etc/capsule/orders` sets how many operators must sign each action, one
`<action> <number>` or `<action> off` per line, `*` for the rest; `exec` is
off unless listed.

### tissue

```
capsule tissue -key <file> [-o <file>] <tissue.json>
capsule tissue sign -key <file> <signed file>
capsule tissue send <signed file>
capsule tissue status
```

Signs a tissue (which cells must be alive, how many, on which hosts) and
publishes it to the ledger. `-o` writes the signed file instead, for another
operator to `sign` before it is sent. `status` shows every host and every
slot: who holds it, at which term, on which release, and the beacon round of
the draw that decided it (`?` marks a draw made without the beacon).

The file:

| Field | Meaning |
|---|---|
| `name` | The tissue's name |
| `lease` | Ticks a renewal lasts (default 10) |
| `budget` | `memory`, `cpus`: the most the whole tissue may commit |
| `cells.<name>` | `root`, `min`, `max`, `on`, `standby` (`warm`, `hot`), `takeover` (`fast`, `strict`), `step`, `detect`, `snapshot` |
| `hosts[]` | `file` (from `capsule host -export`), `labels`, `weight`, `memory`, `cpus`, `cores`, `nics`, `drain` |

### tend

```
capsule tend
```

On a host: one pass over the tissue. Says the host is alive, reads the
leases, and does this host's part: claims a slot it has won, renews the ones
it holds, keeps a standby ready, moves to a new release when it is its turn,
and stops what it no longer holds. `capsule-orders.timer` runs it every 5
seconds after `capsule orders`. It does nothing on a host with no operators,
no ledger or no tissue.

## Environment variables

| Variable | Effect |
|---|---|
| `CAPSULE_CONFIG` | Use this folder for settings instead of `/etc/capsule` (or `~/.config/capsule`) |
| `CAPSULE_DATA` | Use this folder for data instead of `/var/lib/capsule` (or `~/.local/share/capsule`) |
| `CAPSULE_RUN` | Use this folder for run state instead of `/run/capsule` |
| `CAPSULE_DRAND` | Comma-separated drand endpoints for `timelock` and ticks, instead of the public ones |
| `CAPSULE_PSK_TICKS` | How many ticks a tunnel's post-quantum secret lasts before it is replaced. Default 1200 (an hour) |
| `CAPSULE_HELPER` | The helper's socket, instead of `/run/capsule-helper.sock`; `off` runs without it |
| `CAPSULE_LOG_MAX` | Size in bytes at which the log is set aside and a new file started. Default 64 MB |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | Credentials for an `s3://` ledger |
| `VAULT_TOKEN` | Credentials for a `vault://` ledger |
| `ARTIFACTORY_TOKEN`, or `ARTIFACTORY_USER` and `ARTIFACTORY_PASSWORD` | Credentials for an `artifactory://` ledger |

Ledger credentials can instead go in `/etc/capsule/ledger.env` as
`NAME=value` lines; the environment wins if both are set.

## Files a command reads or writes in a capsule folder

| File | Written by | Read by |
|---|---|---|
| `capsule.json` | you, `init`, `build` | everything |
| `rootfs/` | you, `init`, `build` | `seal`, `run` |
| `capsule.seal` | `seal`, `build -key` | `run`, `verify`, `inspect`, `approve`, `permit`, `revoke`, `publish` |
| `rootfs.enc` | `seal` (when the policy has `hosts` or `timelock`) | `run` |
| `capsule.approvals` | `approve` | `run`, `inspect` |
| `capsule.permits` | `permit` | `run` |
