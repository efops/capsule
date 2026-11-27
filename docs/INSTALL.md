# Installing capsule

This covers what a host needs, how to build and install, how to check the
installation, and how to upgrade or remove it. For what to do next, see
[GUIDE.md](GUIDE.md).

## At a glance

```sh
# on a machine with Go 1.26
make linux

# on the Linux host
sudo sh dist/install.sh bin/capsule-linux-amd64     # or bin/capsule-linux-arm64
capsule version
```

## 1. What the host needs

Capsule runs programs on Linux. It is tested on Ubuntu 24.04 (kernel 6.8,
x86-64) and Ubuntu 25.04 (kernel 6.14, arm64). Other distributions with the
same kernel features should work but have not been tested.

**Required**

| Need | Check | Expect |
|---|---|---|
| Linux kernel 5.11 or newer | `uname -r` | `5.11` or higher |
| cgroup v2 | `stat -fc %T /sys/fs/cgroup` | `cgroup2fs` |
| systemd | `systemctl --version` | any recent version |

If `stat` prints `tmpfs`, the host is on the older cgroup v1 layout and
capsule will not run there.

**Needed only for some features**

| Feature | Needs | Check or install |
|---|---|---|
| Mesh networking | WireGuard and nftables in the kernel; root | `sudo modprobe wireguard && sudo modprobe nf_tables` |
| Volumes with a `size` or `encrypt` | `mkfs.ext4`; root | `sudo apt-get install -y e2fsprogs` (usually present) |
| `timelock`, `fetch` from a bucket, URL bases in a build | Outbound HTTPS | |
| Running without root on Ubuntu 24.04 or newer | The AppArmor profile | Installed by `install.sh` |
| The examples and the test scripts | `curl`, `busybox` | `sudo apt-get install -y curl busybox-static` |

**Open ports.** Capsule itself listens on nothing. If you use the mesh
between hosts, allow the UDP port you pass to `run -listen` through your
firewall. Published ports are whatever you choose with `run -publish`.

**Clock.** Keep the host's clock synchronised (`timedatectl` should show
`System clock synchronized: yes`). Time-limited capsules, approvals that
expire, and fleet scaling all compare times.

## 2. Build

You need Go 1.26 or newer. The build machine does not have to be the host:
the result is one static file with no dependencies.

```sh
cd capsule
make linux
```

This writes `bin/capsule-linux-amd64` and `bin/capsule-linux-arm64`. Pick the
one matching the host (`uname -m`: `x86_64` is amd64, `aarch64` is arm64).

On a Mac, `make build` writes `bin/capsule` for your own machine. With it you
can make keys and build, seal, approve and inspect capsules. Running them
needs a Linux host.

To check the build before installing:

```sh
go test .
```

## 3. Install

Copy the binary and the `dist/` folder to the host, then:

```sh
sudo sh dist/install.sh bin/capsule-linux-amd64
```

What it does:

| Step | Result |
|---|---|
| Installs the program | `/usr/local/bin/capsule` |
| Creates the settings folders | `/etc/capsule/` with `trust.d`, `peers.d`, `grants.d`, `revoked.d`, `policy.d`, `recovery.d`, `apps` |
| Creates the data folder | `/var/lib/capsule/` (readable by root only) |
| Installs the service template | `/etc/systemd/system/capsule@.service` |
| Installs the orders timer, not enabled | `capsule-orders.timer` and `.service`, for the system and for users |
| Creates the `capsule` group and turns on the helper's socket | `/run/capsule-helper.sock`, open to that group only |
| On hosts with AppArmor, installs and loads the profile | `/etc/apparmor.d/capsule` |

It changes nothing else and is safe to run again. The only thing it turns on
is the helper's socket, which does nothing until a member of the `capsule`
group uses it, and the group starts empty.

If you prefer `make`: `sudo make install BIN=bin/capsule-linux-amd64` runs the
same script.

## 4. Check it works

```sh
capsule version                    # capsule 0.3.0
sudo capsule host                  # prints this host's id and signing key id
```

The first `capsule host` creates the host's secret, `/etc/capsule/host.key`.
**Back that file up somewhere safe.** The host's identity, its log signatures
and its ability to open anything encrypted for it all come from it.

Then run something. This makes a key, trusts it, and runs a 3 MB Alpine
Linux capsule:

```sh
capsule keygen dev
sudo install -m 644 dev.pub /etc/capsule/trust.d/dev.pub
curl -fsSLO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
capsule init -rootfs alpine-minirootfs-3.20.3-x86_64.tar.gz hello
capsule seal -key dev.key hello
sudo capsule run hello             # hello from hello
```

(On arm64, use `aarch64` in both places in the URL.)

For a fuller check, the project's own tests run against the installed
program. They need `busybox-static`, `nftables` and internet access, and
should be run on a test machine, not a production host:

```sh
sudo sh test/smoke.sh /usr/local/bin/capsule     # the sandbox, policy, volumes, and more
sudo sh test/guide.sh /usr/local/bin/capsule     # every step of the beginner's guide
```

## 5. Set up for your team

**Trust.** A host runs only what a key it trusts has sealed. Put each
trusted public key in `/etc/capsule/trust.d/` as a `.pub` file. Keep the
matching `.key` files off the hosts: a host never needs them.

**Without root.** Any user can run capsules without `sudo`; nothing extra
needs installing. To also give a user sized and encrypted volumes, the
kernel's WireGuard for the mesh, the encrypted on-disk store and ports below
1024, add them to the `capsule` group (`sudo usermod -aG capsule <user>`,
effective at their next login). That lets them reach the helper described in
the guide, section 11. Their settings and data go under `~/.config/capsule` and
`~/.local/share/capsule`. They need a normal login session. For capsules that
must keep running after the user logs out, enable lingering once:

```sh
sudo loginctl enable-linger <user>
```

**Services.** To run a capsule at boot and restart it if it fails:

```sh
sudo cp -a <capsule folder> /var/lib/capsule/apps/<name>
echo 'CAPSULE_ARGS=-publish 8080:8080' | sudo tee /etc/capsule/apps/<name>.env
sudo systemctl enable --now capsule@<name>
```

**Orders instead of SSH.** To operate a host through signed orders (guide,
section 9), put the operators' public keys in `/etc/capsule/operators.d/`,
set `/etc/capsule/ledger`, and enable the timer:

```sh
sudo systemctl enable --now capsule-orders.timer
```

For capsules a user runs without root, that user enables their own:
`systemctl --user enable --now capsule-orders.timer`. Once orders work you
can close the host's SSH port; keep console access for emergencies.

**A fleet that looks after itself.** The same timer makes a host follow a
tissue (guide, section 9): a signed list of what must be alive, which the
hosts keep true between them. Nothing more needs installing.

**A fleet on the mesh.** Capsules a tissue starts are run without flags, so
tell each host once where its tunnels can be reached, and share one folder of
cards between the hosts:

```sh
echo 10.0.0.5 | sudo tee /etc/capsule/advertise     # this host's address
# /etc/capsule/peers.d: a folder every host can read and write, such as a shared mount
```

**Latency-critical capsules.** To let capsules have cores of their own, name
the cores this host keeps for them in `/etc/capsule/latency`:

```
cores 2-7
```

Ideally these are cores the kernel was told to leave alone at boot
(`isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7`). Every other capsule is then
kept off them.

**More than one host.** Install the same way on each. Then give every host
the same line in `/etc/capsule/ledger` (see the guide, section 9) and, for
the mesh, a delegation for the capsule names it may run (section 7).

## 6. Upgrade

Build the new version and run the installer again:

```sh
sudo sh dist/install.sh bin/capsule-linux-amd64
```

Running capsules are not interrupted: each keeps running under the program
that started it. Restart a service to move it to the new version
(`sudo systemctl restart capsule@<name>`).

Settings, keys, volumes and the log are untouched by an upgrade.

## 7. Remove

```sh
sudo sh dist/uninstall.sh
```

This removes the program, the systemd units and the AppArmor profile, and
keeps your settings and data. It refuses while capsules are running.

To delete everything, including the host's secret, trusted keys, all volume
data, snapshots and the log:

```sh
sudo sh dist/uninstall.sh --purge
```

That cannot be undone. Copy `/etc/capsule/host.key` and anything you need
from `/var/lib/capsule/volumes` and `/var/lib/capsule/snapshots` first.

A user's own files are in `~/.config/capsule` and `~/.local/share/capsule`;
delete those by hand if you want them gone.

## 8. If installation goes wrong

| Symptom | Cause and fix |
|---|---|
| `capsule: command not found` | `/usr/local/bin` is not on your `PATH`, or the installer was not run as root |
| `cannot execute binary file: Exec format error` | Wrong architecture: install the other `bin/capsule-linux-*` |
| `cgroup v2 is not mounted at /sys/fs/cgroup` | The host uses cgroup v1. Boot with `systemd.unified_cgroup_hierarchy=1`, or use a newer distribution |
| Without root: `no cgroup this user may manage` | You are not in a normal login session (for example inside `su` or a bare SSH command). Log in properly, or enable lingering |
| Without root: `the host restricts user namespaces` | The AppArmor profile is missing: run the installer again |
| `creating WireGuard interface (is the wireguard module available?)` | `sudo modprobe wireguard`; install your distribution's WireGuard kernel module if that fails |
| `a volume with a size needs mkfs.ext4` | `sudo apt-get install -y e2fsprogs` |
| `no trusted keys` | Put a `.pub` in `/etc/capsule/trust.d/`, or pass `-trust <file>` |
