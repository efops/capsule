# Example capsules

Three small applications, each built from a CUE file and its source code.

| Example | What it shows | Runtime |
|---|---|---|
| [`python-web`](python-web/) | A web service that keeps data in a volume | Python 3.12 |
| [`python-job`](python-job/) | A batch job that runs once, with a signed receipt | Python 3.12 |
| [`java-web`](java-web/) | A web service scaled to several replicas behind one port | Java 21 |

All three work with or without root. `test/examples.sh` builds and runs every
one of them.

## Before you start

You need capsule installed (see [docs/INSTALL.md](../docs/INSTALL.md)), `curl`,
and a signing key the host trusts:

```sh
capsule keygen dev
sudo install -m 644 dev.pub /etc/capsule/trust.d/dev.pub
```

Without root, skip the second line and add `-trust dev.pub` to each
`capsule run` below.

The first build of each runtime downloads it into `examples/.cache`: Alpine
Linux (3 MB), Python (50 MB) or the Java JDK (200 MB). Later builds reuse it.

## How an example is put together

Each folder holds the application's source and a `capsule.cue`. The build
file names three things, laid one over the next:

```cue
rootfs: {
	from: "../.cache/alpine.tar.gz"                       // a base system
	add: [{from: "../.cache/python.tar.gz", to: "/opt"}]  // the language runtime
	files: "/app/app.py": source: "app.py"                // your code
}
```

`examples/build.sh` downloads what is needed and runs `capsule build`. The
sealed capsule lands in `examples/out/`.

To change an example, edit its source or `capsule.cue` and build again. A
capsule will not run with anything changed since it was sealed.

## python-web: a service that remembers

```sh
sh examples/build.sh python-web dev.key
sudo capsule run -publish 127.0.0.1:8000:8000 examples/out/pyweb
```

In another terminal:

```sh
curl http://127.0.0.1:8000/
# Hello from Python 3.12.16 in a capsule. Visit 1.
curl http://127.0.0.1:8000/
# Hello from Python 3.12.16 in a capsule. Visit 2.
```

Stop it with Ctrl-C and run it again: the count carries on, because it is
kept in a volume. `sudo capsule volumes` shows the data, and
`sudo capsule volumes -rm pyweb` resets it.

Things to try:

- `sudo capsule ps` while it runs, then `sudo capsule resize -memory 256M <id>`.
- Edit `examples/python-web/app.py`, build again, and run: the visits are still there.
- Edit a file under `examples/out/pyweb/rootfs/` and run without building: it is refused.

## python-job: run once, with a receipt

```sh
sh examples/build.sh python-job dev.key
sudo capsule run -receipt receipt.json examples/out/pyjob
# run 1 at 2026-11-23T11:43:07Z result 5c1a9b4e6f0d2a37
```

The job exits when it is done, and so does `capsule run`. Run it again and it
reports `run 2`: its reports accumulate in a volume.

`receipt.json` is this host's signed statement of which sealed capsule ran,
when, its exit status, and a hash of what it printed. Anyone can check it
with the host's signing key id:

```sh
sudo capsule host                  # the "sign" line is the id
capsule receipt -host <sign id> receipt.json
```

Things to try:

- Add `policy: max_runs: 3` to the `capsule` block in `capsule.cue`: the fourth run is refused.
- Add `policy: approvals: {required: 1, signers: ["<contents of dev.id>"]}`: it will not run until you `capsule approve -key dev.key examples/out/pyjob`.

## java-web: several replicas behind one port

```sh
sh examples/build.sh java-web dev.key
sudo capsule run -publish 127.0.0.1:8080:8080 examples/out/javaweb
```

Give it a few seconds: the JVM compiles the source file as it starts. Then:

```sh
curl http://127.0.0.1:8080/
# Hello from Java 21 in a capsule, replica 3f9c2a10.
curl http://127.0.0.1:8080/
# Hello from Java 21 in a capsule, replica b71e04d5.
```

The manifest's `scale` section keeps between two and four replicas running,
and the published port is shared between them. `sudo capsule ps` lists each
replica.

Things to try:

- `sudo capsule kill <id>` on one replica: requests keep being answered, and it is started again within seconds.
- Put load on it (`while true; do curl -s localhost:8080 >/dev/null; done` in a few terminals) and watch `capsule run` report replicas being added, then removed when you stop.

Two details worth knowing for Java:

- A capsule cannot see the host's memory limit files, so the JVM is told its heap size with `-Xmx`. Keep it comfortably below `limits.memory`.
- Each JVM thread counts towards `limits.pids`, so that limit is set higher than for the Python examples.

## Running an example as a service

```sh
sudo cp -a examples/out/pyweb /var/lib/capsule/apps/pyweb
echo 'CAPSULE_ARGS=-publish 127.0.0.1:8000:8000' | sudo tee /etc/capsule/apps/pyweb.env
sudo systemctl enable --now capsule@pyweb
```

## Using your own application

Copy the closest example and change three things in `capsule.cue`: the
`name`, the `command`, and the `files` (or an `add` entry pointing at a folder
of your code, such as `{from: "build/", to: "/app"}`).

Runtimes must be built for Alpine Linux, which uses the musl C library:
ordinary Linux downloads of Python, Node or Java are built for glibc and will
not start. The two used here are the "musl" builds of
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
and the "alpine-linux" builds of [Eclipse Temurin](https://adoptium.net).
Alternatively, start from a different base: any Linux root filesystem works
as `from`, including one exported from a Debian or Ubuntu system.
