package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// initSpec is what the parent hands to the first process inside the namespaces.
type initSpec struct {
	Rootfs   string // verified copy in the store
	Stage    string
	Address  string // this instance's mesh address, if any
	Volumes  []volumeMount
	Manifest Manifest
}

// volumeMount is a host directory to mount at a path inside the capsule.
type volumeMount struct {
	Source, Path string
	Exec         bool
}

func cmdRun(args []string) error {
	fl := flag.NewFlagSet("run", flag.ExitOnError)
	var trust trustFlag
	fl.Var(&trust, "trust", "extra trusted public key file")
	instance := fl.String("instance", "", "label that tells replicas on one host apart: each gets its own volumes and mesh identity")
	listen := fl.Int("listen", 0, "mesh: host UDP port for this instance's tunnel (0 picks one)")
	cards := fl.String("peers", filepath.Join(configDir(), "peers.d"), "mesh: directory of signed peer cards")
	grants := fl.String("grants", grantsDir(), "cell: directory of signed grants this host presents")
	advertise := fl.String("advertise", "", "mesh: this host's IP, so a self-issued card tells peers where to connect")
	receiptPath := fl.String("receipt", "", "write a signed receipt of this run, including a hash of its output, to this file")
	isReplica := fl.Bool("replica", false, "internal: this run is one replica started by the autoscaler")
	var publish publishFlag
	fl.Var(&publish, "publish", "[addr:]hostport:capsuleport, for a port the manifest lists under publish")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule run [-trust <pub>] [-publish host:capsule] [-receipt <file>] [mesh flags] <dir>")
	}
	if os.Geteuid() != 0 {
		if os.Getenv("CAPSULE_SCOPED") == "" {
			return reexecInScope(args)
		}
		return runInUserns(args)
	}
	rootless := !realRoot()
	running() // clears up after any capsule here whose supervisor was killed, such as this one's predecessor
	// Children are killed if the thread that started them exits, so pin this one.
	runtime.LockOSThread()
	dir := fl.Arg(0)
	store, runDir := hostPaths()

	keys, err := loadTrust(trust)
	if err != nil {
		return err
	}
	sc, err := openCapsule(dir, keys)
	if err != nil {
		appendLog(logEntry{Event: "refused", Detail: dir + ": " + err.Error()})
		return fmt.Errorf("refusing to run: %w", err)
	}
	m := sc.Manifest
	if m.Scale != nil && !*isReplica {
		// A capsule with a scale section runs as a set of replicas, each a run of its own.
		for _, p := range publish {
			if !slices.Contains(m.Publish, p.port) {
				return fmt.Errorf("refusing to run: the manifest does not allow publishing port %d", p.port)
			}
		}
		var pass []string
		for _, t := range trust {
			pass = append(pass, "-trust", t)
		}
		pass = append(pass, "-peers", *cards, "-grants", *grants)
		if *advertise != "" {
			pass = append(pass, "-advertise", *advertise)
		}
		return autoscale(dir, m, pass, publish, keys) // published ports are balanced across the replicas here
	}
	entry := logEntry{Capsule: m.Name, Seal: sc.ID, Rootfs: sc.Seal.Rootfs}
	refuse := func(err error) error {
		e := entry
		e.Event, e.Detail = "refused", err.Error()
		appendLog(e)
		return fmt.Errorf("refusing to run: %w", err)
	}

	now := time.Now()
	if err := checkPolicy(dir, sc, keys, now); err != nil {
		return refuse(err)
	}
	for _, p := range publish {
		if !slices.Contains(m.Publish, p.port) {
			return refuse(fmt.Errorf("the manifest does not allow publishing port %d", p.port))
		}
	}
	for _, stage := range m.Unlock { // settings whose time has come
		if !now.Before(stage.At) {
			if m.Env == nil {
				m.Env = map[string]string{}
			}
			maps.Copy(m.Env, stage.Env)
		}
	}
	storeLock, err := lockStore(store, syscall.LOCK_SH)
	if err != nil {
		return err
	}
	defer storeLock.Close()
	if sc.Seal.Encrypted {
		// The plaintext must never sit on this host's disk. With root it goes
		// into an encrypted store kept on disk and shared by every run of
		// this seal. Without root, or if that cannot be set up, it goes into
		// memory-backed run state and is gone when the run ends.
		sealed := ""
		size := int64(0)
		if info, err := os.Stat(filepath.Join(dir, "rootfs.enc")); err == nil {
			size = info.Size()
		}
		open := openSealedStore
		if rootless {
			open = helperStore // the same store, opened for this user by the helper
		}
		if path, release, err := open(sc.Seal.Rootfs, size); err == nil {
			sealed = path
			defer release()
		} else if !errors.Is(err, errNoHelper) {
			fmt.Fprintln(os.Stderr, "capsule: keeping the decrypted capsule in memory, as the encrypted store is unavailable:", err)
		}
		if sealed != "" {
			store = sealed
		} else {
			suffix := make([]byte, 4)
			rand.Read(suffix)
			store = filepath.Join(runDir, "plain-"+hex.EncodeToString(suffix))
			// Held for as long as this supervisor lives. If it is killed
			// outright, the lock drops and the next capsule command removes
			// the decrypted copy it left in memory.
			if err := os.MkdirAll(runDir, 0o700); err != nil {
				return err
			}
			held, err := os.OpenFile(store+".lock", os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				return err
			}
			defer os.Remove(held.Name())
			defer held.Close()
			if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
				return err
			}
			defer removeTree(store)
			keepOutOfSwap(rootless)
		}
	}
	rootfs, err := importRootfs(dir, sc, store)
	if err != nil {
		return refuse(err)
	}
	if err := countRun(dir, sc, now); err != nil {
		return refuse(err)
	}
	spec := initSpec{Rootfs: rootfs, Manifest: m}

	// Volumes belong to the capsule's name (and instance), not to one seal, so
	// data carries over when a new version is sealed. One running instance
	// holds them at a time.
	if len(m.Volumes) > 0 {
		unit := m.Name
		if *instance != "" {
			unit += "-" + *instance
		}
		home := filepath.Join(dataDir(), "volumes", unit)
		if err := os.MkdirAll(home, 0o700); err != nil {
			return err
		}
		held, err := os.OpenFile(filepath.Join(home, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer held.Close()
		if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return refuse(fmt.Errorf("the volumes of %s are in use by another running instance; give replicas different -instance labels", unit))
		}
		for _, v := range m.Volumes {
			source := filepath.Join(home, v.Name)
			if v.Size != "" {
				var data string
				var closeVolume func()
				if rootless {
					data, closeVolume, err = helperVolume(unit, v.Name, v.Size, v.Encrypt)
					if errors.Is(err, errNoHelper) {
						return refuse(fmt.Errorf("volume %s has a size, which needs root or the capsule helper (see docs/INSTALL.md): a sized volume is its own filesystem", v.Name))
					}
				} else {
					data, closeVolume, err = openImageVolume(source+".img", source, v.Size, v.Encrypt)
				}
				if err != nil {
					return err
				}
				defer closeVolume() // runs after the capsule's cgroup is gone
				source = data
			} else if err := os.MkdirAll(source, 0o755); err != nil {
				return err
			}
			spec.Volumes = append(spec.Volumes, volumeMount{Source: source, Path: v.Path, Exec: v.Exec})
		}
	}

	var net *mesh
	if m.meshed() {
		id, err := newMeshIdentity(m.Name, *instance)
		if err != nil {
			return err
		}
		net = &mesh{id: id, name: m.Name, peers: m.peers(), cards: *cards, trusted: keys, cell: m.Network == "cell", user: rootless}
		for _, n := range m.Needs {
			if n.Port != 0 {
				net.cellNeeds = append(net.cellNeeds, n)
			}
		}
		for _, o := range m.Offers {
			if o.direct() {
				net.cellOffers = append(net.cellOffers, o)
			}
		}
		spec.Address = id.addr.String()
	}

	suffix := make([]byte, 4)
	rand.Read(suffix)
	id := m.Name + "-" + hex.EncodeToString(suffix)

	cg, err := newCgroup(id, m.Limits)
	if err != nil {
		return err
	}
	defer removeCgroup(cg)
	releaseCores, err := assignCores(cg, filepath.Join(runDir, id), m.Latency)
	if err != nil {
		return refuse(err)
	}
	defer releaseCores()
	if m.Scale != nil && m.Scale.MemoryMax != "" {
		// The autoscaler will raise this capsule's memory limit as it fills.
		// A soft limit just below the hard one, in place before the first
		// process starts, makes the kernel slow the capsule down there
		// instead of killing it, which gives the autoscaler time to act.
		if limit, err := parseSizeText(m.Limits.Memory); err == nil {
			os.WriteFile(filepath.Join(cg, "memory.high"), []byte(strconv.FormatInt(limit/100*softLimitPercent, 10)), 0)
		}
	}
	cgDir, err := os.Open(cg)
	if err != nil {
		return err
	}
	defer cgDir.Close()

	spec.Stage = filepath.Join(runDir, id)
	if err := os.MkdirAll(spec.Stage, 0o700); err != nil {
		return err
	}
	defer os.Remove(spec.Stage)
	// Held for as long as this supervisor lives. If it is killed outright,
	// the lock drops and the next ps, kill or prune clears up after it.
	alive, err := os.OpenFile(spec.Stage+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(alive.Name())
	defer alive.Close()
	if err := syscall.Flock(int(alive.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	if err := os.WriteFile(spec.Stage+".label", []byte(m.Name+" "+*instance+"\n"), 0o644); err != nil {
		return err
	}
	defer os.Remove(spec.Stage + ".label")
	// What an exec order needs to give a command the same confinement as the capsule's own program.
	if raw, err := json.Marshal(m); err == nil {
		os.WriteFile(spec.Stage+".manifest", raw, 0o600)
		defer os.Remove(spec.Stage + ".manifest")
	}
	for suffix, target := range map[string]string{".cg": cg, ".rootfs": rootfs} {
		if err := os.Symlink(target, spec.Stage+suffix); err != nil {
			return err
		}
		defer os.Remove(spec.Stage + suffix)
	}
	if m.Network == "cell" {
		// Where the cell's sockets live: the application sees it as /run/cell.
		cellDir := spec.Stage + ".cell"
		if err := os.MkdirAll(cellDir, 0o755); err != nil {
			return err
		}
		defer removeTree(cellDir)
		spec.Volumes = append(spec.Volumes, volumeMount{Source: cellDir, Path: "/run/cell"})
	}
	storeLock.Close() // registered: prune can now see this run's rootfs is in use

	// The child builds its filesystem, then waits on this pipe until its
	// network is ready. Closing it without writing tells the child to give up.
	ready, start, err := os.Pipe()
	if err != nil {
		return err
	}
	defer start.Close()

	specJSON, _ := json.Marshal(spec)
	flags := unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC
	if m.Network != "host" {
		flags |= unix.CLONE_NEWNET
	}
	cmd := exec.Command("/proc/self/exe", "__init")
	cmd.Env = []string{"CAPSULE_SPEC=" + string(specJSON)}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	output := sha256.New()
	if *receiptPath != "" {
		cmd.Stdout = io.MultiWriter(os.Stdout, output)
	}
	cmd.ExtraFiles = []*os.File{ready} // fd 3 in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true, // start directly inside the cgroup, no window outside it
		CgroupFD:    int(cgDir.Fd()),
		Pdeathsig:   syscall.SIGKILL, // no daemon: if this process dies, so does the capsule
	}
	cmd.SysProcAttr.Cloneflags = uintptr(flags)

	// The capsule's first process is PID 1 in its namespace and ignores
	// ordinary signals, so stop it by killing the whole cgroup.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	var stopped atomic.Bool
	go func() {
		stopped.Store(<-sigs == syscall.SIGTERM)
		killCgroup(cg)
	}()

	if err := cmd.Start(); err != nil {
		return err
	}
	ready.Close()
	abort := func(err error) error {
		start.Close()
		cmd.Wait()
		return err
	}
	if m.Network != "host" {
		ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
		if err != nil {
			return abort(err)
		}
		defer ns.Close()
		if net != nil {
			defer pinNetwork(cmd.Process.Pid, spec.Stage+".netns")()
			if err := net.attach(ns, *listen, *advertise); err != nil {
				return abort(fmt.Errorf("mesh: %w", err))
			}
			defer net.close()
			defer net.removeCard()
			go net.watch()
			if m.Network == "cell" {
				receptors := &cell{m: m, ms: net, ns: ns, dir: spec.Stage + ".cell", grants: *grants, trusted: keys}
				if err := receptors.start(); err != nil {
					return abort(fmt.Errorf("cell: %w", err))
				}
			}
		}
		if err := startForwarding(ns, m, publish); err != nil {
			return abort(err)
		}
		if m.Latency != nil && m.Latency.Nic != nil {
			giveBack, err := handOverNic(ns, *m.Latency.Nic)
			if err != nil {
				return abort(fmt.Errorf("latency: %w", err))
			}
			defer giveBack()
		}
	}
	started := entry
	started.Event, started.Detail = "run", id
	if _, err := appendLog(started); err != nil {
		return abort(fmt.Errorf("cannot record the run, so not starting it: %w", err))
	}
	start.Write([]byte{1})
	start.Close()
	// From here this process only waits. Everything it needed to check and
	// start the capsule is garbage now: hand that memory back to the system.
	debug.SetGCPercent(20)
	debug.FreeOSMemory()

	err = cmd.Wait()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	} else if err != nil {
		return err
	}

	finished := entry
	finished.Event, finished.Detail, finished.Exit = "exit", id, &code
	if *receiptPath != "" {
		finished.Output = "sha256:" + hex.EncodeToString(output.Sum(nil))
	}
	finished, err = appendLog(finished)
	if l, lerr := openLedger(); lerr == nil && l != nil {
		// Every run is also a chance to witness the rest of the fleet.
		if _, alerts, werr := witness(l); werr == nil {
			for _, alert := range alerts {
				fmt.Fprintln(os.Stderr, "capsule: ALERT:", alert)
			}
		}
	}
	if err == nil && *receiptPath != "" {
		key, kerr := hostSigner()
		if kerr != nil {
			return kerr
		}
		out, _ := json.MarshalIndent(receipt{Entry: finished, Key: key.pub}, "", "  ")
		err = os.WriteFile(*receiptPath, append(out, '\n'), 0o644)
	}
	if err != nil {
		return err
	}
	if code != 0 && !stopped.Load() { // being asked to stop is not a failure
		return exitError(code)
	}
	return nil
}
