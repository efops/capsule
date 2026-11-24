package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cgroupFS = "/sys/fs/cgroup"

// hostPaths says where this user keeps verified rootfs copies and run state.
func hostPaths() (store, runDir string) {
	store = filepath.Join(dataDir(), "store")
	if dir := os.Getenv("CAPSULE_RUN"); dir != "" {
		return store, dir
	}
	if realRoot() {
		return store, "/run/capsule"
	}
	runDir = os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		runDir = fmt.Sprintf("/tmp/capsule-run-%d", os.Getuid())
	}
	return store, filepath.Join(runDir, "capsule")
}

// reexecInScope restarts `capsule run` inside a systemd user scope, the
// usual way for an unprivileged user to get a cgroup they may manage.
func reexecInScope(args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	env := append(os.Environ(), "CAPSULE_SCOPED=1")
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		// No systemd: carry on in the current cgroup, which works if it has
		// been delegated to this user some other way.
		return syscall.Exec(self, append([]string{self, "run"}, args...), env)
	}
	argv := append([]string{"systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", "Delegate=yes", "--", self, "run"}, args...)
	return syscall.Exec(systemdRun, argv, env)
}

// runInUserns runs the supervisor as root inside a new user namespace owned
// by this user. From there the rootless path is the root path: the
// supervisor can create the capsule's namespaces and enter its network, yet
// holds no privilege over anything the user could not already touch.
func runInUserns(args []string) error {
	// A cgroup cannot both hold processes and hand controllers to its
	// children, so step aside into a leaf before starting anything.
	scope, err := ownCgroup()
	if err != nil {
		return err
	}
	leaf := filepath.Join(scope, "supervisor")
	if err := os.Mkdir(leaf, 0o755); err != nil {
		return fmt.Errorf("no cgroup this user may manage (needs a systemd user session or a delegated cgroup): %w", err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte("0"), 0); err != nil {
		return err
	}
	runtime.LockOSThread() // the child is killed if the thread that started it exits
	cmd := exec.Command("/proc/self/exe", append([]string{"run"}, args...)...)
	cmd.Env = append(os.Environ(), "CAPSULE_USERNS=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("creating a user namespace (see dist/apparmor/capsule if the host restricts them): %w", err)
	}
	go func() {
		for sig := range sigs {
			cmd.Process.Signal(sig)
		}
	}()
	err = cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitError(128 + int(ws.Signal()))
		}
		return exitError(exit.ExitCode())
	}
	return err
}

// keepOutOfSwap stops the kernel writing this supervisor's memory to swap,
// which is where a capsule decrypted into memory is held. Memory is charged
// to whoever first writes it, so the decrypted files belong to this
// process's cgroup, and a swap limit of zero there pins them in RAM. Where
// that cannot be set and the host has swap, it says so: the capsule's
// contents could then reach the disk.
func keepOutOfSwap(rootless bool) {
	pinned := false
	if own, err := ownCgroup(); err == nil && rootless {
		enableControllers(filepath.Dir(own)) // the scope this user was given; this process sits in a leaf of it
		pinned = os.WriteFile(filepath.Join(own, "memory.swap.max"), []byte("0"), 0) == nil
	}
	if pinned {
		return
	}
	if raw, err := os.ReadFile("/proc/swaps"); err == nil && strings.Count(strings.TrimSpace(string(raw)), "\n") > 0 {
		fmt.Fprintln(os.Stderr, "capsule: warning: this host has swap, and the decrypted capsule is held in memory that may be written to it. "+
			"Run with root to keep it in an encrypted store, or use encrypted swap.")
	}
}

func ownCgroup() (string, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	return filepath.Join(cgroupFS, strings.TrimPrefix(strings.TrimSpace(string(raw)), "0::")), nil
}

// newCgroup creates the capsule's cgroup and applies its limits.
func newCgroup(id string, l Limits) (string, error) {
	if _, err := os.Stat(cgroupFS + "/cgroup.controllers"); err != nil {
		return "", errors.New("cgroup v2 is not mounted at " + cgroupFS)
	}
	var parent, cg string
	if realRoot() {
		parent = cgroupFS + "/capsule"
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return "", err
		}
		enableControllers(cgroupFS)
		cg = filepath.Join(parent, id)
	} else {
		// runInUserns left us in the "supervisor" leaf of the delegated scope.
		own, err := ownCgroup()
		if err != nil {
			return "", err
		}
		parent = filepath.Dir(own)
		cg = filepath.Join(parent, id) // several capsules can share one scope when an autoscaler runs them
	}
	enableControllers(parent)
	if err := os.Mkdir(cg, 0o755); err != nil {
		return "", err
	}

	if err := applyLimits(cg, l); err != nil {
		os.Remove(cg)
		return "", err
	}
	return cg, nil
}

// applyLimits writes the limits that are set; it works on a running capsule too.
func applyLimits(cg string, l Limits) error {
	set := map[string]string{}
	if l.Memory != "" {
		set["memory.max"] = l.Memory
		set["memory.swap.max"] = "0"
	}
	if l.CPUs > 0 {
		set["cpu.max"] = fmt.Sprintf("%d 100000", int(l.CPUs*100000))
	}
	if l.Pids > 0 {
		set["pids.max"] = strconv.Itoa(l.Pids)
	}
	for file, value := range set {
		err := os.WriteFile(filepath.Join(cg, file), []byte(value), 0)
		if err != nil && file != "memory.swap.max" { // absent when the host has no swap accounting
			controller, _, _ := strings.Cut(file, ".")
			return fmt.Errorf("cannot set %s=%s (is the %s controller available to this user?): %w", file, value, controller, err)
		}
	}
	return nil
}

// enableControllers turns on what it can; a missing one surfaces when its limit is set.
func enableControllers(cg string) {
	for _, c := range []string{"+cpu", "+memory", "+pids"} {
		os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte(c), 0)
	}
}

func killCgroup(cg string) error {
	return os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0)
}

func removeCgroup(cg string) {
	killCgroup(cg)
	for i := 0; i < 40; i++ { // rmdir fails with EBUSY until the last process is reaped
		if err := os.Remove(cg); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "capsule: could not remove", cg)
}

// instance is one running capsule. There is no daemon: each run leaves
// symlinks to its cgroup and rootfs, and the kernel's cgroup is the truth.
type instance struct{ cgroup, rootfs, name, label, stage string }

func running() map[string]instance {
	_, runDir := hostPaths()
	// Decrypted capsules held in memory by supervisors that are gone.
	orphans, _ := filepath.Glob(filepath.Join(runDir, "plain-*.lock"))
	for _, lock := range orphans {
		if !supervised(lock) {
			removeTree(strings.TrimSuffix(lock, ".lock"))
			os.Remove(lock)
		}
	}
	links, _ := filepath.Glob(filepath.Join(runDir, "*.cg"))
	out := map[string]instance{}
	for _, link := range links {
		cg, err := os.Readlink(link)
		if err != nil {
			continue
		}
		base := strings.TrimSuffix(link, ".cg")
		if !supervised(base + ".lock") { // its supervisor is gone: stop what is left and clear up
			removeCgroup(cg)
			releaseTunnel(base + ".netns")
			removeTree(base + ".cell")
			for _, suffix := range []string{".cg", ".rootfs", ".lock", ".label", ".manifest", ""} {
				os.Remove(base + suffix)
			}
			continue
		}
		rootfs, _ := os.Readlink(base + ".rootfs")
		name, label, _ := strings.Cut(firstLine(base+".label"), " ")
		out[filepath.Base(base)] = instance{cg, rootfs, name, label, base}
	}
	return out
}

func firstLine(path string) string {
	raw, _ := os.ReadFile(path)
	line, _, _ := strings.Cut(string(raw), "\n")
	return line
}

// supervised reports whether a supervisor still holds this run's lock.
func supervised(lock string) bool {
	f, err := os.Open(lock)
	if err != nil {
		return false
	}
	defer f.Close()
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil
}

func cmdPs() error { return listRunning(os.Stdout) }

func listRunning(w io.Writer) error {
	fmt.Fprintf(w, "%-32s %6s %12s %12s %8s\n", "ID", "PIDS", "MEMORY", "MEM LIMIT", "CPUS")
	for id, inst := range running() {
		read := func(file string) string {
			b, _ := os.ReadFile(filepath.Join(inst.cgroup, file))
			return strings.TrimSpace(string(b))
		}
		mb := func(s string) string {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return "-"
			}
			return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
		}
		cpus := "-"
		if quota, period, ok := strings.Cut(read("cpu.max"), " "); ok && quota != "max" {
			q, _ := strconv.ParseFloat(quota, 64)
			p, _ := strconv.ParseFloat(period, 64)
			cpus = strconv.FormatFloat(q/p, 'g', 3, 64)
		}
		fmt.Fprintf(w, "%-32s %6s %12s %12s %8s\n", id, read("pids.current"), mb(read("memory.current")), mb(read("memory.max")), cpus)
	}
	return nil
}

func find(id string) (instance, error) {
	inst, ok := running()[id]
	if !ok {
		return inst, fmt.Errorf("no running capsule %s", id)
	}
	return inst, nil
}

func cmdKill(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: capsule kill <id>")
	}
	inst, err := find(args[0])
	if err != nil {
		return err
	}
	return killCgroup(inst.cgroup)
}

// cmdResize changes a running capsule's limits in place. Limits protect the
// host from the capsule, so they are the host operator's to change.
func cmdResize(args []string) error {
	fl := flag.NewFlagSet("resize", flag.ExitOnError)
	var l Limits
	fl.StringVar(&l.Memory, "memory", "", "new memory limit, e.g. 512M")
	fl.Float64Var(&l.CPUs, "cpus", 0, "new CPU limit in cores")
	fl.IntVar(&l.Pids, "pids", 0, "new process limit")
	fl.Parse(args)
	if fl.NArg() != 1 || l == (Limits{}) {
		return errors.New("usage: capsule resize [-memory 512M] [-cpus 2] [-pids 256] <id>")
	}
	inst, err := find(fl.Arg(0))
	if err != nil {
		return err
	}
	return applyLimits(inst.cgroup, l)
}
