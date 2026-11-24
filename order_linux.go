package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// carryOut performs one order that has passed every check. Each action is a
// fixed piece of code here: nothing in an order is ever handed to a shell.
func carryOut(o order, left time.Duration) (string, error) {
	switch o.Action {
	case "ps":
		var out bytes.Buffer
		err := listRunning(&out)
		return out.String(), err
	case "log":
		n := 20
		if v, set := o.Params["lines"]; set {
			n, _ = strconv.Atoi(v)
		}
		return tailLog(n)
	case "fetch":
		trusted, err := loadTrust(nil)
		if err != nil {
			return "", err
		}
		return fetchRelease(o.Capsule, "", trusted)
	case "revoke":
		return "this host will not run " + o.Params["seal"] + " again", revokeHere(o.Params["seal"])
	case "resize":
		limits, err := orderLimits(o.Params)
		if err != nil {
			return "", err
		}
		n := 0
		for _, inst := range running() {
			if inst.name == o.Capsule {
				if err := applyLimits(inst.cgroup, limits); err != nil {
					return "", err
				}
				n++
			}
		}
		if n == 0 {
			return "", fmt.Errorf("%s is not running here", o.Capsule)
		}
		return fmt.Sprintf("resized %d instance(s) of %s", n, o.Capsule), nil
	case "run":
		return startCapsule(o.Capsule)
	case "stop":
		return stopCapsule(o.Capsule)
	case "exec":
		limit := orderExecLimit
		if v, set := o.Params["timeout"]; set {
			limit, _ = time.ParseDuration(v)
		}
		return execIn(o.Capsule, o.Params["instance"], o.Command, min(limit, left))
	}
	return "", fmt.Errorf("%q is not an action", o.Action)
}

// tailLog returns the last n entries of the host's record.
func tailLog(n int) (string, error) {
	raw, err := os.ReadFile(logPath())
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	return strings.Join(lines[max(len(lines)-n, 0):], "\n"), nil
}

// ---- run and stop ----

// A capsule lives only as long as its supervisor, and an order must not
// leave anything of capsule's own running to keep it alive. So a started
// capsule is handed to systemd as a service: the unit the installer provides
// when there is one, otherwise a transient unit made on the spot.

const unitTemplate = "/etc/systemd/system/capsule@.service"

func systemctl(args ...string) ([]byte, error) {
	if !realRoot() {
		args = append([]string{"--user"}, args...)
	}
	return exec.Command("systemctl", args...).CombinedOutput()
}

func capsuleUnits(name string) []string {
	units := []string{"capsule-run-" + name + ".service"}
	// The installed unit runs what is in the host's usual places, so it only stands in when those are in use.
	if _, err := os.Stat(unitTemplate); err == nil && realRoot() && dataDir() == "/var/lib/capsule" && configDir() == "/etc/capsule" {
		units = append([]string{"capsule@" + name + ".service"}, units...)
	}
	return units
}

func instancesNamed(name string) (ids []string) {
	for id, inst := range running() {
		if inst.name == name {
			ids = append(ids, id)
		}
	}
	return ids
}

func startCapsule(name string) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", errors.New("run orders need systemd on the host, to keep the capsule running after the order is done")
	}
	if ids := instancesNamed(name); len(ids) > 0 {
		return name + " is already running: " + strings.Join(ids, " "), nil
	}
	trusted, err := loadTrust(nil)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(dataDir(), "apps", name)
	note := ""
	if _, _, err := blobs(); err == nil {
		// Pick up the current release first. A host that already has the
		// capsule can still start it while the ledger is out of reach.
		if note, err = fetchRelease(name, "", trusted); err != nil {
			if _, serr := readSeal(dir); serr != nil {
				return "", err
			}
			note = "starting the copy already here; could not fetch: " + err.Error()
		}
	}
	if err := verifyCapsule(dir, trusted); err != nil {
		return note, fmt.Errorf("refusing to run: %w", err)
	}
	began := time.Now().Add(-time.Second)
	units := capsuleUnits(name)
	unit := units[0]
	if strings.HasPrefix(unit, "capsule@") {
		if out, err := systemctl("start", unit); err != nil {
			return note, fmt.Errorf("starting %s: %s", unit, strings.TrimSpace(string(out)))
		}
	} else {
		self, err := os.Executable()
		if err != nil {
			return note, err
		}
		systemctl("reset-failed", unit)
		args := []string{"--unit", unit, "--collect", "--quiet",
			"-p", "Restart=on-failure", "-p", "RestartSec=2", "-p", "KillMode=process", "-p", "TimeoutStopSec=15"}
		if !realRoot() {
			// Without root the supervisor needs a cgroup of its own to manage; the service's is handed to it.
			args = append([]string{"--user"}, append(args, "-p", "Delegate=yes", "--setenv", "CAPSULE_SCOPED=1")...)
		}
		for _, v := range []string{"CAPSULE_CONFIG", "CAPSULE_DATA", "CAPSULE_RUN"} {
			if os.Getenv(v) != "" {
				args = append(args, "--setenv", v+"="+os.Getenv(v))
			}
		}
		args = append(args, "--", self, "run", dir)
		if out, err := exec.Command("systemd-run", args...).CombinedOutput(); err != nil {
			return note, fmt.Errorf("starting %s: %s", unit, strings.TrimSpace(string(out)))
		}
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if ids := instancesNamed(name); len(ids) > 0 {
			return strings.TrimSpace(note + "\nstarted " + strings.Join(ids, " ")), nil
		}
		if why := refusedSince(name, began); why != "" {
			systemctl("stop", unit) // do not leave it trying again every two seconds
			return note, errors.New(why)
		}
	}
	return note, fmt.Errorf("%s was started as %s but is not running yet; look at the host's record with a log order", name, unit)
}

// refusedSince finds why the host most recently refused to run a capsule, if it has since t.
func refusedSince(name string, t time.Time) string {
	text, _ := tailLog(20)
	why := ""
	for _, line := range strings.Split(text, "\n") {
		var e logEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.Event != "refused" {
			continue
		}
		when, _ := time.Parse(time.RFC3339, e.Time)
		if !when.Before(t.Truncate(time.Second)) && (e.Capsule == name || strings.Contains(e.Detail, "/"+name+":")) {
			why = "refused to run: " + e.Detail
		}
	}
	return why
}

func stopCapsule(name string) (string, error) {
	stopped := false
	if _, err := exec.LookPath("systemctl"); err == nil {
		for _, unit := range capsuleUnits(name) {
			if out, _ := systemctl("is-active", unit); strings.TrimSpace(string(out)) != "inactive" && strings.TrimSpace(string(out)) != "failed" && strings.TrimSpace(string(out)) != "unknown" {
				if out, err := systemctl("stop", unit); err != nil {
					return "", fmt.Errorf("stopping %s: %s", unit, strings.TrimSpace(string(out)))
				}
				stopped = true
			}
		}
	}
	// Whatever was started by hand, outside any unit.
	for _, inst := range running() {
		if inst.name == name {
			if err := killCgroup(inst.cgroup); err != nil {
				return "", err
			}
			stopped = true
		}
	}
	if !stopped {
		return name + " was not running", nil
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if len(instancesNamed(name)) == 0 {
			return "stopped " + name, nil
		}
	}
	return "", fmt.Errorf("%s is still running", name)
}

// ---- exec ----

// enterSpec is what a command joining a running capsule is told.
type enterSpec struct {
	Command  []string
	Env      []string
	Syscalls []string
	UnixOnly bool
}

// limitedBuffer keeps the first part of what is written to it and counts the rest as written.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// execIn runs a command inside a running capsule and returns what it
// printed. The command is in the capsule's namespaces and its cgroup from its
// first instruction, and gives up every privilege the same way the capsule's
// own program did: no capabilities, the same system call filter, the same
// read-only root. It can do nothing the capsule could not.
func execIn(name, label string, command []string, limit time.Duration) (string, error) {
	var inst instance
	found := 0
	for _, i := range running() {
		if i.name == name && (label == "" || i.label == label) {
			inst = i
			found++
		}
	}
	switch {
	case found == 0:
		return "", fmt.Errorf("%s is not running here", name)
	case found > 1 && label == "":
		return "", fmt.Errorf("%d instances of %s are running here; name one with instance=<label>", found, name)
	}
	var m Manifest
	raw, err := os.ReadFile(inst.stage + ".manifest")
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return "", errors.New("this capsule was started by an older capsule and cannot be entered; restart it")
	}
	pid, err := firstProcess(inst.cgroup)
	if err != nil {
		return "", err
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return "", errors.New("exec orders need nsenter (util-linux) on the host")
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	mnt, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return "", err
	}
	defer mnt.Close()
	cg, err := os.Open(inst.cgroup)
	if err != nil {
		return "", err
	}
	defer cg.Close()

	spec := enterSpec{Command: command, Syscalls: m.Syscalls, UnixOnly: m.socketsOnly()}
	env := map[string]string{"PATH": defaultPath, "HOME": "/"}
	for k, v := range m.Env {
		env[k] = v
	}
	for k, v := range env {
		spec.Env = append(spec.Env, k+"="+v)
	}
	specJSON, _ := json.Marshal(spec)

	args := []string{"-t", strconv.Itoa(pid)}
	if !realRoot() {
		// The capsule belongs to a user namespace this user owns. Keeping
		// this user's ids is what makes them root inside it and nowhere else.
		args = append(args, "-U", "--preserve-credentials")
	}
	// Every namespace but the mount one, which the command joins itself: it
	// has to find this program on the host first.
	args = append(args, "-n", "-p", "-i", "-u", "--", self, "__enter")
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	runtime.LockOSThread() // the child is killed if the thread that started it exits
	defer runtime.UnlockOSThread()
	cmd := exec.CommandContext(ctx, nsenter, args...)
	cmd.Env = []string{"CAPSULE_ENTER=" + string(specJSON)}
	out := &limitedBuffer{max: orderOutputMax}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.ExtraFiles = []*os.File{mnt} // fd 3
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true, // inside the capsule's limits from the start, and gone with it
		CgroupFD:    int(cg.Fd()),
		Setpgid:     true,
		Pdeathsig:   syscall.SIGKILL,
	}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EACCES) && !realRoot() {
			return "", errors.New("cannot join the capsule's cgroup from here: run `capsule orders` from this user's systemd session, as the installed timer does")
		}
		return "", err
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		err = fmt.Errorf("the command was stopped after %s", limit.Round(time.Second))
	}
	return out.String(), err
}

// firstProcess finds the capsule's own program: the process that is number 1 in its namespace.
func firstProcess(cgroup string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil {
		return 0, err
	}
	for _, field := range strings.Fields(string(raw)) {
		status, _ := os.ReadFile("/proc/" + field + "/status")
		for _, line := range strings.Split(string(status), "\n") {
			if rest, ok := strings.CutPrefix(line, "NSpid:"); ok {
				ids := strings.Fields(rest)
				if len(ids) > 1 && ids[len(ids)-1] == "1" {
					return strconv.Atoi(field)
				}
			}
		}
	}
	return 0, errors.New("the capsule's first process is gone")
}

// enterCapsule is the far side of execIn. It arrives already in the
// capsule's cgroup and in all of its namespaces except the mount namespace,
// steps into that, sheds every privilege and becomes the command.
func enterCapsule() error {
	runtime.LockOSThread()
	var spec enterSpec
	if err := json.Unmarshal([]byte(os.Getenv("CAPSULE_ENTER")), &spec); err != nil || len(spec.Command) == 0 {
		return errors.New("this command is internal; use an exec order")
	}
	// A thread may change mount namespace only if it shares its view of the
	// filesystem with no other thread.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare: %w", err)
	}
	if err := unix.Setns(3, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("joining the capsule's filesystem: %w", err)
	}
	unix.Close(3)
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	path := defaultPath
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	bin, err := lookPath(spec.Command[0], path)
	if err != nil {
		return err
	}
	if err := dropPrivileges(spec.Syscalls, spec.UnixOnly); err != nil {
		return err
	}
	return fmt.Errorf("exec %s: %w", bin, unix.Exec(bin, spec.Command, spec.Env))
}
