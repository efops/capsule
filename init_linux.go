package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// initCapsule runs as PID 1 inside the new namespaces. It builds the root
// filesystem, gives up every privilege, then execs the capsule's command.
func initCapsule() error {
	runtime.LockOSThread() // capabilities and seccomp are per-thread; exec from this one
	var spec initSpec
	if err := json.Unmarshal([]byte(os.Getenv("CAPSULE_SPEC")), &spec); err != nil {
		return errors.New("this command is internal; use capsule run")
	}
	m := spec.Manifest

	if err := buildRoot(spec); err != nil {
		return err
	}
	if m.Network != "host" {
		if err := loopbackUp(); err != nil {
			return fmt.Errorf("loopback: %w", err)
		}
	}
	// The parent writes one byte once the network is ready, or closes the
	// pipe to call the run off.
	ready := os.NewFile(3, "ready")
	if n, _ := ready.Read(make([]byte, 1)); n != 1 {
		os.Exit(1)
	}
	ready.Close()

	hostname := m.Hostname
	if hostname == "" {
		hostname = m.Name
	}
	if err := unix.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("hostname: %w", err)
	}

	env := map[string]string{"PATH": defaultPath, "HOME": "/"}
	for k, v := range m.Env {
		env[k] = v
	}
	var environ []string
	for k, v := range env {
		environ = append(environ, k+"="+v)
	}
	bin, err := lookPath(m.Command[0], env["PATH"])
	if err != nil {
		return err
	}

	if m.Latency != nil && m.Latency.MemoryLock {
		// The program has no capabilities, so this limit is what lets it pin its memory.
		unlimited := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unlimited); err != nil {
			return fmt.Errorf("latency: memory_lock needs root: %w", err)
		}
	}
	if err := dropPrivileges(m.Syscalls, m.socketsOnly()); err != nil {
		return err
	}
	return fmt.Errorf("exec %s: %w", bin, unix.Exec(bin, m.Command, environ))
}

func mount(src, dst, fstype string, flags uintptr, data string) error {
	if err := unix.Mount(src, dst, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", src, dst, err)
	}
	return nil
}

// buildRoot layers a throwaway tmpfs over the sealed rootfs (which is never
// written to), adds /proc, /dev and /tmp, pivots into it and makes it read-only.
func buildRoot(spec initSpec) error {
	// Keep every mount below private to this namespace.
	if err := mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		if os.Getuid() == 0 && errors.Is(err, unix.EACCES) {
			err = fmt.Errorf("%w (the host restricts user namespaces; see dist/apparmor/capsule)", err)
		}
		return err
	}
	if err := mount("tmpfs", spec.Stage, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700"); err != nil {
		return err
	}
	upper, work, root := spec.Stage+"/upper", spec.Stage+"/work", spec.Stage+"/root"
	for _, d := range []string{upper, work, root} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	opts := "lowerdir=" + spec.Rootfs + ",upperdir=" + upper + ",workdir=" + work
	if err := mount("overlay", root, "overlay", 0, opts); err != nil {
		return err
	}
	// The rootfs is content we do not control, and we are still outside it
	// with full privileges. A path such as root+"/etc/hosts" would follow a
	// symlink planted in the rootfs out to the host. So nothing below builds
	// a path into the rootfs: every location is opened through os.Root, which
	// refuses to leave it, and then addressed by its open file descriptor.
	inside, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer inside.Close()
	var held []*os.File
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	// at returns a path to a directory inside the rootfs, creating it if needed.
	// After mounting onto it, call at again to reach what was mounted.
	at := func(rel string) (string, error) {
		if err := inside.MkdirAll(rel, 0o755); err != nil {
			return "", fmt.Errorf("rootfs /%s cannot be used as a directory: %w", rel, err)
		}
		f, err := inside.Open(rel)
		if err != nil {
			return "", fmt.Errorf("rootfs /%s: %w", rel, err)
		}
		held = append(held, f)
		return fmt.Sprintf("/proc/self/fd/%d", f.Fd()), nil
	}

	if m := spec.Manifest; m.meshed() || len(m.Egress) > 0 {
		hosts := "127.0.0.1 localhost\n::1 localhost\n"
		if m.Network == "mesh" {
			// A peer's name resolves to its service address, never to one machine.
			self := true
			for _, p := range m.Mesh.Peers {
				hosts += serviceAddr(p.Name).String() + " " + p.Name + "\n"
				self = self && p.Name != m.Name
			}
			if self {
				hosts += spec.Address + " " + m.Name + "\n"
			}
		}
		for _, n := range m.Needs {
			if n.Port != 0 { // a need's name resolves to the cell that offers it, never to one machine
				hosts += serviceAddr(n.From).String() + " " + n.Name + "\n"
			}
		}
		for host, addr := range egressAddrs(m) {
			hosts += addr.String() + " " + host + "\n"
		}
		if err := inside.MkdirAll("etc", 0o755); err != nil {
			return fmt.Errorf("rootfs /etc cannot be used as a directory: %w", err)
		}
		inside.Remove("etc/hosts") // replace it, never write through whatever the rootfs put there
		f, err := inside.OpenFile("etc/hosts", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("rootfs /etc/hosts: %w", err)
		}
		_, err = f.WriteString(hosts)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}

	// Persistent volumes: host directories that outlive the capsule, mounted
	// so that nothing in them can be a device or grant privilege.
	for _, v := range spec.Volumes {
		target, err := at(strings.TrimPrefix(v.Path, "/"))
		if err != nil {
			return err
		}
		if err := mount(v.Source, target, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if target, err = at(strings.TrimPrefix(v.Path, "/")); err != nil {
			return err
		}
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV)
		if !v.Exec {
			flags |= unix.MS_NOEXEC
		}
		// Without root, a remount must keep the access-time setting the host mounted the directory with.
		var st unix.Statfs_t
		if err := unix.Statfs(target, &st); err == nil {
			for have, keep := range map[int64]uintptr{unix.ST_NOATIME: unix.MS_NOATIME, unix.ST_NODIRATIME: unix.MS_NODIRATIME, unix.ST_RELATIME: unix.MS_RELATIME, unix.ST_RDONLY: unix.MS_RDONLY} {
				if int64(st.Flags)&have != 0 {
					flags |= keep
				}
			}
		}
		if err := mount("", target, "", flags, ""); err != nil {
			return err
		}
	}

	proc, err := at("proc")
	if err != nil {
		return err
	}
	if err := mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	if proc, err = at("proc"); err != nil {
		return err
	}
	dev, err := at("dev")
	if err != nil {
		return err
	}
	if err := mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID, "mode=0755,size=64k"); err != nil {
		return err
	}
	if dev, err = at("dev"); err != nil {
		return err
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		target := dev + "/" + name
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			return err
		}
		if err := mount("/dev/"+name, target, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	for link, target := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(target, dev+"/"+link); err != nil {
			return err
		}
	}
	if l := spec.Manifest.Latency; l != nil {
		for _, d := range l.Devices {
			// The device file itself, as the host has it: same device, same permissions.
			var st unix.Stat_t
			if err := unix.Stat(d, &st); err != nil || (st.Mode&unix.S_IFMT != unix.S_IFCHR && st.Mode&unix.S_IFMT != unix.S_IFBLK) {
				return fmt.Errorf("latency: %s is not a device on this host", d)
			}
			target := dev + strings.TrimPrefix(d, "/dev")
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, nil, 0o644); err != nil {
				return err
			}
			if err := mount(d, target, "", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("latency: %w", err)
			}
		}
	}
	if l := spec.Manifest.Latency; l != nil && l.Hugepages {
		if err := os.Mkdir(dev+"/hugepages", 0o755); err != nil {
			return err
		}
		if err := mount("hugetlbfs", dev+"/hugepages", "hugetlbfs", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return fmt.Errorf("latency: hugepages (needs root, and huge pages set aside on the host): %w", err)
		}
	}
	tmp, err := at("tmp")
	if err != nil {
		return err
	}
	if err := mount("tmpfs", tmp, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m"); err != nil {
		return err
	}

	// The capsule runs as uid 0 without capabilities, and plain file
	// permissions would still let it write these host-wide controls.
	if _, err := os.Stat(proc + "/sys"); err != nil {
		return fmt.Errorf("the capsule's /proc is not in place, so it cannot be locked down: %w", err)
	}
	for _, p := range []string{"sys", "sysrq-trigger", "irq", "bus", "fs"} {
		p = proc + "/" + p
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
		if err := mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return err
		}
	}
	for _, p := range []string{"kcore", "keys", "timer_list", "kallsyms"} {
		p = proc + "/" + p
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}

	if err := unix.Chdir(root); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil { // drop the host filesystem
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return mount("", "/", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func lookPath(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in capsule", name)
}

// dropPrivileges is one-way: no new privileges, an empty capability set, and
// the syscall allow list. Nothing after this point can undo it.
func dropPrivileges(syscalls []string, unixOnly bool) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	for c := uintptr(0); c < 64; c++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0)
		if err == unix.EINVAL { // past the last capability this kernel knows
			break
		}
		if err != nil {
			return fmt.Errorf("drop capability %d: %w", c, err)
		}
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var none [2]unix.CapUserData
	if err := unix.Capset(&hdr, &none[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return installSeccomp(syscalls, unixOnly)
}
