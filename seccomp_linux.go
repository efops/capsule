package main

import (
	"fmt"
	"runtime"
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"
)

// neverAllowed are calls that reach outside the sandbox. A manifest's allow
// list can only narrow the default profile, so these stay blocked even if
// listed. clone3 is here because its flags sit behind a pointer the filter
// cannot read; libc falls back to clone, whose namespace flags are checked.
var neverAllowed = []string{
	"mount", "umount", "umount2", "pivot_root", "chroot",
	"move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "fspick", "mount_setattr",
	"setns", "unshare", "clone3", "open_by_handle_at",
	"ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
	"kexec_load", "kexec_file_load", "reboot",
	"init_module", "finit_module", "delete_module",
	"bpf", "perf_event_open", "userfaultfd",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"swapon", "swapoff", "acct", "quotactl", "quotactl_fd", "syslog", "vhangup",
	"iopl", "ioperm", "sethostname", "setdomainname",
	"settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
	"add_key", "request_key", "keyctl",
}

// needed by the runtime itself between installing the filter and the command starting.
var alwaysAllowed = []string{"execve", "exit_group"}

const cloneNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWTIME

// allowedSyscalls returns the sorted syscall numbers the capsule may make on
// this architecture: the manifest's list, or every syscall this build knows
// about, minus neverAllowed. Names another architecture has and this one
// lacks are skipped, so one manifest works on both.
func allowedSyscalls(listed []string) ([]int, error) {
	column := map[string]int{"amd64": 0, "arm64": 1}
	col, ok := column[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("no syscall table for %s", runtime.GOARCH)
	}
	allowed := map[int]bool{}
	add := func(name string) {
		if nr := syscallTable[name][col]; nr >= 0 {
			allowed[nr] = true
		}
	}
	if listed == nil {
		for name := range syscallTable {
			add(name)
		}
	} else {
		for _, name := range append(listed, alwaysAllowed...) {
			add(name)
		}
	}
	for _, name := range neverAllowed {
		if nrs, ok := syscallTable[name]; ok {
			delete(allowed, nrs[col])
		}
	}
	nrs := make([]int, 0, len(allowed))
	for nr := range allowed {
		nrs = append(nrs, nr)
	}
	sort.Ints(nrs)
	return nrs, nil
}

// seccompFilter builds an allow-list filter. Anything not allowed, including
// syscalls newer than this build, fails with ENOSYS as if the kernel lacked it.
//
// With unixOnly, the only sockets that can be created are local ones: a
// cell that is given socket files for everything has no use for any other.
func seccompFilter(allowed []int, unixOnly bool) ([]unix.SockFilter, error) {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, fmt.Errorf("no seccomp filter for %s", runtime.GOARCH)
	}
	const (
		load = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jgt  = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K

		offNr, offArch, offArg0 = 0, 4, 16 // struct seccomp_data, low word of args[0]
	)
	deny := unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)}
	f := []unix.SockFilter{
		{Code: load, K: offArch},
		{Code: jeq, K: arch, Jt: 1},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		// clone may not create namespaces
		{Code: load, K: offNr},
		{Code: jeq, K: unix.SYS_CLONE, Jf: 3},
		{Code: load, K: offArg0},
		{Code: jset, K: cloneNamespaceFlags, Jf: 1},
		deny,
		{Code: load, K: offNr},
	}
	if unixOnly {
		f = append(f,
			unix.SockFilter{Code: jeq, K: unix.SYS_SOCKET, Jf: 3},
			unix.SockFilter{Code: load, K: offArg0},
			unix.SockFilter{Code: jeq, K: unix.AF_UNIX, Jt: 1},
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)},
			unix.SockFilter{Code: load, K: offNr},
		)
	}
	// One block per run of consecutive allowed numbers. On amd64 this also
	// rejects the x32 ABI, whose numbers start at 0x40000000.
	for i := 0; i < len(allowed); {
		j := i
		for j+1 < len(allowed) && allowed[j+1] == allowed[j]+1 {
			j++
		}
		f = append(f,
			unix.SockFilter{Code: jge, K: uint32(allowed[i]), Jf: 2}, // below the run: try the next
			unix.SockFilter{Code: jgt, K: uint32(allowed[j]), Jt: 1}, // above the run: try the next
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		)
		i = j + 1
	}
	return append(f, deny), nil
}

func installSeccomp(listed []string, unixOnly bool) error {
	allowed, err := allowedSyscalls(listed)
	if err != nil {
		return err
	}
	filter, err := seccompFilter(allowed, unixOnly)
	if err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	return nil
}
