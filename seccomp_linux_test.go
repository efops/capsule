package main

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// runFilter interprets the classic-BPF program the way the kernel would for
// one system call, and returns the action it ends on.
func runFilter(t *testing.T, prog []unix.SockFilter, arch uint32, nr int, arg0 uint32) uint32 {
	t.Helper()
	data := map[uint32]uint32{0: uint32(nr), 4: arch, 16: arg0}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		jump := func(taken bool) {
			if taken {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		}
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = data[ins.K]
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			jump(acc == ins.K)
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			jump(acc >= ins.K)
		case unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K:
			jump(acc > ins.K)
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			jump(acc&ins.K != 0)
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			t.Fatalf("filter uses an instruction this test does not model: %#x", ins.Code)
		}
	}
	t.Fatal("filter ran off its end")
	return 0
}

func TestSeccompFilter(t *testing.T) {
	arch := map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}[runtime.GOARCH]
	col := map[string]int{"amd64": 0, "arm64": 1}[runtime.GOARCH]
	const allow, refuse = unix.SECCOMP_RET_ALLOW, unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	build := func(listed []string) []unix.SockFilter {
		allowed, err := allowedSyscalls(listed)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := seccompFilter(allowed, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(prog) > 4096 {
			t.Fatalf("filter has %d instructions; the kernel accepts 4096", len(prog))
		}
		return prog
	}

	// The default profile: every known call is allowed unless it is on the never list.
	prog := build(nil)
	never := map[string]bool{}
	for _, name := range neverAllowed {
		never[name] = true
	}
	for name, nrs := range syscallTable {
		nr := nrs[col]
		if nr < 0 {
			continue
		}
		want := uint32(allow)
		if never[name] {
			want = refuse
		}
		if got := runFilter(t, prog, arch, nr, 0); got != want {
			t.Errorf("default profile: %s (%d) -> %#x, want %#x", name, nr, got, want)
		}
	}
	for _, nr := range []int{9999, 0x40000000, 0x40000000 + 59, 1 << 30, -1} { // unknown, and the x32 ABI
		if got := runFilter(t, prog, arch, nr, 0); got != refuse {
			t.Errorf("default profile: unknown syscall %d -> %#x, want refusal", nr, got)
		}
	}
	if got := runFilter(t, prog, 0x12345678, unix.SYS_READ, 0); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Errorf("foreign architecture -> %#x, want the process killed", got)
	}
	if got := runFilter(t, prog, arch, unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_THREAD); got != allow {
		t.Errorf("clone for a thread -> %#x, want allowed", got)
	}
	for _, flag := range []uint32{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWNET, unix.CLONE_NEWPID, unix.CLONE_NEWCGROUP} {
		if got := runFilter(t, prog, arch, unix.SYS_CLONE, unix.CLONE_VM|flag); got != refuse {
			t.Errorf("clone creating a namespace (%#x) -> %#x, want refusal", flag, got)
		}
	}

	// A cell given only socket files: local sockets and nothing else, with the rest of the profile unchanged.
	allowed, _ := allowedSyscalls(nil)
	local, err := seccompFilter(allowed, true)
	if err != nil {
		t.Fatal(err)
	}
	for family, want := range map[uint32]uint32{
		unix.AF_UNIX: allow, unix.AF_INET: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT),
		unix.AF_INET6: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT), unix.AF_NETLINK: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT),
		unix.AF_PACKET: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT),
	} {
		if got := runFilter(t, local, arch, unix.SYS_SOCKET, family); got != want {
			t.Errorf("sockets-only profile: socket family %d -> %#x, want %#x", family, got, want)
		}
	}
	for name, want := range map[string]uint32{"read": allow, "connect": allow, "mount": refuse, "bpf": refuse} {
		if got := runFilter(t, local, arch, syscallTable[name][col], 0); got != want {
			t.Errorf("sockets-only profile: %s -> %#x, want %#x", name, got, want)
		}
	}
	if got := runFilter(t, local, arch, unix.SYS_CLONE, unix.CLONE_NEWNET); got != refuse {
		t.Errorf("sockets-only profile: clone creating a namespace -> %#x, want refusal", got)
	}

	// A manifest's list only narrows: what it leaves out is refused, and it cannot add back a never-allowed call.
	prog = build([]string{"read", "write", "mount", "clone3", "bpf"})
	for name, want := range map[string]uint32{
		"read": allow, "write": allow, "execve": allow, "exit_group": allow,
		"mount": refuse, "clone3": refuse, "bpf": refuse, "openat": refuse, "socket": refuse,
	} {
		if got := runFilter(t, prog, arch, syscallTable[name][col], 0); got != want {
			t.Errorf("narrowed profile: %s -> %#x, want %#x", name, got, want)
		}
	}
}
