package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// The latency profile is for programs that measure themselves in
// microseconds. Everything here happens before the program starts; once it
// runs, nothing of capsule sits between it and its cores, memory or network
// interface.
//
// Dedicated cores come from a set the host's operator has put aside in
// <config>/latency:
//
//	cores 2-7
//
// ideally the same cores the kernel was told to keep free at boot
// (isolcpus, nohz_full, rcu_nocbs). A capsule that asks for cores gets that
// many from the set, to itself, with no CPU quota to pause it. Every other
// capsule on the host is kept off the whole set.

// parseCPUList reads the kernel's list form, such as "0-3,6".
func parseCPUList(text string) ([]int, error) {
	var cpus []int
	for _, part := range strings.Split(strings.TrimSpace(text), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		if isRange && err == nil {
			b, err = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err != nil || a < 0 || b < a || b > 4095 {
			return nil, fmt.Errorf("%q is not a list of cores", text)
		}
		for c := a; c <= b; c++ {
			cpus = append(cpus, c)
		}
	}
	sort.Ints(cpus)
	return slices.Compact(cpus), nil
}

func formatCPUList(cpus []int) string {
	var parts []string
	for _, c := range cpus {
		parts = append(parts, strconv.Itoa(c))
	}
	return strings.Join(parts, ",")
}

// reservedCores is the set this host keeps for latency-critical capsules, or nil.
func reservedCores() ([]int, error) {
	file := filepath.Join(configDir(), "latency")
	raw, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "cores"); ok {
			return parseCPUList(rest)
		}
	}
	return nil, fmt.Errorf("%s: want a line like `cores 2-7`", file)
}

// assignCores pins the capsule's cgroup. A capsule with latency.cores gets
// that many reserved cores no other capsule has, and memory from their NUMA
// node. Any other capsule is confined to the cores that are not reserved.
// stage names this run; the choice is recorded beside it so that other runs
// can see which cores are taken.
func assignCores(cg, stage string, l *Latency) (release func(), err error) {
	release = func() {}
	reserved, err := reservedCores()
	if err != nil {
		return release, err
	}
	wants := 0
	if l != nil {
		wants = l.Cores
	}
	if wants == 0 {
		if len(reserved) == 0 {
			return release, nil
		}
		online, err := os.ReadFile("/sys/devices/system/cpu/online")
		if err != nil {
			return release, nil
		}
		all, _ := parseCPUList(string(online))
		rest := slices.DeleteFunc(all, func(c int) bool { return slices.Contains(reserved, c) })
		if len(rest) > 0 {
			// Best effort: a host that cannot set this still runs the capsule, only without the fence.
			os.WriteFile(filepath.Join(cg, "cpuset.cpus"), []byte(formatCPUList(rest)), 0)
		}
		return release, nil
	}
	if !realRoot() {
		return release, errors.New("latency: dedicated cores need root")
	}
	if len(reserved) == 0 {
		return release, errors.New("latency: this host has set no cores aside; put a line like `cores 2-7` in " + filepath.Join(configDir(), "latency"))
	}
	runDir := filepath.Dir(stage)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return release, err
	}
	lock, err := os.OpenFile(filepath.Join(runDir, "cores.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return release, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return release, err
	}
	taken := map[int]bool{}
	for _, inst := range running() { // also clears away the records of runs that are gone
		raw, _ := os.ReadFile(inst.stage + ".cores")
		cores, _ := parseCPUList(string(raw))
		for _, c := range cores {
			taken[c] = true
		}
	}
	var mine []int
	for _, c := range reserved {
		if !taken[c] && len(mine) < wants {
			mine = append(mine, c)
		}
	}
	if len(mine) < wants {
		return release, fmt.Errorf("latency: %d dedicated core(s) asked for, %d of this host's %d are free", wants, len(mine), len(reserved))
	}
	list := formatCPUList(mine)
	if err := os.WriteFile(filepath.Join(cg, "cpuset.cpus"), []byte(list), 0); err != nil {
		return release, fmt.Errorf("latency: cannot pin to cores %s (is the cpuset controller available?): %w", list, err)
	}
	if nodes := numaNodes(mine); nodes != "" {
		os.WriteFile(filepath.Join(cg, "cpuset.mems"), []byte(nodes), 0) // memory from the cores' own node
	}
	if err := os.WriteFile(stage+".cores", []byte(list+"\n"), 0o600); err != nil {
		return release, err
	}
	return func() { os.Remove(stage + ".cores") }, nil
}

// numaNodes lists the memory nodes the given cores sit on.
func numaNodes(cores []int) string {
	var nodes []int
	for _, c := range cores {
		matches, _ := filepath.Glob(fmt.Sprintf("/sys/devices/system/cpu/cpu%d/node*", c))
		for _, m := range matches {
			if n, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(m), "node")); err == nil {
				nodes = append(nodes, n)
			}
		}
	}
	sort.Ints(nodes)
	return formatCPUList(slices.Compact(nodes))
}

// handOverNic moves one of the host's network interfaces into the capsule
// and sets it up there, since the program has no privilege to do so itself.
// The interface is the capsule's alone until it ends, when it is moved back.
func handOverNic(ns *os.File, nic Nic) (giveBack func(), err error) {
	if !realRoot() {
		return nil, errors.New("handing a network interface to a capsule needs root")
	}
	link, err := netlink.LinkByName(nic.Name)
	if err != nil {
		return nil, fmt.Errorf("this host has no network interface %s", nic.Name)
	}
	home, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetNsFd(link, int(ns.Fd())); err != nil {
		home.Close()
		return nil, fmt.Errorf("moving %s into the capsule: %w", nic.Name, err)
	}
	inside, err := netlink.NewHandleAt(netns.NsHandle(ns.Fd()))
	giveBack = func() {
		if inside != nil {
			if link, err := inside.LinkByName(nic.Name); err == nil {
				inside.LinkSetDown(link)
				inside.LinkSetNsFd(link, int(home.Fd()))
			}
			inside.Close()
		}
		home.Close()
	}
	if err != nil {
		giveBack()
		return nil, err
	}
	fail := func(err error) (func(), error) {
		giveBack()
		return nil, fmt.Errorf("setting up %s in the capsule: %w", nic.Name, err)
	}
	if link, err = inside.LinkByName(nic.Name); err != nil {
		return fail(err)
	}
	if nic.Address != "" {
		addr, err := netlink.ParseAddr(nic.Address)
		if err != nil {
			return fail(err)
		}
		if err := inside.AddrAdd(link, addr); err != nil {
			return fail(err)
		}
	}
	if err := inside.LinkSetUp(link); err != nil {
		return fail(err)
	}
	if nic.Gateway != "" {
		if err := inside.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP(nic.Gateway)}); err != nil {
			return fail(err)
		}
	}
	return giveBack, nil
}
