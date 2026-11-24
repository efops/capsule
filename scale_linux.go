package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// replica is one running copy of an autoscaled capsule: a `capsule run`
// process of its own, with its own cgroup, volumes and mesh identity.
type replica struct {
	label   string
	cmd     *exec.Cmd
	exited  chan struct{}
	started time.Time

	cgroup  string   // known once the replica has registered itself
	ns      *os.File // its network namespace, for balancing a published port
	usage   uint64   // CPU microseconds at the last sample
	sampled time.Time
	active  atomic.Int64 // connections it is carrying from published ports
}

const (
	scaleEvery       = 2 * time.Second        // CPU is judged, and memory looked at, on this rhythm
	startEvery       = 250 * time.Millisecond // while a replica is starting, look for it this often
	softLimitPercent = 92                     // memory.high as a share of memory.max
	hotSamples       = 3                      // this many samples in a row above target before adding a replica
	coldSample       = 5                      // this many in a row below half of target before removing one
)

// autoscale runs a capsule whose manifest has a "scale" section. It keeps
// between min and max replicas running, restarts those that exit as the
// manifest says, adds one when average CPU use stays above the target and
// removes one when it stays well below, raises a replica's memory limit as
// it nears it, and balances any published port across the replicas. The
// policy is sealed in the manifest; this process only carries it out.
func autoscale(dir string, m Manifest, childFlags []string, publish []publishSpec, trusted trustSet) error {
	sc := m.Scale
	cooldown, _ := time.ParseDuration(sc.Cooldown) // validated with the manifest
	if sc.Cooldown == "" {
		cooldown = 30 * time.Second
	}
	cpus := m.Limits.CPUs
	if cpus <= 0 {
		cpus = 1
	}
	var memoryMax int64
	if sc.MemoryMax != "" {
		memoryMax, _ = parseSizeText(sc.MemoryMax)
	}
	say := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "capsule: scale: %s: %s\n", m.Name, fmt.Sprintf(format, a...))
	}

	var mu sync.Mutex // guards replicas, which the port balancers read
	replicas := map[int]*replica{}
	var lookForNew func() // set once the loop's timers exist
	start := func(n int) error {
		label := "r" + strconv.Itoa(n)
		args := append(append([]string{"run"}, childFlags...), "-replica", "-instance", label, dir)
		cmd := exec.Command("/proc/self/exe", args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		r := &replica{label: label, cmd: cmd, exited: make(chan struct{}), started: time.Now()}
		go func() { cmd.Wait(); close(r.exited) }()
		mu.Lock()
		replicas[n] = r
		mu.Unlock()
		if lookForNew != nil {
			lookForNew()
		}
		return nil
	}
	forget := func(n int) {
		mu.Lock()
		if r := replicas[n]; r != nil && r.ns != nil {
			r.ns.Close()
		}
		delete(replicas, n)
		mu.Unlock()
	}
	stop := func(n int) {
		r := replicas[n]
		r.cmd.Process.Signal(syscall.SIGTERM) // the replica's own supervisor stops its capsule and cleans up
		select {
		case <-r.exited:
		case <-time.After(15 * time.Second):
			r.cmd.Process.Kill()
			<-r.exited
		}
		forget(n)
	}
	stopAll := func() {
		for n := range replicas {
			stop(n)
		}
	}
	lowestFree := func() int {
		for n := 1; ; n++ {
			if replicas[n] == nil {
				return n
			}
		}
	}
	highest := func() int {
		top := 0
		for n := range replicas {
			top = max(top, n)
		}
		return top
	}

	// A published port is one host port shared by all replicas. Each new
	// connection goes to a replica chosen by scale.balance.
	var turn atomic.Uint64
	for _, p := range publish {
		l, err := net.Listen("tcp", p.host)
		if err != nil {
			return err
		}
		defer l.Close()
		go serve(l, fmt.Sprintf("publish %d", p.port), func() (net.Conn, func(), error) {
			mu.Lock()
			var ready []*replica
			for _, r := range replicas {
				if r.ns != nil {
					ready = append(ready, r)
				}
			}
			mu.Unlock()
			sort.Slice(ready, func(i, j int) bool { return ready[i].label < ready[j].label })
			load := make([]int64, len(ready))
			for i, r := range ready {
				load[i] = r.active.Load()
			}
			err := errors.New("no replica is running yet")
			for _, i := range pickBackend(sc.Balance, load, turn.Add(1)) {
				var c net.Conn
				if c, err = dialCapsule(ready[i].ns, p.port); err == nil {
					r := ready[i]
					r.active.Add(1)
					return c, func() { r.active.Add(-1) }, nil
				}
			}
			return nil, nil, err
		})
	}

	// With "fleet", hosts running this capsule share their load through the
	// ledger and take turns, so the fleet scales as one and the next replica
	// goes to the host with the fewest.
	var fleet ledger
	me := "self"
	if sc.Fleet {
		var err error
		if fleet, err = openLedger(); err != nil {
			return err
		} else if fleet == nil {
			return errors.New("scale.fleet needs the fleet ledger, and this host has none configured (see <config>/ledger)")
		}
		key, err := hostSigner()
		if err != nil {
			return err
		}
		me = key.id()
		if selfDelegation(m.Name) == nil {
			say("this host has not been delegated %q by a trusted key, so the other hosts will not count its load (see capsule delegate)", m.Name)
		}
	}
	// view publishes this host's load and returns everyone's, own first.
	view := func(own hostLoad) []hostLoad {
		all := []hostLoad{own}
		if fleet == nil {
			return all
		}
		key, err := hostSigner()
		if err != nil {
			return all
		}
		report := loadReport{hostLoad: own, Name: m.Name, Time: time.Now().Unix(), Signer: key.pub, Delegation: selfDelegation(m.Name)}
		report.Signature = key.sign(report.message())
		raw, _ := json.Marshal(report)
		prefix := "load/" + m.Name + "/"
		if err := fleet.put(prefix+idHex(me), raw); err != nil {
			say("could not share this host's load: %v", err)
		}
		keys, err := fleet.list(prefix)
		if err != nil {
			say("could not read the fleet's load: %v", err)
			return all
		}
		for _, k := range keys {
			var r loadReport
			raw, found, err := fleet.get(k)
			if err != nil || !found || json.Unmarshal(raw, &r) != nil || r.Name != m.Name || r.Host == me {
				continue
			}
			// A report counts only if it is recent, signed by the host it
			// claims to be from, and that host has been delegated this
			// capsule's name by a key we trust. A machine that merely has
			// write access to the ledger cannot steer the fleet's scaling.
			d := r.Delegation
			if keyID(r.Signer) != r.Host || time.Now().Unix()-r.Time > 15 || !verifySig(r.Signer, r.Signature, r.message()) ||
				d == nil || d.Host != r.Host || !slices.Contains(d.Names, m.Name) || !signedBy(trusted, d.Signer, d.Signature, d.message()) {
				continue
			}
			all = append(all, r.hostLoad)
		}
		return all
	}

	for len(replicas) < sc.Min {
		if err := start(lowestFree()); err != nil {
			stopAll()
			return err
		}
	}
	say("%d replica(s) running, between %d and %d allowed", len(replicas), sc.Min, sc.Max)
	debug.SetGCPercent(20) // this process lives as long as the service: keep it small
	debug.FreeOSMemory()

	// grow raises a replica's memory limit when it is close to it. The soft
	// limit (memory.high) sits just below the hard one, so in the moments
	// before this runs the kernel slows the capsule down rather than killing it.
	setLimit := func(r *replica, limit int64) error {
		if err := os.WriteFile(filepath.Join(r.cgroup, "memory.max"), []byte(strconv.FormatInt(limit, 10)), 0); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(r.cgroup, "memory.high"), []byte(strconv.FormatInt(limit/100*softLimitPercent, 10)), 0)
	}
	grow := func(r *replica) {
		limit, used := readInt(r.cgroup, "memory.max"), readInt(r.cgroup, "memory.current")
		if limit <= 0 || limit >= memoryMax || used*100 < limit*85 {
			return
		}
		bigger := min(limit+limit/2, memoryMax)
		if err := setLimit(r, bigger); err == nil {
			say("replica %s was using %dM of %dM; memory limit raised to %dM", r.label, used>>20, limit>>20, bigger>>20)
		}
	}

	// discover finds the cgroup and network of replicas that have registered since the last look.
	discover := func() {
		waiting := false
		for _, r := range replicas {
			waiting = waiting || r.cgroup == "" || (r.ns == nil && len(publish) > 0)
		}
		if !waiting {
			return
		}
		byLabel := map[string]instance{}
		for _, inst := range running() {
			if inst.name == m.Name {
				byLabel[inst.label] = inst
			}
		}
		for _, r := range replicas {
			inst, ok := byLabel[r.label]
			if !ok {
				continue // still starting
			}
			r.cgroup = inst.cgroup
			if r.ns == nil && len(publish) > 0 {
				if pid := strings.Fields(firstLine(filepath.Join(r.cgroup, "cgroup.procs")) + " 0")[0]; pid != "0" {
					if ns, err := os.Open("/proc/" + pid + "/ns/net"); err == nil {
						mu.Lock()
						r.ns = ns
						mu.Unlock()
					}
				}
			}
		}
	}

	// Memory pressure is not polled for. The kernel is asked to say when a
	// replica crosses its soft limit, and this process sleeps until it does.
	pressure := make(chan struct{}, 1)
	watcher, watchErr := unix.InotifyInit1(unix.IN_CLOEXEC)
	if watchErr == nil {
		defer unix.Close(watcher)
		go func() {
			buf := make([]byte, 4096)
			for {
				if n, err := unix.Read(watcher, buf); err == unix.EINTR {
					continue
				} else if err != nil || n <= 0 {
					return
				}
				select {
				case pressure <- struct{}{}:
				default: // a wake-up is already pending
				}
			}
		}()
	}
	watched := map[string]bool{}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	cpuTick, startTick := time.NewTicker(scaleEvery), time.NewTicker(startEvery)
	defer cpuTick.Stop()
	defer startTick.Stop()
	lookForNew = func() { startTick.Reset(startEvery) }
	growAll := func() {
		for _, r := range replicas {
			if r.cgroup != "" {
				grow(r)
			}
		}
	}
	hot, cold := 0, 0
	changed := time.Now()
	lastStatus, finished := 0, false
	for {
		select {
		case <-sigs:
			stopAll()
			return nil
		case <-pressure:
			growAll()
			continue
		case <-startTick.C:
			discover()
			waiting := false
			for _, r := range replicas {
				waiting = waiting || r.cgroup == "" || (r.ns == nil && len(publish) > 0)
				if r.cgroup != "" && memoryMax > 0 && watchErr == nil && !watched[r.cgroup] {
					watched[r.cgroup] = true // the watch goes away by itself when the cgroup does
					unix.InotifyAddWatch(watcher, filepath.Join(r.cgroup, "memory.events"), unix.IN_MODIFY)
					grow(r)
				}
			}
			if !waiting {
				startTick.Stop() // nothing is starting: stop waking up for it
			}
			continue
		case <-cpuTick.C:
			if memoryMax > 0 {
				growAll() // a replica sitting just under its soft limit raises no event
			}
		}

		// Replicas that exited by themselves: start them again, or not, as the manifest says.
		for n, r := range replicas {
			select {
			case <-r.exited:
			default:
				continue
			}
			status := r.cmd.ProcessState.ExitCode()
			if time.Since(r.started) < 3*time.Second && len(replicas) == 1 && r.cgroup == "" && status != 0 {
				return errors.New("the capsule did not start; see the error above") // refused or broken: do not loop on it
			}
			forget(n)
			lastStatus = status
			if sc.Restart == "never" || (sc.Restart == "on-failure" && status == 0) {
				say("replica %s finished with status %d", r.label, status)
				finished = true
				continue
			}
			say("replica %s exited with status %d; starting it again", r.label, status)
			if err := start(n); err != nil {
				say("could not restart replica: %v", err)
			}
		}
		if len(replicas) == 0 && finished { // every replica has finished and none is to be restarted
			if lastStatus != 0 {
				return exitError(lastStatus)
			}
			return nil
		}

		total, measured := 0.0, 0
		for _, r := range replicas {
			if r.cgroup == "" {
				continue // still starting
			}
			if usage, at := cpuUsage(r.cgroup), time.Now(); usage > 0 {
				if !r.sampled.IsZero() && usage >= r.usage {
					total += float64(usage-r.usage) / float64(at.Sub(r.sampled).Microseconds()) / cpus * 100
					measured++
				}
				r.usage, r.sampled = usage, at
			}
		}
		own := hostLoad{Host: me, Replicas: len(replicas), Min: sc.Min, Max: sc.Max}
		if measured > 0 {
			own.CPU = total / float64(measured)
		} else if len(replicas) > 0 {
			continue // replicas are still starting; nothing to judge by yet
		}
		if sc.CPU == 0 {
			continue
		}
		everyone := view(own)
		average, fleetReplicas := fleetAverage(everyone)

		// Add or remove a replica when the load has clearly moved, and it is this host's turn.
		switch {
		case fleetReplicas == 0:
			// Nothing is running anywhere, so someone must start. Count up to
			// it like any other decision: by then every host that began at
			// the same moment has seen the others' figures, and they agree
			// on which one of them it is.
			hot, cold = hot+1, 0
		case average > float64(sc.CPU):
			hot, cold = hot+1, 0
		case average < float64(sc.CPU)/2:
			hot, cold = 0, cold+1
		default:
			hot, cold = 0, 0
		}
		if time.Since(changed) < cooldown {
			continue
		}
		switch {
		case hot >= hotSamples && len(replicas) < sc.Max && growTurn(everyone) == me:
			if err := start(lowestFree()); err != nil {
				say("could not add a replica: %v", err)
				continue
			}
			say("CPU at %.0f%% of limit across %d replica(s), above the %d%% target: now %d here", average, fleetReplicas, sc.CPU, len(replicas))
			hot, changed = 0, time.Now()
		case cold >= coldSample && len(replicas) > sc.Min && shrinkTurn(everyone) == me:
			stop(highest())
			say("CPU at %.0f%% of limit across %d replica(s), well below the %d%% target: now %d here", average, fleetReplicas, sc.CPU, len(replicas))
			cold, changed = 0, time.Now()
		}
	}
}

// loadReport is a host's signed statement of its load for one capsule.
type loadReport struct {
	hostLoad
	Name       string      `json:"name"`
	Time       int64       `json:"time"`
	Signer     string      `json:"signer"`
	Signature  string      `json:"signature"`
	Delegation *delegation `json:"delegation,omitempty"`
}

func (r loadReport) message() []byte {
	return []byte(fmt.Sprintf("capsule-load-v1\n%s\n%s\n%d\n%d\n%d\n%.3f\n%d\n", r.Name, r.Host, r.Replicas, r.Min, r.Max, r.CPU, r.Time))
}

func readInt(cgroup, file string) int64 {
	raw, _ := os.ReadFile(filepath.Join(cgroup, file))
	n, _ := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64) // "max" reads as 0: no limit to compare against
	return n
}

func cpuUsage(cgroup string) uint64 {
	raw, _ := os.ReadFile(filepath.Join(cgroup, "cpu.stat"))
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "usage_usec "); ok {
			n, _ := strconv.ParseUint(rest, 10, 64)
			return n
		}
	}
	return 0
}
