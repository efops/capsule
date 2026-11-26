package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drand/drand/v2/crypto"
)

// A tissue is how a fleet keeps a set of cells alive with no scheduler, no
// control plane and no leader.
//
// An operator signs one document: which cells are roots, how many of each
// may live, and which hosts may carry them. Everything else follows from
// three rules every host applies alone, from the same public facts:
//
//	need   a cell lives because it is a root or because a living cell needs
//	       it. What nothing needs is stopped.
//	draw   a vacant slot goes to the host that wins a draw made from the
//	       drand beacon: nobody can know the winner beforehand, every host
//	       works out the same one, and anyone can check it afterwards.
//	lease  a slot is held for a span of ticks and must be renewed. A lease
//	       that lapses is taken by the next host in the draw with a higher
//	       term, and a host that sees a higher term than its own stops.
//
// The ledger holds the record; it decides nothing. A claim is a key that can
// be created once, so two hosts never hold the same term.

const (
	tissueEpoch   = 20 // ticks: every draw made within one epoch uses the same round
	tissueStagger = 2  // ticks each further-ranked host waits before stepping in
	defaultLease  = 10 // ticks a pulse keeps a slot: half a minute, well over one slow pass
	busyPercent   = 80 // a cell grows when every instance is busier than this
	idlePercent   = 30 // and shrinks when every instance is idler than this
)

type tissueCell struct {
	Root     bool     `json:"root,omitempty"`     // alive whether or not anything needs it
	Min      int      `json:"min,omitempty"`      // instances, each on a host of its own (default 1)
	Max      int      `json:"max,omitempty"`      // it may grow to this many under load (default min)
	On       []string `json:"on,omitempty"`       // labels a host must carry
	Standby  string   `json:"standby,omitempty"`  // "warm": the runner-up keeps it ready; "hot": it runs there too
	Takeover string   `json:"takeover,omitempty"` // "fast" (default) or "strict": stop rather than risk two copies
	Step     int      `json:"step,omitempty"`     // instances replaced at a time when a new release appears (default 1)
}

type tissueHost struct {
	File    string   `json:"file,omitempty"` // as written by the operator: a host file, resolved when signing
	ID      string   `json:"id,omitempty"`
	SignKey string   `json:"sign_key,omitempty"`
	Labels  []string `json:"labels,omitempty"`
	Weight  int      `json:"weight,omitempty"` // share of draws it wins (default 1)
	Memory  string   `json:"memory,omitempty"` // what it offers the tissue; empty is no limit
	CPUs    float64  `json:"cpus,omitempty"`
	Cores   int      `json:"cores,omitempty"` // dedicated cores it offers latency-critical cells
	Nics    []string `json:"nics,omitempty"`  // network interfaces it can hand to one
}

type tissue struct {
	Name       string                `json:"name"`
	Time       int64                 `json:"time"`            // nanoseconds; a host never goes back to an older one
	Lease      int                   `json:"lease,omitempty"` // ticks
	Cells      map[string]tissueCell `json:"cells"`
	Hosts      []tissueHost          `json:"hosts"`
	Budget     *Limits               `json:"budget,omitempty"` // memory and CPUs the whole tissue may commit
	Signatures []orderSig            `json:"signatures,omitempty"`
}

func (t tissue) message() []byte {
	t.Signatures = nil
	b, _ := json.Marshal(t)
	return append([]byte("capsule-tissue-v1\n"), b...)
}

func (t tissue) lease() uint64 {
	if t.Lease > 0 {
		return uint64(t.Lease)
	}
	return defaultLease
}

// cell returns a cell's settings with the defaults filled in. A cell that is
// only needed, and not listed, gets one instance and no more: nothing grows
// past a number an operator signed.
func (t tissue) cell(name string) tissueCell {
	c := t.Cells[name]
	c.Min = max(c.Min, 1)
	c.Max = max(c.Max, c.Min)
	c.Step = max(c.Step, 1)
	return c
}

func (t tissue) host(id string) (tissueHost, bool) {
	for _, h := range t.Hosts {
		if h.ID == id {
			return h, true
		}
	}
	return tissueHost{}, false
}

func (t tissue) validate() error {
	if !nameRE.MatchString(t.Name) {
		return errors.New("tissue: name must match [a-z0-9][a-z0-9-]*")
	}
	if t.Lease != 0 && (t.Lease < 2 || t.Lease > 1200) {
		return errors.New("tissue: lease must be between 2 and 1200 ticks")
	}
	roots := 0
	for name, c := range t.Cells {
		switch {
		case !nameRE.MatchString(name):
			return fmt.Errorf("tissue: %q is not a cell name", name)
		case c.Min < 0 || c.Max < 0 || (c.Max != 0 && c.Max < c.Min) || c.Step < 0:
			return fmt.Errorf("tissue: %s: min, max and step must not be negative, and max not below min", name)
		case !slices.Contains([]string{"", "warm", "hot"}, c.Standby):
			return fmt.Errorf(`tissue: %s: standby must be "warm" or "hot"`, name)
		case !slices.Contains([]string{"", "fast", "strict"}, c.Takeover):
			return fmt.Errorf(`tissue: %s: takeover must be "fast" or "strict"`, name)
		}
		if c.Root {
			roots++
		}
	}
	if roots == 0 {
		return errors.New("tissue: no cell is a root, so nothing would live")
	}
	if len(t.Hosts) == 0 {
		return errors.New("tissue: no hosts")
	}
	seen := map[string]bool{}
	for _, h := range t.Hosts {
		if !isID(h.ID) || keyID(h.SignKey) == "" || seen[h.ID] || h.Weight < 0 || h.CPUs < 0 || h.Cores < 0 {
			return errors.New("tissue: a host is listed twice or is not from a host file")
		}
		if h.Memory != "" {
			if _, err := parseSizeText(h.Memory); err != nil {
				return fmt.Errorf("tissue: host memory: %w", err)
			}
		}
		seen[h.ID] = true
	}
	if t.Budget != nil && t.Budget.Memory != "" {
		if _, err := parseSizeText(t.Budget.Memory); err != nil {
			return fmt.Errorf("tissue: budget: %w", err)
		}
	}
	return nil
}

// ---- what hosts write to the ledger ----

// beat is one signed fact from a host: that it is alive, that it has taken a
// slot, that it still holds one, how many instances a cell should have, or
// that a release failed to come up.
type beat struct {
	Kind      string `json:"kind"` // host, lease, pulse, want, halt
	Cell      string `json:"cell,omitempty"`
	Slot      int    `json:"slot,omitempty"`
	Term      int    `json:"term,omitempty"`
	Host      string `json:"host"`
	Tick      uint64 `json:"tick"`
	Round     uint64 `json:"round,omitempty"`  // lease: the beacon round its draw used
	Proven    bool   `json:"proven,omitempty"` // lease: that round came signed from the beacon
	Seal      string `json:"seal,omitempty"`   // the release this instance runs
	Busy      int    `json:"busy,omitempty"`   // pulse: CPU in use, as a percentage of its limit
	Want      int    `json:"want,omitempty"`
	Key       string `json:"key"`
	Signature string `json:"signature,omitempty"`
}

func (b beat) message() []byte {
	b.Signature = ""
	raw, _ := json.Marshal(b)
	return append([]byte("capsule-beat-v1\n"), raw...)
}

// from reports whether the beat was signed by the host it names, as the tissue knows that host.
func (b beat) from(t tissue) bool {
	h, ok := t.host(b.Host)
	return ok && h.SignKey == b.Key && verifySig(b.Key, b.Signature, b.message())
}

func leaseKey(cell string, slot, term int) string {
	return fmt.Sprintf("tissue/leases/%s/%03d/%08d", cell, slot, term)
}
func pulseKey(cell string, slot int) string { return fmt.Sprintf("tissue/pulse/%s/%03d", cell, slot) }

// ---- the world as one pass sees it ----

// cellInfo is what the current release of a cell says about itself.
type cellInfo struct {
	Seal     string // the release the tissue runs: the newest that has not been held back
	Released int64  // when it was published
	Manifest Manifest
	Newest   string // the newest release published, which is the same unless that one was held back
}

type slotState struct {
	lease *beat // the highest term anyone has validly taken
	pulse *beat // that holder's latest renewal
	top   int   // the highest term number in use, valid or not: the next claim goes above it
}

// last is the tick the holder was last known to be there.
func (s slotState) last() uint64 {
	if s.lease == nil {
		return 0
	}
	if s.pulse != nil {
		return max(s.lease.Tick, s.pulse.Tick)
	}
	return s.lease.Tick
}

type world struct {
	t      tissue
	now    uint64
	infos  map[string]cellInfo
	alive  map[string]bool        // hosts that have pulsed within a lease
	slots  map[string][]slotState // by cell, then slot
	want   map[string]int         // instances asked for beyond the minimum, by cell
	wantAt map[string]uint64
	halted map[string]bool                              // cell + " " + seal: a release that failed to come up
	beacon func(round uint64) (sig []byte, proven bool) // the draw's source of randomness
	taking map[string][]string                          // while planning: cells a host is about to claim, by host
}

func (w *world) slot(cell string, i int) slotState {
	if s := w.slots[cell]; i < len(s) {
		return s[i]
	}
	return slotState{}
}

func (w *world) held(s slotState) bool {
	return s.lease != nil && s.last()+w.t.lease() >= w.now
}

// needs lists the cells a manifest reaches out to.
func needsOf(m Manifest) []string {
	var names []string
	for _, n := range m.Needs {
		names = append(names, n.From)
	}
	if m.Mesh != nil {
		for _, p := range m.Mesh.Peers {
			if len(p.Out)+len(p.OutUDP) > 0 {
				names = append(names, p.Name)
			}
		}
	}
	return names
}

// wanted works out how many instances of each cell should be alive: the
// roots, everything they need however far down, each at its signed minimum
// plus whatever load has asked for up to its signed maximum, and all of it
// within the tissue's budget. Cells are taken in a fixed order, so every
// host cuts the same ones when the budget runs out.
func (w *world) wanted() (counts map[string]int, short []string) {
	var order []string
	seen := map[string]bool{}
	var visit func(name string)
	visit = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		order = append(order, name)
		needs := needsOf(w.infos[name].Manifest)
		sort.Strings(needs)
		for _, n := range needs {
			visit(n)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(w.t.Cells)) {
		if w.t.Cells[name].Root {
			visit(name)
		}
	}
	var memLeft, cpuLeft = int64(math.MaxInt64), math.MaxFloat64
	if b := w.t.Budget; b != nil {
		if b.Memory != "" {
			memLeft, _ = parseSizeText(b.Memory)
		}
		if b.CPUs > 0 {
			cpuLeft = b.CPUs
		}
	}
	counts = map[string]int{}
	for _, name := range order {
		info, known := w.infos[name]
		if !known {
			short = append(short, name+": not published")
			continue
		}
		c := w.t.cell(name)
		n := min(c.Min+w.want[name], c.Max)
		mem, cpus := cellSize(info.Manifest)
		for n > 0 && (int64(n)*mem > memLeft || float64(n)*cpus > cpuLeft) {
			n--
		}
		if n < c.Min {
			short = append(short, fmt.Sprintf("%s: the budget allows %d of %d", name, n, c.Min))
		}
		memLeft -= int64(n) * mem
		cpuLeft -= float64(n) * cpus
		counts[name] = n
	}
	return counts, short
}

// cellSize is what one instance commits on its host, from its sealed limits.
func cellSize(m Manifest) (memory int64, cpus float64) {
	memory, _ = parseSizeText(m.Limits.Memory)
	cpus = m.Limits.CPUs
	if m.Latency != nil && m.Latency.Cores > 0 {
		cpus = float64(m.Latency.Cores)
	}
	return memory, cpus
}

// committed adds up what a host has taken on: the leases it holds, sized by
// each capsule's signed limits. It is computed from the ledger, never from
// what the host says about itself.
func (w *world) committed(host string) (memory int64, cpus float64, cores, leases int) {
	for cell, slots := range w.slots {
		for _, s := range slots {
			if w.held(s) && s.lease.Host == host {
				m := w.infos[cell].Manifest
				mem, c := cellSize(m)
				memory, cpus, leases = memory+mem, cpus+c, leases+1
				if m.Latency != nil {
					cores += m.Latency.Cores
				}
			}
		}
	}
	for _, cell := range w.taking[host] {
		m := w.infos[cell].Manifest
		mem, c := cellSize(m)
		memory, cpus, leases = memory+mem, cpus+c, leases+1
		if m.Latency != nil {
			cores += m.Latency.Cores
		}
	}
	return
}

func (w *world) holds(host, cell string) bool {
	if slices.Contains(w.taking[host], cell) {
		return true
	}
	for _, s := range w.slots[cell] {
		if w.held(s) && s.lease.Host == host {
			return true
		}
	}
	return false
}

// eligible reports whether a host could take one more instance of a cell.
func (w *world) eligible(h tissueHost, cell string) bool {
	if !w.alive[h.ID] || w.holds(h.ID, cell) { // one instance of a cell per host
		return false
	}
	for _, label := range w.t.cell(cell).On {
		if !slices.Contains(h.Labels, label) {
			return false
		}
	}
	m := w.infos[cell].Manifest
	mem, cpus := cellSize(m)
	usedMem, usedCPU, usedCores, _ := w.committed(h.ID)
	if h.Memory != "" {
		if limit, _ := parseSizeText(h.Memory); usedMem+mem > limit {
			return false
		}
	}
	if h.CPUs > 0 && usedCPU+cpus > h.CPUs {
		return false
	}
	if l := m.Latency; l != nil {
		if l.Cores > 0 && usedCores+l.Cores > h.Cores {
			return false
		}
		if l.Nic != nil && !slices.Contains(h.Nics, l.Nic.Name) {
			return false
		}
	}
	return true
}

// drawRound is the beacon round the draws of the epoch containing tick use.
func drawRound(tick uint64) uint64 { return tick - tick%tissueEpoch }

// rank orders the hosts that could take a slot. Each host's place comes from
// a hash of the beacon's signature for the round, the slot and the host's
// id, scaled by the host's signed weight: the standard way to draw without
// anyone holding the dice. Of the first two, the one that has committed less
// goes first, which spreads load without trusting any host's own report.
func (w *world) rank(cell string, slot int, round uint64, except string) (hosts []string, proven bool) {
	sig, proven := w.beacon(round)
	type entry struct {
		id    string
		score float64
	}
	var entries []entry
	for _, h := range w.t.Hosts {
		if h.ID == except || !w.eligible(h, cell) {
			continue
		}
		sum := sha256.Sum256(fmt.Appendf(nil, "capsule-draw-v1\x00%x\x00%s\x00%d\x00%s", sig, cell, slot, h.ID))
		u := (float64(binary.BigEndian.Uint64(sum[:8])>>11) + 1) / (1 << 53) // in (0, 1]
		entries = append(entries, entry{h.ID, -math.Log(u) / float64(max(h.Weight, 1))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].score < entries[j].score })
	for _, e := range entries {
		hosts = append(hosts, e.id)
	}
	if len(hosts) > 1 && w.loadOf(hosts[1]) < w.loadOf(hosts[0]) {
		hosts[0], hosts[1] = hosts[1], hosts[0]
	}
	return hosts, proven
}

// loadOf is the share of its offer a host has committed, or the number of leases it holds if it named no offer.
func (w *world) loadOf(host string) float64 {
	h, _ := w.t.host(host)
	mem, _, _, leases := w.committed(host)
	if limit, _ := parseSizeText(h.Memory); limit > 0 {
		return float64(mem) / float64(limit)
	}
	return float64(leases)
}

// understudy is the host that stands behind a held slot: the next in the
// draw that put the holder there.
func (w *world) understudy(cell string, slot int) string {
	s := w.slot(cell, slot)
	if !w.held(s) || w.t.cell(cell).Standby == "" {
		return ""
	}
	if hosts, _ := w.rank(cell, slot, s.lease.Round, s.lease.Host); len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}

// pinned reports whether a slot must stay where it is: a cell that keeps
// data on a host can only come back on that host.
func (w *world) pinned(cell string, slot int) string {
	if s := w.slot(cell, slot); s.lease != nil && len(w.infos[cell].Manifest.Volumes) > 0 {
		return s.lease.Host
	}
	return ""
}

// step is one thing a host should do after looking at the world.
type step struct {
	Do   string // claim, hold, ready, shadow, renew, want
	Cell string
	Slot int
	Term int
	// claim: the round its draw used. want: the new number.
	Round  uint64
	Proven bool
	Want   int
}

// plan decides what one host should do. It is a pure function of the world,
// so every host reaches the same view of who should act, and it can be
// tested without a fleet. Stopping what the plan no longer mentions is the
// caller's part.
func (w *world) plan(me string) []step {
	var steps []step
	w.taking = map[string][]string{} // what this pass decides to claim counts against what it may claim next
	counts, _ := w.wanted()
	for _, cell := range slices.Sorted(maps.Keys(counts)) {
		c, info := w.t.cell(cell), w.infos[cell]
		for i := 0; i < counts[cell]; i++ {
			s := w.slot(cell, i)
			if w.held(s) {
				switch {
				case s.lease.Host == me:
					steps = append(steps, step{Do: "hold", Cell: cell, Slot: i, Term: s.lease.Term})
					if w.due(cell, i, counts[cell], info) {
						steps = append(steps, step{Do: "renew", Cell: cell, Slot: i, Term: s.lease.Term})
					}
				case w.understudy(cell, i) == me:
					steps = append(steps, step{Do: map[string]string{"warm": "ready", "hot": "shadow"}[c.Standby], Cell: cell, Slot: i})
				}
				continue
			}
			if pin := w.pinned(cell, i); pin != "" && pin != me {
				continue
			}
			round := drawRound(w.now)
			hosts, proven := w.rank(cell, i, round, "")
			if s.lease != nil {
				// Whoever let the lease lapse goes to the back, and a cell with
				// a standby goes first to the host that has been standing by.
				if at := slices.Index(hosts, s.lease.Host); at >= 0 && len(hosts) > 1 {
					hosts = append(slices.Delete(hosts, at, at+1), s.lease.Host)
				}
				if c.Standby != "" {
					if behind, _ := w.rank(cell, i, s.lease.Round, s.lease.Host); len(behind) > 0 {
						hosts = append([]string{behind[0]}, slices.DeleteFunc(hosts, func(h string) bool { return h == behind[0] })...)
					}
				}
			}
			k := slices.Index(hosts, me)
			if k < 0 {
				continue
			}
			// The winner acts at once. The others step in only if it has not, each a little later than the one before.
			vacant := round // a slot nobody has held: the others wait from the start of the epoch
			if s.lease != nil {
				vacant = s.last() + w.t.lease()
			}
			if k == 0 || w.now >= vacant+uint64(k)*tissueStagger {
				term := s.top + 1
				if s.lease != nil {
					term = max(term, s.lease.Term+1)
				}
				steps = append(steps, step{Do: "claim", Cell: cell, Slot: i, Term: term, Round: round, Proven: proven})
				w.taking[me] = append(w.taking[me], cell)
			}
		}
		// Whoever holds a cell's first slot speaks for how many it should have.
		if first := w.slot(cell, 0); c.Max > c.Min && w.held(first) && first.lease.Host == me && w.now >= w.wantAt[cell]+tissueEpoch {
			busy, idle, n := true, true, 0
			for i := 0; i < counts[cell]; i++ {
				if s := w.slot(cell, i); w.held(s) && s.pulse != nil {
					n++
					busy = busy && s.pulse.Busy >= busyPercent
					idle = idle && s.pulse.Busy <= idlePercent
				}
			}
			extra := w.want[cell]
			switch {
			case n == counts[cell] && busy && c.Min+extra < c.Max:
				steps = append(steps, step{Do: "want", Cell: cell, Want: extra + 1})
			case n == counts[cell] && idle && extra > 0:
				steps = append(steps, step{Do: "want", Cell: cell, Want: extra - 1})
			}
		}
	}
	return steps
}

// due reports whether it is this slot's turn to move to the current release.
// A new release is a new generation. The beacon round of the moment it was
// published fixes the order the slots change in, and a slot waits until all
// but step-1 of those before it are running the new one. A release that
// failed to come up anywhere is not tried again.
func (w *world) due(cell string, slot, count int, info cellInfo) bool {
	s := w.slot(cell, slot)
	running := s.lease.Seal
	if s.pulse != nil {
		running = s.pulse.Seal
	}
	if running == "" || running == info.Seal || w.halted[cell+" "+info.Seal] {
		return false
	}
	sig, _ := w.beacon(drawRound(clockTick(time.Unix(0, info.Released))))
	place := func(i int) string {
		sum := sha256.Sum256(fmt.Appendf(nil, "capsule-generation-v1\x00%x\x00%s\x00%d", sig, cell, i))
		return string(sum[:])
	}
	behind := 0
	for i := 0; i < count; i++ {
		other := w.slot(cell, i)
		if i == slot || place(i) >= place(slot) {
			continue
		}
		if !w.held(other) || other.pulse == nil || other.pulse.Seal != info.Seal {
			behind++
		}
	}
	return behind < w.t.cell(cell).Step
}

// ---- reading the ledger ----

// fallbackBeacon stands in when no signed round can be had. Every host
// derives the same value, so they still agree; it is only no longer a secret
// beforehand, and a lease taken with it says so.
func fallbackBeacon(round uint64) []byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "capsule-unproven-round\x00%d", round))
	return sum[:]
}

// beaconAt returns the beacon's signature for a round. A signature proves
// itself, so one host that can reach the beacon passes it on through the
// ledger to those that cannot, and each keeps what it has checked.
func beaconAt(l ledger, round uint64) ([]byte, bool) {
	cache := filepath.Join(dataDir(), "beacons", strconv.FormatUint(round, 10))
	if sig, err := os.ReadFile(cache); err == nil && len(sig) > 0 {
		return sig, true
	}
	keep := func(sig []byte) ([]byte, bool) {
		if os.MkdirAll(filepath.Dir(cache), 0o700) == nil {
			os.WriteFile(cache, sig, 0o600)
		}
		return sig, true
	}
	key := fmt.Sprintf("beacons/%d", round)
	if l != nil {
		if sig, found, err := l.get(key); err == nil && found && verifyRound(round, sig) {
			return keep(sig)
		}
	}
	if network, err := drandNetwork(); err == nil {
		rememberChain(network.Scheme().Name, network.PublicKey())
		if sig, err := network.Signature(round); err == nil && verifyRound(round, sig) {
			if l != nil {
				l.put(key, sig)
			}
			return keep(sig)
		}
	}
	return fallbackBeacon(round), false
}

func chainFile() string { return filepath.Join(dataDir(), "beacons", "chain") }

// rememberChain keeps the beacon's public key, so rounds can be checked later without reaching it.
func rememberChain(scheme string, key interface{ MarshalBinary() ([]byte, error) }) {
	raw, err := key.MarshalBinary()
	if _, serr := os.Stat(chainFile()); err != nil || serr == nil {
		return
	}
	if os.MkdirAll(filepath.Dir(chainFile()), 0o700) == nil {
		os.WriteFile(chainFile(), []byte(scheme+"\n"+b64.EncodeToString(raw)+"\n"), 0o600)
	}
}

// verifyRound checks a round's signature against the chain's key as this host first learnt it.
func verifyRound(round uint64, sig []byte) bool {
	raw, err := os.ReadFile(chainFile())
	if err != nil {
		network, nerr := drandNetwork()
		if nerr != nil {
			return false
		}
		rememberChain(network.Scheme().Name, network.PublicKey())
		if raw, err = os.ReadFile(chainFile()); err != nil {
			return false
		}
	}
	name, keyText, _ := strings.Cut(strings.TrimSpace(string(raw)), "\n")
	scheme, err := crypto.SchemeFromName(name)
	if err != nil {
		return false
	}
	keyRaw, err := b64.DecodeString(keyText)
	point := scheme.KeyGroup.Point()
	if err != nil || point.UnmarshalBinary(keyRaw) != nil {
		return false
	}
	return scheme.VerifyBeacon(beacon{Round: round, signature: sig}, point) == nil
}

// readTissue returns the tissue in the ledger if enough operators signed it.
// rules is nil where there are none to check against, as on an operator's
// own machine.
func readTissue(l ledger, rules *orderRules) (tissue, bool, error) {
	var t tissue
	raw, found, err := l.get("tissue/current")
	if err != nil || !found {
		return t, false, err
	}
	if json.Unmarshal(raw, &t) != nil || t.validate() != nil {
		return t, false, errors.New("the tissue in the ledger is malformed")
	}
	if rules != nil {
		if err := rules.signedByEnough("tissue", t.message(), t.Signatures); err != nil {
			return t, false, fmt.Errorf("the tissue in the ledger is not one this host follows: %w", err)
		}
	}
	return t, true, nil
}

// readWorld gathers what the ledger says. Everything in it is checked
// against the tissue's own list of hosts, so whoever can write to the ledger
// can hide a fact but cannot invent one.
func readWorld(l ledger, t tissue, now uint64, trusted trustSet) (*world, error) {
	w := &world{t: t, now: now, infos: map[string]cellInfo{}, alive: map[string]bool{}, slots: map[string][]slotState{},
		want: map[string]int{}, wantAt: map[string]uint64{}, halted: map[string]bool{}}
	rounds := map[uint64][]byte{}
	proven := map[uint64]bool{}
	w.beacon = func(round uint64) ([]byte, bool) {
		if _, ok := rounds[round]; !ok {
			rounds[round], proven[round] = beaconAt(l, round)
		}
		return rounds[round], proven[round]
	}
	keys, err := l.list("tissue/")
	if err != nil {
		return nil, err
	}
	read := func(key, kind string) *beat {
		raw, found, err := l.get(key)
		var b beat
		if err != nil || !found || json.Unmarshal(raw, &b) != nil || b.Kind != kind || !b.from(t) {
			return nil
		}
		return &b
	}
	leases := map[string][]string{} // cell/slot -> keys, lowest term first
	var wants []*beat
	for _, key := range keys {
		parts := strings.Split(strings.TrimPrefix(key, "tissue/"), "/")
		switch {
		case len(parts) == 2 && parts[0] == "hosts":
			if b := read(key, "host"); b != nil && idHex(b.Host) == parts[1] && b.Tick+t.lease() >= now {
				w.alive[b.Host] = true
			}
		case len(parts) == 4 && parts[0] == "leases":
			leases[parts[1]+"/"+parts[2]] = append(leases[parts[1]+"/"+parts[2]], key)
		case len(parts) == 2 && parts[0] == "want":
			if b := read(key, "want"); b != nil && b.Cell == parts[1] {
				wants = append(wants, b)
			}
		case len(parts) == 3 && parts[0] == "halt":
			if b := read(key, "halt"); b != nil && b.Cell == parts[1] && idHex(b.Seal) == parts[2] {
				w.halted[b.Cell+" "+b.Seal] = true
			}
		}
	}
	for name, keys := range leases {
		cell, slotText, _ := strings.Cut(name, "/")
		i, err := strconv.Atoi(slotText)
		if err != nil || i < 0 || i > 999 {
			continue
		}
		var s slotState
		sort.Strings(keys)
		// A term that exists cannot be created again, even if its lease no
		// longer counts, as when its host has left the tissue.
		s.top, _ = strconv.Atoi(keys[len(keys)-1][strings.LastIndexByte(keys[len(keys)-1], '/')+1:])
		for k := len(keys) - 1; k >= 0 && s.lease == nil; k-- { // the highest term that is a real lease
			if b := read(keys[k], "lease"); b != nil && b.Cell == cell && b.Slot == i && leaseKey(cell, i, b.Term) == keys[k] {
				s.lease = b
			}
		}
		if s.lease != nil {
			if p := read(pulseKey(cell, i), "pulse"); p != nil && p.Cell == cell && p.Slot == i && p.Term == s.lease.Term && p.Host == s.lease.Host {
				s.pulse = p
			}
		}
		for len(w.slots[cell]) <= i {
			w.slots[cell] = append(w.slots[cell], slotState{})
		}
		w.slots[cell][i] = s
	}
	for _, b := range wants { // only the holder of a cell's first slot speaks for its size
		if first := w.slot(b.Cell, 0); first.lease != nil && first.lease.Host == b.Host {
			w.want[b.Cell], w.wantAt[b.Cell] = max(b.Want, 0), b.Tick
		}
	}
	// The releases: every listed cell, and whatever those turn out to need.
	todo := slices.Collect(maps.Keys(t.Cells))
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		if _, done := w.infos[name]; done || !nameRE.MatchString(name) {
			continue
		}
		info, err := releaseInfo(l, name, trusted, w.halted)
		if err != nil {
			continue
		}
		w.infos[name] = info
		todo = append(todo, needsOf(info.Manifest)...)
	}
	return w, nil
}

// releaseCard is the small part of a published capsule a host needs to plan
// with: its manifest and seal, without the root filesystem.
type releaseCard struct {
	Manifest string `json:"manifest"` // capsule.json, base64
	Seal     Seal   `json:"seal"`
}

func releaseCardKey(name, seal string) string {
	return "capsules/" + name + "/" + idHex(seal) + ".json"
}

// releaseInfo reads the release of a cell the tissue should run, and its
// manifest: the newest one published that has not been held back. With
// trusted keys it accepts only what they signed; without (on an operator's
// machine, to show status) it reads what is there.
func releaseInfo(l ledger, name string, trusted trustSet, halted map[string]bool) (cellInfo, error) {
	var info cellInfo
	problem := fmt.Errorf("%s has not been published", name)
	for _, r := range releaseHistory(l, name) {
		if info.Newest == "" {
			info.Newest = r.Seal
		}
		if halted[name+" "+r.Seal] {
			continue
		}
		if trusted != nil && !signedBy(trusted, r.Signer, r.Signature, r.message()) {
			problem = fmt.Errorf("the release of %s is not signed by a trusted key", name)
			continue
		}
		raw, found, err := l.get(releaseCardKey(name, r.Seal))
		var card releaseCard
		if err != nil || !found || json.Unmarshal(raw, &card) != nil || card.Seal.id() != r.Seal {
			problem = fmt.Errorf("%s was published by an older capsule; publish it again", name)
			continue
		}
		manifest, err := b64.DecodeString(card.Manifest)
		if err != nil || digest(manifest) != card.Seal.Manifest {
			problem = fmt.Errorf("the published manifest of %s does not match its seal", name)
			continue
		}
		if trusted != nil && (!trusted[keyID(card.Seal.PublicKey)] || !verifySig(card.Seal.PublicKey, card.Seal.Signature, card.Seal.message())) {
			problem = fmt.Errorf("%s is not sealed by a trusted key", name)
			continue
		}
		m, err := parseManifest(manifest)
		if err != nil || m.Name != name {
			problem = fmt.Errorf("the published manifest of %s is not valid", name)
			continue
		}
		info.Seal, info.Released, info.Manifest = r.Seal, r.Time, m
		return info, nil
	}
	return info, problem
}

// ---- the operator's side ----

const tissueUsage = `usage:
  capsule tissue -key <file> [-o <file>] <tissue.json>   sign a tissue and publish it
  capsule tissue sign -key <file> <signed file>          add another operator's signature
  capsule tissue send <signed file>
  capsule tissue status                                  what is alive, where, and by which draw`

func cmdTissue(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return tissueStatus()
		case "send":
			if len(args) != 2 {
				return errors.New(tissueUsage)
			}
			return sendTissue(args[1])
		case "sign":
			fl := flag.NewFlagSet("tissue sign", flag.ExitOnError)
			keyPath := fl.String("key", "", "operator's private key")
			fl.Parse(args[1:])
			if *keyPath == "" || fl.NArg() != 1 {
				return errors.New(tissueUsage)
			}
			return signTissue(*keyPath, fl.Arg(0), fl.Arg(0), false)
		}
	}
	fl := flag.NewFlagSet("tissue", flag.ExitOnError)
	keyPath := fl.String("key", "", "operator's private key")
	out := fl.String("o", "", "write the signed tissue here instead of publishing it, for others to sign")
	fl.Parse(args)
	if *keyPath == "" || fl.NArg() != 1 {
		return errors.New(tissueUsage)
	}
	if *out != "" {
		return signTissue(*keyPath, fl.Arg(0), *out, true)
	}
	signed := filepath.Join(os.TempDir(), fmt.Sprintf("capsule-tissue-%d.json", os.Getpid()))
	defer os.Remove(signed)
	if err := signTissue(*keyPath, fl.Arg(0), signed, true); err != nil {
		return err
	}
	return sendTissue(signed)
}

// signTissue signs a tissue file. A fresh one has its host files resolved and is stamped with the time.
func signTissue(keyPath, in, out string, fresh bool) error {
	key, err := loadSigner(keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var t tissue
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	if fresh {
		for i, h := range t.Hosts {
			if h.File == "" {
				return fmt.Errorf("%s: each host needs \"file\": a host file from `capsule host -export`", in)
			}
			file := h.File
			if !filepath.IsAbs(file) {
				file = filepath.Join(filepath.Dir(in), file)
			}
			cards, err := loadHostCards([]string{file})
			if err != nil {
				return err
			}
			t.Hosts[i].File, t.Hosts[i].ID, t.Hosts[i].SignKey = "", cards[0].ID, cards[0].SignKey
		}
		t.Time, t.Signatures = time.Now().UnixNano(), nil
	}
	if err := t.validate(); err != nil {
		return err
	}
	t.Signatures = slices.DeleteFunc(t.Signatures, func(s orderSig) bool { return s.Signer == key.pub })
	t.Signatures = append(t.Signatures, orderSig{key.pub, key.sign(t.message())})
	signed, _ := json.MarshalIndent(t, "", "  ")
	if err := os.WriteFile(out, append(signed, '\n'), 0o644); err != nil {
		return err
	}
	if !strings.HasPrefix(filepath.Base(out), "capsule-tissue-") {
		fmt.Printf("signed tissue %s: %d signature(s), in %s\n", t.Name, len(t.Signatures), out)
	}
	return nil
}

func sendTissue(file string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var t tissue
	if json.Unmarshal(raw, &t) != nil || t.validate() != nil || len(t.Signatures) == 0 {
		return fmt.Errorf("%s: not a signed tissue", file)
	}
	l, err := orderLedger()
	if err != nil {
		return err
	}
	// Say now what a host would only find out later.
	w := &world{t: t, infos: map[string]cellInfo{}, want: map[string]int{}}
	todo := slices.Collect(maps.Keys(t.Cells))
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		if _, done := w.infos[name]; done {
			continue
		}
		info, err := releaseInfo(l, name, nil, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "capsule: warning:", err)
			continue
		}
		w.infos[name] = info
		todo = append(todo, needsOf(info.Manifest)...)
	}
	counts, short := w.wanted()
	for _, s := range short {
		fmt.Fprintln(os.Stderr, "capsule: warning:", s)
	}
	compact, _ := json.Marshal(t)
	if err := l.put("tissue/current", compact); err != nil {
		return err
	}
	var parts []string
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		parts = append(parts, fmt.Sprintf("%s x%d", name, counts[name]))
	}
	fmt.Printf("published tissue %s for %d host(s): %s\n", t.Name, len(t.Hosts), strings.Join(parts, ", "))
	return nil
}

func tissueStatus() error {
	l, err := orderLedger()
	if err != nil {
		return err
	}
	t, found, err := readTissue(l, nil)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("no tissue has been published to this ledger")
	}
	now, proven := new(ticker).now()
	w, err := readWorld(l, t, now, nil)
	if err != nil {
		return err
	}
	clock := "signed by the beacon"
	if !proven {
		clock = "from this machine's clock"
	}
	fmt.Printf("tissue %s, tick %d (%s), lease %d ticks\n\n", t.Name, now, clock, t.lease())
	short8 := func(id string) string { return idHex(id)[:8] }
	fmt.Printf("%-10s %-6s %-9s %-10s %s\n", "HOST", "STATE", "LEASES", "COMMITTED", "LABELS")
	for _, h := range t.Hosts {
		state := "alive"
		if !w.alive[h.ID] {
			state = "silent"
		}
		mem, cpus, _, leases := w.committed(h.ID)
		fmt.Printf("%-10s %-6s %-9d %-10s %s\n", short8(h.ID), state, leases, fmt.Sprintf("%dM/%.1f", mem>>20, cpus), strings.Join(h.Labels, ","))
	}
	counts, short := w.wanted()
	fmt.Printf("\n%-16s %-5s %-10s %-5s %-8s %-10s %-9s %s\n", "CELL", "SLOT", "HOST", "TERM", "STATE", "RELEASE", "DRAW", "STANDBY")
	for _, cell := range slices.Sorted(maps.Keys(counts)) {
		for i := 0; i < counts[cell]; i++ {
			s := w.slot(cell, i)
			if s.lease == nil {
				fmt.Printf("%-16s %-5d %-10s %-5s %-8s\n", cell, i, "-", "-", "vacant")
				continue
			}
			state, running := "alive", s.lease.Seal
			if !w.held(s) {
				state = "lapsed"
			}
			if s.pulse != nil {
				running = s.pulse.Seal
			}
			release := "current"
			switch info := w.infos[cell]; {
			case running != info.Seal:
				release = "previous"
			case info.Newest != info.Seal:
				release = "held back" // on the newest release that works; a newer one failed to come up
			}
			draw := fmt.Sprintf("%d", s.lease.Round)
			if !s.lease.Proven {
				draw += "?"
			}
			standby := ""
			if u := w.understudy(cell, i); u != "" {
				standby = short8(u) + " " + t.cell(cell).Standby
			}
			fmt.Printf("%-16s %-5d %-10s %-5d %-8s %-10s %-9s %s\n", cell, i, short8(s.lease.Host), s.lease.Term, state, release, draw, standby)
		}
	}
	for _, s := range short {
		fmt.Println("\nshort:", s)
	}
	fmt.Println("\nA draw is the beacon round that decided the host; \"?\" marks one made while the beacon could not be reached.")
	return nil
}
