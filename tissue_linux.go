package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// cmdTend is one host's pass over the tissue: say it is alive, read the
// world, and do its own part of the plan. It is run from the same timer as
// orders, holds nothing open afterwards, and talks to no other host: what
// the others are doing it reads from the ledger.
func cmdTend(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: capsule tend")
	}
	rules, err := loadOrderRules()
	if err != nil {
		return err
	}
	if len(rules.operators) == 0 {
		return nil // a host that obeys no one follows no tissue
	}
	me, err := hostID()
	if err != nil {
		return err
	}
	key, err := hostSigner()
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir(), "tissue")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil // an earlier pass is still at work
	}
	p := &tending{dir: dir, me: me, key: key, now: passTick(dir)}
	p.held = p.readHeld()
	l, err := openLedger()
	if err != nil {
		p.guard() // a ledger that cannot be used is a ledger that cannot be reached
		return err
	}
	if l == nil {
		return nil
	}
	p.l = l

	t, found, err := readTissue(l, &rules)
	if err != nil {
		p.guard()
		return err
	}
	if !found {
		return nil
	}
	// Never follow an older tissue than one already followed, whatever the ledger offers.
	seen, _ := strconv.ParseInt(strings.TrimSpace(readText(filepath.Join(dir, "seen"))), 10, 64)
	if t.Time < seen {
		return errors.New("the ledger offers an older tissue than the one this host follows; refusing to go back")
	}
	os.WriteFile(filepath.Join(dir, "seen"), []byte(strconv.FormatInt(t.Time, 10)+"\n"), 0o600)
	p.t = t
	if _, listed := t.host(me); !listed {
		p.stopAllBut(nil)
		return nil
	}
	if err := p.put("tissue/hosts/"+idHex(me), beat{Kind: "host"}); err != nil {
		p.guard()
		return err
	}
	if p.trusted, err = loadTrust(nil); err != nil {
		return err
	}
	w, err := readWorld(l, t, p.now, p.trusted)
	if err != nil {
		p.guard()
		return err
	}
	w.alive[me] = true
	keep := map[string]bool{}
	steps := w.plan(me)
	// Renew what is held before anything that can take time, so a slow start
	// of one cell never lets the leases of the others lapse.
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Do == "hold" && steps[j].Do != "hold" })
	for _, s := range steps {
		info := w.infos[s.Cell]
		switch s.Do {
		case "claim":
			b := p.sign(beat{Kind: "lease", Cell: s.Cell, Slot: s.Slot, Term: s.Term, Round: s.Round, Proven: s.Proven, Seal: info.Seal})
			raw, _ := json.Marshal(b)
			won, err := createOnce(l, leaseKey(s.Cell, s.Slot, s.Term), raw)
			if err != nil || !won {
				continue // another host took it, which is the draw working
			}
			keep[s.Cell] = true
			p.note("took %s slot %d (term %d) by the draw of round %d", s.Cell, s.Slot, s.Term, s.Round)
			if err := p.bringData(w, s); err != nil {
				p.note("could not bring the data of %s here, so not starting it: %v", s.Cell, err)
				continue
			}
			p.tell(w, s, "holder")
			if err := p.ensure(s.Cell, info.Seal); err != nil {
				p.note("could not start %s: %v", s.Cell, err)
				continue
			}
			p.pulse(w, s)
			if remover, ok := l.(interface{ remove(string) error }); ok && s.Term > 2 {
				remover.remove(leaseKey(s.Cell, s.Slot, s.Term-2)) // terms long superseded
			}
		case "hold":
			keep[s.Cell] = true
			p.tell(w, s, "holder")
			if err := p.ensure(s.Cell, ""); err != nil {
				p.note("could not start %s: %v", s.Cell, err)
				continue // no pulse: if this goes on, the lease lapses and another host takes over
			}
			p.pulse(w, s)
		case "renew":
			p.renew(w, s, info)
		case "ready":
			if _, err := fetchRelease(s.Cell, "", p.trusted, info.Seal); err != nil {
				p.note("could not keep %s ready: %v", s.Cell, err)
			}
		case "shadow":
			keep[s.Cell] = true
			p.tell(w, s, "standby")
			if err := p.ensure(s.Cell, info.Seal); err != nil {
				p.note("could not run %s as a standby: %v", s.Cell, err)
			}
		case "leave":
			// This host is being emptied. Stop the cell, send its data on, and give the slot up.
			h := p.held[s.Cell]
			if _, err := stopCapsule(s.Cell); err != nil {
				keep[s.Cell] = true
				p.note("could not stop %s to hand it over: %v", s.Cell, err)
				continue
			}
			if c := p.t.cell(s.Cell); c.interval() > 0 && len(info.Manifest.Volumes) > 0 {
				if err := p.ship(s.Cell, s.Slot, ""); err != nil {
					// Its data could not be sent on, so it stays, and keeps running here.
					keep[s.Cell] = true
					p.note("could not ship the data of %s, so it stays on this host: %v", s.Cell, err)
					p.ensure(s.Cell, "")
					p.pulse(w, s)
					continue
				}
			}
			h.Ships = false // shipped just now; nothing more to send when it is cleared away below
			p.held[s.Cell] = h
			p.put(pulseKey(s.Cell, s.Slot), beat{Kind: "pulse", Cell: s.Cell, Slot: s.Slot, Term: s.Term, Left: true})
			p.note("handed %s over: this host is being drained", s.Cell)
			appendLog(logEntry{Event: "tissue", Capsule: s.Cell, Detail: "handed over: this host is being drained"})
		case "ship":
			prev := ""
			if rec := w.shipped[fmt.Sprintf("%s/%d", s.Cell, s.Slot)]; rec != nil {
				prev = rec.Object
			}
			if err := p.ship(s.Cell, s.Slot, prev); err != nil {
				p.note("could not ship a snapshot of %s: %v", s.Cell, err)
			}
		case "want":
			p.put("tissue/want/"+s.Cell, beat{Kind: "want", Cell: s.Cell, Want: s.Want})
			p.note("%s should have %d more than its minimum", s.Cell, s.Want)
		}
	}
	p.stopAllBut(keep)
	for cell := range p.held {
		if !keep[cell] {
			delete(p.held, cell)
		}
	}
	p.writeHeld()
	return nil
}

// state is the directory through which this host tells a cell's supervisor,
// and the capsule itself, what the tissue says of it.
func (p *tending) state(cell string) string { return filepath.Join(p.dir, "state", cell) }

// tell records a cell's role here before it is started and on every pass. A
// standby that has promoted itself keeps that until the tissue either gives
// it the lease or has heard from the holder since.
func (p *tending) tell(w *world, s step, role string) {
	dir := p.state(s.Cell)
	os.MkdirAll(dir, 0o755)
	c := p.t.cell(s.Cell)
	if d, err := time.ParseDuration(c.Detect); err == nil {
		os.WriteFile(filepath.Join(dir, "detect"), []byte(strconv.FormatInt(d.Milliseconds(), 10)+"\n"), 0o644)
	} else {
		os.Remove(filepath.Join(dir, "detect"))
	}
	if c.Takeover != "strict" || role != "holder" {
		os.Remove(filepath.Join(dir, "until"))
	}
	file := filepath.Join(dir, "role")
	now := strings.TrimSpace(readText(file))
	if now == "holder promoted" && role == "standby" {
		if info, err := os.Stat(file); err == nil && w.slot(s.Cell, s.Slot).last() <= clockTick(info.ModTime())+1 {
			return // the holder has not been heard from since: the promotion stands
		}
	}
	if now != role && !(now == "holder promoted" && role == "holder") {
		writeRole(dir, role)
	}
}

func (p *tending) shippedMark(cell string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(readText(filepath.Join(p.dir, "shipped-"+cell))), 10, 64)
	return n
}

// ship sends a copy of a cell's volumes to the ledger's store, encrypted
// under a fresh key that is wrapped for every host of the tissue, so that
// whichever of them takes the cell next can restore it.
func (p *tending) ship(cell string, slot int, previous string) error {
	_, store, err := blobs()
	if err != nil {
		return err
	}
	snapshot, err := snapshotVolumes(cell, len(instancesNamed(cell)) > 0)
	if err != nil {
		return err
	}
	defer removeTree(snapshot)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	sealed, err := os.CreateTemp(p.dir, "ship-")
	if err != nil {
		return err
	}
	defer os.Remove(sealed.Name())
	err = encryptTree(snapshot, sealed, key)
	if cerr := sealed.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	sum, _, err := fileHash(sealed.Name())
	if err != nil {
		return err
	}
	b := beat{Kind: "ship", Cell: cell, Slot: slot, Sum: sum, Object: fmt.Sprintf("tissue/snapshots/%s/%03d/%d.enc", cell, slot, p.now)}
	for _, h := range p.t.Hosts {
		pub, err := b64.DecodeString(h.Key)
		if err != nil || len(pub) == 0 {
			continue
		}
		wrap, err := wrapKey(key, pub)
		if err != nil {
			return err
		}
		b.Wraps = append(b.Wraps, wrap)
	}
	if err := store.putFile(b.Object, sealed.Name()); err != nil {
		return err
	}
	if err := p.put(fmt.Sprintf("tissue/shipped/%s/%03d", cell, slot), b); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(p.dir, "shipped-"+cell), []byte(strconv.FormatUint(p.now, 10)+"\n"), 0o600)
	if remover, ok := p.l.(interface{ remove(string) error }); ok && previous != "" && previous != b.Object {
		remover.remove(previous)
	}
	p.note("shipped a snapshot of %s", cell)
	return nil
}

// bringData restores a cell's volumes from the latest snapshot before the
// cell is started on a host that does not have its newest data.
func (p *tending) bringData(w *world, s step) error {
	rec := w.shipped[fmt.Sprintf("%s/%d", s.Cell, s.Slot)]
	if rec == nil || len(w.infos[s.Cell].Manifest.Volumes) == 0 || p.t.cell(s.Cell).Snapshot == "" {
		return nil
	}
	if rec.Host == p.me && rec.Tick <= p.shippedMark(s.Cell) {
		return nil // the newest snapshot is this host's own: what is here is at least as new
	}
	if len(instancesNamed(s.Cell)) > 0 {
		return errors.New("it is running here already")
	}
	_, store, err := blobs()
	if err != nil {
		return err
	}
	box, err := hostBoxKey()
	if err != nil {
		return err
	}
	var key []byte
	for _, wrap := range rec.Wraps {
		if wrap.Host == p.me {
			if key, err = unwrapKey(wrap, box); err != nil {
				return err
			}
		}
	}
	if key == nil {
		return errors.New("the snapshot was not made out to this host")
	}
	sealed := filepath.Join(p.dir, "fetch-"+s.Cell)
	defer os.Remove(sealed)
	if err := store.getFile(rec.Object, sealed); err != nil {
		return err
	}
	if sum, _, err := fileHash(sealed); err != nil || sum != rec.Sum {
		return errors.New("the snapshot in the store is not the one its holder signed for")
	}
	name := fmt.Sprintf("tissue-%d", rec.Tick)
	unpacked := filepath.Join(dataDir(), "snapshots", s.Cell, name)
	removeTree(unpacked)
	defer removeTree(unpacked)
	if err := os.MkdirAll(filepath.Dir(unpacked), 0o700); err != nil {
		return err
	}
	f, err := os.Open(sealed)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := decryptTree(f, key, unpacked); err != nil {
		return fmt.Errorf("opening the snapshot: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir(), "volumes", s.Cell), 0o700); err != nil {
		return err
	}
	if err := restoreVolumes(s.Cell, name); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(p.dir, "shipped-"+s.Cell), []byte(strconv.FormatUint(rec.Tick, 10)+"\n"), 0o600)
	p.note("restored the data of %s from the snapshot of tick %d", s.Cell, rec.Tick)
	appendLog(logEntry{Event: "tissue", Capsule: s.Cell, Detail: fmt.Sprintf("restored volumes from the snapshot of tick %d", rec.Tick)})
	return nil
}

// infoSeal is the release of a cell the tissue runs, read afresh.
func (p *tending) infoSeal(cell string) string {
	info, err := releaseInfo(p.l, cell, p.trusted, nil)
	if err != nil {
		return ""
	}
	return info.Seal
}

type tending struct {
	l       ledger
	t       tissue
	dir     string
	me      string
	key     *signer
	now     uint64
	trusted trustSet
	held    map[string]heldCell
}

// heldCell is what this host remembers of a slot it holds, for the day the ledger cannot be reached.
type heldCell struct {
	Last   uint64 `json:"last"` // the tick of its last renewal that reached the ledger
	Lease  uint64 `json:"lease"`
	Strict bool   `json:"strict"`
	Slot   int    `json:"slot"`
	Ships  bool   `json:"ships"` // it keeps data that is shipped for a standby
}

func readText(path string) string {
	raw, _ := os.ReadFile(path)
	return string(raw)
}

// passTick is the current tick for a pass. The beacon is asked at most once
// in five minutes; between askings the count is carried forward on the
// host's clock, so a pass every few seconds does not lean on the beacon.
func passTick(dir string) uint64 {
	file := filepath.Join(dir, "tick")
	roundText, atText, _ := strings.Cut(strings.TrimSpace(readText(file)), " ")
	round, _ := strconv.ParseUint(roundText, 10, 64)
	at, _ := strconv.ParseInt(atText, 10, 64)
	if age := time.Now().Unix() - at; round > 0 && age >= 0 && age < 300 {
		return round + uint64(age)/uint64(tickPeriod/time.Second)
	}
	tick, proven := new(ticker).now()
	if proven {
		os.WriteFile(file, []byte(fmt.Sprintf("%d %d\n", tick, time.Now().Unix())), 0o600)
	}
	return tick
}

func (p *tending) note(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "capsule: tissue: "+format+"\n", args...)
}

func (p *tending) sign(b beat) beat {
	b.Host, b.Tick, b.Key = p.me, p.now, p.key.pub
	b.Signature = p.key.sign(b.message())
	return b
}

func (p *tending) put(key string, b beat) error {
	raw, _ := json.Marshal(p.sign(b))
	return p.l.put(key, raw)
}

// pulse renews a slot this host holds, saying which release it runs and how busy it is.
func (p *tending) pulse(w *world, s step) {
	seal := ""
	if sealed, err := readSeal(p.app(s.Cell)); err == nil {
		seal = sealed.id()
	}
	err := p.put(pulseKey(s.Cell, s.Slot), beat{Kind: "pulse", Cell: s.Cell, Slot: s.Slot, Term: s.Term, Seal: seal, Busy: p.busy(s.Cell, w.infos[s.Cell].Manifest)})
	if err != nil {
		p.note("could not renew %s: %v", s.Cell, err)
		return
	}
	c := p.t.cell(s.Cell)
	p.held[s.Cell] = heldCell{Last: p.now, Lease: p.t.lease(), Strict: c.Takeover == "strict", Slot: s.Slot,
		Ships: c.interval() > 0 && len(w.infos[s.Cell].Manifest.Volumes) > 0}
	if c.Takeover == "strict" {
		// The supervisor holds the capsule to this: past it, with no renewal, it stops the capsule itself.
		until := time.Now().Unix() + int64(p.t.lease())*int64(tickPeriod/time.Second) - int64(tickPeriod/time.Second)
		os.WriteFile(filepath.Join(p.state(s.Cell), "until"), []byte(strconv.FormatInt(until, 10)+"\n"), 0o644)
	}
}

func (p *tending) app(cell string) string { return filepath.Join(dataDir(), "apps", cell) }

// ensure makes sure the cell is running here. With a seal, that release is
// fetched first if it is not the one already here; without, whatever copy
// this host has is started as it is.
func (p *tending) ensure(cell, seal string) error {
	if len(instancesNamed(cell)) > 0 {
		return nil
	}
	if seal == "" {
		if _, err := readSeal(p.app(cell)); err != nil {
			seal = p.infoSeal(cell) // nothing here to start
		}
	}
	os.MkdirAll(p.state(cell), 0o755)
	_, err := startCapsuleUnit(cell, cellUnit(cell), seal != "", seal, "-tissue", p.state(cell))
	if err != nil {
		systemctl("stop", cellUnit(cell)) // do not leave systemd retrying what the next pass will decide afresh
		return err
	}
	p.manage(cell, true)
	appendLog(logEntry{Event: "tissue", Capsule: cell, Detail: "started for tissue " + p.t.Name})
	return nil
}

// renew moves a held slot to the current release. The new release is
// fetched and checked beside the old one; only then is the old one stopped.
// If the new one does not come up, the old one is put back and started, and
// the release is marked so that no other slot tries it.
func (p *tending) renew(w *world, s step, info cellInfo) {
	app, next, prev := p.app(s.Cell), p.app(s.Cell)+".next", p.app(s.Cell)+".prev"
	removeTree(next)
	if _, err := fetchRelease(s.Cell, next, p.trusted, info.Seal); err != nil {
		p.note("could not fetch the new release of %s: %v", s.Cell, err)
		return
	}
	if sealed, err := readSeal(next); err != nil || sealed.id() != info.Seal {
		removeTree(next)
		return // the release moved on again; the next pass sees the newer one
	}
	stopCapsule(s.Cell)
	removeTree(prev)
	if err := os.Rename(app, prev); err != nil {
		p.note("could not set the running release of %s aside: %v", s.Cell, err)
		startCapsuleUnit(s.Cell, cellUnit(s.Cell), false, "", "-tissue", p.state(s.Cell))
		return
	}
	err := os.Rename(next, app)
	if err == nil {
		_, err = startCapsuleUnit(s.Cell, cellUnit(s.Cell), false, "", "-tissue", p.state(s.Cell))
	}
	if err == nil {
		removeTree(prev)
		p.note("%s slot %d now runs release %s", s.Cell, s.Slot, info.Seal)
		appendLog(logEntry{Event: "tissue", Capsule: s.Cell, Seal: info.Seal, Detail: "moved to the new release"})
		p.pulse(w, s)
		return
	}
	p.note("the new release of %s did not come up (%v); going back to the one before", s.Cell, err)
	stopCapsule(s.Cell)
	removeTree(app)
	os.Rename(prev, app)
	raw, _ := json.Marshal(p.sign(beat{Kind: "halt", Cell: s.Cell, Seal: info.Seal}))
	p.l.create("tissue/halt/"+s.Cell+"/"+idHex(info.Seal), raw)
	appendLog(logEntry{Event: "tissue", Capsule: s.Cell, Seal: info.Seal, Detail: "the new release did not come up; held back for the whole tissue: " + err.Error()})
	if _, err := startCapsuleUnit(s.Cell, cellUnit(s.Cell), false, "", "-tissue", p.state(s.Cell)); err != nil {
		p.note("could not restart the previous release of %s: %v", s.Cell, err)
	}
}

// busy is the cell's CPU use since the last pass, as a percentage of what it may use.
func (p *tending) busy(cell string, m Manifest) int {
	var usage uint64
	for _, inst := range running() {
		if inst.name == cell {
			usage += cpuUsage(inst.cgroup)
		}
	}
	file := filepath.Join(p.dir, "cpu-"+cell)
	usedText, atText, _ := strings.Cut(strings.TrimSpace(readText(file)), " ")
	before, _ := strconv.ParseUint(usedText, 10, 64)
	at, _ := strconv.ParseInt(atText, 10, 64)
	now := time.Now().UnixMicro()
	os.WriteFile(file, []byte(fmt.Sprintf("%d %d\n", usage, now)), 0o600)
	_, cpus := cellSize(m)
	if cpus <= 0 {
		cpus = 1
	}
	if at == 0 || now <= at || usage < before {
		return 0
	}
	return min(int(float64(usage-before)/float64(now-at)/cpus*100), 100)
}

// The cells this host runs for the tissue are listed in a file, so that a
// pass only ever stops what an earlier pass started.
func (p *tending) managed() []string {
	return strings.Fields(readText(filepath.Join(p.dir, "managed")))
}

func (p *tending) manage(cell string, on bool) {
	list := slices.DeleteFunc(p.managed(), func(c string) bool { return c == cell })
	if on {
		list = append(list, cell)
	}
	os.WriteFile(filepath.Join(p.dir, "managed"), []byte(strings.Join(list, "\n")+"\n"), 0o600)
}

// stopAllBut stops every cell this host runs for the tissue and is no longer to.
func (p *tending) stopAllBut(keep map[string]bool) {
	for _, cell := range p.managed() {
		if keep[cell] || !nameRE.MatchString(cell) {
			continue
		}
		if _, err := stopCapsule(cell); err != nil {
			p.note("could not stop %s: %v", cell, err)
			continue
		}
		p.manage(cell, false)
		if h, was := p.held[cell]; was && h.Ships && p.l != nil {
			// Stopped, so the copy is exact: whoever takes the cell next starts from here.
			if err := p.ship(cell, h.Slot, ""); err != nil {
				p.note("could not ship a last snapshot of %s: %v", cell, err)
			}
		}
		p.note("stopped %s: this host no longer holds it", cell)
		appendLog(logEntry{Event: "tissue", Capsule: cell, Detail: "stopped: this host no longer holds it"})
	}
}

func (p *tending) readHeld() map[string]heldCell {
	held := map[string]heldCell{}
	json.Unmarshal([]byte(readText(filepath.Join(p.dir, "held"))), &held)
	return held
}

func (p *tending) writeHeld() {
	raw, _ := json.Marshal(p.held)
	os.WriteFile(filepath.Join(p.dir, "held"), raw, 0o600)
}

// guard is what a host does when the ledger cannot be reached. Most cells
// carry on: nothing can take their slots meanwhile either. A cell marked
// strict is stopped just before its lease would lapse, because from then on
// another host may be running it.
func (p *tending) guard() {
	for cell, h := range p.held {
		if h.Strict && p.now+1 >= h.Last+h.Lease && len(instancesNamed(cell)) > 0 {
			stopCapsule(cell)
			p.note("stopped %s: its lease could not be renewed, and it must never run twice", cell)
			appendLog(logEntry{Event: "tissue", Capsule: cell, Detail: "stopped: lease could not be renewed (strict)"})
		}
	}
}
