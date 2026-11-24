package main

import (
	"math/rand/v2"
	"time"
)

// pickBackend chooses which replica gets the next connection on a published
// port. active[i] is how many connections replica i is carrying now; turn is
// a counter the caller keeps. It returns the replicas in the order to try
// them, so a replica that is not accepting yet is passed over.
//
//	least-connections  the replica carrying the fewest now (ties taken in turn)
//	round-robin        each replica in turn
//	random             any replica
func pickBackend(mode string, active []int64, turn uint64) []int {
	n := len(active)
	order := make([]int, n)
	if n == 0 {
		return order
	}
	start := int(turn % uint64(n))
	if mode == "random" {
		start = rand.IntN(n)
	}
	for i := range order {
		order[i] = (start + i) % n
	}
	if mode == "" || mode == "least-connections" {
		// A stable sort on the rotated order: equal loads keep taking turns.
		for i := 1; i < n; i++ {
			for j := i; j > 0 && active[order[j]] < active[order[j-1]]; j-- {
				order[j], order[j-1] = order[j-1], order[j]
			}
		}
	}
	return order
}

// hostLoad is what one host tells the fleet about a capsule it is scaling.
type hostLoad struct {
	Host     string  `json:"host"` // id, also the tie-breaker
	Replicas int     `json:"replicas"`
	Min      int     `json:"min"`
	Max      int     `json:"max"`
	CPU      float64 `json:"cpu"` // average percent of limit across its replicas
}

// fleetAverage is the CPU average over every replica in the fleet, and how many there are.
func fleetAverage(view []hostLoad) (average float64, replicas int) {
	total := 0.0
	for _, h := range view {
		total += h.CPU * float64(h.Replicas)
		replicas += h.Replicas
	}
	if replicas == 0 {
		return 0, 0
	}
	return total / float64(replicas), replicas
}

// growTurn names the host that should add the next replica: the one with
// the fewest that still has room. Every host works this out from the same
// view and only the named host acts, so replicas spread evenly and two
// hosts do not both jump at once. It returns "" if nobody has room.
func growTurn(view []hostLoad) string {
	turn, fewest := "", 0
	for _, h := range view {
		if h.Replicas >= h.Max {
			continue
		}
		if turn == "" || h.Replicas < fewest || (h.Replicas == fewest && h.Host < turn) {
			turn, fewest = h.Host, h.Replicas
		}
	}
	return turn
}

// shrinkTurn names the host that should remove a replica: the one with the
// most, as long as the fleet keeps at least its floor. It returns "" if the
// fleet is already at its floor.
func shrinkTurn(view []hostLoad) string {
	floor, total := 0, 0
	for _, h := range view {
		floor += h.Min
		total += h.Replicas
	}
	if total <= max(floor, 1) { // a fleet never scales itself down to nothing
		return ""
	}
	turn, most := "", 0
	for _, h := range view {
		if h.Replicas <= h.Min {
			continue
		}
		if turn == "" || h.Replicas > most || (h.Replicas == most && h.Host > turn) {
			turn, most = h.Host, h.Replicas
		}
	}
	return turn
}

// Health checks on the mesh open a real connection to an instance, which the
// instance's application sees. So one is made only when nothing cheaper says
// the instance is serving.
const (
	probeFast = 2 * time.Second  // an instance that is down, or one we are sending to
	probeSlow = 30 * time.Second // an idle, healthy instance
)

// probeState is what is remembered about one instance between looks.
type probeState struct {
	Next   time.Time     // when a check is next due
	Every  time.Duration // the current gap between checks
	Rx, Tx uint64        // bytes received from and sent to it over the tunnel, at the last look
}

// needProbe decides whether to check an instance with a connection now.
// rx and tx are the tunnel's byte counts for it; open says this capsule has a
// connection to it that is still open; accepted says it accepted a new
// connection of ours since the last look.
func needProbe(st *probeState, now time.Time, rx, tx uint64, open, accepted bool) bool {
	rxMoved, txMoved := rx != st.Rx, tx != st.Tx
	st.Rx, st.Tx = rx, tx
	switch {
	case accepted, open && rxMoved:
		// Proof enough that it is serving: it has just taken a connection of
		// ours, or it is answering on one. No need to open another to ask.
		st.Every, st.Next = probeFast, now.Add(probeFast)
		return false
	case txMoved && !rxMoved:
		return true // we are sending to it and nothing is coming back
	}
	return !now.Before(st.Next)
}

// probed records the result of a check and sets when the next one is due:
// soon if the instance is down or in use, at a lengthening gap while it is
// healthy and idle.
func probed(st *probeState, now time.Time, up, inUse bool) {
	if !up || inUse {
		st.Every = probeFast
	} else {
		st.Every = min(max(st.Every, probeFast)*2, probeSlow)
	}
	st.Next = now.Add(st.Every)
}
