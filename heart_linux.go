package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A tissue's passes come every few seconds, which is too slow for a cell
// that must not be missed. So the supervisors of a cell's instances also
// watch each other directly: a datagram over the mesh every few
// milliseconds. When the standby stops hearing the holder, it promotes
// itself at once, by writing its new role where the application reads it,
// and the tissue catches up with the lease on its next pass.
//
// The tissue's side of this is a small directory it keeps for each cell it
// runs here, which the supervisor is given and the capsule sees at
// /run/capsule:
//
//	role    "holder" or "standby", written by the tissue; "holder promoted"
//	        when the supervisor steps up by itself
//	detect  how long a silence means the other is gone, in milliseconds
//	until   for a strict cell: the moment its lease can no longer be
//	        trusted, in Unix seconds. Past it, the supervisor stops the capsule

// heartbeatEvery returns how long a silence counts as a failure, or 0 if this run does not watch its peers.
func heartbeatEvery(state string) time.Duration {
	if state == "" {
		return 0
	}
	ms, err := strconv.Atoi(strings.TrimSpace(readText(filepath.Join(state, "detect"))))
	if err != nil || ms < 10 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func writeRole(state, role string) error {
	tmp := filepath.Join(state, ".role")
	if err := os.WriteFile(tmp, []byte(role+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(state, "role")) // whole or not at all, for whoever is reading
}

// startHeart sends this instance's heartbeat to the other instances of its
// cell and listens for theirs.
func startHeart(ms *mesh, state string, detect time.Duration) error {
	listen := net.ListenConfig{Control: markSocket}
	var conn net.PacketConn
	if err := inNetns(ms.ns, func() (err error) {
		conn, err = listen.ListenPacket(nil, "udp6", net.JoinHostPort(ms.id.addr.String(), strconv.Itoa(pulsePort())))
		return
	}); err != nil {
		return err
	}
	var mu sync.Mutex
	heard := map[string]time.Time{}
	go func() {
		buf := make([]byte, 16)
		for {
			_, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Only an instance of this same cell can reach this port, and only through its tunnel.
			if from := src.(*net.UDPAddr); ms.caller(from.IP) == ms.name {
				mu.Lock()
				heard[from.IP.String()] = time.Now()
				mu.Unlock()
			}
		}
	}()
	go func() {
		interval := max(detect/5, 2*time.Millisecond)
		for range time.Tick(interval) {
			for _, addr := range ms.instancesOf(ms.name) {
				conn.WriteTo([]byte{1}, &net.UDPAddr{IP: addr, Port: pulsePort()})
			}
			if !strings.HasPrefix(readText(filepath.Join(state, "role")), "standby") {
				continue
			}
			mu.Lock()
			for addr, last := range heard {
				if silence := time.Since(last); silence > detect {
					delete(heard, addr) // step up once for one loss; the tissue takes it from here
					if err := writeRole(state, "holder promoted"); err == nil {
						fmt.Fprintf(os.Stderr, "capsule: the holder of %s has been silent for %s; this standby has taken over\n", ms.name, silence.Round(time.Millisecond))
						appendLog(logEntry{Event: "tissue", Capsule: ms.name, Detail: fmt.Sprintf("standby took over after %s of silence from the holder", silence.Round(time.Millisecond))})
					}
				}
			}
			mu.Unlock()
		}
	}()
	return nil
}

// keepLease stops a strict cell when its lease can no longer be trusted.
// It runs in the supervisor, so it holds even if nothing else on the host
// is running any more: the tissue's passes move the moment forward, and if
// they stop coming, the capsule stops with them.
func keepLease(state, cgroup, name string) {
	for range time.Tick(250 * time.Millisecond) {
		text := strings.TrimSpace(readText(filepath.Join(state, "until")))
		if text == "" {
			continue // not a strict cell, or not yet told
		}
		until, err := strconv.ParseInt(text, 10, 64)
		if err == nil && time.Now().Unix() > until {
			fmt.Fprintf(os.Stderr, "capsule: stopping %s: its lease has run out and was not renewed, and it must never run twice\n", name)
			appendLog(logEntry{Event: "tissue", Capsule: name, Detail: "stopped by its supervisor: lease ran out (strict)"})
			killCgroup(cgroup)
			return
		}
	}
}
