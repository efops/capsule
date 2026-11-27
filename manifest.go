package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Manifest is capsule.json: everything the capsule is allowed to be and do.
type Manifest struct {
	Name     string            `json:"name"`
	Command  []string          `json:"command"`
	Env      map[string]string `json:"env,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Network  string            `json:"network,omitempty"`  // "none" (default), "host", "mesh" or "cell"
	Mesh     *Mesh             `json:"mesh,omitempty"`     // required when network is "mesh"
	Offers   []Offer           `json:"offers,omitempty"`   // network "cell": named services it gives to other cells
	Needs    []Need            `json:"needs,omitempty"`    // network "cell": named services it uses
	Policy   *Policy           `json:"policy,omitempty"`   // conditions that must hold before it runs
	Publish  []int             `json:"publish,omitempty"`  // TCP ports the host operator may expose with run -publish
	Egress   []Egress          `json:"egress,omitempty"`   // outside hosts it may connect to
	Unlock   []Stage           `json:"unlock,omitempty"`   // settings that switch on at a set time
	Volumes  []Volume          `json:"volumes,omitempty"`  // directories that persist between runs
	Scale    *Scale            `json:"scale,omitempty"`    // run as replicas that grow and shrink with load
	Syscalls []string          `json:"syscalls,omitempty"` // allow list; omitted means the default profile
	Limits   Limits            `json:"limits,omitempty"`
	Latency  *Latency          `json:"latency,omitempty"` // for programs where microseconds matter
}

// Latency asks capsule to stay out of the program's way once it has started.
type Latency struct {
	Cores      int  `json:"cores,omitempty"`       // whole cores of its own: pinned, shared with no other capsule, never throttled
	MemoryLock bool `json:"memory_lock,omitempty"` // let the program lock its memory in RAM (mlockall)
	Hugepages  bool `json:"hugepages,omitempty"`   // give it the host's huge pages at /dev/hugepages
	Nic        *Nic `json:"nic,omitempty"`         // a network interface of the host, handed over whole
	// Devices are device files of the host the capsule may open, such as
	// /dev/vfio/vfio for a network stack that bypasses the kernel.
	Devices []string `json:"devices,omitempty"`
}

// Nic is a host network interface moved into the capsule for as long as it runs.
type Nic struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"` // e.g. 10.0.0.5/24
	Gateway string `json:"gateway,omitempty"`
}

// Limits map directly onto cgroup v2 files.
type Limits struct {
	Memory string  `json:"memory,omitempty"` // memory.max, e.g. "64M"
	CPUs   float64 `json:"cpus,omitempty"`   // cpu.max, in cores
	Pids   int     `json:"pids,omitempty"`   // pids.max
}

// Mesh is the capsule's whole network: the services it may talk to and on
// which ports. A peer is a name, not a machine: which hosts currently run it
// comes from signed peer cards, so replicas come and go without resealing.
type Mesh struct {
	Peers []Peer `json:"peers"`
}

type Peer struct {
	Name   string `json:"name"`
	Out    []int  `json:"out,omitempty"` // TCP ports this capsule may connect to on the peer
	In     []int  `json:"in,omitempty"`  // TCP ports the peer may connect to on this capsule
	OutUDP []int  `json:"out_udp,omitempty"`
	InUDP  []int  `json:"in_udp,omitempty"`

	// Balance is how connections to this peer are spread over its instances:
	//   random       each connection to a random live instance (the default)
	//   round-robin  each live instance in turn
	//   sticky       always the same instance for this caller, while it lives
	//   failover     every caller uses the same one instance, moving on only when it dies
	//   least-connections  the instance holding the fewest of this caller's
	//                open connections (including ones still awaiting a reply),
	//                re-counted every two seconds
	Balance string `json:"balance,omitempty"`
}

// meshed reports whether the capsule has a place on the mesh.
func (m Manifest) meshed() bool { return m.Network == "mesh" || m.Network == "cell" }

// peers returns who the capsule exchanges packets with: as listed, or, for
// a cell, as its offers and needs imply.
func (m Manifest) peers() []Peer {
	if m.Network == "cell" {
		return cellPeers(m)
	}
	if m.Mesh == nil {
		return nil
	}
	return m.Mesh.Peers
}

func (p Peer) ports() []int {
	return slices.Concat(p.Out, p.In, p.OutUDP, p.InUDP)
}

// Volume is a directory that outlives the capsule. Everything else in a
// capsule is read-only or discarded when it stops; this is where state lives.
// It is kept on the host under the capsule's name, mounted without device
// files or setuid, and without execute permission unless exec is set.
// Volume contents are the application's own data and are not part of the seal.
type Volume struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Exec    bool   `json:"exec,omitempty"`
	Size    string `json:"size,omitempty"`    // a hard limit such as "10G"; the volume becomes its own filesystem (needs root)
	Encrypt bool   `json:"encrypt,omitempty"` // encrypt it at rest with a key that exists only on this host (needs size)
}

// Scale turns one capsule into a set of replicas on a host. Each replica has
// its own volumes and its own place on the mesh.
type Scale struct {
	Min       int    `json:"min"`                  // replicas always kept running
	Max       int    `json:"max"`                  // never more than this
	CPU       int    `json:"cpu,omitempty"`        // add a replica when average CPU stays above this percent of limits.cpus
	Cooldown  string `json:"cooldown,omitempty"`   // wait this long between changes (default 30s)
	MemoryMax string `json:"memory_max,omitempty"` // raise a replica's memory limit, up to this, when it nears it
	Restart   string `json:"restart,omitempty"`    // "always" (default), "on-failure" or "never": what to do when a replica exits
	Balance   string `json:"balance,omitempty"`    // for a published port: "least-connections" (default), "round-robin" or "random"
	Fleet     bool   `json:"fleet,omitempty"`      // scale with the other hosts running it, through the fleet ledger; min may then be 0
}

func (s *Scale) validate(m Manifest) error {
	switch {
	case s.Min < 0 || s.Max < 1 || s.Max < s.Min || (s.Min == 0 && !s.Fleet):
		return errors.New("scale: need 1 <= min <= max (min may be 0 only with fleet, for a host that takes overflow)")
	case s.Max > s.Min && (s.CPU < 1 || s.CPU > 100):
		return errors.New("scale: cpu must be a percentage from 1 to 100 when max is above min")
	case s.CPU < 0 || s.CPU > 100:
		return errors.New("scale: cpu must be a percentage from 1 to 100")
	}
	if !slices.Contains([]string{"", "always", "on-failure", "never"}, s.Restart) {
		return errors.New(`scale: restart must be "always", "on-failure" or "never"`)
	}
	if !slices.Contains([]string{"", "least-connections", "round-robin", "random"}, s.Balance) {
		return errors.New(`scale: balance must be "least-connections", "round-robin" or "random"`)
	}
	if s.Cooldown != "" {
		if d, err := time.ParseDuration(s.Cooldown); err != nil || d < 0 {
			return errors.New("scale: cooldown must be a duration such as 30s")
		}
	}
	if s.MemoryMax != "" {
		limit, err1 := parseSizeText(m.Limits.Memory)
		ceiling, err2 := parseSizeText(s.MemoryMax)
		if err1 != nil || err2 != nil || ceiling < limit {
			return errors.New("scale: memory_max needs limits.memory, and must not be below it")
		}
	}
	return nil
}

// parseSizeText reads sizes such as 512M or 2G.
func parseSizeText(s string) (int64, error) {
	unit := int64(1)
	if s != "" {
		switch s[len(s)-1] {
		case 'K', 'k':
			unit, s = 1<<10, s[:len(s)-1]
		case 'M', 'm':
			unit, s = 1<<20, s[:len(s)-1]
		case 'G', 'g':
			unit, s = 1<<30, s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("not a size such as 512M or 2G")
	}
	return n * unit, nil
}

// Egress is one outside host and TCP port. Inside the capsule the name
// resolves to a loopback address where the supervisor forwards to the real
// host, so TLS still runs end to end from the application.
type Egress struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Stage is a set of environment variables that apply once its time has come.
type Stage struct {
	At  time.Time         `json:"at"`
	Env map[string]string `json:"env"`
}

// egressAddrs gives each outside host its own loopback address inside the capsule.
func egressAddrs(m Manifest) map[string]net.IP {
	out := map[string]net.IP{}
	for _, e := range m.Egress {
		if _, ok := out[e.Host]; !ok {
			n := len(out)
			out[e.Host] = net.IPv4(127, 1, byte(n/250), byte(n%250+1))
		}
	}
	return out
}

var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

func validPort(p int) bool { return p >= 1 && p <= 65535 }

var nicRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func parseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("capsule.json: %w", err)
	}
	if err := m.validate(); err != nil {
		return m, fmt.Errorf("capsule.json: %w", err)
	}
	return m, nil
}

func (m Manifest) validate() error {
	switch {
	case !nameRE.MatchString(m.Name):
		return errors.New("name must match [a-z0-9][a-z0-9-]*")
	case len(m.Command) == 0:
		return errors.New("command is empty")
	}
	if m.Network != "cell" && len(m.Offers)+len(m.Needs) > 0 {
		return errors.New(`offers and needs apply only to network "cell"`)
	}
	switch m.Network {
	case "", "none", "host":
		if m.Mesh != nil {
			return errors.New(`mesh is set but network is not "mesh"`)
		}
	case "cell":
		if m.Mesh != nil {
			return errors.New(`a cell has offers and needs, not a mesh section`)
		}
		if err := m.validateCell(); err != nil {
			return err
		}
	case "mesh":
		if m.Mesh == nil {
			return errors.New(`network "mesh" needs a mesh section`)
		}
		for _, p := range m.Mesh.Peers {
			if !nameRE.MatchString(p.Name) {
				return errors.New("peer name must match [a-z0-9][a-z0-9-]*")
			}
			if !slices.Contains([]string{"", "random", "round-robin", "sticky", "failover", "least-connections"}, p.Balance) {
				return fmt.Errorf(`peer %s: balance must be "random", "round-robin", "sticky", "failover" or "least-connections"`, p.Name)
			}
			for _, port := range p.ports() {
				if !validPort(port) {
					return fmt.Errorf("peer %s: %d is not a port", p.Name, port)
				}
			}
		}
	default:
		return errors.New(`network must be "none", "host", "mesh" or "cell"`)
	}
	seenName, seenPath := map[string]bool{}, map[string]bool{}
	for _, v := range m.Volumes {
		clean := filepath.Clean(v.Path)
		reserved := clean == "/" || clean == "/proc" || clean == "/dev" || clean == "/tmp" ||
			strings.HasPrefix(clean, "/proc/") || strings.HasPrefix(clean, "/dev/") || strings.HasPrefix(clean, "/tmp/")
		switch {
		case !nameRE.MatchString(v.Name):
			return errors.New("volume name must match [a-z0-9][a-z0-9-]*")
		case !strings.HasPrefix(v.Path, "/") || clean != v.Path || reserved:
			return fmt.Errorf("volume %s: path %q must be a clean absolute path outside /proc, /dev and /tmp", v.Name, v.Path)
		case seenName[v.Name] || seenPath[clean]:
			return fmt.Errorf("volume %s: name or path is used twice", v.Name)
		case v.Encrypt && v.Size == "":
			return fmt.Errorf("volume %s: encrypt needs a size", v.Name)
		}
		if v.Size != "" {
			if n, err := parseSizeText(v.Size); err != nil || n < 16<<20 {
				return fmt.Errorf("volume %s: size must be at least 16M, written like 512M or 10G", v.Name)
			}
		}
		seenName[v.Name], seenPath[clean] = true, true
	}
	if l := m.Latency; l != nil {
		switch {
		case l.Cores < 0 || l.Cores > 1024:
			return errors.New("latency: cores is out of range")
		case l.Cores > 0 && m.Limits.CPUs > 0:
			return errors.New("latency: cores are dedicated and never throttled, so limits.cpus cannot also be set")
		case l.Cores > 0 && m.Scale != nil:
			return errors.New("latency: a capsule with dedicated cores cannot also have a scale section")
		}
		for _, d := range l.Devices {
			if !strings.HasPrefix(d, "/dev/") || filepath.Clean(d) != d || len(d) > 128 ||
				slices.Contains([]string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/hugepages", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"}, d) ||
				strings.HasPrefix(d, "/dev/hugepages/") || strings.HasPrefix(d, "/dev/fd/") {
				return fmt.Errorf("latency: %q is not a device file a capsule can be given", d)
			}
		}
		if n := l.Nic; n != nil {
			if !nicRE.MatchString(n.Name) {
				return errors.New("latency: nic.name is not an interface name")
			}
			if m.Network == "host" {
				return errors.New(`latency: a nic is handed to the capsule's own network, so network cannot be "host"`)
			}
			if n.Address != "" {
				if _, err := netip.ParsePrefix(n.Address); err != nil {
					return errors.New("latency: nic.address must look like 10.0.0.5/24")
				}
			}
			if n.Gateway != "" {
				if _, err := netip.ParseAddr(n.Gateway); err != nil || n.Address == "" {
					return errors.New("latency: nic.gateway must be an IP address, and needs nic.address")
				}
			}
		}
	}
	if m.Network == "host" && len(m.Publish)+len(m.Egress) > 0 {
		return errors.New(`publish and egress do not apply to network "host"`)
	}
	for _, port := range m.Publish {
		if !validPort(port) {
			return fmt.Errorf("publish: %d is not a port", port)
		}
	}
	for _, e := range m.Egress {
		if !hostnameRE.MatchString(e.Host) || e.Host == "localhost" || !validPort(e.Port) {
			return fmt.Errorf("egress: %s:%d is not a host name and port", e.Host, e.Port)
		}
	}
	if len(egressAddrs(m)) > 60000 {
		return errors.New("egress: too many hosts")
	}
	if m.Scale != nil {
		if err := m.Scale.validate(m); err != nil {
			return err
		}
	}
	if m.Policy != nil {
		if err := m.Policy.validate(); err != nil {
			return err
		}
	}
	for _, name := range m.Syscalls {
		if _, ok := syscallTable[name]; !ok {
			return fmt.Errorf("unknown syscall %q", name)
		}
	}
	return nil
}

func (m Manifest) validateCell() error {
	balances := []string{"", "random", "round-robin", "sticky", "failover", "least-connections"}
	carried := map[int]string{} // receptor names share a range of ports on the mesh
	local := map[string]bool{}
	carried[controlPort()] = "the cell's own control channel"
	offered, needed, balance := map[string]bool{}, map[string]bool{}, map[string]string{}
	for _, o := range m.Offers {
		switch {
		case !nameRE.MatchString(o.Name) || offered[o.Name]:
			return fmt.Errorf("offer %q: the name must match [a-z0-9][a-z0-9-]* and be used once", o.Name)
		case len(o.To) == 0:
			return fmt.Errorf("offer %s: say which cells it is offered to", o.Name)
		case o.Port != 0 && !validPort(o.Port):
			return fmt.Errorf("offer %s: %d is not a port", o.Name, o.Port)
		case o.UDP && (o.Port == 0 || o.ProxyProtocol):
			return fmt.Errorf("offer %s: udp needs a port, and cannot carry proxy_protocol", o.Name)
		}
		for _, to := range o.To {
			if !nameRE.MatchString(to) {
				return fmt.Errorf("offer %s: %q is not a cell name", o.Name, to)
			}
		}
		if other, clash := carried[receptorPort(o.Name)]; clash {
			return fmt.Errorf("offers %s and %s cannot be in one cell: their names map to the same place on the mesh; rename one", other, o.Name)
		}
		offered[o.Name], carried[receptorPort(o.Name)] = true, o.Name
	}
	for _, n := range m.Needs {
		switch {
		case !nameRE.MatchString(n.Name) || needed[n.Name]:
			return fmt.Errorf("need %q: the name must match [a-z0-9][a-z0-9-]* and be used once", n.Name)
		case !nameRE.MatchString(n.From):
			return fmt.Errorf("need %s: from must name the cell that offers it", n.Name)
		case !slices.Contains(balances, n.Balance):
			return fmt.Errorf(`need %s: balance must be "random", "round-robin", "sticky", "failover" or "least-connections"`, n.Name)
		case n.UDP && n.Port == 0:
			return fmt.Errorf("need %s: udp needs a port", n.Name)
		case n.Port != 0 && (!validPort(n.Port) || local[fmt.Sprint(n.From, n.Port, n.UDP)]):
			return fmt.Errorf("need %s: port %d is not a port, or is used for two needs from %s", n.Name, n.Port, n.From)
		}
		if n.Balance != "" {
			if had, ok := balance[n.From]; ok && had != n.Balance {
				return fmt.Errorf("needs from %s ask for different balance settings; a cell is balanced one way", n.From)
			}
			balance[n.From] = n.Balance
		}
		needed[n.Name] = true
		if n.Port != 0 {
			local[fmt.Sprint(n.From, n.Port, n.UDP)] = true
		}
	}
	if len(m.Offers)+len(m.Needs) == 0 {
		return errors.New(`network "cell" needs offers or needs`)
	}
	return nil
}

// loadManifest returns the parsed manifest and the exact bytes it was parsed from.
func loadManifest(dir string) (Manifest, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "capsule.json"))
	if err != nil {
		return Manifest{}, nil, err
	}
	m, err := parseManifest(raw)
	return m, raw, err
}
