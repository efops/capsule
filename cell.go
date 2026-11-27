package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A cell is a capsule whose only way in or out is a set of named openings,
// its receptors. The application never addresses another machine or opens a
// port to the mesh: it is handed a socket for each thing it needs, and its
// supervisor answers for each thing it offers. Which cell may use which
// receptor is in the sealed manifest; an offer can further demand a signed
// grant that is good only for a span of ticks.

// Offer is a service this cell gives to the named cells.
type Offer struct {
	Name string   `json:"name"`
	To   []string `json:"to"` // the cells that may use it
	// Port is where the application listens. Without it, the application
	// listens on the socket /run/cell/offer/<name>.
	Port          int  `json:"port,omitempty"`
	UDP           bool `json:"udp,omitempty"`            // datagrams instead of a stream; needs port
	Grant         bool `json:"grant,omitempty"`          // callers must also hold a signed grant that is in date
	ProxyProtocol bool `json:"proxy_protocol,omitempty"` // tell the application who is calling, with a PROXY protocol line
}

// direct reports whether the kernel can hand this offer's traffic to the
// application by itself: the application has a port, and nothing has to be
// checked or added per connection beyond who is calling, which the firewall
// knows from the caller's address.
func (o Offer) direct() bool { return o.Port != 0 && !o.Grant && !o.ProxyProtocol }

// Need is a service this cell uses, offered under the same name by another cell.
type Need struct {
	Name string `json:"name"`
	From string `json:"from"` // the cell that offers it
	// The application connects to the socket /run/cell/need/<name>. With
	// Port, the need's name also resolves to an address where that port
	// leads to the offering cell, for software that speaks TCP or UDP.
	Port    int    `json:"port,omitempty"`
	UDP     bool   `json:"udp,omitempty"`     // datagrams instead of a stream; needs port
	Balance string `json:"balance,omitempty"` // as for a mesh peer
}

// socketsOnly reports whether the capsule is a cell whose every opening is
// a socket file. Such a program has no use for network sockets at all, so
// it is not allowed to create any.
func (m Manifest) socketsOnly() bool {
	if m.Network != "cell" || len(m.Publish)+len(m.Egress) > 0 {
		return false
	}
	for _, o := range m.Offers {
		if o.Port != 0 {
			return false
		}
	}
	for _, n := range m.Needs {
		if n.Port != 0 {
			return false
		}
	}
	return true
}

// receptorPort is where a receptor is carried on the mesh. It is derived
// from the name, so both ends agree on it and nobody has to choose one.
func receptorPort(name string) int {
	sum := sha256.Sum256([]byte("capsule-receptor-v1\x00" + name))
	return 10000 + int(binary.BigEndian.Uint16(sum[:2]))%50000
}

// controlPort is where a cell's supervisor hears from the supervisors of
// cells that call it. Its label cannot be a receptor's name.
func controlPort() int { return receptorPort("\x00control") }

// pulsePort is where the supervisors of one cell's instances listen for each other's heartbeat.
func pulsePort() int { return receptorPort("\x00pulse") }

// cellPeers turns offers and needs into the mesh's terms: who this cell
// exchanges packets with, and on which receptor ports.
func cellPeers(m Manifest) []Peer {
	var peers []Peer
	find := func(name string) *Peer {
		for i := range peers {
			if peers[i].Name == name {
				return &peers[i]
			}
		}
		peers = append(peers, Peer{Name: name})
		return &peers[len(peers)-1]
	}
	for _, n := range m.Needs {
		p := find(n.From)
		if !slices.Contains(p.OutUDP, controlPort()) {
			p.OutUDP = append(p.OutUDP, controlPort())
		}
		if n.UDP {
			p.OutUDP = append(p.OutUDP, receptorPort(n.Name))
		} else {
			p.Out = append(p.Out, receptorPort(n.Name))
		}
		if n.Balance != "" {
			p.Balance = n.Balance
		}
	}
	for _, o := range m.Offers {
		for _, to := range o.To {
			p := find(to)
			if !slices.Contains(p.InUDP, controlPort()) {
				p.InUDP = append(p.InUDP, controlPort())
			}
			if o.UDP {
				p.InUDP = append(p.InUDP, receptorPort(o.Name))
			} else {
				p.In = append(p.In, receptorPort(o.Name))
			}
		}
	}
	return peers
}

// A tick is one round of the drand beacon: three seconds. Counting time in
// ticks gives every host the same clock, and one that can be checked: a
// round's signature cannot exist before its time, so a host that has seen
// round N knows it is at least that late, whatever its own clock says.
const (
	tickGenesis = 1692803367 // the quicknet chain's first round, in Unix time
	tickPeriod  = 3 * time.Second
	tickSkew    = 20 // a grant is accepted this many ticks (a minute) before it starts
)

func clockTick(t time.Time) uint64 {
	if t.Unix() < tickGenesis {
		return 0
	}
	return uint64((t.Unix()-tickGenesis)/int64(tickPeriod/time.Second)) + 1
}

// ticker tells the current tick. It asks the beacon for its latest round and
// checks the signature; between askings it counts forward on the monotonic
// clock, which setting the host's time does not move. If the beacon cannot
// be reached it falls back on the host's clock, and says so.
type ticker struct {
	mu     sync.Mutex
	base   uint64    // a round the beacon has signed
	at     time.Time // when it was fetched
	tried  time.Time
	asking bool
	floor  uint64 // the tick is never below this
}

func (t *ticker) now() (tick uint64, proven bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	wait := 5 * time.Minute
	if t.base == 0 {
		wait = 30 * time.Second
	}
	switch {
	case t.tried.IsZero(): // the first asking is waited for
		t.tried = time.Now()
		if round, err := latestRound(); err == nil {
			t.base, t.at = round, time.Now()
		}
	case time.Since(t.tried) > wait && !t.asking:
		// Later ones happen on the side: whoever wants the tick now gets
		// the count carried forward, not a pause while the beacon answers.
		t.tried, t.asking = time.Now(), true
		go func() {
			round, err := latestRound()
			t.mu.Lock()
			if err == nil {
				t.base, t.at = round, time.Now()
			}
			t.asking = false
			t.mu.Unlock()
		}()
	}
	if t.floor == 0 {
		t.floor = readTickFloor()
	}
	if t.base != 0 {
		tick = t.base + uint64(time.Since(t.at)/tickPeriod)
		// Remember the latest tick the beacon has proven, about once a
		// minute, for the day the beacon cannot be reached.
		if tick > t.floor+20 {
			t.floor = tick
			writeTickFloor(tick)
		}
		return tick, true
	}
	// No beacon. The host's clock stands in, but it may not go back past
	// the last tick the beacon proved here or the last one handed out: a
	// clock set back does not make an expired grant good again.
	tick = max(clockTick(time.Now()), t.floor)
	t.floor = tick
	return tick, false
}

func tickFloorPath() string { return filepath.Join(dataDir(), "tick") }

func readTickFloor() uint64 {
	raw, _ := os.ReadFile(tickFloorPath())
	n, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return n
}

func writeTickFloor(tick uint64) {
	path := tickFloorPath()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, []byte(strconv.FormatUint(tick, 10)+"\n"), 0o600) == nil {
		os.Rename(tmp, path)
	}
}

type beacon struct {
	Round     uint64 `json:"round"`
	signature []byte
}

func (b beacon) GetRound() uint64             { return b.Round }
func (b beacon) GetSignature() []byte         { return b.signature }
func (b beacon) GetPreviousSignature() []byte { return nil }

// latestRound returns the newest round the beacon has published, having
// checked its signature against the chain's key.
func latestRound() (uint64, error) {
	network, err := drandNetwork()
	if err != nil {
		return 0, err
	}
	hosts := drandHosts
	if h := os.Getenv("CAPSULE_DRAND"); h != "" {
		hosts = strings.Split(h, ",")
	}
	var last error
	client := http.Client{Timeout: 5 * time.Second}
	for _, host := range hosts {
		var b beacon
		resp, err := client.Get(host + "/" + drandChain + "/public/latest")
		if err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			err = json.Unmarshal(raw, &b)
		}
		if err == nil && b.Round == 0 {
			err = errors.New("no round in the beacon's answer")
		}
		if err == nil {
			b.signature, err = network.Signature(b.Round)
		}
		if err == nil {
			scheme := network.Scheme()
			err = scheme.VerifyBeacon(b, network.PublicKey())
		}
		if err == nil {
			return b.Round, nil
		}
		last = err
	}
	return 0, fmt.Errorf("cannot get a signed round from the drand network: %w", last)
}

func cmdTick(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: capsule tick")
	}
	tick, proven := new(ticker).now()
	source := "signed by the drand beacon"
	if !proven {
		source = "from this host's clock, and never earlier than the last tick the beacon proved here: the drand beacon could not be reached"
	}
	fmt.Printf("%d  (%s)\n", tick, source)
	return nil
}

// grant lets one cell use one receptor of another for a span of ticks. It is
// signed by a key the offering host trusts. It names cells, not machines:
// which keys are instances of a cell is what signed cards say.
type grant struct {
	Receptor  string `json:"receptor"`
	Of        string `json:"of"` // the cell that offers it
	To        string `json:"to"` // the cell that may use it
	From      uint64 `json:"from"`
	Until     uint64 `json:"until"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

func (g grant) message() []byte {
	return []byte("capsule-grant-v1\n" + g.Receptor + "\n" + g.Of + "\n" + g.To + "\n" +
		strconv.FormatUint(g.From, 10) + "\n" + strconv.FormatUint(g.Until, 10) + "\n")
}

// check says why the grant does not let caller use receptor of the cell named of at this tick, or nil if it does.
func (g grant) check(trusted trustSet, receptor, of, caller string, tick uint64) error {
	switch {
	case !signedBy(trusted, g.Signer, g.Signature, g.message()):
		return errors.New("the grant is not signed by a trusted key")
	case g.Receptor != receptor || g.Of != of || g.To != caller:
		return errors.New("the grant is for something else")
	case tick+tickSkew < g.From:
		return errors.New("the grant is not valid yet")
	case tick > g.Until:
		return errors.New("the grant has expired")
	}
	return nil
}

func grantsDir() string { return filepath.Join(configDir(), "grants.d") }

// findGrant returns, encoded for sending, the grant in dir for this use that
// lasts longest, or "-" if there is none. It is read afresh for each
// connection, so a renewed grant takes effect without a restart.
func findGrant(dir, receptor, of, to string, trusted trustSet) string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.grant"))
	var best grant
	var bestRaw []byte
	for _, f := range files {
		raw, err := os.ReadFile(f)
		var g grant
		if err != nil || json.Unmarshal(raw, &g) != nil || g.Receptor != receptor || g.Of != of || g.To != to ||
			!verifySig(g.Signer, g.Signature, g.message()) {
			continue
		}
		if bestRaw == nil || g.Until > best.Until {
			best = g
			bestRaw, _ = json.Marshal(g)
		}
	}
	if bestRaw == nil {
		return "-"
	}
	return b64.EncodeToString(bestRaw)
}

func cmdGrant(args []string) error {
	fl := flag.NewFlagSet("grant", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	receptor := fl.String("receptor", "", "the receptor's name")
	of := fl.String("of", "", "the cell that offers it")
	to := fl.String("to", "", "the cell that may use it")
	span := fl.Duration("for", 24*time.Hour, "how long the grant lasts from now")
	fl.Parse(args)
	if *keyPath == "" || fl.NArg() != 0 || !nameRE.MatchString(*receptor) || !nameRE.MatchString(*of) || !nameRE.MatchString(*to) || *span <= 0 {
		return errors.New("usage: capsule grant -key <file> -receptor <name> -of <cell> -to <cell> [-for 24h]")
	}
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	tick, proven := new(ticker).now()
	if !proven {
		fmt.Fprintln(os.Stderr, "capsule: warning: the drand beacon could not be reached; counting ticks from this host's clock")
	}
	g := grant{Receptor: *receptor, Of: *of, To: *to, From: tick, Until: tick + uint64(*span/tickPeriod), Signer: key.pub}
	g.Signature = key.sign(g.message())
	out, _ := json.MarshalIndent(g, "", "  ")
	fmt.Println(string(out))
	return nil
}
