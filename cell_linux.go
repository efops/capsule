package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// cellMark is set on every socket the supervisor opens towards the mesh. In
// a cell the firewall lets the application send only to the receptors it
// needs by port; everything else that leaves must carry this mark, and the
// application, which has no capabilities, cannot set one.
const cellMark = 0x63656c6c

func markSocket(_, _ string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, cellMark) })
	return err
}

// meshDialer opens connections that a cell's firewall lets through.
func meshDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: markSocket}
}

// cell carries a running cell's receptors. It lives in the supervisor.
//
// Where both ends of a receptor are ports, the kernel carries the traffic
// and this process never sees it: the caller's firewall rewrites the
// connection to an instance of the offering cell, whose firewall admits it
// by the caller's address and hands it to the application. This process
// steps in only where something must be done per connection that the kernel
// cannot do: joining a socket file to the network, reaching an application
// that listens on IPv4 only, checking a grant, or announcing the caller.
//
// Grants travel separately. A calling cell's supervisor tells each instance
// it calls which grants it holds, over a control channel, at the start and
// whenever they change; the offering supervisor remembers until when each
// caller is covered.
type cell struct {
	m       Manifest
	ms      *mesh
	ns      *os.File
	dir     string // the host's side of /run/cell
	offers  *os.File
	grants  string
	trusted trustSet
	ticks   ticker
	control net.PacketConn

	mu       sync.Mutex
	covered  map[string]time.Time // "caller address receptor" -> when its grant runs out
	answers  map[string]string    // "instance address receptor" -> what that instance last said to our hello
	awaiting map[string]bool
	said     map[string]time.Time // complaints already made, so a repeated one is not repeated
}

// start opens every receptor. It runs before the application does, so the
// application finds its sockets waiting and cannot take a receptor's place.
func (c *cell) start() error {
	c.covered, c.answers, c.said = map[string]time.Time{}, map[string]string{}, map[string]time.Time{}
	for _, sub := range []string{"need", "offer"} {
		if err := os.MkdirAll(filepath.Join(c.dir, sub), 0o755); err != nil {
			return err
		}
	}
	var err error
	if c.offers, err = os.OpenFile(filepath.Join(c.dir, "offer"), unix.O_PATH|unix.O_DIRECTORY, 0); err != nil {
		return err
	}
	own := c.ms.id.addr.String()
	listen := net.ListenConfig{Control: markSocket}
	if err := inNetns(c.ns, func() (err error) {
		c.control, err = listen.ListenPacket(nil, "udp6", net.JoinHostPort(own, strconv.Itoa(controlPort())))
		return
	}); err != nil {
		return fmt.Errorf("control channel: %w", err)
	}
	go c.hear()
	for _, n := range c.m.Needs {
		if n.UDP {
			continue // by port only, which the kernel carries
		}
		path := filepath.Join(c.dir, "need", n.Name)
		l, err := net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("need %s: %w", n.Name, err)
		}
		os.Chmod(path, 0o666)
		go c.serveNeed(l, n)
	}
	for _, o := range c.m.Offers {
		addr := net.JoinHostPort(own, strconv.Itoa(receptorPort(o.Name)))
		if o.UDP {
			var l net.PacketConn
			if err := inNetns(c.ns, func() (err error) { l, err = net.ListenPacket("udp6", addr); return }); err != nil {
				return fmt.Errorf("offer %s: %w", o.Name, err)
			}
			go c.serveDatagrams(l, o)
			continue
		}
		var l net.Listener
		if err := inNetns(c.ns, func() (err error) { l, err = net.Listen("tcp6", addr); return }); err != nil {
			return fmt.Errorf("offer %s: %w", o.Name, err)
		}
		go c.serveOffer(l, o)
	}
	if slices.ContainsFunc(c.m.Offers, func(o Offer) bool { return o.Grant }) {
		c.ticks.now() // ask the beacon now, so the first caller's grant is not kept waiting on it
	}
	if len(c.m.Needs) > 0 {
		// Say hello before the application starts, and give the cells it
		// calls a moment to answer, so its first connection is expected.
		c.announce(time.Second)
		go c.keepAnnouncing()
	}
	return nil
}

func (c *cell) complain(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	c.mu.Lock()
	recent := time.Since(c.said[msg]) < time.Minute
	c.said[msg] = time.Now()
	c.mu.Unlock()
	if !recent {
		fmt.Fprintf(os.Stderr, "capsule: cell %s: %s\n", c.m.Name, msg)
	}
}

// ---- the control channel ----

// announce tells every instance this cell calls which receptors it means to
// use and what grant it holds for each. With wait, it returns once they have
// all answered or the time is up.
func (c *cell) announce(wait time.Duration) {
	awaiting := map[string]bool{}
	hellos := map[string][]byte{}
	for _, n := range c.m.Needs {
		token := findGrant(c.grants, n.Name, n.From, c.m.Name, c.trusted)
		for _, addr := range c.ms.instancesOf(n.From) {
			awaiting[addr.String()+" "+n.Name] = true
			hellos[addr.String()+" "+n.Name] = []byte("CELL2 " + n.Name + " " + token)
		}
	}
	c.mu.Lock()
	c.awaiting = awaiting
	c.mu.Unlock()
	end := time.Now().Add(wait)
	for sent := 0; ; sent++ {
		c.mu.Lock()
		for key := range c.awaiting { // whoever has not answered yet; a datagram can be lost
			addr, _, _ := strings.Cut(key, " ")
			c.control.WriteTo(hellos[key], &net.UDPAddr{IP: net.ParseIP(addr), Port: controlPort()})
		}
		left := len(c.awaiting)
		c.mu.Unlock()
		if left == 0 || !time.Now().Before(end) {
			return
		}
		time.Sleep(time.Duration(20<<min(sent, 3)) * time.Millisecond)
	}
}

// keepAnnouncing says hello again when the grants this host holds change,
// when the instances it calls change, and every half minute regardless.
func (c *cell) keepAnnouncing() {
	seen, last := "", time.Now()
	state := func() string {
		var b strings.Builder
		files, _ := filepath.Glob(filepath.Join(c.grants, "*.grant"))
		for _, f := range files {
			if st, err := os.Stat(f); err == nil {
				fmt.Fprintf(&b, "%s %d %d\n", f, st.Size(), st.ModTime().UnixNano())
			}
		}
		for _, n := range c.m.Needs {
			fmt.Fprintln(&b, c.ms.instancesOf(n.From))
		}
		return b.String()
	}
	seen = state()
	for range time.Tick(time.Second) {
		if now := state(); now != seen || time.Since(last) > 30*time.Second {
			seen, last = now, time.Now()
			c.announce(0)
		}
	}
}

// hear handles the control channel: hellos from cells that call this one, and answers to its own.
func (c *cell) hear() {
	buf := make([]byte, 65536)
	for {
		size, src, err := c.control.ReadFrom(buf)
		if err != nil {
			return
		}
		from := src.(*net.UDPAddr)
		caller := c.ms.caller(from.IP)
		word := strings.SplitN(string(buf[:size]), " ", 3)
		if len(word) < 2 {
			continue
		}
		key := from.IP.String() + " " + word[1]
		switch word[0] {
		case "CELL2": // a hello: "CELL2 <receptor> <grant or ->"
			if len(word) != 3 {
				continue
			}
			answer := "OK " + word[1]
			if why := c.admit(from.IP, caller, word[1], word[2]); why != nil {
				answer = "NO " + word[1] + " " + why.Error()
				c.complain("offer %s: refused %s (%s): %v", word[1], caller, from.IP, why)
			}
			c.control.WriteTo([]byte(answer), from)
		case "OK", "NO": // an answer to our hello
			said := strings.Join(word, " ")
			c.mu.Lock()
			changed := c.answers[key] != said
			c.answers[key] = said
			delete(c.awaiting, key)
			c.mu.Unlock()
			if changed && word[0] == "NO" && len(word) == 3 {
				c.complain("need %s: %s refused: %s", word[1], caller, word[2])
			}
		}
	}
}

// admit records what a hello entitles its sender to, or says why it is refused.
func (c *cell) admit(addr net.IP, caller, receptor, token string) error {
	i := slices.IndexFunc(c.m.Offers, func(o Offer) bool { return o.Name == receptor })
	key := addr.String() + " " + receptor
	switch {
	case i < 0 || !slices.Contains(c.m.Offers[i].To, caller):
		return errors.New("this receptor is not offered to you")
	case !c.m.Offers[i].Grant:
		return nil
	}
	left, err := c.checkGrant(token, receptor, caller)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		delete(c.covered, key)
		return err
	}
	c.covered[key] = time.Now().Add(left)
	return nil
}

// checkGrant returns how much longer the presented grant lets the caller use the receptor.
func (c *cell) checkGrant(token, receptor, caller string) (time.Duration, error) {
	if token == "-" {
		return 0, errors.New("this receptor needs a grant, and none was presented")
	}
	raw, err := b64.DecodeString(token)
	var g grant
	if err != nil || json.Unmarshal(raw, &g) != nil {
		return 0, errors.New("the grant is malformed")
	}
	tick, _ := c.ticks.now()
	if err := g.check(c.trusted, receptor, c.m.Name, caller, tick); err != nil {
		return 0, err
	}
	return time.Duration(g.Until-tick+1) * tickPeriod, nil
}

// allowed says how long the caller at addr may go on using an offer: zero or
// less if not at all, and a year if the offer asks for no grant.
func (c *cell) allowed(o Offer, addr net.IP) time.Duration {
	if !slices.Contains(o.To, c.ms.caller(addr)) {
		return 0
	}
	if !o.Grant {
		return 365 * 24 * time.Hour
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Until(c.covered[addr.String()+" "+o.Name])
}

// ---- connections this process carries ----

// serveNeed joins each connection the application makes to a need's socket
// file with one to a cell that offers it. The kernel picks the instance.
func (c *cell) serveNeed(l net.Listener, n Need) {
	target := net.JoinHostPort(serviceAddr(n.From).String(), strconv.Itoa(receptorPort(n.Name)))
	for {
		a, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer a.Close()
			var b net.Conn
			if err := inNetns(c.ns, func() (err error) { b, err = meshDialer(5*time.Second).Dial("tcp6", target); return }); err != nil {
				c.complain("need %s: cannot reach %s: %v", n.Name, n.From, err)
				return
			}
			defer b.Close()
			relay(a, b)
		}()
	}
}

// serveOffer answers for a receptor on the connections the kernel leaves to
// this process. The caller is known by its address, which only the holder of
// that cell's key can send from.
func (c *cell) serveOffer(l net.Listener, o Offer) {
	for {
		a, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer a.Close()
			from := a.RemoteAddr().(*net.TCPAddr)
			if c.allowed(o, from.IP) <= 0 {
				c.complain("offer %s: turned away %s (%s): it holds no grant in date", o.Name, c.ms.caller(from.IP), from.IP)
				return
			}
			b, err := c.reach(o)
			if err != nil {
				c.complain("offer %s: the application is not answering: %v", o.Name, err)
				return
			}
			defer b.Close()
			if o.ProxyProtocol {
				to := a.LocalAddr().(*net.TCPAddr)
				fmt.Fprintf(b, "PROXY TCP6 %s %s %d %d\r\n", from.IP, to.IP, from.Port, to.Port)
			}
			if o.Grant {
				// The connection lives no longer than its caller's grant. A
				// grant renewed in the meantime keeps it open.
				over := make(chan struct{})
				defer close(over)
				go func() {
					for {
						select {
						case <-over:
							return
						case <-time.After(c.allowed(o, from.IP)):
						}
						if c.allowed(o, from.IP) <= 0 {
							c.complain("offer %s: closing a connection from %s: its grant has run out", o.Name, c.ms.caller(from.IP))
							a.Close()
							b.Close()
							return
						}
					}
				}()
			}
			relay(a, b)
		}()
	}
}

// reach connects to the application behind an offer.
func (c *cell) reach(o Offer) (net.Conn, error) {
	if o.Port != 0 {
		return dialCapsule(c.ns, o.Port)
	}
	// The application made this socket, in a directory it controls. Open
	// whatever has that name without following links, make sure it is a
	// socket, and connect to that very file: a link planted there must not
	// lead this process, which runs on the host, to one of the host's sockets.
	fd, err := unix.Openat(int(c.offers.Fd()), o.Name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errors.New("not a socket")
	}
	return net.DialTimeout("unix", fmt.Sprintf("/proc/self/fd/%d", fd), 5*time.Second)
}

// serveDatagrams carries a datagram receptor's traffic to the application
// and back, a short-lived session per sender, for as long as that sender is
// allowed. A session idle for a minute is forgotten.
func (c *cell) serveDatagrams(mesh net.PacketConn, o Offer) {
	var mu sync.Mutex
	sessions := map[netip.AddrPort]net.Conn{}
	inside := net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port))
	buf := make([]byte, 65536)
	for {
		size, src, err := mesh.ReadFrom(buf)
		if err != nil {
			return
		}
		from := src.(*net.UDPAddr)
		if c.allowed(o, from.IP) <= 0 {
			c.complain("offer %s: turned away %s (%s): it holds no grant in date", o.Name, c.ms.caller(from.IP), from.IP)
			continue
		}
		key := from.AddrPort()
		mu.Lock()
		app := sessions[key]
		mu.Unlock()
		if app == nil {
			if err := inNetns(c.ns, func() (err error) { app, err = net.Dial("udp4", inside); return }); err != nil {
				continue
			}
			mu.Lock()
			sessions[key] = app
			mu.Unlock()
			go func() { // the application's answers, back to this sender
				defer func() {
					mu.Lock()
					delete(sessions, key)
					mu.Unlock()
					app.Close()
				}()
				reply := make([]byte, 65536)
				for {
					app.SetReadDeadline(time.Now().Add(time.Minute))
					size, err := app.Read(reply)
					if err != nil {
						return
					}
					mesh.WriteTo(reply[:size], from)
				}
			}()
		}
		app.Write(buf[:size])
	}
}
