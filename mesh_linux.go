package main

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// meshIdentity is one instance's WireGuard key on this host and the address derived from it.
type meshIdentity struct {
	key  wgtypes.Key
	addr net.IP
	kem  *mlkem.DecapsulationKey768
}

func (id *meshIdentity) kemKey() string {
	return b64.EncodeToString(id.kem.EncapsulationKey().Bytes())
}

// newMeshIdentity derives the key from the host secret, the capsule's name
// and an instance label, so an instance keeps its identity across runs and
// two replicas on one host get different ones.
func newMeshIdentity(name, instance string) (*meshIdentity, error) {
	raw, err := hostDerive("capsule-mesh-key-v1\x00" + name + "\x00" + instance)
	if err != nil {
		return nil, err
	}
	raw[0] &= 248 // Curve25519 private key form
	raw[31] = raw[31]&127 | 64
	key, err := wgtypes.NewKey(raw)
	if err != nil {
		return nil, err
	}
	var seed []byte
	for _, half := range []string{"a", "b"} {
		part, err := hostDerive("capsule-mesh-kem-v1\x00" + half + "\x00" + name + "\x00" + instance)
		if err != nil {
			return nil, err
		}
		seed = append(seed, part...)
	}
	kem, err := mlkem.NewDecapsulationKey768(seed[:mlkem.SeedSize])
	if err != nil {
		return nil, err
	}
	pub := key.PublicKey()
	return &meshIdentity{key: key, addr: meshAddr(pub[:]), kem: kem}, nil
}

func cmdIdentity(args []string) error {
	fl := flag.NewFlagSet("identity", flag.ExitOnError)
	instance := fl.String("instance", "", "instance label, as passed to run")
	fl.Parse(args)
	if fl.NArg() != 1 || !nameRE.MatchString(fl.Arg(0)) {
		return errors.New("usage: capsule identity [-instance <label>] <name>")
	}
	id, err := newMeshIdentity(fl.Arg(0), *instance)
	if err != nil {
		return err
	}
	fmt.Printf("key      %s\naddress  %s\nkem      %s\n", id.key.PublicKey(), id.addr, id.kemKey())
	return nil
}

func hostBits(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// mesh is a running capsule's network. The capsule's only interface is a
// WireGuard device whose encrypted socket lives in the host namespace, so
// everything it sends or receives is authenticated by key. Which keys are
// peers, and which ports each may use, is recomputed from the sealed manifest
// and the signed cards whenever the cards change.
type mesh struct {
	id        *meshIdentity
	name      string
	peers     []Peer
	cards     string
	trusted   trustSet
	ns        *os.File
	wg        tunnel
	user      bool           // no root: the tunnel runs in this process
	userDev   *device.Device // that tunnel
	nft       *nftables.Conn // without root: a firewall connection opened inside the capsule's network
	current   map[wgtypes.Key]bool
	instances map[string][]net.IP // peer name -> addresses of its instances
	down      map[string]bool     // instance addresses that failed their last check
	nl        *netlink.Handle     // netlink inside the capsule's namespace
	open      map[string]int      // this capsule's established connections, per instance address
	leastSeen string              // which instances were least loaded when the firewall was last built
	probes    map[string]*probeState
	flows     map[string]bool // connections seen at the last look, to tell new ones apart
	accepted  map[string]bool // instances that accepted a new connection of ours since the last look
	traffic   map[string][2]uint64
	seen      string
	ownCard   string

	listed  bool // this instance's own card says where to reach it
	running bool // past its start: the application may be sending
	psks    map[wgtypes.Key]*pskState
	epoch   uint64
	closed  atomic.Bool // the capsule has ended; the watcher has nothing left to keep current

	// cell: the application may send only to the receptors it needs by
	// port; anything else that leaves must come from the supervisor.
	cell       bool
	cellNeeds  []Need         // needs with a port: the kernel carries them
	cellOffers []Offer        // offers the kernel may deliver to the application itself
	lands      map[string]int // "tcp <receptor port>" -> the application's port, for offers delivered that way now
	mu         sync.Mutex
	who        map[string]string // instance address -> the name of the peer it is an instance of
}

// instancesOf returns the addresses of a peer's known instances.
func (ms *mesh) instancesOf(name string) []net.IP {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	var out []net.IP
	for addr, peer := range ms.who {
		if peer == name {
			out = append(out, net.ParseIP(addr))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// landing reports which offers the kernel can deliver to the application by
// itself right now: those it is listening for on every address, which
// includes this cell's address on the mesh. An application that listens on
// IPv4 only, or has not started listening yet, is reached by the supervisor.
func (ms *mesh) landing() (changed bool) {
	if len(ms.cellOffers) == 0 {
		return false
	}
	listening := map[string]bool{}
	inNetns(ms.ns, func() error {
		for proto, file := range map[string]string{"tcp": "tcp6", "udp": "udp6"} {
			raw, _ := os.ReadFile("/proc/thread-self/net/" + file)
			for _, line := range strings.Split(string(raw), "\n") {
				f := strings.Fields(line)
				if len(f) < 4 || (proto == "tcp" && f[3] != "0A") { // 0A: a listening socket
					continue
				}
				addr, port, _ := strings.Cut(f[1], ":")
				if n, err := strconv.ParseUint(port, 16, 16); err == nil && strings.Trim(addr, "0") == "" {
					listening[fmt.Sprint(proto, " ", n)] = true
				}
			}
		}
		return nil
	})
	next := map[string]int{}
	for _, o := range ms.cellOffers {
		proto := "tcp"
		if o.UDP {
			proto = "udp"
		}
		if listening[fmt.Sprint(proto, " ", o.Port)] {
			next[fmt.Sprint(proto, " ", receptorPort(o.Name))] = o.Port
		}
	}
	changed = fmt.Sprint(next) != fmt.Sprint(ms.lands)
	ms.lands = next
	return changed
}

// caller names the peer an address belongs to, or "" if it is nobody's.
func (ms *mesh) caller(addr net.IP) string {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.who[addr.String()]
}

// attach creates the device in the host namespace, moves it into the
// capsule's, and applies the first policy.
func (ms *mesh) attach(ns *os.File, listen int, advertise string) error {
	ms.ns = ns
	if ms.user {
		return ms.attachUser(listen, advertise)
	}
	suffix := make([]byte, 4)
	rand.Read(suffix)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "cps" + hex.EncodeToString(suffix)
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		return fmt.Errorf("creating WireGuard interface (is the wireguard module available?): %w", err)
	}
	link, err := netlink.LinkByName(attrs.Name)
	if err != nil {
		return err
	}
	moved := false
	defer func() {
		if !moved {
			netlink.LinkDel(link)
		}
	}()

	hostWG, err := wgctrl.New()
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{PrivateKey: &ms.id.key}
	if listen != 0 {
		cfg.ListenPort = &listen
	}
	// A tunnel that has just been torn down can hold its port for a moment
	// longer, as when a service restarts at once. Wait for it rather than fail.
	for attempt := 0; ; attempt++ {
		err = hostWG.ConfigureDevice(attrs.Name, cfg)
		if err == nil || attempt == 40 || !errors.Is(err, unix.EADDRINUSE) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	hostWG.Close()
	if err != nil {
		return fmt.Errorf("configuring WireGuard: %w", err)
	}

	if err := netlink.LinkSetNsFd(link, int(ms.ns.Fd())); err != nil {
		return err
	}
	moved = true // from here it dies with the capsule's namespace

	inside, err := netlink.NewHandleAt(netns.NsHandle(ms.ns.Fd()))
	if err != nil {
		return err
	}
	ms.nl = inside // kept: connections are counted through it while the capsule runs
	if link, err = inside.LinkByName(attrs.Name); err != nil {
		return err
	}
	if err := inside.LinkSetName(link, "wg0"); err != nil {
		return err
	}
	// A control socket opened inside the namespace keeps working from outside it.
	if err := inNetns(ms.ns, func() (err error) { ms.wg, err = wgctrl.New(); return }); err != nil {
		return err
	}
	return ms.bringUp(advertise)
}

// attachUser is attach without root: the tunnel runs in this process, on an
// interface made inside the capsule's network, which this process owns.
func (ms *mesh) attachUser(listen int, advertise string) error {
	// With the helper installed the tunnel is the kernel's all the same:
	// the helper makes the device and this process, which owns the
	// capsule's network, does everything else to it.
	name, err := helperTunnel(ms.ns, listen)
	if err == nil {
		return ms.attachHelped(name, advertise)
	} else if !errors.Is(err, errNoHelper) {
		fmt.Fprintln(os.Stderr, "capsule: running the tunnel inside capsule itself, as the helper could not make one:", err)
	}
	var tunnel *userTunnel
	if err := inNetns(ms.ns, func() (err error) {
		if tunnel, err = newUserTunnel("wg0"); err != nil {
			return fmt.Errorf("creating a tunnel interface (is /dev/net/tun available?): %w", err)
		}
		// Sockets made here stay in the capsule's network when used from elsewhere.
		if ms.nl, err = netlink.NewHandle(); err != nil {
			return err
		}
		ms.nft, err = nftables.New(nftables.AsLasting())
		return err
	}); err != nil {
		if tunnel != nil {
			tunnel.dev.Close()
		}
		return err
	}
	ms.wg, ms.userDev = tunnel, tunnel.dev
	cfg := wgtypes.Config{PrivateKey: &ms.id.key}
	if listen != 0 {
		cfg.ListenPort = &listen
	}
	if err := tunnel.ConfigureDevice("wg0", cfg); err != nil {
		return fmt.Errorf("configuring WireGuard: %w", err)
	}
	if err := tunnel.dev.Up(); err != nil {
		return fmt.Errorf("opening the tunnel's port: %w", err)
	}
	return ms.bringUp(advertise)
}

// attachHelped finishes a kernel tunnel the helper has put in the capsule's
// network under a temporary name. The device's key never leaves this process.
func (ms *mesh) attachHelped(name string, advertise string) error {
	var wg *wgctrl.Client
	if err := inNetns(ms.ns, func() (err error) {
		if ms.nl, err = netlink.NewHandle(); err != nil {
			return err
		}
		if ms.nft, err = nftables.New(nftables.AsLasting()); err != nil {
			return err
		}
		wg, err = wgctrl.New()
		return err
	}); err != nil {
		return err
	}
	ms.wg = wg
	link, err := ms.nl.LinkByName(name)
	if err != nil {
		return err
	}
	if err := ms.nl.LinkSetName(link, "wg0"); err != nil {
		return err
	}
	if err := wg.ConfigureDevice("wg0", wgtypes.Config{PrivateKey: &ms.id.key}); err != nil {
		return fmt.Errorf("configuring WireGuard: %w", err)
	}
	return ms.bringUp(advertise)
}

// bringUp gives the tunnel interface, now inside the capsule's network, its address and applies the first policy.
func (ms *mesh) bringUp(advertise string) error {
	inside := ms.nl
	link, err := inside.LinkByName("wg0")
	if err != nil {
		return err
	}
	if err := inside.AddrAdd(link, &netlink.Addr{IPNet: hostBits(ms.id.addr), Flags: unix.IFA_F_NODAD}); err != nil {
		return err
	}
	if err := inside.LinkSetUp(link); err != nil {
		return err
	}
	meshRange := &net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(8, 128)}
	if err := inside.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: meshRange}); err != nil {
		return err
	}
	ms.current, ms.down = map[wgtypes.Key]bool{}, map[string]bool{}
	if err := ms.publishCard(advertise); err != nil {
		return err
	}
	ms.seen = ms.fingerprint()
	err = ms.sync()
	ms.running = true
	return err
}

// publishCard registers this instance in the cards directory when the host
// has been delegated its name. Other capsules watching that directory pick
// it up within seconds; removeCard takes it out again on exit.
func (ms *mesh) publishCard(advertise string) error {
	endpoint := ""
	if advertise != "" {
		dev, err := ms.wg.Device("wg0")
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(advertise)
		if err != nil {
			return errors.New("-advertise must be an IP address")
		}
		endpoint = netip.AddrPortFrom(addr, uint16(dev.ListenPort)).String()
	}
	own := ms.id.key.PublicKey()
	c := selfCard(ms.name, own.String(), ms.id.kemKey(), endpoint)
	if c == nil {
		return nil
	}
	if err := os.MkdirAll(ms.cards, 0o755); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	ms.ownCard = filepath.Join(ms.cards, fmt.Sprintf("%s-%s.card", ms.name, hex.EncodeToString(own[:6])))
	return os.WriteFile(ms.ownCard, append(raw, '\n'), 0o644)
}

func (ms *mesh) removeCard() {
	if ms.ownCard != "" {
		os.Remove(ms.ownCard)
	}
}

// WireGuard's own key exchange can be undone by a large quantum computer,
// including, later, for traffic recorded today. It also mixes in an optional
// preshared key, and that is where a second, post-quantum secret goes. For
// each pair of instances the one with the lower key makes a fresh secret,
// encapsulates it to the other's ML-KEM key (from its signed card), and puts
// the ciphertext beside the cards, where only the other can open it. It does
// so again every epoch, so no one secret protects more than an hour of
// traffic. Tunnels go on working across a change: sessions already set up
// are untouched, and the next handshake uses the new secret.
const pskEpochTicks = 1200 // an hour

func pskEpoch() uint64 {
	ticks := uint64(pskEpochTicks)
	if n, err := strconv.ParseUint(os.Getenv("CAPSULE_PSK_TICKS"), 10, 64); err == nil && n > 0 {
		ticks = n
	}
	return clockTick(time.Now()) / ticks
}

type pskFile struct {
	Epoch uint64 `json:"epoch"`
	CT    string `json:"ct"`
}

// pskState is what one side knows about the secret it shares with one peer.
type pskState struct {
	Raw   string `json:"raw"` // the published file this secret goes with
	Key   string `json:"key"`
	Epoch uint64 `json:"epoch"`
	key   wgtypes.Key
	path  string
	kept  string
	wrote bool   // this side made the secret
	fresh bool   // made during this pass: the other side has still to pick it up
	acked bool   // the other side has said it holds this secret
	ack   string // the published file this side last acknowledged
	late  bool   // the tunnel was already in use when this secret arrived, or before the other side had it
}

func pskAck(raw string) string {
	sum := sha256.Sum256([]byte("capsule-mesh-psk-ack-v1\x00" + raw))
	return hex.EncodeToString(sum[:])
}

// settle makes the two ends of each tunnel agree before traffic is sent.
// A handshake between ends holding different secrets fails silently and is
// not tried again for five seconds, so the end that takes a secret up says
// so with a small file beside it, and the end that made it waits for that,
// briefly, when the secret is new: long enough for a peer on this host. It returns the peers whose
// tunnels may have tried and failed in the meantime, and are usable now:
// kick starts those again at once. Only one end of a tunnel ever does that,
// or the two could each undo the other's handshake: the end that took the
// secret up, if the card tells it where the maker is, and otherwise the
// maker, which is then the only one able to start a handshake at all.
func (ms *mesh) settle(want map[wgtypes.Key]wgtypes.PeerConfig) (ready []wgtypes.Key) {
	for key, st := range ms.psks {
		if _, ok := want[key]; ok && !st.wrote && st.ack != st.Raw {
			if os.WriteFile(st.path+".ack", []byte(pskAck(st.Raw)), 0o644) == nil {
				st.ack = st.Raw
			}
			if st.late && want[key].Endpoint != nil {
				ready = append(ready, key)
			}
			st.late = false
		}
	}
	for deadline := time.Now().Add(200 * time.Millisecond); ; time.Sleep(5 * time.Millisecond) {
		waiting := false
		for key, st := range ms.psks {
			if _, ok := want[key]; !ok || !st.wrote || st.acked {
				continue
			}
			if raw, _ := os.ReadFile(st.path + ".ack"); string(raw) == pskAck(st.Raw) {
				st.acked = true
				if st.late && !ms.listed {
					ready = append(ready, key)
				}
				st.late = false
			} else if st.fresh {
				waiting = true
			}
		}
		// Waiting is for the start, before the application runs. Later, this
		// is the loop that keeps every tunnel current: it must not stall on a
		// peer that is not there to answer.
		if !waiting || ms.running || time.Now().After(deadline) {
			break
		}
	}
	for _, st := range ms.psks {
		st.fresh = false
		if st.wrote && !st.acked {
			st.late = true // traffic may now be tried before the other side is ready
		}
	}
	return ready
}

// kick starts the handshake with peers whose secret both ends now hold,
// unless a session is already up. Taking the peer out and putting it back
// clears the five-second wait a failed attempt leaves behind; one datagram,
// which the peer's firewall discards, then sets the handshake off.
func (ms *mesh) kick(ready []wgtypes.Key, want map[wgtypes.Key]wgtypes.PeerConfig) {
	if len(ready) == 0 {
		return
	}
	up := map[wgtypes.Key]bool{}
	if dev, err := ms.wg.Device("wg0"); err == nil {
		for _, p := range dev.Peers {
			up[p.PublicKey] = time.Since(p.LastHandshakeTime) < 3*time.Minute
		}
	}
	for _, key := range ready {
		cfg, ok := want[key]
		if !ok || up[key] {
			continue
		}
		ms.wg.ConfigureDevice("wg0", wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}})
		ms.wg.ConfigureDevice("wg0", wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}})
		target := net.JoinHostPort(meshAddr(key[:]).String(), "9")
		inNetns(ms.ns, func() error {
			if c, err := meshDialer(time.Second).Dial("udp6", target); err == nil {
				c.Write([]byte{0})
				c.Close()
			}
			return nil
		})
	}
}

// preshared returns the secret to mix into the tunnel with one peer: the
// zero key, meaning none, unless the pair has a post-quantum one. kem is the
// peer's ML-KEM key from its card, if it has one. fresh is set when a new
// secret was just published, which the peer has still to pick up.
func (ms *mesh) preshared(peer wgtypes.Key, kem string) (key *wgtypes.Key, fresh bool) {
	none := &wgtypes.Key{}
	own := ms.id.key.PublicKey()
	first, second := own, peer
	makes := bytes.Compare(own[:], peer[:]) < 0
	if !makes {
		first, second = peer, own
	}
	name := hex.EncodeToString(first[:8]) + "-" + hex.EncodeToString(second[:8]) + ".psk"
	path := filepath.Join(ms.cards, name)
	mix := func(secret []byte, epoch uint64) wgtypes.Key {
		h := sha256.New()
		h.Write([]byte("capsule-mesh-psk-v1\x00"))
		h.Write(secret)
		h.Write(first[:])
		h.Write(second[:])
		binary.Write(h, binary.BigEndian, epoch)
		var k wgtypes.Key
		copy(k[:], h.Sum(nil))
		return k
	}
	if ms.psks == nil {
		ms.psks = map[wgtypes.Key]*pskState{}
	}
	st := ms.psks[peer]
	raw, readErr := os.ReadFile(path)
	if !makes {
		if readErr != nil {
			return none, false
		}
		if st != nil && st.Raw == string(raw) {
			return &st.key, false
		}
		var f pskFile
		if json.Unmarshal(raw, &f) != nil {
			return none, false
		}
		ct, _ := b64.DecodeString(f.CT)
		secret, err := ms.id.kem.Decapsulate(ct)
		if err != nil {
			return none, false
		}
		st = &pskState{Raw: string(raw), key: mix(secret, f.Epoch), path: path}
		ms.psks[peer] = st
		return &st.key, false
	}
	if kem == "" {
		if readErr == nil {
			os.Remove(path) // left from when the peer's card had a key
		}
		delete(ms.psks, peer)
		return none, false
	}
	// The maker keeps its secret on disk too, readable by root alone like
	// the host's own secret, so a restart does not have to publish a new one.
	kept := filepath.Join(dataDir(), "psk", name)
	epoch := pskEpoch()
	if st == nil {
		var saved pskState
		if data, err := os.ReadFile(kept); err == nil && json.Unmarshal(data, &saved) == nil {
			if k, err := b64.DecodeString(saved.Key); err == nil && len(k) == len(saved.key) {
				copy(saved.key[:], k)
				st = &saved
			}
		}
	}
	if st != nil && st.Epoch == epoch && readErr == nil && st.Raw == string(raw) {
		st.path, st.kept, st.wrote = path, kept, true
		ms.psks[peer] = st
		return &st.key, false
	}
	ekRaw, _ := b64.DecodeString(kem)
	ek, err := mlkem.NewEncapsulationKey768(ekRaw)
	if err != nil {
		return none, false
	}
	secret, ct := ek.Encapsulate()
	body, _ := json.Marshal(pskFile{Epoch: epoch, CT: b64.EncodeToString(ct)})
	st = &pskState{Raw: string(body), Epoch: epoch, key: mix(secret, epoch), path: path, kept: kept, wrote: true, fresh: true}
	st.Key = b64.EncodeToString(st.key[:])
	save, _ := json.Marshal(st)
	publish := func(file string, data []byte, mode os.FileMode) error {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			return err
		}
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		return os.Rename(tmp, file)
	}
	os.MkdirAll(filepath.Dir(kept), 0o700)
	if publish(kept, save, 0o600) != nil || publish(path, body, 0o644) != nil {
		delete(ms.psks, peer) // the cards folder cannot be written: the tunnel stays as WireGuard alone makes it
		return none, false
	}
	ms.psks[peer] = st
	return &st.key, true
}

// pinNetwork keeps a handle to the capsule's network namespace on disk, so
// that if this supervisor is killed outright, whatever capsule command runs
// next can still reach the tunnel and remove it. Without that, the kernel
// keeps an orphaned tunnel, and its port, until the namespace's last
// connection has timed out, which can take minutes.
func pinNetwork(pid int, pin string) func() {
	if os.WriteFile(pin, nil, 0o600) != nil {
		return func() {}
	}
	if err := unix.Mount(fmt.Sprintf("/proc/%d/ns/net", pid), pin, "", unix.MS_BIND, ""); err != nil {
		os.Remove(pin)
		return func() {}
	}
	return func() {
		unix.Unmount(pin, unix.MNT_DETACH)
		os.Remove(pin)
	}
}

// releaseTunnel removes the tunnel of a capsule whose supervisor is gone, through the handle it left.
func releaseTunnel(pin string) {
	f, err := os.Open(pin)
	if err != nil {
		return
	}
	if inside, err := netlink.NewHandleAt(netns.NsHandle(f.Fd())); err == nil {
		if link, err := inside.LinkByName("wg0"); err == nil {
			inside.LinkDel(link)
		}
		inside.Close()
	}
	f.Close()
	unix.Unmount(pin, unix.MNT_DETACH)
	os.Remove(pin)
}

// close removes the tunnel at once, which frees its port, instead of leaving
// that to happen whenever the kernel gets round to discarding the namespace.
func (ms *mesh) close() {
	if ms.nl == nil {
		return
	}
	ms.closed.Store(true)
	if ms.userDev != nil {
		ms.userDev.Close()
	} else if link, err := ms.nl.LinkByName("wg0"); err == nil {
		ms.nl.LinkDel(link)
	}
	if ms.nft != nil {
		ms.nft.CloseLasting()
	}
	ms.nl.Close()
}

func (ms *mesh) fingerprint() string {
	files, _ := filepath.Glob(filepath.Join(ms.cards, "*.card"))
	own := ms.id.key.PublicKey()
	secrets, _ := filepath.Glob(filepath.Join(ms.cards, "*"+hex.EncodeToString(own[:8])+"*.psk*"))
	files = append(files, secrets...)
	var b strings.Builder
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(&b, "%s %d %d\n", f, st.Size(), st.ModTime().UnixNano())
		}
	}
	return b.String()
}

// watch keeps the network current while the capsule runs: it re-reads cards
// when they change, so instances of a peer can come and go, and it keeps
// track of which instances are serving so connections stop going to ones
// that have died.
func (ms *mesh) watch() {
	// The kernel says at once when the cards folder changes on this host.
	// Changes that arrive some other way, as on a network filesystem, are
	// found by looking every two seconds.
	changed := make(chan struct{}, 1)
	changed <- struct{}{} // look once straight away: something may have changed while this capsule was starting
	if fd, err := unix.InotifyInit1(unix.IN_CLOEXEC); err == nil {
		if _, err := unix.InotifyAddWatch(fd, ms.cards, unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_DELETE); err == nil {
			go func() {
				buf := make([]byte, 4096)
				for {
					if n, err := unix.Read(fd, buf); n <= 0 && err != unix.EINTR {
						return
					}
					select {
					case changed <- struct{}{}:
					default:
					}
				}
			}()
		} else {
			unix.Close(fd)
		}
	}
	every := time.Tick(2 * time.Second)
	for {
		routine := false
		select {
		case <-every:
			routine = true
		case <-changed:
		}
		if ms.closed.Load() {
			return
		}
		var err error
		if now := ms.fingerprint(); now != ms.seen || pskEpoch() != ms.epoch {
			ms.seen = now
			err = ms.sync()
		} else if !routine {
			continue
		} else if health, load, landed := ms.check(false), ms.measure(), ms.landing(); health || load || landed {
			err = ms.applyPolicy()
		}
		if err != nil && !ms.closed.Load() {
			fmt.Fprintln(os.Stderr, "capsule: mesh:", err)
		}
	}
}

// observe looks at what the kernel already knows, without sending anything:
// this capsule's connections to each instance, and how many bytes have gone
// each way over the tunnel.
func (ms *mesh) observe() {
	// Reading the kernel's table can be cut short when it changes underneath; ask again.
	var flows []*netlink.ConntrackFlow
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if flows, err = ms.nl.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET6); err == nil {
			break
		}
	}
	// A connection counts as open while either side may still send:
	// established, or closed in one direction only (a caller that has sent
	// its request and is waiting for the answer is still work for the
	// instance). Those are the kernel's states 3 to 5. States 6 and 7 are
	// connections that were established and have since closed in good order.
	const established, closeWait, timeWait = 3, 5, 7
	open, accepted, seen := map[string]int{}, map[string]bool{}, map[string]bool{}
	for _, f := range flows {
		tcp, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP)
		if !ok || tcp.State < established || tcp.State > timeWait {
			continue
		}
		instance := f.Reverse.SrcIP.String() // the reply comes from the instance the connection was sent to
		if tcp.State <= closeWait {
			open[instance]++
		}
		id := fmt.Sprintf("%s %d %d", instance, f.Forward.SrcPort, f.Forward.DstPort)
		seen[id] = true
		if !ms.flows[id] {
			accepted[instance] = true // a connection that got as far as being established, and is new
		}
	}
	if err == nil {
		ms.open, ms.accepted, ms.flows = open, accepted, seen
	}
	traffic := map[string][2]uint64{}
	if dev, err := ms.wg.Device("wg0"); err == nil {
		for _, p := range dev.Peers {
			traffic[meshAddr(p.PublicKey[:]).String()] = [2]uint64{uint64(p.ReceiveBytes), uint64(p.TransmitBytes)}
		}
	}
	ms.traffic = traffic
}

// check works out which instances are serving and reports whether any
// changed between up and down. It reads what the kernel knows first, and
// opens a connection to an instance only when that leaves the question open:
// on the first port this capsule may use there. With all, every instance is
// checked with a connection. Peers reached only over UDP are not checked.
func (ms *mesh) check(all bool) (changed bool) {
	ms.observe()
	if ms.probes == nil {
		ms.probes = map[string]*probeState{}
	}
	now := time.Now()
	type result struct {
		addr string
		down bool
	}
	results := make(chan result)
	pending := 0
	inUse := map[string]bool{}
	for _, p := range ms.peers {
		if len(p.Out) == 0 {
			continue
		}
		for _, addr := range ms.instances[p.Name] {
			name := addr.String()
			st := ms.probes[name]
			if st == nil {
				st = &probeState{}
				ms.probes[name] = st
			}
			sent := st.Tx
			t := ms.traffic[name]
			if !needProbe(st, now, t[0], t[1], ms.open[name] > 0, ms.accepted[name]) && !all {
				if now.Before(st.Next) && (ms.accepted[name] || ms.open[name] > 0) && ms.down[name] {
					ms.down[name], changed = false, true // seen serving without having to ask
				}
				continue
			}
			inUse[name] = t[1] != sent
			pending++
			go func() {
				target := net.JoinHostPort(name, strconv.Itoa(p.Out[0]))
				err := inNetns(ms.ns, func() error {
					c, err := meshDialer(time.Second).Dial("tcp6", target)
					if err == nil {
						c.Close()
					}
					return err
				})
				results <- result{name, err != nil}
			}()
		}
	}
	for ; pending > 0; pending-- {
		r := <-results
		changed = changed || ms.down[r.addr] != r.down
		ms.down[r.addr] = r.down
		probed(ms.probes[r.addr], now, !r.down, inUse[r.addr])
	}
	return changed
}

// least returns the live instances of a peer that hold the fewest of this capsule's open connections.
func (ms *mesh) least(live []net.IP) []net.IP {
	fewest := -1
	for _, addr := range live {
		if n := ms.open[addr.String()]; fewest < 0 || n < fewest {
			fewest = n
		}
	}
	var out []net.IP
	for _, addr := range live {
		if ms.open[addr.String()] == fewest {
			out = append(out, addr)
		}
	}
	return out
}

// measure reports whether, for any peer balanced by least connections, the
// set of least-loaded instances has changed since the firewall was built.
// The counts come from observe.
func (ms *mesh) measure() bool {
	seen := ""
	for _, p := range ms.peers {
		if p.Balance == "least-connections" {
			seen += p.Name + fmt.Sprint(ms.least(ms.liveInstances(p.Name))) + ";"
		}
	}
	changed := seen != ms.leastSeen
	ms.leastSeen = seen
	return changed
}

// liveInstances returns a peer's instances that answered their last check, or all of them if none did.
func (ms *mesh) liveInstances(name string) []net.IP {
	addrs := ms.instances[name]
	live := slices.DeleteFunc(slices.Clone(addrs), func(a net.IP) bool { return ms.down[a.String()] })
	if len(live) == 0 {
		return addrs // nothing answers: keep trying them all rather than none
	}
	return live
}

// sync makes the WireGuard peers and the firewall match the manifest and the current cards.
func (ms *mesh) sync() error {
	cards := loadCards(ms.cards, ms.trusted)
	own := ms.id.key.PublicKey()
	ms.epoch = pskEpoch()
	ms.listed = false
	for _, c := range cards[ms.name] {
		if c.Key == own.String() && c.Endpoint != "" {
			ms.listed = true
		}
	}
	want := map[wgtypes.Key]wgtypes.PeerConfig{}
	instances := map[string][]net.IP{}
	for _, p := range ms.peers {
		for _, c := range cards[p.Name] {
			pub, _ := c.publicKey() // checked when the card was loaded
			key, _ := wgtypes.NewKey(pub)
			if key == own {
				continue
			}
			addr := meshAddr(pub)
			cfg := wgtypes.PeerConfig{PublicKey: key, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*hostBits(addr)}}
			if c.Endpoint != "" {
				cfg.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.Endpoint))
			}
			before := ms.psks[key]
			cfg.PresharedKey, _ = ms.preshared(key, c.Kem)
			if st := ms.psks[key]; st != nil && st != before && !st.wrote && ms.current[key] {
				st.late = true // a tunnel already set up is being given a new secret
			}
			if _, dup := want[key]; !dup {
				instances[p.Name] = append(instances[p.Name], addr)
			}
			want[key] = cfg
		}
		sort.Slice(instances[p.Name], func(i, j int) bool { return instances[p.Name][i].String() < instances[p.Name][j].String() })
	}

	// Add and remove only what changed, so live tunnels are not reset.
	var changes []wgtypes.PeerConfig
	for key, cfg := range want {
		changes = append(changes, cfg)
		ms.current[key] = true
	}
	for key, st := range ms.psks {
		if _, keep := want[key]; !keep {
			if st.wrote { // the peer's card is gone: so is the secret made for it
				os.Remove(st.path)
				os.Remove(st.path + ".ack")
				os.Remove(st.kept)
			}
			delete(ms.psks, key)
		}
	}
	for key := range ms.current {
		if _, keep := want[key]; !keep {
			changes = append(changes, wgtypes.PeerConfig{PublicKey: key, Remove: true})
			delete(ms.current, key)
		}
	}
	if err := ms.wg.ConfigureDevice("wg0", wgtypes.Config{Peers: changes}); err != nil {
		return fmt.Errorf("configuring WireGuard peers: %w", err)
	}
	ready := ms.settle(want)
	// Let traffic to the new set through first, so the checks can reach it,
	// then balance only across the instances that answered.
	if ms.instances != nil && fmt.Sprint(instances) == fmt.Sprint(ms.instances) {
		// Only a tunnel's secret changed. Who is where has not, so the
		// firewall, and the turn-taking it keeps count of, stay as they are,
		// unless a tunnel that was failing has just been put right.
		if len(ready) > 0 {
			ms.kick(ready, want)
			if ms.check(true) {
				return ms.applyPolicy()
			}
		}
		return nil
	}
	ms.instances = instances
	who := map[string]string{}
	for name, addrs := range instances {
		for _, addr := range addrs {
			who[addr.String()] = name
		}
	}
	ms.mu.Lock()
	ms.who = who
	ms.mu.Unlock()
	if err := ms.applyPolicy(); err != nil {
		return err
	}
	ms.kick(ready, want)
	if ms.check(true) { // the set of instances is new: ask each of them
		return ms.applyPolicy()
	}
	return nil
}

// applyPolicy replaces the firewall inside the capsule's namespace in one
// atomic step. The capsule has no capabilities, so it cannot change it.
//
//	balance: a connection to a peer's service address goes to one of its live instances,
//	         chosen the way that peer's "balance" setting says
//	filter:  drop by default; accept loopback and replies to allowed connections
//	in:      from an instance of a peer, to a port in that peer's "in" or "in_udp"
//	out:     to an instance of a peer,   to a port in that peer's "out" or "out_udp"
func (ms *mesh) applyPolicy() error {
	c := ms.nft
	if c == nil {
		var err error
		if c, err = nftables.New(nftables.WithNetNSFd(int(ms.ns.Fd()))); err != nil {
			return err
		}
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "capsule"})
	c.FlushTable(table)
	drop, accept := nftables.ChainPolicyDrop, nftables.ChainPolicyAccept
	in := c.AddChain(&nftables.Chain{Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	out := c.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	balance := c.AddChain(&nftables.Chain{Name: "balance", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest, Policy: &accept})

	const reg = 1
	eq := func(data []byte) expr.Any { return &expr.Cmp{Op: expr.CmpOpEq, Register: reg, Data: data} }
	add := func(ch *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: ch, Exprs: exprs})
	}
	verdict := &expr.Verdict{Kind: expr.VerdictAccept}

	loopback := make([]byte, unix.IFNAMSIZ)
	copy(loopback, "lo")
	add(in, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: reg}, eq(loopback), verdict)
	add(out, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: reg}, eq(loopback), verdict)
	for _, ch := range []*nftables.Chain{in, out} {
		add(ch,
			&expr.Ct{Register: reg, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: reg, DestRegister: reg, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: reg, Data: binaryutil.NativeEndian.PutUint32(0)},
			verdict,
		)
	}

	const ip6Src, ip6Dst, dport = 8, 24, 2 // header offsets; TCP and UDP keep the port in the same place
	ip6 := func(offset uint32, addr net.IP) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: reg}, eq([]byte{unix.NFPROTO_IPV6}),
			&expr.Payload{DestRegister: reg, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: net.IPv6len}, eq(addr),
		}
	}
	l4Port := func(proto byte, port int) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg}, eq([]byte{proto}),
			&expr.Payload{DestRegister: reg, Base: expr.PayloadBaseTransportHeader, Offset: dport, Len: 2}, eq(binaryutil.BigEndian.PutUint16(uint16(port))),
		}
	}
	protoName := map[byte]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}
	protoOf := func(udp bool) byte {
		if udp {
			return unix.IPPROTO_UDP
		}
		return unix.IPPROTO_TCP
	}
	own := map[string]bool{} // receptor ports the application reaches itself
	for _, n := range ms.cellNeeds {
		own[fmt.Sprint(protoName[protoOf(n.UDP)], " ", receptorPort(n.Name))] = true
	}
	const reg2 = 2
	port16 := func(port int) expr.Any {
		return &expr.Immediate{Register: reg2, Data: binaryutil.BigEndian.PutUint16(uint16(port))}
	}
	if len(ms.lands) > 0 {
		// What arrives for a receptor goes straight to the application's own port.
		arrive := c.AddChain(&nftables.Chain{Name: "arrive", Table: table, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
		for _, o := range ms.cellOffers {
			proto := protoOf(o.UDP)
			if ms.lands[fmt.Sprint(protoName[proto], " ", receptorPort(o.Name))] == 0 {
				continue
			}
			rule := append(ip6(ip6Dst, ms.id.addr), l4Port(proto, receptorPort(o.Name))...)
			add(arrive, append(rule, &expr.Immediate{Register: reg, Data: ms.id.addr.To16()}, port16(o.Port),
				&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: reg, RegAddrMax: reg, RegProtoMin: reg2, RegProtoMax: reg2, Specified: true})...)
		}
	}
	allow := func(ch *nftables.Chain, offset uint32, addr net.IP, proto byte, ports []int) {
		for _, port := range ports {
			if landed := ms.lands[fmt.Sprint(protoName[proto], " ", port)]; ch == in && landed != 0 {
				add(ch, append(append(ip6(offset, addr), l4Port(proto, landed)...), verdict)...) // as it looks once redirected
			}
			rule := append(ip6(offset, addr), l4Port(proto, port)...)
			if ms.cell && ch == out && !own[fmt.Sprint(protoName[proto], " ", port)] {
				// In a cell, only the supervisor may send anything else.
				rule = append(rule, &expr.Meta{Key: expr.MetaKeyMARK, Register: reg}, eq(binaryutil.NativeEndian.PutUint32(cellMark)))
			}
			add(ch, append(rule, verdict)...)
		}
	}
	for _, p := range ms.peers {
		addrs := ms.instances[p.Name]
		if len(p.Out)+len(p.OutUDP) > 0 {
			live := ms.liveInstances(p.Name)
			if p.Balance == "least-connections" {
				live = ms.least(live) // then at random among those tied for fewest
			}
			// What is sent to the peer's service address goes to one of its
			// instances. A need the application reaches by port is, in the
			// same step, moved from the port the application used to the
			// one the receptor is carried on.
			type target struct {
				match []expr.Any
				port  int
			}
			var targets []target
			for _, n := range ms.cellNeeds {
				if n.From == p.Name {
					targets = append(targets, target{append(ip6(ip6Dst, serviceAddr(p.Name)), l4Port(protoOf(n.UDP), n.Port)...), receptorPort(n.Name)})
				}
			}
			targets = append(targets, target{ip6(ip6Dst, serviceAddr(p.Name)), 0})
			if len(live) == 0 {
				// The peer has no instance yet. There is nowhere to send, and
				// nothing is allowed out; the rules are rebuilt when one appears.
				targets = nil
			}
			for _, t := range targets {
				var pick []expr.Any
				one := func(addr net.IP) { pick = []expr.Any{&expr.Immediate{Register: reg, Data: addr}} }
				switch {
				case p.Balance == "failover" || len(live) == 1:
					// The lowest address among the live instances. Every caller
					// sorts the same way, so all of them agree on which it is.
					one(live[0])
				case p.Balance == "sticky":
					// The instance that scores highest when hashed with this
					// caller's address. An instance joining or leaving only moves
					// the callers that were, or now are, best matched to it.
					best, bestScore := live[0], ""
					for _, addr := range live {
						if score := meshHash("capsule-sticky-v1", append(append([]byte{}, ms.id.addr...), addr...)).String(); score > bestScore {
							best, bestScore = addr, score
						}
					}
					one(best)
				default:
					// A number from 0 to n-1, drawn at random or counted up in
					// turn, looked up in a map from number to instance.
					kind := uint32(unix.NFT_NG_RANDOM)
					if p.Balance == "round-robin" {
						kind = unix.NFT_NG_INCREMENTAL
					}
					instances := &nftables.Set{Table: table, Anonymous: true, Constant: true, IsMap: true,
						KeyType: nftables.TypeInteger, DataType: nftables.TypeIP6Addr}
					elements := make([]nftables.SetElement, len(live))
					for i, addr := range live {
						elements[i] = nftables.SetElement{Key: binaryutil.NativeEndian.PutUint32(uint32(i)), Val: addr}
					}
					if err := c.AddSet(instances, elements); err != nil {
						return err
					}
					pick = []expr.Any{&expr.Numgen{Register: reg, Modulus: uint32(len(live)), Type: kind},
						&expr.Lookup{SourceRegister: reg, DestRegister: reg, IsDestRegSet: true, SetName: instances.Name, SetID: instances.ID}}
				}
				nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: reg, RegAddrMax: reg}
				rule := append(slices.Clone(t.match), pick...)
				if t.port != 0 {
					rule = append(rule, port16(t.port))
					nat.RegProtoMin, nat.RegProtoMax, nat.Specified = reg2, reg2, true
				}
				add(balance, append(rule, nat)...)
			}
		}
		for _, addr := range addrs {
			// What the supervisor itself sends to an instance may always leave: that is how it starts a tunnel.
			add(out, append(ip6(ip6Dst, addr), &expr.Meta{Key: expr.MetaKeyMARK, Register: reg}, eq(binaryutil.NativeEndian.PutUint32(cellMark)), verdict)...)
			allow(in, ip6Src, addr, unix.IPPROTO_TCP, p.In)
			allow(in, ip6Src, addr, unix.IPPROTO_UDP, p.InUDP)
			allow(out, ip6Dst, addr, unix.IPPROTO_TCP, p.Out)
			allow(out, ip6Dst, addr, unix.IPPROTO_UDP, p.OutUDP)
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("installing firewall: %w", err)
	}
	return nil
}
