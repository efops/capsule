package main

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func meshHash(label string, data []byte) net.IP {
	sum := sha256.Sum256(append([]byte(label+"\x00"), data...))
	ip := make(net.IP, net.IPv6len)
	ip[0] = 0xfd // unique local address range, fd00::/8
	copy(ip[1:], sum[:15])
	return ip
}

// meshAddr derives an instance's address from its mesh public key, so the
// address is the identity: WireGuard only accepts packets from that address
// if they were encrypted by the holder of that key.
func meshAddr(pub []byte) net.IP { return meshHash("capsule-mesh-addr-v1", pub) }

// serviceAddr is the one stable address a capsule uses to reach a peer by
// name. The kernel rewrites it to one of the peer's running instances.
func serviceAddr(name string) net.IP { return meshHash("capsule-mesh-service-v1", []byte(name)) }

// card states that one mesh key is an instance of a named capsule, and where
// to reach it. It is signed either by a key the host trusts, or by a host
// that a trusted key has delegated that name to, so instances can register
// themselves without anyone signing by hand.
type card struct {
	Name       string      `json:"name"`
	Key        string      `json:"key"`
	Endpoint   string      `json:"endpoint,omitempty"`
	Kem        string      `json:"kem,omitempty"` // the instance's ML-KEM-768 key, for a post-quantum tunnel secret
	Signer     string      `json:"signer"`        // the signer's full public key
	Signature  string      `json:"signature"`
	Delegation *delegation `json:"delegation,omitempty"`
}

// delegation lets one host's signing key issue cards for the listed names.
type delegation struct {
	Host      string   `json:"host"` // id of the host's signing key, from `capsule host`
	Names     []string `json:"names"`
	Signer    string   `json:"signer"`
	Signature string   `json:"signature"`
}

func (d delegation) message() []byte {
	return []byte("capsule-delegation-v1\n" + d.Host + "\n" + strings.Join(d.Names, ",") + "\n")
}

func (c card) message() []byte {
	msg := "capsule-peer-v1\n" + c.Name + "\n" + c.Key + "\n" + c.Endpoint + "\n"
	if c.Kem != "" {
		msg += c.Kem + "\n"
	}
	return []byte(msg)
}

func (c card) publicKey() ([]byte, error) {
	key, err := b64.DecodeString(c.Key)
	if err != nil || len(key) != 32 {
		return nil, errors.New("not a mesh key")
	}
	return key, nil
}

func (c card) valid(trusted trustSet) bool {
	if !nameRE.MatchString(c.Name) {
		return false
	}
	if _, err := c.publicKey(); err != nil {
		return false
	}
	if c.Endpoint != "" {
		if _, err := netip.ParseAddrPort(c.Endpoint); err != nil {
			return false
		}
	}
	if c.Kem != "" {
		if raw, err := b64.DecodeString(c.Kem); err != nil || len(raw) != mlkem.EncapsulationKeySize768 {
			return false
		}
	}
	if signedBy(trusted, c.Signer, c.Signature, c.message()) {
		return true
	}
	d := c.Delegation
	if d == nil || d.Host != keyID(c.Signer) || !slices.Contains(d.Names, c.Name) || !signedBy(trusted, d.Signer, d.Signature, d.message()) {
		return false
	}
	return verifySig(c.Signer, c.Signature, c.message())
}

// loadCards returns the valid cards in dir, grouped by capsule name. Cards
// that are malformed or signed by an untrusted key are ignored.
func loadCards(dir string, trusted trustSet) map[string][]card {
	out := map[string][]card{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.card"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		var c card
		if err != nil || json.Unmarshal(raw, &c) != nil || !c.valid(trusted) {
			continue
		}
		out[c.Name] = append(out[c.Name], c)
	}
	return out
}

func cmdCard(args []string) error {
	fl := flag.NewFlagSet("card", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	name := fl.String("name", "", "capsule name")
	wg := fl.String("mesh-key", "", "the instance's mesh key, from `capsule identity`")
	endpoint := fl.String("endpoint", "", "host ip:port where the instance listens")
	kem := fl.String("kem", "", "the instance's kem key, from `capsule identity`: its tunnels then also resist quantum computers")
	fl.Parse(args)
	c := card{Name: *name, Key: *wg, Endpoint: *endpoint, Kem: *kem}
	if *keyPath == "" || fl.NArg() != 0 {
		return errors.New("usage: capsule card -key <file> -name <name> -mesh-key <key> [-kem <key>] [-endpoint ip:port]")
	}
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	c.Signer = key.pub
	c.Signature = key.sign(c.message())
	if !c.valid(trustSet{key.id(): true}) {
		return errors.New("card needs a valid -name, -mesh-key and, if given, -kem and -endpoint ip:port")
	}
	out, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(out))
	return nil
}

func delegationPath() string { return filepath.Join(configDir(), "delegation") }

// cmdDelegate lets a host issue its own cards for the given capsule names.
func cmdDelegate(args []string) error {
	fl := flag.NewFlagSet("delegate", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	host := fl.String("host", "", "the id of the host's signing key, from `capsule host`")
	fl.Parse(args)
	if *keyPath == "" || *host == "" || fl.NArg() == 0 {
		return errors.New("usage: capsule delegate -key <file> -host <signing key id> <name>...")
	}
	for _, name := range fl.Args() {
		if !nameRE.MatchString(name) {
			return fmt.Errorf("%q is not a capsule name", name)
		}
	}
	if !isID(*host) {
		return errors.New("-host is not a signing key id")
	}
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	d := delegation{Host: *host, Names: fl.Args(), Signer: key.pub}
	d.Signature = key.sign(d.message())
	out, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(out))
	return nil
}

// selfDelegation returns this host's delegation for a capsule name, or nil if it has none.
func selfDelegation(name string) *delegation {
	raw, err := os.ReadFile(delegationPath())
	var d delegation
	if err != nil || json.Unmarshal(raw, &d) != nil || !slices.Contains(d.Names, name) {
		return nil
	}
	if key, err := hostSigner(); err != nil || d.Host != key.id() {
		return nil
	}
	return &d
}

// selfCard issues this host's own card for an instance, if a trusted key has
// delegated the name to this host. It returns nil when there is no delegation.
func selfCard(name, meshKey, kem, endpoint string) *card {
	raw, err := os.ReadFile(delegationPath())
	var d delegation
	if err != nil || json.Unmarshal(raw, &d) != nil || !slices.Contains(d.Names, name) {
		return nil
	}
	key, err := hostSigner()
	if err != nil || d.Host != key.id() {
		return nil
	}
	c := card{Name: name, Key: meshKey, Kem: kem, Endpoint: endpoint, Signer: key.pub, Delegation: &d}
	c.Signature = key.sign(c.message())
	return &c
}
