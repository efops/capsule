package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Orders are how a host is told what to do without anyone logging in to it.
// An order is a signed request for one fixed action. It is put in the fleet
// ledger; each host it names pulls it, checks it against the operators that
// host knows, carries it out once, and answers with a signed receipt whose
// contents only the sender can read. The host listens on nothing, and there
// is no action that runs a command on the host itself.

const (
	orderMaxSpan   = 28800    // ticks: an order is good for a day at most
	orderOutputMax = 64 << 10 // bytes of a result that are kept
	orderKeep      = 1200     // ticks a host remembers an order after it has lapsed
	orderExecLimit = time.Minute
)

// orderActions lists every action there is, with how it is written.
var orderActions = map[string]string{
	"fetch":  "fetch <name>                      install the current release of a capsule",
	"run":    "run <name>                        start a capsule and keep it running",
	"stop":   "stop <name>                       stop a capsule",
	"resize": "resize <name> [memory=512M] [cpus=2] [pids=256]",
	"revoke": "revoke <seal id>                  never run this seal on the host again",
	"ps":     "ps                                list what is running",
	"log":    "log [lines]                       the end of the host's signed record",
	"exec": "exec <name> [instance=<label>] [timeout=30s] -- <command>...\n" +
		"                                         run a command inside a running capsule",
}

var sealIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type orderSig struct {
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

type order struct {
	Action  string            `json:"action"`
	Hosts   []string          `json:"hosts"` // ids of the hosts that are to carry it out
	Capsule string            `json:"capsule,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Command []string          `json:"command,omitempty"`
	From    uint64            `json:"from"` // ticks
	Until   uint64            `json:"until"`
	Nonce   string            `json:"nonce"`
	// Reply is the sender's encryption key. Results are sealed to it, so the
	// ledger never holds a capsule's output in the clear.
	Reply      string     `json:"reply"`
	Signatures []orderSig `json:"signatures,omitempty"`
}

func (o order) message() []byte {
	o.Signatures = nil
	b, _ := json.Marshal(o)
	return append([]byte("capsule-order-v1\n"), b...)
}

func (o order) id() string { return digest(o.message()) }

func (o order) signers() string {
	var ids []string
	for _, s := range o.Signatures {
		ids = append(ids, keyID(s.Signer))
	}
	return strings.Join(ids, ",")
}

// parseOrder turns the words after the flags into an order's action.
func parseOrder(words []string) (order, error) {
	var o order
	if len(words) == 0 {
		return o, errors.New("no action given")
	}
	o.Action = words[0]
	if _, known := orderActions[o.Action]; !known {
		return o, fmt.Errorf("%q is not an action; there are only: %s", o.Action, strings.Join(slices.Sorted(maps.Keys(orderActions)), ", "))
	}
	rest := words[1:]
	if i := slices.Index(rest, "--"); i >= 0 {
		rest, o.Command = rest[:i], rest[i+1:]
	}
	for _, w := range rest {
		k, v, isParam := strings.Cut(w, "=")
		switch {
		case isParam:
			if o.Params == nil {
				o.Params = map[string]string{}
			}
			o.Params[k] = v
		case o.Action == "revoke" && o.Params == nil:
			o.Params = map[string]string{"seal": w}
		case o.Action == "log" && o.Params == nil:
			o.Params = map[string]string{"lines": w}
		case o.Capsule == "":
			o.Capsule = w
		default:
			return o, fmt.Errorf("unexpected %q", w)
		}
	}
	return o, o.validate()
}

// validate checks the action is one of the fixed set and carries only what that action takes.
func (o order) validate() error {
	usage, known := orderActions[o.Action]
	if !known {
		return fmt.Errorf("%q is not an action", o.Action)
	}
	bad := func() error { return errors.New("usage: " + strings.Join(strings.Fields(usage), " ")) }
	allowed := map[string][]string{
		"resize": {"memory", "cpus", "pids"}, "revoke": {"seal"}, "log": {"lines"}, "exec": {"instance", "timeout"},
	}[o.Action]
	for k := range o.Params {
		if !slices.Contains(allowed, k) {
			return bad()
		}
	}
	named := !slices.Contains([]string{"ps", "log", "revoke"}, o.Action)
	if named != nameRE.MatchString(o.Capsule) || (!named && o.Capsule != "") { // a name where one belongs, and nowhere else
		return bad()
	}
	if (o.Action == "exec") != (len(o.Command) > 0) {
		return bad()
	}
	switch o.Action {
	case "resize":
		if len(o.Params) == 0 {
			return bad()
		}
		if _, err := orderLimits(o.Params); err != nil {
			return err
		}
	case "revoke":
		if !sealIDRE.MatchString(o.Params["seal"]) {
			return bad()
		}
	case "log":
		if v, set := o.Params["lines"]; set {
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1000 {
				return errors.New("log: lines must be between 1 and 1000")
			}
		}
	case "exec":
		if v, set := o.Params["timeout"]; set {
			if d, err := time.ParseDuration(v); err != nil || d <= 0 || d > 10*time.Minute {
				return errors.New("exec: timeout must be at most 10m")
			}
		}
		if v, set := o.Params["instance"]; set && !nameRE.MatchString(v) {
			return bad()
		}
	}
	return nil
}

func orderLimits(p map[string]string) (Limits, error) {
	l := Limits{Memory: p["memory"]}
	var err error
	if v, set := p["cpus"]; set {
		if l.CPUs, err = strconv.ParseFloat(v, 64); err != nil || l.CPUs <= 0 {
			return l, errors.New("resize: cpus must be a positive number")
		}
	}
	if v, set := p["pids"]; set {
		if l.Pids, err = strconv.Atoi(v); err != nil || l.Pids <= 0 {
			return l, errors.New("resize: pids must be a positive number")
		}
	}
	if l.Memory != "" {
		if _, err := parseSizeText(l.Memory); err != nil {
			return l, fmt.Errorf("resize: memory: %w", err)
		}
	}
	return l, nil
}

// ---- what a host obeys ----

// orderRules say whose orders this host carries out. Operators are the keys
// in <config>/operators.d, a different set from the keys trusted to sign
// capsules. <config>/orders says how many of them must sign each action:
//
//	run 2
//	exec 2
//	* 1
//
// "off" refuses an action outright. Without the file every action needs one
// operator, except exec, which is off until it is asked for there.
type orderRules struct {
	operators trustSet
	need      map[string]int
}

func loadOrderRules() (orderRules, error) {
	r := orderRules{operators: trustSet{}, need: map[string]int{}}
	files, _ := filepath.Glob(filepath.Join(configDir(), "operators.d", "*.pub"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return r, err
		}
		id := keyID(string(raw))
		if id == "" {
			return r, fmt.Errorf("%s: not a capsule public key", f)
		}
		r.operators[id] = true
	}
	for action := range orderActions {
		r.need[action] = 1
	}
	r.need["exec"] = 0
	raw, err := os.ReadFile(filepath.Join(configDir(), "orders"))
	if os.IsNotExist(err) {
		return r, nil
	} else if err != nil {
		return r, err
	}
	explicit := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.Atoi(f[len(f)-1])
		if f[len(f)-1] == "off" {
			n, err = 0, nil
		}
		_, known := orderActions[f[0]]
		if len(f) != 2 || err != nil || n < 0 || (!known && f[0] != "*") {
			return r, fmt.Errorf("%s line %d: want `<action> <signatures needed>` or `<action> off`", filepath.Join(configDir(), "orders"), i+1)
		}
		if f[0] == "*" {
			for action := range orderActions {
				if !explicit[action] {
					r.need[action] = n
				}
			}
			continue
		}
		r.need[f[0]], explicit[f[0]] = n, true
	}
	return r, nil
}

// permits reports whether enough of this host's operators signed the order.
func (r orderRules) permits(o order) error {
	need := r.need[o.Action]
	if need == 0 {
		return fmt.Errorf("this host does not take %s orders", o.Action)
	}
	msg, seen := o.message(), map[string]bool{}
	for _, s := range o.Signatures {
		if id := keyID(s.Signer); r.operators[id] && !seen[id] && verifySig(s.Signer, s.Signature, msg) {
			seen[id] = true
		}
	}
	if len(seen) < need {
		return fmt.Errorf("signed by %d of this host's operators; %s needs %d", len(seen), o.Action, need)
	}
	return nil
}

// ---- receipts ----

// orderReceipt is a host's signed answer to one order.
type orderReceipt struct {
	Order     string    `json:"order"`
	Host      string    `json:"host"`
	Time      string    `json:"time"`
	Tick      uint64    `json:"tick"`
	OK        bool      `json:"ok"`
	Wrap      recipient `json:"wrap"`   // the result's key, sealed to the order's reply key
	Result    string    `json:"result"` // what the action printed, or why it failed
	Key       string    `json:"key"`    // the host's signing key
	Signature string    `json:"signature,omitempty"`
}

func (r orderReceipt) message() []byte {
	r.Signature = ""
	b, _ := json.Marshal(r)
	return append([]byte("capsule-order-receipt-v1\n"), b...)
}

func sealResult(reply, text string) (recipient, string, error) {
	pub, err := b64.DecodeString(reply)
	if err != nil {
		return recipient{}, "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return recipient{}, "", err
	}
	wrap, err := wrapKey(key, pub)
	if err != nil {
		return wrap, "", err
	}
	aead, err := newGCM(key)
	if err != nil {
		return wrap, "", err
	}
	// The key is made for this one result, so a fixed nonce is safe.
	return wrap, b64.EncodeToString(aead.Seal(nil, make([]byte, aead.NonceSize()), []byte(text), nil)), nil
}

func openResult(r orderReceipt, box *hostKEM) (string, error) {
	key, err := unwrapKey(r.Wrap, box)
	if err != nil {
		return "", err
	}
	sealed, err := b64.DecodeString(r.Result)
	if err != nil {
		return "", err
	}
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	text, err := aead.Open(nil, make([]byte, aead.NonceSize()), sealed, nil)
	return string(text), err
}

// ---- sending ----

// orderBundle is an order together with the public details of the hosts it
// is for, which is what checking their receipts takes.
type orderBundle struct {
	Order order      `json:"order"`
	Hosts []hostCard `json:"hosts"`
}

func readBundle(file string) (orderBundle, error) {
	var b orderBundle
	raw, err := os.ReadFile(file)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil || len(b.Hosts) == 0 || b.Order.validate() != nil {
		return b, fmt.Errorf("%s: not an order file", file)
	}
	return b, nil
}

func writeBundle(file string, b orderBundle) error {
	out, _ := json.MarshalIndent(b, "", "  ")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	return os.WriteFile(file, append(out, '\n'), 0o600)
}

func sentDir() string { return filepath.Join(dataDir(), "sent") }

// findBundle takes an order file, an order id or the start of one.
func findBundle(ref string) (orderBundle, error) {
	if _, err := os.Stat(ref); err == nil {
		return readBundle(ref)
	}
	want := strings.TrimPrefix(ref, "sha256:")
	matches, _ := filepath.Glob(filepath.Join(sentDir(), want+"*.json"))
	if len(want) < 6 || len(matches) != 1 {
		return orderBundle{}, fmt.Errorf("%s is neither an order file nor the id of one order sent from here", ref)
	}
	return readBundle(matches[0])
}

func loadHostCards(files []string) ([]hostCard, error) {
	var cards []hostCard
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c hostCard
		pub := []byte(nil)
		if err := json.Unmarshal(raw, &c); err == nil {
			pub, _ = b64.DecodeString(c.Key)
		}
		if len(pub) != kemPubSize || hostKeyID(pub) != c.ID || keyID(c.SignKey) == "" || keyID(c.SignKey) != c.Sign {
			return nil, fmt.Errorf("%s: not a host file from `capsule host -export`", filepath.Base(f))
		}
		cards = append(cards, c)
	}
	return cards, nil
}

const orderUsage = `usage:
  capsule order -key <file> -host <host file>... [-for 10m] [-wait 30s] [-o <file>] <action>
  capsule order sign -key <file> <order file>     add another operator's signature
  capsule order send [-wait 30s] <order file>
  capsule order result [-wait 30s] <order file or id>
actions:
`

func cmdOrder(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "sign":
			return orderSign(args[1:])
		case "send":
			return orderSend(args[1:])
		case "result":
			return orderResult(args[1:])
		}
	}
	fl := flag.NewFlagSet("order", flag.ExitOnError)
	fl.Usage = func() {
		fmt.Fprint(os.Stderr, orderUsage)
		names := slices.Sorted(maps.Keys(orderActions))
		for _, a := range names {
			fmt.Fprintln(os.Stderr, "  "+orderActions[a])
		}
	}
	keyPath := fl.String("key", "", "operator's private key")
	var hostFiles trustFlag
	fl.Var(&hostFiles, "host", "host file of a host that is to carry the order out (repeat for more)")
	span := fl.Duration("for", 10*time.Minute, "how long the order stays good")
	wait := fl.Duration("wait", 0, "after sending, wait this long for the hosts' answers and print them")
	out := fl.String("o", "", "write the order to this file instead of sending it, for others to sign")
	fl.Parse(args)
	if *keyPath == "" || len(hostFiles) == 0 || fl.NArg() == 0 {
		fl.Usage()
		return exitError(2)
	}
	o, err := parseOrder(fl.Args())
	if err != nil {
		return err
	}
	if *span < tickPeriod || *span > orderMaxSpan*tickPeriod {
		return errors.New("-for must be between 3s and 24h")
	}
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	cards, err := loadHostCards(hostFiles)
	if err != nil {
		return err
	}
	for _, c := range cards {
		o.Hosts = append(o.Hosts, c.ID)
	}
	box, err := hostBoxKey()
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	tick, _ := new(ticker).now()
	o.From, o.Until = tick, tick+uint64(*span/tickPeriod)
	o.Nonce, o.Reply = hex.EncodeToString(nonce), b64.EncodeToString(box.public())
	o.Signatures = []orderSig{{key.pub, key.sign(o.message())}}
	b := orderBundle{Order: o, Hosts: cards}
	if *out != "" {
		if err := writeBundle(*out, b); err != nil {
			return err
		}
		fmt.Printf("order %s written to %s, not sent\n", o.id(), *out)
		return nil
	}
	return sendOrder(b, *wait)
}

func orderSign(args []string) error {
	fl := flag.NewFlagSet("order sign", flag.ExitOnError)
	keyPath := fl.String("key", "", "operator's private key")
	fl.Parse(args)
	if *keyPath == "" || fl.NArg() != 1 {
		return errors.New("usage: capsule order sign -key <file> <order file>")
	}
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	b, err := readBundle(fl.Arg(0))
	if err != nil {
		return err
	}
	o := &b.Order
	o.Signatures = slices.DeleteFunc(o.Signatures, func(s orderSig) bool { return s.Signer == key.pub })
	o.Signatures = append(o.Signatures, orderSig{key.pub, key.sign(o.message())})
	if err := writeBundle(fl.Arg(0), b); err != nil {
		return err
	}
	what := o.Action + " " + o.Capsule
	if len(o.Command) > 0 {
		what += " -- " + strings.Join(o.Command, " ")
	}
	fmt.Printf("signed order %s (%s): %d signature(s)\n", o.id(), strings.TrimSpace(what), len(o.Signatures))
	return nil
}

func orderSend(args []string) error {
	fl := flag.NewFlagSet("order send", flag.ExitOnError)
	wait := fl.Duration("wait", 0, "wait this long for the hosts' answers and print them")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule order send [-wait 30s] <order file>")
	}
	b, err := readBundle(fl.Arg(0))
	if err != nil {
		return err
	}
	return sendOrder(b, *wait)
}

func orderLedger() (ledger, error) {
	l, err := openLedger()
	if err == nil && l == nil {
		err = errors.New("no ledger is configured here (see <config>/ledger); orders travel through it")
	}
	return l, err
}

func sendOrder(b orderBundle, wait time.Duration) error {
	l, err := orderLedger()
	if err != nil {
		return err
	}
	o := b.Order
	raw, _ := json.Marshal(o)
	for _, h := range o.Hosts {
		if _, err := l.create("orders/"+idHex(h)+"/"+idHex(o.id()), raw); err != nil {
			return err
		}
	}
	if err := writeBundle(filepath.Join(sentDir(), idHex(o.id())+".json"), b); err != nil {
		return err
	}
	fmt.Printf("sent order %s to %d host(s)\n", o.id(), len(o.Hosts))
	if wait > 0 {
		return printResults(l, b, wait)
	}
	return nil
}

func orderResult(args []string) error {
	fl := flag.NewFlagSet("order result", flag.ExitOnError)
	wait := fl.Duration("wait", 0, "keep looking this long for answers still missing")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule order result [-wait 30s] <order file or id>")
	}
	b, err := findBundle(fl.Arg(0))
	if err != nil {
		return err
	}
	l, err := orderLedger()
	if err != nil {
		return err
	}
	return printResults(l, b, *wait)
}

// printResults prints each host's answer once it is there and checks out. It
// fails if any host refused, failed or has not answered in time.
func printResults(l ledger, b orderBundle, wait time.Duration) error {
	box, err := hostBoxKey()
	if err != nil {
		return err
	}
	id := b.Order.id()
	pending := slices.Clone(b.Hosts)
	failed := 0
	for deadline := time.Now().Add(wait); ; time.Sleep(time.Second) {
		pending = slices.DeleteFunc(pending, func(h hostCard) bool {
			raw, found, err := l.get("receipts/" + idHex(id) + "/" + idHex(h.ID))
			if err != nil || !found {
				return false
			}
			var r orderReceipt
			text := ""
			if json.Unmarshal(raw, &r) != nil || r.Order != id || r.Host != h.ID || r.Key != h.SignKey || !verifySig(r.Key, r.Signature, r.message()) {
				r.OK, text = false, "the answer in the ledger is not signed by this host"
			} else if text, err = openResult(r, box); err != nil {
				r.OK, text = false, "the answer is sealed to another machine: read it where the order was written"
			}
			state := "ok"
			if !r.OK {
				state = "FAILED"
				failed++
			}
			fmt.Printf("host %s: %s\n", h.ID, state)
			if text = strings.TrimRight(text, "\n"); text != "" {
				fmt.Println(text)
			}
			return true
		})
		if len(pending) == 0 || !time.Now().Before(deadline) {
			break
		}
	}
	for _, h := range pending {
		fmt.Printf("host %s: no answer yet\n", h.ID)
	}
	if failed+len(pending) > 0 {
		return exitError(1)
	}
	return nil
}

// ---- obeying ----

// cmdOrders pulls the orders addressed to this host and carries out those
// that are in order, once each. It is meant to be run every few seconds by a
// timer; it holds nothing open in between.
func cmdOrders(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: capsule orders")
	}
	rules, err := loadOrderRules()
	if err != nil {
		return err
	}
	if len(rules.operators) == 0 {
		return errors.New("this host obeys no one: put the operators' public keys in " + filepath.Join(configDir(), "operators.d"))
	}
	host, err := hostID()
	if err != nil {
		return err
	}
	l, err := orderLedger()
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir(), "orders")
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
	prefix := "orders/" + idHex(host) + "/"
	keys, err := l.list(prefix)
	if err != nil {
		return err
	}
	listed := map[string]bool{}
	var fresh []order
	for _, key := range keys {
		name := path.Base(key)
		listed[name] = true
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			continue // seen before
		}
		raw, found, err := l.get(key)
		if err != nil {
			return err
		}
		var o order
		if !found || json.Unmarshal(raw, &o) != nil || idHex(o.id()) != name || !slices.Contains(o.Hosts, host) {
			// Not an order for this host, whatever put it here. Remember the name so it is not read again.
			os.WriteFile(filepath.Join(dir, name), []byte("0\n"), 0o600)
			continue
		}
		fresh = append(fresh, o)
	}
	forgetOrders(dir, listed)
	if len(fresh) == 0 {
		return nil
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].From < fresh[j].From })
	clock := new(ticker)
	signing, err := hostSigner()
	if err != nil {
		return err
	}
	for _, o := range fresh {
		tick, _ := clock.now()
		if o.From > tick+tickSkew {
			continue // not yet
		}
		id := o.id()
		// Mark it before acting: an order is carried out at most once, even
		// if this process is cut short halfway.
		marker, err := os.OpenFile(filepath.Join(dir, idHex(id)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			continue
		}
		fmt.Fprintf(marker, "%d\n", o.Until)
		marker.Sync()
		marker.Close()

		result, known := "", true
		err = o.validate()
		if err == nil {
			err = rules.permits(o)
			known = err == nil
		}
		switch {
		case err != nil:
		case o.Until < o.From || o.Until-o.From > orderMaxSpan:
			err = errors.New("the order's span is longer than a day")
		case tick > o.Until:
			err = errors.New("the order has lapsed")
		default:
			left := time.Duration(o.Until-tick+1) * tickPeriod
			result, err = carryOut(o, left)
		}
		outcome := "done"
		if err != nil {
			outcome = "failed: " + err.Error()
			result = strings.TrimRight(result, "\n") + "\n" + err.Error()
			fmt.Fprintf(os.Stderr, "capsule: order %s (%s): %v\n", id, o.Action, err)
		}
		if known {
			// Only orders from this host's operators go on its record:
			// anything else is noise whoever can write to the ledger could make.
			if _, lerr := appendLog(logEntry{Event: "order", Capsule: o.Capsule, Detail: fmt.Sprintf("%s %s by %s: %s", id, o.Action, o.signers(), outcome)}); lerr != nil {
				fmt.Fprintln(os.Stderr, "capsule: could not record the order:", lerr)
			}
		}
		if len(result) > orderOutputMax {
			result = result[:orderOutputMax] + "\n[cut short]"
		}
		r := orderReceipt{Order: id, Host: host, Time: time.Now().UTC().Format(time.RFC3339), Tick: tick, OK: err == nil, Key: signing.pub}
		if r.Wrap, r.Result, err = sealResult(o.Reply, strings.TrimLeft(result, "\n")); err != nil {
			continue // no usable reply key: there is no one to tell
		}
		r.Signature = signing.sign(r.message())
		raw, _ := json.Marshal(r)
		if _, err := l.create("receipts/"+idHex(id)+"/"+idHex(host), raw); err != nil {
			fmt.Fprintln(os.Stderr, "capsule: could not publish the answer to order", id+":", err)
			continue
		}
		// The receipt stands for the order now. Clearing the order away
		// keeps each pass cheap; a store that will not delete is no harm.
		if r, ok := l.(interface{ remove(string) error }); ok {
			r.remove(prefix + idHex(id))
		}
	}
	return nil
}

// forgetOrders drops the memory of orders that have long lapsed and are gone
// from the ledger. Put back later, such an order is refused for its age.
func forgetOrders(dir string, listed map[string]bool) {
	now := clockTick(time.Now())
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if listed[e.Name()] || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		until, err := strconv.ParseUint(string(bytes.TrimSpace(raw)), 10, 64)
		if err == nil && until+orderKeep < now {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
