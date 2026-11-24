package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// idHex turns a key id or seal id into a form usable in a ledger key.
func idHex(id string) string {
	if rest, ok := strings.CutPrefix(id, "sha256:"); ok {
		return rest
	}
	raw, _ := b64.DecodeString(id)
	return hex.EncodeToString(raw)
}

// ---- permits: run limits that need no network ----

// permit lets one named host run one exact seal a number of times. Because
// each host is told its own share in advance, no host has to ask anyone how
// many runs the others have used.
type permit struct {
	Seal      string `json:"seal"`
	Host      string `json:"host"` // host id
	Runs      int    `json:"runs"`
	Expires   int64  `json:"expires,omitempty"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

func (p permit) message() []byte {
	return []byte(fmt.Sprintf("capsule-permit-v1\n%s\n%s\n%d\n%d\n", p.Seal, p.Host, p.Runs, p.Expires))
}

func readPermits(dir string) []permit {
	var list []permit
	raw, _ := os.ReadFile(filepath.Join(dir, "capsule.permits"))
	json.Unmarshal(raw, &list)
	return list
}

// permittedRuns adds up the valid permits this host holds for this seal.
func permittedRuns(dir string, sc sealedCapsule, now time.Time) (int, error) {
	host, err := hostID()
	if err != nil {
		return 0, err
	}
	total := 0
	for _, p := range readPermits(dir) {
		if p.Seal != sc.ID || p.Host != host || p.Runs < 1 || (p.Expires != 0 && now.Unix() >= p.Expires) {
			continue
		}
		if slices.Contains(sc.Manifest.Policy.Permits, keyID(p.Signer)) && verifySig(p.Signer, p.Signature, p.message()) {
			total += p.Runs
		}
	}
	return total, nil
}

func cmdPermit(args []string) error {
	fl := flag.NewFlagSet("permit", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	host := fl.String("host", "", "id of the host the permit is for, from `capsule host`")
	runs := fl.Int("runs", 1, "how many times that host may run it")
	days := fl.Int("days", 0, "permit lapses after this many days (0: never)")
	fl.Parse(args)
	if fl.NArg() != 1 || *keyPath == "" || !isID(*host) || *runs < 1 {
		return errors.New("usage: capsule permit -key <file> -host <host id> [-runs N] [-days N] <dir>")
	}
	dir := fl.Arg(0)
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	seal, err := readSeal(dir)
	if err != nil {
		return err
	}
	p := permit{Seal: seal.id(), Host: *host, Runs: *runs, Signer: key.pub}
	if *days > 0 {
		p.Expires = time.Now().AddDate(0, 0, *days).Unix()
	}
	p.Signature = key.sign(p.message())
	out, _ := json.MarshalIndent(append(readPermits(dir), p), "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "capsule.permits"), append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("permitted %d runs of %s on host %s\n", *runs, seal.id(), *host)
	return nil
}

// ---- the fleet ledger: run slots and revocations ----

// fleetLedger opens the ledger for a capsule. One whose policy says "fleet"
// must have it; for any other it is used if present and reachable.
func fleetLedger(p *Policy) (ledger, error) {
	l, err := openLedger()
	required := p != nil && p.Fleet
	if required && err == nil && l == nil {
		err = errors.New("this capsule needs the fleet ledger, and this host has none configured (see <config>/ledger)")
	}
	if err != nil && !required {
		fmt.Fprintln(os.Stderr, "capsule: continuing without the ledger:", err)
		return nil, nil
	}
	return l, err
}

// runClaim records which host took a run slot.
type runClaim struct {
	Seal      string `json:"seal"`
	Slot      int    `json:"slot"`
	Time      string `json:"time"`
	Host      string `json:"host"`
	Signature string `json:"signature"`
}

// claimFleetRun takes one of the capsule's fleet-wide run slots. A slot is a
// ledger key that can be created once, and the claim is confirmed by reading
// it back, so two hosts can never both get it.
func claimFleetRun(l ledger, sc sealedCapsule) error {
	limit := sc.Manifest.Policy.MaxRuns
	prefix := "runs/" + idHex(sc.ID) + "/"
	taken, err := l.list(prefix)
	if err != nil {
		return err
	}
	key, err := hostSigner()
	if err != nil {
		return err
	}
	for slot := len(taken) + 1; slot <= limit; slot++ {
		claim := runClaim{Seal: sc.ID, Slot: slot, Time: time.Now().UTC().Format(time.RFC3339), Host: key.pub}
		claim.Signature = key.sign([]byte(fmt.Sprintf("capsule-run-v1\n%s\n%d\n%s\n", claim.Seal, claim.Slot, claim.Time)))
		raw, _ := json.Marshal(claim)
		created, err := createOnce(l, fmt.Sprintf("%s%06d", prefix, slot), raw) // raw is unique: it carries this host's signature and the time
		if err != nil {
			return err
		}
		if created {
			return nil
		}
	}
	return fmt.Errorf("all %d fleet-wide runs have been used", limit)
}

// ledgerRevoked reports whether a trusted key has published a revocation of this seal.
func ledgerRevoked(l ledger, sealID string, trusted trustSet) (bool, error) {
	keys, err := l.list("revoked/" + idHex(sealID) + "/")
	if err != nil {
		return false, err
	}
	for _, key := range keys {
		raw, found, err := l.get(key)
		if err != nil {
			return false, err
		}
		var r revocation
		if found && json.Unmarshal(raw, &r) == nil && r.Seal == sealID && signedBy(trusted, r.Signer, r.Signature, r.message()) {
			return true, nil
		}
	}
	return false, nil
}

// ---- witnessing: hosts keep each other's records honest ----

// head is a host's signed statement of what its log looked like at one entry.
// Once published it cannot be replaced, so a host that later rewrites its log
// contradicts its own earlier statements, which other hosts have co-signed.
type head struct {
	Host      string `json:"host"` // full signing key
	Seq       int    `json:"seq"`
	Head      string `json:"head"` // hash of that log line
	Signature string `json:"signature"`
}

func (h head) message() []byte {
	return []byte(fmt.Sprintf("capsule-head-v1\n%s\n%d\n%s\n", keyID(h.Host), h.Seq, h.Head))
}

func headKey(hostID string, seq int) string {
	return fmt.Sprintf("heads/%s/%010d", idHex(hostID), seq)
}

// publishHeads publishes a head for every log entry not yet published.
func publishHeads(l ledger) error {
	key, err := hostSigner()
	if err != nil {
		return err
	}
	f, err := os.Open(logPath())
	if err != nil {
		return nil // nothing logged yet
	}
	defer f.Close()
	// "published" holds the number of the last entry published. Where the
	// next one begins in the current file is remembered separately, purely
	// to avoid re-reading; entries carry their own numbers, so a wrong or
	// missing offset costs time, never correctness.
	marker := filepath.Join(dataDir(), "published")
	done, offset := -1, int64(0)
	if m, err := os.ReadFile(marker); err == nil {
		done, _ = strconv.Atoi(strings.Fields(string(m) + " -1")[0])
	}
	if o, err := os.ReadFile(marker + ".offset"); err == nil {
		offset, _ = strconv.ParseInt(strings.TrimSpace(string(o)), 10, 64)
	}
	if info, err := f.Stat(); err != nil || offset > info.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	lines := bufio.NewScanner(f)
	lines.Buffer(nil, 4<<20)
	for lines.Scan() {
		offset += int64(len(lines.Bytes())) + 1
		var e logEntry
		if json.Unmarshal(lines.Bytes(), &e) != nil || e.Seq <= done {
			continue
		}
		h := head{Host: key.pub, Seq: e.Seq, Head: digest(lines.Bytes())}
		h.Signature = key.sign(h.message())
		value, _ := json.Marshal(h)
		if _, err := l.create(headKey(key.id(), e.Seq), value); err != nil {
			return err
		}
		done = e.Seq
		if err := os.WriteFile(marker, []byte(strconv.Itoa(done)+"\n"), 0o600); err != nil {
			return err
		}
		os.WriteFile(marker+".offset", []byte(strconv.FormatInt(offset, 10)+"\n"), 0o600)
	}
	return lines.Err()
}

type seenHead struct {
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}

// witness co-signs the newest head of every other host, and compares each
// against what this host saw before. It returns how many hosts it witnessed
// and a description of anything that shows a record was altered.
func witness(l ledger) (int, []string, error) {
	me, err := hostSigner()
	if err != nil {
		return 0, nil, err
	}
	keys, err := l.list("heads/")
	if err != nil {
		return 0, nil, err
	}
	latest := map[string]string{} // host (hex) -> its highest head key; keys sort by sequence
	for _, k := range keys {
		if parts := strings.Split(k, "/"); len(parts) == 3 && parts[1] != idHex(me.id()) {
			latest[parts[1]] = k
		}
	}
	seenDir := filepath.Join(dataDir(), "witness")
	if err := os.MkdirAll(seenDir, 0o700); err != nil {
		return 0, nil, err
	}
	load := func(key string) (head, bool) {
		var h head
		raw, found, err := l.get(key)
		ok := err == nil && found && json.Unmarshal(raw, &h) == nil && verifySig(h.Host, h.Signature, h.message())
		return h, ok
	}
	var alerts []string
	witnessed := 0
	for host, key := range latest {
		h, ok := load(key)
		if !ok || idHex(keyID(h.Host)) != host || key != headKey(keyID(h.Host), h.Seq) {
			alerts = append(alerts, fmt.Sprintf("host %s published a record entry that is not validly signed", host[:12]))
			continue
		}
		var seen seenHead
		seenFile := filepath.Join(seenDir, host)
		if raw, err := os.ReadFile(seenFile); err == nil && json.Unmarshal(raw, &seen) == nil {
			old, stillThere := load(headKey(keyID(h.Host), seen.Seq))
			switch {
			case h.Seq < seen.Seq:
				alerts = append(alerts, fmt.Sprintf("host %s: its record now ends at entry %d, but entry %d was published before; entries have been removed", host[:12], h.Seq, seen.Seq))
				continue
			case !stillThere || old.Head != seen.Head:
				alerts = append(alerts, fmt.Sprintf("host %s: entry %d of its record is not what it published before; the record has been rewritten", host[:12], seen.Seq))
				continue
			}
		}
		co := map[string]string{"witness": me.pub, "signature": me.sign(h.message())}
		value, _ := json.Marshal(co)
		if _, err := l.create(fmt.Sprintf("witness/%s/%010d/%s", host, h.Seq, idHex(me.id())), value); err != nil {
			return witnessed, alerts, err
		}
		raw, _ := json.Marshal(seenHead{h.Seq, h.Head})
		if err := os.WriteFile(seenFile, raw, 0o600); err != nil {
			return witnessed, alerts, err
		}
		witnessed++
	}
	return witnessed, alerts, nil
}

// cmdWitness publishes this host's record and witnesses the others'. Run it
// from a timer on hosts that do not start capsules often; `capsule run` also
// does it after each run.
func cmdWitness(args []string) error {
	l, err := openLedger()
	if err != nil {
		return err
	}
	if l == nil {
		return errors.New("this host has no ledger configured (see <config>/ledger)")
	}
	if err := publishHeads(l); err != nil {
		return err
	}
	n, alerts, err := witness(l)
	if err != nil {
		return err
	}
	fmt.Printf("witnessed %d other hosts\n", n)
	if len(alerts) > 0 {
		return errors.New(strings.Join(alerts, "\n"))
	}
	return nil
}

// checkPublished compares a log with the heads its host published and counts
// who co-signed them. lines are the log's lines in order; host is the id of
// the key that signed them.
func checkPublished(l ledger, host string, base int, lines [][]byte) (string, error) {
	keys, err := l.list("heads/" + idHex(host) + "/")
	if err != nil {
		return "", err
	}
	for _, key := range keys {
		raw, found, err := l.get(key)
		if err != nil {
			return "", err
		}
		var h head
		if !found || json.Unmarshal(raw, &h) != nil || keyID(h.Host) != host || !verifySig(h.Host, h.Signature, h.message()) {
			continue // not this host's statement; nothing to hold it to
		}
		if h.Seq < base {
			continue // in a file set aside by rotation; capsule log -all -ledger checks those too
		}
		if h.Seq-base >= len(lines) {
			return "", fmt.Errorf("entry %d was published to the ledger but is missing here: entries have been removed from this log", h.Seq)
		}
		if digest(lines[h.Seq-base]) != h.Head {
			return "", fmt.Errorf("entry %d is not what was published to the ledger: this log was rewritten after publication", h.Seq)
		}
	}
	witnesses := map[string]bool{}
	cosigned, err := l.list("witness/" + idHex(host) + "/")
	if err != nil {
		return "", err
	}
	for _, key := range cosigned {
		parts := strings.Split(key, "/")
		seq, convErr := strconv.Atoi(parts[len(parts)-2])
		raw, found, err := l.get(key)
		var co struct{ Witness, Signature string }
		if err != nil || convErr != nil || !found || json.Unmarshal(raw, &co) != nil || seq < base || seq-base >= len(lines) {
			continue
		}
		var hostPub string
		if hraw, ok, _ := l.get(headKey(host, seq)); ok {
			var h head
			json.Unmarshal(hraw, &h)
			hostPub = h.Host
		}
		if verifySig(co.Witness, co.Signature, head{Host: hostPub, Seq: seq, Head: digest(lines[seq-base])}.message()) {
			witnesses[keyID(co.Witness)] = true
		}
	}
	return fmt.Sprintf("ledger: %d entries published and matching, co-signed by %d other hosts", len(keys), len(witnesses)), nil
}
