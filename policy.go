package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Policy is the sealed set of conditions that must hold before a capsule runs.
type Policy struct {
	NotBefore *time.Time `json:"not_before,omitempty"` // time lock
	Timelock  bool       `json:"timelock,omitempty"`   // enforce not_before with drand timelock encryption
	Expires   *time.Time `json:"expires,omitempty"`
	MaxRuns   int        `json:"max_runs,omitempty"`  // per host, or across the fleet with "fleet"; 0 is unlimited
	Fleet     bool       `json:"fleet,omitempty"`     // count runs and check revocation in the fleet ledger; refuse without it
	Permits   []string   `json:"permits,omitempty"`   // ids of keys that may issue run permits; a host then needs one to run it
	Hosts     []string   `json:"hosts,omitempty"`     // ids of the hosts (`capsule host`) allowed to run it
	Approvals *Approvals `json:"approvals,omitempty"` // M-of-N sign-off
}

type Approvals struct {
	Required int      `json:"required"`
	Signers  []string `json:"signers"` // key ids from `capsule keygen` (the .id file)
}

func (p *Policy) validate() error {
	if p.NotBefore != nil && p.Expires != nil && !p.NotBefore.Before(*p.Expires) {
		return errors.New("policy: not_before must be earlier than expires")
	}
	if p.Timelock && p.NotBefore == nil {
		return errors.New("policy: timelock needs not_before")
	}
	if p.MaxRuns < 0 {
		return errors.New("policy: max_runs is negative")
	}
	ids := slices.Concat(p.Hosts, p.Permits)
	if a := p.Approvals; a != nil {
		if a.Required < 1 || a.Required > len(a.Signers) {
			return errors.New("policy: approvals.required must be between 1 and the number of signers")
		}
		ids = append(slices.Clone(ids), a.Signers...)
	}
	for _, id := range ids {
		if !isID(id) {
			return fmt.Errorf("policy: %q is not a key id", id)
		}
	}
	return nil
}

// approval is one signer's sign-off on one exact seal.
type approval struct {
	Signer    string `json:"signer"`            // the signer's full public key
	Expires   int64  `json:"expires,omitempty"` // unix seconds; 0 never expires
	Signature string `json:"signature"`
}

func approvalMessage(sealID string, expires int64) []byte {
	return []byte("capsule-approval-v1\n" + sealID + "\n" + strconv.FormatInt(expires, 10) + "\n")
}

func readApprovals(dir string) []approval {
	var list []approval
	raw, _ := os.ReadFile(filepath.Join(dir, "capsule.approvals"))
	json.Unmarshal(raw, &list)
	return list
}

// countApprovals returns how many distinct required signers have a valid, unexpired approval.
func countApprovals(dir, sealID string, a *Approvals, now time.Time) int {
	seen := map[string]bool{}
	for _, ap := range readApprovals(dir) {
		id := keyID(ap.Signer)
		if id == "" || !slices.Contains(a.Signers, id) {
			continue
		}
		if ap.Expires != 0 && now.Unix() >= ap.Expires {
			continue
		}
		if verifySig(ap.Signer, ap.Signature, approvalMessage(sealID, ap.Expires)) {
			seen[id] = true
		}
	}
	return len(seen)
}

func cmdApprove(args []string) error {
	fl := flag.NewFlagSet("approve", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	days := fl.Int("days", 0, "approval lapses after this many days (0: never)")
	fl.Parse(args)
	if fl.NArg() != 1 || *keyPath == "" {
		return errors.New("usage: capsule approve -key <file> [-days N] <dir>")
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
	ap := approval{Signer: key.pub}
	if *days > 0 {
		ap.Expires = time.Now().AddDate(0, 0, *days).Unix()
	}
	ap.Signature = key.sign(approvalMessage(seal.id(), ap.Expires))

	list := slices.DeleteFunc(readApprovals(dir), func(old approval) bool { return old.Signer == ap.Signer })
	out, _ := json.MarshalIndent(append(list, ap), "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "capsule.approvals"), append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("approved", seal.id())
	return nil
}

// revocation withdraws one exact seal. Signed by a trusted key, it applies on
// every host that has the file; revoked.d can be a shared directory.
type revocation struct {
	Seal      string `json:"seal"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

func (r revocation) message() []byte { return []byte("capsule-revoke-v1\n" + r.Seal + "\n") }

func isRevoked(sealID string, trusted trustSet) bool {
	// the host operator's own list
	if f, err := os.Open(filepath.Join(configDir(), "revoked")); err == nil {
		defer f.Close()
		for sc := bufio.NewScanner(f); sc.Scan(); {
			if strings.TrimSpace(sc.Text()) == sealID {
				return true
			}
		}
	}
	files, _ := filepath.Glob(filepath.Join(configDir(), "revoked.d", "*.json"))
	for _, file := range files {
		raw, err := os.ReadFile(file)
		var r revocation
		if err == nil && json.Unmarshal(raw, &r) == nil && r.Seal == sealID && signedBy(trusted, r.Signer, r.Signature, r.message()) {
			return true
		}
	}
	return false
}

// cmdRevoke stops one exact seal from running again: on this host, or with
// -key as a signed notice for every host that is given it.
func cmdRevoke(args []string) error {
	fl := flag.NewFlagSet("revoke", flag.ExitOnError)
	keyPath := fl.String("key", "", "sign a revocation for all hosts instead of revoking only here")
	publish := fl.Bool("publish", false, "with -key: put the revocation in the fleet ledger instead of printing it")
	fl.Parse(args)
	if fl.NArg() != 1 || (*publish && *keyPath == "") {
		return errors.New("usage: capsule revoke [-key <file> [-publish]] <dir>")
	}
	seal, err := readSeal(fl.Arg(0))
	if err != nil {
		return err
	}
	if *keyPath != "" {
		key, err := loadSigner(*keyPath)
		if err != nil {
			return err
		}
		r := revocation{Seal: seal.id(), Signer: key.pub}
		r.Signature = key.sign(r.message())
		out, _ := json.MarshalIndent(r, "", "  ")
		if !*publish {
			fmt.Println(string(out))
			return nil
		}
		l, err := openLedger()
		if err != nil {
			return err
		}
		if l == nil {
			return errors.New("this host has no ledger configured (see <config>/ledger)")
		}
		if _, err := l.create("revoked/"+idHex(seal.id())+"/"+idHex(key.id()), out); err != nil {
			return err
		}
		fmt.Println("revoked for the whole fleet:", seal.id())
		return nil
	}
	return revokeHere(seal.id())
}

// revokeHere adds a seal to this host's own list of seals it will never run.
func revokeHere(sealID string) error {
	if isRevoked(sealID, nil) {
		return nil
	}
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(configDir(), "revoked"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, sealID)
	return err
}

// checkPolicy decides whether this host may run this capsule right now.
func checkPolicy(dir string, sc sealedCapsule, trusted trustSet, now time.Time) error {
	if isRevoked(sc.ID, trusted) {
		return errors.New("this seal has been revoked")
	}
	l, err := fleetLedger(sc.Manifest.Policy)
	if err != nil {
		return err
	}
	if l != nil {
		revoked, err := ledgerRevoked(l, sc.ID, trusted)
		if err != nil && sc.Manifest.Policy != nil && sc.Manifest.Policy.Fleet {
			return fmt.Errorf("cannot check the fleet ledger, which this capsule requires: %w", err)
		} else if err != nil {
			fmt.Fprintln(os.Stderr, "capsule: could not check the ledger for revocations:", err)
		}
		if revoked {
			return errors.New("this seal has been revoked for the whole fleet")
		}
	}
	if err := admit(sc.ManifestRaw); err != nil {
		return err
	}
	p := sc.Manifest.Policy
	if p == nil {
		return nil
	}
	if p.NotBefore != nil || p.Expires != nil {
		// A host cannot prove what time it is, but it can notice its clock
		// has been set back to before something it already recorded.
		if last := lastLogTime(); now.Before(last.Add(-5 * time.Minute)) {
			return fmt.Errorf("host clock (%s) is behind its own record (%s); not trusting it for a time-limited capsule",
				now.UTC().Format(time.RFC3339), last.Format(time.RFC3339))
		}
	}
	if p.NotBefore != nil && now.Before(*p.NotBefore) {
		return fmt.Errorf("time-locked until %s", p.NotBefore.Format(time.RFC3339))
	}
	if p.Expires != nil && !now.Before(*p.Expires) {
		return fmt.Errorf("expired at %s", p.Expires.Format(time.RFC3339))
	}
	if len(p.Hosts) > 0 {
		id, err := hostID()
		if err != nil {
			return err
		}
		if !slices.Contains(p.Hosts, id) {
			return errors.New("this host is not authorised to run it")
		}
		if !sc.Seal.Encrypted {
			return errors.New("a host list only binds when the rootfs is encrypted to those hosts; seal it again")
		}
	}
	if p.Timelock && sc.Seal.Timelock == nil {
		return errors.New("policy asks for a time lock but the seal has none; seal it again")
	}
	if a := p.Approvals; a != nil {
		if got := countApprovals(dir, sc.ID, a, now); got < a.Required {
			return fmt.Errorf("has %d of %d required approvals", got, a.Required)
		}
	}
	return nil
}

// countRun records one more run of this seal, or refuses if it has none left.
// Three limits can apply: permits issued to this host, a per-host max_runs,
// and a fleet-wide max_runs counted in the ledger.
func countRun(dir string, sc sealedCapsule, now time.Time) error {
	p := sc.Manifest.Policy
	if p == nil || (p.MaxRuns == 0 && len(p.Permits) == 0) {
		return nil
	}
	limit, what := -1, ""
	if len(p.Permits) > 0 {
		allowed, err := permittedRuns(dir, sc, now)
		if err != nil {
			return err
		}
		if allowed == 0 {
			return errors.New("this host holds no valid permit to run it")
		}
		limit, what = allowed, "permitted"
	}
	if p.MaxRuns > 0 && !p.Fleet && (limit < 0 || p.MaxRuns < limit) {
		limit, what = p.MaxRuns, "permitted"
	}

	runs := filepath.Join(dataDir(), "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(runs, idHex(sc.ID)), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	raw, _ := os.ReadFile(f.Name())
	used, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if limit >= 0 && used >= limit {
		return fmt.Errorf("already ran %d of %d %s times on this host", used, limit, what)
	}
	if p.Fleet && p.MaxRuns > 0 {
		l, err := fleetLedger(p)
		if err != nil {
			return err
		}
		if err := claimFleetRun(l, sc); err != nil {
			return err
		}
	}
	if _, err = f.WriteAt([]byte(strconv.Itoa(used+1)+"\n"), 0); err == nil {
		err = f.Sync() // a counted run stays counted across a power cut
	}
	return err
}
