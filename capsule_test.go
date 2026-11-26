package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// newHost points this test at a fresh, empty host: its own secret, log and counters.
func newHost(t *testing.T) {
	t.Helper()
	t.Setenv("CAPSULE_CONFIG", t.TempDir())
	t.Setenv("CAPSULE_DATA", t.TempDir())
}

// newKey makes a signing key and returns its private key file and its id.
func newKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := cmdKeygen([]string{path}); err != nil {
		t.Fatal(err)
	}
	key, err := loadSigner(path + ".key")
	must(t, err)
	return path + ".key", key.id()
}

// hostFile writes the export file for a host key and returns its path and the host's id.
func hostFile(t *testing.T, host *hostKEM) (string, string) {
	t.Helper()
	data, _ := json.Marshal(hostCard{ID: host.id(), Key: b64.EncodeToString(host.public())})
	path := filepath.Join(t.TempDir(), "host.json")
	must(t, os.WriteFile(path, data, 0o644))
	return path, host.id()
}

func randomHost(t *testing.T) *hostKEM {
	t.Helper()
	seed := make([]byte, 32)
	rand.Read(seed)
	host, err := newHostKEM(seed)
	must(t, err)
	return host
}

// newCapsule writes a small capsule directory with the given manifest.
func newCapsule(t *testing.T, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "rootfs/bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "rootfs/bin/app"), []byte("#!/bin/sh\necho hi\n"), 0o755))
	must(t, os.Symlink("app", filepath.Join(dir, "rootfs/bin/alias")))
	must(t, os.WriteFile(filepath.Join(dir, "capsule.json"), []byte(manifest), 0o644))
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("got error %v, want one containing %q", err, contains)
	}
}

const plain = `{"name":"app","command":["/bin/app"]}`

func TestSealDetectsEveryChange(t *testing.T) {
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	_, other := newKey(t, keys, "other")
	trusted := trustSet{id: true}
	dir := newCapsule(t, plain)

	wantErr(t, verifyCapsule(dir, trusted), "not sealed")
	_, err := sealCapsule(dir, key, nil)
	must(t, err)
	must(t, verifyCapsule(dir, trusted))
	wantErr(t, verifyCapsule(dir, trustSet{other: true}), "does not trust")
	wantErr(t, verifyCapsule(dir, nil), "no trusted keys")

	app := filepath.Join(dir, "rootfs/bin/app")
	for name, change := range map[string]func(){
		"file contents": func() { must(t, os.WriteFile(app, []byte("#!/bin/sh\necho evil\n"), 0o755)) },
		"file mode":     func() { must(t, os.Chmod(app, 0o700)) },
		"added file":    func() { must(t, os.WriteFile(app+"2", nil, 0o644)) },
		"symlink target": func() {
			os.Remove(filepath.Join(dir, "rootfs/bin/alias"))
			os.Symlink("/etc/passwd", filepath.Join(dir, "rootfs/bin/alias"))
		},
	} {
		must(t, os.Chmod(app, 0o755))
		_, err := sealCapsule(dir, key, nil)
		must(t, err)
		change()
		if err := verifyCapsule(dir, trusted); err == nil || !strings.Contains(err.Error(), "rootfs was changed") {
			t.Errorf("%s: change not detected (%v)", name, err)
		}
	}

	_, err = sealCapsule(dir, key, nil)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "capsule.json"), []byte(`{"name":"app","command":["/bin/sh"]}`), 0o644))
	wantErr(t, verifyCapsule(dir, trusted), "capsule.json was changed")

	// A seal re-signed by an attacker's key over the attacker's content is still not trusted.
	must(t, os.WriteFile(filepath.Join(dir, "capsule.json"), []byte(plain), 0o644))
	_, err = sealCapsule(dir, filepath.Join(keys, "other.key"), nil)
	must(t, err)
	wantErr(t, verifyCapsule(dir, trusted), "does not trust")

	// A seal that keeps the trusted key's name but carries someone else's signature.
	_, err = sealCapsule(dir, key, nil)
	must(t, err)
	good, err := readSeal(dir)
	must(t, err)
	mallory, err := loadSigner(filepath.Join(keys, "other.key"))
	must(t, err)
	forged := good
	forged.Signature = mallory.sign(good.message())
	data, _ := json.Marshal(forged)
	must(t, os.WriteFile(filepath.Join(dir, "capsule.seal"), data, 0o644))
	wantErr(t, verifyCapsule(dir, trusted), "signature is invalid")
}

func TestSignatureNeedsBothHalves(t *testing.T) {
	seedA, seedB := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a, b := newSigner(seedA), newSigner(seedB)
	msg := []byte("capsule-seal-v1\nexample\n")
	sig := a.sign(msg)
	if !verifySig(a.pub, sig, msg) {
		t.Fatal("a genuine signature does not verify")
	}
	if newSigner(seedA).pub != a.pub || a.pub == b.pub || a.id() == b.id() {
		t.Fatal("keys are not a pure function of their seed")
	}
	rawA, _ := b64.DecodeString(sig)
	rawB, _ := b64.DecodeString(b.sign(msg))
	const split = ed25519.SignatureSize
	pubA, _ := b64.DecodeString(a.pub)
	pubB, _ := b64.DecodeString(b.pub)
	join := func(x, y []byte) string { return b64.EncodeToString(append(append([]byte{}, x...), y...)) }
	for name, c := range map[string][2]string{
		"other message":                {a.pub, a.sign([]byte("other"))},
		"another key's signature":      {a.pub, b.sign(msg)},
		"only the classical half":      {a.pub, join(rawA[:split], rawB[split:])},
		"only the post-quantum half":   {a.pub, join(rawB[:split], rawA[split:])},
		"classical half alone":         {a.pub, b64.EncodeToString(rawA[:split])},
		"post-quantum half zeroed":     {a.pub, join(rawA[:split], make([]byte, len(rawA)-split))},
		"key with a swapped classical": {join(pubB[:ed25519.PublicKeySize], pubA[ed25519.PublicKeySize:]), sig},
		"key with a swapped quantum":   {join(pubA[:ed25519.PublicKeySize], pubB[ed25519.PublicKeySize:]), sig},
	} {
		if verifySig(c[0], c[1], msg) {
			t.Errorf("%s: accepted", name)
		}
	}
	// A key that shares one half with a trusted key is a different key, not a trusted one.
	half := join(pubA[:ed25519.PublicKeySize], pubB[ed25519.PublicKeySize:])
	if keyID(half) == a.id() || signedBy(trustSet{a.id(): true}, half, sig, msg) {
		t.Error("a key sharing one half with a trusted key was treated as trusted")
	}
}

func TestManifestRejectsWhatItDoesNotUnderstand(t *testing.T) {
	for manifest, want := range map[string]string{
		`{"name":"app","command":["/x"],"priviledged":true}`:                                                                               "unknown field",
		`{"name":"App","command":["/x"]}`:                                                                                                  "name must match",
		`{"name":"app","command":[]}`:                                                                                                      "command is empty",
		`{"name":"app","command":["/x"],"network":"bridge"}`:                                                                               "network must be",
		`{"name":"app","command":["/x"],"network":"mesh"}`:                                                                                 "needs a mesh section",
		`{"name":"app","command":["/x"],"publish":[70000]}`:                                                                                "not a port",
		`{"name":"app","command":["/x"],"egress":[{"host":"localhost","port":80}]}`:                                                        "not a host name",
		`{"name":"app","command":["/x"],"network":"host","publish":[80]}`:                                                                  "do not apply",
		`{"name":"app","command":["/x"],"syscalls":["read","frobnicate"]}`:                                                                 "unknown syscall",
		`{"name":"app","command":["/x"],"policy":{"timelock":true}}`:                                                                       "timelock needs not_before",
		`{"name":"app","command":["/x"],"policy":{"hosts":["short"]}}`:                                                                     "is not a key",
		`{"name":"app","command":["/x"],"policy":{"approvals":{"required":2,"signers":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}}}`: "approvals.required",
	} {
		if _, err := parseManifest([]byte(manifest)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s\n  got %v, want an error containing %q", manifest, err, want)
		}
	}
}

func TestEncryptedRootfs(t *testing.T) {
	src := filepath.Join(newCapsule(t, plain), "rootfs")
	must(t, os.WriteFile(filepath.Join(src, "big"), bytes.Repeat([]byte("capsule "), 40000), 0o600)) // several chunks
	want, err := hashRootfs(src)
	must(t, err)
	key := make([]byte, 32)
	rand.Read(key)
	var enc bytes.Buffer
	must(t, encryptTree(src, &enc, key))
	if bytes.Contains(enc.Bytes(), []byte("capsule capsule")) {
		t.Fatal("ciphertext contains plaintext")
	}

	out := filepath.Join(t.TempDir(), "rootfs")
	must(t, decryptTree(bytes.NewReader(enc.Bytes()), key, out))
	got, err := hashRootfs(out)
	must(t, err)
	if got != want {
		t.Fatal("decrypted rootfs differs from the original")
	}

	data := enc.Bytes()
	header := len(encMagic)
	first := 4 + chunkSize + 16 // one full chunk: length, ciphertext, tag
	swapped := append([]byte{}, data[:header]...)
	swapped = append(swapped, data[header+first:header+2*first]...)
	swapped = append(swapped, data[header:header+first]...)
	swapped = append(swapped, data[header+2*first:]...)
	flipped := append([]byte{}, data...)
	flipped[len(flipped)/2] ^= 1
	wrongKey := make([]byte, 32)
	for name, c := range map[string]struct {
		data []byte
		key  []byte
	}{
		"flipped bit":      {flipped, key},
		"cut short":        {data[:len(data)-100], key},
		"last chunk gone":  {data[:header+first], key},
		"chunks reordered": {swapped, key},
		"wrong key":        {data, wrongKey},
	} {
		if err := decryptTree(bytes.NewReader(c.data), c.key, filepath.Join(t.TempDir(), "rootfs")); err == nil {
			t.Errorf("%s: decrypted without error", name)
		}
	}
}

func TestKeyWrapNeedsBothExchanges(t *testing.T) {
	host, stranger := randomHost(t), randomHost(t)
	part := []byte("0123456789abcdef0123456789abcdef")
	r, err := wrapKey(part, host.public())
	must(t, err)
	got, err := unwrapKey(r, host)
	must(t, err)
	if !bytes.Equal(got, part) {
		t.Fatal("unwrapped key differs")
	}
	if r.Host != host.id() || host.id() == stranger.id() {
		t.Fatal("recipient is not labelled with its host's id")
	}
	if _, err := unwrapKey(r, stranger); err == nil {
		t.Fatal("another host unwrapped the key")
	}
	// A host holding only one of the two private keys cannot unwrap.
	if _, err := unwrapKey(r, &hostKEM{x: host.x, m: stranger.m}); err == nil {
		t.Fatal("unwrapped with the classical key alone")
	}
	if _, err := unwrapKey(r, &hostKEM{x: stranger.x, m: host.m}); err == nil {
		t.Fatal("unwrapped with the post-quantum key alone")
	}
	// Each public value of the exchange is bound into the wrapping key.
	other, err := wrapKey(part, host.public())
	must(t, err)
	for name, edit := range map[string]func(*recipient){
		"ephemeral key swapped":  func(r *recipient) { r.Ephemeral = other.Ephemeral },
		"KEM ciphertext swapped": func(r *recipient) { r.KEM = other.KEM },
		"wrapped key swapped":    func(r *recipient) { r.Key = other.Key },
	} {
		edited := r
		edit(&edited)
		if _, err := unwrapKey(edited, host); err == nil {
			t.Errorf("%s: still unwrapped", name)
		}
	}
	if _, err := wrapKey(part, host.public()[:40]); err == nil {
		t.Error("wrapped to a truncated host key")
	}
	if bytes.Equal(contentKey(part, nil), contentKey(nil, part)) || bytes.Equal(contentKey(part, nil), part) {
		t.Fatal("content key does not depend on which part is which")
	}
}

// archive builds a tar from (name, type, body-or-link) entries.
func archive(t *testing.T, entries ...[3]string) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o644}
		switch e[1] {
		case "dir":
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case "file":
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e[2]))
		case "symlink":
			h.Typeflag, h.Linkname = tar.TypeSymlink, e[2]
		case "hardlink":
			h.Typeflag, h.Linkname = tar.TypeLink, e[2]
		case "device":
			h.Typeflag = tar.TypeChar
		}
		must(t, w.WriteHeader(h))
		if e[1] == "file" {
			w.Write([]byte(e[2]))
		}
	}
	must(t, w.Close())
	return tar.NewReader(&buf)
}

func TestUnpackCannotEscape(t *testing.T) {
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	for name, entries := range map[string][][3]string{
		"parent path":         {{"../victim", "file", "x"}},
		"absolute path":       {{victim, "file", "x"}},
		"through a symlink":   {{"link", "symlink", outside}, {"link/victim", "file", "x"}},
		"through a deep link": {{"a", "dir", ""}, {"a/link", "symlink", "../.."}, {"a/link/victim", "file", "x"}},
		"hardlink to outside": {{"link", "hardlink", "../victim"}},
	} {
		dst := filepath.Join(outside, "dst-"+strings.ReplaceAll(name, " ", "-"))
		if _, err := unpackTar(archive(t, entries...), dst, false); err == nil {
			t.Errorf("%s: unpacked without error", name)
		}
		if _, err := os.Lstat(victim); err == nil {
			t.Fatalf("%s: wrote outside the destination", name)
		}
	}

	dst := filepath.Join(t.TempDir(), "ok")
	skipped, err := unpackTar(archive(t, [3]string{"bin", "dir", ""}, [3]string{"bin/app", "file", "x"},
		[3]string{"bin/app2", "hardlink", "bin/app"}, [3]string{"dev/null", "device", ""}), dst, false)
	must(t, err)
	if skipped != 1 {
		t.Errorf("skipped %d entries, want 1 (the device)", skipped)
	}
	if _, err := unpackTar(archive(t, [3]string{"dev/null", "device", ""}), filepath.Join(t.TempDir(), "strict"), true); err == nil {
		t.Error("strict mode accepted a device node")
	}
}

func TestPolicy(t *testing.T) {
	newHost(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	aliceKey, alice := newKey(t, keys, "alice")
	bobKey, bob := newKey(t, keys, "bob")
	malloryKey, _ := newKey(t, keys, "mallory")
	trusted := trustSet{id: true}
	self, err := hostBoxKey()
	must(t, err)
	selfFile, selfID := hostFile(t, self)
	strangerFile, strangerID := hostFile(t, randomHost(t))
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	check := func(manifest string, prepare func(dir string)) error {
		t.Helper()
		dir := newCapsule(t, manifest)
		_, err := sealCapsule(dir, key, []string{selfFile, strangerFile})
		must(t, err)
		if prepare != nil {
			prepare(dir)
		}
		sc, err := openCapsule(dir, trusted)
		must(t, err)
		return checkPolicy(dir, sc, trusted, now)
	}

	must(t, check(plain, nil))
	wantErr(t, check(`{"name":"app","command":["/x"],"policy":{"not_before":"2026-06-02T00:00:00Z"}}`, nil), "time-locked until")
	wantErr(t, check(`{"name":"app","command":["/x"],"policy":{"expires":"2026-06-01T00:00:00Z"}}`, nil), "expired at")
	must(t, check(`{"name":"app","command":["/x"],"policy":{"not_before":"2026-05-01T00:00:00Z","expires":"2026-07-01T00:00:00Z"}}`, nil))

	wantErr(t, check(`{"name":"app","command":["/x"],"policy":{"hosts":["`+strangerID+`"]}}`, nil), "not authorised")
	must(t, check(`{"name":"app","command":["/x"],"policy":{"hosts":["`+selfID+`"]}}`, nil))
	// A capsule cannot be sealed for a host whose key the sealer does not have.
	unknown := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"hosts":["`+selfID+`"]}}`)
	_, err = sealCapsule(unknown, key, []string{strangerFile})
	wantErr(t, err, "host file was not given")

	approvals := `{"name":"app","command":["/x"],"policy":{"approvals":{"required":2,"signers":["` + alice + `","` + bob + `"]}}}`
	wantErr(t, check(approvals, nil), "has 0 of 2")
	wantErr(t, check(approvals, func(dir string) {
		must(t, cmdApprove([]string{"-key", aliceKey, dir}))
		must(t, cmdApprove([]string{"-key", aliceKey, dir}))   // twice by one signer
		must(t, cmdApprove([]string{"-key", malloryKey, dir})) // not a listed signer
	}), "has 1 of 2")
	must(t, check(approvals, func(dir string) {
		must(t, cmdApprove([]string{"-key", aliceKey, dir}))
		must(t, cmdApprove([]string{"-key", bobKey, dir}))
	}))
	wantErr(t, check(approvals, func(dir string) { // approvals copied from a different seal
		other := newCapsule(t, strings.Replace(approvals, `"/x"`, `"/y"`, 1))
		_, err := sealCapsule(other, key, nil)
		must(t, err)
		must(t, cmdApprove([]string{"-key", aliceKey, other}))
		must(t, cmdApprove([]string{"-key", bobKey, other}))
		data, _ := os.ReadFile(filepath.Join(other, "capsule.approvals"))
		must(t, os.WriteFile(filepath.Join(dir, "capsule.approvals"), data, 0o644))
	}), "has 0 of 2")
	wantErr(t, check(approvals, func(dir string) { // an approval that has lapsed
		must(t, cmdApprove([]string{"-key", aliceKey, dir}))
		must(t, cmdApprove([]string{"-key", bobKey, dir}))
		var list []approval
		data, _ := os.ReadFile(filepath.Join(dir, "capsule.approvals"))
		must(t, json.Unmarshal(data, &list))
		list[0].Expires = now.Add(-time.Hour).Unix() // edited expiry no longer matches its signature either
		data, _ = json.Marshal(list)
		must(t, os.WriteFile(filepath.Join(dir, "capsule.approvals"), data, 0o644))
	}), "has 1 of 2")
}

func TestRevocationAndRunLimit(t *testing.T) {
	newHost(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	malloryKey, _ := newKey(t, keys, "mallory")
	trusted := trustSet{id: true}
	dir := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"max_runs":2}}`)
	_, err := sealCapsule(dir, key, nil)
	must(t, err)
	sc, err := openCapsule(dir, trusted)
	must(t, err)

	must(t, countRun(dir, sc, time.Now()))
	must(t, countRun(dir, sc, time.Now()))
	wantErr(t, countRun(dir, sc, time.Now()), "already ran 2 of 2")

	notice := func(keyFile string) revocation {
		k, err := loadSigner(keyFile)
		must(t, err)
		r := revocation{Seal: sc.ID, Signer: k.pub}
		r.Signature = k.sign(r.message())
		return r
	}
	write := func(name string, r revocation) {
		data, _ := json.Marshal(r)
		must(t, os.MkdirAll(filepath.Join(configDir(), "revoked.d"), 0o755))
		must(t, os.WriteFile(filepath.Join(configDir(), "revoked.d", name), data, 0o644))
	}
	write("untrusted.json", notice(malloryKey))
	if isRevoked(sc.ID, trusted) {
		t.Fatal("a revocation signed by an untrusted key was honoured")
	}
	forged := notice(key)
	forged.Seal = "sha256:" + strings.Repeat("0", 64) // a real signature moved to another seal
	write("forged.json", forged)
	if isRevoked(forged.Seal, trusted) {
		t.Fatal("a revocation whose seal was edited was honoured")
	}
	write("trusted.json", notice(key))
	if !isRevoked(sc.ID, trusted) {
		t.Fatal("a revocation signed by a trusted key was ignored")
	}
}

func TestLogChain(t *testing.T) {
	newHost(t)
	for _, event := range []string{"run", "exit", "refused", "run"} {
		_, err := appendLog(logEntry{Event: event, Capsule: "app"})
		must(t, err)
	}
	must(t, cmdLog(nil))
	original, err := os.ReadFile(logPath())
	must(t, err)
	lines := bytes.Split(bytes.TrimSpace(original), []byte("\n"))
	join := func(l ...[]byte) []byte { return append(bytes.Join(l, []byte("\n")), '\n') }
	for name, altered := range map[string][]byte{
		"edited entry":  bytes.Replace(original, []byte(`"refused"`), []byte(`"allowed"`), 1),
		"removed entry": join(lines[0], lines[2], lines[3]),
		"removed first": join(lines[1], lines[2], lines[3]),
		"reordered":     join(lines[0], lines[2], lines[1], lines[3]),
		"duplicated":    join(lines[0], lines[1], lines[1], lines[2], lines[3]),
	} {
		must(t, os.WriteFile(logPath(), altered, 0o600))
		if err := cmdLog(nil); err == nil {
			t.Errorf("%s: log still verifies", name)
		}
	}
	// Note: dropping entries from the end is not detectable from the log alone; see the README.
	must(t, os.WriteFile(logPath(), original, 0o600))
	must(t, cmdLog(nil))
}

func TestCardsAndDelegation(t *testing.T) {
	newHost(t)
	keys := t.TempDir()
	devFile, devID := newKey(t, keys, "dev")
	malloryFile, malloryID := newKey(t, keys, "mallory")
	dev, err := loadSigner(devFile)
	must(t, err)
	mallory, err := loadSigner(malloryFile)
	must(t, err)
	trusted := trustSet{devID: true}
	meshKey := b64.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sign := func(c card, k *signer) card {
		c.Signer = k.pub
		c.Signature = k.sign(c.message())
		return c
	}
	delegate := func(hostID string, k *signer, names ...string) *delegation {
		d := delegation{Host: hostID, Names: names, Signer: k.pub}
		d.Signature = k.sign(d.message())
		return &d
	}
	base := card{Name: "web", Key: meshKey, Endpoint: "10.0.0.5:51820"}

	if !sign(base, dev).valid(trusted) {
		t.Error("card signed by a trusted key rejected")
	}
	if sign(base, mallory).valid(trusted) {
		t.Error("card signed by an untrusted key accepted")
	}
	moved := sign(base, dev)
	moved.Endpoint = "10.6.6.6:51820"
	if moved.valid(trusted) {
		t.Error("card accepted after its endpoint was edited")
	}
	renamed := sign(base, dev)
	renamed.Name = "db"
	if renamed.valid(trusted) {
		t.Error("card accepted after its name was edited")
	}

	// mallory's host may issue cards for web, and only for web
	self := sign(base, mallory)
	self.Delegation = delegate(malloryID, dev, "web")
	if !self.valid(trusted) {
		t.Error("host-issued card under a valid delegation rejected")
	}
	db := base
	db.Name = "db"
	db = sign(db, mallory)
	db.Delegation = delegate(malloryID, dev, "web")
	if db.valid(trusted) {
		t.Error("host issued a card for a name it was not delegated")
	}
	selfMade := sign(base, mallory)
	selfMade.Delegation = delegate(malloryID, mallory, "web")
	if selfMade.valid(trusted) {
		t.Error("delegation signed by an untrusted key accepted")
	}
	borrowed := sign(base, mallory)
	borrowed.Delegation = delegate(devID, dev, "web") // a real delegation, but to a different host
	if borrowed.valid(trusted) {
		t.Error("card accepted with a delegation made out to another host")
	}
	if meshAddr([]byte(meshKey)).Equal(serviceAddr("web")) || meshAddr([]byte("a")).Equal(meshAddr([]byte("b"))) {
		t.Error("mesh addresses collide")
	}
}

func TestBuildFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}
	good := write("app.cue", `
_port: 8080
capsule: {name: "web", command: ["/bin/server", "\(_port)"], publish: [_port], limits: memory: "64M"}
rootfs: files: {
	"/bin/server":   {contents: "#!/bin/sh\n", mode: 0o755}
	"/etc/app.conf": contents: "port=\(_port)\n"
}`)
	out := filepath.Join(dir, "out")
	must(t, cmdBuild([]string{"-o", out, good}))
	m, _, err := loadManifest(out)
	must(t, err)
	if m.Command[1] != "8080" || m.Publish[0] != 8080 {
		t.Errorf("manifest not rendered from the build file: %+v", m)
	}
	if info, err := os.Stat(filepath.Join(out, "rootfs/bin/server")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("declared file missing or wrong mode: %v", err)
	}
	wantErr(t, cmdBuild([]string{"-o", out, good}), "already exists")

	wantErr(t, cmdBuild([]string{"-o", filepath.Join(dir, "typo"), write("typo.cue",
		`capsule: {name: "web", command: ["/x"], publsh: [80]}`+"\nrootfs: {}")}), "publsh: field not allowed")
	wantErr(t, cmdBuild([]string{"-o", filepath.Join(dir, "port"), write("port.cue",
		`capsule: {name: "web", command: ["/x"], publish: [99999]}`+"\nrootfs: {}")}), "publish")
	rules := write("org.cue", `capsule: {limits: {memory: string, pids: int}, network: *"none" | "mesh"}`)
	wantErr(t, cmdBuild([]string{"-o", filepath.Join(dir, "rules"), "-rules", rules, good}), "capsule.limits.pids: must be set")
	// A path that tries to climb out is confined to the rootfs, not written outside it.
	must(t, cmdBuild([]string{"-o", filepath.Join(dir, "escape"), write("escape.cue",
		`capsule: {name: "web", command: ["/x"]}`+"\n"+`rootfs: files: "/../../escaped": contents: "x"`)}))
	if _, err := os.Stat(filepath.Join(dir, "escaped")); err == nil {
		t.Fatal("a declared file was written outside the rootfs")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape/rootfs/escaped")); err != nil {
		t.Fatal("a climbing path was not confined to the rootfs")
	}
	wantErr(t, cmdBuild([]string{"-o", filepath.Join(dir, "url"), write("url.cue",
		`capsule: {name: "web", command: ["/x"]}`+"\n"+`rootfs: from: "https://example.invalid/base.tar.gz"`)}), "sha256 is required")

	// The same rule file refuses a non-compliant capsule at run time on a host that installs it.
	newHost(t)
	must(t, os.MkdirAll(filepath.Join(configDir(), "policy.d"), 0o755))
	data, _ := os.ReadFile(rules)
	must(t, os.WriteFile(filepath.Join(configDir(), "policy.d", "org.cue"), data, 0o644))
	wantErr(t, admit([]byte(`{"name":"web","command":["/x"],"limits":{"memory":"64M"}}`)), "capsule.limits.pids: must be set")
	wantErr(t, admit([]byte(`{"name":"web","command":["/x"],"limits":{"memory":"64M","pids":8},"network":"host"}`)), "capsule.network")
	must(t, admit([]byte(`{"name":"web","command":["/x"],"limits":{"memory":"64M","pids":8}}`)))
}

// TestTimelock talks to the public drand network, so it only runs when asked:
// CAPSULE_NETWORK_TESTS=1 go test -run Timelock .
func TestTimelock(t *testing.T) {
	if os.Getenv("CAPSULE_NETWORK_TESTS") == "" {
		t.Skip("set CAPSULE_NETWORK_TESTS=1 to run tests that need the drand network")
	}
	newHost(t)
	part := bytes.Repeat([]byte{42}, 32)
	lock, err := lockKey(part, time.Now().Add(10*time.Second))
	must(t, err)
	if strings.Contains(lock.Key, b64.EncodeToString(part)) {
		t.Fatal("locked key contains the key")
	}
	if _, err := unlockKey(lock, "sha256:early"); err != errTooEarly {
		t.Fatalf("unlocked before its round was published: %v", err)
	}
	time.Sleep(15 * time.Second)
	got, err := unlockKey(lock, "sha256:ontime")
	must(t, err)
	if !bytes.Equal(got, part) {
		t.Fatal("unlocked key differs")
	}
	tampered := *lock
	tampered.Round-- // claiming an earlier round does not help: the ciphertext is bound to its own
	if got, err := unlockKey(&tampered, "sha256:tampered"); err != nil || !bytes.Equal(got, part) {
		t.Logf("edited round field: %v (the ciphertext carries its own round, so the field is informational)", err)
	}
}

func TestHostSecretSurvivesInterruptedCreation(t *testing.T) {
	newHost(t)
	path := filepath.Join(configDir(), "host.key")
	must(t, os.WriteFile(path, nil, 0o600)) // what a crash mid-creation used to leave behind
	first, err := hostID()
	must(t, err)
	again, err := hostID()
	must(t, err)
	if first != again {
		t.Fatal("host id changed between calls")
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret not recreated privately: %v", err)
	}
	must(t, os.WriteFile(path, []byte("garbage\n"), 0o600))
	if _, err := hostID(); err == nil {
		t.Fatal("a corrupt, non-empty secret was silently replaced")
	}
	leftovers, _ := filepath.Glob(filepath.Join(configDir(), ".host.key-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestPickBackend(t *testing.T) {
	// Least connections: the idle replica first, busiest last.
	if got := pickBackend("least-connections", []int64{5, 0, 2}, 0); fmt.Sprint(got) != "[1 2 0]" {
		t.Errorf("least-connections ordered %v, want [1 2 0]", got)
	}
	// Equal loads take turns instead of always landing on the first replica.
	seen := map[int]int{}
	for turn := uint64(0); turn < 9; turn++ {
		seen[pickBackend("", []int64{1, 1, 1}, turn)[0]]++
	}
	if seen[0] != 3 || seen[1] != 3 || seen[2] != 3 {
		t.Errorf("equal loads were not shared in turn: %v", seen)
	}
	// Round-robin ignores load and offers the others as fallbacks.
	if got := pickBackend("round-robin", []int64{9, 0, 0}, 3); fmt.Sprint(got) != "[0 1 2]" {
		t.Errorf("round-robin ordered %v, want [0 1 2]", got)
	}
	if got := pickBackend("round-robin", []int64{0, 0, 0}, 4); got[0] != 1 {
		t.Errorf("round-robin did not move on: %v", got)
	}
	for _, mode := range []string{"", "random", "round-robin"} {
		got := pickBackend(mode, []int64{0, 0, 0, 0}, 7)
		sorted := append([]int{}, got...)
		sort.Ints(sorted)
		if fmt.Sprint(sorted) != "[0 1 2 3]" {
			t.Errorf("%q did not return every replica once: %v", mode, got)
		}
	}
	if len(pickBackend("", nil, 0)) != 0 {
		t.Error("no replicas should give nothing to try")
	}
}

func TestFleetTurns(t *testing.T) {
	a := hostLoad{Host: "a", Max: 2, CPU: 90}
	b := hostLoad{Host: "b", Max: 2, CPU: 0}
	// Nothing running: the lowest id starts, and both hosts agree on that.
	if growTurn([]hostLoad{a, b}) != "a" || growTurn([]hostLoad{b, a}) != "a" {
		t.Error("hosts disagree on who starts the first replica")
	}
	// Replicas go to whoever has fewest, so they spread: a, b, a, b.
	order := ""
	for range 4 {
		turn := growTurn([]hostLoad{a, b})
		order += turn
		if turn == "a" {
			a.Replicas++
		} else {
			b.Replicas++
		}
	}
	if order != "abab" || growTurn([]hostLoad{a, b}) != "" {
		t.Errorf("replicas were placed %q and then %q, want abab and then nobody", order, growTurn([]hostLoad{a, b}))
	}
	if avg, n := fleetAverage([]hostLoad{{Replicas: 3, CPU: 100}, {Replicas: 1, CPU: 0}}); avg != 75 || n != 4 {
		t.Errorf("fleet average %v over %d, want 75 over 4", avg, n)
	}
	// Shrinking takes from whoever has most, and never below one in total.
	order = ""
	for range 5 {
		turn := shrinkTurn([]hostLoad{a, b})
		order += turn
		switch turn {
		case "a":
			a.Replicas--
		case "b":
			b.Replicas--
		}
	}
	if order != "bab" || a.Replicas+b.Replicas != 1 {
		t.Errorf("replicas were removed %q leaving %d, want bab leaving 1", order, a.Replicas+b.Replicas)
	}
	// A host with a minimum keeps it.
	if got := shrinkTurn([]hostLoad{{Host: "a", Replicas: 1, Min: 1, Max: 2}, {Host: "b", Replicas: 0, Max: 2}}); got != "" {
		t.Errorf("shrank a fleet already at its floor: %q", got)
	}
}

func TestBlobsInADirectoryLedger(t *testing.T) {
	store := dirLedger{t.TempDir()}
	src := filepath.Join(t.TempDir(), "src")
	must(t, os.WriteFile(src, bytes.Repeat([]byte("capsule"), 100000), 0o644))
	must(t, store.putFile("capsules/app/x.tar", src))
	dst := filepath.Join(t.TempDir(), "dst")
	must(t, store.getFile("capsules/app/x.tar", dst))
	if !bytes.Equal(mustRead(t, src), mustRead(t, dst)) {
		t.Fatal("file changed on the way through the store")
	}
	if err := store.getFile("capsules/app/missing.tar", dst); err == nil {
		t.Fatal("fetching a file that is not there succeeded")
	}
}

func TestBuildLayers(t *testing.T) {
	dir := t.TempDir()
	// a "runtime" tarball that wraps everything in one top folder, as real ones do
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range [][3]string{{"runtime-1.2/", "dir", ""}, {"runtime-1.2/bin/", "dir", ""}, {"runtime-1.2/bin/run", "file", "#!/bin/sh\n"},
		{"runtime-1.2/bin/alias", "symlink", "run"}, {"runtime-1.2/lib/data", "file", "from the runtime"}} {
		h := &tar.Header{Name: e[0], Mode: 0o755}
		switch e[1] {
		case "dir":
			h.Typeflag = tar.TypeDir
		case "file":
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e[2]))
		case "symlink":
			h.Typeflag, h.Linkname = tar.TypeSymlink, e[2]
		}
		must(t, tw.WriteHeader(h))
		tw.Write([]byte(e[2]))
	}
	must(t, tw.Close())
	must(t, gz.Close())
	must(t, os.WriteFile(filepath.Join(dir, "runtime.tar.gz"), buf.Bytes(), 0o644))
	must(t, os.MkdirAll(filepath.Join(dir, "base/etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "base/etc/os"), []byte("base"), 0o644))
	must(t, os.MkdirAll(filepath.Join(dir, "app"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "app/main.py"), []byte("print(1)"), 0o644))
	build := func(name, body string) error {
		file := filepath.Join(dir, name+".cue")
		must(t, os.WriteFile(file, []byte(body), 0o644))
		return cmdBuild([]string{"-o", filepath.Join(dir, name), file})
	}
	must(t, build("ok", `
capsule: {name: "ok", command: ["/opt/runtime/bin/run"]}
rootfs: {
	from: "base"
	add: [
		{from: "runtime.tar.gz", to: "/opt/runtime", strip: 1},
		{from: "app", to: "/app"},
	]
	files: "/opt/runtime/lib/data": contents: "overridden by files"
}`))
	root := filepath.Join(dir, "ok/rootfs")
	for path, want := range map[string]string{"etc/os": "base", "opt/runtime/bin/run": "#!/bin/sh\n", "app/main.py": "print(1)", "opt/runtime/lib/data": "overridden by files"} {
		if got := string(mustRead(t, filepath.Join(root, path))); got != want {
			t.Errorf("%s holds %q, want %q", path, got, want)
		}
	}
	if link, err := os.Readlink(filepath.Join(root, "opt/runtime/bin/alias")); err != nil || link != "run" {
		t.Errorf("symlink not carried over: %q %v", link, err)
	}
	if info, err := os.Stat(filepath.Join(root, "opt/runtime/bin/run")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("runtime file lost its mode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "opt/runtime/runtime-1.2")); err == nil {
		t.Error("strip did not drop the archive's top folder")
	}
	// A layer cannot write outside the rootfs, however its entries are named.
	var evil bytes.Buffer
	tw = tar.NewWriter(&evil)
	must(t, tw.WriteHeader(&tar.Header{Name: "../../escaped", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}))
	tw.Write([]byte("x"))
	must(t, tw.Close())
	must(t, os.WriteFile(filepath.Join(dir, "evil.tar"), evil.Bytes(), 0o644))
	if err := build("evil", `capsule: {name: "evil", command: ["/x"]}`+"\n"+`rootfs: {from: "base", add: [{from: "evil.tar"}]}`); err == nil {
		t.Error("a layer with a climbing path was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped")); err == nil {
		t.Fatal("a layer wrote outside the rootfs")
	}
}

func TestLogStaysSmallAndRotates(t *testing.T) {
	newHost(t)
	add := func() logEntry {
		e, err := appendLog(logEntry{Event: "run", Capsule: "app"})
		must(t, err)
		return e
	}
	first, second := add(), add()
	if first.Key == "" || second.Key != "" {
		t.Fatal("the full key should be on the first entry of a file and not on the next")
	}
	if first.Host != second.Host || keyID(first.Key) != first.Host {
		t.Fatal("entries do not name the host by the id of its key")
	}
	lines := splitLines(mustRead(t, logPath()))
	if len(lines[1]) > len(lines[0])-2000 {
		t.Errorf("a later entry (%d bytes) is not much smaller than the first (%d)", len(lines[1]), len(lines[0]))
	}

	// With a small limit the log is set aside and carried on, and both the
	// current file alone and the whole history verify.
	t.Setenv("CAPSULE_LOG_MAX", "15000")
	for range 8 {
		add()
	}
	if len(logArchives()) == 0 {
		t.Fatal("the log was not rotated")
	}
	must(t, cmdLog(nil))
	must(t, cmdLog([]string{"-all"}))
	current := splitLines(mustRead(t, logPath()))
	var head logEntry
	must(t, json.Unmarshal(current[0], &head))
	if head.Seq == 0 || head.Key == "" {
		t.Fatalf("the file that follows a rotation should continue the numbering and carry the key: %+v", head.Seq)
	}

	// A piece cut from the middle has no key in it: it verifies only with the host's file.
	piece := filepath.Join(t.TempDir(), "piece")
	must(t, os.WriteFile(piece, append(bytes.Join(current[1:], []byte("\n")), '\n'), 0o600))
	if len(current) > 2 {
		wantErr(t, cmdLog([]string{"-file", piece}), "pass -hostfile")
		key, err := hostSigner()
		must(t, err)
		card, _ := json.Marshal(hostCard{Sign: key.id(), SignKey: key.pub})
		cardFile := filepath.Join(t.TempDir(), "host")
		must(t, os.WriteFile(cardFile, card, 0o600))
		must(t, cmdLog([]string{"-file", piece, "-hostfile", cardFile}))
	}

	// An archive that is altered breaks the whole history, though the current file alone still looks fine.
	archive := logArchives()[0]
	must(t, os.WriteFile(archive, bytes.Replace(mustRead(t, archive), []byte(`"app"`), []byte(`"xyz"`), 1), 0o600))
	must(t, cmdLog(nil))
	if err := cmdLog([]string{"-all"}); err == nil {
		t.Fatal("an altered archive was not detected")
	}
}

func TestHealthCheckScheduling(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := func(st *probeState, rx, tx uint64, open, accepted bool) bool {
		now = now.Add(2 * time.Second)
		ask := needProbe(st, now, rx, tx, open, accepted)
		if ask {
			probed(st, now, true, tx != 0 && false)
		}
		return ask
	}
	// An idle, healthy instance is asked less and less often, down to once in 30 seconds.
	st := &probeState{}
	asked := 0
	for range 60 { // two minutes
		if tick(st, 0, 0, false, false) {
			asked++
		}
	}
	if asked > 8 {
		t.Errorf("an idle healthy instance was checked %d times in two minutes; every two seconds would be 60", asked)
	}
	if st.Every != probeSlow {
		t.Errorf("the gap settled at %v, want %v", st.Every, probeSlow)
	}

	// One that is visibly serving is never asked: it keeps accepting connections, or answers on an open one.
	st = &probeState{}
	rx, tx := uint64(0), uint64(0)
	for i := range 30 {
		rx, tx = rx+1000, tx+1000
		if tick(st, rx, tx, i%2 == 0, i%2 == 1) {
			t.Fatalf("an instance that is serving was checked with a connection at step %d", i)
		}
	}

	// The moment we send and nothing comes back, it is asked at once, whatever the schedule said.
	st = &probeState{Next: now.Add(time.Hour), Every: probeSlow}
	if !tick(st, 0, 500, false, false) {
		t.Error("an instance that stopped answering was not checked at once")
	}
	// Traffic coming back with no open or new connection (refusals, say) is not proof of serving.
	st = &probeState{}
	tick(st, 0, 0, false, false)
	now = now.Add(time.Minute)
	if !needProbe(st, now, 900, 900, false, false) {
		t.Error("bytes coming back with no connection behind them were taken as proof of health")
	}
	// An instance found down is asked again soon, so its return is noticed.
	probed(st, now, false, false)
	if st.Every != probeFast {
		t.Errorf("a down instance is rechecked every %v, want %v", st.Every, probeFast)
	}
}

func TestCellManifest(t *testing.T) {
	base := `{"name":"app","command":["/x"],"network":"cell",`
	for raw, want := range map[string]string{
		base + `"needs":[{"name":"db","from":"store","port":5432}],"offers":[{"name":"api","to":["web"]}]}`:       "",
		base + `"offers":[{"name":"api","to":[]}]}`:                                                               "say which cells",
		base + `"needs":[{"name":"db","from":"store"},{"name":"db","from":"other"}]}`:                             "used once",
		base + `"needs":[{"name":"a","from":"s","balance":"sticky"},{"name":"b","from":"s","balance":"random"}]}`: "balanced one way",
		base + `"mesh":{"peers":[]},"needs":[{"name":"db","from":"store"}]}`:                                      "not a mesh section",
		`{"name":"app","command":["/x"],"network":"cell"}`:                                                        "needs offers or needs",
		`{"name":"app","command":["/x"],"needs":[{"name":"db","from":"store"}]}`:                                  `only to network "cell"`,
	} {
		_, err := parseManifest([]byte(raw))
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: got %v, want %q", raw, err, want)
		}
	}
	m, err := parseManifest([]byte(base + `"needs":[{"name":"db","from":"store"}],"offers":[{"name":"api","to":["web","store"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	peers := m.peers()
	if len(peers) != 2 || peers[0].Name != "store" || len(peers[0].Out) != 1 || peers[0].Out[0] != receptorPort("db") ||
		len(peers[0].In) != 1 || peers[0].In[0] != receptorPort("api") || peers[1].Name != "web" || len(peers[1].Out) != 0 {
		t.Errorf("a cell's peers were derived wrongly: %+v", peers)
	}
	if p := receptorPort("db"); p < 10000 || p >= 60000 || p != receptorPort("db") || p == receptorPort("api") {
		t.Errorf("receptor port %d", p)
	}
}

func TestGrant(t *testing.T) {
	key, other := newSigner(bytes.Repeat([]byte{7}, 32)), newSigner(bytes.Repeat([]byte{8}, 32))
	trusted := trustSet{key.id(): true}
	sign := func(k *signer, g grant) grant {
		g.Signer = k.pub
		g.Signature = k.sign(g.message())
		return g
	}
	g := sign(key, grant{Receptor: "db", Of: "store", To: "web", From: 1000, Until: 2000})
	for name, c := range map[string]struct {
		g                    grant
		receptor, of, caller string
		tick                 uint64
		want                 string
	}{
		"in date":           {g, "db", "store", "web", 1500, ""},
		"just before":       {g, "db", "store", "web", 1000 - tickSkew, ""},
		"too early":         {g, "db", "store", "web", 1000 - tickSkew - 1, "not valid yet"},
		"last tick":         {g, "db", "store", "web", 2000, ""},
		"expired":           {g, "db", "store", "web", 2001, "expired"},
		"other receptor":    {g, "admin", "store", "web", 1500, "something else"},
		"other offerer":     {g, "db", "vault", "web", 1500, "something else"},
		"other caller":      {g, "db", "store", "rogue", 1500, "something else"},
		"untrusted signer":  {sign(other, g), "db", "store", "web", 1500, "not signed by a trusted key"},
		"altered after":     {func() grant { x := g; x.Until = 9000; return x }(), "db", "store", "web", 5000, "not signed by a trusted key"},
		"altered recipient": {func() grant { x := g; x.To = "rogue"; return x }(), "db", "store", "rogue", 1500, "not signed by a trusted key"},
	} {
		err := c.g.check(trusted, c.receptor, c.of, c.caller, c.tick)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}

	dir := t.TempDir()
	write := func(file string, g grant) {
		raw, _ := json.Marshal(g)
		os.WriteFile(filepath.Join(dir, file), raw, 0o644)
	}
	if got := findGrant(dir, "db", "store", "web", trusted); got != "-" {
		t.Errorf("found a grant in an empty directory: %s", got)
	}
	write("old.grant", g)
	write("new.grant", sign(key, grant{Receptor: "db", Of: "store", To: "web", From: 1000, Until: 3000}))
	write("else.grant", sign(key, grant{Receptor: "db", Of: "store", To: "cli", From: 1000, Until: 9000}))
	raw, _ := b64.DecodeString(findGrant(dir, "db", "store", "web", trusted))
	var found grant
	if json.Unmarshal(raw, &found) != nil || found.Until != 3000 || found.To != "web" {
		t.Errorf("did not pick the grant for this use that lasts longest: %+v", found)
	}
}

func TestClockTick(t *testing.T) {
	if clockTick(time.Unix(tickGenesis, 0)) != 1 || clockTick(time.Unix(tickGenesis+2, 0)) != 1 || clockTick(time.Unix(tickGenesis+3, 0)) != 2 || clockTick(time.Unix(0, 0)) != 0 {
		t.Error("ticks are not the beacon's rounds")
	}
}

func TestCardKem(t *testing.T) {
	key := newSigner(bytes.Repeat([]byte{9}, 32))
	trusted := trustSet{key.id(): true}
	dk, _ := mlkem.GenerateKey768()
	c := card{Name: "web", Key: b64.EncodeToString(bytes.Repeat([]byte{1}, 32)), Kem: b64.EncodeToString(dk.EncapsulationKey().Bytes()), Signer: key.pub}
	c.Signature = key.sign(c.message())
	if !c.valid(trusted) {
		t.Fatal("a card carrying a kem key is not valid")
	}
	other, _ := mlkem.GenerateKey768()
	swapped := c
	swapped.Kem = b64.EncodeToString(other.EncapsulationKey().Bytes())
	if swapped.valid(trusted) {
		t.Error("a card whose kem key was swapped after signing is still valid")
	}
	stripped := c
	stripped.Kem = ""
	if stripped.valid(trusted) {
		t.Error("a card whose kem key was removed after signing is still valid")
	}
	plain := card{Name: "web", Key: c.Key, Signer: key.pub}
	plain.Signature = key.sign(plain.message())
	if !plain.valid(trusted) {
		t.Error("a card without a kem key, as made before they existed, is no longer valid")
	}
}

func TestOrderParse(t *testing.T) {
	good := [][]string{
		{"ps"}, {"log"}, {"log", "50"}, {"fetch", "web"}, {"run", "web"}, {"stop", "web"},
		{"resize", "web", "memory=512M", "cpus=1.5"}, {"exec", "web", "instance=a", "--", "ls", "-l", "x=y"},
		{"revoke", "sha256:" + strings.Repeat("ab", 32)},
	}
	for _, words := range good {
		if _, err := parseOrder(words); err != nil {
			t.Errorf("%v: %v", words, err)
		}
	}
	bad := [][]string{
		{}, {"sh", "-c", "id"}, {"ps", "web"}, {"run"}, {"run", "web", "extra"}, {"run", "../web"}, {"run", "web", "--", "id"},
		{"resize", "web"}, {"resize", "web", "memory=lots"}, {"resize", "web", "shell=1"}, {"exec", "web"},
		{"revoke", "web"}, {"log", "0"}, {"exec", "web", "timeout=1h", "--", "id"}, {"fetch", "web", "o=/etc"},
	}
	for _, words := range bad {
		if _, err := parseOrder(words); err == nil {
			t.Errorf("%v was accepted", words)
		}
	}
	o, _ := parseOrder([]string{"exec", "web", "--", "sh", "-c", "a=b"})
	if len(o.Command) != 3 || o.Params != nil {
		t.Errorf("words after -- must be the command untouched: %+v", o)
	}
}

func TestOrderRules(t *testing.T) {
	newHost(t)
	dir := t.TempDir()
	ops := filepath.Join(os.Getenv("CAPSULE_CONFIG"), "operators.d")
	os.MkdirAll(ops, 0o755)
	var keys []*signer
	for _, name := range []string{"one", "two", "outsider"} {
		path, _ := newKey(t, dir, name)
		k, err := loadSigner(path)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		if name != "outsider" {
			os.WriteFile(filepath.Join(ops, name+".pub"), []byte(k.pub), 0o644)
		}
	}
	signed := func(action string, by ...*signer) order {
		o := order{Action: action, Hosts: []string{"h"}, From: 10, Until: 20, Nonce: "n"}
		if action != "ps" {
			o.Capsule = "web"
		}
		if action == "exec" {
			o.Command = []string{"id"}
		}
		for _, k := range by {
			o.Signatures = append(o.Signatures, orderSig{k.pub, k.sign(o.message())})
		}
		return o
	}
	rules, err := loadOrderRules()
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.permits(signed("ps", keys[0])); err != nil {
		t.Errorf("one operator, default rules: %v", err)
	}
	if rules.permits(signed("ps", keys[2])) == nil {
		t.Error("an outsider's order was permitted")
	}
	if rules.permits(signed("ps")) == nil {
		t.Error("an unsigned order was permitted")
	}
	if rules.permits(signed("exec", keys[0], keys[1])) == nil {
		t.Error("exec was permitted without being turned on")
	}
	tampered := signed("stop", keys[0])
	tampered.Capsule = "db"
	if rules.permits(tampered) == nil {
		t.Error("an order changed after signing was permitted")
	}
	elsewhere := signed("stop", keys[0])
	id := elsewhere.id()
	elsewhere.Hosts = []string{"other"}
	if rules.permits(elsewhere) == nil || elsewhere.id() == id {
		t.Error("the hosts an order names are not covered by its signature")
	}

	os.WriteFile(filepath.Join(os.Getenv("CAPSULE_CONFIG"), "orders"), []byte("# rules\nexec 2\nrun 2\nstop off\n* 1\n"), 0o644)
	if rules, err = loadOrderRules(); err != nil {
		t.Fatal(err)
	}
	if rules.permits(signed("run", keys[0])) == nil || rules.permits(signed("run", keys[0], keys[0])) == nil {
		t.Error("run needs two different operators")
	}
	if rules.permits(signed("run", keys[0], keys[2])) == nil {
		t.Error("an outsider counted towards the signatures needed")
	}
	if err := rules.permits(signed("exec", keys[0], keys[1])); err != nil {
		t.Errorf("two operators: %v", err)
	}
	if rules.permits(signed("stop", keys[0], keys[1])) == nil {
		t.Error("an action that is off was permitted")
	}
	if err := rules.permits(signed("ps", keys[1])); err != nil {
		t.Errorf("the * rule: %v", err)
	}
	os.WriteFile(filepath.Join(os.Getenv("CAPSULE_CONFIG"), "orders"), []byte("shell 1\n"), 0o644)
	if _, err := loadOrderRules(); err == nil {
		t.Error("a rule for an action that does not exist was accepted")
	}
}

func TestOrderResultSealed(t *testing.T) {
	newHost(t)
	box, err := hostBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	wrap, sealed, err := sealResult(b64.EncodeToString(box.public()), "the output")
	if err != nil {
		t.Fatal(err)
	}
	r := orderReceipt{Order: "o", Host: "h", OK: true, Wrap: wrap, Result: sealed}
	if text, err := openResult(r, box); err != nil || text != "the output" {
		t.Fatalf("got %q, %v", text, err)
	}
	if strings.Contains(sealed, "output") {
		t.Error("the result is not encrypted")
	}
	newHost(t) // another machine
	other, _ := hostBoxKey()
	if _, err := openResult(r, other); err == nil {
		t.Error("another machine opened the result")
	}
	if _, _, err := sealResult("not a key", "x"); err == nil {
		t.Error("a malformed reply key was accepted")
	}
}

// ---- the tissue ----

// testWorld builds a world of n hosts and the given cells without a ledger.
func testWorld(t *testing.T, n int, cells map[string]tissueCell, manifests map[string]Manifest) *world {
	t.Helper()
	w := &world{now: 1000, infos: map[string]cellInfo{}, alive: map[string]bool{}, slots: map[string][]slotState{},
		want: map[string]int{}, wantAt: map[string]uint64{}, halted: map[string]bool{}}
	w.beacon = func(round uint64) ([]byte, bool) { return fallbackBeacon(round), true }
	w.t = tissue{Name: "test", Time: 1, Cells: cells}
	for i := 0; i < n; i++ {
		id := hashID("test-host", []byte{byte(i)})
		w.t.Hosts = append(w.t.Hosts, tissueHost{ID: id})
		w.alive[id] = true
	}
	for name, m := range manifests {
		m.Name = name
		w.infos[name] = cellInfo{Seal: "sha256:" + strings.Repeat("0", 63) + "1", Manifest: m}
	}
	return w
}

// settle lets every host act on its plan in turn until nothing changes, and returns the claims made.
func settle(w *world) int {
	claims := 0
	for round := 0; round < 20; round++ {
		acted := false
		for _, h := range w.t.Hosts {
			for _, s := range w.plan(h.ID) {
				if s.Do != "claim" {
					continue
				}
				if cur := w.slot(s.Cell, s.Slot); w.held(cur) || (cur.lease != nil && cur.lease.Term >= s.Term) {
					continue // lost the race: the key already exists
				}
				for len(w.slots[s.Cell]) <= s.Slot {
					w.slots[s.Cell] = append(w.slots[s.Cell], slotState{})
				}
				w.slots[s.Cell][s.Slot] = slotState{lease: &beat{Kind: "lease", Cell: s.Cell, Slot: s.Slot, Term: s.Term, Host: h.ID, Tick: w.now, Round: s.Round, Seal: w.infos[s.Cell].Seal}}
				claims++
				acted = true
			}
		}
		if !acted {
			break
		}
	}
	return claims
}

func holders(w *world, cell string) []string {
	var hosts []string
	for _, s := range w.slots[cell] {
		if w.held(s) {
			hosts = append(hosts, s.lease.Host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

func TestTissueGrowsFromNeeds(t *testing.T) {
	w := testWorld(t, 4, map[string]tissueCell{"web": {Root: true, Min: 2}, "spare": {}}, map[string]Manifest{
		"web":   {Network: "cell", Needs: []Need{{Name: "db", From: "db"}}},
		"db":    {Network: "cell", Needs: []Need{{Name: "kv", From: "vault"}, {Name: "back", From: "web"}}}, // a loop is not a problem
		"vault": {},
		"spare": {},
	})
	counts, short := w.wanted()
	if counts["web"] != 2 || counts["db"] != 1 || counts["vault"] != 1 || len(short) != 0 {
		t.Fatalf("wanted %v, short %v", counts, short)
	}
	if _, grown := counts["spare"]; grown {
		t.Error("a cell that is neither a root nor needed was grown")
	}
	settle(w)
	if got := holders(w, "web"); len(got) != 2 || got[0] == got[1] {
		t.Errorf("web should be on two different hosts: %v", got)
	}
	if len(holders(w, "db")) != 1 || len(holders(w, "vault")) != 1 {
		t.Error("needed cells were not placed")
	}
	// A cell that is only needed is never grown past one, whatever load says.
	w.want["db"] = 5
	if counts, _ := w.wanted(); counts["db"] != 1 {
		t.Errorf("an unlisted cell grew to %d", counts["db"])
	}
	// A needed cell whose release is missing is reported, not guessed at.
	delete(w.infos, "vault")
	if _, short := w.wanted(); len(short) != 1 {
		t.Errorf("a missing release was not reported: %v", short)
	}
}

func TestTissueDraw(t *testing.T) {
	cells := map[string]tissueCell{"web": {Root: true}}
	w := testWorld(t, 5, cells, map[string]Manifest{"web": {}})
	first, _ := w.rank("web", 0, 100, "")
	again, _ := w.rank("web", 0, 100, "")
	if len(first) != 5 || strings.Join(first, " ") != strings.Join(again, " ") {
		t.Fatal("the same round must give every host the same order")
	}
	// Every host, planning alone, agrees who the winner is: exactly one claims at once.
	claimers := 0
	for _, h := range w.t.Hosts {
		for _, s := range w.plan(h.ID) {
			if s.Do == "claim" {
				claimers++
				if h.ID != first[0] && drawRound(w.now) == 100 {
					t.Error("a host other than the winner claimed first")
				}
			}
		}
	}
	if claimers != 1 {
		t.Errorf("%d hosts claimed a fresh slot at once, want only the winner", claimers)
	}
	// Different rounds and different slots give different winners over time.
	winners := map[string]bool{}
	for round := uint64(0); round < 400; round += tissueEpoch {
		order, _ := w.rank("web", 0, round, "")
		winners[order[0]] = true
	}
	if len(winners) != 5 {
		t.Errorf("over 20 rounds only %d of 5 hosts ever won", len(winners))
	}
	// Weight is the share of draws a host wins.
	w.t.Hosts[0].Weight = 9
	wins := 0
	for round := uint64(0); round < 4000; round += tissueEpoch {
		if order, _ := w.rank("web", 0, round, ""); order[0] == w.t.Hosts[0].ID {
			wins++
		}
	}
	if wins < 120 || wins > 160 { // 9 of 13 shares of 200 draws is about 138
		t.Errorf("a host with 9 of 13 shares won %d of 200 draws", wins)
	}
	// A silent host is not in the draw at all.
	w.alive[first[0]] = false
	if order, _ := w.rank("web", 0, 100, ""); slices.Contains(order, first[0]) {
		t.Error("a host that has stopped pulsing was still drawn")
	}
}

func TestTissueLeaseAndTakeover(t *testing.T) {
	w := testWorld(t, 3, map[string]tissueCell{"db": {Root: true, Standby: "warm"}}, map[string]Manifest{"db": {}})
	settle(w)
	holder := holders(w, "db")[0]
	understudy := w.understudy("db", 0)
	if understudy == "" || understudy == holder {
		t.Fatalf("understudy %q, holder %q", understudy, holder)
	}
	doing := func(host string) string {
		var all []string
		for _, s := range w.plan(host) {
			all = append(all, s.Do)
		}
		return strings.Join(all, ",")
	}
	if doing(holder) != "hold" || doing(understudy) != "ready" {
		t.Errorf("holder does %q, understudy does %q", doing(holder), doing(understudy))
	}
	// While the lease lasts nobody else moves.
	w.now += w.t.lease()
	for _, h := range w.t.Hosts {
		if strings.Contains(doing(h.ID), "claim") {
			t.Error("a slot was claimed while its lease was still good")
		}
	}
	// Once it lapses the understudy takes it at once, with the next term; the others wait.
	w.now += 1
	for _, h := range w.t.Hosts {
		claims := strings.Contains(doing(h.ID), "claim")
		if claims != (h.ID == understudy) {
			t.Errorf("host claims=%v right after the lapse; only the understudy should", claims)
		}
	}
	for _, s := range w.plan(understudy) {
		if s.Do == "claim" && s.Term != 2 {
			t.Errorf("takeover used term %d, want 2", s.Term)
		}
	}
	// If the understudy does nothing, the others step in after a pause, the old holder last.
	w.now += tissueStagger
	third := ""
	for _, h := range w.t.Hosts {
		if h.ID != holder && h.ID != understudy {
			third = h.ID
		}
	}
	if !strings.Contains(doing(third), "claim") {
		t.Error("nobody stepped in for an understudy that did not act")
	}
	if strings.Contains(doing(holder), "claim") {
		t.Error("the host that let the lease lapse was first back in line")
	}
	// A cell that keeps data only comes back where its data is.
	w = testWorld(t, 3, map[string]tissueCell{"db": {Root: true}}, map[string]Manifest{"db": {Volumes: []Volume{{Name: "data", Path: "/data"}}}})
	settle(w)
	holder = holders(w, "db")[0]
	w.now += w.t.lease() + 10
	for _, h := range w.t.Hosts {
		claims := false
		for _, s := range w.plan(h.ID) {
			claims = claims || s.Do == "claim"
		}
		if claims != (h.ID == holder) {
			t.Error("a cell with volumes was offered to a host that does not have its data")
		}
	}
}

func TestTissueLimits(t *testing.T) {
	manifests := map[string]Manifest{"web": {Limits: Limits{Memory: "1G", CPUs: 1}}, "big": {Limits: Limits{Memory: "3G", CPUs: 1}}}
	w := testWorld(t, 3, map[string]tissueCell{"web": {Root: true, Min: 2, Max: 3}, "big": {Root: true}}, manifests)
	w.t.Budget = &Limits{Memory: "4G"}
	counts, short := w.wanted()
	if counts["big"] != 1 || counts["web"] != 1 || len(short) != 1 {
		t.Errorf("a 4G budget should hold big and one web: %v, short %v", counts, short)
	}
	w.t.Budget = nil
	// Load can ask for more, but never past the signed maximum.
	w.want["web"] = 7
	if counts, _ := w.wanted(); counts["web"] != 3 {
		t.Errorf("web grew to %d, past its maximum of 3", counts["web"])
	}
	w.want["web"] = 0
	// A host takes only what fits in what it offers, and labels are respected.
	for i := range w.t.Hosts {
		w.t.Hosts[i].Memory = "2G"
	}
	w.t.Hosts[2].Memory, w.t.Hosts[2].Labels = "8G", []string{"large"}
	settle(w)
	if got := holders(w, "big"); len(got) != 1 || got[0] != w.t.Hosts[2].ID {
		t.Errorf("big (3G) must land on the only host that offers enough: %v", got)
	}
	w = testWorld(t, 3, map[string]tissueCell{"web": {Root: true, On: []string{"eu"}}}, manifests)
	w.t.Hosts[1].Labels = []string{"eu"}
	settle(w)
	if got := holders(w, "web"); len(got) != 1 || got[0] != w.t.Hosts[1].ID {
		t.Errorf("web must land on the host labelled eu: %v", got)
	}
	// A cell that needs dedicated cores and a network card goes only where they are.
	fast := map[string]Manifest{"feed": {Latency: &Latency{Cores: 2, Nic: &Nic{Name: "eth1"}}}}
	w = testWorld(t, 3, map[string]tissueCell{"feed": {Root: true}}, fast)
	w.t.Hosts[0].Cores, w.t.Hosts[0].Nics = 4, []string{"eth1"}
	w.t.Hosts[1].Cores = 4
	settle(w)
	if got := holders(w, "feed"); len(got) != 1 || got[0] != w.t.Hosts[0].ID {
		t.Errorf("feed must land on the host with cores and the card: %v", got)
	}
}

func TestTissueGrowsAndShrinksWithLoad(t *testing.T) {
	w := testWorld(t, 4, map[string]tissueCell{"web": {Root: true, Min: 1, Max: 3}}, map[string]Manifest{"web": {}})
	settle(w)
	speaker := holders(w, "web")[0]
	wantStep := func() (int, bool) {
		for _, s := range w.plan(speaker) {
			if s.Do == "want" {
				return s.Want, true
			}
		}
		return 0, false
	}
	setBusy := func(percent int) {
		for i := range w.slots["web"] {
			s := &w.slots["web"][i]
			if s.lease != nil {
				s.pulse = &beat{Kind: "pulse", Cell: "web", Slot: i, Term: s.lease.Term, Host: s.lease.Host, Tick: w.now, Busy: percent, Seal: s.lease.Seal}
			}
		}
	}
	setBusy(95)
	if n, ok := wantStep(); !ok || n != 1 {
		t.Fatalf("a busy cell should ask for one more: %d %v", n, ok)
	}
	w.want["web"], w.wantAt["web"] = 1, w.now
	settle(w)
	setBusy(95)
	if _, ok := wantStep(); ok {
		t.Error("a cell grew twice within one epoch")
	}
	w.now += tissueEpoch
	setBusy(95)
	if n, ok := wantStep(); !ok || n != 2 {
		t.Errorf("after an epoch a busy cell should ask again: %d %v", n, ok)
	}
	w.want["web"], w.wantAt["web"] = 2, w.now
	settle(w)
	w.now += tissueEpoch
	setBusy(95)
	if _, ok := wantStep(); ok {
		t.Error("a cell asked to grow past its maximum")
	}
	setBusy(5)
	if n, ok := wantStep(); !ok || n != 1 {
		t.Errorf("an idle cell should give one back: %d %v", n, ok)
	}
}

func TestTissueGenerations(t *testing.T) {
	w := testWorld(t, 4, map[string]tissueCell{"web": {Root: true, Min: 3}}, map[string]Manifest{"web": {}})
	settle(w)
	old := w.infos["web"].Seal
	fresh := "sha256:" + strings.Repeat("0", 63) + "2"
	pulseAll := func() {
		for i := range w.slots["web"] {
			s := &w.slots["web"][i]
			seal := old
			if s.pulse != nil {
				seal = s.pulse.Seal
			}
			s.pulse = &beat{Kind: "pulse", Cell: "web", Slot: i, Term: s.lease.Term, Host: s.lease.Host, Tick: w.now, Seal: seal}
		}
	}
	pulseAll()
	info := w.infos["web"]
	info.Seal, info.Released = fresh, time.Now().UnixNano()
	w.infos["web"] = info
	due := func() (slots []int) {
		for i := range w.slots["web"] {
			if w.due("web", i, 3, info) {
				slots = append(slots, i)
			}
		}
		return slots
	}
	var order []int
	for len(order) < 3 {
		now := due()
		if len(now) != 1 {
			t.Fatalf("with step 1 exactly one slot may move at a time, got %v after %v", now, order)
		}
		order = append(order, now[0])
		w.slots["web"][now[0]].pulse.Seal = fresh
	}
	if len(due()) != 0 {
		t.Error("a slot on the current release was told to move again")
	}
	// A release that failed somewhere is not tried by anyone else.
	for i := range w.slots["web"] {
		w.slots["web"][i].pulse.Seal = old
	}
	w.halted["web "+fresh] = true
	if len(due()) != 0 {
		t.Error("a release that was held back was tried again")
	}
	// Two at a time when the tissue says so.
	delete(w.halted, "web "+fresh)
	c := w.t.Cells["web"]
	c.Step = 2
	w.t.Cells["web"] = c
	if len(due()) != 2 {
		t.Errorf("with step 2, two slots may move at once: %v", due())
	}
}

func TestTissueSignedAndChecked(t *testing.T) {
	newHost(t)
	dir := t.TempDir()
	opPath, _ := newKey(t, dir, "op")
	op, _ := loadSigner(opPath)
	hostKey, _ := hostSigner()
	me, _ := hostID()
	tis := tissue{Name: "prod", Time: 5, Cells: map[string]tissueCell{"web": {Root: true}}, Hosts: []tissueHost{{ID: me, SignKey: hostKey.pub}}}
	if err := tis.validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*tissue){
		func(x *tissue) { x.Cells = map[string]tissueCell{"web": {}} },                           // no root
		func(x *tissue) { x.Cells = map[string]tissueCell{"web": {Root: true, Min: 3, Max: 2}} }, // max below min
		func(x *tissue) { x.Cells = map[string]tissueCell{"web": {Root: true, Standby: "lukewarm"}} },
		func(x *tissue) { x.Hosts = append(x.Hosts, x.Hosts[0]) }, // a host twice
		func(x *tissue) { x.Lease = 1 },
		func(x *tissue) { x.Name = "../x" },
	} {
		broken := tis
		bad(&broken)
		if broken.validate() == nil {
			t.Errorf("an invalid tissue was accepted: %+v", broken)
		}
	}
	// A beat counts only if the host it names signed it, with the key the tissue lists for that host.
	b := beat{Kind: "lease", Cell: "web", Term: 1, Host: me, Tick: 10, Key: hostKey.pub}
	b.Signature = hostKey.sign(b.message())
	if !b.from(tis) {
		t.Fatal("a host's own beat was not accepted")
	}
	forged := b
	forged.Term = 9
	if forged.from(tis) {
		t.Error("a beat changed after signing was accepted")
	}
	outsider := beat{Kind: "lease", Cell: "web", Term: 2, Host: me, Tick: 10, Key: op.pub}
	outsider.Signature = op.sign(outsider.message())
	if outsider.from(tis) {
		t.Error("a beat signed by a key that is not that host's was accepted")
	}
	// Operators sign the tissue; the host counts them like it counts an order's signatures.
	os.MkdirAll(filepath.Join(os.Getenv("CAPSULE_CONFIG"), "operators.d"), 0o755)
	os.WriteFile(filepath.Join(os.Getenv("CAPSULE_CONFIG"), "operators.d", "op.pub"), []byte(op.pub), 0o644)
	rules, _ := loadOrderRules()
	if rules.signedByEnough("tissue", tis.message(), nil) == nil {
		t.Error("an unsigned tissue was accepted")
	}
	tis.Signatures = []orderSig{{op.pub, op.sign(tis.message())}}
	if err := rules.signedByEnough("tissue", tis.message(), tis.Signatures); err != nil {
		t.Errorf("an operator's tissue was refused: %v", err)
	}
	tis.Cells["extra"] = tissueCell{Root: true}
	if rules.signedByEnough("tissue", tis.message(), tis.Signatures) == nil {
		t.Error("a tissue changed after signing was accepted")
	}
}

func TestLatencyManifest(t *testing.T) {
	base := `{"name":"feed","command":["/bin/feed"],%s}`
	good := []string{
		`"latency":{"cores":2,"memory_lock":true,"hugepages":true}`,
		`"latency":{"nic":{"name":"eth1","address":"10.0.0.5/24","gateway":"10.0.0.1"}}`,
	}
	for _, g := range good {
		if _, err := parseManifest([]byte(fmt.Sprintf(base, g))); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	bad := []string{
		`"latency":{"cores":2},"limits":{"cpus":1}`,          // dedicated and throttled at once
		`"latency":{"nic":{"name":"eth1"}},"network":"host"`, // nothing to hand it to
		`"latency":{"nic":{"name":"../x"}}`,
		`"latency":{"nic":{"name":"eth1","address":"10.0.0.5"}}`, // no prefix length
		`"latency":{"nic":{"name":"eth1","gateway":"10.0.0.1"}}`, // gateway without an address
		`"latency":{"cores":-1}`,
	}
	for _, b := range bad {
		if _, err := parseManifest([]byte(fmt.Sprintf(base, b))); err == nil {
			t.Errorf("accepted: %s", b)
		}
	}
}

func TestTissueTermsSkipLeasesThatNoLongerCount(t *testing.T) {
	w := testWorld(t, 2, map[string]tissueCell{"web": {Root: true}}, map[string]Manifest{"web": {}})
	// Terms 1 to 3 exist in the ledger, taken by a host that has since left the tissue.
	w.slots["web"] = []slotState{{top: 3}}
	terms := map[int]bool{}
	for _, h := range w.t.Hosts {
		for _, s := range w.plan(h.ID) {
			if s.Do == "claim" {
				terms[s.Term] = true
			}
		}
	}
	if len(terms) != 1 || !terms[4] {
		t.Errorf("the next claim must take term 4, got %v", terms)
	}
}
