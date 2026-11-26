package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Capsules travel between machines through the same shared store as the
// ledger. A published capsule is an archive named by its seal, plus a small
// pointer saying which seal is current. Nothing fetched is trusted because of
// where it came from: the pointer must be signed by a trusted key, and the
// capsule must pass the same seal check as any other before it is installed.

// release says which seal of a capsule is the current one.
type release struct {
	Name      string `json:"name"`
	Seal      string `json:"seal"`
	Time      int64  `json:"time"` // nanoseconds, so two releases never share one
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

func (r release) message() []byte {
	return []byte(fmt.Sprintf("capsule-release-v1\n%s\n%s\n%d\n", r.Name, r.Seal, r.Time))
}

func blobs() (ledger, blobLedger, error) {
	l, err := openLedger()
	if err != nil {
		return nil, nil, err
	}
	if l == nil {
		return nil, nil, errors.New("this host has no ledger configured (see <config>/ledger)")
	}
	b, ok := l.(blobLedger)
	if !ok {
		return nil, nil, errors.New("this ledger cannot hold capsules: Vault is for secrets; use a bucket, Artifactory or a shared directory")
	}
	return l, b, nil
}

// cmdPublish uploads a sealed capsule and marks it as the current release of its name.
func cmdPublish(args []string) error {
	fl := flag.NewFlagSet("publish", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key that signs the release; hosts must trust it")
	var trust trustFlag
	fl.Var(&trust, "trust", "extra trusted public key file")
	fl.Parse(args)
	if fl.NArg() != 1 || *keyPath == "" {
		return errors.New("usage: capsule publish -key <file> [-trust <pub>] <dir>")
	}
	dir := fl.Arg(0)
	key, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	trusted, err := loadTrust(trust)
	if err != nil {
		return err
	}
	trusted[key.id()] = true // the publisher vouches with the key it signs the release with
	if err := verifyCapsule(dir, trusted); err != nil {
		return fmt.Errorf("not publishing: %w", err)
	}
	sc, err := openCapsule(dir, trusted)
	if err != nil {
		return err
	}
	l, store, err := blobs()
	if err != nil {
		return err
	}

	archive, err := os.CreateTemp("", "capsule-publish-")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	tw := tar.NewWriter(archive)
	for _, name := range []string{"capsule.json", "capsule.seal", "capsule.approvals", "capsule.permits", "rootfs.enc"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || (name == "rootfs.enc" && !sc.Seal.Encrypted) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: info.Size(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if !sc.Seal.Encrypted { // an encrypted capsule travels without its plaintext
		if err := packTree(tw, filepath.Join(dir, "rootfs"), "rootfs"); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	name := sc.Manifest.Name
	if err := store.putFile("capsules/"+name+"/"+idHex(sc.ID)+".tar", archive.Name()); err != nil {
		return err
	}
	// The manifest and seal by themselves, for hosts that plan with them before fetching anything.
	card, _ := json.Marshal(releaseCard{Manifest: b64.EncodeToString(sc.ManifestRaw), Seal: sc.Seal})
	if err := l.put(releaseCardKey(name, sc.ID), card); err != nil {
		return err
	}
	r := release{Name: name, Seal: sc.ID, Time: time.Now().UnixNano(), Signer: key.pub}
	r.Signature = key.sign(r.message())
	raw, _ := json.Marshal(r)
	if err := l.put("capsules/"+name+"/current", raw); err != nil {
		return err
	}
	// And for good: the releases there have been, newest last.
	if _, err := l.create(fmt.Sprintf("capsules/%s/releases/%020d", name, r.Time), raw); err != nil {
		return err
	}
	fmt.Printf("published %s %s\n", name, sc.ID)
	return nil
}

// releaseHistory lists the releases of a capsule that were published, newest
// first, the current one included. Nothing in it is checked here.
func releaseHistory(l ledger, name string) []release {
	var all []release
	add := func(key string) {
		var r release
		if raw, found, err := l.get(key); err == nil && found && json.Unmarshal(raw, &r) == nil && r.Name == name {
			all = append(all, r)
		}
	}
	add("capsules/" + name + "/current")
	keys, _ := l.list("capsules/" + name + "/releases/")
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys[:min(len(keys), 8)] {
		add(key)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time > all[j].Time })
	return all
}

// cmdFetch installs the current release of a capsule on this host, or
// replaces an older one. It refuses a release that is not signed by a trusted
// key, one older than what this host fetched before, and a capsule that does
// not match its seal.
func cmdFetch(args []string) error {
	fl := flag.NewFlagSet("fetch", flag.ExitOnError)
	out := fl.String("o", "", "install here (default: <data>/apps/<name>)")
	var trust trustFlag
	fl.Var(&trust, "trust", "extra trusted public key file")
	fl.Parse(args)
	if fl.NArg() != 1 || !nameRE.MatchString(fl.Arg(0)) {
		return errors.New("usage: capsule fetch [-o <dir>] [-trust <pub>] <name>")
	}
	trusted, err := loadTrust(trust)
	if err != nil {
		return err
	}
	msg, err := fetchRelease(fl.Arg(0), *out, trusted)
	if err == nil {
		fmt.Println(msg)
	}
	return err
}

// fetchRelease does the work of fetch and says what it did.
//
// With a seal named, it installs that exact release instead of the current
// one. That is for a tissue, which holds back a release that failed to come
// up: the choice is then made from host-signed records, and the release
// must still be one a trusted key published.
func fetchRelease(name, dir string, trusted trustSet, exactly ...string) (string, error) {
	l, store, err := blobs()
	if err != nil {
		return "", err
	}
	var r release
	want := ""
	if len(exactly) == 1 {
		want = exactly[0]
	}
	if want != "" {
		found := false
		for _, past := range releaseHistory(l, name) {
			if past.Seal == want && signedBy(trusted, past.Signer, past.Signature, past.message()) {
				r, found = past, true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("no trusted release of %s with seal %s is in this ledger", name, want)
		}
	} else {
		raw, found, err := l.get("capsules/" + name + "/current")
		if err != nil {
			return "", err
		}
		if !found || json.Unmarshal(raw, &r) != nil || r.Name != name {
			return "", fmt.Errorf("%s has not been published to this ledger", name)
		}
		if !signedBy(trusted, r.Signer, r.Signature, r.message()) {
			return "", fmt.Errorf("the release of %s is not signed by a key this host trusts", name)
		}
	}
	// Do not let the store hand back an older release than one already seen.
	seenFile := filepath.Join(dataDir(), "fetched", name)
	if prev, err := os.ReadFile(seenFile); err == nil && want == "" {
		stamp, seal, _ := strings.Cut(strings.TrimSpace(string(prev)), " ")
		last, _ := strconv.ParseInt(stamp, 10, 64)
		if r.Time < last || (r.Time == last && r.Seal != seal) {
			return "", fmt.Errorf("the ledger offers a release of %s older than the one this host already fetched; refusing to go back", name)
		}
	}
	if dir == "" {
		dir = filepath.Join(dataDir(), "apps", name)
	}
	if seal, err := readSeal(dir); err == nil && seal.id() == r.Seal {
		return fmt.Sprintf("%s is up to date (%s)", name, r.Seal), nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	archive := dir + ".download"
	defer os.Remove(archive)
	if err := store.getFile("capsules/"+name+"/"+idHex(r.Seal)+".tar", archive); err != nil {
		return "", err
	}
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fresh := dir + ".new"
	removeTree(fresh)
	defer removeTree(fresh)
	if _, err := unpackTar(tar.NewReader(f), fresh, true); err != nil {
		return "", fmt.Errorf("unpacking %s: %w", name, err)
	}
	if err := verifyCapsule(fresh, trusted); err != nil {
		return "", fmt.Errorf("not installing %s: %w", name, err)
	}
	if seal, err := readSeal(fresh); err != nil || seal.id() != r.Seal {
		return "", fmt.Errorf("not installing %s: the archive is not the release it was published as", name)
	}
	old := dir + ".old"
	removeTree(old)
	os.Rename(dir, old) // a running capsule keeps using its verified copy in the store, not this directory
	if err := os.Rename(fresh, dir); err != nil {
		os.Rename(old, dir)
		return "", err
	}
	removeTree(old)
	if err := os.MkdirAll(filepath.Dir(seenFile), 0o700); err == nil {
		os.WriteFile(seenFile, []byte(strconv.FormatInt(r.Time, 10)+" "+r.Seal+"\n"), 0o600)
	}
	return fmt.Sprintf("installed %s %s in %s", name, r.Seal, dir), nil
}
