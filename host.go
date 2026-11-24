package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var b64 = base64.StdEncoding

// realRoot is false for an ordinary user, including while their capsule
// supervisor runs as "root" inside its own user namespace.
func realRoot() bool { return os.Geteuid() == 0 && os.Getenv("CAPSULE_USERNS") == "" }

// configDir holds this host's secret, trusted peer cards and revocations.
func configDir() string {
	if d := os.Getenv("CAPSULE_CONFIG"); d != "" {
		return d
	}
	if realRoot() {
		return "/etc/capsule"
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "capsule")
}

// dataDir holds verified rootfs copies, run counters and the log.
func dataDir() string {
	if d := os.Getenv("CAPSULE_DATA"); d != "" {
		return d
	}
	if realRoot() {
		return "/var/lib/capsule"
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".local/share")
	}
	return filepath.Join(base, "capsule")
}

// hostDerive returns a key derived from the host's one secret, which never
// leaves the machine. Every host key (decryption, signing, mesh) comes from
// it, so there is a single file to protect and back up.
func hostDerive(label string) ([]byte, error) {
	path := filepath.Join(configDir(), "host.key")
	raw, err := os.ReadFile(path)
	if err == nil && len(strings.TrimSpace(string(raw))) == 0 {
		// An empty file is a secret whose creation was cut off by a crash
		// before it reached the disk. Nothing was ever derived from it.
		os.Remove(path)
		err = os.ErrNotExist
	}
	if os.IsNotExist(err) {
		if raw, err = createHostSecret(path); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	secret, err := b64.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(secret) != 32 {
		return nil, errors.New(path + " is not a host secret")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	return mac.Sum(nil), nil
}

// createHostSecret writes a new secret so that it appears complete or not at
// all, even if this process is interrupted or another creates one at the same
// moment: the file is written and synced under a temporary name, then linked
// into place, which fails rather than overwrites if a secret already exists.
func createHostSecret(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".host.key-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	encoded := []byte(b64.EncodeToString(secret) + "\n")
	if _, err := tmp.Write(encoded); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if os.IsExist(err) { // another process won; use its secret
			return os.ReadFile(path)
		}
		return nil, err
	}
	syncDir(filepath.Dir(path))
	return encoded, nil
}

// syncDir makes a new or renamed entry in dir survive a power cut.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// hostBoxKey decrypts capsules addressed to this host. The id of its public half is the host's id.
func hostBoxKey() (*hostKEM, error) {
	seed, err := hostDerive("capsule-host-box-v2")
	if err != nil {
		return nil, err
	}
	return newHostKEM(seed)
}

// hostSigner signs this host's log entries, run receipts and self-issued cards.
func hostSigner() (*signer, error) {
	seed, err := hostDerive("capsule-host-sign-v2")
	if err != nil {
		return nil, err
	}
	return newSigner(seed), nil
}

func hostID() (string, error) {
	key, err := hostBoxKey()
	if err != nil {
		return "", err
	}
	return key.id(), nil
}

// cmdHost prints this host's ids, or with -export the file someone needs to
// seal an encrypted capsule for it.
func cmdHost(args []string) error {
	fl := flag.NewFlagSet("host", flag.ExitOnError)
	export := fl.Bool("export", false, "print this host's public keys as a host file, for `capsule seal -host`")
	fl.Parse(args)
	box, err := hostBoxKey()
	if err != nil {
		return err
	}
	sign, err := hostSigner()
	if err != nil {
		return err
	}
	if *export {
		out, _ := json.MarshalIndent(hostCard{ID: box.id(), Key: b64.EncodeToString(box.public()), Sign: sign.id(), SignKey: sign.pub}, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	fmt.Printf("id    %s\nsign  %s\n", box.id(), sign.id())
	return nil
}
