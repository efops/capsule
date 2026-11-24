package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const trustDir = "/etc/capsule/trust.d"

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Seal is capsule.seal: the two hashes and a signature over them. The
// recipients are outside the signature: changing them can only stop the
// rootfs decrypting, and what does decrypt is still checked against Rootfs.
type Seal struct {
	Version    int         `json:"version"`
	Rootfs     string      `json:"rootfs"`
	Manifest   string      `json:"manifest"`
	PublicKey  string      `json:"public_key"`
	Signature  string      `json:"signature"`
	Encrypted  bool        `json:"encrypted,omitempty"` // rootfs is shipped as rootfs.enc
	Recipients []recipient `json:"recipients,omitempty"`
	Timelock   *timelock   `json:"timelock,omitempty"`
}

func (s Seal) message() []byte {
	return []byte("capsule-seal-v1\n" + s.Rootfs + "\n" + s.Manifest + "\n")
}

// id names one exact sealed capsule: approvals, revocations and run counts refer to it.
func (s Seal) id() string { return digest(s.message()) }

func readSeal(dir string) (Seal, error) {
	var s Seal
	raw, err := os.ReadFile(filepath.Join(dir, "capsule.seal"))
	if errors.Is(err, fs.ErrNotExist) {
		return s, errors.New("capsule is not sealed")
	} else if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Version != 1 || !digestRE.MatchString(s.Rootfs) {
		return s, errors.New("capsule.seal is malformed")
	}
	return s, nil
}

// sealedCapsule is a capsule whose seal has been checked against trusted keys.
type sealedCapsule struct {
	Manifest    Manifest
	ManifestRaw []byte
	Seal        Seal
	ID          string
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// permBits are the mode bits a rootfs entry keeps.
const permBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// hashRootfs hashes the tree deterministically: path, type and permission
// bits, then the link target or file contents. Ownership is not an input:
// the runtime makes every file root-owned when it imports the rootfs.
func hashRootfs(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		mode := info.Mode()
		if mode&fs.ModeSymlink != 0 {
			mode = fs.ModeSymlink // link permissions differ between systems and mean nothing
		}
		fmt.Fprintf(h, "%q %o ", filepath.ToSlash(rel), uint32(mode&(fs.ModeType|permBits)))
		switch {
		case mode.IsDir():
		case mode&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%q", target)
		case mode.IsRegular():
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			fh := sha256.New()
			_, err = io.Copy(fh, f)
			f.Close()
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%x", fh.Sum(nil))
		default:
			return fmt.Errorf("%s: devices, sockets and fifos are not allowed in a rootfs", rel)
		}
		h.Write([]byte{'\n'})
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// loadTrust reads the host's trusted public keys plus any given on the command line.
func loadTrust(extra []string) (trustSet, error) {
	paths, _ := filepath.Glob(filepath.Join(trustDir, "*.pub"))
	if own := filepath.Join(configDir(), "trust.d"); own != trustDir {
		// A user's own settings can add keys for what that user runs, as -trust does.
		more, _ := filepath.Glob(filepath.Join(own, "*.pub"))
		paths = append(paths, more...)
	}
	trusted := trustSet{}
	for _, p := range append(paths, extra...) {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		id := keyID(string(raw))
		if id == "" {
			return nil, fmt.Errorf("%s: not a capsule public key (keys from older builds must be made again with keygen)", p)
		}
		trusted[id] = true
	}
	return trusted, nil
}

// openCapsule reads the seal and manifest once and checks the signature was
// made by a trusted key. The manifest it returns is parsed from the bytes
// that were verified.
func openCapsule(dir string, trusted trustSet) (sealedCapsule, error) {
	var sc sealedCapsule
	if len(trusted) == 0 {
		return sc, fmt.Errorf("no trusted keys (add one to %s or pass -trust)", trustDir)
	}
	s, err := readSeal(dir)
	if err != nil {
		return sc, err
	}
	if id := keyID(s.PublicKey); id == "" {
		return sc, errors.New("capsule.seal is malformed")
	} else if !trusted[id] {
		return sc, errors.New("sealed by a key this host does not trust")
	}
	if !verifySig(s.PublicKey, s.Signature, s.message()) {
		return sc, errors.New("seal signature is invalid")
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "capsule.json"))
	if err != nil {
		return sc, err
	}
	if digest(manifest) != s.Manifest {
		return sc, errors.New("capsule.json was changed after sealing")
	}
	m, err := parseManifest(manifest)
	return sealedCapsule{Manifest: m, ManifestRaw: manifest, Seal: s, ID: s.id()}, err
}

// verifyCapsule checks the seal and, when the rootfs is not encrypted, the rootfs in place.
func verifyCapsule(dir string, trusted trustSet) error {
	sc, err := openCapsule(dir, trusted)
	if err != nil || sc.Seal.Encrypted {
		return err
	}
	got, err := hashRootfs(filepath.Join(dir, "rootfs"))
	if err != nil {
		return err
	}
	if got != sc.Seal.Rootfs {
		return errors.New("rootfs was changed after sealing")
	}
	return nil
}

// cmdKeygen writes a private key, its public key and that key's id.
func cmdKeygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: capsule keygen <name>")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	key := newSigner(seed)
	keyFile, err := os.OpenFile(args[0]+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	if _, err := fmt.Fprintln(keyFile, b64.EncodeToString(seed)); err != nil {
		return err
	}
	if err := os.WriteFile(args[0]+".pub", []byte(key.pub+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(args[0]+".id", []byte(key.id()+"\n"), 0o644)
}

func cmdSeal(args []string) error {
	fl := flag.NewFlagSet("seal", flag.ExitOnError)
	keyPath := fl.String("key", "", "private key file")
	var hosts ruleFlag
	fl.Var(&hosts, "host", "host file from `capsule host -export`, one for each id in policy.hosts (repeatable)")
	fl.Parse(args)
	if fl.NArg() != 1 || *keyPath == "" {
		return errors.New("usage: capsule seal -key <file> [-host <host file>]... <dir>")
	}
	s, err := sealCapsule(fl.Arg(0), *keyPath, hosts)
	if err != nil {
		return err
	}
	fmt.Println("sealed", s.Rootfs)
	return nil
}

// sealCapsule hashes and signs a capsule directory. A host list or a time
// lock is only enforceable as encryption, so either one also writes
// rootfs.enc, readable only by those hosts and only after that time.
func sealCapsule(dir, keyPath string, hostFiles []string) (Seal, error) {
	var s Seal
	key, err := loadSigner(keyPath)
	if err != nil {
		return s, err
	}
	hostKeys, err := loadHostKeys(hostFiles)
	if err != nil {
		return s, err
	}
	m, manifest, err := loadManifest(dir)
	if err != nil {
		return s, err
	}
	rootfs, err := hashRootfs(filepath.Join(dir, "rootfs"))
	if err != nil {
		return s, err
	}
	s = Seal{Version: 1, Rootfs: rootfs, Manifest: digest(manifest)}
	os.Remove(filepath.Join(dir, "rootfs.enc")) // never leave one from an earlier seal beside a new seal
	if p := m.Policy; p != nil && (len(p.Hosts) > 0 || p.Timelock) {
		var hostPart, timePart []byte
		if len(p.Hosts) > 0 {
			hostPart = make([]byte, 32)
			rand.Read(hostPart)
			for _, host := range p.Hosts {
				pub, ok := hostKeys[host]
				if !ok {
					return s, fmt.Errorf("policy.hosts lists %s but its host file was not given; run `capsule host -export` on that host and pass the file with -host", host)
				}
				r, err := wrapKey(hostPart, pub)
				if err != nil {
					return s, fmt.Errorf("policy.hosts: %w", err)
				}
				s.Recipients = append(s.Recipients, r)
			}
		}
		if p.Timelock {
			timePart = make([]byte, 32)
			rand.Read(timePart)
			if s.Timelock, err = lockKey(timePart, *p.NotBefore); err != nil {
				return s, err
			}
		}
		out, err := os.Create(filepath.Join(dir, "rootfs.enc"))
		if err != nil {
			return s, err
		}
		if err := encryptTree(filepath.Join(dir, "rootfs"), out, contentKey(hostPart, timePart)); err != nil {
			out.Close()
			return s, err
		}
		if err := out.Close(); err != nil {
			return s, err
		}
		s.Encrypted = true
	}
	s.PublicKey = key.pub
	s.Signature = key.sign(s.message())
	out, _ := json.MarshalIndent(s, "", "  ")
	return s, os.WriteFile(filepath.Join(dir, "capsule.seal"), append(out, '\n'), 0o644)
}

// trustFlag collects repeated -trust flags.
type trustFlag []string

func (t *trustFlag) String() string     { return strings.Join(*t, ",") }
func (t *trustFlag) Set(v string) error { *t = append(*t, v); return nil }

func cmdVerify(args []string) error {
	fl := flag.NewFlagSet("verify", flag.ExitOnError)
	var trust trustFlag
	fl.Var(&trust, "trust", "extra trusted public key file")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule verify [-trust <pub>] <dir>")
	}
	keys, err := loadTrust(trust)
	if err != nil {
		return err
	}
	if err := verifyCapsule(fl.Arg(0), keys); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}
