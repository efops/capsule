package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Every signature here is two signatures over the same message, Ed25519 and
// ML-DSA-65, and both must verify. Every key wrap combines two key exchanges,
// X25519 and ML-KEM-768, and both shared secrets feed the wrapping key. An
// attacker has to break the classical scheme and the post-quantum one, so
// capsules stay safe if a large quantum computer breaks the first, or if a
// flaw is found in the newer second.
//
// Hybrid public keys are about 2 KB, too long to list in a manifest, so keys
// are named by id, the SHA-256 of the public key. Wherever a key is used, the
// full key travels with it and is checked against the id.

const (
	sigContext    = "capsule"
	signPubSize   = ed25519.PublicKeySize + mldsa65.PublicKeySize
	signatureSize = ed25519.SignatureSize + mldsa65.SignatureSize
	kemPubSize    = 32 + mlkem.EncapsulationKeySize768
)

func derive(seed []byte, label string, size int) []byte {
	key, err := hkdf.Key(sha256.New, seed, nil, label, size)
	if err != nil {
		panic(err) // only for an impossible output length
	}
	return key
}

func hashID(label string, data []byte) string {
	sum := sha256.Sum256(append([]byte(label+"\x00"), data...))
	return b64.EncodeToString(sum[:])
}

// isID reports whether s has the form of a key id.
func isID(s string) bool {
	raw, err := b64.DecodeString(s)
	return err == nil && len(raw) == sha256.Size
}

// signer is a hybrid signing key, expanded from one 32-byte seed.
type signer struct {
	ed  ed25519.PrivateKey
	pq  *mldsa65.PrivateKey
	pub string // base64 of the Ed25519 public key followed by the ML-DSA one
}

func newSigner(seed []byte) *signer {
	ed := ed25519.NewKeyFromSeed(derive(seed, "capsule-sign-ed25519-v1", ed25519.SeedSize))
	var pqSeed [mldsa65.SeedSize]byte
	copy(pqSeed[:], derive(seed, "capsule-sign-mldsa65-v1", mldsa65.SeedSize))
	pqPub, pq := mldsa65.NewKeyFromSeed(&pqSeed)
	pub := append(append([]byte{}, ed.Public().(ed25519.PublicKey)...), pqPub.Bytes()...)
	return &signer{ed: ed, pq: pq, pub: b64.EncodeToString(pub)}
}

// loadSigner reads a private key file written by keygen.
func loadSigner(path string) (*signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := b64.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("%s: not a capsule private key (keys from older builds must be made again with keygen)", path)
	}
	return newSigner(seed), nil
}

func (s *signer) id() string { return keyID(s.pub) }

func (s *signer) sign(msg []byte) string {
	sig := make([]byte, signatureSize)
	copy(sig, ed25519.Sign(s.ed, msg))
	if err := mldsa65.SignTo(s.pq, msg, []byte(sigContext), true, sig[ed25519.SignatureSize:]); err != nil {
		panic(err) // only for an over-long context, which is a constant here
	}
	return b64.EncodeToString(sig)
}

// keyID names a signing key by the hash of its public key, or returns "" if it is malformed.
func keyID(pub string) string {
	raw, err := b64.DecodeString(strings.TrimSpace(pub))
	if err != nil || len(raw) != signPubSize {
		return ""
	}
	return hashID("capsule-sign-key-v1", raw)
}

// verifySig reports whether sig holds valid Ed25519 and ML-DSA signatures by pub over msg.
func verifySig(pub, sig string, msg []byte) bool {
	rawPub, err1 := b64.DecodeString(pub)
	rawSig, err2 := b64.DecodeString(sig)
	if err1 != nil || err2 != nil || len(rawPub) != signPubSize || len(rawSig) != signatureSize {
		return false
	}
	var pq mldsa65.PublicKey
	if err := pq.UnmarshalBinary(rawPub[ed25519.PublicKeySize:]); err != nil {
		return false
	}
	classical := ed25519.Verify(rawPub[:ed25519.PublicKeySize], msg, rawSig[:ed25519.SignatureSize])
	postQuantum := mldsa65.Verify(&pq, msg, []byte(sigContext), rawSig[ed25519.SignatureSize:])
	return classical && postQuantum
}

// trustSet is the ids of the signing keys a host accepts.
type trustSet map[string]bool

// signedBy reports whether pub is a trusted key and sig is its signature over msg.
func signedBy(trusted trustSet, pub, sig string, msg []byte) bool {
	id := keyID(pub)
	return id != "" && trusted[id] && verifySig(pub, sig, msg)
}

// hostKEM is a host's hybrid decryption key.
type hostKEM struct {
	x *ecdh.PrivateKey
	m *mlkem.DecapsulationKey768
}

func newHostKEM(seed []byte) (*hostKEM, error) {
	x, err := ecdh.X25519().NewPrivateKey(derive(seed, "capsule-host-x25519-v1", 32))
	if err != nil {
		return nil, err
	}
	m, err := mlkem.NewDecapsulationKey768(derive(seed, "capsule-host-mlkem768-v1", mlkem.SeedSize))
	if err != nil {
		return nil, err
	}
	return &hostKEM{x, m}, nil
}

// public is the X25519 public key followed by the ML-KEM encapsulation key.
func (h *hostKEM) public() []byte {
	return append(h.x.PublicKey().Bytes(), h.m.EncapsulationKey().Bytes()...)
}

func (h *hostKEM) id() string { return hostKeyID(h.public()) }

func hostKeyID(pub []byte) string { return hashID("capsule-host-key-v1", pub) }

// hostCard is what `capsule host -export` writes: what someone sealing a
// capsule for this host needs, and nothing secret.
type hostCard struct {
	ID   string `json:"id"`
	Key  string `json:"key"`  // hybrid encryption key
	Sign string `json:"sign"` // id of the key that signs this host's log and receipts
	// SignKey is that key in full, for checking a piece of this host's log that does not carry it.
	SignKey string `json:"sign_key,omitempty"`
}

// loadHostKeys reads exported host files and returns each host's encryption key by id.
func loadHostKeys(files []string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c hostCard
		pub, decodeErr := []byte(nil), error(nil)
		if err := json.Unmarshal(raw, &c); err == nil {
			pub, decodeErr = b64.DecodeString(c.Key)
		}
		if decodeErr != nil || len(pub) != kemPubSize || hostKeyID(pub) != c.ID {
			return nil, fmt.Errorf("%s: not a host file from `capsule host -export`", filepath.Base(f))
		}
		keys[c.ID] = pub
	}
	return keys, nil
}

// recipient is one part of the content key, wrapped for one authorised host.
type recipient struct {
	Host      string `json:"host"`
	Ephemeral string `json:"ephemeral"` // X25519
	KEM       string `json:"kem"`       // ML-KEM-768 ciphertext
	Key       string `json:"key"`
}

// wrapSecret binds both shared secrets and everything public about the
// exchange into the key that wraps the part.
func wrapSecret(classical, postQuantum, ephemeral, kemCiphertext, hostPub []byte) ([]byte, error) {
	secret := append(append([]byte{}, postQuantum...), classical...)
	salt := append(append(append([]byte{}, ephemeral...), kemCiphertext...), hostPub...)
	return hkdf.Key(sha256.New, secret, salt, "capsule-wrap-v2", 32)
}

// wrapKey encrypts part so that only the holder of the host's secret can
// recover it, and only by undoing both key exchanges.
func wrapKey(part, hostPub []byte) (recipient, error) {
	var r recipient
	if len(hostPub) != kemPubSize {
		return r, errors.New("not a host encryption key")
	}
	x, err := ecdh.X25519().NewPublicKey(hostPub[:32])
	if err != nil {
		return r, err
	}
	ek, err := mlkem.NewEncapsulationKey768(hostPub[32:])
	if err != nil {
		return r, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return r, err
	}
	classical, err := eph.ECDH(x)
	if err != nil {
		return r, err
	}
	postQuantum, ciphertext := ek.Encapsulate()
	key, err := wrapSecret(classical, postQuantum, eph.PublicKey().Bytes(), ciphertext, hostPub)
	if err != nil {
		return r, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return r, err
	}
	// The wrapping key is used exactly once, so a fixed nonce is safe.
	wrapped := aead.Seal(nil, make([]byte, aead.NonceSize()), part, nil)
	return recipient{
		Host:      hostKeyID(hostPub),
		Ephemeral: b64.EncodeToString(eph.PublicKey().Bytes()),
		KEM:       b64.EncodeToString(ciphertext),
		Key:       b64.EncodeToString(wrapped),
	}, nil
}

func unwrapKey(r recipient, host *hostKEM) ([]byte, error) {
	ephRaw, err1 := b64.DecodeString(r.Ephemeral)
	ciphertext, err2 := b64.DecodeString(r.KEM)
	wrapped, err3 := b64.DecodeString(r.Key)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("capsule.seal is malformed")
	}
	eph, err := ecdh.X25519().NewPublicKey(ephRaw)
	if err != nil {
		return nil, err
	}
	classical, err := host.x.ECDH(eph)
	if err != nil {
		return nil, err
	}
	postQuantum, err := host.m.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := wrapSecret(classical, postQuantum, ephRaw, ciphertext, host.public())
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), wrapped, nil)
}
