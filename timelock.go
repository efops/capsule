package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drand/tlock"
	drandhttp "github.com/drand/tlock/networks/http"
)

// The drand "quicknet" beacon: a public, decentralised network that publishes
// a threshold signature every three seconds. Data encrypted to a future
// round can be decrypted by anyone once that round is published and by
// nobody before, whatever any host's clock or administrator says.
const drandChain = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

var drandHosts = []string{"https://api.drand.sh", "https://drand.cloudflare.com"}

// timelock is part of a capsule's content key, locked until a drand round.
type timelock struct {
	Chain string `json:"chain"`
	Round uint64 `json:"round"`
	Key   string `json:"key"`
}

var errTooEarly = errors.New("too early")

func drandNetwork() (*drandhttp.Network, error) {
	hosts := drandHosts
	if h := os.Getenv("CAPSULE_DRAND"); h != "" {
		hosts = strings.Split(h, ",")
	}
	var last error
	for _, host := range hosts {
		network, err := drandhttp.NewNetwork(host, drandChain)
		if err == nil {
			return network, nil
		}
		last = err
	}
	return nil, fmt.Errorf("cannot reach the drand network: %w", last)
}

// lockKey encrypts part so it cannot be read before the given time.
func lockKey(part []byte, at time.Time) (*timelock, error) {
	network, err := drandNetwork()
	if err != nil {
		return nil, err
	}
	round := network.RoundNumber(at)
	var out bytes.Buffer
	if err := tlock.New(network).Encrypt(&out, bytes.NewReader(part), round); err != nil {
		return nil, err
	}
	return &timelock{Chain: drandChain, Round: round, Key: b64.EncodeToString(out.Bytes())}, nil
}

// unlockKey recovers the part once its round has been published. The result
// is public knowledge from then on, so it is cached and later runs need no network.
func unlockKey(t *timelock, sealID string) ([]byte, error) {
	if t.Chain != drandChain {
		return nil, errors.New("capsule is time-locked to a drand chain this build does not know")
	}
	cache := filepath.Join(dataDir(), "timelock", strings.TrimPrefix(sealID, "sha256:"))
	if raw, err := os.ReadFile(cache); err == nil && len(raw) == 32 {
		return raw, nil
	}
	locked, err := b64.DecodeString(t.Key)
	if err != nil {
		return nil, errors.New("capsule.seal is malformed")
	}
	network, err := drandNetwork()
	if err != nil {
		return nil, err
	}
	var part bytes.Buffer
	if err := tlock.New(network).Decrypt(&part, bytes.NewReader(locked)); err != nil {
		if errors.Is(err, tlock.ErrTooEarly) {
			return nil, errTooEarly
		}
		return nil, fmt.Errorf("time lock: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err == nil {
		os.WriteFile(cache, part.Bytes(), 0o600)
	}
	return part.Bytes(), nil
}

// contentKey combines the parts a capsule's rootfs key is split into. Every
// part that exists is needed: the one wrapped for authorised hosts, and the
// one locked until a time.
func contentKey(hostPart, timePart []byte) []byte {
	h := sha256.New()
	h.Write([]byte("capsule-content-v1\x00"))
	for _, part := range [][]byte{hostPart, timePart} {
		h.Write([]byte{byte(len(part))}) // each part is labelled by position and length, so one cannot stand in for the other
		h.Write(part)
	}
	return h.Sum(nil)
}
