package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// A ledger is a shared place where hosts record facts the whole fleet must
// agree on: which run slots are taken, what has been revoked, and what each
// host's log looked like at each point. It offers one primitive that matters:
// create a key only if it does not exist. Everything stored is signed, so the
// store has to be available and has to keep what it is given, but it is never
// trusted to tell the truth.
type ledger interface {
	create(key string, value []byte) (created bool, err error)
	get(key string) (value []byte, found bool, err error)
	list(prefix string) (keys []string, err error)
	// put writes key whether or not it exists. It is only for state that is
	// meant to be replaced and that nothing relies on for a guarantee, such
	// as each host's current load.
	put(key string, value []byte) error
}

// openLedger returns the ledger named in <config>/ledger, or nil if this host has none.
//
//	file:///mnt/shared/capsule                              a shared directory
//	s3://bucket/prefix?region=eu-west-1                     AWS S3
//	s3://bucket/prefix?endpoint=https://store.internal:9000 any S3-compatible store (optionally &settle=2s)
//	vault://vault.internal:8200/secret/capsule              Vault KV version 2 (vault+http:// for plain HTTP)
//	artifactory://acme.jfrog.io/artifactory/capsule-ledger  a generic repository in Artifactory
//
// Credentials come from the usual environment variables (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, VAULT_TOKEN, ARTIFACTORY_TOKEN or
// ARTIFACTORY_USER and ARTIFACTORY_PASSWORD) or, failing that, from KEY=VALUE
// lines in <config>/ledger.env.
func openLedger() (ledger, error) {
	raw, err := os.ReadFile(filepath.Join(configDir(), "ledger"))
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	secret := ledgerSecrets()
	client := &http.Client{Timeout: 15 * time.Second}
	prefix := strings.Trim(u.Path, "/")
	switch u.Scheme {
	case "file":
		return dirLedger{u.Path}, nil
	case "s3":
		s := &s3Ledger{client: client, bucket: u.Host, prefix: prefix, region: u.Query().Get("region"),
			access: secret("AWS_ACCESS_KEY_ID"), secret: secret("AWS_SECRET_ACCESS_KEY"), token: secret("AWS_SESSION_TOKEN")}
		if s.region == "" {
			s.region = "us-east-1"
		}
		if endpoint := u.Query().Get("endpoint"); endpoint != "" {
			s.base = strings.TrimRight(endpoint, "/") + "/" + s.bucket // path style, as S3-compatible stores expect
			// Not every S3-compatible store applies a conditional write
			// atomically, so by default a contended claim on one is only
			// believed after a pause and a read-back. `capsule ledger check`
			// measures the store; settle=0 turns the pause off for one that passes.
			s.settle = time.Second
		} else {
			s.base = "https://" + s.bucket + ".s3." + s.region + ".amazonaws.com"
		}
		if s.settle, err = settleParam(u, s.settle); err != nil {
			return nil, err
		}
		if s.access == "" || s.secret == "" {
			return nil, errors.New("ledger: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
		}
		return s, nil
	case "vault", "vault+http":
		mount, path, _ := strings.Cut(prefix, "/")
		scheme := map[string]string{"vault": "https", "vault+http": "http"}[u.Scheme]
		v := &vaultLedger{client: client, base: scheme + "://" + u.Host + "/v1/" + mount, prefix: path, token: secret("VAULT_TOKEN")}
		if mount == "" || v.token == "" {
			return nil, errors.New("ledger: a Vault ledger needs a mount in its URL and VAULT_TOKEN")
		}
		return v, nil
	case "artifactory", "artifactory+http":
		// artifactory://host/<context>/<repository>/<folder...>, as the path appears in Artifactory itself
		parts := strings.Split(prefix, "/")
		if len(parts) < 2 {
			return nil, errors.New("ledger: an Artifactory ledger URL needs /<context>/<repository>, for example artifactory://acme.jfrog.io/artifactory/capsule-ledger")
		}
		scheme := map[string]string{"artifactory": "https", "artifactory+http": "http"}[u.Scheme]
		a := &artifactoryLedger{client: client, base: scheme + "://" + u.Host + "/" + parts[0], repo: parts[1], prefix: strings.Join(parts[2:], "/"),
			token: secret("ARTIFACTORY_TOKEN"), user: secret("ARTIFACTORY_USER"), password: secret("ARTIFACTORY_PASSWORD"), settle: time.Second}
		if a.token == "" && a.user == "" {
			return nil, errors.New("ledger: ARTIFACTORY_TOKEN, or ARTIFACTORY_USER and ARTIFACTORY_PASSWORD, are not set")
		}
		if a.settle, err = settleParam(u, a.settle); err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, fmt.Errorf("ledger: unknown kind %q (want file, s3, vault or artifactory)", u.Scheme)
}

// settleParam reads settle= from a ledger URL, keeping the backend's default if it is absent.
func settleParam(u *url.URL, fallback time.Duration) (time.Duration, error) {
	v := u.Query().Get("settle")
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("ledger: settle=%s is not a duration such as 1s or 500ms", v)
	}
	return d, nil
}

func ledgerSecrets() func(string) string {
	file := map[string]string{}
	raw, _ := os.ReadFile(filepath.Join(configDir(), "ledger.env"))
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			file[k] = strings.Trim(v, `"'`)
		}
	}
	return func(name string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return file[name]
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

// dirLedger keeps the ledger in a directory, typically one shared between hosts.
type dirLedger struct{ root string }

func (d dirLedger) create(key string, value []byte) (bool, error) {
	path := filepath.Join(d.root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".new-")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(value); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return false, err
	}
	// A hard link either creates the name with its full contents or fails because it exists.
	if err := os.Link(tmp.Name(), path); os.IsExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	syncDir(filepath.Dir(path))
	return true, nil
}

func (d dirLedger) put(key string, value []byte) error {
	path := filepath.Join(d.root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".new-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(value)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) // readers see the old value or the new one, never half of one
}

func (d dirLedger) remove(key string) error {
	return os.Remove(filepath.Join(d.root, filepath.FromSlash(key)))
}

func (d dirLedger) get(key string) ([]byte, bool, error) {
	value, err := os.ReadFile(filepath.Join(d.root, filepath.FromSlash(key)))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return value, err == nil, err
}

func (d dirLedger) list(prefix string) ([]string, error) {
	var keys []string
	start := filepath.Join(d.root, filepath.FromSlash(prefix))
	err := filepath.WalkDir(start, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".new-") {
			rel, _ := filepath.Rel(d.root, p)
			keys = append(keys, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(keys)
	return keys, err
}

// s3Ledger keeps the ledger in S3 or any store that speaks its API. Creation
// uses a conditional write (If-None-Match: *), which the store applies atomically.
type s3Ledger struct {
	client                *http.Client
	base, bucket, prefix  string
	region                string
	access, secret, token string
	settle                time.Duration
}

func (s *s3Ledger) settleTime() time.Duration { return s.settle }

func (s *s3Ledger) put(key string, value []byte) error {
	resp, err := s.do("PUT", join(s.prefix, key), nil, value, nil)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return httpProblem("put "+key, resp)
	}
	return nil
}

func (s *s3Ledger) remove(key string) error {
	resp, err := s.do("DELETE", join(s.prefix, key), nil, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (s *s3Ledger) do(method, key string, query url.Values, body []byte, header map[string]string) (*http.Response, error) {
	sum := sha256.Sum256(body)
	return s.send(method, key, query, bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:]), header, s.client)
}

// send makes one signed request. The body's hash is part of the signature, so it must be known first.
func (s *s3Ledger) send(method, key string, query url.Values, body io.Reader, size int64, hash string, header map[string]string, client *http.Client) (*http.Response, error) {
	target := s.base
	if key != "" {
		target += "/" + key
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.URL.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20") // already sorted by key, as signing requires
	for k, v := range header {
		req.Header.Set(k, v)
	}
	s.sign(req, hash, time.Now().UTC())
	return client.Do(req)
}

// sign adds an AWS Signature Version 4 to the request. payload is the hex SHA-256 of its body.
func (s *s3Ledger) sign(req *http.Request, payload string, now time.Time) {
	date, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	req.Header.Set("x-amz-content-sha256", payload)
	req.Header.Set("x-amz-date", stamp)
	if s.token != "" {
		req.Header.Set("x-amz-security-token", s.token)
	}
	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if s.token != "" {
		names = append(names, "x-amz-security-token")
	}
	var headers strings.Builder
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, req.URL.RawQuery, headers.String(), signed, payload}, "\n")
	scope := date + "/" + s.region + "/s3/aws4_request"
	digest := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}
	key := mac(mac(mac(mac([]byte("AWS4"+s.secret), date), s.region), "s3"), "aws4_request")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.access, scope, signed, hex.EncodeToString(mac(key, toSign))))
}

func httpProblem(what string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return fmt.Errorf("ledger: %s: %s %s", what, resp.Status, strings.Join(strings.Fields(string(body)), " "))
}

func (s *s3Ledger) create(key string, value []byte) (bool, error) {
	for attempt := 0; ; attempt++ {
		resp, err := s.do("PUT", join(s.prefix, key), nil, value, map[string]string{"If-None-Match": "*"})
		if err != nil {
			return false, fmt.Errorf("ledger: %w", err)
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			return true, nil
		case resp.StatusCode == http.StatusPreconditionFailed:
			return false, nil
		case resp.StatusCode == http.StatusConflict && attempt < 3: // another writer is mid-flight on this key
			time.Sleep(200 * time.Millisecond)
		default:
			return false, httpProblem("create "+key, resp)
		}
	}
}

func (s *s3Ledger) get(key string) ([]byte, bool, error) {
	resp, err := s.do("GET", join(s.prefix, key), nil, nil, nil)
	if err != nil {
		return nil, false, fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		value, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return value, err == nil, err
	case http.StatusNotFound:
		return nil, false, nil
	}
	return nil, false, httpProblem("get "+key, resp)
}

func (s *s3Ledger) list(prefix string) ([]string, error) {
	var keys []string
	query := url.Values{"list-type": {"2"}, "prefix": {join(s.prefix, prefix)}}
	for {
		resp, err := s.do("GET", "", query, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("ledger: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, httpProblem("list "+prefix, resp)
		}
		var page struct {
			Contents []struct{ Key string }
			Next     string `xml:"NextContinuationToken"`
		}
		if err := xml.NewDecoder(resp.Body).Decode(&page); err != nil {
			return nil, fmt.Errorf("ledger: list %s: %w", prefix, err)
		}
		for _, c := range page.Contents {
			keys = append(keys, strings.TrimPrefix(strings.TrimPrefix(c.Key, s.prefix), "/"))
		}
		if page.Next == "" {
			sort.Strings(keys)
			return keys, nil
		}
		query.Set("continuation-token", page.Next)
	}
}

// vaultLedger keeps the ledger in a Vault KV version 2 mount. Creation uses
// check-and-set with version 0, which succeeds only for a key never written.
type vaultLedger struct {
	client              *http.Client
	base, prefix, token string
}

func (v *vaultLedger) do(method, path string, body any) (*http.Response, error) {
	var payload io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, v.base+path, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	return v.client.Do(req)
}

func (v *vaultLedger) create(key string, value []byte) (bool, error) {
	resp, err := v.do("POST", "/data/"+join(v.prefix, key), map[string]any{
		"options": map[string]int{"cas": 0},
		"data":    map[string]string{"value": b64.EncodeToString(value)},
	})
	if err != nil {
		return false, fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return true, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "check-and-set") {
		return false, nil
	}
	return false, fmt.Errorf("ledger: create %s: %s %s", key, resp.Status, strings.Join(strings.Fields(string(body)), " "))
}

func (v *vaultLedger) put(key string, value []byte) error {
	resp, err := v.do("POST", "/data/"+join(v.prefix, key), map[string]any{"data": map[string]string{"value": b64.EncodeToString(value)}})
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return httpProblem("put "+key, resp)
	}
	return nil
}

func (v *vaultLedger) remove(key string) error {
	resp, err := v.do("DELETE", "/metadata/"+join(v.prefix, key), nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (v *vaultLedger) get(key string) ([]byte, bool, error) {
	resp, err := v.do("GET", "/data/"+join(v.prefix, key), nil)
	if err != nil {
		return nil, false, fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, false, httpProblem("get "+key, resp)
	}
	var out struct {
		Data struct {
			Data struct{ Value string }
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, fmt.Errorf("ledger: get %s: %w", key, err)
	}
	value, err := b64.DecodeString(out.Data.Data.Value)
	return value, err == nil, err
}

func (v *vaultLedger) list(prefix string) ([]string, error) {
	var keys []string
	var walk func(dir string) error
	walk = func(dir string) error {
		resp, err := v.do("GET", "/metadata/"+join(v.prefix, dir)+"?list=true", nil)
		if err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil
		} else if resp.StatusCode != http.StatusOK {
			return httpProblem("list "+dir, resp)
		}
		var out struct {
			Data struct{ Keys []string }
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return fmt.Errorf("ledger: list %s: %w", dir, err)
		}
		for _, name := range out.Data.Keys {
			if child := strings.TrimSuffix(dir, "/") + "/" + name; strings.HasSuffix(name, "/") {
				if err := walk(strings.TrimSuffix(child, "/")); err != nil {
					return err
				}
			} else {
				keys = append(keys, child)
			}
		}
		return nil
	}
	err := walk(strings.TrimSuffix(prefix, "/"))
	sort.Strings(keys)
	return keys, err
}

// artifactoryLedger keeps the ledger in a generic Artifactory repository.
// Artifactory has no conditional upload, so creation is a check followed by
// an upload, and competing claims are settled by createOnce's read-back. If
// the credentials are not allowed to overwrite or delete in the repository,
// Artifactory itself refuses the second upload, which makes creation atomic.
type artifactoryLedger struct {
	client                *http.Client
	base, repo, prefix    string
	token, user, password string
	settle                time.Duration
}

func (a *artifactoryLedger) settleTime() time.Duration { return a.settle }

func (a *artifactoryLedger) do(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else {
		req.SetBasicAuth(a.user, a.password)
	}
	return a.client.Do(req)
}

func (a *artifactoryLedger) file(key string) string { return "/" + a.repo + "/" + join(a.prefix, key) }

func (a *artifactoryLedger) exists(key string) (bool, error) {
	resp, err := a.do("HEAD", a.file(key), nil)
	if err != nil {
		return false, fmt.Errorf("ledger: %w", err)
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("ledger: checking %s: %s", key, resp.Status)
}

func (a *artifactoryLedger) create(key string, value []byte) (bool, error) {
	if exists, err := a.exists(key); err != nil || exists {
		return false, err
	}
	resp, err := a.do("PUT", a.file(key), value)
	if err != nil {
		return false, fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		return true, nil
	case http.StatusForbidden, http.StatusConflict:
		// Refused: either someone created it first and we may not overwrite, or we may not write at all.
		if exists, err := a.exists(key); err == nil && exists {
			return false, nil
		}
	}
	return false, httpProblem("create "+key, resp)
}

func (a *artifactoryLedger) put(key string, value []byte) error {
	resp, err := a.do("PUT", a.file(key), value)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return httpProblem("put "+key, resp) // credentials denied overwrite cannot replace a value
	}
	return nil
}

func (a *artifactoryLedger) get(key string) ([]byte, bool, error) {
	resp, err := a.do("GET", a.file(key), nil)
	if err != nil {
		return nil, false, fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		value, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return value, err == nil, err
	case http.StatusNotFound:
		return nil, false, nil
	}
	return nil, false, httpProblem("get "+key, resp)
}

func (a *artifactoryLedger) remove(key string) error {
	resp, err := a.do("DELETE", a.file(key), nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (a *artifactoryLedger) list(prefix string) ([]string, error) {
	var keys []string
	var walk func(dir string) error
	walk = func(dir string) error {
		resp, err := a.do("GET", "/api/storage/"+a.repo+"/"+join(a.prefix, dir), nil)
		if err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil
		} else if resp.StatusCode != http.StatusOK {
			return httpProblem("list "+dir, resp)
		}
		var info struct {
			Children []struct {
				URI    string
				Folder bool
			}
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return fmt.Errorf("ledger: list %s: %w", dir, err)
		}
		for _, child := range info.Children {
			path := strings.TrimSuffix(dir, "/") + child.URI
			if child.Folder {
				if err := walk(path); err != nil {
					return err
				}
			} else {
				keys = append(keys, strings.TrimPrefix(path, "/"))
			}
		}
		return nil
	}
	err := walk(strings.TrimSuffix(prefix, "/"))
	sort.Strings(keys)
	return keys, err
}

// createOnce creates key and then confirms the claim by reading it back,
// after the store's settle time if it has one. A store that wrongly tells
// several racing writers they each created the key keeps only one value, so
// only the writer whose value is stored counts as having created it. Use it
// for keys that hosts compete for; value must be unique to the caller.
func createOnce(l ledger, key string, value []byte) (bool, error) {
	created, err := l.create(key, value)
	if err != nil || !created {
		return false, err
	}
	if s, ok := l.(interface{ settleTime() time.Duration }); ok {
		time.Sleep(s.settleTime())
	}
	stored, found, err := l.get(key)
	if err != nil {
		return false, err
	}
	return found && bytes.Equal(stored, value), nil
}

// cmdLedger checks whether the configured ledger can be trusted with fleet-wide run limits.
func cmdLedger(args []string) error {
	fl := flag.NewFlagSet("ledger", flag.ExitOnError)
	writers := fl.Int("writers", 12, "how many writers race for each key")
	rounds := fl.Int("rounds", 5, "how many keys to race for")
	fl.Parse(args)
	if fl.Arg(0) != "check" || fl.NArg() != 1 || *writers < 2 || *rounds < 1 {
		return errors.New("usage: capsule ledger [-writers N] [-rounds N] check")
	}
	l, err := openLedger()
	if err != nil {
		return err
	}
	if l == nil {
		return errors.New("this host has no ledger configured (see <config>/ledger)")
	}
	told, confirmed, err := raceLedger(l, *writers, *rounds)
	if err != nil {
		return err
	}
	atomic, safe, worst := 0, 0, 0
	for i := range told {
		if told[i] == 1 {
			atomic++
		}
		if confirmed[i] == 1 {
			safe++
		}
		worst = max(worst, told[i])
	}
	settle := time.Duration(0)
	if s, ok := l.(interface{ settleTime() time.Duration }); ok {
		settle = s.settleTime()
	}
	fmt.Printf("%d writers raced to create each of %d keys\n", *writers, *rounds)
	if atomic == *rounds {
		fmt.Printf("create-once: held every time; the store applies it atomically\n")
	} else {
		fmt.Printf("create-once: BROKEN in %d of %d races; up to %d writers were each told they had created the same key\n", *rounds-atomic, *rounds, worst)
	}
	fmt.Printf("after reading back (pause %s): exactly one winner in %d of %d races\n", settle, safe, *rounds)
	switch {
	case safe != *rounds:
		return errors.New("NOT safe for fleet-wide run limits: raise settle= in the ledger URL and check again, or use another store")
	case atomic != *rounds && settle == 0:
		return errors.New("NOT safe as configured: the store is not atomic, and with settle=0 the read-back only resolved these races by luck of timing; remove settle=0 or set settle=1s or more")
	case atomic != *rounds:
		fmt.Printf("verdict: usable for fleet-wide run limits only because of the read-back; keep settle=%s (each fleet run waits that long)\n", settle)
	case settle > 0:
		fmt.Println("verdict: safe for fleet-wide run limits; you can add settle=0 to the ledger URL to drop the pause")
	default:
		fmt.Println("verdict: safe for fleet-wide run limits")
	}
	return nil
}

// raceLedger has several writers race to create each of a number of fresh
// keys. For each key it returns how many writers the store told had created
// it, and how many still believe so after createOnce's read-back. It removes
// the keys afterwards.
func raceLedger(l ledger, writers, rounds int) (told, confirmed []int, err error) {
	suffix := make([]byte, 6)
	rand.Read(suffix)
	prefix := "check-" + hex.EncodeToString(suffix) + "/"
	defer func() {
		if r, ok := l.(interface{ remove(string) error }); ok {
			keys, _ := l.list(prefix)
			for _, key := range keys {
				r.remove(key)
			}
		}
		if left, _ := l.list(prefix); len(left) > 0 {
			fmt.Fprintf(os.Stderr, "capsule: note: %d objects from this check could not be removed and remain under %s\n", len(left), prefix)
		}
	}()
	settle := time.Duration(0)
	if s, ok := l.(interface{ settleTime() time.Duration }); ok {
		settle = s.settleTime()
	}
	for round := 0; round < rounds; round++ {
		key := fmt.Sprintf("%srace-%d", prefix, round)
		created, kept := make([]bool, writers), make([]bool, writers)
		errs := make([]error, writers)
		var ready, done sync.WaitGroup
		start := make(chan struct{})
		for w := 0; w < writers; w++ {
			ready.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				l.get(prefix + "warm-up") // open this writer's connection first, so the writes land together
				ready.Done()
				<-start
				value := []byte(fmt.Sprintf("writer %d", w))
				if created[w], errs[w] = l.create(key, value); created[w] {
					// exactly what createOnce does next for a real claim
					time.Sleep(settle)
					stored, _, err := l.get(key)
					kept[w], errs[w] = bytes.Equal(stored, value), err
				}
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
		if err := errors.Join(errs...); err != nil {
			return nil, nil, err
		}
		nTold, nConfirmed := 0, 0
		for w := range created {
			if created[w] {
				nTold++
			}
			if kept[w] {
				nConfirmed++
			}
		}
		told, confirmed = append(told, nTold), append(confirmed, nConfirmed)
	}
	return told, confirmed, nil
}

// blobLedger is a ledger that can also hold large files, which is what
// distributing capsules through it needs. Vault cannot: it is built for
// secrets, not artifacts.
type blobLedger interface {
	putFile(key, path string) error
	getFile(key, path string) error
}

var slow = &http.Client{Timeout: 30 * time.Minute} // for whole capsules, not ledger entries

func fileHash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// saveBody writes a download to path through a temporary name, so path only ever holds a complete file.
func saveBody(resp *http.Response, what, path string) error {
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("ledger: %s is not there", what)
	} else if resp.StatusCode != http.StatusOK {
		return httpProblem("get "+what, resp)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (d dirLedger) putFile(key, path string) error {
	target := filepath.Join(d.root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(target), ".new-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, in)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

func (d dirLedger) getFile(key, path string) error {
	in, err := os.Open(filepath.Join(d.root, filepath.FromSlash(key)))
	if os.IsNotExist(err) {
		return fmt.Errorf("ledger: %s is not there", key)
	} else if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, in)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *s3Ledger) putFile(key, path string) error {
	hash, size, err := fileHash(path)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	resp, err := s.send("PUT", join(s.prefix, key), nil, f, size, hash, nil, slow)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return httpProblem("upload "+key, resp)
	}
	return nil
}

func (s *s3Ledger) getFile(key, path string) error {
	empty := sha256.Sum256(nil)
	resp, err := s.send("GET", join(s.prefix, key), nil, http.NoBody, 0, hex.EncodeToString(empty[:]), nil, slow)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return saveBody(resp, key, path)
}

func (a *artifactoryLedger) stream(method, path string, body io.Reader, size int64) (*http.Response, error) {
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else {
		req.SetBasicAuth(a.user, a.password)
	}
	return slow.Do(req)
}

func (a *artifactoryLedger) putFile(key, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	resp, err := a.stream("PUT", a.file(key), f, info.Size())
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return httpProblem("upload "+key, resp)
	}
	return nil
}

func (a *artifactoryLedger) getFile(key, path string) error {
	resp, err := a.stream("GET", a.file(key), http.NoBody, 0)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return saveBody(resp, key, path)
}
