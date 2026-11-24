package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeS3 is the part of the S3 API the ledger uses, with conditional writes.
func fakeS3(t *testing.T) *s3Ledger { return fakeS3Store(t, 0) }

// fakeS3Store with a non-zero window imitates a store that checks the
// condition, then takes that long to store the object, so racing writers all
// pass the check and the last one's value is kept. A real store was found to
// behave this way.
func fakeS3Store(t *testing.T, window time.Duration) *s3Ledger {
	var mu sync.Mutex
	objects := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if window > 0 && r.Method == "PUT" {
			_, exists := objects[strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/bucket"), "/")]
			if exists && r.Header.Get("If-None-Match") == "*" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Unlock()
			time.Sleep(window)
			mu.Lock()
			objects[strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/bucket"), "/")] = body
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/bucket")
		key = strings.TrimPrefix(key, "/")
		switch {
		case r.Method == "PUT":
			if _, exists := objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			objects[key], _ = io.ReadAll(r.Body)
		case r.Method == "GET" && key == "":
			type contents struct{ Key string }
			var page struct {
				XMLName  xml.Name `xml:"ListBucketResult"`
				Contents []contents
			}
			for k := range objects {
				if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
					page.Contents = append(page.Contents, contents{k})
				}
			}
			sort.Slice(page.Contents, func(i, j int) bool { return page.Contents[i].Key < page.Contents[j].Key })
			xml.NewEncoder(w).Encode(page)
		case r.Method == "GET":
			if v, ok := objects[key]; ok {
				w.Write(v)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return &s3Ledger{client: srv.Client(), base: srv.URL + "/bucket", bucket: "bucket", prefix: "fleet", region: "us-east-1", access: "AKIDTEST", secret: "secret"}
}

// fakeVault is the part of the KV version 2 API the ledger uses, with check-and-set.
func fakeVault(t *testing.T) *vaultLedger {
	var mu sync.Mutex
	secrets := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("X-Vault-Token") != "token" {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/") && r.Method == "POST":
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			var body struct {
				Options struct{ CAS *int }
				Data    struct{ Value string }
			}
			json.NewDecoder(r.Body).Decode(&body)
			if _, exists := secrets[key]; exists && body.Options.CAS != nil && *body.Options.CAS == 0 {
				http.Error(w, `{"errors":["check-and-set parameter did not match the current version"]}`, http.StatusBadRequest)
				return
			}
			secrets[key] = body.Data.Value
			w.Write([]byte(`{"data":{"version":1}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			if v, ok := secrets[strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")]; ok {
				fmt.Fprintf(w, `{"data":{"data":{"value":%q}}}`, v)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
			dir := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/"), "/") + "/"
			names := map[string]bool{}
			for k := range secrets {
				if rest, ok := strings.CutPrefix(k, dir); ok {
					if child, _, nested := strings.Cut(rest, "/"); nested {
						names[child+"/"] = true
					} else {
						names[child] = true
					}
				}
			}
			if len(names) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var keys []string
			for n := range names {
				keys = append(keys, n)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		}
	}))
	t.Cleanup(srv.Close)
	return &vaultLedger{client: srv.Client(), base: srv.URL + "/v1/secret", prefix: "fleet", token: "token"}
}

// fakeArtifactory is the part of Artifactory's API the ledger uses: upload,
// download, existence check, folder listing and delete. With overwrite
// allowed, a second upload replaces the first, as Artifactory does for
// credentials that hold delete permission; without it, the upload is refused.
func fakeArtifactory(t *testing.T, overwrite bool) *artifactoryLedger {
	var mu sync.Mutex
	files := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if dir, ok := strings.CutPrefix(r.URL.Path, "/artifactory/api/storage/repo/"); ok {
			dir = strings.TrimSuffix(dir, "/") + "/"
			type child struct {
				URI    string `json:"uri"`
				Folder bool   `json:"folder"`
			}
			seen := map[string]bool{}
			var children []child
			for name := range files {
				if rest, ok := strings.CutPrefix(name, dir); ok {
					first, _, nested := strings.Cut(rest, "/")
					if !seen[first] {
						seen[first] = true
						children = append(children, child{"/" + first, nested})
					}
				}
			}
			if len(children) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"children": children})
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/artifactory/repo/")
		_, exists := files[name]
		switch r.Method {
		case "PUT":
			if exists && !overwrite {
				http.Error(w, "not permitted to overwrite", http.StatusForbidden)
				return
			}
			files[name], _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		case "DELETE":
			delete(files, name)
		default: // GET and HEAD
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(files[name])
		}
	}))
	t.Cleanup(srv.Close)
	return &artifactoryLedger{client: srv.Client(), base: srv.URL + "/artifactory", repo: "repo", prefix: "fleet", token: "token"}
}

// Every backend must behave the same way, above all in creating a key at most once.
func TestLedgerBackends(t *testing.T) {
	for name, l := range map[string]ledger{"directory": dirLedger{t.TempDir()}, "s3": fakeS3(t), "vault": fakeVault(t),
		"artifactory, overwrite refused": fakeArtifactory(t, false)} {
		t.Run(name, func(t *testing.T) { ledgerConformance(t, l) })
	}
}

// TestLedgerRealStore runs the same checks, and a race for fleet run slots,
// against a real store. It only runs when given one:
//
//	CAPSULE_TEST_LEDGER='s3://bucket/some/prefix?endpoint=https://...' AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... go test -run RealStore -v .
//	CAPSULE_TEST_LEDGER='artifactory://host/artifactory/repo/some/folder' ARTIFACTORY_TOKEN=... go test -run RealStore -v .
//
// Everything it writes goes under a fresh random prefix, which it removes
// afterwards. Nothing else in the store is read or changed.
func TestLedgerRealStore(t *testing.T) {
	target := os.Getenv("CAPSULE_TEST_LEDGER")
	if target == "" {
		t.Skip("set CAPSULE_TEST_LEDGER to a ledger URL to test against a real store")
	}
	newHost(t)
	suffix := make([]byte, 6)
	rand.Read(suffix)
	u, err := url.Parse(target)
	must(t, err)
	u.Path = strings.TrimRight(u.Path, "/") + "/capsule-test-" + hex.EncodeToString(suffix)
	must(t, os.WriteFile(filepath.Join(configDir(), "ledger"), []byte(u.String()+"\n"), 0o644))
	l, err := openLedger()
	must(t, err)
	if r, ok := l.(interface{ remove(string) error }); ok {
		t.Cleanup(func() {
			keys, err := l.list("")
			if err != nil {
				t.Errorf("could not list the test's own keys to remove them: %v", err)
				return
			}
			for _, key := range keys {
				r.remove(key)
			}
			left, _ := l.list("")
			t.Logf("removed %d test objects under %s, %d left", len(keys)-len(left), u.Path, len(left))
		})
	}
	ledgerConformance(t, l)

	// Whole capsules travel through the same store: a few megabytes up and back, byte for byte.
	if store, ok := l.(blobLedger); ok {
		big := filepath.Join(t.TempDir(), "big")
		data := make([]byte, 3<<20)
		rand.Read(data)
		must(t, os.WriteFile(big, data, 0o644))
		must(t, store.putFile("capsules/test/archive.tar", big))
		back := filepath.Join(t.TempDir(), "back")
		must(t, store.getFile("capsules/test/archive.tar", back))
		if got := mustRead(t, back); !bytes.Equal(got, data) {
			t.Fatalf("a %d byte file came back as %d bytes, or changed", len(data), len(got))
		}
		if err := store.getFile("capsules/test/missing.tar", back); err == nil {
			t.Fatal("fetching a file that is not there succeeded")
		}
	}

	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	dir := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"max_runs":3,"fleet":true}}`)
	_, err = sealCapsule(dir, key, nil)
	must(t, err)
	sc, err := openCapsule(dir, trustSet{id: true})
	must(t, err)
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ { // twelve hosts racing for three run slots
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := claimFleetRun(l, sc); err == nil {
				won.Add(1)
			} else if !strings.Contains(err.Error(), "fleet-wide runs have been used") {
				t.Errorf("claim failed for another reason: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 3 {
		t.Fatalf("%d racing claims succeeded on the real store, want exactly 3", won.Load())
	}
	wantErr(t, claimFleetRun(l, sc), "all 3 fleet-wide runs have been used")
}

func ledgerConformance(t *testing.T, l ledger) {
	{
		{
			// put replaces; it is how advisory state such as load is shared
			// (credentials that Artifactory denies overwrite cannot do this, which is the price of atomic creation there)
			if !strings.Contains(t.Name(), "refused") {
				must(t, l.put("load/app/host", []byte("one")))
				must(t, l.put("load/app/host", []byte("two")))
				if v, found, err := l.get("load/app/host"); err != nil || !found || string(v) != "two" {
					t.Fatalf("put did not replace the value: %q %v %v", v, found, err)
				}
			}
			created, err := l.create("runs/abc/000001", []byte("first"))
			if err != nil || !created {
				t.Fatalf("first create: %v %v", created, err)
			}
			created, err = l.create("runs/abc/000001", []byte("second"))
			if err != nil || created {
				t.Fatalf("a key was created twice: %v %v", created, err)
			}
			value, found, err := l.get("runs/abc/000001")
			if err != nil || !found || string(value) != "first" {
				t.Fatalf("get returned %q %v %v, want the first value", value, found, err)
			}
			if _, found, err := l.get("runs/abc/000009"); err != nil || found {
				t.Fatalf("a missing key was found: %v %v", found, err)
			}
			for _, key := range []string{"runs/abc/000002", "runs/abcd/000001", "heads/h/0000000000"} {
				if _, err := l.create(key, []byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			keys, err := l.list("runs/abc/")
			if err != nil || strings.Join(keys, " ") != "runs/abc/000001 runs/abc/000002" {
				t.Fatalf("list returned %v %v", keys, err)
			}
			if keys, err := l.list("nothing/"); err != nil || len(keys) != 0 {
				t.Fatalf("listing an empty prefix returned %v %v", keys, err)
			}

			var wins atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 40; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					created, err := l.create("race/slot", []byte(fmt.Sprint(i)))
					if err != nil {
						t.Errorf("a racing create failed outright: %v", err)
					} else if created {
						wins.Add(1)
					}
				}()
			}
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%d of 40 concurrent creators won the same key, want exactly 1", wins.Load())
			}
		}
	}
}

// The request signature is checked against the worked examples in AWS's own documentation.
func TestS3Signature(t *testing.T) {
	s := &s3Ledger{region: "us-east-1", access: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	for query, want := range map[string]string{
		"lifecycle=":          "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		"max-keys=2&prefix=J": "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
	} {
		req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?"+query, nil)
		empty := sha256.Sum256(nil)
		s.sign(req, hex.EncodeToString(empty[:]), at)
		if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, "Signature="+want) {
			t.Errorf("?%s signed as\n  %s\nwant signature %s", query, got, want)
		}
	}
}

// twoHosts returns functions that switch this test between two hosts sharing one ledger.
func twoHosts(t *testing.T) (asA, asB func()) {
	shared := t.TempDir()
	host := func() func() {
		config, data := t.TempDir(), t.TempDir()
		must(t, os.WriteFile(filepath.Join(config, "ledger"), []byte("file://"+shared+"\n"), 0o644))
		return func() { t.Setenv("CAPSULE_CONFIG", config); t.Setenv("CAPSULE_DATA", data) }
	}
	return host(), host()
}

func TestFleetRunLimitAndRevocation(t *testing.T) {
	asA, asB := twoHosts(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	malloryKey, _ := newKey(t, keys, "mallory")
	trusted := trustSet{id: true}
	dir := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"max_runs":3,"fleet":true}}`)
	_, err := sealCapsule(dir, key, nil)
	must(t, err)
	sc, err := openCapsule(dir, trusted)
	must(t, err)

	ran := 0
	for i, as := range []func(){asA, asB, asA, asB, asA, asB} { // six attempts across two hosts, three allowed
		as()
		if err := countRun(dir, sc, time.Now()); err == nil {
			ran++
		} else if !strings.Contains(err.Error(), "all 3 fleet-wide runs have been used") {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if ran != 3 {
		t.Fatalf("%d runs happened across the fleet, want 3", ran)
	}

	asA()
	l, err := openLedger()
	must(t, err)
	big := newCapsule(t, `{"name":"big","command":["/x"],"policy":{"max_runs":5,"fleet":true}}`)
	_, err = sealCapsule(big, key, nil)
	must(t, err)
	bigSC, err := openCapsule(big, trusted)
	must(t, err)
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ { // thirty hosts racing for five slots
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimFleetRun(l, bigSC) == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 5 {
		t.Fatalf("%d racing claims succeeded, want exactly 5", won.Load())
	}

	// A host with no ledger cannot run a capsule that requires one.
	newHost(t)
	wantErr(t, checkPolicy(dir, sc, trusted, time.Now()), "needs the fleet ledger")

	// Revocation published on one host stops the other.
	asB()
	must(t, checkPolicy(dir, sc, trusted, time.Now()))
	asA()
	must(t, cmdRevoke([]string{"-key", malloryKey, "-publish", dir}))
	asB()
	must(t, checkPolicy(dir, sc, trusted, time.Now())) // not from a trusted key
	asA()
	must(t, cmdRevoke([]string{"-key", key, "-publish", dir}))
	asB()
	wantErr(t, checkPolicy(dir, sc, trusted, time.Now()), "revoked for the whole fleet")
}

func TestPermits(t *testing.T) {
	newHost(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	issuerKey, issuer := newKey(t, keys, "issuer")
	malloryKey, _ := newKey(t, keys, "mallory")
	trusted := trustSet{id: true}
	self, err := hostID()
	must(t, err)
	other := randomHost(t).id()
	dir := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"permits":["`+issuer+`"]}}`)
	_, err = sealCapsule(dir, key, nil)
	must(t, err)
	sc, err := openCapsule(dir, trusted)
	must(t, err)
	now := time.Now()

	wantErr(t, countRun(dir, sc, now), "no valid permit")
	must(t, cmdPermit([]string{"-key", issuerKey, "-host", other, "-runs", "9", dir})) // for a different host
	must(t, cmdPermit([]string{"-key", malloryKey, "-host", self, "-runs", "9", dir})) // from a key the manifest does not list
	wantErr(t, countRun(dir, sc, now), "no valid permit")
	must(t, cmdPermit([]string{"-key", issuerKey, "-host", self, "-runs", "2", dir}))
	must(t, countRun(dir, sc, now))
	must(t, countRun(dir, sc, now))
	wantErr(t, countRun(dir, sc, now), "already ran 2 of 2")
	must(t, cmdPermit([]string{"-key", issuerKey, "-host", self, "-runs", "1", "-days", "1", dir}))
	must(t, countRun(dir, sc, now))
	wantErr(t, countRun(dir, sc, now), "already ran 3 of 3")
	wantErr(t, countRun(dir, sc, now.AddDate(0, 0, 2)), "already ran 3 of 2") // the dated permit has lapsed

	// A permit edited to allow more runs no longer carries a valid signature.
	fresh := newCapsule(t, `{"name":"two","command":["/x"],"policy":{"permits":["`+issuer+`"]}}`)
	_, err = sealCapsule(fresh, key, nil)
	must(t, err)
	freshSC, err := openCapsule(fresh, trusted)
	must(t, err)
	must(t, cmdPermit([]string{"-key", issuerKey, "-host", self, "-runs", "1", fresh}))
	raw, _ := os.ReadFile(filepath.Join(fresh, "capsule.permits"))
	must(t, os.WriteFile(filepath.Join(fresh, "capsule.permits"), []byte(strings.Replace(string(raw), `"runs": 1`, `"runs": 100`, 1)), 0o644))
	wantErr(t, countRun(fresh, freshSC, now), "no valid permit")
	// And a permit for one seal does not carry over to another.
	must(t, os.WriteFile(filepath.Join(fresh, "capsule.permits"), mustRead(t, filepath.Join(dir, "capsule.permits")), 0o644))
	wantErr(t, countRun(fresh, freshSC, now), "no valid permit")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	return data
}

func TestWitnessing(t *testing.T) {
	asA, asB := twoHosts(t)
	logRun := func() {
		_, err := appendLog(logEntry{Event: "run", Capsule: "app"})
		must(t, err)
	}
	asA()
	logRun()
	logRun()
	logRun()
	aLog, aData := logPath(), dataDir()
	l, err := openLedger()
	must(t, err)

	asB()
	logRun()
	n, alerts, err := witness(l)
	if err != nil || n != 1 || len(alerts) != 0 {
		t.Fatalf("B witnessing A: %d %v %v", n, alerts, err)
	}
	asA()
	n, alerts, err = witness(l)
	if err != nil || n != 1 || len(alerts) != 0 {
		t.Fatalf("A witnessing B: %d %v %v", n, alerts, err)
	}
	must(t, cmdLog([]string{"-ledger"}))
	a, err := hostSigner()
	must(t, err)
	summary, err := checkPublished(l, a.id(), 0, splitLines(mustRead(t, aLog)))
	must(t, err)
	if !strings.Contains(summary, "3 entries published") || !strings.Contains(summary, "co-signed by 1 other hosts") {
		t.Fatalf("unexpected summary: %s", summary)
	}

	// A rewrites its whole log, validly chained and signed with its own key.
	original := mustRead(t, aLog)
	must(t, os.Remove(aLog))
	must(t, os.Remove(filepath.Join(aData, "published")))
	os.Remove(filepath.Join(aData, "published.offset"))
	_, err = appendLog(logEntry{Event: "run", Capsule: "innocent"})
	must(t, err)
	must(t, cmdLog(nil)) // on its own the rewritten log still looks intact
	wantErr(t, cmdLog([]string{"-ledger"}), "rewritten after publication")

	// A truncates its log instead.
	lines := splitLines(original)
	must(t, os.WriteFile(aLog, append(lines[0], '\n'), 0o600))
	wantErr(t, cmdLog([]string{"-ledger"}), "entries have been removed")
	must(t, os.WriteFile(aLog, original, 0o600))
	must(t, cmdLog([]string{"-ledger"}))

	// Whoever controls the store deletes A's published entries: B, who saw them, notices.
	asB()
	shared := l.(dirLedger).root
	must(t, os.Remove(filepath.Join(shared, headKey(a.id(), 2))))
	_, alerts, err = witness(l)
	must(t, err)
	if len(alerts) != 1 || !strings.Contains(alerts[0], "entries have been removed") {
		t.Fatalf("deleted head not noticed: %v", alerts)
	}
	// Or replaces one with a different, validly signed statement.
	forged := head{Host: a.pub, Seq: 2, Head: digest([]byte("something else"))}
	forged.Signature = a.sign(forged.message())
	raw, _ := json.Marshal(forged)
	must(t, os.WriteFile(filepath.Join(shared, headKey(a.id(), 2)), raw, 0o644))
	_, alerts, err = witness(l)
	must(t, err)
	if len(alerts) != 1 || !strings.Contains(alerts[0], "has been rewritten") {
		t.Fatalf("replaced head not noticed: %v", alerts)
	}
}

func splitLines(raw []byte) [][]byte {
	var out [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		out = append(out, []byte(line))
	}
	return out
}

// A store that tells several racing writers they each created a key must not
// turn into several hosts each taking the same run slot.
func TestRunSlotsOnAStoreThatIsNotAtomic(t *testing.T) {
	racy := fakeS3Store(t, 30*time.Millisecond)
	told, confirmed, err := raceLedger(racy, 8, 3)
	must(t, err)
	for i := range told {
		if told[i] < 2 {
			t.Fatalf("the imitation store is meant to be racy, but told %d writers", told[i])
		}
	}
	_ = confirmed // without a pause the read-back may or may not be enough; the pause below is what makes it so
	racy.settle = 200 * time.Millisecond
	told, confirmed, err = raceLedger(racy, 8, 3)
	must(t, err)
	for i := range told {
		if told[i] < 2 || confirmed[i] != 1 {
			t.Fatalf("with a pause, %d writers were told they won and %d still believed it, want several and exactly 1", told[i], confirmed[i])
		}
	}

	newHost(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	dir := newCapsule(t, `{"name":"app","command":["/x"],"policy":{"max_runs":3,"fleet":true}}`)
	_, err = sealCapsule(dir, key, nil)
	must(t, err)
	sc, err := openCapsule(dir, trustSet{id: true})
	must(t, err)
	race := func(l ledger) int32 {
		var won atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if claimFleetRun(l, sc) == nil {
					won.Add(1)
				}
			}()
		}
		wg.Wait()
		return won.Load()
	}
	racy.settle = 200 * time.Millisecond
	if got := race(racy); got != 3 {
		t.Fatalf("%d hosts took 3 run slots on a racy store, with the read-back in place", got)
	}
	atomicStore := fakeS3(t)
	if got := race(atomicStore); got != 3 {
		t.Fatalf("%d hosts took 3 run slots on an atomic store", got)
	}

	// Artifactory with credentials that may overwrite: the last upload wins,
	// so the read-back is what keeps the count right.
	overwriting := fakeArtifactory(t, true)
	overwriting.settle = 200 * time.Millisecond
	told, confirmed, err = raceLedger(overwriting, 8, 3)
	must(t, err)
	for i := range told {
		if confirmed[i] != 1 {
			t.Fatalf("on Artifactory with overwrite allowed, %d of %d writers kept believing they had won", confirmed[i], told[i])
		}
	}
	if got := race(overwriting); got != 3 {
		t.Fatalf("%d hosts took 3 run slots on Artifactory with overwrite allowed", got)
	}
	// With overwrite refused, Artifactory itself lets only one upload through.
	told, _, err = raceLedger(fakeArtifactory(t, false), 8, 3)
	must(t, err)
	for i := range told {
		if told[i] != 1 {
			t.Fatalf("on Artifactory with overwrite refused, %d writers were told they had created the key", told[i])
		}
	}
}

func TestArtifactoryPutNeedsOverwrite(t *testing.T) {
	allowed := fakeArtifactory(t, true)
	must(t, allowed.put("load/app/host", []byte("one")))
	must(t, allowed.put("load/app/host", []byte("two")))
	if v, _, _ := allowed.get("load/app/host"); string(v) != "two" {
		t.Fatalf("put did not replace the value: %q", v)
	}
	refused := fakeArtifactory(t, false)
	must(t, refused.put("load/app/host", []byte("one")))
	if err := refused.put("load/app/host", []byte("two")); err == nil {
		t.Fatal("replacing a value succeeded although overwrite is refused")
	}
}
