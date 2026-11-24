package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// logEntry is one line of the host's record. Each entry carries the hash of
// the line before it and the host's signature, so an entry cannot be changed,
// removed or reordered without breaking every entry after it.
type logEntry struct {
	Seq       int    `json:"seq"`
	Time      string `json:"time"`
	Event     string `json:"event"` // run, exit, refused
	Capsule   string `json:"capsule,omitempty"`
	Seal      string `json:"seal,omitempty"`
	Rootfs    string `json:"rootfs,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Exit      *int   `json:"exit,omitempty"`
	Output    string `json:"output,omitempty"` // sha256 of what the capsule wrote to stdout
	Prev      string `json:"prev"`
	Host      string `json:"host"`          // id of the host's signing key, as `capsule host` prints it
	Key       string `json:"key,omitempty"` // the full key: only on the first entry of a file, and when it changes
	Signature string `json:"signature,omitempty"`
}

func (e logEntry) signedBytes() []byte {
	e.Signature = ""
	b, _ := json.Marshal(e)
	return b
}

// verify checks the entry's signature with the given full key, which must be the one the entry names.
func (e logEntry) verify(key string) bool {
	return keyID(key) == e.Host && verifySig(key, e.Signature, e.signedBytes())
}

func logPath() string { return filepath.Join(dataDir(), "log.jsonl") }

// When the log reaches this size it is set aside under a numbered name and a
// new file continues the same chain.
func logLimit() int64 {
	if n, err := strconv.ParseInt(os.Getenv("CAPSULE_LOG_MAX"), 10, 64); err == nil && n > 0 {
		return n
	}
	return 64 << 20
}

// logArchives lists the files set aside by rotation, oldest first.
func logArchives() []string {
	files, _ := filepath.Glob(filepath.Join(dataDir(), "log-*.jsonl"))
	sort.Strings(files)
	return files
}

// appendLog adds a signed entry to the chain and returns it.
func appendLog(e logEntry) (logEntry, error) {
	key, err := hostSigner()
	if err != nil {
		return e, err
	}
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return e, err
	}
	lock, err := os.OpenFile(filepath.Join(dataDir(), "log.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return e, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return e, err
	}
	last, err := lastLogLine()
	if err != nil {
		return e, err
	}
	e.Prev, e.Host = digest(nil), key.id()
	carryKey := true // a file's first entry carries the full key, so the file can be checked by itself
	if last != nil {
		var prev logEntry
		if err := json.Unmarshal(last, &prev); err != nil {
			return e, errors.New("log is corrupt; refusing to extend it")
		}
		e.Seq, e.Prev = prev.Seq+1, digest(last)
		carryKey = prev.Host != e.Host
		if info, err := os.Stat(logPath()); err == nil && info.Size() >= logLimit() {
			// Set the full file aside. The chain carries straight on: the next
			// entry still names the hash of the last one in the file set aside.
			if err := os.Rename(logPath(), filepath.Join(dataDir(), fmt.Sprintf("log-%012d.jsonl", prev.Seq))); err != nil {
				return e, err
			}
			os.Remove(filepath.Join(dataDir(), "published.offset"))
			carryKey = true
		}
	}
	if carryKey {
		e.Key = key.pub
	}
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Signature = key.sign(e.signedBytes())
	line, _ := json.Marshal(e)
	// Send it off the host before keeping it: a copy this host cannot reach
	// is what turns a rewritten log from undetectable into provable.
	if err := forwardLog(line); err != nil {
		return e, err
	}
	f, err := os.OpenFile(logPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return e, err
	}
	defer f.Close()
	if _, err = f.Write(append(line, '\n')); err == nil {
		err = f.Sync() // the record of a run must not be lost to a power cut after the run has started
	}
	if err == nil {
		// Publish what the log now looks like. This is best effort here: an
		// entry missed during an outage is published by the next one.
		if l, lerr := openLedger(); lerr == nil && l != nil {
			if perr := publishHeads(l); perr != nil {
				fmt.Fprintln(os.Stderr, "capsule: could not publish to the ledger:", perr)
			}
		}
	}
	return e, err
}

// forwardLog posts an entry to the collector named in <config>/log-forward, if there is one.
func forwardLog(line []byte) error {
	raw, err := os.ReadFile(filepath.Join(configDir(), "log-forward"))
	if err != nil {
		return nil
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(strings.TrimSpace(string(raw)), "application/json", bytes.NewReader(append(line, '\n')))
	if err != nil {
		return fmt.Errorf("log collector: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("log collector answered %s", resp.Status)
	}
	return nil
}

// lastLogLine returns the log's final entry, or nil if there is none. It
// reads only the end of the file, so appending stays cheap however long the
// log grows.
func lastLogLine() ([]byte, error) {
	f, err := os.Open(logPath())
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	for window := int64(64 << 10); ; window *= 4 {
		start := max(info.Size()-window, 0)
		buf := make([]byte, info.Size()-start)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return nil, err
		}
		buf = bytes.TrimRight(buf, "\n")
		if len(buf) == 0 {
			return nil, nil
		}
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 || start == 0 {
			return buf[i+1:], nil
		}
		// the last entry is longer than the window: look further back
	}
}

// lastLogTime is when this host last recorded anything, or zero.
func lastLogTime() time.Time {
	last, _ := lastLogLine()
	var e logEntry
	json.Unmarshal(last, &e)
	t, _ := time.Parse(time.RFC3339, e.Time)
	return t
}

// cmdLog prints the record and checks the whole chain.
func cmdLog(args []string) error {
	fl := flag.NewFlagSet("log", flag.ExitOnError)
	host := fl.String("host", "", "require every entry to be signed by the host signing key with this id")
	file := fl.String("file", "", "check this copy of a log, for example one kept by a collector")
	hostFile := fl.String("hostfile", "", "a host file (capsule host -export), for a copy that does not begin with the host's key")
	all := fl.Bool("all", false, "also go through the files set aside by rotation, oldest first")
	published := fl.Bool("ledger", false, "also check the log against what its host published to the fleet ledger")
	fl.Parse(args)
	files := []string{*file}
	if *file == "" {
		files = []string{logPath()}
		if *all {
			files = append(logArchives(), logPath())
		}
	}
	keys := map[string]string{} // signing key id -> full key, as entries or the host file supply them
	if *hostFile != "" {
		raw, err := os.ReadFile(*hostFile)
		var card hostCard
		if err != nil || json.Unmarshal(raw, &card) != nil || keyID(card.SignKey) == "" {
			return errors.New("-hostfile is not a host file from `capsule host -export`")
		}
		keys[keyID(card.SignKey)] = card.SignKey
	}
	prev, next, count := "", -1, 0 // what the next entry must follow, once the first has been read
	base := 0
	var lines [][]byte
	signers := map[string]bool{}
	for _, name := range files {
		f, err := os.Open(name)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 4<<20)
		for sc.Scan() {
			var e logEntry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				f.Close()
				return fmt.Errorf("entry after %d is not valid: log has been altered", next-1)
			}
			if next < 0 { // the first entry read says where this copy starts
				next, prev, base = e.Seq, e.Prev, e.Seq
				if e.Seq == 0 && e.Prev != digest(nil) {
					f.Close()
					return errors.New("entry 0 does not start a chain: log has been altered")
				}
			}
			if e.Key != "" && keyID(e.Key) == e.Host {
				keys[e.Host] = e.Key
			}
			key, known := keys[e.Host]
			switch {
			case e.Seq != next || e.Prev != prev:
				f.Close()
				return fmt.Errorf("entry %d does not follow the one before it: log has been altered", next)
			case !known:
				f.Close()
				return fmt.Errorf("entry %d names a signing key this copy does not contain; pass -hostfile", next)
			case !e.verify(key):
				f.Close()
				return fmt.Errorf("entry %d has a bad signature: log has been altered", next)
			case *host != "" && e.Host != *host:
				f.Close()
				return fmt.Errorf("entry %d is signed by a different host", next)
			}
			prev, next = digest(sc.Bytes()), next+1
			count++
			lines = append(lines, bytes.Clone(sc.Bytes()))
			signers[e.Host] = true
			detail := e.Detail
			if e.Exit != nil {
				detail = fmt.Sprintf("%s status=%d", detail, *e.Exit)
			}
			fmt.Printf("%4d  %s  %-8s %-16s %s\n", e.Seq, e.Time, e.Event, e.Capsule, detail)
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return err
		}
	}
	if count == 0 {
		fmt.Println("log is empty")
		return nil
	}
	// Whoever holds the host secret can rewrite the whole log. A copy or this
	// head value kept somewhere else is what makes a rewrite detectable.
	fmt.Printf("%d entries, chain intact, head %s\n", count, prev)
	if base > 0 {
		fmt.Printf("this copy starts at entry %d; earlier entries are in files set aside by rotation (capsule log -all)\n", base)
	}
	if !*published {
		return nil
	}
	l, err := openLedger()
	if err != nil {
		return err
	}
	if l == nil {
		return errors.New("this host has no ledger configured (see <config>/ledger)")
	}
	for host := range signers {
		summary, err := checkPublished(l, host, base, lines)
		if err != nil {
			return err
		}
		fmt.Println(summary)
	}
	return nil
}

// receipt is a run's closing log entry together with the key that signed it,
// so that it can be checked by someone who has nothing else from this host.
type receipt struct {
	Entry logEntry `json:"entry"`
	Key   string   `json:"key"`
}

// cmdReceipt checks a run receipt: proof of which sealed capsule ran, on
// which host, and what it produced.
func cmdReceipt(args []string) error {
	fl := flag.NewFlagSet("receipt", flag.ExitOnError)
	host := fl.String("host", "", "the id of the host signing key the receipt must come from")
	fl.Parse(args)
	if fl.NArg() != 1 || *host == "" {
		return errors.New("usage: capsule receipt -host <signing key id> <file>")
	}
	raw, err := os.ReadFile(fl.Arg(0))
	if err != nil {
		return err
	}
	var r receipt
	e := &r.Entry
	if err := json.Unmarshal(raw, &r); err != nil || e.Event != "exit" || e.Exit == nil {
		return errors.New("not a run receipt")
	}
	if e.Host != *host || !e.verify(r.Key) {
		return errors.New("receipt was not signed by that host")
	}
	fmt.Printf("capsule  %s\nseal     %s\nrootfs   %s\nfinished %s\nstatus   %d\noutput   %s\n", e.Capsule, e.Seal, e.Rootfs, e.Time, *e.Exit, e.Output)
	return nil
}
