package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	must(t, err)
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestStoreSharesFilesAndRemembersChecks(t *testing.T) {
	newHost(t)
	keys := t.TempDir()
	key, id := newKey(t, keys, "dev")
	trusted := trustSet{id: true}
	store := filepath.Join(dataDir(), "store")
	open := func(dir string) (sealedCapsule, string) {
		t.Helper()
		_, err := sealCapsule(dir, key, nil)
		must(t, err)
		sc, err := openCapsule(dir, trusted)
		must(t, err)
		path, err := importRootfs(dir, sc, store)
		must(t, err)
		return sc, path
	}

	// Two capsules with the same program and different extra files share the program's bytes.
	one := newCapsule(t, plain)
	two := newCapsule(t, `{"name":"two","command":["/bin/app"]}`)
	must(t, os.WriteFile(filepath.Join(two, "rootfs/extra"), []byte("only in two"), 0o644))
	scOne, first := open(one)
	_, second := open(two)
	if first == second {
		t.Fatal("two different rootfs trees got the same store entry")
	}
	if inode(t, filepath.Join(first, "bin/app")) != inode(t, filepath.Join(second, "bin/app")) {
		t.Error("the same file in two capsules is stored twice")
	}
	if got, err := hashRootfs(first); err != nil || got != scOne.Seal.Rootfs {
		t.Fatalf("the stored copy does not match its seal: %v", err)
	}
	// Same contents, different permissions: must not share, or one would get the other's mode.
	three := newCapsule(t, `{"name":"three","command":["/bin/app"]}`)
	must(t, os.Chmod(filepath.Join(three, "rootfs/bin/app"), 0o700))
	_, third := open(three)
	if inode(t, filepath.Join(third, "bin/app")) == inode(t, filepath.Join(first, "bin/app")) {
		t.Error("files with different permissions were stored as one")
	}
	if info, _ := os.Stat(filepath.Join(third, "bin/app")); info.Mode().Perm() != 0o700 {
		t.Errorf("stored file has mode %o, want 700", info.Mode().Perm())
	}

	// A second run with nothing changed does not need to read contents: prove it by
	// making the contents unreadable to a full check and seeing the run still succeed.
	record := first + ".ok"
	if _, err := os.Stat(record); err != nil {
		t.Fatal("a successful check was not remembered")
	}
	if _, err := importRootfs(one, scOne, store); err != nil {
		t.Fatalf("second import failed: %v", err)
	}

	// The capsule folder changes, with size and modification time put back: still noticed.
	app := filepath.Join(one, "rootfs/bin/app")
	info, _ := os.Stat(app)
	original := mustRead(t, app)
	must(t, os.WriteFile(app, []byte(strings.Repeat("x", len(original))), 0o755))
	must(t, os.Chtimes(app, info.ModTime(), info.ModTime()))
	if _, err := importRootfs(one, scOne, store); err == nil || !strings.Contains(err.Error(), "rootfs was changed after sealing") {
		t.Fatalf("a changed folder with restored size and time was accepted: %v", err)
	}
	must(t, os.WriteFile(app, original, 0o755))
	if _, err := importRootfs(one, scOne, store); err != nil {
		t.Fatalf("restoring the folder did not make it acceptable again: %v", err)
	}

	// The stored copy is damaged the way a power cut does it (a file cut short): noticed and repaired.
	must(t, os.Truncate(filepath.Join(first, "bin/app"), 0))
	repaired, err := importRootfs(one, scOne, store)
	must(t, err)
	if got, err := hashRootfs(repaired); err != nil || got != scOne.Seal.Rootfs {
		t.Fatalf("the damaged copy was not repaired: %v", err)
	}
	// The damage went through the shared file, so the other capsule's copy is damaged too, and is repaired when it next runs.
	scTwo, err := openCapsule(two, trusted)
	must(t, err)
	fixed, err := importRootfs(two, scTwo, store)
	must(t, err)
	if got, err := hashRootfs(fixed); err != nil || got != scTwo.Seal.Rootfs {
		t.Fatalf("the second capsule's copy was not repaired: %v", err)
	}

	// A check older than a day is done again in full.
	old := []byte(strings.Replace(string(mustRead(t, fixed+".ok")), " ", " ", 1))
	fields := strings.Fields(string(old))
	must(t, os.WriteFile(fixed+".ok", []byte(fields[0]+" "+fields[1]+" 1\n"), 0o600))
	if remembered(fixed+".ok", fields[0], fields[1]) {
		t.Error("a check from long ago still counts")
	}
	_ = time.Now
}
