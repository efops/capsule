package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// lockStore takes the store-wide lock. Runs hold it shared while they import
// and register themselves; prune holds it exclusively.
func lockStore(store string, how int) (*os.File, error) {
	if err := os.MkdirAll(store, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(store, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Checking a rootfs against its seal means reading all of it, which for a
// language runtime is hundreds of megabytes. So a check that passed is
// remembered, together with a fingerprint of the tree taken from file
// metadata alone: every path, type, size, modification time and inode. As
// long as that fingerprint is unchanged the contents are not read again,
// except once a day, to catch a disk quietly going bad.
const recheckAfter = 24 * time.Hour

// fingerprint summarises a tree without reading any file's contents. With
// changeTime it also covers each inode's change time, which the system sets
// on any modification and which cannot be put back.
func fingerprint(root string, changeTime bool) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("no file metadata")
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%q %o %d %d.%d %d", rel, uint32(info.Mode()), info.Size(), st.Mtim.Sec, st.Mtim.Nsec, st.Ino)
		if changeTime {
			fmt.Fprintf(h, " %d.%d", st.Ctim.Sec, st.Ctim.Nsec)
		}
		h.Write([]byte{'\n'})
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}

// remembered reports whether file records this fingerprint for this subject, recently enough.
func remembered(file, subject, print string) bool {
	raw, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != subject || fields[1] != print {
		return false
	}
	at, err := strconv.ParseInt(fields[2], 10, 64)
	return err == nil && time.Since(time.Unix(at, 0)) < recheckAfter
}

func remember(file, subject, print string) {
	if os.MkdirAll(filepath.Dir(file), 0o700) != nil {
		return
	}
	tmp := file + ".new"
	if os.WriteFile(tmp, []byte(fmt.Sprintf("%s %s %d\n", subject, print, time.Now().Unix())), 0o600) == nil {
		os.Rename(tmp, file)
	}
}

// sourceRecord is where the last successful check of a capsule folder's rootfs is remembered.
func sourceRecord(src string) string {
	abs, _ := filepath.Abs(src)
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(dataDir(), "checked", hex.EncodeToString(sum[:]))
}

// importRootfs puts a capsule's rootfs into the host's private store and
// verifies the stored copy, so the bytes that were hashed are the bytes that
// run: nothing that can write to the capsule directory can change them
// afterwards. Entries are named by hash and only ever created here.
func importRootfs(dir string, sc sealedCapsule, store string) (string, error) {
	want := sc.Seal.Rootfs
	src := filepath.Join(dir, "rootfs")
	dst := filepath.Join(store, strings.Replace(want, ":", "-", 1))
	// The folder's fingerprint is taken before its contents are read, so a
	// change made while we read cannot be mistaken for the state we checked.
	srcPrint := ""
	if !sc.Seal.Encrypted {
		var err error
		if srcPrint, err = fingerprint(src, true); err != nil {
			return "", err
		}
	}
	if _, err := os.Stat(dst); err == nil {
		// The stored copy is what actually executes, so it is checked on
		// every run: by fingerprint, and by contents when that has changed
		// or the last full check is a day old.
		print, err := fingerprint(dst, false)
		sound := err == nil && remembered(dst+".ok", want, print)
		if !sound && err == nil {
			if stored, err := hashRootfs(dst); err == nil && stored == want {
				remember(dst+".ok", want, print)
				sound = true
			}
		}
		if sound {
			if sc.Seal.Encrypted {
				return dst, nil
			}
			// Also refuse a folder that no longer matches its seal, rather
			// than quietly running the older content that was sealed.
			if !remembered(sourceRecord(src), sc.ID, srcPrint) {
				got, err := hashRootfs(src)
				if err != nil {
					return "", err
				}
				if got != want {
					return "", errors.New("rootfs was changed after sealing")
				}
				remember(sourceRecord(src), sc.ID, srcPrint)
			}
			return dst, nil
		}
		fmt.Fprintln(os.Stderr, "capsule: stored rootfs copy is damaged; importing it again")
		removeTree(dst)
		os.Remove(dst + ".ok")
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		return "", err
	}
	// Files go through a pool where each distinct file is kept once, so
	// capsules that share a runtime, and successive versions of one capsule,
	// share its bytes on disk and in memory. If a pooled file turns out to be
	// bad, the import is done again with plain copies.
	for _, pooled := range []bool{!sc.Seal.Encrypted, false} {
		tmp, err := os.MkdirTemp(store, "import-")
		if err != nil {
			return "", err
		}
		defer removeTree(tmp)
		root := filepath.Join(tmp, "rootfs")
		switch {
		case sc.Seal.Encrypted:
			err = decryptRootfs(filepath.Join(dir, "rootfs.enc"), sc, root)
		case pooled:
			err = copyTreeVia(src, root, filepath.Join(store, "blobs"))
		default:
			err = copyTree(src, root)
		}
		if err != nil {
			return "", err
		}
		got, err := hashRootfs(root)
		if err != nil {
			return "", err
		}
		if got != want {
			if pooled {
				continue
			}
			return "", errors.New("rootfs was changed after sealing")
		}
		// Flush the copy to disk before it gets its final name, so a power cut
		// can never leave an entry that exists but is incomplete.
		if dir, err := os.Open(tmp); err == nil {
			err = unix.Syncfs(int(dir.Fd()))
			dir.Close()
			if err != nil {
				return "", err
			}
		}
		defer syncDir(store)
		if err := os.Rename(root, dst); err != nil {
			if _, statErr := os.Stat(dst); statErr == nil { // another run imported it first
				return dst, nil
			}
			return "", err
		}
		if print, err := fingerprint(dst, false); err == nil {
			remember(dst+".ok", want, print)
		}
		if !sc.Seal.Encrypted {
			remember(sourceRecord(src), sc.ID, srcPrint)
		}
		return dst, nil
	}
	return "", errors.New("rootfs was changed after sealing")
}

// copyTreeVia copies a tree like copyTree, but each regular file is stored
// once in the pool, named by its contents and mode, and hard-linked into the
// tree. The store is never written to after import, so sharing is safe.
func copyTreeVia(src, dst, pool string) error {
	type dirMode struct {
		path string
		mode fs.FileMode
	}
	var dirs []dirMode
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		mode := info.Mode()
		switch {
		case mode.IsDir():
			dirs = append(dirs, dirMode{target, mode & permBits})
			return os.Mkdir(target, 0o700)
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case mode.IsRegular():
			return poolFile(p, mode&permBits, pool, target)
		default:
			return fmt.Errorf("%s: devices, sockets and fifos are not allowed in a rootfs", rel)
		}
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i].path, dirs[i].mode); err != nil {
			return err
		}
	}
	return nil
}

// poolFile makes target a hard link to the pool's copy of src, adding it to the pool if it is new.
func poolFile(src string, mode fs.FileMode, pool, target string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	h := sha256.New()
	size, err := io.Copy(h, in)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%x-%o", h.Sum(nil), uint32(mode))
	blob := filepath.Join(pool, name[:2], name)
	if st, err := os.Stat(blob); err != nil || st.Size() != size {
		if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(blob), ".new-")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			return err
		}
		_, err = io.Copy(tmp, in)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Chmod(tmp.Name(), mode)
		}
		if err == nil {
			err = os.Rename(tmp.Name(), blob)
		}
		if err != nil {
			return err
		}
	}
	if err := os.Link(blob, target); err != nil {
		// A file system limits how many names one file may have. Past that, this tree gets its own copy.
		data, rerr := os.ReadFile(blob)
		if rerr != nil {
			return err
		}
		if werr := os.WriteFile(target, data, 0o600); werr != nil {
			return werr
		}
		return os.Chmod(target, mode)
	}
	return nil
}

// decryptRootfs unpacks rootfs.enc. The key is in up to two parts and every
// part present is required: one wrapped for this host, one locked until a time.
func decryptRootfs(path string, sc sealedCapsule, dst string) error {
	seal := sc.Seal
	var hostPart, timePart []byte
	if len(seal.Recipients) > 0 {
		host, err := hostBoxKey()
		if err != nil {
			return err
		}
		id := host.id()
		for _, r := range seal.Recipients {
			if r.Host == id {
				if hostPart, err = unwrapKey(r, host); err != nil {
					return errors.New("this host's key does not open the capsule")
				}
			}
		}
		if hostPart == nil {
			return errors.New("capsule is encrypted and this host is not one of its recipients")
		}
	}
	if seal.Timelock != nil {
		var err error
		if timePart, err = unlockKey(seal.Timelock, sc.ID); errors.Is(err, errTooEarly) {
			return fmt.Errorf("time-locked: the drand network has not yet published round %d", seal.Timelock.Round)
		} else if err != nil {
			return err
		}
	}
	if hostPart == nil && timePart == nil {
		return errors.New("capsule.seal is malformed")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return decryptTree(f, contentKey(hostPart, timePart), dst)
}

// cmdPrune deletes stored rootfs copies that no running capsule uses.
func cmdPrune(args []string) error {
	store, _ := hostPaths()
	lock, err := lockStore(store, syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer lock.Close()
	inUse := map[string]bool{}
	for _, r := range running() {
		inUse[r.rootfs] = true
	}
	entries, _ := os.ReadDir(store)
	removed := 0
	for _, e := range entries {
		path := filepath.Join(store, e.Name())
		if !e.IsDir() || e.Name() == "blobs" || inUse[path] {
			continue
		}
		removeTree(path) // unused rootfs, or what an interrupted import left behind
		os.Remove(path + ".ok")
		removed++
	}
	// Pooled files that no remaining rootfs links to.
	filepath.WalkDir(filepath.Join(store, "blobs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink == 1 {
				os.Remove(p)
			}
		}
		return nil
	})
	if dirs, err := os.ReadDir(filepath.Join(store, "blobs")); err == nil {
		for _, d := range dirs {
			os.Remove(filepath.Join(store, "blobs", d.Name())) // only succeeds once it is empty
		}
		os.Remove(filepath.Join(store, "blobs"))
	}
	if os.Geteuid() == 0 && realRoot() {
		removed += pruneSealed()
	}
	fmt.Printf("removed %d, kept %d in use\n", removed, len(inUse))
	return nil
}
