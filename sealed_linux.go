package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// An encrypted capsule has to be decrypted somewhere before it can run.
// Doing that into memory on every start keeps the plaintext off the disk,
// but costs the capsule's full size in RAM for as long as it runs, and the
// work of decrypting each time. With root there is a better place: a small
// filesystem of its own, encrypted with a key derived from the host secret.
// The capsule is decrypted into it once; on disk there is only ciphertext;
// and later starts, and every replica, share the one copy.

// openSealedStore mounts the encrypted store for one sealed rootfs, creating
// it if needed, and returns the directory to import into and a function to
// call when this run is over. encSize is the size of the capsule's
// rootfs.enc, from which the store's capacity is chosen.
func openSealedStore(rootfsHash string, encSize int64) (string, func(), error) {
	home := filepath.Join(dataDir(), "sealed")
	return openSealedStoreAt(home, home, rootfsHash, encSize)
}

// openSealedStoreAt keeps the store's image in home and mounts it under mounts.
func openSealedStoreAt(home, mounts, rootfsHash string, encSize int64) (string, func(), error) {
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		return "", nil, errors.New("mkfs.ext4 (package e2fsprogs) is not installed")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", nil, err
	}
	name := strings.TrimPrefix(rootfsHash, "sha256:")
	image, mount := filepath.Join(home, name+".img"), filepath.Join(mounts, name)
	lock, err := os.OpenFile(filepath.Join(home, name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return "", nil, err
	}
	fail := func(err error) (string, func(), error) {
		lock.Close()
		return "", nil, err
	}
	// One run at a time sets the store up; every run then holds it shared.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fail(err)
	}
	if !isMountpoint(mount) {
		if _, err := os.Stat(image); os.IsNotExist(err) {
			f, err := os.OpenFile(image+".new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return fail(err)
			}
			err = f.Truncate(max(encSize*3+128<<20, 256<<20)) // sparse: it takes disk space only as it fills
			f.Close()
			if err != nil {
				return fail(err)
			}
			if out, err := exec.Command(mkfs, "-q", "-F", "-m", "0", "-O", "encrypt", image+".new").CombinedOutput(); err != nil {
				os.Remove(image + ".new")
				return fail(fmt.Errorf("mkfs.ext4: %v: %s", err, out))
			}
			if err := os.Rename(image+".new", image); err != nil {
				return fail(err)
			}
		}
		if err := os.MkdirAll(mount, 0o700); err != nil {
			return fail(err)
		}
		device, held, err := attachLoop(image)
		if err != nil {
			return fail(err)
		}
		for attempt := 0; ; attempt++ {
			err = unix.Mount(device, mount, "ext4", unix.MS_NOSUID|unix.MS_NODEV, "")
			if err == nil || attempt == 20 || !(errors.Is(err, unix.EIO) || errors.Is(err, unix.EBUSY)) {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		held.Close()
		if err != nil {
			return fail(fmt.Errorf("mounting the encrypted store: %w", err))
		}
		seed, err := hostDerive("capsule-sealed-store-v1\x00" + name)
		if err == nil {
			data := filepath.Join(mount, "data")
			fresh := os.Mkdir(data, 0o755) == nil
			err = encryptDirectory(mount, data, fresh, derive(seed, "capsule-sealed-store-key-v1", 64))
		}
		if err != nil {
			unix.Unmount(mount, unix.MNT_DETACH)
			return fail(fmt.Errorf("encrypting the store: %w", err))
		}
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return fail(err)
	}
	release := func() {
		// If no other run is using it, take the key away again by unmounting.
		if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			unix.Unmount(mount, unix.MNT_DETACH)
		}
		lock.Close()
	}
	return filepath.Join(mount, "data"), release, nil
}

func isMountpoint(dir string) bool {
	var here, parent unix.Stat_t
	return unix.Stat(dir, &here) == nil && unix.Stat(filepath.Dir(dir), &parent) == nil && here.Dev != parent.Dev
}

// pruneSealed removes encrypted stores no run is using. They are rebuilt
// from the capsule's rootfs.enc when next needed.
func pruneSealed() int {
	home := filepath.Join(dataDir(), "sealed")
	locks, _ := filepath.Glob(filepath.Join(home, "*.lock"))
	removed := 0
	for _, path := range locks {
		lock, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			continue
		}
		if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			base := strings.TrimSuffix(path, ".lock")
			unix.Unmount(base, unix.MNT_DETACH)
			os.Remove(base)
			os.Remove(base + ".img")
			os.Remove(path)
			removed++
		}
		lock.Close()
	}
	os.Remove(home) // only if empty
	return removed
}
