package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A volume with a size is its own small ext4 filesystem in a file. That
// gives it a hard size limit, lets it be encrypted with the filesystem's own
// encryption, and lets it be frozen for a consistent snapshot. It needs root:
// attaching a file as a disk is not something an ordinary user may do.

const (
	loFlagsAutoclear = 4          // detach the loop device when its last user goes away
	fiFreeze         = 0xc0045877 // FIFREEZE
	fiThaw           = 0xc0045878 // FITHAW
)

// openImageVolume makes sure the volume's filesystem exists, mounts it at
// dir, and returns the directory inside it to give the capsule, plus a
// function that unmounts it. If encrypt is set, everything the capsule
// writes there is encrypted with a key derived from the host secret.
func openImageVolume(image, dir, size string, encrypt bool) (string, func(), error) {
	want, err := parseSizeText(size)
	if err != nil {
		return "", nil, err
	}
	if _, err := os.Stat(image); os.IsNotExist(err) {
		mkfs, err := exec.LookPath("mkfs.ext4")
		if err != nil {
			return "", nil, errors.New("a volume with a size needs mkfs.ext4 (package e2fsprogs) on this host")
		}
		f, err := os.OpenFile(image+".new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return "", nil, err
		}
		err = f.Truncate(want) // sparse: it takes disk space only as it fills
		f.Close()
		if err != nil {
			return "", nil, err
		}
		args := []string{"-q", "-F", "-m", "0"}
		if encrypt {
			args = append(args, "-O", "encrypt")
		}
		if out, err := exec.Command(mkfs, append(args, image+".new")...).CombinedOutput(); err != nil {
			os.Remove(image + ".new")
			return "", nil, fmt.Errorf("mkfs.ext4: %v: %s", err, out)
		}
		if encrypt {
			if err := newVolumeKey(image + ".keys"); err != nil {
				os.Remove(image + ".new")
				return "", nil, err
			}
		}
		if err := os.Rename(image+".new", image); err != nil {
			return "", nil, err
		}
	} else if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	unix.Unmount(dir, unix.MNT_DETACH) // left mounted by a supervisor that was killed; we hold this volume's lock

	device, held, err := attachLoop(image)
	if err != nil {
		return "", nil, err
	}
	// The device detaches itself when its last user lets go. Until the
	// mount is holding it, that user is this open handle.
	defer held.Close()
	// On a busy or slow host the new device can briefly refuse reads while
	// the system finishes examining it; give it a few moments.
	for attempt := 0; ; attempt++ {
		err = unix.Mount(device, dir, "ext4", unix.MS_NOSUID|unix.MS_NODEV, "")
		if err == nil || attempt == 20 || !(errors.Is(err, unix.EIO) || errors.Is(err, unix.EBUSY)) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return "", nil, fmt.Errorf("mounting volume %s: %w", filepath.Base(dir), err)
	}
	closeVolume := func() { unix.Unmount(dir, unix.MNT_DETACH) }
	data := filepath.Join(dir, "data")
	fresh := false
	if err := os.Mkdir(data, 0o755); err == nil {
		fresh = true
	} else if !os.IsExist(err) {
		closeVolume()
		return "", nil, err
	}
	if encrypt {
		raw, err := volumeKey(image + ".keys")
		if err == nil {
			err = encryptDirectory(dir, data, fresh, raw)
		}
		if err != nil {
			closeVolume()
			return "", nil, fmt.Errorf("encrypting volume %s: %w", filepath.Base(dir), err)
		}
	}
	return data, closeVolume, nil
}

// attachLoop presents a file as a block device. It returns the device's
// path and an open handle to it, which the caller must keep until something
// else (a mount) is using the device.
func attachLoop(image string) (string, *os.File, error) {
	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", nil, fmt.Errorf("loop devices are not available: %w", err)
	}
	defer control.Close()
	file, err := os.OpenFile(image, os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	for attempt := 0; attempt < 20; attempt++ {
		n, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return "", nil, err
		}
		path := fmt.Sprintf("/dev/loop%d", n)
		device, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return "", nil, err
		}
		// One call that attaches the file and sets its options together, so
		// the device is never visible half set up.
		err = unix.IoctlLoopConfigure(int(device.Fd()), &unix.LoopConfig{Fd: uint32(file.Fd()), Info: unix.LoopInfo64{Flags: loFlagsAutoclear}})
		if err == nil {
			return path, device, nil
		}
		device.Close()
		if !errors.Is(err, unix.EBUSY) { // EBUSY: another process took that device first; ask again
			return "", nil, err
		}
	}
	return "", nil, errors.New("no free loop device")
}

// A volume's key is random and kept beside the volume, wrapped for each host
// allowed to open it: this one, any recovery hosts named in
// <config>/recovery.d when the volume was made, and any granted later. The
// wrap is the same hybrid one used for encrypted capsules. So losing a host
// does not lose the data, as long as one host that holds the key remains.

func newVolumeKey(path string) error {
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	self, err := hostBoxKey()
	if err != nil {
		return err
	}
	hosts := [][]byte{self.public()}
	files, _ := filepath.Glob(filepath.Join(configDir(), "recovery.d", "*.host"))
	others, err := loadHostKeys(files)
	if err != nil {
		return err
	}
	for _, pub := range others {
		hosts = append(hosts, pub)
	}
	var recipients []recipient
	for _, pub := range hosts {
		r, err := wrapKey(raw, pub)
		if err != nil {
			return err
		}
		recipients = append(recipients, r)
	}
	out, _ := json.MarshalIndent(recipients, "", "  ")
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// volumeKey unwraps the volume's key for this host.
func volumeKey(path string) ([]byte, error) {
	var recipients []recipient
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &recipients) != nil {
		return nil, errors.New("the volume's key file is missing or unreadable")
	}
	self, err := hostBoxKey()
	if err != nil {
		return nil, err
	}
	for _, r := range recipients {
		if r.Host == self.id() {
			return unwrapKey(r, self)
		}
	}
	return nil, errors.New("this host holds no key for it; grant one from a host that does, with capsule volumes -grant")
}

// grantVolumes lets another host open every encrypted volume of a capsule.
func grantVolumes(unit, hostFile string) (int, error) {
	hosts, err := loadHostKeys([]string{hostFile})
	if err != nil {
		return 0, err
	}
	files, _ := filepath.Glob(filepath.Join(dataDir(), "volumes", unit, "*.img.keys"))
	granted := 0
	for _, file := range files {
		key, err := volumeKey(file)
		if err != nil {
			return granted, fmt.Errorf("%s: %w", filepath.Base(file), err)
		}
		var recipients []recipient
		raw, _ := os.ReadFile(file)
		json.Unmarshal(raw, &recipients)
		for id, pub := range hosts {
			if slices.ContainsFunc(recipients, func(r recipient) bool { return r.Host == id }) {
				continue
			}
			r, err := wrapKey(key, pub)
			if err != nil {
				return granted, err
			}
			recipients = append(recipients, r)
		}
		out, _ := json.MarshalIndent(recipients, "", "  ")
		if err := os.WriteFile(file, append(out, '\n'), 0o600); err != nil {
			return granted, err
		}
		granted++
	}
	return granted, nil
}

// encryptDirectory turns on ext4's own encryption for data. The key is
// handed to the mounted filesystem and is gone when it is unmounted; on disk
// there is only ciphertext.
func encryptDirectory(mount, data string, fresh bool, raw []byte) error {
	root, err := os.Open(mount)
	if err != nil {
		return err
	}
	defer root.Close()
	// struct fscrypt_add_key_arg, immediately followed by the raw key
	buf := make([]byte, int(unsafe.Sizeof(unix.FscryptAddKeyArg{}))+len(raw))
	arg := (*unix.FscryptAddKeyArg)(unsafe.Pointer(&buf[0]))
	arg.Key_spec.Type = unix.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER
	arg.Raw_size = uint32(len(raw))
	copy(buf[unsafe.Sizeof(*arg):], raw)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, root.Fd(), unix.FS_IOC_ADD_ENCRYPTION_KEY, uintptr(unsafe.Pointer(arg))); errno != 0 {
		return fmt.Errorf("adding the key (does this kernel have filesystem encryption?): %w", errno)
	}
	if !fresh {
		return nil // the directory already carries its policy; with the key added it is readable
	}
	policy := unix.FscryptPolicyV2{Version: 2, Contents_encryption_mode: unix.FSCRYPT_MODE_AES_256_XTS,
		Filenames_encryption_mode: unix.FSCRYPT_MODE_AES_256_CTS, Flags: unix.FSCRYPT_POLICY_FLAGS_PAD_32}
	copy(policy.Master_key_identifier[:], arg.Key_spec.U[:16]) // the kernel filled in the key's identifier
	dir, err := os.Open(data)
	if err != nil {
		return err
	}
	defer dir.Close()
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(), unix.FS_IOC_SET_ENCRYPTION_POLICY, uintptr(unsafe.Pointer(&policy))); errno != 0 {
		return fmt.Errorf("setting the policy: %w", errno)
	}
	return nil
}

// copySparse copies a file without filling in its holes, so a mostly empty
// volume image stays small on disk.
func copySparse(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := out.Truncate(info.Size()); err != nil {
		return err
	}
	for offset := int64(0); offset < info.Size(); {
		data, err := unix.Seek(int(in.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) { // nothing but a hole from here to the end
			break
		} else if err != nil {
			return err
		}
		hole, err := unix.Seek(int(in.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if _, err := in.Seek(data, io.SeekStart); err != nil {
			return err
		}
		if _, err := out.Seek(data, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(out, in, hole-data); err != nil {
			return err
		}
		offset = hole
	}
	return out.Sync()
}

// snapshotVolumes copies a capsule's volume data to a dated directory. A
// sized volume that is in use is frozen for the moment of the copy, so the
// snapshot is consistent even while the capsule runs; a plain directory
// volume can only be copied while the capsule is stopped.
func snapshotVolumes(unit string, running bool) (string, error) {
	home := filepath.Join(dataDir(), "volumes", unit)
	entries, err := os.ReadDir(home)
	if err != nil {
		return "", fmt.Errorf("no volume data for %s", unit)
	}
	dest := filepath.Join(dataDir(), "snapshots", unit, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	images := map[string]bool{}
	for _, e := range entries {
		if name, ok := trimSuffix(e.Name(), ".img"); ok {
			images[name] = true
		}
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case filepath.Ext(name) == ".img":
			volume := filepath.Join(home, name[:len(name)-len(".img")])
			// Freeze it only if it is mounted now: a capsule's earlier
			// versions may have left volumes its current one does not use.
			var here, parent unix.Stat_t
			mounted := unix.Stat(volume, &here) == nil && unix.Stat(home, &parent) == nil && here.Dev != parent.Dev
			if running && mounted {
				dir, err := os.Open(volume)
				if err != nil {
					return "", err
				}
				if err := unix.IoctlSetInt(int(dir.Fd()), fiFreeze, 0); err != nil {
					dir.Close()
					return "", fmt.Errorf("freezing volume %s: %w", filepath.Base(volume), err)
				}
				err = copySparse(filepath.Join(home, name), filepath.Join(dest, name))
				unix.IoctlSetInt(int(dir.Fd()), fiThaw, 0)
				dir.Close()
				if err != nil {
					return "", err
				}
			} else if err := copySparse(filepath.Join(home, name), filepath.Join(dest, name)); err != nil {
				return "", err
			}
		case filepath.Ext(name) == ".keys":
			data, err := os.ReadFile(filepath.Join(home, name))
			if err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(dest, name), data, 0o600); err != nil {
				return "", err
			}
		case e.IsDir() && !images[name]:
			if running {
				return "", fmt.Errorf("%s is running and its volume %s is a plain directory; stop it first, or give the volume a size so it can be frozen", unit, name)
			}
			if err := copyTree(filepath.Join(home, name), filepath.Join(dest, name)); err != nil {
				return "", err
			}
		}
	}
	syncDir(dest)
	return dest, nil
}

func trimSuffix(s, suffix string) (string, bool) {
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// restoreVolumes replaces a stopped capsule's volume data with a snapshot.
func restoreVolumes(unit, snapshot string) error {
	source := filepath.Join(dataDir(), "snapshots", unit, snapshot)
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("no snapshot %s of %s", snapshot, unit)
	}
	home := filepath.Join(dataDir(), "volumes", unit)
	for _, e := range entries {
		target := filepath.Join(home, e.Name())
		if e.IsDir() {
			removeTree(target)
			if err := copyTree(filepath.Join(source, e.Name()), target); err != nil {
				return err
			}
			continue
		}
		os.Remove(target)
		if err := copySparse(filepath.Join(source, e.Name()), target); err != nil {
			return err
		}
	}
	return nil
}
