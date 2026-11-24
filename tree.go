package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// copyTree copies directories, regular files and symlinks, never following a
// link. Files end up owned by whoever runs the import.
func copyTree(src, dst string) error {
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
			return os.Mkdir(target, 0o700) // real mode is set last, so read-only directories can be filled
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case mode.IsRegular():
			in, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			return os.Chmod(target, mode&permBits)
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

// removeTree deletes a tree that may contain read-only directories.
func removeTree(path string) {
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	os.RemoveAll(path)
}

// unpackTar writes an archive into dst, which must not exist. os.Root keeps
// every path inside dst even if the archive is hostile. Ownership is dropped.
// In strict mode anything but files, directories and symlinks is an error;
// otherwise hard links are kept and device nodes and fifos are skipped and
// counted, since a capsule gets its own /dev.
func unpackTar(tr *tar.Reader, dst string, strict bool) (skipped int, err error) {
	if err := os.Mkdir(dst, 0o755); err != nil {
		return 0, err
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return 0, err
	}
	defer root.Close()

	dirs := map[string]fs.FileMode{}
	var order []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return skipped, err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if !filepath.IsLocal(name) {
			return skipped, fmt.Errorf("archive path %q escapes the rootfs", hdr.Name)
		}
		mode := hdr.FileInfo().Mode() & permBits
		if hdr.Typeflag != tar.TypeDir {
			if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return skipped, err
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return skipped, err
			}
			if _, seen := dirs[name]; !seen {
				order = append(order, name)
			}
			dirs[name] = mode // applied last, so read-only directories can be filled
		case tar.TypeSymlink:
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return skipped, err
			}
		case tar.TypeReg:
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return skipped, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return skipped, err
			}
			if err := f.Close(); err != nil {
				return skipped, err
			}
			if err := root.Chmod(name, mode); err != nil {
				return skipped, err
			}
		case tar.TypeLink:
			if strict {
				return skipped, fmt.Errorf("archive entry %s has an unsupported type", hdr.Name)
			}
			if err := root.Link(filepath.Clean(filepath.FromSlash(hdr.Linkname)), name); err != nil {
				return skipped, err
			}
		default:
			if strict {
				return skipped, fmt.Errorf("archive entry %s has an unsupported type", hdr.Name)
			}
			skipped++
		}
	}
	for i := len(order) - 1; i >= 0; i-- {
		if err := root.Chmod(order[i], dirs[order[i]]); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// packTree writes a directory tree into an archive, under prefix if one is
// given. Ownership and timestamps are left out, so the same tree always
// produces the same entries.
func packTree(tw *tar.Writer, root, prefix string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		mode := info.Mode()
		hdr := &tar.Header{Name: filepath.ToSlash(filepath.Join(prefix, rel)), Mode: int64(mode.Perm()), Format: tar.FormatPAX}
		if mode&fs.ModeSetuid != 0 {
			hdr.Mode |= 0o4000
		}
		if mode&fs.ModeSetgid != 0 {
			hdr.Mode |= 0o2000
		}
		if mode&fs.ModeSticky != 0 {
			hdr.Mode |= 0o1000
		}
		switch {
		case mode.IsDir():
			hdr.Typeflag = tar.TypeDir
			return tw.WriteHeader(hdr)
		case mode&fs.ModeSymlink != 0:
			hdr.Typeflag = tar.TypeSymlink
			if hdr.Linkname, err = os.Readlink(p); err != nil {
				return err
			}
			return tw.WriteHeader(hdr)
		case mode.IsRegular():
			hdr.Typeflag, hdr.Size = tar.TypeReg, info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		default:
			return fmt.Errorf("%s: devices, sockets and fifos are not allowed in a rootfs", rel)
		}
	})
}

// addLayer lays an archive or a directory over an existing rootfs, under
// "to", dropping "strip" leading path elements from each entry (a runtime
// tarball usually wraps everything in one folder). Entries replace what is
// there. os.Root keeps every path inside the rootfs.
func addLayer(rootfs, from, to string, strip int) error {
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	var tr *tar.Reader
	if info.IsDir() {
		pr, pw := io.Pipe()
		go func() {
			tw := tar.NewWriter(pw)
			err := packTree(tw, from, "")
			if err == nil {
				err = tw.Close()
			}
			pw.CloseWithError(err)
		}()
		defer pr.Close()
		tr = tar.NewReader(pr)
	} else {
		f, err := os.Open(from)
		if err != nil {
			return err
		}
		defer f.Close()
		var in io.Reader = bufio.NewReader(f)
		if magic, _ := in.(*bufio.Reader).Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
			if in, err = gzip.NewReader(in); err != nil {
				return err
			}
		}
		tr = tar.NewReader(in)
	}
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return err
	}
	defer root.Close()
	base := strings.TrimPrefix(filepath.Clean("/"+to), "/")
	// place maps an entry's name to its path in the rootfs, or reports that it is stripped away.
	place := func(name string) (string, bool, error) {
		parts := strings.Split(strings.Trim(filepath.ToSlash(filepath.Clean(name)), "/"), "/")
		if len(parts) <= strip || parts[0] == "." && len(parts) == 1 {
			return "", false, nil
		}
		rel := filepath.Join(parts[strip:]...)
		if !filepath.IsLocal(rel) {
			return "", false, fmt.Errorf("path %q escapes the rootfs", name)
		}
		return filepath.Join(base, rel), true, nil
	}
	type dirMode struct {
		path string
		mode fs.FileMode
	}
	var dirs []dirMode
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		path, ok, err := place(hdr.Name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		mode := hdr.FileInfo().Mode() & permBits
		if hdr.Typeflag != tar.TypeDir {
			if err := root.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(path, 0o755); err != nil {
				return err
			}
			dirs = append(dirs, dirMode{path, mode})
		case tar.TypeSymlink:
			root.Remove(path)
			if err := root.Symlink(hdr.Linkname, path); err != nil {
				return err
			}
		case tar.TypeReg:
			root.Remove(path)
			f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if err := root.Chmod(path, mode); err != nil {
				return err
			}
		case tar.TypeLink:
			target, ok, err := place(hdr.Linkname)
			if err != nil || !ok {
				return fmt.Errorf("hard link %s points outside what is being added", hdr.Name)
			}
			root.Remove(path)
			if err := root.Link(target, path); err != nil {
				return err
			}
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := root.Chmod(dirs[i].path, dirs[i].mode|0o700); err != nil { // keep it writable for later layers and files
			return err
		}
	}
	return nil
}
