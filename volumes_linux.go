package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// cmdVolumes lists the data capsules have kept on this host, or deletes one capsule's.
func cmdVolumes(args []string) error {
	fl := flag.NewFlagSet("volumes", flag.ExitOnError)
	remove := fl.String("rm", "", "delete all volume data of this capsule (name, or name-instance)")
	snapshot := fl.String("snapshot", "", "copy this capsule's volume data to a dated snapshot")
	restore := fl.String("restore", "", "replace this stopped capsule's volume data with the snapshot named as the argument")
	grant := fl.String("grant", "", "let the host whose host file is the argument open this capsule's encrypted volumes")
	fl.Parse(args)
	home := filepath.Join(dataDir(), "volumes")
	// held reports whether the capsule is running, by trying its volume lock.
	held := func(unit string) (bool, func(), error) {
		if filepath.Base(unit) != unit {
			return false, nil, errors.New("give a capsule name, not a path")
		}
		lock, err := os.OpenFile(filepath.Join(home, unit, ".lock"), os.O_RDWR, 0)
		if err != nil {
			return false, nil, fmt.Errorf("no volume data for %s", unit)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return true, func() {}, nil
		}
		return false, func() { lock.Close() }, nil
	}
	switch {
	case *snapshot != "" && fl.NArg() == 0:
		running, release, err := held(*snapshot)
		if err != nil {
			return err
		}
		defer release()
		dest, err := snapshotVolumes(*snapshot, running)
		if err != nil {
			return err
		}
		fmt.Println(filepath.Base(dest))
		return nil
	case *restore != "" && fl.NArg() == 1:
		running, release, err := held(*restore)
		if err != nil {
			return err
		}
		defer release()
		if running {
			return fmt.Errorf("%s is running; stop it before restoring its data", *restore)
		}
		return restoreVolumes(*restore, fl.Arg(0))
	case *grant != "" && fl.NArg() == 1:
		n, err := grantVolumes(*grant, fl.Arg(0))
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%s has no encrypted volumes", *grant)
		}
		fmt.Printf("granted %d volume(s)\n", n)
		return nil
	case fl.NArg() != 0 || *snapshot != "" || *restore != "" || *grant != "":
		return errors.New("usage: capsule volumes [-rm <name> | -snapshot <name> | -restore <name> <snapshot> | -grant <name> <host file>]")
	}
	if *remove != "" {
		if filepath.Base(*remove) != *remove {
			return errors.New("-rm takes a capsule name, not a path")
		}
		unit := filepath.Join(home, *remove)
		lock, err := os.OpenFile(filepath.Join(unit, ".lock"), os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("no volume data for %s", *remove)
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return fmt.Errorf("%s is running; stop it before deleting its data", *remove)
		}
		removeTree(unit)
		return nil
	}
	fmt.Printf("%-32s %-16s %10s\n", "CAPSULE", "VOLUME", "SIZE")
	units, _ := os.ReadDir(home)
	for _, unit := range units {
		volumes, _ := os.ReadDir(filepath.Join(home, unit.Name()))
		sized := map[string]bool{}
		for _, v := range volumes {
			if name, ok := trimSuffix(v.Name(), ".img"); ok {
				sized[name] = true
			}
		}
		for _, v := range volumes {
			path := filepath.Join(home, unit.Name(), v.Name())
			var size int64
			name, isImage := trimSuffix(v.Name(), ".img")
			switch {
			case isImage: // a sized volume: report the disk space its file really takes
				var st syscall.Stat_t
				if syscall.Stat(path, &st) == nil {
					size = st.Blocks * 512
				}
			case v.IsDir() && !sized[name]:
				filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if info, ierr := d.Info(); ierr == nil && info.Mode().IsRegular() {
						size += info.Size()
					}
					return nil
				})
			default:
				continue
			}
			fmt.Printf("%-32s %-16s %9.1fM\n", unit.Name(), name, float64(size)/(1<<20))
		}
	}
	return nil
}
