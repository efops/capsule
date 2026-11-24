package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const version = "0.1.0"

var notNameChar = regexp.MustCompile(`[^a-z0-9-]+`)

// cmdInit creates a capsule directory: a starter manifest and a rootfs,
// empty or filled from a directory or a rootfs tarball.
func cmdInit(args []string) error {
	fl := flag.NewFlagSet("init", flag.ExitOnError)
	from := fl.String("rootfs", "", "fill the rootfs from this directory or .tar/.tar.gz archive")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule init [-rootfs <dir or tarball>] <dir>")
	}
	dir := fl.Arg(0)
	manifest := filepath.Join(dir, "capsule.json")
	if _, err := os.Stat(manifest); err == nil {
		return fmt.Errorf("%s already exists", manifest)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	name := strings.Trim(notNameChar.ReplaceAllString(strings.ToLower(filepath.Base(abs)), "-"), "-")
	if !nameRE.MatchString(name) {
		name = "app"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := fillRootfs(*from, filepath.Join(dir, "rootfs")); err != nil {
		return err
	}
	m := Manifest{
		Name:    name,
		Command: []string{"/bin/sh", "-c", "echo hello from " + name},
		Limits:  Limits{Memory: "256M", CPUs: 1, Pids: 256},
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(manifest, append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("created %s\nnext: edit %s, then `capsule seal -key <key> %s` and `capsule run %s`\n", dir, manifest, dir, dir)
	return nil
}

// fillRootfs creates dst empty, or from a directory or a .tar/.tar.gz archive.
func fillRootfs(from, dst string) error {
	info, err := os.Stat(from)
	switch {
	case from == "":
		return os.Mkdir(dst, 0o755)
	case err != nil:
		return err
	case info.IsDir():
		return copyTree(from, dst)
	}
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
	skipped, err := unpackTar(tar.NewReader(in), dst, false)
	if skipped > 0 {
		fmt.Printf("skipped %d device nodes or fifos; a capsule gets its own /dev\n", skipped)
	}
	return err
}

// cmdInspect describes a capsule and says whether this host would run it now, and if not, why.
func cmdInspect(args []string) error {
	fl := flag.NewFlagSet("inspect", flag.ExitOnError)
	var trust trustFlag
	fl.Var(&trust, "trust", "extra trusted public key file")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule inspect [-trust <pub>] <dir>")
	}
	dir := fl.Arg(0)
	m, _, err := loadManifest(dir)
	if err != nil {
		return err
	}
	row := func(label, format string, a ...any) { fmt.Printf("%-10s %s\n", label, fmt.Sprintf(format, a...)) }
	row("name", "%s", m.Name)
	row("command", "%s", strings.Join(m.Command, " "))
	network := m.Network
	if network == "" {
		network = "none"
	}
	row("network", "%s", network)
	if m.Mesh != nil {
		for _, p := range m.Mesh.Peers {
			row("  peer", "%s  out tcp %v udp %v  in tcp %v udp %v", p.Name, p.Out, p.OutUDP, p.In, p.InUDP)
		}
	}
	for _, o := range m.Offers {
		how := "socket /run/cell/offer/" + o.Name
		if o.Port != 0 {
			how = fmt.Sprintf("port %d", o.Port)
		}
		if o.Grant {
			how += ", needs a grant"
		}
		row("  offers", "%s  to %s  (%s; carried on mesh port %d)", o.Name, strings.Join(o.To, ", "), how, receptorPort(o.Name))
	}
	for _, n := range m.Needs {
		row("  needs", "%s  from %s  (socket /run/cell/need/%s)", n.Name, n.From, n.Name)
	}
	if len(m.Publish) > 0 {
		row("publish", "%v", m.Publish)
	}
	for _, e := range m.Egress {
		row("egress", "%s:%d", e.Host, e.Port)
	}
	row("limits", "memory %s  cpus %v  pids %d", orDash(m.Limits.Memory), m.Limits.CPUs, m.Limits.Pids)
	if m.Syscalls != nil {
		row("syscalls", "%d allowed", len(m.Syscalls))
	}
	if p := m.Policy; p != nil {
		if p.NotBefore != nil {
			row("policy", "not before %s", p.NotBefore.Format(time.RFC3339))
		}
		if p.Expires != nil {
			row("policy", "expires %s", p.Expires.Format(time.RFC3339))
		}
		if p.MaxRuns > 0 {
			row("policy", "at most %d runs per host", p.MaxRuns)
		}
		if len(p.Hosts) > 0 {
			row("policy", "%d authorised hosts, rootfs encrypted to them", len(p.Hosts))
		}
		if p.Timelock {
			row("policy", "cannot be decrypted before not_before (drand time lock)")
		}
		if p.Approvals != nil {
			row("policy", "%d of %d approvals", p.Approvals.Required, len(p.Approvals.Signers))
		}
	}

	seal, err := readSeal(dir)
	if err != nil {
		row("seal", "%v", err)
		return nil
	}
	row("seal", "%s", seal.id())
	row("signer", "%s", seal.PublicKey)
	if !seal.Encrypted {
		got, err := hashRootfs(filepath.Join(dir, "rootfs"))
		switch {
		case err != nil:
			row("rootfs", "%v", err)
		case got != seal.Rootfs:
			row("rootfs", "changed since sealing")
		default:
			row("rootfs", "matches the seal")
		}
	}
	if a := m.Policy; a != nil && a.Approvals != nil {
		row("approvals", "%d of %d required", countApprovals(dir, seal.id(), a.Approvals, time.Now()), a.Approvals.Required)
	}

	keys, err := loadTrust(trust)
	if err != nil {
		return err
	}
	verdict := func() error {
		sc, err := openCapsule(dir, keys)
		if err != nil {
			return err
		}
		return checkPolicy(dir, sc, keys, time.Now())
	}()
	if verdict != nil {
		row("this host", "would refuse: %v", verdict)
	} else {
		row("this host", "would run it")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
