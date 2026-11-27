package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/load"
)

// cueSchema is what a build file and a fleet file must satisfy. The
// definitions are closed, so a misspelt field is an error, not a silently
// ignored setting.
const cueSchema = `
#Port: int & >=1 & <=65535
#Name: =~"^[a-z0-9][a-z0-9-]{0,40}$"
#Key:  =~"^[A-Za-z0-9+/]{43}=$" // a key id: the .id file from keygen, or the id from "capsule host"

#Capsule: {
	name: #Name
	command: [string, ...string]
	env?: [string]: string
	hostname?: string
	network?:  "none" | "host" | "mesh" | "cell"
	offers?: [...{
		name:            #Name
		to:              [#Name, ...#Name]
		port?:           #Port
		udp?:            bool
		grant?:          bool
		proxy_protocol?: bool
	}]
	needs?: [...{
		name:     #Name
		from:     #Name
		port?:    #Port
		udp?:     bool
		balance?: "random" | "round-robin" | "sticky" | "failover" | "least-connections"
	}]
	mesh?: peers: [...{
		name:     #Name
		out?:     [...#Port]
		in?:      [...#Port]
		out_udp?: [...#Port]
		in_udp?:  [...#Port]
		balance?: "random" | "round-robin" | "sticky" | "failover" | "least-connections"
	}]
	policy?: {
		not_before?: string
		expires?:    string
		timelock?:   bool
		max_runs?:   int & >=0
		fleet?:      bool
		permits?:    [...#Key]
		hosts?:      [...#Key]
		approvals?: {
			required: int & >=1
			signers:  [#Key, ...#Key]
		}
	}
	publish?: [...#Port]
	egress?: [...{host: string, port: #Port}]
	unlock?: [...{at: string, env: [string]: string}]
	volumes?: [...{name: #Name, path: =~"^/", exec?: bool, size?: string, encrypt?: bool}]
	scale?: {
		min:         int & >=0
		max:         int & >=min & >=1
		fleet?:      bool
		cpu?:        int & >=1 & <=100
		cooldown?:   string
		memory_max?: string
		restart?:    "always" | "on-failure" | "never"
		balance?:    "least-connections" | "round-robin" | "random"
	}
	syscalls?: [...string]
	limits?: {
		memory?: string
		cpus?:   number & >0
		pids?:   int & >0
	}
	latency?: {
		cores?:       int & >0
		memory_lock?: bool
		hugepages?:   bool
		devices?: [...string]
		nic?: {
			name:     string
			address?: string
			gateway?: string
		}
	}
}

#File: {
	contents?: string
	source?:   string
	mode:      int | *0o644
}

#Build: {
	capsule: #Capsule
	rootfs: {
		from?:   string // a directory, a .tar/.tar.gz file, or an https URL
		sha256?: string // required for a URL
		add?: [...{ // laid over the base in order, before files
			from:    string
			sha256?: string
			to:      =~"^/" | *"/"
			strip:   int & >=0 | *0 // leading path elements to drop from each entry
		}]
		files?: [=~"^/"]: #File
	}
}

#Fleet: {
	hosts: [#Name]: {address?: string}
	deploy: [...{
		capsule:   string // a sealed capsule directory
		host:      #Name
		instance?: #Name
		listen?:   #Port
		publish?:  [...string]
		args?:     [...string]
	}]
}
`

// cueProblems turns CUE's errors into one line each, saying plainly when a
// rule needs a field that was not set.
func cueProblems(err error) string {
	var lines []string
	for _, e := range cueerrors.Errors(err) {
		format, args := e.Msg()
		msg := fmt.Sprintf(format, args...)
		path := strings.TrimPrefix(strings.TrimPrefix(strings.Join(e.Path(), "."), "#Build."), "#Fleet.")
		if strings.HasPrefix(msg, "incomplete value") {
			msg = "must be set (required" + strings.TrimPrefix(msg, "incomplete value") + ")"
		}
		line := path + ": " + msg
		if pos := e.Position(); pos.IsValid() && pos.Filename() != "" {
			line += fmt.Sprintf(" (%s:%d)", filepath.Base(pos.Filename()), pos.Line())
		}
		if !slices.Contains(lines, line) {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// loadCUE evaluates a CUE file against one of the schema's definitions and
// any extra rule files, and requires the result to be fully decided.
func loadCUE(file, definition string, rules []string) (cue.Value, error) {
	ctx := cuecontext.New()
	abs, err := filepath.Abs(file)
	if err != nil {
		return cue.Value{}, err
	}
	insts := load.Instances([]string{filepath.Base(abs)}, &load.Config{Dir: filepath.Dir(abs)})
	if insts[0].Err != nil {
		return cue.Value{}, errors.New(cueerrors.Details(insts[0].Err, nil))
	}
	v := ctx.CompileString(cueSchema).LookupPath(cue.ParsePath(definition)).Unify(ctx.BuildInstance(insts[0]))
	for _, rule := range rules {
		src, err := os.ReadFile(rule)
		if err != nil {
			return v, err
		}
		v = v.Unify(ctx.CompileBytes(src, cue.Filename(rule)))
	}
	if err := v.Validate(cue.Concrete(true)); err != nil {
		return v, errors.New(cueProblems(err))
	}
	return v, nil
}

// admit applies the host's own rules, /etc/capsule/policy.d/*.cue, to a
// manifest that is about to run. The rules have the same shape as a build
// file, so `capsule: limits: memory: string` insists on a memory limit and
// `capsule: network: "none" | "mesh"` forbids host networking.
func admit(manifest []byte) error {
	rules, _ := filepath.Glob(filepath.Join(configDir(), "policy.d", "*.cue"))
	if len(rules) == 0 {
		return nil
	}
	ctx := cuecontext.New()
	v := ctx.CompileString("capsule: _").FillPath(cue.ParsePath("capsule"), ctx.CompileBytes(manifest))
	for _, rule := range rules {
		src, err := os.ReadFile(rule)
		if err != nil {
			return err
		}
		checked := v.Unify(ctx.CompileBytes(src, cue.Filename(rule)))
		if err := checked.Validate(cue.Concrete(true)); err != nil {
			return fmt.Errorf("host rule %s does not allow it: %s", filepath.Base(rule), cueProblems(err))
		}
	}
	return nil
}

type ruleFlag []string

func (r *ruleFlag) String() string     { return strings.Join(*r, ",") }
func (r *ruleFlag) Set(v string) error { *r = append(*r, v); return nil }

// cmdBuild turns a CUE build file into a capsule directory: it assembles the
// rootfs from a verified base plus declared files, writes the manifest, and
// seals it if given a key.
func cmdBuild(args []string) error {
	fl := flag.NewFlagSet("build", flag.ExitOnError)
	out := fl.String("o", "", "output directory (default: the capsule's name)")
	keyPath := fl.String("key", "", "seal the result with this private key")
	force := fl.Bool("force", false, "replace the output directory if it exists")
	var rules, hosts ruleFlag
	fl.Var(&rules, "rules", "extra CUE file of rules the build must satisfy (repeatable)")
	fl.Var(&hosts, "host", "host file from `capsule host -export`, one for each id in policy.hosts (repeatable)")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule build [-o <dir>] [-key <file>] [-rules <file.cue>] [-force] <file.cue>")
	}
	file := fl.Arg(0)
	v, err := loadCUE(file, "#Build", rules)
	if err != nil {
		return err
	}
	raw, err := v.LookupPath(cue.ParsePath("capsule")).MarshalJSON()
	if err != nil {
		return err
	}
	m, err := parseManifest(raw) // the runtime's own checks, on top of the schema
	if err != nil {
		return err
	}
	var rootfs struct {
		From   string `json:"from"`
		SHA256 string `json:"sha256"`
		Add    []struct {
			From   string `json:"from"`
			SHA256 string `json:"sha256"`
			To     string `json:"to"`
			Strip  int    `json:"strip"`
		} `json:"add"`
		Files map[string]struct {
			Contents *string `json:"contents"`
			Source   string  `json:"source"`
			Mode     uint32  `json:"mode"`
		} `json:"files"`
	}
	if err := v.LookupPath(cue.ParsePath("rootfs")).Decode(&rootfs); err != nil {
		return err
	}

	dir := *out
	if dir == "" {
		dir = m.Name
	}
	if _, err := os.Stat(dir); err == nil {
		if !*force {
			return fmt.Errorf("%s already exists (use -force to replace it)", dir)
		}
		removeTree(dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	base := filepath.Dir(file) // paths in the build file are relative to it
	rel := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	// source turns a "from" into a local path: a download checked against
	// its declared hash, or a path beside the build file.
	source := func(from, sha string) (string, error) {
		switch {
		case strings.HasPrefix(from, "https://"):
			return fetch(from, sha)
		case from != "":
			from = rel(from)
			if sha != "" {
				if got, err := fileSHA256(from); err != nil || got != sha {
					return "", fmt.Errorf("%s does not have the declared sha256", from)
				}
			}
		}
		return from, nil
	}
	from, err := source(rootfs.From, rootfs.SHA256)
	if err != nil {
		return err
	}
	if err := fillRootfs(from, filepath.Join(dir, "rootfs")); err != nil {
		return err
	}
	// Further archives or directories laid over the base: a language runtime, an application bundle.
	for _, layer := range rootfs.Add {
		from, err := source(layer.From, layer.SHA256)
		if err != nil {
			return err
		}
		if err := addLayer(filepath.Join(dir, "rootfs"), from, layer.To, layer.Strip); err != nil {
			return fmt.Errorf("rootfs.add %s: %w", layer.From, err)
		}
	}

	root, err := os.OpenRoot(filepath.Join(dir, "rootfs")) // declared files cannot land outside the rootfs
	if err != nil {
		return err
	}
	defer root.Close()
	paths := make([]string, 0, len(rootfs.Files))
	for p := range rootfs.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		f := rootfs.Files[p]
		if (f.Contents == nil) == (f.Source == "") {
			return fmt.Errorf("rootfs.files[%q]: give exactly one of contents and source", p)
		}
		data := []byte{}
		if f.Contents != nil {
			data = []byte(*f.Contents)
		} else if data, err = os.ReadFile(rel(f.Source)); err != nil {
			return err
		}
		name := strings.TrimPrefix(filepath.Clean(p), "/")
		if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		root.Remove(name) // replace a file from the base, or a symlink, rather than writing through it
		w, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		if err := root.Chmod(name, os.FileMode(f.Mode)&0o777); err != nil { // permission bits only; setuid has no effect in a capsule
			return err
		}
	}

	var pretty bytes.Buffer
	json.Indent(&pretty, raw, "", "  ")
	pretty.WriteByte('\n')
	if err := os.WriteFile(filepath.Join(dir, "capsule.json"), pretty.Bytes(), 0o644); err != nil {
		return err
	}
	if *keyPath == "" {
		fmt.Printf("built %s (not sealed; pass -key or run capsule seal)\n", dir)
		return nil
	}
	s, err := sealCapsule(dir, *keyPath, hosts)
	if err != nil {
		return err
	}
	fmt.Printf("built and sealed %s %s\n", dir, s.id())
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), err
}

// fetch downloads a base rootfs, refusing anything whose hash is not the one
// declared, and keeps it in the user's cache under that hash.
func fetch(url, want string) (string, error) {
	if len(want) != 64 {
		return "", errors.New("rootfs.sha256 is required when rootfs.from is a URL")
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cached := filepath.Join(cacheDir, "capsule", want)
	if got, err := fileSHA256(cached); err == nil && got == want {
		return cached, nil
	}
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		return "", err
	}
	client := http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(cached), "download-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s has sha256 %s, not the declared %s", url, got, want)
	}
	return cached, os.Rename(tmp.Name(), cached)
}

// cmdRender turns a CUE fleet file into one directory per host, laid out as
// the host's own filesystem: each capsule under /var/lib/capsule/apps and its
// run flags under /etc/capsule/apps, ready to copy over and start.
func cmdRender(args []string) error {
	fl := flag.NewFlagSet("render", flag.ExitOnError)
	out := fl.String("o", "deploy", "output directory")
	var rules ruleFlag
	fl.Var(&rules, "rules", "extra CUE file of rules the fleet must satisfy (repeatable)")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: capsule render [-o <dir>] [-rules <file.cue>] <fleet.cue>")
	}
	file := fl.Arg(0)
	v, err := loadCUE(file, "#Fleet", rules)
	if err != nil {
		return err
	}
	var fleet struct {
		Hosts map[string]struct {
			Address string `json:"address"`
		} `json:"hosts"`
		Deploy []struct {
			Capsule  string   `json:"capsule"`
			Host     string   `json:"host"`
			Instance string   `json:"instance"`
			Listen   int      `json:"listen"`
			Publish  []string `json:"publish"`
			Args     []string `json:"args"`
		} `json:"deploy"`
	}
	if err := v.Decode(&fleet); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists", *out)
	}
	units := map[string][]string{} // host -> service names
	for _, d := range fleet.Deploy {
		host, ok := fleet.Hosts[d.Host]
		if !ok {
			return fmt.Errorf("deploy: host %q is not in hosts", d.Host)
		}
		src := d.Capsule
		if !filepath.IsAbs(src) {
			src = filepath.Join(filepath.Dir(file), src)
		}
		m, _, err := loadManifest(src)
		if err != nil {
			return err
		}
		seal, err := readSeal(src)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Capsule, err)
		}
		unit := m.Name
		if d.Instance != "" {
			unit += "-" + d.Instance
		}
		if slices.Contains(units[d.Host], unit) {
			return fmt.Errorf("deploy: %s appears twice on %s; give the replicas different instance labels", unit, d.Host)
		}
		units[d.Host] = append(units[d.Host], unit)

		app := filepath.Join(*out, d.Host, "var/lib/capsule/apps", unit)
		if err := os.MkdirAll(app, 0o755); err != nil {
			return err
		}
		files := []string{"capsule.json", "capsule.seal", "capsule.approvals"}
		if seal.Encrypted {
			files = append(files, "rootfs.enc") // an encrypted capsule ships without its plaintext
		} else if err := copyTree(filepath.Join(src, "rootfs"), filepath.Join(app, "rootfs")); err != nil {
			return err
		}
		for _, name := range files {
			data, err := os.ReadFile(filepath.Join(src, name))
			if os.IsNotExist(err) && name == "capsule.approvals" {
				continue
			} else if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(app, name), data, 0o644); err != nil {
				return err
			}
		}

		var flags []string
		if d.Instance != "" {
			flags = append(flags, "-instance", d.Instance)
		}
		if d.Listen != 0 {
			flags = append(flags, "-listen", strconv.Itoa(d.Listen))
		}
		if m.meshed() && host.Address != "" {
			flags = append(flags, "-advertise", host.Address)
		}
		for _, p := range d.Publish {
			flags = append(flags, "-publish", p)
		}
		flags = append(flags, d.Args...)
		env := filepath.Join(*out, d.Host, "etc/capsule/apps", unit+".env")
		if err := os.MkdirAll(filepath.Dir(env), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(env, []byte("CAPSULE_ARGS="+strings.Join(flags, " ")+"\n"), 0o644); err != nil {
			return err
		}
	}
	hosts := make([]string, 0, len(units))
	for h := range units {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		target := h
		if a := fleet.Hosts[h].Address; a != "" {
			target = a
		}
		services := make([]string, len(units[h]))
		for i, u := range units[h] {
			services[i] = "capsule@" + u
		}
		fmt.Printf("%s:\n  rsync -a %s/ root@%s:/\n  ssh root@%s systemctl enable --now %s\n",
			h, filepath.Join(*out, h), target, target, strings.Join(services, " "))
	}
	return nil
}
