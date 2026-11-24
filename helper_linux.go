package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A few things the kernel lets only root do: make a WireGuard device in the
// host's network, attach a file as a disk, and listen on a port below 1024.
// Without root, capsule works around the first two in slower ways and cannot
// do the others. The helper closes that gap without making anyone root.
//
// It is this same program, started as root by systemd each time an
// unprivileged capsule connects to a socket only members of the "capsule"
// group may open. There is no setuid program and nothing left running: one
// helper serves one request. It takes no paths and no commands, only the four
// fixed requests below, and works out every path itself under directories
// only root can write, so the only disk images it ever mounts are ones it
// made. A volume or store stays mounted for as long as the capsule that asked
// keeps its connection open, and is put away when that connection closes,
// however the capsule ended.

const (
	helperHome   = "/var/lib/capsule/users" // disk images, by user id
	helperMounts = "/run/capsule-helper"    // where they are mounted, by user id
)

var errNoHelper = errors.New("the capsule helper is not available to this user")

func helperSocket() string {
	if s := os.Getenv("CAPSULE_HELPER"); s != "" {
		return s // "off" turns it off
	}
	return "/run/capsule-helper.sock"
}

type helperRequest struct {
	Op      string `json:"op"` // tunnel, listen, volume, store
	Unit    string `json:"unit,omitempty"`
	Name    string `json:"name,omitempty"`
	Size    string `json:"size,omitempty"`
	Encrypt bool   `json:"encrypt,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Port    int    `json:"port,omitempty"`
}

type helperReply struct {
	Error string `json:"error,omitempty"`
	Path  string `json:"path,omitempty"`
	Name  string `json:"name,omitempty"`
}

// ---- asking ----

// askHelper sends one request, with a file if the request carries one, and
// returns the answer, any file that came with it, and the connection, which
// the caller closes when it no longer needs what it asked for.
func askHelper(req helperRequest, send *os.File) (helperReply, *os.File, *net.UnixConn, error) {
	var reply helperReply
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: helperSocket(), Net: "unix"})
	if err != nil {
		return reply, nil, nil, errNoHelper
	}
	msg, _ := json.Marshal(req)
	var oob []byte
	if send != nil {
		oob = unix.UnixRights(int(send.Fd()))
	}
	conn.SetDeadline(time.Now().Add(2 * time.Minute)) // making a filesystem can take a while
	if _, _, err := conn.WriteMsgUnix(msg, oob, nil); err != nil {
		conn.Close()
		return reply, nil, nil, err
	}
	buf, in := make([]byte, 8192), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, in)
	if err != nil || json.Unmarshal(buf[:n], &reply) != nil {
		conn.Close()
		return reply, nil, nil, fmt.Errorf("the capsule helper gave no answer (see `journalctl -u 'capsule-helper@*'`): %v", err)
	}
	conn.SetDeadline(time.Time{})
	got := receivedFile(in[:oobn])
	if reply.Error != "" {
		if got != nil {
			got.Close()
		}
		conn.Close()
		return reply, nil, nil, errors.New(reply.Error)
	}
	return reply, got, conn, nil
}

func receivedFile(oob []byte) *os.File {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var file *os.File
	for _, m := range msgs {
		fds, _ := unix.ParseUnixRights(&m)
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			if file == nil {
				file = os.NewFile(uintptr(fd), "passed")
			} else {
				unix.Close(fd)
			}
		}
	}
	return file
}

// helperTunnel has a kernel WireGuard device made in the host's network and
// moved into the given network namespace, and returns its name there. The
// kernel lets a tunnel's port be chosen only from the host's side, so the
// helper sets that too; the tunnel's key it never sees.
func helperTunnel(ns *os.File, listen int) (string, error) {
	reply, _, conn, err := askHelper(helperRequest{Op: "tunnel", Port: listen}, ns)
	if err != nil {
		return "", err
	}
	conn.Close()
	return reply.Name, nil
}

// helperListen returns a listener on a port below 1024.
func helperListen(addr string) (net.Listener, error) {
	_, file, conn, err := askHelper(helperRequest{Op: "listen", Addr: addr}, nil)
	if err != nil {
		return nil, err
	}
	conn.Close()
	if file == nil {
		return nil, errors.New("the capsule helper sent no listener")
	}
	defer file.Close()
	return net.FileListener(file)
}

// helperVolume opens a sized volume and returns its data directory and a function that lets go of it.
func helperVolume(unit, name, size string, encrypt bool) (string, func(), error) {
	reply, _, conn, err := askHelper(helperRequest{Op: "volume", Unit: unit, Name: name, Size: size, Encrypt: encrypt}, nil)
	if err != nil {
		return "", nil, err
	}
	return reply.Path, func() { conn.Close() }, nil
}

// helperStore opens the encrypted on-disk store for one sealed rootfs.
func helperStore(rootfsHash string, encSize int64) (string, func(), error) {
	reply, _, conn, err := askHelper(helperRequest{Op: "store", Hash: rootfsHash, Bytes: encSize}, nil)
	if err != nil {
		return "", nil, err
	}
	return reply.Path, func() { conn.Close() }, nil
}

// ---- answering ----

var (
	helperUnitRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,90}$`)
	helperHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// cmdHelper serves the one connection systemd started it for.
func cmdHelper() error {
	if !realRoot() || os.Getenv("LISTEN_FDS") != "1" {
		return errors.New("this command is internal: systemd starts it for capsule-helper.socket")
	}
	c, err := net.FileConn(os.NewFile(3, "connection"))
	if err != nil {
		return err
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	var cred *unix.Ucred
	raw, err := conn.SyscallConn()
	if err == nil {
		var cerr error
		err = raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if err == nil {
			err = cerr
		}
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf, oob := make([]byte, 8192), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return err
	}
	passed := receivedFile(oob[:oobn])
	if passed != nil {
		defer passed.Close()
	}
	conn.SetDeadline(time.Time{})
	var req helperRequest
	answer := func(reply helperReply, file *os.File) error {
		msg, _ := json.Marshal(reply)
		var rights []byte
		if file != nil {
			rights = unix.UnixRights(int(file.Fd()))
		}
		_, _, err := conn.WriteMsgUnix(msg, rights, nil)
		return err
	}
	if json.Unmarshal(buf[:n], &req) != nil {
		return answer(helperReply{Error: "not a request"}, nil)
	}
	fmt.Fprintf(os.Stderr, "uid %d: %q %q\n", cred.Uid, req.Op, req.Unit+req.Name+req.Hash+req.Addr)
	path, name, file, release, err := helperServe(req, cred, passed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uid %d: %q refused: %v\n", cred.Uid, req.Op, err)
		return answer(helperReply{Error: err.Error()}, nil)
	}
	if file != nil {
		defer file.Close()
	}
	err = answer(helperReply{Path: path, Name: name}, file)
	if release != nil {
		if err == nil {
			conn.Read(buf) // returns when the capsule lets go, or is gone
		}
		release()
	}
	return err
}

func helperServe(req helperRequest, cred *unix.Ucred, passed *os.File) (path, name string, file *os.File, release func(), err error) {
	if cred.Uid == 0 {
		return "", "", nil, nil, errors.New("root has no use for the helper")
	}
	switch req.Op {
	case "tunnel":
		name, err = helperMakeTunnel(cred, passed, req.Port)
	case "listen":
		file, err = helperBind(req.Addr)
	case "volume":
		path, release, err = helperOpenVolume(req, cred)
	case "store":
		path, release, err = helperOpenStore(req, cred)
	default:
		err = fmt.Errorf("%q is not something the helper does", req.Op)
	}
	return
}

// helperMakeTunnel only puts a device into a network namespace that belongs
// to the caller: one owned by a user namespace that user created.
func helperMakeTunnel(cred *unix.Ucred, ns *os.File, listen int) (string, error) {
	if listen != 0 && (listen < 1024 || listen > 65535) {
		return "", errors.New("a tunnel's port must be 1024 or above")
	}
	if ns == nil {
		return "", errors.New("no network namespace was passed")
	}
	if kind, err := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNET {
		return "", errors.New("what was passed is not a network namespace")
	}
	owner, err := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return "", err
	}
	defer unix.Close(owner)
	uid, err := unix.IoctlGetUint32(owner, unix.NS_GET_OWNER_UID)
	if err != nil {
		return "", err
	}
	var self, theirs unix.Stat_t
	if unix.Stat("/proc/self/ns/user", &self) != nil || unix.Fstat(owner, &theirs) != nil || self.Ino == theirs.Ino || uid != cred.Uid {
		return "", errors.New("that network namespace does not belong to you")
	}
	suffix := make([]byte, 4)
	rand.Read(suffix)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "cps" + hex.EncodeToString(suffix)
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		return "", fmt.Errorf("creating WireGuard interface (is the wireguard module available?): %w", err)
	}
	link, err := netlink.LinkByName(attrs.Name)
	if err == nil && listen != 0 {
		var wg *wgctrl.Client
		if wg, err = wgctrl.New(); err == nil {
			// A tunnel just torn down can hold its port a moment longer.
			for attempt := 0; ; attempt++ {
				err = wg.ConfigureDevice(attrs.Name, wgtypes.Config{ListenPort: &listen})
				if err == nil || attempt == 40 || !errors.Is(err, unix.EADDRINUSE) {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			wg.Close()
		}
	}
	if err == nil {
		err = netlink.LinkSetNsFd(link, int(ns.Fd()))
	}
	if err != nil {
		if link != nil {
			netlink.LinkDel(link)
		}
		return "", err
	}
	return attrs.Name, nil
}

func helperBind(addr string) (*os.File, error) {
	_, portText, err := net.SplitHostPort(addr)
	port, perr := strconv.Atoi(portText)
	if err != nil || perr != nil || port < 1 || port > 1023 {
		return nil, errors.New("the helper only opens ports below 1024; any user can open the others")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return l.(*net.TCPListener).File()
}

// helperDirs makes the two directories one user's images and mounts live in.
// Both chains are root's; the mounts are only visible to that user.
func helperDirs(cred *unix.Ucred, kind, name string) (images, mount string, err error) {
	uid := strconv.Itoa(int(cred.Uid))
	images = filepath.Join(helperHome, uid, kind)
	if err = os.MkdirAll(images, 0o700); err != nil {
		return
	}
	userMounts := filepath.Join(helperMounts, uid)
	if err = os.MkdirAll(userMounts, 0o750); err != nil {
		return
	}
	if err = os.Chown(userMounts, 0, int(cred.Gid)); err != nil {
		return
	}
	if err = os.Chmod(helperMounts, 0o755); err != nil {
		return
	}
	mount = filepath.Join(userMounts, kind, name)
	err = os.MkdirAll(filepath.Dir(mount), 0o755)
	return
}

func helperOpenVolume(req helperRequest, cred *unix.Ucred) (string, func(), error) {
	if !helperUnitRE.MatchString(req.Unit) || !nameRE.MatchString(req.Name) {
		return "", nil, errors.New("not a volume name")
	}
	if _, err := parseSizeText(req.Size); err != nil {
		return "", nil, err
	}
	images, mount, err := helperDirs(cred, "volumes", req.Unit+"/"+req.Name)
	if err != nil {
		return "", nil, err
	}
	images = filepath.Join(images, req.Unit)
	if err := os.MkdirAll(images, 0o700); err != nil {
		return "", nil, err
	}
	image := filepath.Join(images, req.Name+".img")
	// One capsule at a time: the same filesystem is never mounted twice. A
	// capsule restarting may find the last one's helper still letting go.
	lock, err := os.OpenFile(image+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return "", nil, err
	}
	for attempt := 0; ; attempt++ {
		if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			break
		}
		if attempt == 50 {
			lock.Close()
			return "", nil, errors.New("the volume is in use by another running capsule")
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, closeVolume, err := openImageVolume(image, mount, req.Size, req.Encrypt)
	if err != nil {
		lock.Close()
		return "", nil, err
	}
	release := func() { closeVolume(); lock.Close() }
	if err := helperHandOver(data, cred); err != nil {
		release()
		return "", nil, err
	}
	return data, release, nil
}

func helperOpenStore(req helperRequest, cred *unix.Ucred) (string, func(), error) {
	if !helperHashRE.MatchString(req.Hash) || req.Bytes < 0 || req.Bytes > 1<<40 {
		return "", nil, errors.New("not a sealed rootfs")
	}
	images, mount, err := helperDirs(cred, "sealed", "x")
	if err != nil {
		return "", nil, err
	}
	data, release, err := openSealedStoreAt(images, filepath.Dir(mount), req.Hash, req.Bytes)
	if err != nil {
		return "", nil, err
	}
	if err := helperHandOver(data, cred); err != nil {
		release()
		return "", nil, err
	}
	return data, release, nil
}

// helperHandOver gives the top directory of a volume or store to the user
// whose capsule will use it, and closes it to everyone else. The capsule's
// root is that user. Nothing beneath the directory is touched.
func helperHandOver(data string, cred *unix.Ucred) error {
	var st unix.Stat_t
	if err := unix.Lstat(data, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("the volume's data directory is not a directory")
	}
	if st.Uid == cred.Uid {
		return nil // handed over on an earlier run; how open it is has been the user's to decide since
	}
	if err := os.Lchown(data, int(cred.Uid), int(cred.Gid)); err != nil {
		return err
	}
	return os.Chmod(data, 0o700)
}
