package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// inNetns runs f on a thread moved into the given network namespace. Sockets
// f opens stay in that namespace afterwards. The thread is never moved back:
// an unprivileged supervisor may enter its capsule's namespace but not
// re-enter the host's, so the goroutine stays locked and Go discards the
// thread when it ends.
func inNetns(ns *os.File, f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("entering the capsule's network: %w", err)
			return
		}
		done <- f()
	}()
	return <-done
}

// publishSpec is one `-publish [addr:]hostport:capsuleport` flag.
type publishSpec struct {
	host string
	port int
}

type publishFlag []publishSpec

func (p *publishFlag) String() string { return fmt.Sprint(*p) }
func (p *publishFlag) Set(v string) error {
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return errors.New("want [addr:]hostport:capsuleport")
	}
	port, err := strconv.Atoi(v[i+1:])
	if err != nil || !validPort(port) {
		return errors.New("want [addr:]hostport:capsuleport")
	}
	host := v[:i]
	if !strings.Contains(host, ":") {
		host = ":" + host
	}
	*p = append(*p, publishSpec{host, port})
	return nil
}

// startForwarding opens the only two ways traffic crosses the capsule's
// boundary outside the mesh, both declared in the sealed manifest and both
// carried by this supervisor process, so there is no extra proxy to deploy:
//
//	publish: a host port forwarded to a port inside the capsule
//	egress:  a loopback address inside the capsule forwarded to a named outside host
func startForwarding(ns *os.File, m Manifest, publish []publishSpec) error {
	for _, p := range publish {
		if !slices.Contains(m.Publish, p.port) {
			return fmt.Errorf("the manifest does not allow publishing port %d", p.port)
		}
		l, err := net.Listen("tcp", p.host)
		if errors.Is(err, syscall.EACCES) && !realRoot() {
			// A port below 1024. The helper opens it and hands it over.
			if helped, herr := helperListen(p.host); herr == nil {
				l, err = helped, nil
			} else if !errors.Is(herr, errNoHelper) {
				err = herr
			}
		}
		if err != nil {
			return err
		}
		go serve(l, fmt.Sprintf("publish %d", p.port), func() (net.Conn, func(), error) {
			c, err := dialCapsule(ns, p.port)
			return c, nil, err
		})
	}
	addrs := egressAddrs(m)
	for _, e := range m.Egress {
		var l net.Listener
		inside := net.JoinHostPort(addrs[e.Host].String(), strconv.Itoa(e.Port))
		if err := inNetns(ns, func() (err error) { l, err = net.Listen("tcp4", inside); return }); err != nil {
			return fmt.Errorf("egress %s: %w", e.Host, err)
		}
		outside := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
		go serve(l, "egress "+outside, func() (net.Conn, func(), error) {
			c, err := net.DialTimeout("tcp", outside, 10*time.Second)
			return c, nil, err
		})
	}
	return nil
}

// dialCapsule connects to a port on the capsule's own loopback.
func dialCapsule(ns *os.File, port int) (c net.Conn, err error) {
	err = inNetns(ns, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), "capsule")
		defer f.Close()
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return err
		}
		c, err = net.FileConn(f)
		return err
	})
	return c, err
}

// serve joins each accepted connection to one from dial. If dial also
// returns a function, it is called when that connection has ended.
func serve(l net.Listener, what string, dial func() (net.Conn, func(), error)) {
	for {
		a, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer a.Close()
			b, ended, err := dial()
			if err != nil {
				fmt.Fprintf(os.Stderr, "capsule: %s: %v\n", what, err)
				return
			}
			defer b.Close()
			if ended != nil {
				defer ended()
			}
			relay(a, b)
		}()
	}
}

// relay copies between two connections until both directions have ended.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite() // pass on end-of-stream without cutting the other direction
		}
		done <- struct{}{}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	<-done
	<-done
}
