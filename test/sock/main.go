// sock is a test helper: the smallest program that uses a cell's socket files.
//
//	sock dial <path>          connect, print what the other side sends
//	sock serve <path> <text>  listen, answer every connection with text
//	sock serve4 <port> <text>     listen on IPv4 only, answer every connection with text
//	sock udp-serve <port> <text>  answer every datagram with text
//	sock udp-ask <host:port>      send a datagram, print the answer
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "dial" {
		c, err := net.Dial("unix", os.Args[2])
		if err != nil {
			fmt.Println("blocked")
			return
		}
		if n, _ := io.Copy(os.Stdout, c); n == 0 {
			fmt.Println("blocked")
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "serve" {
		l, err := net.Listen("unix", os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			fmt.Fprintln(c, os.Args[3])
			c.Close()
		}
	}
	if len(os.Args) == 4 && os.Args[1] == "serve4" {
		l, err := net.Listen("tcp4", "127.0.0.1:"+os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			fmt.Fprintln(c, os.Args[3])
			c.Close()
		}
	}
	if len(os.Args) == 4 && os.Args[1] == "udp-serve" {
		l, err := net.ListenPacket("udp", ":"+os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		buf := make([]byte, 2048)
		for {
			_, from, err := l.ReadFrom(buf)
			if err != nil {
				return
			}
			l.WriteTo([]byte(os.Args[3]+"\n"), from)
		}
	}
	if len(os.Args) == 3 && os.Args[1] == "udp-ask" {
		c, err := net.Dial("udp", os.Args[2])
		if err != nil {
			fmt.Println("blocked")
			return
		}
		buf := make([]byte, 2048)
		for try := 0; try < 3; try++ { // datagrams may be lost; ask again
			c.Write([]byte("hi"))
			c.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := c.Read(buf); err == nil {
				os.Stdout.Write(buf[:n])
				return
			}
		}
		fmt.Println("blocked")
		return
	}
	os.Exit(2)
}
