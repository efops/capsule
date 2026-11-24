package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// tunnel is what the mesh asks of WireGuard, wherever it runs.
//
// With root it is the kernel's: the device is made in the host's network,
// where its encrypted socket stays, and moved into the capsule. Only root
// may make one there. Without root the same protocol runs inside the
// supervisor instead: a plain tunnel interface in the capsule's network,
// which the supervisor is allowed to create because it owns that network,
// with the supervisor encrypting each packet to an ordinary UDP socket on
// the host. It interoperates with the kernel's, so a fleet can mix the two.
// It is slower, since every packet passes through the supervisor.
type tunnel interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
}

type userTunnel struct{ dev *device.Device }

// newUserTunnel makes the interface on the calling thread, which must be in the capsule's network.
func newUserTunnel(name string) (*userTunnel, error) {
	t, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return nil, err
	}
	return &userTunnel{device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))}, nil
}

func (u *userTunnel) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	var b strings.Builder
	if cfg.PrivateKey != nil {
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	}
	if cfg.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *cfg.ListenPort)
	}
	for _, p := range cfg.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.AddrPort())
		}
		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
		}
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
	}
	return u.dev.IpcSet(b.String())
}

func (u *userTunnel) Device(name string) (*wgtypes.Device, error) {
	raw, err := u.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	out := &wgtypes.Device{Name: name}
	var peer *wgtypes.Peer
	for _, line := range strings.Split(raw, "\n") {
		key, value, _ := strings.Cut(line, "=")
		number, _ := strconv.ParseInt(value, 10, 64)
		switch key {
		case "listen_port":
			out.ListenPort = int(number)
		case "public_key":
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != wgtypes.KeyLen {
				continue
			}
			out.Peers = append(out.Peers, wgtypes.Peer{})
			peer = &out.Peers[len(out.Peers)-1]
			copy(peer.PublicKey[:], raw)
		case "rx_bytes":
			if peer != nil {
				peer.ReceiveBytes = number
			}
		case "tx_bytes":
			if peer != nil {
				peer.TransmitBytes = number
			}
		case "last_handshake_time_sec":
			if peer != nil && number > 0 {
				peer.LastHandshakeTime = time.Unix(number, 0)
			}
		case "endpoint":
			if peer != nil {
				peer.Endpoint, _ = net.ResolveUDPAddr("udp", value)
			}
		}
	}
	return out, nil
}
