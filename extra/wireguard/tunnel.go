package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/chainreactors/proxyclient"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type tunnel struct {
	dev  *device.Device
	tnet *netstack.Net
}

func newTunnel(cfg *wgConfig, upstream proxyclient.Dial) (*tunnel, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(cfg.addresses, cfg.dns, cfg.mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}

	bind := newProxyBind(upstream, cfg.endpoint)

	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, ""))

	if err := dev.IpcSet(cfg.ipcConfig()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc config: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	return &tunnel{dev: dev, tnet: tnet}, nil
}

func (t *tunnel) dial(ctx context.Context, network, address string) (net.Conn, error) {
	return t.tnet.DialContext(ctx, network, address)
}

func (t *tunnel) close() {
	if t.dev != nil {
		t.dev.Close()
	}
}

// proxyBind implements conn.Bind by routing WireGuard's UDP traffic through
// an upstream dialer, enabling proxy chaining (e.g. socks5 -> wireguard).
type proxyBind struct {
	upstream proxyclient.Dial
	endpoint string

	mu      sync.Mutex
	udpConn net.Conn
	closed  bool
}

func newProxyBind(upstream proxyclient.Dial, endpoint string) *proxyBind {
	return &proxyBind{upstream: upstream, endpoint: endpoint}
}

func (b *proxyBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, 0, net.ErrClosed
	}

	c, err := b.upstream(context.Background(), "udp", b.endpoint)
	if err != nil {
		return nil, 0, fmt.Errorf("wireguard bind: %w", err)
	}
	b.udpConn = c

	ep := &proxyEndpoint{dst: b.endpoint}

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := c.Read(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}

	return []conn.ReceiveFunc{recv}, 0, nil
}

func (b *proxyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.udpConn != nil {
		err := b.udpConn.Close()
		b.udpConn = nil
		return err
	}
	return nil
}

func (b *proxyBind) SetMark(mark uint32) error { return nil }

func (b *proxyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.udpConn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *proxyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &proxyEndpoint{dst: s}, nil
}

func (b *proxyBind) BatchSize() int { return 1 }

type proxyEndpoint struct {
	dst string
}

func (e *proxyEndpoint) ClearSrc() {}

func (e *proxyEndpoint) SrcToString() string { return "" }

func (e *proxyEndpoint) DstToString() string { return e.dst }

func (e *proxyEndpoint) DstToBytes() []byte {
	ap, err := netip.ParseAddrPort(e.dst)
	if err != nil {
		return nil
	}
	b, _ := ap.MarshalBinary()
	return b
}

func (e *proxyEndpoint) DstIP() netip.Addr {
	ap, _ := netip.ParseAddrPort(e.dst)
	return ap.Addr()
}

func (e *proxyEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
