package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/proxyclient"
	sagtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestHandlerPrepareConnection(t *testing.T) {
	h := newHandler(nil)
	if _, err := h.PrepareConnection(N.NetworkTCP, M.Socksaddr{}, M.Socksaddr{}, nil, 0); err != nil {
		t.Fatalf("tcp should be accepted: %v", err)
	}
	if _, err := h.PrepareConnection(N.NetworkUDP, M.Socksaddr{}, M.Socksaddr{}, nil, 0); err != nil {
		t.Fatalf("udp should be accepted: %v", err)
	}
	if _, err := h.PrepareConnection(N.NetworkICMP, M.Socksaddr{}, M.Socksaddr{}, nil, 0); !errors.Is(err, sagtun.ErrDrop) {
		t.Fatalf("icmp should be dropped, got %v", err)
	}
}

func TestHandlerTCPForwarding(t *testing.T) {
	inboundStack, inboundClient := net.Pipe()
	outboundProxy, outboundTarget := net.Pipe()
	defer inboundClient.Close()
	defer outboundTarget.Close()

	destination := M.ParseSocksaddr("198.51.100.10:443")
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("unexpected network: %s", network)
		}
		if address != destination.String() {
			t.Fatalf("unexpected destination: %s", address)
		}
		return outboundProxy, nil
	}

	done := make(chan error, 1)
	go newHandler(proxyclient.Dial(dial)).NewConnectionEx(context.Background(), inboundStack, M.ParseSocksaddr("172.19.0.2:40000"), destination, func(err error) {
		done <- err
	})

	mustWriteRead(t, inboundClient, outboundTarget, []byte("client to target"))
	mustWriteRead(t, outboundTarget, inboundClient, []byte("target to client"))

	inboundClient.Close()
	outboundTarget.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop after both pipes closed")
	}
}

func TestHandlerUDPForwarding(t *testing.T) {
	outboundProxy, outboundTarget := net.Pipe()
	defer outboundTarget.Close()

	stackConn := newFakePacketConn(M.ParseSocksaddr("172.19.0.2:53000"))
	destination := M.ParseSocksaddr("198.51.100.53:53")
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" {
			t.Fatalf("unexpected network: %s", network)
		}
		if address != destination.String() {
			t.Fatalf("unexpected destination: %s", address)
		}
		return outboundProxy, nil
	}

	done := make(chan error, 1)
	go newHandler(proxyclient.Dial(dial)).NewPacketConnectionEx(context.Background(), stackConn, M.ParseSocksaddr("172.19.0.2:53000"), destination, func(err error) {
		done <- err
	})

	stackConn.pushPacket([]byte("query"), destination)
	readWithDeadline(t, outboundTarget, []byte("query"))

	writeWithDeadline(t, outboundTarget, []byte("response"))
	packet := stackConn.popPacket(t)
	if string(packet.data) != "response" {
		t.Fatalf("unexpected response data: %q", string(packet.data))
	}
	if packet.destination != destination {
		t.Fatalf("unexpected response destination: %v", packet.destination)
	}

	stackConn.Close()
	outboundTarget.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop after packet connection closed")
	}
}

func mustWriteRead(t *testing.T, writer net.Conn, reader net.Conn, payload []byte) {
	t.Helper()
	writeWithDeadline(t, writer, payload)
	readWithDeadline(t, reader, payload)
}

func writeWithDeadline(t *testing.T, writer net.Conn, payload []byte) {
	t.Helper()
	if err := writer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func readWithDeadline(t *testing.T, reader net.Conn, expected []byte) {
	t.Helper()
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(expected) {
		t.Fatalf("expected %q, got %q", string(expected), string(got))
	}
}

type fakePacket struct {
	data        []byte
	destination M.Socksaddr
}

type fakePacketConn struct {
	local    M.Socksaddr
	inbound  chan fakePacket
	outbound chan fakePacket
	done     chan struct{}
	once     sync.Once
}

func newFakePacketConn(local M.Socksaddr) *fakePacketConn {
	return &fakePacketConn{
		local:    local,
		inbound:  make(chan fakePacket, 4),
		outbound: make(chan fakePacket, 4),
		done:     make(chan struct{}),
	}
}

func (c *fakePacketConn) pushPacket(data []byte, destination M.Socksaddr) {
	c.inbound <- fakePacket{data: append([]byte(nil), data...), destination: destination}
}

func (c *fakePacketConn) popPacket(t *testing.T) fakePacket {
	t.Helper()
	select {
	case packet := <-c.outbound:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet")
		return fakePacket{}
	}
}

func (c *fakePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.inbound:
		_, err := buffer.Write(packet.data)
		return packet.destination, err
	case <-c.done:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (c *fakePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.outbound <- fakePacket{data: append([]byte(nil), buffer.Bytes()...), destination: destination}
	return nil
}

func (c *fakePacketConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr              { return c.local }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ N.PacketConn = (*fakePacketConn)(nil)
