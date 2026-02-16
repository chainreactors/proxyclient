package socksproxy

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
)

// startTCPEchoServer starts a TCP server that echoes back whatever it receives.
func startTCPEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

// startUDPEchoServer starts a UDP server that echoes back whatever it receives.
func startUDPEchoServer(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], remote)
		}
	}()
	return conn
}

// startSocks5Server starts a standard SOCKS5 server using things-go/go-socks5.
func startSocks5Server(t *testing.T) net.Listener {
	t.Helper()
	server := socks5.NewServer(
		socks5.WithBindIP(net.ParseIP("127.0.0.1")),
		socks5.WithRule(socks5.NewPermitAll()),
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(ln)
	return ln
}

func TestSocks5Client_TCP_Connect(t *testing.T) {
	echoLn := startTCPEchoServer(t)
	defer echoLn.Close()

	proxyLn := startSocks5Server(t)
	defer proxyLn.Close()

	proxyURL, _ := url.Parse("socks5://" + proxyLn.Addr().String())
	client := &Socks5Client{
		proxy: proxyURL,
		conf:  &SOCKSConf{Dial: (&net.Dialer{}).DialContext},
	}

	conn, err := client.Dial(context.Background(), "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("TCP Dial failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello via socks5 tcp")
	if _, err = conn.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
	t.Logf("TCP CONNECT OK: sent and received %q", msg)
}

func TestSocks5Client_UDP_Associate(t *testing.T) {
	echoConn := startUDPEchoServer(t)
	defer echoConn.Close()

	proxyLn := startSocks5Server(t)
	defer proxyLn.Close()

	proxyURL, _ := url.Parse("socks5://" + proxyLn.Addr().String())
	client := &Socks5Client{
		proxy: proxyURL,
		conf:  &SOCKSConf{Dial: (&net.Dialer{}).DialContext},
	}

	conn, err := client.Dial(context.Background(), "udp", echoConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("UDP Dial failed: %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*socks5UDPConn); !ok {
		t.Fatalf("expected *socks5UDPConn, got %T", conn)
	}

	msg := []byte("hello via socks5 udp")
	if _, err = conn.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf[:n], msg)
	}
	t.Logf("UDP ASSOCIATE OK: sent and received %q", msg)
}

func TestSocks5UDPDatagram_RoundTrip(t *testing.T) {
	// IPv4
	orig := &socks5UDPDatagram{
		frag: 0,
		addr: &socks5Addr{
			addrType: socks5AddressTypeIPv4,
			addr:     net.IPv4(127, 0, 0, 1).To4(),
			port:     []byte{0x1F, 0x90}, // 8080
		},
		data: []byte("test payload"),
	}
	encoded := orig.ToBytes()
	decoded, err := parseSocks5UDPDatagram(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if decoded.frag != orig.frag {
		t.Fatalf("frag mismatch: %d vs %d", decoded.frag, orig.frag)
	}
	if decoded.addr.addrType != orig.addr.addrType {
		t.Fatalf("addrType mismatch: %d vs %d", decoded.addr.addrType, orig.addr.addrType)
	}
	if string(decoded.data) != string(orig.data) {
		t.Fatalf("data mismatch: %q vs %q", decoded.data, orig.data)
	}

	// FQDN (client-constructed: addr includes length prefix)
	host := "example.com"
	fqdnOrig := &socks5UDPDatagram{
		frag: 0,
		addr: &socks5Addr{
			addrType: socks5AddressTypeFQDN,
			addr:     append([]byte{byte(len(host))}, host...),
			port:     []byte{0x00, 0x50}, // 80
		},
		data: []byte("fqdn payload"),
	}
	fqdnDecoded, err := parseSocks5UDPDatagram(fqdnOrig.ToBytes())
	if err != nil {
		t.Fatalf("FQDN parse failed: %v", err)
	}
	if string(fqdnDecoded.data) != "fqdn payload" {
		t.Fatalf("FQDN data mismatch: %q", fqdnDecoded.data)
	}
	if string(fqdnDecoded.addr.addr) != host {
		t.Fatalf("FQDN addr mismatch: got %q, want %q", fqdnDecoded.addr.addr, host)
	}
	t.Log("UDP datagram round-trip OK")
}
