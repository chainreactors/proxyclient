package httpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDialPreservesBytesBufferedAfterConnectResponse(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		proxyConn.Close()
	})

	proxyDone := make(chan error, 1)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(proxyConn))
		if err != nil {
			proxyDone <- err
			return
		}
		request.Body.Close()
		_, err = io.WriteString(proxyConn, "HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-TestServer\r\n")
		proxyDone <- err
	}()

	proxyURL, err := url.Parse("http://proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(*proxyURL, func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	conn, err := client.Dial(context.Background(), "tcp", "target.test:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	banner := make([]byte, len("SSH-2.0-TestServer\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatal(err)
	}
	if got := string(banner); got != "SSH-2.0-TestServer\r\n" {
		t.Fatalf("banner = %q", got)
	}
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialRejectsNonSuccessfulConnect(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(proxyConn))
		_, _ = io.WriteString(proxyConn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	}()

	proxyURL, err := url.Parse("http://proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(*proxyURL, func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	conn, err := client.Dial(context.Background(), "tcp", "target.test:22")
	if conn != nil {
		conn.Close()
		t.Fatal("Dial returned a connection for a rejected CONNECT request")
	}
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("Dial error = %v, want HTTP 407", err)
	}
}
