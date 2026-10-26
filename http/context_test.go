package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestConnectSendsUsernameWithoutPassword(t *testing.T) {
	for _, user := range []*url.Userinfo{url.User("call-1"), url.UserPassword("call-2", ""), url.UserPassword("call-3", "secret")} {
		t.Run(user.Username(), func(t *testing.T) {
			clientConn, proxyConn := net.Pipe()
			t.Cleanup(func() { clientConn.Close(); proxyConn.Close() })
			header := make(chan string, 1)
			go func() {
				req, err := http.ReadRequest(bufio.NewReader(proxyConn))
				if err != nil {
					header <- ""
					return
				}
				header <- req.Header.Get("Proxy-Authorization")
				_, _ = io.WriteString(proxyConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			}()
			client := NewClient(url.URL{Scheme: "http", Host: "proxy.test", User: user}, func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
			conn, err := client.Dial(context.Background(), "tcp", "target.test:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			password, _ := user.Password()
			want := encodeBasicAuth(user.Username(), password)
			if got := <-header; got != want {
				t.Fatalf("CONNECT omitted or changed its proxy identity: got %q, want %q", got, want)
			}
		})
	}
}

func TestDialPassesCallerContextToUpstream(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "caller"), time.Second)
	defer cancel()
	sentinel := errors.New("upstream refused")
	client := NewClient(url.URL{Scheme: "http", Host: "proxy.test"}, func(got context.Context, _, _ string) (net.Conn, error) {
		if got.Value(contextKey{}) != "caller" {
			t.Error("upstream lost caller context")
		}
		if _, ok := got.Deadline(); !ok {
			t.Error("upstream lost caller deadline")
		}
		return nil, sentinel
	})
	if _, err := client.Dial(ctx, "tcp", "target.test:443"); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v", err)
	}
}

func TestDialCancellationInterruptsHandshake(t *testing.T) {
	for _, phase := range []string{"request write", "response read", "tls handshake"} {
		t.Run(phase, func(t *testing.T) {
			clientConn, proxyConn := net.Pipe()
			t.Cleanup(func() { clientConn.Close(); proxyConn.Close() })
			if phase == "response read" {
				go func() { _, _ = http.ReadRequest(bufio.NewReader(proxyConn)) }()
			}
			scheme := "http"
			if phase == "tls handshake" {
				scheme = "https"
			}
			client := NewClient(url.URL{Scheme: scheme, Host: "proxy.test"}, func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
			client.TLSConfig = &tls.Config{ServerName: "proxy.test", MinVersion: tls.VersionTLS12}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := client.Dial(ctx, "tcp", "target.test:443")
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error = %v, want caller deadline", err)
				}
			case <-time.After(time.Second):
				clientConn.Close()
				<-done
				t.Fatal("CONNECT ignored caller timeout")
			}
		})
	}
}

func TestSuccessfulTunnelOutlivesDialContext(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); proxyConn.Close() })
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(proxyConn))
		_, _ = io.WriteString(proxyConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	client := NewClient(url.URL{Scheme: "http", Host: "proxy.test"}, func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := client.Dial(ctx, "tcp", "target.test:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = io.WriteString(proxyConn, "still connected") }()
	body := make([]byte, len("still connected"))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("dial cancellation closed an established tunnel: %v", err)
	}
}
