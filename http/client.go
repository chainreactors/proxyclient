package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	Proxy        url.URL
	TLSConfig    *tls.Config
	UpstreamDial func(ctx context.Context, network, address string) (net.Conn, error)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func NewClient(proxy url.URL, dial func(ctx context.Context, network, address string) (net.Conn, error)) *Client {
	return &Client{proxy, nil, dial}
}

func (client *Client) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	switch strings.ToUpper(client.Proxy.Scheme) {
	case "HTTP", "HTTPS":
	default:
		err = errors.New("Proxy URL Scheme not HTTP or HTTPS")
		return
	}

	if conn, err = client.connect(ctx, network, client.Proxy.Host); err != nil {
		return
	}
	// Request.Write and ReadResponse do not accept a context. Close the socket
	// on cancellation while CONNECT is in progress, then detach the callback
	// before handing ownership of an established tunnel to the caller.
	rawConn := conn
	canceled := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		rawConn.Close()
		close(canceled)
	})
	defer func() {
		if !stopCancel() {
			<-canceled
			err = ctx.Err()
		}
		if err != nil {
			rawConn.Close()
			conn = nil
		}
	}()

	var request *http.Request
	var response *http.Response
	reader := bufio.NewReader(conn)

	if request, err = client.newRequest(address); err != nil {
		conn.Close()
		return
	}
	if err = request.Write(conn); err != nil {
		conn.Close()
		return
	}
	if response, err = http.ReadResponse(reader, request); err != nil {
		conn.Close()
		return
	}
	if response.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", response.Status)
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (client *Client) connect(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = client.UpstreamDial(ctx, network, address)
	if err != nil {
		return
	}
	if strings.ToUpper(client.Proxy.Scheme) == "HTTPS" {
		tlsConn := tls.Client(conn, client.TLSConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			conn = nil
			return
		}
		conn = tlsConn
	}
	return
}

func (client *Client) newRequest(address string) (*http.Request, error) {
	//remoteHost, _, err := net.SplitHostPort(address)
	//if err != nil {
	//	return nil, err
	//}
	request, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		return nil, err
	}
	request.RequestURI = address
	request.URL.Host = address
	setBasicAuth(request, client.Proxy.User)
	return request, nil
}

func setBasicAuth(request *http.Request, user *url.Userinfo) {
	if user == nil {
		return
	}
	password, _ := user.Password()
	request.Header.Set(authorization, encodeBasicAuth(user.Username(), password))
}
