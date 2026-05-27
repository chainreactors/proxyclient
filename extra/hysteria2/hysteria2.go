
package hysteria2

import (
	"github.com/chainreactors/proxyclient"
	"context"
	"errors"
	"net"
	"net/url"
	"sync"

	"github.com/apernet/hysteria/core/v2/client"
)

func init() {
	proxyclient.RegisterScheme("HYSTERIA2", newHysteria2ProxyClient)
	proxyclient.RegisterScheme("HY2", newHysteria2ProxyClient)
}

func newHysteria2ProxyClient(proxy *url.URL, _ proxyclient.Dial) (proxyclient.Dial, error) {
	var password string
	if proxy.User != nil {
		password = proxy.User.Username()
	}
	if password == "" {
		password = proxy.Query().Get("auth")
	}

	query := proxy.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = proxy.Hostname()
	}
	insecure := query.Get("insecure") == "1" || query.Get("insecure") == "true"

	host := proxy.Hostname()
	port := proxy.Port()
	if port == "" {
		port = "443"
	}
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	cfg := &client.Config{
		ServerAddr: serverAddr,
		Auth:       password,
		TLSConfig: client.TLSConfig{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
		},
	}

	var (
		mu sync.Mutex
		c  client.Client
	)

	getClient := func() (client.Client, error) {
		mu.Lock()
		defer mu.Unlock()
		if c != nil {
			return c, nil
		}
		newClient, _, err := client.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		c = newClient
		return c, nil
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		hyClient, err := getClient()
		if err != nil {
			return nil, err
		}
		conn, err := hyClient.TCP(address)
		if err != nil {
			// reset client on error so next dial reconnects
			mu.Lock()
			c = nil
			mu.Unlock()
			return nil, err
		}
		return conn, nil
	}
	return dial, nil
}

// Ensure hysteria2 has a placeholder for when the scheme is registered
// but connections need to be cleaned up.
var _ proxyclient.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("hysteria2: not connected")
}
