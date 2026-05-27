
package anytls

import (
	"github.com/chainreactors/proxyclient"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"

	anytls "github.com/anytls/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
)

func init() {
	proxyclient.RegisterScheme("ANYTLS", newAnyTLSProxyClient)
}

func newAnyTLSProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	var password string
	if proxy.User != nil {
		password = proxy.User.Username()
	}
	if password == "" {
		return nil, errors.New("anytls: password is required")
	}

	query := proxy.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = proxy.Hostname()
	}
	insecure := query.Get("insecure") == "1" || query.Get("insecure") == "true"

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
	}
	serverAddr := proxy.Host

	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			conn, err := upstreamDial(ctx, "tcp", serverAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, tlsConf)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	})
	if err != nil {
		return nil, err
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dest := M.ParseSocksaddr(address)
		return client.CreateProxy(ctx, dest)
	}
	return dial, nil
}
