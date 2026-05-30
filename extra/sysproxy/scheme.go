package sysproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/chainreactors/proxyclient"
)

func init() {
	proxyclient.RegisterScheme("SYSPROXY", newSysProxyClient)
}

func newSysProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	detected, err := Detect()
	if err != nil {
		return nil, fmt.Errorf("sysproxy: detect: %w", err)
	}
	if detected == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return upstreamDial(ctx, network, address)
		}, nil
	}

	q := proxy.Query()
	if filter := q.Get("type"); filter != "" {
		switch filter {
		case "http":
			if detected.Type != ProxyHTTP {
				return upstreamDial, nil
			}
		case "socks", "socks5":
			if detected.Type != ProxySocks {
				return upstreamDial, nil
			}
		}
	}

	return proxyclient.NewClientWithDial(detected.URL(), upstreamDial)
}
