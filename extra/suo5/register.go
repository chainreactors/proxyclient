package suo5

import (
	"context"
	"net"
	"net/url"

	"github.com/chainreactors/proxyclient"
)

func init() {
	proxyclient.RegisterScheme("SUO5", NewClient)
	proxyclient.RegisterScheme("SUO5S", NewClient)
}

func NewClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	conf, err := NewConfFromURL(proxy)
	if err != nil {
		return nil, err
	}
	if upstreamDial != nil {
		conf.ProxyClient = upstreamDial
	}
	c := &Suo5Client{
		Proxy: proxy,
		Conf:  conf,
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.Dial(network, address)
	}, nil
}
