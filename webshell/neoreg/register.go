//go:build neoreg
// +build neoreg

package neoreg

import (
	"context"
	"net"
	"net/url"

	"github.com/chainreactors/proxyclient"
)

func init() {
	proxyclient.RegisterScheme("NEOREG", NewClient)
	proxyclient.RegisterScheme("NEOREGS", NewClient)
}

func NewClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	conf, err := NewConfFromURL(proxy)
	if err != nil {
		return nil, err
	}
	if upstreamDial != nil {
		conf.Dial = upstreamDial
	}
	client := &NeoregClient{
		Proxy: proxy,
		Conf:  conf,
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.Dial(network, address)
	}, nil
}
