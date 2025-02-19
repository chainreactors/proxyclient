//go:build neoreg
// +build neoreg

package extend

import (
	"context"
	"github.com/chainreactors/proxyclient"
	"github.com/chainreactors/proxyclient/neoreg"
	"net"
	"net/url"
)

func init() {
	proxyclient.RegisterScheme("NEOREG", NewNeoregClient)
	proxyclient.RegisterScheme("NEOREGS", NewNeoregClient)
}

func NewNeoregClient(proxy *url.URL, upstreamDial proxyclient.Dial) (dial proxyclient.Dial, err error) {
	conf, err := neoreg.NewConfFromURL(proxy)
	if err != nil {
		return nil, err
	}
	if upstreamDial != nil {
		conf.Dial = upstreamDial
	}
	client := &neoreg.NeoregClient{
		Proxy: proxy,
		Conf:  conf,
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.Dial(network, address)
	}, nil
}
