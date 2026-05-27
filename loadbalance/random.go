package loadbalance

import (
	"context"
	"math/rand"
	"net"

	"github.com/chainreactors/proxyclient"
)

func NewRandom(proxies []proxyclient.Dial) proxyclient.Dial {
	t := NewTracker(proxies)

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		alive := t.AliveIndices()
		pick := alive[rand.Intn(len(alive))]
		return t.Dial(ctx, network, address, pick)
	}
}
