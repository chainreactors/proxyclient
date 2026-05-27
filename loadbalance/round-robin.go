package loadbalance

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/chainreactors/proxyclient"
)

func NewRoundRobin(proxies []proxyclient.Dial) proxyclient.Dial {
	t := NewTracker(proxies)
	var counter atomic.Int64

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		alive := t.AliveIndices()
		idx := int(counter.Add(1)-1) % len(alive)
		return t.Dial(ctx, network, address, alive[idx])
	}
}
