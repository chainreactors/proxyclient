package loadbalance

import (
	"context"
	"hash/crc32"
	"net"

	"github.com/chainreactors/proxyclient"
)

func NewHash(proxies []proxyclient.Dial) proxyclient.Dial {
	t := NewTracker(proxies)

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		alive := t.AliveIndices()
		checksum := crc32.ChecksumIEEE([]byte(address))
		pick := alive[int(checksum)%len(alive)]
		return t.Dial(ctx, network, address, pick)
	}
}
