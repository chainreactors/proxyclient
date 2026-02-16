package socksproxy

import (
	"context"
	"crypto/tls"
	"net"
)

type SOCKSConf struct {
	Dial      func(ctx context.Context, network, address string) (net.Conn, error)
	TLSConfig *tls.Config
}
