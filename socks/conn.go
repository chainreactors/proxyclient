package socksproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
)

type SOCKSConf struct {
	Auth        func(username, password string) bool
	Dial        func(ctx context.Context, network, address string) (net.Conn, error)
	HandleError func(error)
	TLSConfig   *tls.Config
}

func IsSOCKS(r io.Reader) bool {
	header := make([]byte, 1)
	if _, err := r.Read(header); err != nil {
		return false
	}
	return header[0] == 4 || header[0] == 5
}
