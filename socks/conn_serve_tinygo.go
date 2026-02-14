//go:build tinygo

package socksproxy

import (
	"net"
)

func Serve(listener net.Listener, conf *SOCKSConf) {
	if conf.HandleError == nil {
		conf.HandleError = func(_ error) {}
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			conf.HandleError(err)
			continue
		}
		go handleConn(conn, conf)
	}
}

func handleConn(conn net.Conn, conf *SOCKSConf) {
	var err error
	buffer := make([]byte, 1)
	if _, err = conn.Read(buffer); err != nil {
		conf.HandleError(err)
		return
	}
	switch buffer[0] {
	case socks4version:
		if conf.Auth != nil || conf.TLSConfig != nil {
			return
		}
		socksConn := &socks4Conn{conn, conf}
		err = socksConn.Serve()
	case socks5version:
		// TinyGo does not support tls.Server; TLS wrapping is skipped.
		socksConn := &socks5Conn{conn, conf}
		err = socksConn.Serve()
	}
	if err != nil {
		conf.HandleError(err)
		return
	}
}
