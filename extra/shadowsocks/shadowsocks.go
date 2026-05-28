package shadowsocks

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/chainreactors/proxyclient"
	ss "github.com/shadowsocks/go-shadowsocks2/core"
)

func init() {
	proxyclient.RegisterScheme("SS", newShadowsocksProxyClient)
	proxyclient.RegisterScheme("SHADOWSOCKS", newShadowsocksProxyClient)
}

func newShadowsocksProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	proxy, err := decodedBase64EncodedURL(proxy)
	if err != nil {
		return nil, err
	}
	if proxy.User == nil {
		return nil, errors.New("method and password is not available")
	}
	password, ok := proxy.User.Password()
	if !ok {
		return nil, errors.New("password is not available")
	}
	method := proxy.User.Username()
	cipher, err := ss.PickCipher(method, nil, password)
	if err != nil {
		return nil, err
	}

	serverAddr := proxy.Host
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := upstreamDial(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		conn = cipher.StreamConn(conn)
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			conn.Close()
			return nil, err
		}
		portI, err := strconv.Atoi(port)
		if err != nil {
			conn.Close()
			return nil, err
		}
		addr, err := buildSSAddr(host, portI)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err = conn.Write(addr); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return dial, nil
}

func buildSSAddr(host string, port int) ([]byte, error) {
	if len(host) == 0 {
		return nil, errors.New("empty host")
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = make([]byte, 1+net.IPv4len+2)
			buf[0] = 0x01
			copy(buf[1:], ip4)
		} else {
			buf = make([]byte, 1+net.IPv6len+2)
			buf[0] = 0x04
			copy(buf[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("target host name too long")
		}
		buf = make([]byte, 1+1+len(host)+2)
		buf[0] = 0x03
		buf[1] = byte(len(host))
		copy(buf[2:], []byte(host))
	}

	buf[len(buf)-2], buf[len(buf)-1] = byte(port>>8), byte(port)
	return buf, nil
}

func decodedBase64EncodedURL(proxy *url.URL) (*url.URL, error) {
	if proxy.Scheme == "" && proxy.Host == "" {
		return proxy, nil
	}
	content, err := base64.StdEncoding.DecodeString(proxy.Host)
	if err == nil {
		return proxy.Parse(proxy.Scheme + "://" + string(content))
	}
	return proxy, nil
}
