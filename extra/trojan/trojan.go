
package trojan

import (
	"github.com/chainreactors/proxyclient"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"sync"
)

func init() {
	proxyclient.RegisterScheme("TROJAN", newTrojanProxyClient)
}

func newTrojanProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	if proxy.User == nil {
		return nil, errors.New("trojan: password is required")
	}
	password := proxy.User.Username()
	if password == "" {
		return nil, errors.New("trojan: password is empty")
	}

	hash := sha256.New224()
	hash.Write([]byte(password))
	var passHex [56]byte
	hex.Encode(passHex[:], hash.Sum(nil))

	query := proxy.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = proxy.Hostname()
	}
	allowInsecure := query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1"

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: allowInsecure,
	}

	serverAddr := proxy.Host

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := upstreamDial(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tlsConf)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		addr, err := buildTrojanAddr(host, port)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		return &trojanConn{Conn: tlsConn, passHex: passHex, addr: addr}, nil
	}
	return dial, nil
}

var trojanCRLF = []byte{0x0D, 0x0A}

type trojanConn struct {
	net.Conn
	passHex    [56]byte
	addr       []byte
	mu         sync.Mutex
	headerSent bool
}

func (c *trojanConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.headerSent {
		c.headerSent = true
		c.mu.Unlock()

		// header: SHA224_hex(56) + CRLF(2) + CMD(1) + ATYP+ADDR+PORT(var) + CRLF(2) + payload
		headerLen := 56 + 2 + 1 + len(c.addr) + 2
		buf := make([]byte, headerLen+len(p))
		copy(buf, c.passHex[:])
		copy(buf[56:], trojanCRLF)
		buf[58] = 0x01 // CMD: TCP CONNECT
		copy(buf[59:], c.addr)
		copy(buf[59+len(c.addr):], trojanCRLF)
		copy(buf[headerLen:], p)

		_, err := c.Conn.Write(buf)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// buildTrojanAddr encodes a target address in SOCKS5 ATYP format.
// Format: ATYP(1) + DST.ADDR(variable) + DST.PORT(2, big-endian)
func buildTrojanAddr(host string, port int) ([]byte, error) {
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
			return nil, errors.New("host name too long")
		}
		buf = make([]byte, 1+1+len(host)+2)
		buf[0] = 0x03
		buf[1] = byte(len(host))
		copy(buf[2:], host)
	}
	buf[len(buf)-2] = byte(port >> 8)
	buf[len(buf)-1] = byte(port)
	return buf, nil
}
