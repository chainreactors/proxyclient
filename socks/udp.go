package socksproxy

import (
	"errors"
	"net"
	"sync"
	"time"
)

// socks5UDPDatagram represents a SOCKS5 UDP request/response header per RFC 1928 Section 7.
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
type socks5UDPDatagram struct {
	frag byte
	addr *socks5Addr
	data []byte
}

func (d *socks5UDPDatagram) ToBytes() []byte {
	buf := []byte{0x00, 0x00, d.frag}
	buf = append(buf, d.addr.addrType)
	buf = append(buf, d.addr.addr...)
	buf = append(buf, d.addr.port...)
	buf = append(buf, d.data...)
	return buf
}

func parseSocks5UDPDatagram(buf []byte) (*socks5UDPDatagram, error) {
	if len(buf) < 4 {
		return nil, errors.New("udp datagram too short")
	}
	d := &socks5UDPDatagram{
		frag: buf[2],
		addr: &socks5Addr{addrType: buf[3]},
	}
	pos := 4
	switch d.addr.addrType {
	case socks5AddressTypeIPv4:
		if len(buf) < pos+net.IPv4len+2 {
			return nil, errors.New("udp datagram too short for IPv4")
		}
		d.addr.addr = make([]byte, net.IPv4len)
		copy(d.addr.addr, buf[pos:pos+net.IPv4len])
		pos += net.IPv4len
	case socks5AddressTypeIPv6:
		if len(buf) < pos+net.IPv6len+2 {
			return nil, errors.New("udp datagram too short for IPv6")
		}
		d.addr.addr = make([]byte, net.IPv6len)
		copy(d.addr.addr, buf[pos:pos+net.IPv6len])
		pos += net.IPv6len
	case socks5AddressTypeFQDN:
		if len(buf) < pos+1 {
			return nil, errors.New("udp datagram too short for FQDN length")
		}
		fqdnLen := int(buf[pos])
		pos++
		if len(buf) < pos+fqdnLen+2 {
			return nil, errors.New("udp datagram too short for FQDN")
		}
		d.addr.addr = make([]byte, fqdnLen)
		copy(d.addr.addr, buf[pos:pos+fqdnLen])
		pos += fqdnLen
	default:
		return nil, errAddressTypeNotSupported
	}
	d.addr.port = make([]byte, 2)
	copy(d.addr.port, buf[pos:pos+2])
	pos += 2
	d.data = buf[pos:]
	return d, nil
}

// socks5UDPConn wraps a UDP connection to a SOCKS5 relay, implementing net.Conn.
// It adds/strips the SOCKS5 UDP datagram header on Write/Read and monitors
// the TCP control connection — closing the UDP socket when TCP drops.
type socks5UDPConn struct {
	udpConn *net.UDPConn
	tcpConn net.Conn
	target  *socks5Addr

	closeOnce sync.Once
	done      chan struct{}
}

func newSocks5UDPConn(udpConn *net.UDPConn, tcpConn net.Conn, target *socks5Addr) *socks5UDPConn {
	c := &socks5UDPConn{
		udpConn: udpConn,
		tcpConn: tcpConn,
		target:  target,
		done:    make(chan struct{}),
	}
	go c.monitorTCP()
	return c
}

// monitorTCP watches the TCP control connection. Per RFC 1928, when the TCP
// connection used to establish the UDP ASSOCIATE is closed, the UDP relay
// must also terminate.
func (c *socks5UDPConn) monitorTCP() {
	buf := make([]byte, 1)
	c.tcpConn.Read(buf)
	c.Close()
}

func (c *socks5UDPConn) Read(b []byte) (int, error) {
	buf := make([]byte, 65535)
	n, err := c.udpConn.Read(buf)
	if err != nil {
		return 0, err
	}
	d, err := parseSocks5UDPDatagram(buf[:n])
	if err != nil {
		return 0, err
	}
	if d.frag != 0 {
		return 0, errors.New("fragmented udp datagrams not supported")
	}
	return copy(b, d.data), nil
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	d := &socks5UDPDatagram{
		frag: 0,
		addr: c.target,
		data: b,
	}
	_, err := c.udpConn.Write(d.ToBytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		e1 := c.udpConn.Close()
		e2 := c.tcpConn.Close()
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
	})
	return err
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.udpConn.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr                { return c.udpConn.RemoteAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error       { return c.udpConn.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error   { return c.udpConn.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error  { return c.udpConn.SetWriteDeadline(t) }
