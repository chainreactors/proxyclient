package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/chainreactors/proxyclient"
)

func init() {
	proxyclient.RegisterScheme("WG", newWireGuardProxyClient)
	proxyclient.RegisterScheme("WIREGUARD", newWireGuardProxyClient)
}

type wgConfig struct {
	endpoint     string
	privateKey   string // hex-encoded 32 bytes
	publicKey    string // hex-encoded 32 bytes
	presharedKey string // hex-encoded 32 bytes, optional
	addresses    []netip.Addr
	dns          []netip.Addr
	mtu          int
	reserved     [3]byte
}

func parseConfig(proxy *url.URL) (*wgConfig, error) {
	query := proxy.Query()

	privKeyB64 := query.Get("private-key")
	if privKeyB64 == "" {
		return nil, fmt.Errorf("wireguard: missing private-key")
	}
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		privKeyBytes, err = base64.RawStdEncoding.DecodeString(privKeyB64)
		if err != nil {
			return nil, fmt.Errorf("wireguard: invalid private-key: %w", err)
		}
	}
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("wireguard: private-key must be 32 bytes, got %d", len(privKeyBytes))
	}

	pubKeyB64 := query.Get("public-key")
	if pubKeyB64 == "" {
		return nil, fmt.Errorf("wireguard: missing public-key")
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		pubKeyBytes, err = base64.RawStdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("wireguard: invalid public-key: %w", err)
		}
	}
	if len(pubKeyBytes) != 32 {
		return nil, fmt.Errorf("wireguard: public-key must be 32 bytes, got %d", len(pubKeyBytes))
	}

	addrStr := query.Get("address")
	if addrStr == "" {
		return nil, fmt.Errorf("wireguard: missing address")
	}
	var addresses []netip.Addr
	for _, s := range strings.Split(addrStr, ",") {
		s = strings.TrimSpace(s)
		if prefix, err := netip.ParsePrefix(s); err == nil {
			addresses = append(addresses, prefix.Addr())
		} else if addr, err := netip.ParseAddr(s); err == nil {
			addresses = append(addresses, addr)
		} else {
			return nil, fmt.Errorf("wireguard: invalid address %q: %w", s, err)
		}
	}

	var dns []netip.Addr
	if dnsStr := query.Get("dns"); dnsStr != "" {
		for _, s := range strings.Split(dnsStr, ",") {
			s = strings.TrimSpace(s)
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("wireguard: invalid dns %q: %w", s, err)
			}
			dns = append(dns, addr)
		}
	}

	mtu := 1420
	if mtuStr := query.Get("mtu"); mtuStr != "" {
		mtu, err = strconv.Atoi(mtuStr)
		if err != nil || mtu < 576 || mtu > 65535 {
			return nil, fmt.Errorf("wireguard: invalid mtu %q", mtuStr)
		}
	}

	var presharedKey string
	if pskB64 := query.Get("preshared-key"); pskB64 != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(pskB64)
		if err != nil {
			pskBytes, err = base64.RawStdEncoding.DecodeString(pskB64)
			if err != nil {
				return nil, fmt.Errorf("wireguard: invalid preshared-key: %w", err)
			}
		}
		if len(pskBytes) != 32 {
			return nil, fmt.Errorf("wireguard: preshared-key must be 32 bytes, got %d", len(pskBytes))
		}
		presharedKey = hex.EncodeToString(pskBytes)
	}

	var reserved [3]byte
	if resStr := query.Get("reserved"); resStr != "" {
		parts := strings.SplitN(resStr, ",", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("wireguard: reserved must be 3 comma-separated bytes")
		}
		for i, p := range parts {
			v, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || v < 0 || v > 255 {
				return nil, fmt.Errorf("wireguard: invalid reserved byte %q", p)
			}
			reserved[i] = byte(v)
		}
	}

	host := proxy.Hostname()
	port := proxy.Port()
	if port == "" {
		port = "51820"
	}
	endpoint := net.JoinHostPort(host, port)

	return &wgConfig{
		endpoint:     endpoint,
		privateKey:   hex.EncodeToString(privKeyBytes),
		publicKey:    hex.EncodeToString(pubKeyBytes),
		presharedKey: presharedKey,
		addresses:    addresses,
		dns:          dns,
		mtu:          mtu,
		reserved:     reserved,
	}, nil
}

func (c *wgConfig) ipcConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.privateKey)
	fmt.Fprintf(&b, "public_key=%s\n", c.publicKey)
	fmt.Fprintf(&b, "endpoint=%s\n", c.endpoint)
	if c.presharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", c.presharedKey)
	}
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	b.WriteString("persistent_keepalive_interval=25\n")
	return b.String()
}

func newWireGuardProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	cfg, err := parseConfig(proxy)
	if err != nil {
		return nil, err
	}

	var (
		mu sync.Mutex
		t  *tunnel
	)

	getTunnel := func() (*tunnel, error) {
		mu.Lock()
		defer mu.Unlock()
		if t != nil {
			return t, nil
		}
		newTunnel, err := newTunnel(cfg, upstreamDial)
		if err != nil {
			return nil, fmt.Errorf("wireguard: %w", err)
		}
		t = newTunnel
		return t, nil
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		tun, err := getTunnel()
		if err != nil {
			return nil, err
		}
		conn, err := tun.dial(ctx, network, address)
		if err != nil {
			mu.Lock()
			if t == tun {
				tun.close()
				t = nil
			}
			mu.Unlock()
			return nil, fmt.Errorf("wireguard: %w", err)
		}
		return conn, nil
	}

	return dial, nil
}
