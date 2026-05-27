
package vmess

import (
	"github.com/chainreactors/proxyclient"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func init() {
	proxyclient.RegisterScheme("VMESS", newVMessProxyClient)
	proxyclient.RegisterScheme("VLESS", newVLessProxyClient)
}

// vmessJSON is the standard VMess sharing format.
type vmessJSON struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
}

func newVMessProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	var info vmessJSON
	var serverAddr string

	// vmess URLs can be either base64(json) in Host or query-parameter based
	if raw, err := base64Decode(proxy.Host + proxy.Path); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, errors.New("vmess: invalid base64 JSON payload")
		}
		serverAddr = net.JoinHostPort(info.Add, info.Port)
	} else {
		// query-parameter style: vmess://server:port?id=xxx&security=xxx
		info = vmessJSON{
			Add:  proxy.Hostname(),
			Port: proxy.Port(),
			ID:   proxy.Query().Get("id"),
			Aid:  proxy.Query().Get("aid"),
			Scy:  proxy.Query().Get("security"),
			Net:  proxy.Query().Get("net"),
			TLS:  proxy.Query().Get("tls"),
			SNI:  proxy.Query().Get("sni"),
			Host: proxy.Query().Get("host"),
			Path: proxy.Query().Get("path"),
		}
		serverAddr = proxy.Host
	}

	if info.ID == "" {
		return nil, errors.New("vmess: uuid is required")
	}
	if info.Scy == "" {
		info.Scy = "auto"
	}

	alterId := 0
	if info.Aid != "" {
		alterId, _ = strconv.Atoi(info.Aid)
	}

	client, err := vmess.NewClient(info.ID, info.Scy, alterId)
	if err != nil {
		return nil, err
	}

	useTLS := strings.EqualFold(info.TLS, "tls")
	sni := info.SNI
	if sni == "" {
		sni = info.Host
	}
	if sni == "" {
		sni = info.Add
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := upstreamDial(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		if useTLS {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: sni})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
		dest := M.ParseSocksaddr(address)
		vmessConn, err := client.DialConn(conn, dest)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return vmessConn, nil
	}
	return dial, nil
}

func newVLessProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	var uuid string
	if proxy.User != nil {
		uuid = proxy.User.Username()
	}
	if uuid == "" {
		uuid = proxy.Query().Get("id")
	}
	if uuid == "" {
		return nil, errors.New("vless: uuid is required")
	}

	query := proxy.Query()
	flow := query.Get("flow")
	security := strings.ToLower(query.Get("security"))
	sni := query.Get("sni")
	if sni == "" {
		sni = proxy.Hostname()
	}
	allowInsecure := query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1"

	client, err := vless.NewClient(uuid, flow, logger.NOP())
	if err != nil {
		return nil, err
	}

	serverAddr := proxy.Host

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := upstreamDial(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		// VLESS typically requires TLS
		if security != "none" && security != "" {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: allowInsecure,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
		dest := M.ParseSocksaddr(address)
		vlessConn, err := client.DialConn(conn, dest)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return vlessConn, nil
	}
	return dial, nil
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// try standard, then URL-safe, then without padding
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
