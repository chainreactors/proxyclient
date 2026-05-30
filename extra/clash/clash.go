package clash

import (
	"encoding/base64"
	"fmt"

	"github.com/chainreactors/proxyclient"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ProxyNode struct {
	Name      string
	Type      string // ss, socks5, trojan, vmess, vless, hysteria2, http
	Server    string
	Port      int
	URL       *url.URL
	RawConf   map[string]any
	Supported bool
}

type ProxyGroup struct {
	Name    string
	Type    string   // select, url-test, fallback, load-balance
	Proxies []string // member proxy names
}

type Subscription struct {
	Nodes  []ProxyNode
	Groups []ProxyGroup
}

type clashConfig struct {
	Proxies    []map[string]any `yaml:"proxies"`
	ProxyGroup []map[string]any `yaml:"proxy-groups"`
}

func FetchSubscription(subscribeURL string) (*Subscription, error) {
	return fetchWithUA(subscribeURL, "clash")
}

func fetchWithUA(subscribeURL, userAgent string) (*Subscription, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", subscribeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("clash: invalid subscribe URL: %w", err)
	}
	if userAgent == "" {
		userAgent = "clash"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clash: fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clash: subscription returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("clash: read response: %w", err)
	}
	return ParseSubscription(data)
}

func ParseSubscription(data []byte) (*Subscription, error) {
	// try Clash YAML first
	sub, err := parseYAML(data)
	if err == nil {
		return sub, nil
	}

	// try base64 decode then YAML
	decoded, decErr := tryBase64Decode(data)
	if decErr == nil {
		sub, yamlErr := parseYAML(decoded)
		if yamlErr == nil {
			return sub, nil
		}
		// base64 decoded but not YAML — try URI-per-line on decoded content
		sub, uriErr := parseURIList(decoded)
		if uriErr == nil {
			return sub, nil
		}
	}

	// try URI-per-line on raw data
	sub, uriErr := parseURIList(data)
	if uriErr == nil {
		return sub, nil
	}

	return nil, fmt.Errorf("clash: unrecognized subscription format (tried YAML, base64+YAML, URI-per-line)")
}

// parseURIList parses a subscription where each line is a proxy URI
// (e.g. ss://..., trojan://..., vmess://..., anytls://...).
func parseURIList(data []byte) (*Subscription, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	sub := &Subscription{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		node, err := parseURINode(line)
		if err != nil {
			continue
		}
		sub.Nodes = append(sub.Nodes, node)
	}
	if len(sub.Nodes) == 0 {
		return nil, fmt.Errorf("no valid proxy URIs found")
	}
	return sub, nil
}

func parseURINode(uri string) (ProxyNode, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ProxyNode{}, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return ProxyNode{}, fmt.Errorf("empty scheme")
	}

	// extract name from fragment (URL anchor #name)
	name := u.Fragment
	if decoded, err := url.PathUnescape(name); err == nil {
		name = decoded
	}

	node := ProxyNode{
		Name: name,
		Type: scheme,
		RawConf: map[string]any{
			"type": scheme,
			"uri":  uri,
		},
	}

	switch scheme {
	case "ss", "shadowsocks":
		return parseSSURI(u, node)
	case "trojan", "trojan-go":
		return parseTrojanURI(u, node)
	case "vmess":
		return parseVMessURI(u, node)
	case "vless":
		return parseVLessURI(u, node)
	case "hysteria2", "hy2":
		return parseHysteria2URI(u, node)
	case "anytls":
		return parseAnyTLSURI(u, node)
	case "wg", "wireguard":
		return parseWireGuardURI(u, node)
	case "socks5", "socks":
		return parseSocksURI(u, node)
	case "http", "https":
		return parseHTTPURI(u, node)
	default:
		// unknown but still include it as unsupported
		node.Server = u.Hostname()
		port, _ := strconv.Atoi(u.Port())
		node.Port = port
		node.URL = u
		node.Supported = false
		return node, nil
	}
}

func parseSSURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	// ss://base64(method:password)@server:port#name
	// or ss://method:password@server:port#name
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())

	var method, password string
	if u.User != nil {
		method = u.User.Username()
		password, _ = u.User.Password()
	}
	// if method looks like base64, decode it
	if password == "" && method != "" {
		if decoded, err := base64.StdEncoding.DecodeString(method); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				method = parts[0]
				password = parts[1]
			}
		} else if decoded, err := base64.RawStdEncoding.DecodeString(method); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				method = parts[0]
				password = parts[1]
			}
		}
	}

	if node.Server == "" || node.Port == 0 {
		return node, fmt.Errorf("ss: missing server or port")
	}

	node.URL = &url.URL{
		Scheme: "ss",
		User:   url.UserPassword(method, password),
		Host:   net.JoinHostPort(node.Server, strconv.Itoa(node.Port)),
	}
	node.Supported = true
	return node, nil
}

func parseTrojanURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if node.Server == "" || node.Port == 0 || password == "" {
		return node, fmt.Errorf("trojan: missing required fields")
	}
	q := url.Values{}
	if sni := u.Query().Get("sni"); sni != "" {
		q.Set("sni", sni)
	} else if peer := u.Query().Get("peer"); peer != "" {
		q.Set("sni", peer)
	}
	if u.Query().Get("allowInsecure") == "1" || u.Query().Get("allowInsecure") == "true" {
		q.Set("allowInsecure", "true")
	}
	node.URL = &url.URL{
		Scheme:   "trojan",
		User:     url.User(password),
		Host:     net.JoinHostPort(node.Server, strconv.Itoa(node.Port)),
		RawQuery: q.Encode(),
	}
	node.Supported = true
	return node, nil
}

func parseVMessURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	// vmess://base64(json) — just pass through the URL
	node.URL = u
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	node.Supported = true
	return node, nil
}

func parseVLessURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	node.URL = u
	node.Supported = true
	return node, nil
}

func parseHysteria2URI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	node.URL = u
	node.Supported = true
	return node, nil
}

func parseSocksURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	node.URL = &url.URL{
		Scheme: "socks5",
		User:   u.User,
		Host:   u.Host,
	}
	node.Supported = true
	return node, nil
}

func parseHTTPURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	node.URL = u
	node.Supported = true
	return node, nil
}

func parseAnyTLSURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if node.Server == "" || password == "" {
		return node, fmt.Errorf("anytls: missing required fields")
	}
	q := url.Values{}
	if sni := u.Query().Get("sni"); sni != "" {
		q.Set("sni", sni)
	}
	if u.Query().Get("insecure") == "1" || u.Query().Get("insecure") == "true" {
		q.Set("insecure", "true")
	}
	node.URL = &url.URL{
		Scheme:   "anytls",
		User:     url.User(password),
		Host:     u.Host,
		RawQuery: q.Encode(),
	}
	node.Supported = true
	return node, nil
}

func parseWireGuardURI(u *url.URL, node ProxyNode) (ProxyNode, error) {
	node.Server = u.Hostname()
	node.Port, _ = strconv.Atoi(u.Port())
	if node.Port == 0 {
		node.Port = 51820
	}
	q := u.Query()
	if q.Get("private-key") == "" || q.Get("public-key") == "" || q.Get("address") == "" {
		return node, fmt.Errorf("wireguard: missing required fields (private-key, public-key, address)")
	}
	node.URL = &url.URL{
		Scheme:   "wg",
		Host:     net.JoinHostPort(node.Server, strconv.Itoa(node.Port)),
		RawQuery: u.RawQuery,
	}
	node.Supported = true
	return node, nil
}

func parseYAML(data []byte) (*Subscription, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in subscription")
	}

	sub := &Subscription{}
	for _, raw := range cfg.Proxies {
		node := ProxyNode{
			Name:    getString(raw, "name"),
			Type:    strings.ToLower(getString(raw, "type")),
			Server:  getString(raw, "server"),
			Port:    getInt(raw, "port"),
			RawConf: raw,
		}
		u, err := NodeToURL(raw)
		if err != nil {
			node.Supported = false
		} else {
			node.URL = u
			node.Supported = true
		}
		sub.Nodes = append(sub.Nodes, node)
	}

	for _, raw := range cfg.ProxyGroup {
		group := ProxyGroup{
			Name: getString(raw, "name"),
			Type: getString(raw, "type"),
		}
		if proxies, ok := raw["proxies"].([]any); ok {
			for _, p := range proxies {
				if s, ok := p.(string); ok {
					group.Proxies = append(group.Proxies, s)
				}
			}
		}
		sub.Groups = append(sub.Groups, group)
	}
	return sub, nil
}

func NodeToURL(node map[string]any) (*url.URL, error) {
	typ := strings.ToLower(getString(node, "type"))
	switch typ {
	case "ss", "shadowsocks":
		return ssNodeToURL(node)
	case "socks5":
		return socks5NodeToURL(node)
	case "http":
		return httpNodeToURL(node)
	case "trojan":
		return trojanNodeToURL(node)
	case "vmess":
		return vmessNodeToURL(node)
	case "vless":
		return vlessNodeToURL(node)
	case "hysteria2", "hy2":
		return hysteria2NodeToURL(node)
	case "anytls":
		return anytlsNodeToURL(node)
	case "wireguard":
		return wireguardNodeToURL(node)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", typ)
	}
}

func SupportedNodes(sub *Subscription) []ProxyNode {
	var result []ProxyNode
	for _, n := range sub.Nodes {
		if n.Supported {
			result = append(result, n)
		}
	}
	return result
}

// DialableNodes returns nodes whose URL scheme is registered in proxyclient.
func DialableNodes(sub *Subscription) []ProxyNode {
	registered := make(map[string]bool)
	for _, s := range proxyclient.SupportedSchemes() {
		registered[strings.ToUpper(s)] = true
	}
	var result []ProxyNode
	for _, n := range sub.Nodes {
		if n.Supported && n.URL != nil && registered[strings.ToUpper(n.URL.Scheme)] {
			result = append(result, n)
		}
	}
	return result
}

func NodesByType(sub *Subscription, proxyType string) []ProxyNode {
	proxyType = strings.ToLower(proxyType)
	var result []ProxyNode
	for _, n := range sub.Nodes {
		if n.Type == proxyType {
			result = append(result, n)
		}
	}
	return result
}

// --- per-type converters ---

func ssNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	cipher := getString(node, "cipher")
	password := getString(node, "password")
	if server == "" || port == 0 || cipher == "" || password == "" {
		return nil, fmt.Errorf("ss: missing required fields")
	}
	return &url.URL{
		Scheme: "ss",
		User:   url.UserPassword(cipher, password),
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}, nil
}

func socks5NodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	if server == "" || port == 0 {
		return nil, fmt.Errorf("socks5: missing required fields")
	}
	u := &url.URL{
		Scheme: "socks5",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	user := getString(node, "username")
	pass := getString(node, "password")
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u, nil
}

func httpNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	if server == "" || port == 0 {
		return nil, fmt.Errorf("http: missing required fields")
	}
	scheme := "http"
	if getBool(node, "tls") {
		scheme = "https"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	user := getString(node, "username")
	pass := getString(node, "password")
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u, nil
}

func trojanNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	password := getString(node, "password")
	if server == "" || port == 0 || password == "" {
		return nil, fmt.Errorf("trojan: missing required fields")
	}
	q := url.Values{}
	if sni := getString(node, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if getBool(node, "skip-cert-verify") {
		q.Set("allowInsecure", "true")
	}
	return &url.URL{
		Scheme:   "trojan",
		User:     url.User(password),
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}, nil
}

func vmessNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	uuid := getString(node, "uuid")
	if server == "" || port == 0 || uuid == "" {
		return nil, fmt.Errorf("vmess: missing required fields")
	}
	q := url.Values{}
	q.Set("id", uuid)
	if aid := getInt(node, "alterId"); aid > 0 {
		q.Set("aid", strconv.Itoa(aid))
	}
	if cipher := getString(node, "cipher"); cipher != "" {
		q.Set("security", cipher)
	}
	if getBool(node, "tls") {
		q.Set("tls", "true")
	}
	if sni := getString(node, "servername"); sni != "" {
		q.Set("sni", sni)
	}
	if network := getString(node, "network"); network != "" {
		q.Set("net", network)
	}
	if getBool(node, "skip-cert-verify") {
		q.Set("allowInsecure", "true")
	}
	// ws-opts
	if wsOpts, ok := node["ws-opts"].(map[string]any); ok {
		if path := getString(wsOpts, "path"); path != "" {
			q.Set("path", path)
		}
		if headers, ok := wsOpts["headers"].(map[string]any); ok {
			if host := getString(headers, "Host"); host != "" {
				q.Set("host", host)
			}
		}
	}
	return &url.URL{
		Scheme:   "vmess",
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}, nil
}

func vlessNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	uuid := getString(node, "uuid")
	if server == "" || port == 0 || uuid == "" {
		return nil, fmt.Errorf("vless: missing required fields")
	}
	q := url.Values{}
	if network := getString(node, "network"); network != "" {
		q.Set("type", network)
	}
	if tls := getString(node, "tls"); tls != "" {
		q.Set("security", tls)
	} else if getBool(node, "tls") {
		q.Set("security", "tls")
	}
	if sni := getString(node, "servername"); sni != "" {
		q.Set("sni", sni)
	}
	if flow := getString(node, "flow"); flow != "" {
		q.Set("flow", flow)
	}
	if getBool(node, "skip-cert-verify") {
		q.Set("allowInsecure", "true")
	}
	// reality-opts
	if reality, ok := node["reality-opts"].(map[string]any); ok {
		q.Set("security", "reality")
		if pbk := getString(reality, "public-key"); pbk != "" {
			q.Set("pbk", pbk)
		}
		if sid := getString(reality, "short-id"); sid != "" {
			q.Set("sid", sid)
		}
	}
	return &url.URL{
		Scheme:   "vless",
		User:     url.User(uuid),
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}, nil
}

func hysteria2NodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	password := getString(node, "password")
	if password == "" {
		password = getString(node, "auth")
	}
	if server == "" || port == 0 {
		return nil, fmt.Errorf("hysteria2: missing required fields")
	}
	q := url.Values{}
	if sni := getString(node, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if getBool(node, "skip-cert-verify") {
		q.Set("insecure", "true")
	}
	u := &url.URL{
		Scheme:   "hysteria2",
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}
	if password != "" {
		u.User = url.User(password)
	}
	return u, nil
}

func anytlsNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	password := getString(node, "password")
	if server == "" || port == 0 || password == "" {
		return nil, fmt.Errorf("anytls: missing required fields")
	}
	q := url.Values{}
	if sni := getString(node, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if getBool(node, "skip-cert-verify") {
		q.Set("insecure", "true")
	}
	return &url.URL{
		Scheme:   "anytls",
		User:     url.User(password),
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}, nil
}

func wireguardNodeToURL(node map[string]any) (*url.URL, error) {
	server := getString(node, "server")
	port := getInt(node, "port")
	if port == 0 {
		port = 51820
	}
	privateKey := getString(node, "private-key")
	if server == "" || privateKey == "" {
		return nil, fmt.Errorf("wireguard: missing required fields")
	}
	q := url.Values{}
	q.Set("private-key", privateKey)

	publicKey := getString(node, "public-key")
	if publicKey == "" {
		if peers, ok := node["peers"].([]any); ok && len(peers) > 0 {
			if peer, ok := peers[0].(map[string]any); ok {
				publicKey = getString(peer, "public-key")
				if psk := getString(peer, "preshared-key"); psk != "" {
					q.Set("preshared-key", psk)
				}
				if reserved := getString(peer, "reserved"); reserved != "" {
					q.Set("reserved", reserved)
				}
				if ep := getString(peer, "endpoint"); ep != "" {
					if h, p, err := net.SplitHostPort(ep); err == nil {
						server = h
						if pv, err := strconv.Atoi(p); err == nil {
							port = pv
						}
					}
				}
			}
		}
	}
	if publicKey == "" {
		return nil, fmt.Errorf("wireguard: missing public-key")
	}
	q.Set("public-key", publicKey)

	addr := getString(node, "ip")
	if addr == "" {
		addr = getString(node, "address")
	}
	if ipv6 := getString(node, "ipv6"); ipv6 != "" && addr != "" {
		addr = addr + "," + ipv6
	}
	if addr == "" {
		return nil, fmt.Errorf("wireguard: missing ip/address")
	}
	q.Set("address", addr)

	if dns := getString(node, "dns"); dns != "" {
		q.Set("dns", dns)
	}
	if mtu := getInt(node, "mtu"); mtu > 0 {
		q.Set("mtu", strconv.Itoa(mtu))
	}
	if psk := getString(node, "preshared-key"); psk != "" {
		q.Set("preshared-key", psk)
	}
	if reserved := getString(node, "reserved"); reserved != "" {
		q.Set("reserved", reserved)
	}

	return &url.URL{
		Scheme:   "wg",
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: q.Encode(),
	}, nil
}

// --- helpers ---

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func getInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		n, _ := strconv.Atoi(val)
		return n
	default:
		return 0
	}
}

func getBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true" || val == "1"
	default:
		return false
	}
}

func tryBase64Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(s)
	}
	return decoded, err
}
