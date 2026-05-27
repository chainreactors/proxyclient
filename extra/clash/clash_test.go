package clash

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleSubscriptionYAML = `
proxies:
  - name: "trojan-node"
    type: trojan
    server: trojan.example.com
    port: 443
    password: my-trojan-pass
    sni: trojan.example.com
    skip-cert-verify: true

  - name: "vmess-node"
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: "a3482e88-686a-4a58-8126-99c9df64b7bf"
    alterId: 0
    cipher: auto
    tls: true
    servername: vmess.example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: vmess.example.com

  - name: "ss-node"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: ss-password

  - name: "socks5-node"
    type: socks5
    server: socks.example.com
    port: 1080
    username: user
    password: pass

  - name: "vless-node"
    type: vless
    server: vless.example.com
    port: 443
    uuid: "a3482e88-686a-4a58-8126-99c9df64b7bf"
    tls: true
    servername: vless.example.com
    flow: xtls-rprx-vision
    network: tcp

  - name: "hy2-node"
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: hy2-password
    sni: hy2.example.com

  - name: "unknown-node"
    type: wireguard
    server: wg.example.com
    port: 51820

proxy-groups:
  - name: "auto"
    type: url-test
    proxies:
      - trojan-node
      - vmess-node
      - ss-node
`

func TestParseSubscription(t *testing.T) {
	sub, err := ParseSubscription([]byte(sampleSubscriptionYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sub.Nodes) != 7 {
		t.Fatalf("expected 7 nodes, got %d", len(sub.Nodes))
	}
	if len(sub.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(sub.Groups))
	}

	supported := SupportedNodes(sub)
	if len(supported) != 6 {
		t.Fatalf("expected 6 supported nodes, got %d", len(supported))
	}

	// wireguard should be unsupported
	wg := sub.Nodes[6]
	if wg.Supported {
		t.Fatal("wireguard node should not be supported")
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleSubscriptionYAML))
	sub, err := ParseSubscription([]byte(encoded))
	if err != nil {
		t.Fatalf("parse base64: %v", err)
	}
	if len(sub.Nodes) != 7 {
		t.Fatalf("expected 7 nodes, got %d", len(sub.Nodes))
	}
}

func TestNodeToURL_Trojan(t *testing.T) {
	node := map[string]any{
		"type":             "trojan",
		"server":           "example.com",
		"port":             443,
		"password":         "mypass",
		"sni":              "example.com",
		"skip-cert-verify": true,
	}
	u, err := NodeToURL(node)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "trojan" {
		t.Fatalf("expected scheme trojan, got %s", u.Scheme)
	}
	if u.User.Username() != "mypass" {
		t.Fatalf("expected password mypass, got %s", u.User.Username())
	}
	if u.Query().Get("sni") != "example.com" {
		t.Fatalf("expected sni example.com, got %s", u.Query().Get("sni"))
	}
	if u.Query().Get("allowInsecure") != "true" {
		t.Fatal("expected allowInsecure=true")
	}
}

func TestNodeToURL_VMess(t *testing.T) {
	node := map[string]any{
		"type":       "vmess",
		"server":     "example.com",
		"port":       443,
		"uuid":       "a3482e88-686a-4a58-8126-99c9df64b7bf",
		"alterId":    0,
		"cipher":     "auto",
		"tls":        true,
		"servername": "example.com",
		"network":    "ws",
		"ws-opts": map[string]any{
			"path": "/ws",
			"headers": map[string]any{
				"Host": "example.com",
			},
		},
	}
	u, err := NodeToURL(node)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "vmess" {
		t.Fatalf("expected scheme vmess, got %s", u.Scheme)
	}
	if u.Query().Get("id") != "a3482e88-686a-4a58-8126-99c9df64b7bf" {
		t.Fatalf("unexpected uuid: %s", u.Query().Get("id"))
	}
	if u.Query().Get("net") != "ws" {
		t.Fatalf("expected net=ws, got %s", u.Query().Get("net"))
	}
	if u.Query().Get("path") != "/ws" {
		t.Fatalf("expected path=/ws, got %s", u.Query().Get("path"))
	}
}

func TestNodeToURL_VLESS(t *testing.T) {
	node := map[string]any{
		"type":       "vless",
		"server":     "example.com",
		"port":       443,
		"uuid":       "a3482e88-686a-4a58-8126-99c9df64b7bf",
		"tls":        true,
		"servername": "example.com",
		"flow":       "xtls-rprx-vision",
		"network":    "tcp",
	}
	u, err := NodeToURL(node)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "vless" {
		t.Fatalf("expected scheme vless, got %s", u.Scheme)
	}
	if u.User.Username() != "a3482e88-686a-4a58-8126-99c9df64b7bf" {
		t.Fatalf("unexpected uuid: %s", u.User.Username())
	}
	if u.Query().Get("flow") != "xtls-rprx-vision" {
		t.Fatal("expected flow=xtls-rprx-vision")
	}
}

func TestNodeToURL_SS(t *testing.T) {
	node := map[string]any{
		"type":     "ss",
		"server":   "example.com",
		"port":     8388,
		"cipher":   "aes-256-gcm",
		"password": "mypass",
	}
	u, err := NodeToURL(node)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "ss" {
		t.Fatalf("expected scheme ss, got %s", u.Scheme)
	}
	if u.User.Username() != "aes-256-gcm" {
		t.Fatalf("expected cipher as username, got %s", u.User.Username())
	}
	pass, _ := u.User.Password()
	if pass != "mypass" {
		t.Fatalf("expected password mypass, got %s", pass)
	}
}

func TestNodeToURL_Hysteria2(t *testing.T) {
	node := map[string]any{
		"type":     "hysteria2",
		"server":   "example.com",
		"port":     443,
		"password": "hy2pass",
		"sni":      "example.com",
	}
	u, err := NodeToURL(node)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "hysteria2" {
		t.Fatalf("expected scheme hysteria2, got %s", u.Scheme)
	}
	if u.User.Username() != "hy2pass" {
		t.Fatalf("expected auth hy2pass, got %s", u.User.Username())
	}
}

func TestNodeToURL_Unknown(t *testing.T) {
	node := map[string]any{
		"type":   "wireguard",
		"server": "example.com",
		"port":   51820,
	}
	_, err := NodeToURL(node)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestFetchSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleSubscriptionYAML))
	}))
	defer srv.Close()

	sub, err := FetchSubscription(srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(sub.Nodes) != 7 {
		t.Fatalf("expected 7 nodes, got %d", len(sub.Nodes))
	}
}

func TestNodesByType(t *testing.T) {
	sub, err := ParseSubscription([]byte(sampleSubscriptionYAML))
	if err != nil {
		t.Fatal(err)
	}
	trojans := NodesByType(sub, "trojan")
	if len(trojans) != 1 {
		t.Fatalf("expected 1 trojan node, got %d", len(trojans))
	}
	if trojans[0].Name != "trojan-node" {
		t.Fatalf("expected trojan-node, got %s", trojans[0].Name)
	}
}
