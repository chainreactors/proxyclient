package clash

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/chainreactors/proxyclient"
)

const schemeTestYAML = `
proxies:
  - name: "HK-socks"
    type: socks5
    server: 127.0.0.1
    port: 1080

  - name: "JP-socks"
    type: socks5
    server: 127.0.0.1
    port: 1081

  - name: "trojan-node"
    type: trojan
    server: example.com
    port: 443
    password: pass
    sni: example.com
`

func TestClashSchemeRegistered(t *testing.T) {
	schemes := proxyclient.SupportedSchemes()
	found := false
	for _, s := range schemes {
		if s == "CLASH" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("CLASH scheme not registered")
	}
}

func TestClashSchemeURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(schemeTestYAML))
	}))
	defer srv.Close()

	// Build a clash:// URL
	clashURL := "clash://?url=" + url.QueryEscape(srv.URL) + "&strategy=round-robin&type=socks5"
	u, err := url.Parse(clashURL)
	if err != nil {
		t.Fatal(err)
	}

	dial, err := proxyclient.NewClient(u)
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		t.Fatal("nil dial")
	}
}

func TestClashSchemeMissingURL(t *testing.T) {
	u, _ := url.Parse("clash://?strategy=random")
	_, err := proxyclient.NewClient(u)
	if err == nil {
		t.Fatal("expected error for missing url parameter")
	}
}

func TestClashSchemeWithFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(schemeTestYAML))
	}))
	defer srv.Close()

	// filter by name "HK"
	clashURL := "clash://?url=" + url.QueryEscape(srv.URL) + "&name=HK&strategy=first"
	u, _ := url.Parse(clashURL)
	dial, err := proxyclient.NewClient(u)
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		t.Fatal("nil dial")
	}
}
