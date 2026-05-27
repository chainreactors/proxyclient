package clash

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleYAMLForDialer = `
proxies:
  - name: "socks-1"
    type: socks5
    server: 127.0.0.1
    port: 1080

  - name: "socks-2"
    type: socks5
    server: 127.0.0.1
    port: 1081

  - name: "unsupported"
    type: wireguard
    server: 127.0.0.1
    port: 51820
`

func TestNewDialerFromSubscription_Strategies(t *testing.T) {
	sub, err := ParseSubscription([]byte(sampleYAMLForDialer))
	if err != nil {
		t.Fatal(err)
	}

	for _, strategy := range []Strategy{StrategyRoundRobin, StrategyRandom, StrategyHash, StrategyFirst} {
		dial, _, err := NewDialerFromSubscription(sub, Options{Strategy: strategy})
		if err != nil {
			t.Fatalf("strategy %s: %v", strategy, err)
		}
		if dial == nil {
			t.Fatalf("strategy %s: nil dial", strategy)
		}
	}
}

func TestNewDialerFromSubscription_Filter(t *testing.T) {
	sub, err := ParseSubscription([]byte(sampleYAMLForDialer))
	if err != nil {
		t.Fatal(err)
	}

	// filter to only socks-1
	dial, _, err := NewDialerFromSubscription(sub, Options{
		Filter: FilterByName("socks-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		t.Fatal("nil dial")
	}
}

func TestNewDialerFromSubscription_NoNodes(t *testing.T) {
	sub, err := ParseSubscription([]byte(sampleYAMLForDialer))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = NewDialerFromSubscription(sub, Options{
		Filter: func(n ProxyNode) bool { return false },
	})
	if err == nil {
		t.Fatal("expected error for no nodes")
	}
}

func TestNewDialer_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleYAMLForDialer))
	}))
	defer srv.Close()

	dial, sub, err := NewDialer(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		t.Fatal("nil dial")
	}
	if len(sub.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(sub.Nodes))
	}
}

func TestFilterByType(t *testing.T) {
	filter := FilterByType("socks5")
	if !filter(ProxyNode{Type: "socks5"}) {
		t.Fatal("should match socks5")
	}
	if filter(ProxyNode{Type: "trojan"}) {
		t.Fatal("should not match trojan")
	}
}
