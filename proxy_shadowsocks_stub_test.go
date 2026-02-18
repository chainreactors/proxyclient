//go:build !proxyclient_shadowsocks

package proxyclient

import (
	"net/url"
	"strings"
	"testing"
)

func TestShadowsocksSchemeNotRegisteredByDefault(t *testing.T) {
	proxy, err := url.Parse("ss://method:password@127.0.0.1:8388")
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	_, err = NewClient(proxy)
	if err == nil {
		t.Fatal("expected unsupported scheme error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported proxy client") {
		t.Fatalf("unexpected error: %v", err)
	}
}
