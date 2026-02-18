//go:build !proxyclient_ssh

package proxyclient

import (
	"net/url"
	"strings"
	"testing"
)

func TestSSHSchemeNotRegisteredByDefault(t *testing.T) {
	proxy, err := url.Parse("ssh://user:pass@127.0.0.1:22")
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
