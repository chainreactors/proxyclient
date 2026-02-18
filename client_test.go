package proxyclient

import (
	"errors"
	"net/url"
	"testing"
)

func TestDialNilGuard(t *testing.T) {
	var d Dial
	if _, err := d.Dial("tcp", "127.0.0.1:1"); !errors.Is(err, ErrNilDial) {
		t.Fatalf("expected ErrNilDial, got %v", err)
	}
}

func TestInitBuiltinSchemes_Idempotent(t *testing.T) {
	InitBuiltinSchemes()
	InitBuiltinSchemes()

	proxy, err := url.Parse("direct://")
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	d, err := NewClient(proxy)
	if err != nil {
		t.Fatalf("NewClient(direct) failed: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil dialer")
	}
}
