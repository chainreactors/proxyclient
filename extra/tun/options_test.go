package tun

import (
	"testing"
)

func TestOptionsDefaults(t *testing.T) {
	options := Options{}.withDefaults()
	if options.Name == "" {
		t.Fatal("expected generated tun name")
	}
	if options.Stack != DefaultStack {
		t.Fatalf("expected stack %q, got %q", DefaultStack, options.Stack)
	}
	if options.MTU != DefaultMTU {
		t.Fatalf("expected MTU %d, got %d", DefaultMTU, options.MTU)
	}
	if len(options.Inet4) != 1 || options.Inet4[0] != DefaultInet4Prefix {
		t.Fatalf("unexpected default inet4 prefixes: %v", options.Inet4)
	}
	if len(options.Inet6) != 0 {
		t.Fatalf("unexpected default inet6 prefixes: %v", options.Inet6)
	}
	if options.UDPTimeout != DefaultUDPTimeout {
		t.Fatalf("expected UDP timeout %s, got %s", DefaultUDPTimeout, options.UDPTimeout)
	}
	if options.Logger == nil {
		t.Fatal("expected default logger")
	}
}
