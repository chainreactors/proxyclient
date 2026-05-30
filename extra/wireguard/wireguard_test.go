package wireguard

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func testKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestParseConfig(t *testing.T) {
	privKey := testKey()
	pubKey := testKey()

	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
		check   func(*testing.T, *wgConfig)
	}{
		{
			name:   "basic",
			rawURL: "wg://1.2.3.4:51820?private-key=" + privKey + "&public-key=" + pubKey + "&address=10.0.0.2/32",
			check: func(t *testing.T, c *wgConfig) {
				if c.endpoint != "1.2.3.4:51820" {
					t.Errorf("endpoint = %q, want %q", c.endpoint, "1.2.3.4:51820")
				}
				if c.mtu != 1420 {
					t.Errorf("mtu = %d, want 1420", c.mtu)
				}
				if len(c.addresses) != 1 || c.addresses[0].String() != "10.0.0.2" {
					t.Errorf("addresses = %v, want [10.0.0.2]", c.addresses)
				}
			},
		},
		{
			name:   "default port",
			rawURL: "wg://example.com?private-key=" + privKey + "&public-key=" + pubKey + "&address=10.0.0.2/32",
			check: func(t *testing.T, c *wgConfig) {
				if c.endpoint != "example.com:51820" {
					t.Errorf("endpoint = %q, want %q", c.endpoint, "example.com:51820")
				}
			},
		},
		{
			name:   "full options",
			rawURL: "wg://1.2.3.4:12345?private-key=" + privKey + "&public-key=" + pubKey + "&address=10.0.0.2/32,fd00::2/128&dns=1.1.1.1,8.8.8.8&mtu=1280&preshared-key=" + privKey + "&reserved=1,2,3",
			check: func(t *testing.T, c *wgConfig) {
				if c.mtu != 1280 {
					t.Errorf("mtu = %d, want 1280", c.mtu)
				}
				if len(c.addresses) != 2 {
					t.Errorf("addresses = %v, want 2 addresses", c.addresses)
				}
				if len(c.dns) != 2 {
					t.Errorf("dns = %v, want 2 dns servers", c.dns)
				}
				if c.presharedKey == "" {
					t.Error("preshared key should be set")
				}
				if c.reserved != [3]byte{1, 2, 3} {
					t.Errorf("reserved = %v, want [1,2,3]", c.reserved)
				}
			},
		},
		{
			name:    "missing private key",
			rawURL:  "wg://1.2.3.4:51820?public-key=" + pubKey + "&address=10.0.0.2/32",
			wantErr: true,
		},
		{
			name:    "missing public key",
			rawURL:  "wg://1.2.3.4:51820?private-key=" + privKey + "&address=10.0.0.2/32",
			wantErr: true,
		},
		{
			name:    "missing address",
			rawURL:  "wg://1.2.3.4:51820?private-key=" + privKey + "&public-key=" + pubKey,
			wantErr: true,
		},
		{
			name:    "invalid key length",
			rawURL:  "wg://1.2.3.4:51820?private-key=dGVzdA==&public-key=" + pubKey + "&address=10.0.0.2/32",
			wantErr: true,
		},
		{
			name:    "invalid mtu",
			rawURL:  "wg://1.2.3.4:51820?private-key=" + privKey + "&public-key=" + pubKey + "&address=10.0.0.2/32&mtu=abc",
			wantErr: true,
		},
		{
			name:    "invalid reserved",
			rawURL:  "wg://1.2.3.4:51820?private-key=" + privKey + "&public-key=" + pubKey + "&address=10.0.0.2/32&reserved=1,2",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			cfg, err := parseConfig(u)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestIpcConfig(t *testing.T) {
	cfg := &wgConfig{
		endpoint:   "1.2.3.4:51820",
		privateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		publicKey:  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	}

	ipc := cfg.ipcConfig()

	if !contains(ipc, "private_key=") {
		t.Error("ipc config missing private_key")
	}
	if !contains(ipc, "public_key=") {
		t.Error("ipc config missing public_key")
	}
	if !contains(ipc, "endpoint=1.2.3.4:51820") {
		t.Error("ipc config missing endpoint")
	}
	if !contains(ipc, "allowed_ip=0.0.0.0/0") {
		t.Error("ipc config missing allowed_ip for ipv4")
	}
	if !contains(ipc, "allowed_ip=::/0") {
		t.Error("ipc config missing allowed_ip for ipv6")
	}

	cfg.presharedKey = "aabbccdd"
	ipc = cfg.ipcConfig()
	if !contains(ipc, "preshared_key=aabbccdd") {
		t.Error("ipc config missing preshared_key when set")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
