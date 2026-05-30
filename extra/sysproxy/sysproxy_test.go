package sysproxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/chainreactors/proxyclient"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid HTTP",
			cfg:     Config{Type: ProxyHTTP, Addr: "127.0.0.1:8080"},
			wantErr: false,
		},
		{
			name:    "valid SOCKS",
			cfg:     Config{Type: ProxySocks, Addr: "127.0.0.1:1080"},
			wantErr: false,
		},
		{
			name:    "valid PAC",
			cfg:     Config{PACUrl: "http://example.com/proxy.pac"},
			wantErr: false,
		},
		{
			name:    "missing addr without PAC",
			cfg:     Config{Type: ProxyHTTP},
			wantErr: true,
		},
		{
			name:    "PAC ignores missing addr",
			cfg:     Config{PACUrl: "http://example.com/proxy.pac"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestRestoreNilState(t *testing.T) {
	err := Restore(nil)
	if err != nil {
		t.Errorf("Restore(nil) should return nil, got: %v", err)
	}
}

func TestGeneratePAC(t *testing.T) {
	tests := []struct {
		name     string
		cfg      PACConfig
		contains []string
		excludes []string
	}{
		{
			name: "basic proxy all",
			cfg: PACConfig{
				ProxyAddr: "PROXY 127.0.0.1:8080",
			},
			contains: []string{
				"function FindProxyForURL",
				"PROXY 127.0.0.1:8080",
			},
		},
		{
			name: "with direct domains",
			cfg: PACConfig{
				ProxyAddr:     "PROXY 127.0.0.1:8080",
				DirectDomains: []string{"localhost", "*.local", "10.0.0.0/8"},
			},
			contains: []string{
				`host == "localhost"`,
				`dnsDomainIs(host, ".local")`,
				`isInNet(host, "10.0.0.0"`,
				"PROXY 127.0.0.1:8080",
			},
		},
		{
			name: "with proxy domains only",
			cfg: PACConfig{
				ProxyAddr:    "SOCKS5 127.0.0.1:1080",
				ProxyDomains: []string{"example.com", "*.test.org"},
			},
			contains: []string{
				`host == "example.com"`,
				`dnsDomainIs(host, ".test.org")`,
				"SOCKS5 127.0.0.1:1080",
				`return "DIRECT"`,
			},
		},
		{
			name: "CIDR bypass",
			cfg: PACConfig{
				ProxyAddr:     "PROXY 127.0.0.1:8080",
				DirectDomains: []string{"192.168.0.0/16"},
			},
			contains: []string{
				`isInNet(host, "192.168.0.0", "255.255.0.0")`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pac := GeneratePAC(tt.cfg)

			for _, s := range tt.contains {
				if !strings.Contains(pac, s) {
					t.Errorf("PAC should contain %q, got:\n%s", s, pac)
				}
			}
			for _, s := range tt.excludes {
				if strings.Contains(pac, s) {
					t.Errorf("PAC should not contain %q, got:\n%s", s, pac)
				}
			}
		})
	}
}

func TestServePAC(t *testing.T) {
	cfg := PACConfig{
		ProxyAddr:     "PROXY 127.0.0.1:8080",
		DirectDomains: []string{"localhost"},
	}

	pacURL, stop, err := ServePAC("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("ServePAC: %v", err)
	}
	defer stop()

	if !strings.HasPrefix(pacURL, "http://") {
		t.Errorf("pacURL should start with http://, got: %s", pacURL)
	}
	if !strings.HasSuffix(pacURL, "/proxy.pac") {
		t.Errorf("pacURL should end with /proxy.pac, got: %s", pacURL)
	}

	resp, err := http.Get(pacURL)
	if err != nil {
		t.Fatalf("GET %s: %v", pacURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %q, want application/x-ns-proxy-autoconfig", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "FindProxyForURL") {
		t.Error("response body should contain FindProxyForURL")
	}
}

func TestDetectedProxyURL(t *testing.T) {
	tests := []struct {
		name       string
		proxy      DetectedProxy
		wantScheme string
	}{
		{"http", DetectedProxy{Type: ProxyHTTP, Addr: "proxy.corp.com:8080"}, "http"},
		{"socks", DetectedProxy{Type: ProxySocks, Addr: "127.0.0.1:1080"}, "socks5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := tt.proxy.URL()
			if u.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", u.Scheme, tt.wantScheme)
			}
			if u.Host != tt.proxy.Addr {
				t.Errorf("host = %q, want %q", u.Host, tt.proxy.Addr)
			}
		})
	}
}

func TestDetectReturnsNoError(t *testing.T) {
	d, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	// d may be nil (no system proxy) — that's fine
	_ = d
}

func TestEnvDetect(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		wantType ProxyType
		wantAddr string
	}{
		{"http", "http://proxy.corp.com:8080", ProxyHTTP, "proxy.corp.com:8080"},
		{"bare", "proxy.corp.com:3128", ProxyHTTP, "proxy.corp.com:3128"},
		{"socks5", "socks5://127.0.0.1:1080", ProxySocks, "127.0.0.1:1080"},
		{"socks5h", "socks5h://socks.local:1080", ProxySocks, "socks.local:1080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := parseEnvProxy(tt.env)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if d == nil {
				t.Fatal("expected non-nil result")
			}
			if d.Type != tt.wantType {
				t.Errorf("type = %v, want %v", d.Type, tt.wantType)
			}
			if d.Addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", d.Addr, tt.wantAddr)
			}
		})
	}
}

func TestSchemeRegistered(t *testing.T) {
	schemes := proxyclient.SupportedSchemes()
	found := false
	for _, s := range schemes {
		if s == "SYSPROXY" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SYSPROXY scheme not registered")
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		cidr     string
		wantIP   string
		wantMask string
	}{
		{"10.0.0.0/8", "10.0.0.0", "255.0.0.0"},
		{"192.168.1.0/24", "192.168.1.0", "255.255.255.0"},
		{"172.16.0.0/12", "172.16.0.0", "255.240.0.0"},
		{"invalid", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ip, mask := parseCIDR(tt.cidr)
			if ip != tt.wantIP || mask != tt.wantMask {
				t.Errorf("parseCIDR(%q) = (%q, %q), want (%q, %q)", tt.cidr, ip, mask, tt.wantIP, tt.wantMask)
			}
		})
	}
}
