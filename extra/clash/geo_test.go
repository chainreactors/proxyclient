package clash

import (
	"testing"
)

func TestGeoLookupIP(t *testing.T) {
	geo := Geo()
	tests := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "US"},
		{"114.114.114.114", "CN"},
		{"185.199.108.153", "US"}, // GitHub Pages
	}
	for _, tt := range tests {
		cc, ok := geo.LookupIP(tt.ip)
		if !ok {
			t.Errorf("LookupIP(%s): not found", tt.ip)
			continue
		}
		if cc != tt.want {
			t.Errorf("LookupIP(%s) = %s, want %s", tt.ip, cc, tt.want)
		}
	}
}

func TestGeoResolveAndLookup(t *testing.T) {
	geo := Geo()
	// direct IP
	cc, ok := geo.ResolveAndLookup("8.8.8.8")
	if !ok || cc != "US" {
		t.Errorf("ResolveAndLookup(8.8.8.8) = %s, %v", cc, ok)
	}
}

func TestFilterByCountry(t *testing.T) {
	filter := FilterByCountry("HK", "JP")
	// 8.8.8.8 = US, not HK/JP
	node := ProxyNode{Server: "8.8.8.8"}
	if filter(node) {
		t.Error("US should not match HK/JP filter")
	}
}

func BenchmarkGeoLookup(b *testing.B) {
	geo := Geo()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		geo.LookupIP("103.213.5.35")
	}
}
