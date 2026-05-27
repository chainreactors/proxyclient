package clash

import (
	"compress/gzip"
	"bytes"
	_ "embed"
	"net"
	"strconv"
	"strings"
	"sync"
)

//go:embed ip_country.gz
var ipCountryGZ []byte

type GeoLookup struct {
	ipRanges []uint64
	countries []string
}

var (
	geoOnce   sync.Once
	geoLookup *GeoLookup
)

// Geo returns the shared GeoLookup instance, initialized on first call.
func Geo() *GeoLookup {
	geoOnce.Do(func() {
		geoLookup = loadGeo()
	})
	return geoLookup
}

func loadGeo() *GeoLookup {
	r, err := gzip.NewReader(bytes.NewReader(ipCountryGZ))
	if err != nil {
		return &GeoLookup{}
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	r.Close()
	b := buf.Bytes()

	codes := make([]string, 0, 243)
	idx := 0
	for idx < len(b)-1 {
		c1, c2 := b[idx], b[idx+1]
		idx += 2
		codes = append(codes, string([]byte{c1, c2}))
		if c1 == '*' {
			break
		}
	}

	ranges := make([]uint64, 0, 200000)
	countries := make([]string, 0, 200000)
	var lastEnd uint64
	for idx < len(b) {
		var count int
		n1 := b[idx]
		idx++
		if n1 < 240 {
			count = int(n1)
		} else if n1 == 242 {
			count = int(b[idx]) | int(b[idx+1])<<8
			idx += 2
		} else if n1 == 243 {
			count = int(b[idx]) | int(b[idx+1])<<8 | int(b[idx+2])<<16
			idx += 3
		}
		lastEnd += uint64(count * 256)
		cc := b[idx]
		idx++
		ranges = append(ranges, lastEnd)
		countries = append(countries, codes[cc])
	}
	return &GeoLookup{ipRanges: ranges, countries: countries}
}

// LookupIP returns the 2-letter country code for an IPv4 address string.
func (g *GeoLookup) LookupIP(ipStr string) (string, bool) {
	if g == nil || len(g.ipRanges) == 0 {
		return "", false
	}
	parts := strings.SplitN(ipStr, ".", 4)
	if len(parts) != 4 {
		return "", false
	}
	a, e1 := strconv.Atoi(parts[0])
	b, e2 := strconv.Atoi(parts[1])
	c, e3 := strconv.Atoi(parts[2])
	d, e4 := strconv.Atoi(parts[3])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return "", false
	}
	num := uint64(a)*16777216 + uint64(b)*65536 + uint64(c)*256 + uint64(d)
	lo, hi := 0, len(g.ipRanges)-1
	for lo < hi {
		mid := (lo + hi) >> 1
		if g.ipRanges[mid] <= num {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	cc := g.countries[lo]
	if cc == "--" {
		return "", false
	}
	return cc, true
}

// ResolveAndLookup resolves a hostname to an IP, then looks up the country.
func (g *GeoLookup) ResolveAndLookup(host string) (string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return g.LookupIP(ip4.String())
		}
		return "", false // IPv6 not supported
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", false
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return g.LookupIP(ip4.String())
		}
	}
	return "", false
}

// FilterByCountry returns a filter function for use with clash.Options.Filter
// that keeps nodes whose server IP resolves to one of the given country codes.
func FilterByCountry(codes ...string) func(ProxyNode) bool {
	set := make(map[string]bool, len(codes))
	for _, c := range codes {
		set[strings.ToUpper(c)] = true
	}
	geo := Geo()
	return func(n ProxyNode) bool {
		cc, ok := geo.ResolveAndLookup(n.Server)
		return ok && set[strings.ToUpper(cc)]
	}
}
