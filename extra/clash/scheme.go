package clash

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/chainreactors/proxyclient"
)

func init() {
	proxyclient.RegisterScheme("CLASH", newClashScheme)
}

// newClashScheme creates a load-balanced Dial from a Clash subscription URL.
//
// URL format:
//
//	clash://?url=<encoded-subscribe-url>[&strategy=round-robin][&country=HK,JP][&type=trojan,vless][&name=keyword][&ua=clash-verge]
//
// Parameters:
//   - url:      (required) Clash subscription URL, URL-encoded
//   - strategy: round-robin (default), random, hash, first
//   - country:  comma-separated 2-letter country codes, filter by server IP geo
//   - type:     comma-separated protocol types (trojan, vless, ss, etc.)
//   - name:     keyword filter on node names (case-insensitive)
//   - ua:       User-Agent for fetching subscription (default: "clash")
func newClashScheme(proxy *url.URL, _ proxyclient.Dial) (proxyclient.Dial, error) {
	q := proxy.Query()

	subURL := q.Get("url")
	if subURL == "" {
		return nil, fmt.Errorf("clash: 'url' parameter is required")
	}

	opts := Options{
		UserAgent: q.Get("ua"),
	}
	if s := q.Get("strategy"); s != "" {
		opts.Strategy = Strategy(s)
	}
	if opts.Strategy == StrategyURLTest || q.Get("test") == "true" || q.Get("test") == "1" {
		if opts.Strategy == "" {
			opts.Strategy = StrategyURLTest
		}
		opts.HealthCheck = &HealthCheckConfig{
			URL: q.Get("test-url"),
		}
	}
	opts.Filter = buildFilter(q)

	// url-test needs eager init (health check must run before first Dial)
	if opts.HealthCheck != nil {
		dial, _, err := NewDialer(subURL, opts)
		if err != nil {
			return nil, err
		}
		return dial, nil
	}

	// other strategies: lazy init on first Dial
	var (
		once    sync.Once
		inner   proxyclient.Dial
		initErr error
	)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() {
			inner, _, initErr = NewDialer(subURL, opts)
		})
		if initErr != nil {
			return nil, initErr
		}
		return inner(ctx, network, address)
	}
	return dial, nil
}

func buildFilter(q url.Values) func(ProxyNode) bool {
	var filters []func(ProxyNode) bool

	if v := q.Get("country"); v != "" {
		codes := strings.Split(v, ",")
		filters = append(filters, FilterByCountry(codes...))
	}
	if v := q.Get("type"); v != "" {
		types := strings.Split(v, ",")
		filters = append(filters, FilterByType(types...))
	}
	if v := q.Get("name"); v != "" {
		filters = append(filters, FilterByName(v))
	}

	if len(filters) == 0 {
		return nil
	}
	return func(n ProxyNode) bool {
		for _, f := range filters {
			if !f(n) {
				return false
			}
		}
		return true
	}
}
