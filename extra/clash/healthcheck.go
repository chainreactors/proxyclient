package clash

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/chainreactors/proxyclient"
)

const (
	defaultTestURL     = "https://www.google.com/generate_204"
	defaultTestTimeout = 10 * time.Second
	defaultConcurrency = 20
)

type HealthCheckConfig struct {
	URL         string        // test URL, default: google generate_204
	Timeout     time.Duration // per-node timeout, default: 10s
	Concurrency int           // max concurrent tests, default: 20
}

type NodeResult struct {
	Node    ProxyNode
	Dial    proxyclient.Dial
	Latency time.Duration
	Err     error
}

// HealthCheck tests all dialable nodes concurrently and returns results sorted by latency.
func HealthCheck(sub *Subscription, cfg *HealthCheckConfig, filter func(ProxyNode) bool) []NodeResult {
	if cfg == nil {
		cfg = &HealthCheckConfig{}
	}
	if cfg.URL == "" {
		cfg.URL = defaultTestURL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTestTimeout
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	nodes := DialableNodes(sub)
	if filter != nil {
		var filtered []ProxyNode
		for _, n := range nodes {
			if filter(n) {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}

	results := make([]NodeResult, len(nodes))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n ProxyNode) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dial, err := proxyclient.NewClient(n.URL)
			if err != nil {
				results[idx] = NodeResult{Node: n, Err: err}
				return
			}
			latency, err := testDial(dial, cfg.URL, cfg.Timeout)
			results[idx] = NodeResult{Node: n, Dial: dial, Latency: latency, Err: err}
		}(i, node)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Err != nil && results[j].Err != nil {
			return false
		}
		if results[i].Err != nil {
			return false
		}
		if results[j].Err != nil {
			return true
		}
		return results[i].Latency < results[j].Latency
	})
	return results
}

// HealthyDials returns only the working Dial functions from health check results.
func HealthyDials(results []NodeResult) []proxyclient.Dial {
	var dials []proxyclient.Dial
	for _, r := range results {
		if r.Err == nil && r.Dial != nil {
			dials = append(dials, r.Dial)
		}
	}
	return dials
}

func testDial(dial proxyclient.Dial, testURL string, timeout time.Duration) (time.Duration, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial.DialContext(ctx, network, addr)
		},
		TLSClientConfig:  &tls.Config{},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Get(testURL)
	latency := time.Since(start)
	if err != nil {
		return latency, err
	}
	io.ReadAll(io.LimitReader(resp.Body, 64))
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return latency, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return latency, nil
}
