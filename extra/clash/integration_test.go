package clash

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/chainreactors/proxyclient"
	_ "github.com/chainreactors/proxyclient/extra/trojan"
)

func getTestURL(t *testing.T) string {
	u := os.Getenv("CLASH_TEST_URL")
	if u == "" {
		t.Skip("CLASH_TEST_URL not set, skipping integration test")
	}
	return u
}

func TestIntegration_FetchAndParse(t *testing.T) {
	subURL := getTestURL(t)

	sub, err := FetchSubscription(subURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(sub.Nodes) == 0 {
		t.Fatal("no nodes in subscription")
	}
	t.Logf("total nodes: %d", len(sub.Nodes))

	supported := SupportedNodes(sub)
	if len(supported) == 0 {
		t.Fatal("no supported nodes")
	}
	t.Logf("supported nodes: %d", len(supported))

	typeCounts := map[string]int{}
	for _, n := range sub.Nodes {
		typeCounts[n.Type]++
	}
	for typ, count := range typeCounts {
		t.Logf("  %s: %d", typ, count)
	}
}

func TestIntegration_FilterByType(t *testing.T) {
	subURL := getTestURL(t)

	sub, err := FetchSubscription(subURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	trojans := NodesByType(sub, "trojan")
	if len(trojans) == 0 {
		t.Skip("no trojan nodes in subscription")
	}
	t.Logf("trojan nodes: %d", len(trojans))

	for _, n := range trojans {
		if n.URL == nil {
			t.Errorf("node %q has nil URL", n.Name)
		}
		if n.Server == "" {
			t.Errorf("node %q has empty server", n.Name)
		}
		if n.Port == 0 {
			t.Errorf("node %q has zero port", n.Name)
		}
	}
}

func TestIntegration_FilterByName(t *testing.T) {
	subURL := getTestURL(t)

	sub, err := FetchSubscription(subURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	filter := FilterByName("香港")
	var matched []ProxyNode
	for _, n := range sub.Nodes {
		if filter(n) {
			matched = append(matched, n)
		}
	}
	t.Logf("nodes matching '香港': %d", len(matched))
}

func TestIntegration_DialableNodes(t *testing.T) {
	subURL := getTestURL(t)

	sub, err := FetchSubscription(subURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	dialable := DialableNodes(sub)
	if len(dialable) == 0 {
		t.Fatal("no dialable nodes (is extra/trojan imported?)")
	}
	t.Logf("dialable nodes: %d / %d", len(dialable), len(sub.Nodes))
}

func TestIntegration_NewDialer(t *testing.T) {
	subURL := getTestURL(t)

	for _, strategy := range []Strategy{StrategyRoundRobin, StrategyRandom, StrategyHash, StrategyFirst, StrategyAdaptive} {
		t.Run(string(strategy), func(t *testing.T) {
			dial, sub, err := NewDialer(subURL, Options{Strategy: strategy})
			if err != nil {
				t.Fatalf("NewDialer(%s): %v", strategy, err)
			}
			if dial == nil {
				t.Fatal("nil dial")
			}
			t.Logf("nodes: %d", len(sub.Nodes))
		})
	}
}

func TestIntegration_DialHTTP(t *testing.T) {
	subURL := getTestURL(t)

	dial, _, err := NewDialer(subURL, Options{
		Strategy: StrategyURLTest,
		Filter:   FilterByName("香港"),
		HealthCheck: &HealthCheckConfig{
			Timeout:     10 * time.Second,
			Concurrency: 10,
		},
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial(ctx, network, addr)
			},
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	t.Logf("HTTP proxy dial succeeded, status: %d", resp.StatusCode)
}

func TestIntegration_ClashScheme(t *testing.T) {
	subURL := getTestURL(t)

	clashURL := "clash://?url=" + url.QueryEscape(subURL) + "&strategy=url-test&name=香港&test=true"
	u, err := proxyclient.ParseProxyURLs([]string{clashURL})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dial, err := proxyclient.NewClient(u[0])
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dial(ctx, "tcp", "httpbin.org:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	t.Log("clash:// scheme dial succeeded")
}

func TestIntegration_HealthCheck(t *testing.T) {
	subURL := getTestURL(t)

	sub, err := FetchSubscription(subURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	results := HealthCheck(sub, &HealthCheckConfig{
		Timeout:     10 * time.Second,
		Concurrency: 10,
	}, FilterByName("香港"))

	healthy := 0
	for _, r := range results {
		if r.Err == nil {
			healthy++
			t.Logf("  %s: %v", r.Node.Name, r.Latency)
		}
	}
	t.Logf("healthy: %d / %d", healthy, len(results))

	if healthy == 0 {
		t.Fatal("no healthy nodes")
	}

	dials := HealthyDials(results)
	if len(dials) != healthy {
		t.Fatalf("expected %d dials, got %d", healthy, len(dials))
	}
}
