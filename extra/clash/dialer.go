package clash

import (
	"fmt"
	"strings"

	"github.com/chainreactors/proxyclient"
	"github.com/chainreactors/proxyclient/loadbalance"
)

type Strategy string

const (
	StrategyRoundRobin Strategy = "round-robin"
	StrategyRandom     Strategy = "random"
	StrategyHash       Strategy = "hash"
	StrategyFirst      Strategy = "first"
	StrategyURLTest    Strategy = "url-test"  // health check, then use fastest nodes
	StrategyAdaptive   Strategy = "adaptive"  // auto-learn from success/failure/latency
)

type Options struct {
	Strategy    Strategy
	Filter      func(node ProxyNode) bool
	HealthCheck *HealthCheckConfig // used by url-test strategy, or set to enable pre-filtering
	// UserAgent for fetching subscription. Default: "clash".
	UserAgent string
}

// NewDialer fetches a Clash subscription URL, parses it, creates proxyclient
// dialers for all dialable nodes, and returns a single load-balanced Dial.
func NewDialer(subscribeURL string, opts Options) (proxyclient.Dial, *Subscription, error) {
	sub, err := FetchSubscriptionWithUA(subscribeURL, opts.UserAgent)
	if err != nil {
		return nil, nil, err
	}
	return NewDialerFromSubscription(sub, opts)
}

// NewDialerFromSubscription creates a load-balanced Dial from a pre-parsed subscription.
func NewDialerFromSubscription(sub *Subscription, opts Options) (proxyclient.Dial, *Subscription, error) {
	strategy := opts.Strategy
	if strategy == "" {
		strategy = StrategyAdaptive
	}

	// url-test or explicit HealthCheck: run health check to get healthy dials
	if strategy == StrategyURLTest || opts.HealthCheck != nil {
		return newDialerWithHealthCheck(sub, opts, strategy)
	}

	// fast path: no health check
	nodes := DialableNodes(sub)
	if opts.Filter != nil {
		var filtered []ProxyNode
		for _, n := range nodes {
			if opts.Filter(n) {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}
	if len(nodes) == 0 {
		return nil, sub, fmt.Errorf("clash: no dialable nodes after filtering")
	}

	dials := make([]proxyclient.Dial, 0, len(nodes))
	for _, n := range nodes {
		d, err := proxyclient.NewClient(n.URL)
		if err != nil {
			continue
		}
		dials = append(dials, d)
	}
	if len(dials) == 0 {
		return nil, sub, fmt.Errorf("clash: failed to create dialer for any node")
	}

	return applyStrategy(dials, strategy, sub)
}

func newDialerWithHealthCheck(sub *Subscription, opts Options, strategy Strategy) (proxyclient.Dial, *Subscription, error) {
	results := HealthCheck(sub, opts.HealthCheck, opts.Filter)
	dials := HealthyDials(results)
	if len(dials) == 0 {
		return nil, sub, fmt.Errorf("clash: no healthy nodes (tested %d)", len(results))
	}

	// url-test: healthy nodes fed into adaptive for continued learning
	if strategy == StrategyURLTest {
		strategy = StrategyAdaptive
	}
	return applyStrategy(dials, strategy, sub)
}

func applyStrategy(dials []proxyclient.Dial, strategy Strategy, sub *Subscription) (proxyclient.Dial, *Subscription, error) {
	if len(dials) == 1 {
		return dials[0], sub, nil
	}
	var dial proxyclient.Dial
	switch strategy {
	case StrategyRoundRobin:
		dial = loadbalance.NewRoundRobin(dials)
	case StrategyRandom:
		dial = loadbalance.NewRandom(dials)
	case StrategyHash:
		dial = loadbalance.NewHash(dials)
	case StrategyFirst:
		dial = dials[0]
	case StrategyAdaptive:
		dial = loadbalance.NewAdaptive(dials)
	default:
		return nil, sub, fmt.Errorf("clash: unknown strategy %q", strategy)
	}
	return dial, sub, nil
}

// FetchSubscriptionWithUA fetches a subscription with the given User-Agent.
func FetchSubscriptionWithUA(subscribeURL, userAgent string) (*Subscription, error) {
	if userAgent == "" {
		userAgent = "clash"
	}
	// Temporarily swap the fetch to use custom UA
	// We reuse the existing FetchSubscription but need to handle UA
	return fetchWithUA(subscribeURL, userAgent)
}

// FilterByType returns a filter function that only keeps nodes of the given types.
func FilterByType(types ...string) func(ProxyNode) bool {
	set := make(map[string]bool, len(types))
	for _, t := range types {
		set[strings.ToLower(t)] = true
	}
	return func(n ProxyNode) bool {
		return set[n.Type]
	}
}

// FilterByName returns a filter function that keeps nodes whose name contains the keyword.
func FilterByName(keyword string) func(ProxyNode) bool {
	keyword = strings.ToLower(keyword)
	return func(n ProxyNode) bool {
		return strings.Contains(strings.ToLower(n.Name), keyword)
	}
}
