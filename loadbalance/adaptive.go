package loadbalance

import (
	"context"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proxyclient"
)

type nodeStats struct {
	dial    proxyclient.Dial
	success atomic.Int64
	failure atomic.Int64
	totalMs atomic.Int64 // cumulative latency in ms
	lastErr atomic.Int64 // unix ms of last error, 0 = never
}

func (s *nodeStats) score() float64 {
	succ := s.success.Load()
	fail := s.failure.Load()
	total := succ + fail
	if total == 0 {
		return 1.0 // untested nodes get a neutral score
	}
	successRate := float64(succ) / float64(total)

	// average latency factor: lower is better, normalize to [0, 1]
	var latencyFactor float64
	if succ > 0 {
		avgMs := float64(s.totalMs.Load()) / float64(succ)
		// sigmoid-like: 1000ms → 0.5, 3000ms → 0.18, 500ms → 0.67
		latencyFactor = 1.0 / (1.0 + avgMs/1000.0)
	}

	// recent failure penalty: if last error was recent, reduce score
	var recencyPenalty float64
	if lastErr := s.lastErr.Load(); lastErr > 0 {
		elapsed := time.Since(time.UnixMilli(lastErr)).Seconds()
		// exponential decay: 0s → penalty 1.0, 60s → ~0.37, 300s → ~0.007
		recencyPenalty = math.Exp(-elapsed / 60.0)
	}

	// final score: success rate weighted by latency, penalized by recent failures
	return successRate * (0.5 + 0.5*latencyFactor) * (1.0 - 0.5*recencyPenalty)
}

// NewAdaptive creates a Dial that tracks success/failure/latency per node
// and routes traffic to the best-performing nodes.
func NewAdaptive(dials []proxyclient.Dial) proxyclient.Dial {
	nodes := make([]*nodeStats, len(dials))
	for i, d := range dials {
		nodes[i] = &nodeStats{dial: d}
	}

	var mu sync.Mutex
	var ranked []*nodeStats

	rerank := func() {
		mu.Lock()
		defer mu.Unlock()
		// copy and sort by score descending
		ranked = make([]*nodeStats, len(nodes))
		copy(ranked, nodes)
		for i := 1; i < len(ranked); i++ {
			for j := i; j > 0 && ranked[j].score() > ranked[j-1].score(); j-- {
				ranked[j], ranked[j-1] = ranked[j-1], ranked[j]
			}
		}
	}
	rerank()

	var callCount atomic.Int64

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		count := callCount.Add(1)

		// re-rank every 10 calls
		if count%10 == 0 {
			rerank()
		}

		mu.Lock()
		current := ranked
		mu.Unlock()

		// try top node first, fallback to others on failure
		for _, node := range current {
			start := time.Now()
			conn, err := node.dial(ctx, network, address)
			elapsed := time.Since(start)

			if err != nil {
				node.failure.Add(1)
				node.lastErr.Store(time.Now().UnixMilli())
				continue
			}
			node.success.Add(1)
			node.totalMs.Add(elapsed.Milliseconds())
			return conn, nil
		}
		return nil, net.ErrClosed
	}
}
