package loadbalance

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proxyclient"
)

const (
	deadThreshold  = 3                // consecutive failures to mark dead
	deadCooldown   = 60 * time.Second // how long a dead node stays dead before retry
	retryOnDead    = true
)

type nodeState struct {
	dial       proxyclient.Dial
	consFail   atomic.Int32  // consecutive failures
	deadSince  atomic.Int64  // unix ms, 0 = alive
}

func (s *nodeState) alive() bool {
	ds := s.deadSince.Load()
	if ds == 0 {
		return true
	}
	// allow retry after cooldown
	return time.Since(time.UnixMilli(ds)) > deadCooldown
}

func (s *nodeState) recordSuccess() {
	s.consFail.Store(0)
	s.deadSince.Store(0)
}

func (s *nodeState) recordFailure() {
	n := s.consFail.Add(1)
	if n >= int32(deadThreshold) {
		s.deadSince.Store(time.Now().UnixMilli())
	}
}

// Tracker wraps a set of Dials with dead-node detection.
// Nodes that fail consecutively are temporarily removed from rotation.
type Tracker struct {
	mu    sync.RWMutex
	nodes []*nodeState
}

func NewTracker(dials []proxyclient.Dial) *Tracker {
	nodes := make([]*nodeState, len(dials))
	for i, d := range dials {
		nodes[i] = &nodeState{dial: d}
	}
	return &Tracker{nodes: nodes}
}

// AliveIndices returns indices of nodes currently considered alive.
func (t *Tracker) AliveIndices() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var indices []int
	for i, n := range t.nodes {
		if n.alive() {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		// all dead — return all for retry
		indices = make([]int, len(t.nodes))
		for i := range t.nodes {
			indices[i] = i
		}
	}
	return indices
}

// Dial tries the node at index, records success/failure, and falls back on error.
func (t *Tracker) Dial(ctx context.Context, network, address string, pick int) (net.Conn, error) {
	node := t.nodes[pick]
	conn, err := node.dial(ctx, network, address)
	if err == nil {
		node.recordSuccess()
		return conn, nil
	}
	node.recordFailure()

	// fallback: try other alive nodes
	for _, i := range t.AliveIndices() {
		if i == pick {
			continue
		}
		conn, err2 := t.nodes[i].dial(ctx, network, address)
		if err2 == nil {
			t.nodes[i].recordSuccess()
			return conn, nil
		}
		t.nodes[i].recordFailure()
	}
	return nil, err // return original error
}

func (t *Tracker) Len() int { return len(t.nodes) }
