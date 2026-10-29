// Package backoff computes exponentially growing retry delays with jitter.
// Standard library only.
package backoff

import (
	"math/rand"
	"sync"
	"time"
)

// Backoff hands out delays that double with every consecutive failure, starting at
// base and never exceeding max, each randomised by up to +/-jitter so several
// retrying components (six calendar pollers, the event loop) do not hit Proton in
// lockstep. It is safe for concurrent use.
type Backoff struct {
	base, max time.Duration
	jitter    float64
	rnd       func() float64 // uniform in [0,1); replaced in tests

	mu       sync.Mutex
	failures int
}

// New returns a Backoff with 20% jitter.
func New(base, max time.Duration) *Backoff {
	return &Backoff{base: base, max: max, jitter: 0.2, rnd: rand.Float64}
}

// Next records one more failure and returns how long to wait before retrying:
// base, 2*base, 4*base, ... capped at max.
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	b.failures++
	n := b.failures
	b.mu.Unlock()

	d := b.max
	if shift := n - 1; shift < 40 { // beyond this the shift would overflow anyway
		if grown := b.base << uint(shift); grown > 0 && grown < b.max {
			d = grown
		}
	}
	// Spread over [d*(1-jitter), d*(1+jitter)], but never past max.
	spread := 1 + b.jitter*(2*b.rnd()-1)
	d = time.Duration(float64(d) * spread)
	if d > b.max {
		d = b.max
	}
	if d < 0 {
		d = b.base
	}
	return d
}

// Reset forgets past failures; call it after a success.
func (b *Backoff) Reset() {
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}

// Failures reports the number of consecutive failures recorded.
func (b *Backoff) Failures() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}
