package backoff

import (
	"sync"
	"testing"
	"time"
)

func noJitter(base, max time.Duration) *Backoff {
	b := New(base, max)
	b.rnd = func() float64 { return 0.5 } // factor exactly 1
	return b
}

func TestDelaysDoubleThenCap(t *testing.T) {
	b := noJitter(30*time.Second, 10*time.Minute)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Errorf("failure %d: got %v, want %v", i+1, got, w)
		}
	}
}

func TestResetStartsOver(t *testing.T) {
	b := noJitter(time.Second, time.Hour)
	b.Next()
	b.Next()
	b.Next()
	if b.Failures() != 3 {
		t.Fatalf("failures = %d", b.Failures())
	}
	b.Reset()
	if b.Failures() != 0 || b.Next() != time.Second {
		t.Error("Reset must restart the sequence at base")
	}
}

func TestJitterStaysWithinBoundsAndNeverExceedsMax(t *testing.T) {
	for _, r := range []float64{0, 0.25, 0.999999} {
		b := New(time.Minute, 10*time.Minute)
		b.rnd = func() float64 { return r }
		for i := 0; i < 12; i++ {
			d := b.Next()
			if d > 10*time.Minute {
				t.Fatalf("rnd=%v failure %d: %v exceeds max", r, i+1, d)
			}
			if d <= 0 {
				t.Fatalf("rnd=%v failure %d: non-positive delay %v", r, i+1, d)
			}
		}
	}
	// With the minimum random draw the first delay is base*(1-jitter).
	b := New(100*time.Second, time.Hour)
	b.rnd = func() float64 { return 0 }
	if d := b.Next(); d != 80*time.Second {
		t.Errorf("lowest first delay = %v, want 80s", d)
	}
}

func TestManyFailuresDoNotOverflow(t *testing.T) {
	b := noJitter(30*time.Second, 30*time.Minute)
	var last time.Duration
	for i := 0; i < 500; i++ {
		last = b.Next()
		if last <= 0 || last > 30*time.Minute {
			t.Fatalf("failure %d: delay %v out of range", i+1, last)
		}
	}
	if last != 30*time.Minute {
		t.Errorf("after many failures the delay must sit at max, got %v", last)
	}
}

func TestConcurrentUse(t *testing.T) {
	b := New(time.Millisecond, time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Next()
				b.Failures()
			}
		}()
	}
	wg.Wait()
	if b.Failures() != 800 {
		t.Errorf("lost updates: %d", b.Failures())
	}
}
