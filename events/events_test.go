package events

import (
	"testing"
	"time"
)

func TestPollNeverBlocksAndCoalesces(t *testing.T) {
	r := &Receiver{poll: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			r.Poll() // nobody is receiving: an unbuffered blocking send would hang here
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poll blocked")
	}
	if len(r.poll) != 1 {
		t.Fatalf("%d wake-ups pending, want exactly one", len(r.poll))
	}
}

func TestIntervalDefaultsAndCanBeReplaced(t *testing.T) {
	r := &Receiver{poll: make(chan struct{}, 1)}
	if got := r.currentInterval(); got != pollInterval {
		t.Fatalf("default = %s", got)
	}
	r.SetInterval(func() time.Duration { return 15 * time.Minute })
	if got := r.currentInterval(); got != 15*time.Minute {
		t.Fatalf("replaced = %s", got)
	}
	r.SetInterval(nil)
	if got := r.currentInterval(); got != pollInterval {
		t.Fatalf("restored = %s", got)
	}
}
