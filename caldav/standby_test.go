package caldav

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newStandby(enabled bool) (*standbyState, *clock) {
	clk := &clock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	s := newStandbyState(standbySettings{enabled: enabled, after: 5 * time.Minute, interval: 15 * time.Minute})
	s.now = clk.now
	s.last = clk.now()
	return s, clk
}

func TestPollsAtTheNormalPaceWhileClientsAreAround(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(4 * time.Minute)
	if got := s.interval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("4 minutes idle: %s", got)
	}
}

func TestSlowsDownOnlyAfterTheIdleTime(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(5 * time.Minute)
	if got := s.interval(30 * time.Second); got != 15*time.Minute {
		t.Fatalf("5 minutes idle: %s, want the standby interval", got)
	}
	if _, idle, _ := s.state(); !idle {
		t.Fatal("state must say idle")
	}
}

func TestStandbyNeverMakesPollingFasterThanTheBase(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(time.Hour)
	if got := s.interval(30 * time.Minute); got != 30*time.Minute {
		t.Fatalf("a base slower than the standby interval must stay: %s", got)
	}
}

func TestDisabledStandbyChangesNothing(t *testing.T) {
	s, clk := newStandby(false)
	clk.advance(24 * time.Hour)
	if got := s.interval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("%s", got)
	}
	s.touch() // must not panic or catch up
	var nilState *standbyState
	if got := nilState.interval(time.Second); got != time.Second {
		t.Fatal("a nil state is a disabled one")
	}
	nilState.touch()
}

func TestActiveClientsNeverTriggerACatchUp(t *testing.T) {
	s, clk := newStandby(true)
	var calls atomic.Int32
	s.catchUp = func() { calls.Add(1) }
	for i := 0; i < 10; i++ {
		clk.advance(time.Minute)
		s.touch()
		s.interval(30 * time.Second)
	}
	if calls.Load() != 0 {
		t.Fatalf("%d catch-ups for a client that never went away", calls.Load())
	}
}

func TestFirstRequestBackCatchesUpOnceAndEveryoneWaitsForIt(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(20 * time.Minute)
	s.interval(30 * time.Second) // a poller notices the standby

	release := make(chan struct{})
	var calls atomic.Int32
	s.catchUp = func() { calls.Add(1); <-release }

	var finished atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ { // Thunderbird asks about several calendars at once
		wg.Add(1)
		go func() { defer wg.Done(); s.touch(); finished.Add(1) }()
	}
	time.Sleep(100 * time.Millisecond)
	if finished.Load() != 0 {
		t.Fatalf("%d requests were served before the catch-up was over", finished.Load())
	}
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("%d catch-ups, want exactly one", calls.Load())
	}
	if got := s.interval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("after the catch-up polling must be back to normal, got %s", got)
	}
	if _, idle, _ := s.state(); idle {
		t.Fatal("still idle after a client came back")
	}
}

func TestStandbyIsNotReenteredWhileACatchUpRuns(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(20 * time.Minute)
	s.interval(30 * time.Second)

	started, release := make(chan struct{}), make(chan struct{})
	s.catchUp = func() { close(started); <-release }
	go s.touch()
	<-started
	clk.advance(time.Hour) // a poller wakes during the catch-up, long after the last request
	if got := s.interval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("a poller woken by the catch-up must not fall back asleep: %s", got)
	}
	close(release)
}

// --- cycle accounting ---

func TestAPollAlreadyInFlightDoesNotCountAsTheCatchUp(t *testing.T) {
	var c cycles
	c.register("cal")
	c.begin("cal") // started before the client came back
	target := c.target("cal")
	c.end("cal") // the old poll ends
	if c.waitFor("cal", target, time.After(50*time.Millisecond)) {
		t.Fatal("a poll that began before the wake-up was taken for the catch-up")
	}
	c.begin("cal")
	c.end("cal") // the poll the wake-up caused
	if !c.waitFor("cal", target, time.After(time.Second)) {
		t.Fatal("the poll after the wake-up must count")
	}
}

func TestIdlePollerNeedsOneFullCycle(t *testing.T) {
	var c cycles
	c.register("cal")
	c.begin("cal")
	c.end("cal")
	target := c.target("cal")
	if c.waitFor("cal", target, time.After(30*time.Millisecond)) {
		t.Fatal("nothing has polled since")
	}
	go func() { time.Sleep(30 * time.Millisecond); c.begin("cal"); c.end("cal") }()
	if !c.waitFor("cal", target, time.After(2*time.Second)) {
		t.Fatal("never saw the cycle")
	}
}

func catchUpBackend(t *testing.T, ids ...string) *backend {
	b := &backend{caches: map[string]*calendarCache{}, pollers: map[string]bool{}}
	for _, id := range ids {
		b.cycles.register(id)
		wake := b.push.register(id)
		go func(id string, wake <-chan struct{}) { // a stand-in poller
			for range wake {
				b.cycles.begin(id)
				time.Sleep(20 * time.Millisecond)
				b.cycles.end(id)
			}
		}(id, wake)
	}
	return b
}

func TestCatchUpPollsEveryCalendarAndWaitsForAll(t *testing.T) {
	b := catchUpBackend(t, "a", "b", "c")
	var coreWoken atomic.Bool
	b.core = func() { coreWoken.Store(true) }
	start := time.Now()
	b.catchUp()
	if took := time.Since(start); took < 15*time.Millisecond || took > 3*time.Second {
		t.Fatalf("took %s", took)
	}
	for _, id := range []string{"a", "b", "c"} {
		cs := b.cycles.get(id)
		b.cycles.mu.Lock()
		f := cs.finished
		b.cycles.mu.Unlock()
		if f != 1 {
			t.Errorf("calendar %s finished %d polls, want 1", id, f)
		}
	}
	if !coreWoken.Load() {
		t.Error("the account event loop must be woken too")
	}
}

func TestAHungPollerDoesNotBlockRequestsForever(t *testing.T) {
	old := catchUpTimeout
	catchUpTimeout = 150 * time.Millisecond
	defer func() { catchUpTimeout = old }()

	b := &backend{caches: map[string]*calendarCache{}, pollers: map[string]bool{}}
	b.cycles.register("stuck")
	b.push.register("stuck") // nobody receives: the poller is wedged
	start := time.Now()
	b.catchUp()
	if took := time.Since(start); took < 100*time.Millisecond || took > 2*time.Second {
		t.Fatalf("gave up after %s, want about the timeout", took)
	}
}

func TestStoppedPollersAreNotWaitedFor(t *testing.T) {
	b := catchUpBackend(t, "a", "gone")
	b.cycles.forget("gone")
	start := time.Now()
	b.catchUp()
	if time.Since(start) > 2*time.Second {
		t.Fatal("waited for a poller that no longer exists")
	}
}

// --- the HTTP layer ---

func TestRequestsAreHeldUntilTheCatchUpIsDone(t *testing.T) {
	s, clk := newStandby(true)
	clk.advance(time.Hour)
	s.interval(30 * time.Second)
	var order []string
	var mu sync.Mutex
	add := func(x string) { mu.Lock(); order = append(order, x); mu.Unlock() }
	s.catchUp = func() { time.Sleep(50 * time.Millisecond); add("caught up") }

	b := &backend{standby: s}
	h := activityHandler{b: b, next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { add("served") })}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PROPFIND", "/caldav/", nil))

	if strings.Join(order, ",") != "caught up,served" {
		t.Fatalf("order = %v: data was served before it was brought up to date", order)
	}
}

func TestWiringTheCoreLoop(t *testing.T) {
	s, clk := newStandby(true)
	b := &backend{standby: s}
	var interval func() time.Duration
	var polled atomic.Int32
	WireCoreLoop(activityHandler{b: b}, func(f func() time.Duration) { interval = f }, func() { polled.Add(1) })
	if interval == nil {
		t.Fatal("the interval was not installed")
	}
	if got := interval(); got != coreBaseInterval {
		t.Fatalf("active: %s", got)
	}
	clk.advance(time.Hour)
	if got := interval(); got != 15*time.Minute {
		t.Fatalf("idle: %s", got)
	}
	s.catchUp = b.catchUp
	b.cycles.register("x")
	old := catchUpTimeout
	catchUpTimeout = 20 * time.Millisecond
	defer func() { catchUpTimeout = old }()
	s.touch()
	if polled.Load() != 1 {
		t.Fatalf("the account loop was woken %d times, want once", polled.Load())
	}

	// A plain handler, or standby switched off, leaves the loop alone.
	called := false
	WireCoreLoop(http.NotFoundHandler(), func(func() time.Duration) { called = true }, func() {})
	off, _ := newStandby(false)
	WireCoreLoop(activityHandler{b: &backend{standby: off}}, func(func() time.Duration) { called = true }, func() {})
	if called {
		t.Fatal("wired a handler that has no standby")
	}
}

// --- configuration ---

func TestStandbySettings(t *testing.T) {
	for _, tc := range []struct {
		name, on, after, every string
		want                   standbySettings
	}{
		{"defaults", "", "", "", standbySettings{true, 5 * time.Minute, 15 * time.Minute}},
		{"off", "off", "", "", standbySettings{false, 5 * time.Minute, 15 * time.Minute}},
		{"custom", "on", "10m", "30m", standbySettings{true, 10 * time.Minute, 30 * time.Minute}},
		{"floors", "", "5s", "10s", standbySettings{true, minStandbyAfter, minStandbyInterval}},
		{"nonsense", "maybe", "soon", "-1m", standbySettings{true, 5 * time.Minute, 15 * time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CALOXIDE_STANDBY", tc.on)
			t.Setenv("CALOXIDE_STANDBY_AFTER", tc.after)
			t.Setenv("CALOXIDE_STANDBY_INTERVAL", tc.every)
			if got := standbySettingsFromEnv(); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOtherProtocolsSwitchStandbyOff(t *testing.T) {
	defer SetStandbyAllowed(true)
	SetStandbyAllowed(false)
	t.Setenv("CALOXIDE_STANDBY", "on") // asking for it does not help: it would be wrong
	if standbySettingsFromEnv().enabled {
		t.Fatal("standby must stay off when IMAP, SMTP or CardDAV are served too")
	}
}

func TestStatusMentionsStandby(t *testing.T) {
	b, _ := loadingBackend(false, 1)
	s, clk := newStandby(true)
	b.standby = s
	if out := (Status{Users: []UserStatus{b.status()}}).String(); !strings.Contains(out, "Standby: on (active)") {
		t.Errorf("active:\n%s", out)
	}
	clk.advance(30 * time.Minute)
	s.interval(30 * time.Second)
	clk.advance(10 * time.Minute)
	if out := (Status{Users: []UserStatus{b.status()}}).String(); !strings.Contains(out, "Standby: idle for") {
		t.Errorf("idle:\n%s", out)
	}
}
