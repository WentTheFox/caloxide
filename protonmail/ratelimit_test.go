package protonmail

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock replaces time for the rate limiter: Sleep advances it, nothing really waits.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func useFakeClock(t *testing.T) *fakeClock {
	fc := &fakeClock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	oldNow, oldSleep := rlNow, rlSleep
	rlNow = func() time.Time { fc.mu.Lock(); defer fc.mu.Unlock(); return fc.t }
	rlSleep = func(d time.Duration) {
		fc.mu.Lock()
		fc.t = fc.t.Add(d)
		fc.slept = append(fc.slept, d)
		fc.mu.Unlock()
	}
	resetAllGates()
	t.Cleanup(func() { rlNow, rlSleep = oldNow, oldSleep; resetAllGates() })
	return fc
}

func (fc *fakeClock) totalSlept() (sum time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for _, d := range fc.slept {
		sum += d
	}
	return
}

func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// limitedServer answers the first `limited` requests with 429 and the rest with 200.
func limitedServer(t *testing.T, limited int32, retryAfter string) (*Client, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= limited {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.Header().Set("Set-Cookie", "Session-Id=SECRET; Path=/")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"Code":85131,"Error":"Too many requests"}`)
			return
		}
		fmt.Fprint(w, `{"Code":1000,"Calendars":[]}`)
	}))
	t.Cleanup(srv.Close)
	freshGate(srv.URL)
	c := &Client{RootURL: srv.URL, AppVersion: "Other"}
	c.SetSession("u", "t")
	return c, &hits
}

func TestRetryAfterIsHonouredThenRequestSucceeds(t *testing.T) {
	fc := useFakeClock(t)
	logs := captureLog(t)
	c, hits := limitedServer(t, 1, "7")
	var told time.Duration
	c.OnRateLimited = func(d time.Duration) { told = d }

	if _, err := c.ListCalendars(); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d requests, want the refused one and one retry", hits.Load())
	}
	if got := fc.totalSlept(); got < 7*time.Second {
		t.Fatalf("waited only %s before retrying, Proton said 7s", got)
	}
	if told != 7*time.Second {
		t.Errorf("hook told %s", told)
	}
	out := logs.String()
	for _, want := range []string{"rate limited by Proton", "unexpected response", `why="rate limited"`, "status=429", "Retry-After=7", "Too many requests"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SECRET") {
		t.Errorf("the session cookie leaked into the log:\n%s", out)
	}
}

func TestRetryAfterAsHTTPDate(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter(now.Add(90*time.Second).UTC().Format(http.TimeFormat), now); !ok || d < 89*time.Second || d > 91*time.Second {
		t.Fatalf("got %s %v", d, ok)
	}
	for _, bad := range []string{"", "soon", "-5"} {
		if _, ok := parseRetryAfter(bad, now); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestMissingRetryAfterBacksOffAndGivesUp(t *testing.T) {
	fc := useFakeClock(t)
	captureLog(t)
	c, hits := limitedServer(t, 100, "")
	_, err := c.ListCalendars()
	var rl *RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want a RateLimitedError", err)
	}
	if int(hits.Load()) != maxRateRetries+1 {
		t.Fatalf("%d requests, want %d (one try and %d retries) and then to stop", hits.Load(), maxRateRetries+1, maxRateRetries)
	}
	// 10s, 20s, 40s (plus jitter) were waited out between the attempts.
	if got := fc.totalSlept(); got < 70*time.Second {
		t.Fatalf("waited only %s in total", got)
	}
}

func TestLongPauseFailsFastAndNothingIsSentWhilePaused(t *testing.T) {
	useFakeClock(t)
	captureLog(t)
	c, hits := limitedServer(t, 100, "3600")
	if _, err := c.ListCalendars(); err == nil {
		t.Fatal("expected an error")
	}
	after := hits.Load()
	for i := 0; i < 5; i++ {
		_, err := c.ListCalendars()
		var rl *RateLimitedError
		if !errors.As(err, &rl) {
			t.Fatalf("err = %v", err)
		}
	}
	if hits.Load() != after {
		t.Fatalf("%d more requests reached Proton while it had asked us to wait an hour", hits.Load()-after)
	}
}

func TestPauseIsSharedByEveryClientOfTheHost(t *testing.T) {
	fc := useFakeClock(t)
	captureLog(t)
	c, hits := limitedServer(t, 1, "20")
	if _, err := c.ListCalendars(); err != nil {
		t.Fatal(err)
	}
	// A different client (a detached one, as the re-login uses, or another calendar's
	// poller) must not send before the pause is over.
	other := c.Detached()
	other.SetSession("u2", "t2")
	before := fc.totalSlept()
	fc.mu.Lock()
	fc.t = fc.t.Add(-15 * time.Second) // 5 seconds into the 20 second pause: 15 remain
	fc.mu.Unlock()
	if _, err := other.ListCalendars(); err != nil {
		t.Fatal(err)
	}
	if fc.totalSlept()-before < 10*time.Second {
		t.Fatalf("a second client waited only %s, it must honour the same pause", fc.totalSlept()-before)
	}
	_ = hits
}

func TestUnlimitedResponsesAreNotLogged(t *testing.T) {
	useFakeClock(t)
	logs := captureLog(t)
	c, _ := limitedServer(t, 0, "")
	if _, err := c.ListCalendars(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "unexpected response") {
		t.Errorf("a normal response was logged as unexpected:\n%s", logs.String())
	}
}

func TestSpacingQueuesConcurrentRequests(t *testing.T) {
	fc := useFakeClock(t)
	old := minRequestSpacing
	minRequestSpacing = 250 * time.Millisecond
	t.Cleanup(func() { minRequestSpacing = old })

	g := &rateGate{}
	var waits []time.Duration
	for i := 0; i < 7; i++ { // six calendar pollers and the core loop on one tick
		waits = append(waits, g.reserve())
	}
	for i, w := range waits {
		if want := time.Duration(i) * 250 * time.Millisecond; w != want {
			t.Errorf("request %d waits %s, want %s", i, w, want)
		}
	}
	fc.mu.Lock()
	fc.t = fc.t.Add(time.Minute)
	fc.mu.Unlock()
	if w := g.reserve(); w != 0 {
		t.Errorf("an idle gate made a request wait %s", w)
	}
}

func TestListingAsksForOnePageAtATimeAfterALimit(t *testing.T) {
	f := &fakeEvents{total: 600, delay: 20 * time.Millisecond, failPage: -1}
	c := listClient(t, f)
	t.Cleanup(resetAllGates)
	c.rateGate().limit(time.Millisecond)
	if _, err := c.ListAllCalendarEvents("cal", nil); err != nil {
		t.Fatal(err)
	}
	if peak := f.peak.Load(); peak != 1 {
		t.Fatalf("peak concurrency %d right after a rate limit, want 1", peak)
	}
}

func TestSpacingNeverQueuesLongerThanTheCap(t *testing.T) {
	old := minRequestSpacing
	minRequestSpacing = 250 * time.Millisecond
	defer func() { minRequestSpacing = old }()

	g := &rateGate{next: time.Now().Add(10 * time.Hour)} // as left behind by a clock that jumped
	if w := g.reserve(); w > time.Second {
		t.Fatalf("a corrupt queue made a request wait %s", w)
	}
	// An honest queue is untouched.
	h := &rateGate{}
	var last time.Duration
	for i := 0; i < 8; i++ {
		last = h.reserve()
	}
	if last < 1500*time.Millisecond || last > 2200*time.Millisecond {
		t.Fatalf("eight requests at once: the last waits %s, want about 1.75s", last)
	}
}
