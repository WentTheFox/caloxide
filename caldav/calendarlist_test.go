package caldav

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

// listFixture is a calendar-list cache over a fake Proton that counts how often it is asked.
type listFixture struct {
	c     *calendarListCache
	calls atomic.Int32
	mu    sync.Mutex
	now   time.Time
	err   error
	delay time.Duration
	names []string
}

func newListFixture() *listFixture {
	f := &listFixture{now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), names: []string{"a"}}
	f.c = &calendarListCache{now: f.clock}
	f.c.fetch = func() ([]*protonmail.Calendar, error) {
		f.calls.Add(1)
		f.mu.Lock()
		err, delay := f.err, f.delay
		var out []*protonmail.Calendar
		for _, id := range f.names {
			out = append(out, &protonmail.Calendar{ID: id})
		}
		f.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		return out, err
	}
	return f
}

func (f *listFixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *listFixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}
func (f *listFixture) setErr(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func TestTheCalendarListIsFetchedOnceWithinItsLifetime(t *testing.T) {
	f := newListFixture()
	for i := 0; i < 10; i++ {
		if list, err := f.c.get(); err != nil || len(list) != 1 {
			t.Fatalf("%v %v", list, err)
		}
	}
	if f.calls.Load() != 1 {
		t.Fatalf("%d requests to Proton for 10 checks, want 1", f.calls.Load())
	}
}

func TestItIsFetchedAgainOnceItHasExpired(t *testing.T) {
	f := newListFixture()
	f.c.get()
	f.advance(calendarListTTL - time.Second)
	f.c.get()
	if f.calls.Load() != 1 {
		t.Fatal("fetched again too early")
	}
	f.advance(2 * time.Second)
	f.c.get()
	if f.calls.Load() != 2 {
		t.Fatalf("%d requests, want a second one after the lifetime", f.calls.Load())
	}
}

func TestSixCalendarsCheckedAtOnceCostOneRequest(t *testing.T) {
	f := newListFixture()
	f.delay = 100 * time.Millisecond // long enough that all of them arrive while it runs
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if list, err := f.c.get(); err != nil || len(list) != 1 {
				t.Errorf("%v %v", list, err)
			}
		}()
	}
	wg.Wait()
	if f.calls.Load() != 1 {
		t.Fatalf("%d requests for 12 simultaneous checks, want exactly 1", f.calls.Load())
	}
}

func TestAFailureIsNotCachedAndEveryoneWaitingGetsIt(t *testing.T) {
	f := newListFixture()
	f.setErr(errors.New("proton is down"))
	f.delay = 80 * time.Millisecond
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.c.get(); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 6 {
		t.Fatalf("%d of 6 callers saw the error", failed.Load())
	}
	if f.calls.Load() != 1 {
		t.Fatalf("%d requests, want the waiters to share one", f.calls.Load())
	}

	f.setErr(nil)
	f.delay = 0
	if list, err := f.c.get(); err != nil || len(list) != 1 {
		t.Fatalf("the next check must try again: %v %v", list, err)
	}
}

func TestAnOldListKeepsClientsWorkingThroughAnOutage(t *testing.T) {
	f := newListFixture()
	f.c.get()
	f.advance(10 * time.Minute) // expired, but not too old
	f.setErr(errors.New("rate limited by Proton"))
	list, err := f.c.get()
	if err != nil || len(list) != 1 {
		t.Fatalf("an outage must not break checks of calendars we already know: %v %v", list, err)
	}

	f.advance(2 * time.Hour) // far too old to trust
	if _, err := f.c.get(); err == nil {
		t.Fatal("a list from hours ago must not be served forever")
	}
}

func TestWithNothingKnownAnOutageIsAnError(t *testing.T) {
	f := newListFixture()
	f.setErr(errors.New("down"))
	if _, err := f.c.get(); err == nil || !strings.Contains(err.Error(), "down") {
		t.Fatalf("%v", err)
	}
}

func TestInvalidateForcesTheNextCheckToAskProton(t *testing.T) {
	f := newListFixture()
	f.c.get()
	f.c.invalidate()
	f.mu.Lock()
	f.names = []string{"a", "b"}
	f.mu.Unlock()
	list, _ := f.c.get()
	if len(list) != 2 || f.calls.Load() != 2 {
		t.Fatalf("list=%d calls=%d", len(list), f.calls.Load())
	}
}

func TestRefreshIgnoresTheCacheAndUpdatesIt(t *testing.T) {
	f := newListFixture()
	f.c.get()
	f.mu.Lock()
	f.names = []string{"a", "b", "c"}
	f.mu.Unlock()
	list, err := f.c.refresh()
	if err != nil || len(list) != 3 {
		t.Fatalf("%v %v", list, err)
	}
	if again, _ := f.c.get(); len(again) != 3 || f.calls.Load() != 2 {
		t.Fatalf("what refresh fetched must be what later checks see (calls=%d)", f.calls.Load())
	}
	f.setErr(errors.New("down"))
	if _, err := f.c.refresh(); err == nil {
		t.Fatal("a refresh that fails is an error, not a silent reuse")
	}
}

func TestACalendarChangeInTheAccountEventLoopDropsTheCachedList(t *testing.T) {
	// reconcileCalendars refreshes on purpose; this guards that it goes through refresh and
	// leaves a list that later checks reuse instead of asking again.
	f := newListFixture()
	b := &backend{caches: map[string]*calendarCache{}, pollers: map[string]bool{}, stops: map[string]chan struct{}{}}
	b.calListOnce.Do(func() { b.calList = f.c })
	f.c.get() // one calendar, "a", is known and cached

	f.mu.Lock()
	f.names = []string{"b"} // "a" is gone from the account
	f.mu.Unlock()
	b.caches["a"] = fresh()
	b.pollers["a"] = true
	b.stops["a"] = make(chan struct{})
	b.reconcileCalendars()

	if b.pollers["a"] {
		t.Fatal("reconcile must see the new list, not the cached one: the removed calendar kept its poller")
	}
	before := f.calls.Load()
	if list, _ := b.protonCalendars(); len(list) != 1 || list[0].ID != "b" {
		t.Fatalf("later checks must see the fresh list: %v", list)
	}
	if f.calls.Load() != before {
		t.Fatal("the list refresh made by reconcile should be reused")
	}
}

func TestWaitersOnAFailedFetchShareItEvenWhenAnOldListIsServed(t *testing.T) {
	f := newListFixture()
	f.c.get()
	f.advance(10 * time.Minute) // expired, but within the time an old list is trusted
	f.setErr(errors.New("down"))
	f.delay = 80 * time.Millisecond
	before := f.calls.Load()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if list, err := f.c.get(); err != nil || len(list) != 1 {
				t.Errorf("the old list should keep every caller working: %v %v", list, err)
			}
		}()
	}
	wg.Wait()
	if n := f.calls.Load() - before; n != 1 {
		t.Fatalf("%d requests for 8 simultaneous checks during an outage, want 1 (no stampede)", n)
	}
}

func TestTheOldListNoticeIsLoggedOncePerOutage(t *testing.T) {
	f := newListFixture()
	f.c.get()
	logs := captureCacheLog(t)
	f.advance(10 * time.Minute)
	f.setErr(errors.New("down"))
	for i := 0; i < 5; i++ {
		f.c.get()
		f.advance(time.Minute)
	}
	if n := strings.Count(logs.String(), "using the one from"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, logs.String())
	}

	// A recovery and a second outage is a new notice.
	f.setErr(nil)
	f.c.get()
	f.advance(10 * time.Minute)
	f.setErr(errors.New("down again"))
	f.c.get()
	if n := strings.Count(logs.String(), "using the one from"); n != 2 {
		t.Fatalf("a new outage should be reported again, logged %d times", n)
	}
}
