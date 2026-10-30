package caldav

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
)

func obj(path string) caldav.CalendarObject {
	return caldav.CalendarObject{Path: path, ETag: "e-" + path, Data: ical.NewCalendar()}
}

// loadingBackend has one calendar whose first load is running and has decoded n events.
func loadingBackend(early bool, n int) (*backend, *calendarCache) {
	b := &backend{caches: map[string]*calendarCache{}, earlySync: early, username: "me@example.com"}
	cc := &calendarCache{
		objects:     map[string]caldav.CalendarObject{},
		byToken:     map[string]string{},
		recent:      map[string]recentMutation{},
		loading:     true,
		loadStarted: time.Now().Add(-90 * time.Second),
		fetched:     n,
		total:       3100,
	}
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		cc.objects[id] = obj("/caldav/calendars/cal/" + id + ".ics")
	}
	b.caches["cal"] = cc
	return b, cc
}

func TestEarlySyncOffKeepsAnsweringUnavailableUntilLoaded(t *testing.T) {
	b, _ := loadingBackend(false, 5)
	if _, ready := b.cachedObjects("cal"); ready {
		t.Fatal("with early sync off a half-loaded calendar must not be served")
	}
	if ct := b.cacheCTag("cal"); ct != "" {
		t.Errorf("no CTag may be advertised for a calendar that is not served, got %q", ct)
	}
}

func TestEarlySyncOnServesWhatHasBeenDecoded(t *testing.T) {
	b, cc := loadingBackend(true, 5)
	objs, ready := b.cachedObjects("cal")
	if !ready || len(objs) != 5 {
		t.Fatalf("ready=%v with %d objects", ready, len(objs))
	}
	first := b.cacheCTag("cal")
	if first == "" {
		t.Fatal("a served partial calendar must advertise a CTag or clients cannot notice it growing")
	}

	cc.mu.Lock()
	cc.objects["z"] = obj("/caldav/calendars/cal/z.ics")
	cc.mu.Unlock()
	if second := b.cacheCTag("cal"); second == first {
		t.Fatal("the CTag must change as events are decoded")
	}
}

func TestEarlySyncNeverServesAnEmptyCalendar(t *testing.T) {
	b, _ := loadingBackend(true, 0)
	if objs, ready := b.cachedObjects("cal"); ready || len(objs) != 0 {
		t.Fatalf("an empty, still-loading calendar must stay unavailable (ready=%v)", ready)
	}
}

func TestEarlySyncDoesNotChangeHowLoadedCalendarsBehave(t *testing.T) {
	for _, early := range []bool{false, true} {
		b, cc := loadingBackend(early, 3)
		cc.mu.Lock()
		cc.loaded, cc.loading, cc.loadedAt = true, false, time.Now()
		cc.mu.Unlock()
		if objs, ready := b.cachedObjects("cal"); !ready || len(objs) != 3 {
			t.Errorf("early=%v: ready=%v objs=%d", early, ready, len(objs))
		}
	}
}

func TestWaitForDataIsWokenByTheLoaderNotByATimer(t *testing.T) {
	b, cc := loadingBackend(true, 0)
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		b.waitForData(cc, 10*time.Second)
		done <- time.Since(start)
	}()
	time.Sleep(50 * time.Millisecond) // let it block

	cc.mu.Lock()
	cc.objects["a"] = obj("/caldav/calendars/cal/a.ics")
	cc.broadcastLocked()
	cc.mu.Unlock()

	select {
	case took := <-done:
		if took > 2*time.Second {
			t.Fatalf("took %s: the waiter must be woken by the change", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never woke")
	}
}

func TestWaitForDataGivesUpAtTheDeadline(t *testing.T) {
	b, cc := loadingBackend(false, 0)
	start := time.Now()
	b.waitForData(cc, 100*time.Millisecond)
	if took := time.Since(start); took < 90*time.Millisecond || took > 2*time.Second {
		t.Fatalf("waited %s", took)
	}
}

func TestStatusDescribesEachState(t *testing.T) {
	b, cc := loadingBackend(true, 5)
	b.setCalendarName("cal", "Work")
	cc.mu.Lock()
	cc.loadErr = ""
	cc.mu.Unlock()

	st := Status{Users: []UserStatus{b.status()}}
	c := st.Users[0].Calendars[0]
	if c.State != "loading (serving partial)" || c.Name != "Work" || c.Fetched != 5 || c.Total != 3100 || c.Events != 5 || c.ElapsedSeconds < 89 {
		t.Fatalf("status = %+v", c)
	}
	out := st.String()
	for _, want := range []string{"me@example.com", "Work", "loading (serving partial)", "5 of 3,100 events (0%)", "1m30s elapsed", "serving 5 so far", "Early sync: ON"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// failed, ready, idle
	cc.mu.Lock()
	cc.loading, cc.loadErr = false, "list events failed: boom"
	cc.mu.Unlock()
	if s := b.status().Calendars[0]; s.State != "failed" || s.Error == "" {
		t.Errorf("failed = %+v", s)
	}
	cc.mu.Lock()
	cc.loaded, cc.loadErr = true, ""
	cc.mu.Unlock()
	if s := b.status().Calendars[0]; s.State != "ready" {
		t.Errorf("ready = %+v", s)
	}
}

func TestStatusSurvivesAJSONRoundTrip(t *testing.T) {
	b, _ := loadingBackend(false, 2)
	raw, err := json.Marshal(Status{Users: []UserStatus{b.status()}})
	if err != nil {
		t.Fatal(err)
	}
	var back Status
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Users) != 1 || back.Users[0].Calendars[0].Total != 3100 {
		t.Fatalf("%v %+v", err, back)
	}
	if !strings.Contains((Status{}).String(), "No client has connected yet") {
		t.Error("an empty status must say why it is empty")
	}
}

func TestLoadingMessageShowsProgressAndTheSwitch(t *testing.T) {
	b, cc := loadingBackend(false, 5)
	msg := b.loadingMessage("cal")
	for _, want := range []string{"still loading", "5 of 3,100 events", "CALOXIDE_EARLY_SYNC=on"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	b.earlySync = true
	if strings.Contains(b.loadingMessage("cal"), "CALOXIDE_EARLY_SYNC") {
		t.Error("the hint is pointless when early sync is already on")
	}
	cc.mu.Lock()
	cc.loading, cc.loadErr = false, "boom"
	cc.mu.Unlock()
	if m := b.loadingMessage("cal"); !strings.Contains(m, "failed to load (boom)") {
		t.Errorf("a failed load must say so: %s", m)
	}
}
