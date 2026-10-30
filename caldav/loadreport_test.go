package caldav

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type sent struct{ typ, key, title, body string }

type fixture struct {
	tr   *loadTracker
	mu   sync.Mutex
	sent []sent
	now  time.Time
}

func newFixture(mode alertMode, after time.Duration) *fixture {
	f := &fixture{now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	names := map[string]string{"cal-big": "Work", "cal-small": "Personal"}
	f.tr = newLoadTracker(loadAlertSettings{mode: mode, after: after, every: time.Hour},
		func(id string) string { return names[id] }, nil)
	f.tr.now = func() time.Time { return f.now }
	f.tr.send = func(typ, key, title, body string) {
		f.mu.Lock()
		f.sent = append(f.sent, sent{typ, key, title, body})
		f.mu.Unlock()
	}
	return f
}

func (f *fixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func TestAlertsOffSendNothing(t *testing.T) {
	f := newFixture(alertsOff, time.Minute)
	f.tr.start("cal-big")
	f.advance(3 * time.Hour)
	f.tr.finish("cal-big", 3100, nil)
	if len(f.sent) != 0 {
		t.Fatalf("sent %d messages with alerts off", len(f.sent))
	}
}

func TestQuickLoadsSendNothing(t *testing.T) {
	f := newFixture(alertsDone, time.Minute)
	f.tr.start("cal-big")
	f.advance(20 * time.Second)
	f.tr.finish("cal-big", 100, nil)
	if len(f.sent) != 0 {
		t.Fatalf("a 20 second load sent %+v", f.sent)
	}
}

func TestSlowLoadSendsOneSummaryAfterTheLastCalendar(t *testing.T) {
	f := newFixture(alertsDone, time.Minute)
	f.tr.start("cal-big")
	f.tr.start("cal-small")
	f.advance(10 * time.Second)
	f.tr.finish("cal-small", 22, nil)
	if len(f.sent) != 0 {
		t.Fatal("a summary must wait until everything that was loading has finished")
	}
	f.advance(2*time.Minute + 10*time.Second)
	f.tr.finish("cal-big", 3100, nil)

	if len(f.sent) != 1 {
		t.Fatalf("sent %d messages, want one", len(f.sent))
	}
	m := f.sent[0]
	if m.typ != "success" || !strings.Contains(m.title, "loaded") {
		t.Errorf("message = %+v", m)
	}
	for _, want := range []string{"Work: ready, 3,100 events in 2m20s", "Personal: ready, 22 events in 10s"} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.body)
		}
	}
}

func TestFailureIsAWarningThatNamesTheCause(t *testing.T) {
	f := newFixture(alertsDone, time.Minute)
	f.tr.start("cal-big")
	f.advance(5 * time.Minute)
	f.tr.finish("cal-big", 700, errString("list events failed: boom"))
	if len(f.sent) != 1 || f.sent[0].typ != "warning" || !strings.Contains(f.sent[0].body, "failed after 5m00s: list events failed: boom") {
		t.Fatalf("sent %+v", f.sent)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestProgressMessagesShowPercentageOrAdmitTheTotalIsUnknown(t *testing.T) {
	f := newFixture(alertsProgress, time.Hour) // the timer is armed but far away; ticks are driven by hand
	f.tr.start("cal-big")
	f.tr.start("cal-small")
	f.tr.update("cal-big", 1200, 3100)
	f.tr.update("cal-small", 340, 0)
	f.advance(10 * time.Minute)
	f.tr.tick()
	defer f.tr.timer.Stop()

	if len(f.sent) != 1 || f.sent[0].typ != "info" || !strings.Contains(f.sent[0].title, "2 calendar(s) still loading") {
		t.Fatalf("sent %+v", f.sent)
	}
	body := f.sent[0].body
	for _, want := range []string{
		"Work: 1,200 of 3,100 events (38%), running for 10m00s",
		"Personal: 340 events fetched so far (total unknown)",
		"no percentage",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "no progress") {
		t.Error("the first message cannot claim a lack of progress")
	}
}

func TestProgressNoticesWhenNothingMoved(t *testing.T) {
	f := newFixture(alertsProgress, time.Hour)
	f.tr.start("cal-big")
	f.tr.update("cal-big", 500, 3100)
	f.tr.tick()
	f.advance(30 * time.Minute)
	f.tr.tick() // still 500
	f.tr.update("cal-big", 900, 3100)
	f.advance(30 * time.Minute)
	f.tr.tick()
	defer f.tr.timer.Stop()

	if len(f.sent) != 3 {
		t.Fatalf("sent %d", len(f.sent))
	}
	if strings.Contains(f.sent[0].body, "no progress") || !strings.Contains(f.sent[1].body, "no progress since the last update") || strings.Contains(f.sent[2].body, "no progress") {
		t.Errorf("bodies:\n1: %s\n2: %s\n3: %s", f.sent[0].body, f.sent[1].body, f.sent[2].body)
	}
}

func TestEveryMessageHasItsOwnKeySoNothingIsDebounced(t *testing.T) {
	f := newFixture(alertsProgress, time.Hour)
	f.tr.start("cal-big")
	f.tr.tick()
	f.tr.tick()
	f.tr.tick()
	defer f.tr.timer.Stop()
	seen := map[string]bool{}
	for _, m := range f.sent {
		if seen[m.key] {
			t.Fatalf("key %q reused: the alert debounce would swallow a message", m.key)
		}
		seen[m.key] = true
	}
}

func TestRateLimitPauseIsMentioned(t *testing.T) {
	f := newFixture(alertsProgress, time.Hour)
	f.tr.pause = func() time.Duration { return 4 * time.Minute }
	f.tr.start("cal-big")
	f.tr.tick()
	defer f.tr.timer.Stop()
	if !strings.Contains(f.sent[0].body, "requests are paused for another 4m00s") {
		t.Errorf("body:\n%s", f.sent[0].body)
	}
}

func TestNoTimerOutlivesTheLoads(t *testing.T) {
	f := newFixture(alertsProgress, time.Hour)
	f.tr.start("cal-big")
	f.tr.finish("cal-big", 1, nil)
	if f.tr.timer != nil {
		t.Fatal("the progress timer must be stopped once nothing is loading")
	}
}

func TestNilTrackerIsHarmless(t *testing.T) {
	var tr *loadTracker
	tr.start("x")
	tr.update("x", 1, 2)
	tr.finish("x", 1, nil)
}

func TestSettingsFromEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, mode, after, every string
		want                     loadAlertSettings
	}{
		{"defaults", "", "", "", loadAlertSettings{alertsDone, time.Minute, 30 * time.Minute}},
		{"off", "off", "", "", loadAlertSettings{alertsOff, time.Minute, 30 * time.Minute}},
		{"progress", "Progress", "10s", "15m", loadAlertSettings{alertsProgress, 10 * time.Second, 15 * time.Minute}},
		{"nonsense falls back", "loud", "soon", "-5m", loadAlertSettings{alertsDone, time.Minute, 30 * time.Minute}},
		{"interval has a floor", "progress", "", "30s", loadAlertSettings{alertsProgress, time.Minute, minLoadAlertEvery}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CALOXIDE_LOAD_ALERTS", tc.mode)
			t.Setenv("CALOXIDE_LOAD_ALERT_AFTER", tc.after)
			t.Setenv("CALOXIDE_LOAD_ALERT_EVERY", tc.every)
			if got := loadAlertSettingsFromEnv(); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestEarlySyncIsOffUnlessAskedFor(t *testing.T) {
	for v, want := range map[string]bool{"": false, "off": false, "0": false, "nonsense": false, "on": true, "TRUE": true, "1": true} {
		t.Setenv("CALOXIDE_EARLY_SYNC", v)
		if got := earlySyncFromEnv(); got != want {
			t.Errorf("CALOXIDE_EARLY_SYNC=%q: %v, want %v", v, got, want)
		}
	}
}

func TestFormatting(t *testing.T) {
	if got := describeProgress(3100, 3100); got != "3,100 of 3,100 events (99%)" {
		t.Errorf("a load that has not finished must not read 100%%: %q", got)
	}
	if got := thousands(1234567); got != "1,234,567" {
		t.Errorf("%q", got)
	}
	for d, want := range map[time.Duration]string{45 * time.Second: "45s", 130 * time.Second: "2m10s", 3*time.Hour + 5*time.Minute: "3h05m"} {
		if got := roundDuration(d); got != want {
			t.Errorf("%s -> %q, want %q", d, got, want)
		}
	}
}
