package caldav

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/notify"
)

// A cold load (a calendar fetched from Proton because there is no cache yet) can take
// seconds or hours, and nobody knows which in advance. So the alerts about it are
// configurable and quiet by default:
//
//	CALOXIDE_LOAD_ALERTS       off | done | progress   (default done)
//	CALOXIDE_LOAD_ALERT_AFTER  loads that finish sooner than this send nothing (default 1m)
//	CALOXIDE_LOAD_ALERT_EVERY  progress messages are at most this far apart (default 30m,
//	                           never below 5m)
//
// done: one message when everything that was loading has finished, if it took longer
// than AFTER. progress: also a status message every EVERY while loading, the first one
// after AFTER. The progress shown (logs, status, alerts) never depends on early sync.
const (
	defaultLoadAlertAfter = time.Minute
	defaultLoadAlertEvery = 30 * time.Minute
	minLoadAlertEvery     = 5 * time.Minute
)

type alertMode int

const (
	alertsOff alertMode = iota
	alertsDone
	alertsProgress
)

type loadAlertSettings struct {
	mode  alertMode
	after time.Duration
	every time.Duration
}

func loadAlertSettingsFromEnv() loadAlertSettings {
	s := loadAlertSettings{mode: alertsDone, after: defaultLoadAlertAfter, every: defaultLoadAlertEvery}

	switch v := strings.ToLower(strings.TrimSpace(config.Getenv("CALOXIDE_LOAD_ALERTS"))); v {
	case "", "done":
	case "off", "false", "0", "no":
		s.mode = alertsOff
	case "progress":
		s.mode = alertsProgress
	default:
		log.Printf("CALOXIDE_LOAD_ALERTS=%q is not off, done or progress; using done", v)
	}

	parse := func(name string, def time.Duration) time.Duration {
		v := strings.TrimSpace(config.Getenv(name))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			log.Printf("%s=%q is not a duration like 90s or 10m; using %s", name, v, def)
			return def
		}
		return d
	}
	s.after = parse("CALOXIDE_LOAD_ALERT_AFTER", s.after)
	s.every = parse("CALOXIDE_LOAD_ALERT_EVERY", s.every)
	if s.every < minLoadAlertEvery {
		log.Printf("CALOXIDE_LOAD_ALERT_EVERY is raised to the minimum, %s", minLoadAlertEvery)
		s.every = minLoadAlertEvery
	}
	return s
}

type loadInfo struct {
	fetched, total int
}

type loadResult struct {
	calID  string
	events int
	took   time.Duration
	err    error
}

// loadTracker watches the cold loads of one user and sends the alerts described above.
// A nil tracker does nothing.
type loadTracker struct {
	set   loadAlertSettings
	name  func(calID string) string
	pause func() time.Duration
	send  func(typ, key, title, body string)
	now   func() time.Time

	mu       sync.Mutex
	active   map[string]*loadInfo
	started  map[string]time.Time
	finished []loadResult
	first    time.Time // when the first load of the current batch started
	timer    *time.Timer
	seq      int
	reported map[string]int // events fetched at the previous progress message
}

func newLoadTracker(set loadAlertSettings, name func(string) string, pause func() time.Duration) *loadTracker {
	return &loadTracker{
		set:      set,
		name:     name,
		pause:    pause,
		send:     notify.Send,
		now:      time.Now,
		active:   map[string]*loadInfo{},
		started:  map[string]time.Time{},
		reported: map[string]int{},
	}
}

func (t *loadTracker) start(calID string) {
	if t == nil || t.set.mode == alertsOff {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.active) == 0 && len(t.finished) == 0 {
		t.first = t.now()
	}
	t.active[calID] = &loadInfo{}
	t.started[calID] = t.now()
	if t.set.mode == alertsProgress && t.timer == nil {
		t.timer = time.AfterFunc(t.set.after, t.tick)
	}
}

func (t *loadTracker) update(calID string, fetched, total int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if li := t.active[calID]; li != nil {
		li.fetched, li.total = fetched, total
	}
}

func (t *loadTracker) finish(calID string, events int, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active[calID] == nil {
		return
	}
	t.finished = append(t.finished, loadResult{calID, events, t.now().Sub(t.started[calID]), err})
	delete(t.active, calID)
	delete(t.started, calID)
	delete(t.reported, calID)
	if len(t.active) > 0 {
		return
	}

	// Everything that was loading has finished.
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	if t.now().Sub(t.first) >= t.set.after {
		failed := false
		for _, r := range t.finished {
			failed = failed || r.err != nil
		}
		typ, title := "success", "caloxide: calendars loaded"
		if failed {
			typ, title = "warning", "caloxide: calendar loading finished with errors"
		}
		t.sendLocked(typ, title, t.bodyLocked(false))
	}
	t.finished = nil
	t.first = time.Time{}
}

// tick sends the periodic progress message and schedules the next one.
func (t *loadTracker) tick() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.active) == 0 {
		t.timer = nil
		return
	}
	title := fmt.Sprintf("caloxide: %d calendar(s) still loading", len(t.active))
	t.sendLocked("info", title, t.bodyLocked(true))
	for id, li := range t.active {
		t.reported[id] = li.fetched
	}
	t.timer = time.AfterFunc(t.set.every, t.tick)
}

func (t *loadTracker) sendLocked(typ, title, body string) {
	t.seq++
	// A key of its own per message: the alert debounce is for repeated faults, and these
	// are meant to arrive one after another.
	t.send(typ, fmt.Sprintf("load-%d", t.seq), title, body)
}

func (t *loadTracker) label(calID string) string {
	if t.name != nil {
		if n := t.name(calID); n != "" {
			return n
		}
	}
	if len(calID) > 8 {
		return calID[:8] + "…"
	}
	return calID
}

func (t *loadTracker) bodyLocked(progress bool) string {
	var lines []string

	ids := make([]string, 0, len(t.active))
	for id := range t.active {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		li := t.active[id]
		line := fmt.Sprintf("%s: %s", t.label(id), describeProgress(li.fetched, li.total))
		line += fmt.Sprintf(", running for %s", roundDuration(t.now().Sub(t.started[id])))
		if last, ok := t.reported[id]; ok && last == li.fetched {
			line += " (no progress since the last update)"
		}
		lines = append(lines, line)
	}

	for _, r := range t.finished {
		if r.err != nil {
			lines = append(lines, fmt.Sprintf("%s: failed after %s: %v", t.label(r.calID), roundDuration(r.took), r.err))
		} else {
			lines = append(lines, fmt.Sprintf("%s: ready, %s events in %s", t.label(r.calID), thousands(r.events), roundDuration(r.took)))
		}
	}

	if t.pause != nil {
		if d := t.pause(); d > 0 {
			lines = append(lines, fmt.Sprintf("Proton asked us to slow down: requests are paused for another %s.", roundDuration(d)))
		}
	}
	if progress {
		for _, li := range t.active {
			if li.total <= 0 {
				lines = append(lines, "Proton did not say how many events there are, so there is no percentage.")
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// describeProgress renders fetched/total, with a percentage when the total is known.
// The percentage never reaches 100 before the load has finished.
func describeProgress(fetched, total int) string {
	if total <= 0 {
		return fmt.Sprintf("%s events fetched so far (total unknown)", thousands(fetched))
	}
	pct := fetched * 100 / total
	if pct > 99 {
		pct = 99
	}
	return fmt.Sprintf("%s of %s events (%d%%)", thousands(fetched), thousands(total), pct)
}

func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func roundDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		d = d.Round(time.Second)
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		d = d.Round(time.Minute)
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// earlySyncFromEnv reads CALOXIDE_EARLY_SYNC. Off by default: serving a calendar that is
// still loading for the first time is meant for the initial import, and a client that
// already holds a full local copy of a calendar the server has not loaded yet would
// drop what it cannot see yet from its local copy until it arrives. Turn it off again
// (or remove it) once the calendars are loaded.
func earlySyncFromEnv() bool {
	switch v := strings.ToLower(strings.TrimSpace(config.Getenv("CALOXIDE_EARLY_SYNC"))); v {
	case "", "off", "false", "0", "no":
		return false
	case "on", "true", "1", "yes":
		log.Printf("early sync is ON: calendars are served while they load for the first time; unset CALOXIDE_EARLY_SYNC after the initial import")
		return true
	default:
		log.Printf("CALOXIDE_EARLY_SYNC=%q is not on or off; leaving it off", v)
		return false
	}
}
