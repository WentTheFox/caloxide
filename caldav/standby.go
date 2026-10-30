package caldav

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mathewcsims/protoxide/config"
)

// Standby mode: Thunderbird asks the server something about every minute while it is
// open. When nothing has asked for a while (it was closed, the laptop is asleep), there
// is no point polling Proton about every calendar every 30 seconds. After standbyAfter
// without an authenticated request the pollers and the account event loop slow down to
// standbyInterval. The first request after that waits for a catch-up (one poll of every
// calendar, bounded by catchUpTimeout) before anything is served, so what a client reads
// is as fresh as in normal operation, and polling then goes back to its normal pace.
//
//	CALOXIDE_STANDBY            on | off     (default on)
//	CALOXIDE_STANDBY_AFTER      idle time before standby (default 5m, at least 1m)
//	CALOXIDE_STANDBY_INTERVAL   poll interval in standby (default 15m, at least 2m)
const (
	defaultStandbyAfter    = 5 * time.Minute
	defaultStandbyInterval = 15 * time.Minute
	minStandbyAfter        = time.Minute
	minStandbyInterval     = 2 * time.Minute
)

// catchUpTimeout bounds how long the first request after standby waits. It has to stay
// well under a CalDAV client's request timeout. (A variable so tests can shorten it.)
var catchUpTimeout = 15 * time.Second

// standbyAllowed is cleared when other protocols share the server: standby watches CalDAV
// requests only, so it would wrongly put an in-use IMAP or CardDAV session to sleep.
var (
	standbyAllowedMu sync.Mutex
	standbyAllowed   = true
)

// SetStandbyAllowed turns standby off for good when the server also speaks other
// protocols. Call it before the handlers are created.
func SetStandbyAllowed(ok bool) {
	standbyAllowedMu.Lock()
	standbyAllowed = ok
	standbyAllowedMu.Unlock()
}

type standbySettings struct {
	enabled  bool
	after    time.Duration
	interval time.Duration
}

func standbySettingsFromEnv() standbySettings {
	s := standbySettings{enabled: true, after: defaultStandbyAfter, interval: defaultStandbyInterval}

	standbyAllowedMu.Lock()
	allowed := standbyAllowed
	standbyAllowedMu.Unlock()
	if !allowed {
		s.enabled = false
	}

	switch v := strings.ToLower(strings.TrimSpace(config.Getenv("CALOXIDE_STANDBY"))); v {
	case "", "on", "true", "1", "yes":
	case "off", "false", "0", "no":
		s.enabled = false
	default:
		log.Printf("CALOXIDE_STANDBY=%q is not on or off; leaving it on", v)
	}

	parse := func(name string, def, min time.Duration) time.Duration {
		v := strings.TrimSpace(config.Getenv(name))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			log.Printf("%s=%q is not a duration like 90s or 10m; using %s", name, v, def)
			return def
		}
		if d < min {
			log.Printf("%s is raised to the minimum, %s", name, min)
			return min
		}
		return d
	}
	s.after = parse("CALOXIDE_STANDBY_AFTER", s.after, minStandbyAfter)
	s.interval = parse("CALOXIDE_STANDBY_INTERVAL", s.interval, minStandbyInterval)
	return s
}

// standbyState tracks client activity for one user.
type standbyState struct {
	set     standbySettings
	now     func() time.Time
	catchUp func() // wakes the pollers and waits; replaced in tests

	mu       sync.Mutex
	last     time.Time     // last authenticated request
	idle     bool          // pollers have dropped to the standby interval
	catching chan struct{} // non-nil while a catch-up runs; closed when it is over
	idleFrom time.Time
}

func newStandbyState(set standbySettings) *standbyState {
	return &standbyState{set: set, now: time.Now, last: time.Now()}
}

// interval is how long a poller should wait: base normally, the standby interval once
// nothing has used the server for a while. Pollers call it when they decide how long to
// sleep, which is also where the switch to standby is noticed.
func (s *standbyState) interval(base time.Duration) time.Duration {
	if s == nil || !s.set.enabled {
		return base
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.idle && s.catching == nil && s.now().Sub(s.last) >= s.set.after {
		s.idle = true
		s.idleFrom = s.last
		log.Printf("standby: no client activity for %s, polling Proton every %s until a client returns",
			s.set.after, s.set.interval)
	}
	if s.idle && s.set.interval > base {
		return s.set.interval
	}
	return base
}

// touch records client activity. The first call after standby does not return until the
// catch-up is over, and calls that arrive meanwhile wait for the same catch-up.
func (s *standbyState) touch() {
	if s == nil || !s.set.enabled {
		return
	}
	s.mu.Lock()
	s.last = s.now()
	if s.catching != nil {
		ch := s.catching
		s.mu.Unlock()
		<-ch
		return
	}
	if !s.idle {
		s.mu.Unlock()
		return
	}
	// Back to normal pace first, so the pollers woken by the catch-up sleep 30 s again.
	away := s.now().Sub(s.idleFrom)
	s.idle = false
	ch := make(chan struct{})
	s.catching = ch
	s.mu.Unlock()

	log.Printf("standby: a client is back after %s, bringing the calendars up to date first", away.Round(time.Second))
	if s.catchUp != nil {
		s.catchUp()
	}

	s.mu.Lock()
	s.catching = nil
	s.mu.Unlock()
	close(ch)
}

// state reports the current mode for status.
func (s *standbyState) state() (enabled, idle bool, idleFor time.Duration) {
	if s == nil {
		return false, false, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idle {
		idleFor = s.now().Sub(s.idleFrom)
	}
	return s.set.enabled, s.idle, idleFor
}

// cycles counts, per calendar, the polls the poller has started and finished, so a
// catch-up can wait for a poll that started after it woke the poller (a poll that was
// already in flight began before the client came back and does not count).
type cycles struct {
	mu sync.Mutex
	m  map[string]*cycleState
}

type cycleState struct {
	started, finished int
	changed           chan struct{}
}

func (c *cycles) get(calID string) *cycleState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*cycleState{}
	}
	cs := c.m[calID]
	if cs == nil {
		cs = &cycleState{changed: make(chan struct{})}
		c.m[calID] = cs
	}
	return cs
}

// register marks a calendar's poller as running, so catch-ups wait for it.
func (c *cycles) register(calID string) { c.get(calID) }

func (c *cycles) registered() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.m))
	for id := range c.m {
		ids = append(ids, id)
	}
	return ids
}

func (c *cycles) begin(calID string) {
	cs := c.get(calID)
	c.mu.Lock()
	cs.started++
	c.mu.Unlock()
}

func (c *cycles) end(calID string) {
	cs := c.get(calID)
	c.mu.Lock()
	cs.finished++
	close(cs.changed)
	cs.changed = make(chan struct{})
	c.mu.Unlock()
}

// forget drops a calendar whose poller has stopped, so nothing waits for it.
func (c *cycles) forget(calID string) {
	c.mu.Lock()
	delete(c.m, calID)
	c.mu.Unlock()
}

// target is the number of finished polls that means a poll started after now has ended.
func (c *cycles) target(calID string) int {
	cs := c.get(calID)
	c.mu.Lock()
	defer c.mu.Unlock()
	return cs.started + 1
}

// waitFor blocks until the calendar has finished target polls or the deadline passes.
func (c *cycles) waitFor(calID string, target int, deadline <-chan time.Time) bool {
	for {
		cs := c.get(calID)
		c.mu.Lock()
		done := cs.finished >= target
		ch := cs.changed
		c.mu.Unlock()
		if done {
			return true
		}
		select {
		case <-ch:
		case <-deadline:
			return false
		}
	}
}

// catchUp polls every calendar once, through its own poller, and waits for that.
func (b *backend) catchUp() {
	ids := b.cycles.registered()
	if len(ids) == 0 {
		return
	}

	targets := make(map[string]int, len(ids))
	for _, id := range ids {
		targets[id] = b.cycles.target(id)
	}
	for _, id := range ids {
		b.push.wake(id)
	}

	deadline := time.NewTimer(catchUpTimeout)
	defer deadline.Stop()
	late := 0
	for _, id := range ids {
		if !b.cycles.waitFor(id, targets[id], deadline.C) {
			late++
		}
	}
	if late > 0 {
		log.Printf("standby: %d of %d calendars did not finish catching up within %s; serving what is there", late, len(ids), catchUpTimeout)
	}
	if b.core != nil {
		b.core() // the account event loop picks up the normal pace again
	}
}

// activityHandler counts every authenticated request as client activity.
type activityHandler struct {
	b    *backend
	next http.Handler
}

func (h activityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.b.standby.touch()
	h.next.ServeHTTP(w, r)
}

// WireCoreLoop connects a handler from NewHandler to the account event loop, which lives
// outside this package: setInterval installs the interval the loop should use and poll
// wakes it. Handlers that are not from NewHandler are ignored.
func WireCoreLoop(h http.Handler, setInterval func(func() time.Duration), poll func()) {
	ah, ok := h.(activityHandler)
	if !ok || ah.b.standby == nil || !ah.b.standby.set.enabled {
		return
	}
	setInterval(func() time.Duration { return ah.b.standby.interval(coreBaseInterval) })
	ah.b.core = poll
}

// coreBaseInterval matches events.pollInterval, the normal pace of the account loop.
const coreBaseInterval = 30 * time.Second

// pollInterval is how long a calendar poller sleeps: the normal pace (slower while the
// push channel is up) or, in standby, the standby interval.
func (b *backend) pollInterval() time.Duration {
	return b.standby.interval(b.push.interval())
}
