package caldav

import (
	"log"
	"sync"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

// Every check a client makes of a calendar (the change-token PROPFIND, about once per calendar
// per refresh) needs the calendar's name and keys from Proton's calendar list. Asking Proton
// for it every time is a live request that no cache answers: six calendars at a one-minute
// refresh are six calls a minute for something that changes when a calendar is added or
// renamed. The list is therefore kept briefly. The change token is not part of it: that is
// computed from the local event cache on every call, so a change still shows up at once.
const (
	// calendarListTTL is how long a fetched list is reused.
	calendarListTTL = 30 * time.Second
	// calendarListStale is how old a list may be and still be served when Proton cannot be
	// asked (offline, rate limited): clients keep working, and the names do not change often.
	calendarListStale = time.Hour
)

// flight is one fetch from Proton and the result everyone who waited for it reads.
type flight struct {
	done chan struct{}
	list []*protonmail.Calendar
	err  error
}

type calendarListCache struct {
	mu       sync.Mutex
	list     []*protonmail.Calendar
	at       time.Time // when list was fetched; zero if never
	inflight *flight   // non-nil while one caller fetches for everybody
	stale    bool      // the old list is being served because Proton cannot be asked
	now      func() time.Time
	fetch    func() ([]*protonmail.Calendar, error)
}

func (l *calendarListCache) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// get returns the calendar list, from the cache when it is fresh. Callers that arrive while a
// fetch is running share its result instead of starting another. If Proton cannot be reached
// and an older list is held, that one is returned; otherwise the error is.
func (l *calendarListCache) get() ([]*protonmail.Calendar, error) {
	l.mu.Lock()
	if !l.at.IsZero() && l.clock().Sub(l.at) < calendarListTTL {
		list := l.list
		l.mu.Unlock()
		return list, nil
	}
	if f := l.inflight; f != nil {
		l.mu.Unlock()
		<-f.done
		if f.err == nil {
			return f.list, nil
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.fallbackLocked(f.err)
	}

	f := &flight{done: make(chan struct{})}
	l.inflight = f
	l.mu.Unlock()

	list, err := l.fetch()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.inflight = nil
	f.list, f.err = list, err
	close(f.done)
	if err == nil {
		l.list, l.at, l.stale = list, l.clock(), false
		return list, nil
	}
	return l.fallbackLocked(err)
}

// fallbackLocked answers a failed fetch: an old list keeps clients working through an outage
// (said once per outage), but one that is too old is not trusted. A failure is never cached.
func (l *calendarListCache) fallbackLocked(err error) ([]*protonmail.Calendar, error) {
	if l.list != nil && l.clock().Sub(l.at) < calendarListStale {
		if !l.stale {
			l.stale = true
			log.Printf("calendars: could not refresh the calendar list (%v); using the one from %s ago until Proton answers",
				err, l.clock().Sub(l.at).Round(time.Second))
		}
		return l.list, nil
	}
	return nil, err
}

// refresh fetches the list now, ignoring what is cached, and keeps the result.
func (l *calendarListCache) refresh() ([]*protonmail.Calendar, error) {
	list, err := l.fetch()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.list, l.at, l.stale = list, l.clock(), false
	l.mu.Unlock()
	return list, nil
}

// invalidate makes the next get fetch again.
func (l *calendarListCache) invalidate() {
	l.mu.Lock()
	l.at = time.Time{}
	l.mu.Unlock()
}

// protonCalendars is Proton's calendar list, reused for a short while.
func (b *backend) protonCalendars() ([]*protonmail.Calendar, error) {
	return b.calendarList().get()
}

func (b *backend) calendarList() *calendarListCache {
	b.calListOnce.Do(func() {
		b.calList = &calendarListCache{fetch: func() ([]*protonmail.Calendar, error) { return b.c.ListCalendars() }}
	})
	return b.calList
}
