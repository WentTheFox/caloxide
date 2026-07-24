package caldav

import (
	"log"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
)

// Proton's calendar events endpoint has no working time-range filter and paginates
// oldest-first, so serving a client query directly means walking every page and
// decrypting every event on each request — far too slow for a large calendar, and
// it times the client out. Instead we fetch and decrypt the whole calendar once in
// the background, serve queries instantly from the decrypted cache, and filter time
// ranges ourselves.

const (
	// How long a fully-loaded cache is served before a background refresh.
	cacheTTL = 30 * time.Minute
	// How long the first (cold) request will wait for the initial load to
	// accumulate data before returning what it has. Must stay well under a
	// typical CalDAV client request timeout.
	initialLoadWait = 20 * time.Second
)

type calendarCache struct {
	mu       sync.Mutex
	objects  map[string]caldav.CalendarObject // keyed by Proton event ID
	loaded   bool
	loading  bool
	loadedAt time.Time
}

func (b *backend) cacheFor(calID string) *calendarCache {
	b.cachesMu.Lock()
	defer b.cachesMu.Unlock()
	cc := b.caches[calID]
	if cc == nil {
		cc = &calendarCache{objects: make(map[string]caldav.CalendarObject)}
		b.caches[calID] = cc
	}
	return cc
}

func snapshotObjects(cc *calendarCache) []caldav.CalendarObject {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]caldav.CalendarObject, 0, len(cc.objects))
	for _, o := range cc.objects {
		out = append(out, o)
	}
	return out
}

// cachedObjects returns the decrypted objects for a calendar, triggering a
// background (re)load when the cache is cold or stale. Only the request that
// starts a cold load waits (briefly) for data; refreshes and concurrent requests
// serve the existing snapshot immediately (stale-while-revalidate).
func (b *backend) cachedObjects(calID string) []caldav.CalendarObject {
	cc := b.cacheFor(calID)

	cc.mu.Lock()
	wasCold := !cc.loaded
	stale := cc.loaded && time.Since(cc.loadedAt) > cacheTTL
	triggered := false
	if !cc.loading && (wasCold || stale) {
		cc.loading = true
		triggered = true
		go b.loadCache(calID, cc)
	}
	cc.mu.Unlock()

	if triggered && wasCold {
		deadline := time.Now().Add(initialLoadWait)
		for time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)
			cc.mu.Lock()
			done := cc.loaded
			cc.mu.Unlock()
			if done {
				break
			}
		}
	}

	return snapshotObjects(cc)
}

func (b *backend) loadCache(calID string, cc *calendarCache) {
	defer func() {
		cc.mu.Lock()
		cc.loading = false
		cc.mu.Unlock()
	}()

	bootstrap, err := b.c.BootstrapCalendar(calID)
	if err != nil {
		log.Printf("cache %s: bootstrap failed: %v", calID, err)
		return
	}
	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		log.Printf("cache %s: keyring decrypt failed: %v", calID, err)
		return
	}

	events, err := b.c.ListAllCalendarEvents(calID, nil)
	if err != nil {
		log.Printf("cache %s: list events failed: %v", calID, err)
		return
	}

	fresh := make(map[string]caldav.CalendarObject, len(events))
	for _, event := range events {
		co, err := getCalendarObject(b, calID, calKr, event, bootstrap.CalendarSettings)
		if err != nil {
			log.Printf("cache %s: skipping event %s: %v", calID, event.ID, err)
			continue
		}
		fresh[event.ID] = *co

		// Publish incrementally so a client polling mid-load sees the calendar
		// fill in rather than waiting for the entire decrypt to finish.
		cc.mu.Lock()
		cc.objects[event.ID] = *co
		cc.mu.Unlock()
	}

	// Replace wholesale so events deleted upstream drop out of the cache.
	cc.mu.Lock()
	cc.objects = fresh
	cc.loaded = true
	cc.loadedAt = time.Now()
	cc.mu.Unlock()
	log.Printf("cache %s: loaded %d events", calID, len(fresh))
}

func (b *backend) cacheStore(calID, evtID string, obj caldav.CalendarObject) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	cc.objects[evtID] = obj
	cc.mu.Unlock()
}

func (b *backend) cacheDelete(calID, evtID string) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	delete(cc.objects, evtID)
	cc.mu.Unlock()
}

func (b *backend) cacheLookup(calID, evtID string) (caldav.CalendarObject, bool) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	o, ok := cc.objects[evtID]
	return o, ok
}

// objectInRange reports whether a cached object has a VEVENT overlapping
// [start, end]. Recurring events are always included (their instances may fall
// anywhere), and anything we can't parse is included rather than silently
// dropped — Proton gives us no server-side filtering, so we err toward showing.
func objectInRange(obj caldav.CalendarObject, start, end time.Time) bool {
	if obj.Data == nil {
		return true
	}
	for _, ev := range obj.Data.Events() {
		if ev.Props.Get(ical.PropRecurrenceRule) != nil {
			return true
		}
		s, err := ev.DateTimeStart(nil)
		if err != nil {
			return true
		}
		e, err := ev.DateTimeEnd(nil)
		if err != nil || e.IsZero() {
			e = s
		}
		startsBeforeEnd := end.IsZero() || s.Before(end)
		endsAfterStart := start.IsZero() || e.After(start)
		if startsBeforeEnd && endsAfterStart {
			return true
		}
	}
	return false
}
