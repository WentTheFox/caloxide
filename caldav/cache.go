package caldav

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/config"
)

// Proton's calendar events endpoint has no working time-range filter and paginates
// oldest-first, so serving a client query directly means walking every page and
// decrypting every event on each request — far too slow for a large calendar, and
// it times the client out. Instead we fetch and decrypt the whole calendar once,
// persist the decrypted result to disk (so restarts are instant), serve queries
// from memory, and filter time ranges ourselves.
//
// The on-disk cache holds decrypted event data in the user's config directory
// (0600). This is the same trade-off every local calendar client makes — e.g.
// Thunderbird's own cache.sqlite — and keeps the data on the user's machine.

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

// persistedObject is the on-disk form of a cached object: the encrypted event has
// already been decrypted to plain iCalendar text here.
type persistedObject struct {
	Path    string
	ETag    string
	ModTime time.Time
	ICS     string
}

type persistedCache struct {
	LoadedAt time.Time
	Objects  map[string]persistedObject
}

func cacheFilePath(calID string) (string, error) {
	// calID is URL-safe base64 (may end in "=="), which is filesystem-safe;
	// strip any stray slash defensively.
	return config.Path("calcache-" + strings.ReplaceAll(calID, "/", "_") + ".json")
}

func (b *backend) cacheFor(calID string) *calendarCache {
	b.cachesMu.Lock()
	defer b.cachesMu.Unlock()
	cc := b.caches[calID]
	if cc == nil {
		cc = &calendarCache{objects: make(map[string]caldav.CalendarObject)}
		b.caches[calID] = cc
		if loadCacheFromDisk(calID, cc) {
			log.Printf("cache %s: restored %d events from disk", calID, len(cc.objects))
		}
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
// background (re)load when the cache is cold or stale. Only a cold load (no data
// at all, e.g. no disk cache) makes the request wait briefly; a stale refresh and
// concurrent requests serve the existing snapshot immediately.
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

	saveCacheToDisk(calID, cc)
	log.Printf("cache %s: loaded %d events", calID, len(fresh))
}

func (b *backend) cacheStore(calID, evtID string, obj caldav.CalendarObject) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	cc.objects[evtID] = obj
	cc.mu.Unlock()
	saveCacheToDisk(calID, cc)
}

func (b *backend) cacheDelete(calID, evtID string) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	delete(cc.objects, evtID)
	cc.mu.Unlock()
	saveCacheToDisk(calID, cc)
}

func (b *backend) cacheLookup(calID, evtID string) (caldav.CalendarObject, bool) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	o, ok := cc.objects[evtID]
	return o, ok
}

// findByToken resolves a CalDAV path token (an iCalendar UID, see objectToken) to
// the cached object and the Proton event ID it is stored under, by scanning the
// calendar cache. Proton's write API is keyed by its own event IDs, so this is how
// a client's UID-based path is mapped back to the ID needed for updates/deletes.
// Returns ok=false when no cached event carries that token (i.e. a create).
func (b *backend) findByToken(calID, token string) (caldav.CalendarObject, string, bool) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for protonID, o := range cc.objects {
		if objectToken(o.Data, protonID) == token {
			return o, protonID, true
		}
	}
	return caldav.CalendarObject{}, "", false
}

// saveCacheToDisk atomically writes the decrypted cache to the config directory.
func saveCacheToDisk(calID string, cc *calendarCache) {
	path, err := cacheFilePath(calID)
	if err != nil {
		log.Printf("cache %s: cannot resolve cache path: %v", calID, err)
		return
	}

	cc.mu.Lock()
	pc := persistedCache{
		LoadedAt: cc.loadedAt,
		Objects:  make(map[string]persistedObject, len(cc.objects)),
	}
	for id, o := range cc.objects {
		var buf bytes.Buffer
		if o.Data != nil {
			if err := ical.NewEncoder(&buf).Encode(o.Data); err != nil {
				continue
			}
		}
		pc.Objects[id] = persistedObject{Path: o.Path, ETag: o.ETag, ModTime: o.ModTime, ICS: buf.String()}
	}
	cc.mu.Unlock()

	data, err := json.Marshal(pc)
	if err != nil {
		log.Printf("cache %s: marshal failed: %v", calID, err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("cache %s: write failed: %v", calID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("cache %s: rename failed: %v", calID, err)
	}
}

// loadCacheFromDisk populates cc from a previously-saved cache file, if present.
func loadCacheFromDisk(calID string, cc *calendarCache) bool {
	path, err := cacheFilePath(calID)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var pc persistedCache
	if err := json.Unmarshal(data, &pc); err != nil {
		log.Printf("cache %s: on-disk cache unreadable, ignoring: %v", calID, err)
		return false
	}

	objs := make(map[string]caldav.CalendarObject, len(pc.Objects))
	for id, po := range pc.Objects {
		cal, err := ical.NewDecoder(strings.NewReader(po.ICS)).Decode()
		if err != nil {
			continue
		}
		objs[id] = caldav.CalendarObject{Path: po.Path, ETag: po.ETag, ModTime: po.ModTime, Data: cal}
	}

	cc.mu.Lock()
	cc.objects = objs
	cc.loaded = true
	cc.loadedAt = pc.LoadedAt
	cc.mu.Unlock()
	return true
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
