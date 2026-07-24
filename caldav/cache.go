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
	// How long a locally-written (or deleted) event is protected from being
	// clobbered by a background reload. A full reload takes minutes and fetches
	// Proton's state at the moment it *started*, so an event created while a
	// reload is in flight is absent from the reload result and would otherwise be
	// dropped when the reload swaps in its snapshot. Re-applying recent local
	// mutations on top of every swap bridges that window; once Proton is
	// consistent (seconds) and a later reload includes the event, the overlay
	// entry expires. Must comfortably exceed a full reload's duration.
	recentWriteTTL = 6 * time.Minute
)

// recentMutation records a local write or delete so it can be re-applied on top
// of a background reload that raced it. See recentWriteTTL.
type recentMutation struct {
	obj     caldav.CalendarObject
	deleted bool
	at      time.Time
}

type calendarCache struct {
	mu       sync.Mutex
	objects  map[string]caldav.CalendarObject // keyed by Proton event ID
	byToken  map[string]string                // CalDAV path token -> Proton event ID
	recent   map[string]recentMutation        // local writes/deletes, keyed by Proton event ID
	loaded   bool
	loading  bool
	loadedAt time.Time
}

// buildTokenIndex derives the path-token -> Proton-ID index for a set of objects.
// Tokens are unique per object (see objectToken), so lookups by token are O(1)
// instead of scanning every event — critical for calendar-multiget, which fetches
// one object per href and would otherwise be O(n^2) over the whole calendar.
func buildTokenIndex(objs map[string]caldav.CalendarObject) map[string]string {
	idx := make(map[string]string, len(objs))
	for id, o := range objs {
		idx[objectToken(o.Data, id)] = id
	}
	return idx
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
		cc = &calendarCache{
			objects: make(map[string]caldav.CalendarObject),
			byToken: make(map[string]string),
			recent:  make(map[string]recentMutation),
		}
		b.caches[calID] = cc
		if loadCacheFromDisk(calID, cc) {
			log.Printf("cache %s: restored %d events from disk", calID, len(cc.objects))
		}
	}
	// Start the calendar event-loop poller once per calendar, so inbound changes
	// (events created/edited in Proton or on another device) are patched into the
	// cache within the poll interval instead of only on a 30-minute full reload.
	if b.pollers != nil && !b.pollers[calID] {
		b.pollers[calID] = true
		go b.pollCalendar(calID)
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

// cachedObjects returns the decrypted objects for a calendar and whether the
// cache has completed at least one full load (from disk or network). It triggers
// a background (re)load when cold or stale. A stale refresh and concurrent
// requests serve the existing snapshot immediately; only a cold load makes the
// request wait briefly. When ready is false the caller should signal "not ready"
// rather than serve an empty snapshot — a cold load fetches every page before
// decrypting, so the cache is legitimately empty for the whole fetch, and a
// client that saw 0 objects would treat the calendar as emptied and churn.
func (b *backend) cachedObjects(calID string) (objs []caldav.CalendarObject, ready bool) {
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

	cc.mu.Lock()
	ready = cc.loaded
	cc.mu.Unlock()
	return snapshotObjects(cc), ready
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
		cc.byToken[objectToken(co.Data, event.ID)] = event.ID
		cc.mu.Unlock()
	}

	// Replace wholesale so events deleted upstream drop out of the cache, but
	// re-apply recent local writes/deletes first: a reload fetches Proton's state
	// from when it *started*, so an event written while it was in flight is absent
	// here and must not be dropped. See recentWriteTTL.
	cc.mu.Lock()
	cc.applyRecentLocked(fresh)
	cc.objects = fresh
	cc.byToken = buildTokenIndex(fresh)
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
	cc.byToken[objectToken(obj.Data, evtID)] = evtID
	cc.recent[evtID] = recentMutation{obj: obj, at: time.Now()}
	persist := cc.loaded && !cc.loading
	cc.mu.Unlock()
	// Only persist a fully-loaded, settled cache; otherwise we'd overwrite the
	// on-disk cache with a partial in-memory set (a write landing mid initial load
	// or mid reload). The write is held in memory and in the recent-writes overlay,
	// so loadCache folds it into the full set it persists on completion.
	if persist {
		saveCacheToDisk(calID, cc)
	}
}

func (b *backend) cacheDelete(calID, evtID string) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	if o, ok := cc.objects[evtID]; ok {
		delete(cc.byToken, objectToken(o.Data, evtID))
	}
	delete(cc.objects, evtID)
	cc.recent[evtID] = recentMutation{deleted: true, at: time.Now()}
	persist := cc.loaded && !cc.loading
	cc.mu.Unlock()
	if persist {
		saveCacheToDisk(calID, cc)
	}
}

// applyRecentLocked overlays local writes/deletes from the last recentWriteTTL on
// top of m (typically a fresh reload result), and prunes expired overlay entries.
// cc.mu must be held.
func (cc *calendarCache) applyRecentLocked(m map[string]caldav.CalendarObject) {
	for id, mut := range cc.recent {
		if time.Since(mut.at) > recentWriteTTL {
			delete(cc.recent, id)
			continue
		}
		if mut.deleted {
			delete(m, id)
		} else {
			m[id] = mut.obj
		}
	}
}

func (b *backend) cacheLookup(calID, evtID string) (caldav.CalendarObject, bool) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	o, ok := cc.objects[evtID]
	return o, ok
}

// findByToken resolves a CalDAV path token (see objectToken) to the cached object
// and the Proton event ID it is stored under, via the byToken index (O(1)).
// Proton's write API is keyed by its own event IDs, so this is how a client's
// token-based path is mapped back to the ID needed for updates/deletes. Returns
// ok=false when no cached event carries that token (i.e. a create).
func (b *backend) findByToken(calID, token string) (caldav.CalendarObject, string, bool) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	protonID, ok := cc.byToken[token]
	if !ok {
		return caldav.CalendarObject{}, "", false
	}
	o, ok := cc.objects[protonID]
	if !ok {
		return caldav.CalendarObject{}, "", false
	}
	return o, protonID, true
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
	cc.byToken = buildTokenIndex(objs)
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
