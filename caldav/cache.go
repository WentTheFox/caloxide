package caldav

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/protonmail"
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

	// Progress of the current or last load, for status and alerts.
	loadStarted time.Time
	fetched     int    // events handed over so far
	total       int    // events Proton says the calendar has; 0 when unknown
	loadErr     string // why the last load failed, if it did

	// changed is closed and replaced whenever the cache or its load state changes, so
	// waiters block on it instead of sleeping in a loop.
	changed chan struct{}
}

// broadcastLocked wakes everything waiting on the cache. cc.mu must be held.
func (cc *calendarCache) broadcastLocked() {
	if cc.changed != nil {
		close(cc.changed)
	}
	cc.changed = make(chan struct{})
}

// waitChanLocked returns the channel closed by the next change. cc.mu must be held.
func (cc *calendarCache) waitChanLocked() <-chan struct{} {
	if cc.changed == nil {
		cc.changed = make(chan struct{})
	}
	return cc.changed
}

// servableLocked reports whether the cache may answer listing requests: once fully
// loaded, or, only when early sync is on, as soon as it holds events from a load that
// is still running. An empty cache is never served, so a client cannot mistake "not
// loaded yet" for "emptied". cc.mu must be held.
func (b *backend) servableLocked(cc *calendarCache) bool {
	return cc.loaded || (b.earlySync && len(cc.objects) > 0)
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
//
// New files store the event's structure (Tree) rather than iCalendar text: writing text
// meant encoding it with a validating encoder and parsing it back with a strict decoder,
// and some events did not survive that, which silently dropped them from the restored
// cache. The structure is plain data and always comes back as it went in. Files from
// before that have ICS (text) instead, and are still read.
type persistedObject struct {
	Path    string
	ETag    string
	ModTime time.Time
	ICS     string          `json:",omitempty"`
	Tree    *ical.Component `json:",omitempty"`
}

type persistedCache struct {
	LoadedAt time.Time
	Objects  map[string]persistedObject
	// Count is how many events the cache held when it was saved. Objects can be shorter
	// if some could not be encoded, and a restore that finds fewer than Count must not
	// pass the cache off as complete. Files from before this field existed have 0.
	Count int `json:",omitempty"`
}

// errorClass shortens an error for the log: digits become '#', so the same failure on
// different lines groups together, and it is cut short, since the text may quote a bit of
// the event it failed on.
func errorClass(err error) string {
	s := regexp.MustCompile(`[0-9]+`).ReplaceAllString(err.Error(), "#")
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

// failureSummary renders "3x <class>, 1x <class>" for the most common failures.
func failureSummary(classes map[string]int) string {
	type kv struct {
		k string
		n int
	}
	var all []kv
	for k, n := range classes {
		all = append(all, kv{k, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].k < all[j].k
	})
	var parts []string
	for i, e := range all {
		if i == 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%dx %s", e.n, e.k))
	}
	return strings.Join(parts, "; ")
}

// decodeICS reads a stored event. The strict decoder comes first; the repair that is
// applied to events read from Proton (sanitizeICS) is the fallback, so what was accepted
// when it arrived is also accepted when read back.
func decodeICS(text string) (*ical.Calendar, error) {
	cal, _, err := decodeICSReporting(text)
	return cal, err
}

// decodeICSReporting is decodeICS that also says whether the repair was needed.
func decodeICSReporting(text string) (cal *ical.Calendar, repaired bool, err error) {
	cal, err = ical.NewDecoder(strings.NewReader(text)).Decode()
	if err == nil {
		return cal, false, nil
	}
	if fixed, err2 := ical.NewDecoder(bytes.NewReader(sanitizeICS([]byte(text)))).Decode(); err2 == nil {
		return fixed, true, nil
	}
	return nil, false, err
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
		loadCacheFromDisk(calID, cc, b.cacheKey) // logs what it restored, or why the calendar will be fetched again
	}
	// Start the calendar event-loop poller once per calendar, so inbound changes
	// (events created/edited in Proton or on another device) are patched into the
	// cache within the poll interval instead of only on a 30-minute full reload.
	if b.pollers != nil && !b.pollers[calID] {
		b.pollers[calID] = true
		wake := b.push.register(calID)
		stop := make(chan struct{})
		if b.stops == nil {
			b.stops = make(map[string]chan struct{})
		}
		b.stops[calID] = stop
		if b.notifier != nil {
			go func() {
				if err := b.notifier.Subscribe(protonmail.NotifierLoop{Type: protonmail.NotifierLoopCalendar, Identifier: calID}); err != nil {
					log.Printf("push: could not add calendar %s yet, it will be sent on reconnect: %v", calID, err)
				}
			}()
		}
		go b.pollCalendar(calID, wake, stop)
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
// waitForData blocks until the cache can be served or the wait is over. It is woken by
// the loader, not by a timer, so a calendar that loads quickly answers at once.
func (b *backend) waitForData(cc *calendarCache, wait time.Duration) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		cc.mu.Lock()
		done := b.servableLocked(cc)
		ch := cc.waitChanLocked()
		cc.mu.Unlock()
		if done {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			return
		}
	}
}

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
		b.waitForData(cc, initialLoadWait)
	}

	cc.mu.Lock()
	ready = b.servableLocked(cc)
	cc.mu.Unlock()
	return snapshotObjects(cc), ready
}

func (b *backend) loadCache(calID string, cc *calendarCache) {
	cc.mu.Lock()
	cold := !cc.loaded
	cc.loadStarted = time.Now()
	cc.fetched, cc.total, cc.loadErr = 0, 0, ""
	cc.broadcastLocked()
	cc.mu.Unlock()
	if cold {
		b.loads.start(calID)
	}

	var failure error
	defer func() {
		cc.mu.Lock()
		cc.loading = false
		if failure != nil {
			cc.loadErr = failure.Error()
		}
		events := len(cc.objects)
		cc.broadcastLocked()
		cc.mu.Unlock()
		if cold {
			b.loads.finish(calID, events, failure)
		}
	}()

	bootstrap, err := b.c.BootstrapCalendar(calID)
	if err != nil {
		failure = fmt.Errorf("bootstrap failed: %w", err)
		log.Printf("cache %s: %v", calID, failure)
		return
	}
	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		failure = fmt.Errorf("keyring decrypt failed: %w", err)
		log.Printf("cache %s: %v", calID, failure)
		return
	}

	// The total only makes the progress readable; without it the load goes on and the
	// progress shows what has been fetched so far.
	total, err := b.c.GetEventsCount(calID)
	if err != nil {
		log.Printf("cache %s: event count unavailable, progress will show no total: %v", calID, err)
		total = 0
	}
	cc.mu.Lock()
	cc.total = total
	cc.mu.Unlock()
	b.loads.update(calID, 0, total)

	// Decode each page as it arrives instead of after the last one: the time goes into
	// fetching, so decoding in step costs nothing and lets a calendar that is being
	// served early (see earlySync) fill in while the load is still running.
	fresh := make(map[string]caldav.CalendarObject)
	_, err = b.c.ListAllCalendarEventsProgress(calID, nil, protonmail.ListProgress{
		Total: total,
		Page: func(page []*protonmail.CalendarEvent, running int) {
			for _, event := range page {
				co, err := getCalendarObject(b, calID, calKr, event, bootstrap.CalendarSettings)
				if err != nil {
					log.Printf("cache %s: skipping event %s: %v", calID, event.ID, err)
					continue
				}
				fresh[event.ID] = *co

				// Publish incrementally so a client polling mid-load sees the calendar
				// fill in rather than waiting for the entire load to finish.
				cc.mu.Lock()
				cc.objects[event.ID] = *co
				cc.byToken[objectToken(co.Data, event.ID)] = event.ID
				cc.mu.Unlock()
			}
			cc.mu.Lock()
			cc.fetched = running
			cc.broadcastLocked()
			cc.mu.Unlock()
			b.loads.update(calID, running, total)
		},
	})
	if err != nil {
		failure = fmt.Errorf("list events failed: %w", err)
		log.Printf("cache %s: %v", calID, failure)
		return
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
	cc.broadcastLocked()
	cc.mu.Unlock()

	saveCacheToDisk(calID, cc, b.cacheKey)
	log.Printf("cache %s: loaded %d events", calID, len(fresh))
	if n, ev := addressCollisions(fresh); n > 0 {
		log.Printf("cache %s: %d address(es) are shared by several events (%d events in all), so a client can only be given one of each", calID, n, ev)
	}
	logUnverifiedSignatures(calID)
	logServing(calID)
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
		saveCacheToDisk(calID, cc, b.cacheKey)
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
		saveCacheToDisk(calID, cc, b.cacheKey)
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

// cacheCTag returns a CalendarServer getctag for the calendar: an opaque token
// derived from the current object set that changes whenever any event is added,
// edited or removed. It combines a per-object hash of (path, etag) order-
// independently with the object count, so it is stable across restarts for
// unchanged content and cheap to recompute on each poll. Returns "" until the
// cache has completed a load, so no ctag is advertised while cold (the client
// keeps polling on its interval until real data exists).
func (b *backend) cacheCTag(calID string) string {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if !b.servableLocked(cc) {
		return ""
	}
	var acc uint64
	for _, o := range cc.objects {
		h := fnv.New64a()
		h.Write([]byte(o.Path))
		h.Write([]byte{0})
		h.Write([]byte(o.ETag))
		acc += h.Sum64()
	}
	return fmt.Sprintf("%016x-%d", acc, len(cc.objects))
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

// saveCacheToDisk atomically writes the cache, sealed with key, to the config directory.
// Without a key nothing is written: the cache holds the decrypted calendar, and an
// unencrypted copy is never the fallback.
func saveCacheToDisk(calID string, cc *calendarCache, key *[32]byte) {
	if key == nil {
		noKeyOnce.Do(func() {
			log.Printf("cache: not saving calendars to disk, because there is no key to encrypt them with")
		})
		return
	}
	path, err := cacheFilePath(calID)
	if err != nil {
		log.Printf("cache %s: cannot resolve cache path: %v", calID, err)
		return
	}

	cc.mu.Lock()
	pc := persistedCache{
		LoadedAt: cc.loadedAt,
		Objects:  make(map[string]persistedObject, len(cc.objects)),
		Count:    len(cc.objects),
	}
	for id, o := range cc.objects {
		po := persistedObject{Path: o.Path, ETag: o.ETag, ModTime: o.ModTime}
		if o.Data != nil {
			po.Tree = o.Data.Component
		}
		pc.Objects[id] = po
	}
	cc.mu.Unlock()

	data, err := sealCache(pc, key)
	if err != nil {
		log.Printf("cache %s: could not encrypt the cache: %v", calID, err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("cache %s: write failed: %v", calID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("cache %s: rename failed: %v", calID, err)
		return
	}
	// Version 0.6.1 kept a plaintext copy of an old cache once. An encrypted cache next to
	// a readable copy of itself would be pointless, so it goes.
	if err := os.Remove(path + ".bak"); err == nil {
		log.Printf("cache %s: removed the unencrypted backup left by an earlier version", calID)
	}
}

var noKeyOnce sync.Once

// loadCacheFromDisk populates cc from a previously-saved cache file, if present.
// addressCollisions counts the addresses that more than one event would be served at, and
// the events involved. A client keys an event by its address, so events sharing one cannot
// all be delivered, and which of them is served can change whenever the cache is rebuilt.
func addressCollisions(objs map[string]caldav.CalendarObject) (addresses, events int) {
	byToken := make(map[string]int, len(objs))
	for id, o := range objs {
		byToken[objectToken(o.Data, id)]++
	}
	for _, n := range byToken {
		if n > 1 {
			addresses++
			events += n
		}
	}
	return addresses, events
}

// restoreReport says what reading a cache file back gives.
type restoreReport struct {
	Entries  int            // events in the file
	Want     int            // events the file says it held (Count, or Entries for old files)
	Restored int            // events that were read back
	FromTree int            // ... of which from the structure format
	FromText int            // ... of which from iCalendar text
	Repaired int            // ... of which needed the repair for text from Proton
	Failed   map[string]int // error class -> events that could not be read back

	// Whether the restored events can be handed to a client (see makeEncodable).
	Fixed          int            // events that needed a repair to be served, and got it
	FixedKinds     map[string]int // repair -> events
	Unservable     int            // events that still do not encode after the repair
	UnservableKind map[string]int // error class -> events

	SharedAddresses int // addresses that several events would be served at
	SharedEvents    int // the events involved
}

func (r restoreReport) Complete() bool { return r.Restored == r.Want }

// restoreObjects reads the events of a cache file back.
func restoreObjects(pc persistedCache) (map[string]caldav.CalendarObject, restoreReport) {
	rep := restoreReport{Entries: len(pc.Objects), Want: pc.Count, Failed: map[string]int{},
		FixedKinds: map[string]int{}, UnservableKind: map[string]int{}}
	if rep.Want < rep.Entries {
		rep.Want = rep.Entries
	}
	objs := make(map[string]caldav.CalendarObject, len(pc.Objects))
	for id, po := range pc.Objects {
		var data *ical.Calendar
		switch {
		case po.Tree != nil:
			data = &ical.Calendar{Component: po.Tree}
			rep.FromTree++
		default:
			cal, repaired, err := decodeICSReporting(po.ICS)
			if err != nil {
				rep.Failed[errorClass(err)]++
				continue
			}
			data = cal
			rep.FromText++
			if repaired {
				rep.Repaired++
			}
		}
		// Events cached by an earlier version may not encode, which the server needs for
		// every response. The uid and time to fall back on come from the event itself.
		facts := eventFacts{stamp: po.ModTime}
		if len(data.Children) > 0 {
			if uid := data.Children[0].Props.Get(ical.PropUID); uid != nil {
				facts.uid = uid.Value
			}
		}
		if repairs, err := makeEncodable(data, facts); err != nil {
			rep.Unservable++
			rep.UnservableKind[errorClass(err)]++
		} else if len(repairs) > 0 {
			rep.Fixed++
			seen := map[string]bool{}
			for _, r := range repairs {
				if !seen[r] {
					seen[r] = true
					rep.FixedKinds[r]++
				}
			}
		}
		objs[id] = caldav.CalendarObject{Path: po.Path, ETag: po.ETag, ModTime: po.ModTime, Data: data}
	}
	rep.Restored = len(objs)
	rep.SharedAddresses, rep.SharedEvents = addressCollisions(objs)
	return objs, rep
}

func loadCacheFromDisk(calID string, cc *calendarCache, key *[32]byte) bool {
	path, err := cacheFilePath(calID)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pc, sealed, err := openCacheFile(data, key)
	if err != nil {
		// Fail closed: a cache that cannot be opened is not used, and the calendar is
		// loaded from Proton, which rebuilds and reseals it.
		log.Printf("cache %s: on-disk cache not used, the calendar will be loaded from Proton: %v", calID, err)
		return false
	}
	if !sealed {
		log.Printf("cache %s: the on-disk cache is from a version that did not encrypt it; it is encrypted the next time it is saved", calID)
	}

	objs, rep := restoreObjects(pc)
	complete := rep.Complete()

	cc.mu.Lock()
	cc.objects = objs
	cc.byToken = buildTokenIndex(objs)
	cc.loadedAt = pc.LoadedAt
	// An incomplete cache is kept (it is served early if early sync is on) but is not
	// "loaded": the calendar is fetched in full instead of being passed off as complete.
	cc.loaded = complete
	cc.mu.Unlock()

	if rep.Fixed > 0 {
		log.Printf("cache %s: %d restored event(s) needed repair to be served to clients: %s", calID, rep.Fixed, countsSummary(rep.FixedKinds))
	}
	if rep.SharedAddresses > 0 {
		log.Printf("cache %s: %d address(es) are shared by several events (%d events in all), so a client can only be given one of each",
			calID, rep.SharedAddresses, rep.SharedEvents)
	}
	if rep.Unservable > 0 {
		log.Printf("cache %s: %d restored event(s) cannot be served to clients, because they do not encode as iCalendar; loading the calendar from Proton again may fix them (%s)",
			calID, rep.Unservable, countsSummary(rep.UnservableKind))
	}
	if complete {
		log.Printf("cache %s: restored %d events from disk", calID, rep.Restored)
	} else {
		log.Printf("cache %s: only %d of %d events could be restored from disk, so the calendar will be loaded again in full (%d unreadable: %s)",
			calID, rep.Restored, rep.Want, rep.Want-rep.Restored, failureSummary(rep.Failed))
	}
	return complete
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
