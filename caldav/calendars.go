package caldav

import (
	"log"
	"os"
)

// reconcileCalendars runs when Proton's core event loop reports a change to
// calendars or to the user's membership of them. It re-lists the calendars and
// stops everything still running for one that is gone: without this, the poller
// of a deleted (or unshared) calendar keeps failing and alerting indefinitely.
// New calendars need nothing here, their poller starts on first use (cacheFor).
func (b *backend) reconcileCalendars() {
	cals, err := b.c.ListCalendars()
	if err != nil {
		// Not fatal: the next calendar change in the core loop tries again.
		log.Printf("calendars: could not re-list after a calendar change: %v", err)
		return
	}
	present := make(map[string]bool, len(cals))
	for _, c := range cals {
		present[c.ID] = true
	}

	b.cachesMu.Lock()
	var gone []string
	for id := range b.pollers {
		if !present[id] {
			gone = append(gone, id)
		}
	}
	b.cachesMu.Unlock()

	for _, id := range gone {
		b.removeCalendar(id)
	}
}

// removeCalendar stops a calendar's poller and forgets its cache, in memory and
// on disk. If the calendar comes back, cacheFor starts a fresh poller.
func (b *backend) removeCalendar(calID string) {
	b.cachesMu.Lock()
	stop := b.stops[calID]
	delete(b.stops, calID)
	delete(b.pollers, calID)
	delete(b.caches, calID)
	b.cachesMu.Unlock()

	if stop != nil {
		close(stop)
	}
	b.push.forget(calID)
	if path, err := cacheFilePath(calID); err == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("calendars: could not remove the cache file of %s: %v", calID, err)
		}
	}
	log.Printf("calendars: %s is gone, poller stopped and cache dropped", calID)
}
