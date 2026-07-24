package caldav

import (
	"log"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

// calendarPollInterval is how often the calendar event loop is polled for
// changes. Proton's web client polls on a similar cadence; each idle poll is a
// single cheap request that just echoes the current cursor.
const calendarPollInterval = 30 * time.Second

// pollCalendar drives Proton's calendar event loop
// (GET /calendar/v1/{calID}/modelevents/{cursor}) to keep the decrypted cache
// live. It seeds a cursor at the current head, then polls for changes and patches
// only the affected events into the cache — avoiding the minutes-long full reload
// for every inbound change. One poller runs per calendar; see cacheFor.
func (b *backend) pollCalendar(calID string) {
	cursor, err := b.c.GetLatestCalendarModelEventID(calID)
	if err != nil {
		log.Printf("poller %s: could not seed cursor, delta sync disabled (falling back to periodic reload): %v", calID, err)
		return
	}
	log.Printf("poller %s: started, cursor seeded", calID)

	for {
		time.Sleep(calendarPollInterval)

		// Drain all currently-available pages before sleeping again.
		for {
			evs, err := b.c.GetCalendarModelEvents(calID, cursor)
			if err != nil {
				log.Printf("poller %s: poll failed: %v", calID, err)
				break
			}

			if evs.Refresh != 0 {
				// Cursor too old / state inconsistent: Proton wants a full resync.
				log.Printf("poller %s: server requested refresh, reloading cache", calID)
				b.invalidateCache(calID)
				cursor = evs.CalendarModelEventID
				break
			}

			if len(evs.CalendarEvents) > 0 {
				b.applyModelEvents(calID, evs.CalendarEvents)
			}

			cursor = evs.CalendarModelEventID
			if evs.More == 0 {
				break
			}
			// More pages pending: fetch immediately without waiting.
		}
	}
}

// applyModelEvents patches a batch of calendar-loop changes into the cache. The
// change payload carries only event metadata, so creates/updates are re-fetched
// by ID to get the encrypted cards needed to decrypt them.
func (b *backend) applyModelEvents(calID string, changes []protonmail.CalendarModelEventChange) {
	bootstrap, err := b.c.BootstrapCalendar(calID)
	if err != nil {
		log.Printf("poller %s: bootstrap failed, skipping %d change(s): %v", calID, len(changes), err)
		return
	}
	calKr, err := bootstrap.DecryptKeyring(b.privateKeys)
	if err != nil {
		log.Printf("poller %s: keyring decrypt failed, skipping %d change(s): %v", calID, len(changes), err)
		return
	}

	for _, ch := range changes {
		switch ch.Action {
		case protonmail.EventDelete:
			b.cacheDelete(calID, ch.ID)
			log.Printf("poller %s: deleted event %s", calID, ch.ID)
		case protonmail.EventCreate, protonmail.EventUpdate:
			event, err := b.c.GetCalendarEvent(calID, ch.ID)
			if err != nil {
				log.Printf("poller %s: fetch of changed event %s failed, skipping: %v", calID, ch.ID, err)
				continue
			}
			co, err := getCalendarObject(b, calID, calKr, event, bootstrap.CalendarSettings)
			if err != nil {
				log.Printf("poller %s: decrypt of changed event %s failed, skipping: %v", calID, ch.ID, err)
				continue
			}
			b.cacheStore(calID, ch.ID, *co)
			log.Printf("poller %s: upserted event %s", calID, ch.ID)
		default:
			log.Printf("poller %s: unknown action %d for event %s", calID, ch.Action, ch.ID)
		}
	}
}

// invalidateCache forces a background full reload of a calendar's cache.
func (b *backend) invalidateCache(calID string) {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	if !cc.loading {
		cc.loading = true
		go b.loadCache(calID, cc)
	}
	cc.mu.Unlock()
}
