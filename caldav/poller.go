package caldav

import (
	"fmt"
	"log"
	"time"

	"github.com/mathewcsims/protoxide/backoff"
	"github.com/mathewcsims/protoxide/notify"
	"github.com/mathewcsims/protoxide/protonmail"
)

// calendarPollInterval is how often the calendar event loop is polled for
// changes while Proton's push channel is not usable. Proton's web client polls on
// a similar cadence; each idle poll is a single cheap request that just echoes the
// current cursor.
const calendarPollInterval = 30 * time.Second

// calendarPushFallbackInterval is the safety-net poll while the push channel is
// healthy. Pushes are what normally trigger a poll; this only catches a ping that
// was lost, so it can be slow.
const calendarPushFallbackInterval = 5 * time.Minute

// maxPollBackoff caps the wait after repeated failures: 30s, 1m, 2m, 4m, 8m, then
// every ~10 minutes until a poll succeeds again. Retrying a dead session every 30
// seconds helps nobody and makes this client look abusive to Proton.
const maxPollBackoff = 10 * time.Minute

// pollCalendar drives Proton's calendar event loop
// (GET /calendar/v1/{calID}/modelevents/{cursor}) to keep the decrypted cache
// live. It seeds a cursor at the current head, then polls for changes and patches
// only the affected events into the cache — avoiding the minutes-long full reload
// for every inbound change. One poller runs per calendar; see cacheFor.
func (b *backend) pollCalendar(calID string, wake <-chan struct{}, stop <-chan struct{}) {
	cursor, err := b.c.GetLatestCalendarModelEventID(calID)
	if err != nil {
		log.Printf("poller %s: could not seed cursor, delta sync disabled (falling back to periodic reload): %v", calID, err)
		notify.Send("warning", "poller-seed", "protoxide: inbound sync degraded",
			fmt.Sprintf("Could not start the calendar event-loop poller: %v. Inbound changes will only appear on the 30-minute reload.", err))
		return
	}
	log.Printf("poller %s: started, cursor seeded", calID)

	bo := backoff.New(calendarPollInterval, maxPollBackoff)
	wait := b.push.interval()
	for {
		// Sleep until the next scheduled poll or until Proton pushes a ping for this
		// calendar, whichever comes first.
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-wake:
		case <-stop:
			timer.Stop()
			log.Printf("poller %s: stopped (calendar removed)", calID)
			return
		}
		timer.Stop()
		failed := false

		// Drain all currently-available pages before sleeping again.
		for {
			select {
			case <-stop:
				log.Printf("poller %s: stopped (calendar removed)", calID)
				return
			default:
			}
			evs, err := b.c.GetCalendarModelEvents(calID, cursor)
			if err != nil {
				log.Printf("poller %s: poll failed: %v", calID, err)
				notify.Send("warning", "poller-poll", "protoxide: inbound poll failing",
					fmt.Sprintf("Polling Proton's calendar event loop failed: %v. Inbound sync is stalled; this often means the Proton session needs refreshing.", err))
				failed = true
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

		if failed {
			wait = bo.Next()
			log.Printf("poller %s: next attempt in %s", calID, wait.Round(time.Second))
		} else {
			bo.Reset()
			wait = b.push.interval()
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
