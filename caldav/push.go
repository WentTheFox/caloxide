package caldav

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

// NOTE: Proton's push channel is not available yet (the route answers 404, see
// protonmail/notifier.go), so in practice the pollers run at calendarPollInterval.
// This code is dormant until Proton rolls the feature out.
//
// pushState connects Proton's event-notifier stream to the per-calendar pollers.
// A ping makes the matching poller run now; while the stream is healthy the
// pollers fall back to a slow safety-net interval instead of polling every 30s.
// When the stream is down they go back to the fast interval, so push is never a
// reason for inbound changes to arrive later than they did with polling alone.
type pushState struct {
	up atomic.Bool
	// detail is why the channel is down, or what it is doing, for status.
	detail string

	mu    sync.Mutex
	wakes map[string]chan struct{}
}

func (p *pushState) interval() time.Duration {
	if p.up.Load() {
		return calendarPushFallbackInterval
	}
	return calendarPollInterval
}

// register returns the wake channel for a calendar's poller. It holds one pending
// wake at most, so a burst of pings costs one poll.
func (p *pushState) register(calID string) <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wakes == nil {
		p.wakes = make(map[string]chan struct{})
	}
	ch, ok := p.wakes[calID]
	if !ok {
		ch = make(chan struct{}, 1)
		p.wakes[calID] = ch
	}
	return ch
}

// forget drops a calendar's wake channel so a removed calendar is not kept alive.
func (p *pushState) forget(calID string) {
	p.mu.Lock()
	delete(p.wakes, calID)
	p.mu.Unlock()
}

func (p *pushState) wake(calID string) {
	p.mu.Lock()
	ch := p.wakes[calID]
	p.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (p *pushState) wakeAll() {
	p.mu.Lock()
	ids := make([]string, 0, len(p.wakes))
	for id := range p.wakes {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	for _, id := range ids {
		p.wake(id)
	}
}

// handlePing routes one ping. A ping naming a calendar wakes that calendar's
// poller; a calendar ping without a known calendar (the user-scoped loop) wakes
// all of them. Anything that is not about calendars is ignored.
func (p *pushState) handlePing(ping protonmail.NotifierPing) {
	if ping.Type != protonmail.NotifierLoopCalendar {
		return
	}
	p.mu.Lock()
	_, known := p.wakes[ping.Identifier]
	p.mu.Unlock()
	if known {
		log.Printf("push: ping for calendar %s", ping.Identifier)
		p.wake(ping.Identifier)
		return
	}
	log.Printf("push: calendar ping (identifier %q), waking all pollers", ping.Identifier)
	p.wakeAll()
}

// startPush opens the event-notifier stream for this user. It never fails the
// backend: an unavailable channel only means polling stays at its fast interval.
func (b *backend) startPush() {
	n := b.c.NewNotifier()
	n.OnPing = b.push.handlePing
	n.OnState = func(up bool, detail string) {
		b.push.mu.Lock()
		b.push.detail = detail
		b.push.mu.Unlock()
		was := b.push.up.Swap(up)
		if up != was || !up {
			log.Printf("push: %s", pushStatus(up, detail))
		}
		if !up && was {
			// Pollers may be mid-way through a long safety-net wait; make them poll now
			// and fall back to the fast interval.
			b.push.wakeAll()
		}
	}
	b.notifier = n
	go func() {
		// The user-scoped calendar loop (invitations, calendar list changes). Failing to
		// learn the ID only loses that loop, the per-calendar ones are added by cacheFor.
		if u, err := b.c.GetCurrentUser(); err == nil && u.ID != "" {
			if err := n.Subscribe(protonmail.NotifierLoop{Type: protonmail.NotifierLoopCalendar, Identifier: u.ID}); err != nil {
				log.Printf("push: could not add user loop yet, it will be sent on reconnect: %v", err)
			}
		} else if err != nil {
			log.Printf("push: could not look up the user ID, skipping the user-scoped loop: %v", err)
		}
	}()
	go n.Run(context.Background())
}

func pushStatus(up bool, detail string) string {
	if up {
		return detail + "; polling relaxed to " + calendarPushFallbackInterval.String()
	}
	return "unavailable, polling every " + calendarPollInterval.String() + ": " + detail
}
