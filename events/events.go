package events

import (
	"log"
	"sync"
	"time"

	"github.com/mathewcsims/protoxide/backoff"
	"github.com/mathewcsims/protoxide/protonmail"
)

const pollInterval = 30 * time.Second

// maxErrorBackoff caps the wait after repeated failures (30s, 1m, 2m, ... 10m).
const maxErrorBackoff = 10 * time.Minute

type Receiver struct {
	c *protonmail.Client

	locker   sync.Mutex
	channels []chan<- *protonmail.Event

	// poll wakes the loop early. Buffered by one and sent to without blocking, so a
	// wake-up that arrives while a request is in flight is kept, not lost or waited for.
	poll chan struct{}

	// interval, if set, says how long to wait between polls. See SetInterval.
	interval func() time.Duration
}

// SetInterval makes the loop ask f how long to wait before every poll, so a caller can
// slow it down while nobody is using the server. A nil f restores the default.
func (r *Receiver) SetInterval(f func() time.Duration) {
	r.locker.Lock()
	r.interval = f
	r.locker.Unlock()
}

func (r *Receiver) currentInterval() time.Duration {
	r.locker.Lock()
	f := r.interval
	r.locker.Unlock()
	if f == nil {
		return pollInterval
	}
	return f()
}

func (r *Receiver) receiveEvents() {
	bo := backoff.New(pollInterval, maxErrorBackoff)
	var last string
	for {
		event, err := r.c.GetEvent(last)
		if err != nil {
			wait := bo.Next()
			log.Printf("cannot receive event: %v (next attempt in %s)", err, wait.Round(time.Second))
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-r.poll:
			}
			timer.Stop()
			continue
		}
		bo.Reset()
		last = event.ID

		r.locker.Lock()
		n := len(r.channels)
		for _, ch := range r.channels {
			ch <- event
		}
		r.locker.Unlock()

		if n == 0 {
			break
		}

		timer := time.NewTimer(r.currentInterval())
		select {
		case <-timer.C:
		case <-r.poll:
		}
		timer.Stop()
	}
}

// Poll makes the loop poll now instead of waiting out its interval. It never blocks.
func (r *Receiver) Poll() {
	select {
	case r.poll <- struct{}{}:
	default: // one wake-up is already pending
	}
}

type Manager struct {
	receivers map[string]*Receiver
	locker    sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		receivers: make(map[string]*Receiver),
	}
}

func (m *Manager) Register(c *protonmail.Client, username string, ch chan<- *protonmail.Event, done <-chan struct{}) *Receiver {
	m.locker.Lock()
	defer m.locker.Unlock()

	r, ok := m.receivers[username]
	if ok {
		r.locker.Lock()
		r.channels = append(r.channels, ch)
		r.locker.Unlock()
	} else {
		r = &Receiver{
			c:        c,
			channels: []chan<- *protonmail.Event{ch},
			poll:     make(chan struct{}, 1),
		}

		go func() {
			r.receiveEvents()

			m.locker.Lock()
			delete(m.receivers, username)
			m.locker.Unlock()
		}()

		m.receivers[username] = r
	}

	if done != nil {
		go func() {
			<-done

			r.locker.Lock()
			for i, c := range r.channels {
				if c == ch {
					r.channels = append(r.channels[:i], r.channels[i+1:]...)
				}
			}
			r.locker.Unlock()

			close(ch)
		}()
	}

	return r
}
