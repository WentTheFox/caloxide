package caldav

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is what `caloxide status` shows about the running server. It is read over the
// control socket (mode 0600), never over the network.
type Status struct {
	Users []UserStatus `json:"users"`
}

type UserStatus struct {
	User             string           `json:"user"`
	EarlySync        bool             `json:"early_sync"`
	PushUp           bool             `json:"push_up"`
	PushDetail       string           `json:"push_detail,omitempty"`
	RateLimitSeconds int              `json:"rate_limit_seconds,omitempty"`
	StandbyEnabled   bool             `json:"standby_enabled"`
	StandbyIdle      bool             `json:"standby_idle"`
	StandbySeconds   int              `json:"standby_seconds,omitempty"`
	Calendars        []CalendarStatus `json:"calendars"`
}

type CalendarStatus struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	State          string `json:"state"` // idle, loading, loading (serving partial), ready, refreshing, failed
	Events         int    `json:"events"`
	Fetched        int    `json:"fetched,omitempty"`
	Total          int    `json:"total,omitempty"`
	ElapsedSeconds int    `json:"elapsed_seconds,omitempty"`
	Error          string `json:"error,omitempty"`
}

var registry struct {
	mu       sync.Mutex
	backends []*backend
}

func register(b *backend) {
	registry.mu.Lock()
	registry.backends = append(registry.backends, b)
	registry.mu.Unlock()
}

// CurrentStatus describes every user the server has served so far. A user appears once
// their first authenticated request arrived: until then there is nothing to report.
func CurrentStatus() Status {
	registry.mu.Lock()
	backends := append([]*backend(nil), registry.backends...)
	registry.mu.Unlock()

	var st Status
	for _, b := range backends {
		st.Users = append(st.Users, b.status())
	}
	return st
}

// StatusJSON is CurrentStatus for the control socket.
func StatusJSON() ([]byte, error) { return json.Marshal(CurrentStatus()) }

func (b *backend) status() UserStatus {
	us := UserStatus{User: b.username, EarlySync: b.earlySync}
	b.push.mu.Lock()
	us.PushDetail = b.push.detail
	b.push.mu.Unlock()
	us.PushUp = b.push.up.Load()
	var idleFor time.Duration
	us.StandbyEnabled, us.StandbyIdle, idleFor = b.standby.state()
	us.StandbySeconds = int(idleFor / time.Second)
	if b.c != nil {
		us.RateLimitSeconds = int(b.c.RateLimitPause().Round(time.Second) / time.Second)
	}

	b.cachesMu.Lock()
	ids := make([]string, 0, len(b.caches))
	for id := range b.caches {
		ids = append(ids, id)
	}
	b.cachesMu.Unlock()

	for _, id := range ids {
		cc := b.cacheFor(id)
		cc.mu.Lock()
		cs := CalendarStatus{ID: id, Name: b.calendarName(id), Events: len(cc.objects), Fetched: cc.fetched, Total: cc.total, Error: cc.loadErr}
		switch {
		case cc.loaded && cc.loading:
			cs.State = "refreshing"
		case cc.loaded:
			cs.State = "ready"
		case cc.loading && b.servableLocked(cc):
			cs.State = "loading (serving partial)"
		case cc.loading:
			cs.State = "loading"
		case cc.loadErr != "":
			cs.State = "failed"
		default:
			cs.State = "idle"
		}
		if cc.loading && !cc.loadStarted.IsZero() {
			cs.ElapsedSeconds = int(time.Since(cc.loadStarted) / time.Second)
		}
		cc.mu.Unlock()
		us.Calendars = append(us.Calendars, cs)
	}
	sort.Slice(us.Calendars, func(i, j int) bool {
		a, c := us.Calendars[i], us.Calendars[j]
		if a.Name != c.Name {
			return a.Name < c.Name
		}
		return a.ID < c.ID
	})
	return us
}

// String renders the status for a terminal.
func (s Status) String() string {
	if len(s.Users) == 0 {
		return "No client has connected yet, so no calendar has been loaded.\n"
	}
	var sb strings.Builder
	for _, u := range s.Users {
		fmt.Fprintf(&sb, "%s\n", u.User)
		for _, c := range u.Calendars {
			name := c.Name
			if name == "" {
				name = c.ID
				if len(name) > 12 {
					name = name[:12] + "…"
				}
			}
			switch {
			case strings.HasPrefix(c.State, "loading"):
				fmt.Fprintf(&sb, "  %-24s %s: %s, %s elapsed", name, c.State, describeProgress(c.Fetched, c.Total), roundDuration(time.Duration(c.ElapsedSeconds)*time.Second))
				if c.State != "loading" {
					fmt.Fprintf(&sb, ", serving %s so far", thousands(c.Events))
				}
				sb.WriteString("\n")
			case c.State == "failed":
				fmt.Fprintf(&sb, "  %-24s failed: %s (%s events held)\n", name, c.Error, thousands(c.Events))
			default:
				fmt.Fprintf(&sb, "  %-24s %s, %s events\n", name, c.State, thousands(c.Events))
			}
		}
		if u.RateLimitSeconds > 0 {
			fmt.Fprintf(&sb, "  Proton rate limit: requests paused for another %s\n", roundDuration(time.Duration(u.RateLimitSeconds)*time.Second))
		}
		if u.PushUp {
			sb.WriteString("  Push channel: connected\n")
		} else if u.PushDetail != "" {
			fmt.Fprintf(&sb, "  Push channel: not available (%s), polling\n", u.PushDetail)
		}
		if u.StandbyIdle {
			fmt.Fprintf(&sb, "  Standby: idle for %s, polling slowly until a client returns\n", roundDuration(time.Duration(u.StandbySeconds)*time.Second))
		} else if u.StandbyEnabled {
			sb.WriteString("  Standby: on (active)\n")
		}
		if u.EarlySync {
			sb.WriteString("  Early sync: ON (calendars are served while they load; unset CALOXIDE_EARLY_SYNC after the first import)\n")
		}
	}
	return sb.String()
}

// calendarName is the display name last seen for a calendar, or "".
func (b *backend) calendarName(calID string) string {
	b.namesMu.Lock()
	defer b.namesMu.Unlock()
	return b.names[calID]
}

func (b *backend) setCalendarName(calID, name string) {
	b.namesMu.Lock()
	defer b.namesMu.Unlock()
	if b.names == nil {
		b.names = map[string]string{}
	}
	b.names[calID] = name
}

// loadingMessage says how far a calendar's first load has got, for the 503 a client
// receives meanwhile.
func (b *backend) loadingMessage(calID string) string {
	cc := b.cacheFor(calID)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.loadErr != "" && !cc.loading {
		return "calendar failed to load (" + cc.loadErr + "), it will be retried on the next request"
	}
	msg := "calendar still loading: " + describeProgress(cc.fetched, cc.total)
	if !b.earlySync {
		msg += "; set CALOXIDE_EARLY_SYNC=on to serve it while it loads"
	}
	return msg
}
