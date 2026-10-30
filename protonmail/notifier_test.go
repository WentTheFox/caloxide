package protonmail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNotifier is an event-notifier server: it greets, records subscriptions, and
// sends whatever frames the test queues.
type fakeNotifier struct {
	t      *testing.T
	srv    *httptest.Server
	frames chan string // raw SSE text to write

	mu      sync.Mutex
	subs    []NotifierLoop
	headers http.Header
	query   string
	opens   int
}

func newFakeNotifier(t *testing.T, status int) *fakeNotifier {
	f := &fakeNotifier{t: t, frames: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("/event-notifier/v1/events", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.opens++
		f.headers = r.Header.Clone()
		f.query = r.URL.RawQuery
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"Code":2001,"Error":"nope"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		fmt.Fprint(w, ": hi\n\nevent: Hello\ndata: {\"id\":\"conn 1\"}\n\n")
		fl.Flush()
		for {
			select {
			case fr := <-f.frames:
				if fr == "close" {
					return
				}
				fmt.Fprint(w, fr)
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("/event-notifier/v1/connection/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/event-notifier/v1/connection/conn%201/loops" {
			http.NotFound(w, r)
			return
		}
		var b struct{ Add []NotifierLoop }
		json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.subs = append(f.subs, b.Add...)
		f.mu.Unlock()
		fmt.Fprint(w, `{"Code":1000}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNotifier) client() *Client {
	freshGate(f.srv.URL)
	c := &Client{RootURL: f.srv.URL, AppVersion: "Other"}
	c.SetSession("uid1", "tok1")
	return c
}

type notifierRecorder struct {
	pings  chan NotifierPing
	states chan string
}

func attach(n *Notifier) *notifierRecorder {
	r := &notifierRecorder{pings: make(chan NotifierPing, 16), states: make(chan string, 16)}
	n.OnPing = func(p NotifierPing) { r.pings <- p }
	n.OnState = func(up bool, d string) { r.states <- fmt.Sprintf("%v %s", up, d) }
	return r
}

func TestNotifierSubscribesAndDeliversPings(t *testing.T) {
	f := newFakeNotifier(t, 200)
	n := f.client().NewNotifier()
	rec := attach(n)
	n.Subscribe(NotifierLoop{NotifierLoopCalendar, "cal-a"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	select {
	case s := <-rec.states:
		if !strings.HasPrefix(s, "true connected, 1 loop") {
			t.Fatalf("state = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never connected")
	}

	f.mu.Lock()
	if got := f.headers.Get("Authorization"); got != "Bearer tok1" {
		t.Errorf("Authorization = %q", got)
	}
	if got := f.headers.Get("X-Pm-Uid"); got != "uid1" {
		t.Errorf("X-Pm-Uid = %q", got)
	}
	if !strings.Contains(f.query, "x-pm-uid=uid1") || strings.Contains(f.query, "tok1") {
		t.Errorf("query = %q (uid wanted, token must never be in the URL)", f.query)
	}
	if len(f.subs) != 1 || f.subs[0].Identifier != "cal-a" {
		t.Errorf("subs = %+v", f.subs)
	}
	f.mu.Unlock()

	// A loop added while connected goes out immediately.
	if err := n.Subscribe(NotifierLoop{NotifierLoopCalendar, "cal-b"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if len(f.subs) != 2 || f.subs[1].Identifier != "cal-b" {
		t.Errorf("subs after add = %+v", f.subs)
	}
	f.mu.Unlock()

	f.frames <- "event: Ping\ndata: {\"type\":\"calendar\",\"identifier\":\"cal-a\"}\n\n"
	f.frames <- "event: Ping\ndata: not json\n\n"            // dropped
	f.frames <- "event: Mystery\ndata: {}\n\n"               // dropped
	f.frames <- "event: Ping\ndata: {\"type\":\"core\"}\n\n" // delivered, no identifier
	for _, want := range []string{"calendar/cal-a", "core/"} {
		select {
		case p := <-rec.pings:
			if got := p.Type + "/" + p.Identifier; got != want {
				t.Fatalf("ping = %s, want %s", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no ping %s", want)
		}
	}
}

func TestNotifierMultiLineDataAndCRLessFraming(t *testing.T) {
	f := newFakeNotifier(t, 200)
	n := f.client().NewNotifier()
	rec := attach(n)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	<-rec.states
	f.frames <- "event: Ping\ndata: {\"type\":\ndata: \"calendar\"}\n\n"
	select {
	case p := <-rec.pings:
		if p.Type != "calendar" {
			t.Fatalf("ping = %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("multi-line data frame was lost")
	}
}

func TestNotifierUnavailableIsReportedNotFatal(t *testing.T) {
	f := newFakeNotifier(t, http.StatusNotFound)
	n := f.client().NewNotifier()
	rec := attach(n)
	ctx, cancel := context.WithCancel(context.Background())
	go n.Run(ctx)
	select {
	case s := <-rec.states:
		if !strings.HasPrefix(s, "false HTTP 404") || !strings.Contains(s, "retrying in 6h0m0s") {
			t.Fatalf("state = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no state")
	}
	cancel()
}

func TestNotifierGoodbyeReconnectsAndResubscribes(t *testing.T) {
	f := newFakeNotifier(t, 200)
	n := f.client().NewNotifier()
	rec := attach(n)
	n.Subscribe(NotifierLoop{NotifierLoopCalendar, "cal-a"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	<-rec.states
	f.frames <- "event: Goodbye\ndata: {}\n\n"
	if s := <-rec.states; !strings.HasPrefix(s, "false server said goodbye") {
		t.Fatalf("state = %q", s)
	}
	if s := <-rec.states; !strings.HasPrefix(s, "true connected") {
		t.Fatalf("state = %q", s)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.opens != 2 || len(f.subs) != 2 {
		t.Errorf("opens=%d subs=%+v, want a second connection with the loops sent again", f.opens, f.subs)
	}
}

func TestNotifierRunStopsOnCancel(t *testing.T) {
	f := newFakeNotifier(t, 200)
	n := f.client().NewNotifier()
	rec := attach(n)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	<-rec.states
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestCoreEventParsesCalendarChanges(t *testing.T) {
	var ev Event
	raw := `{"EventID":"e","Calendars":[{"ID":"c1","Action":0},{"ID":"c2","Action":1,"Calendar":{"ID":"c2"}}],"CalendarMembers":[{"ID":"m1","Action":0}]}`
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.Calendars) != 2 || ev.Calendars[0].ID != "c1" || ev.Calendars[0].Action != EventDelete || ev.Calendars[1].Action != EventCreate {
		t.Errorf("calendars = %+v", ev.Calendars)
	}
	if len(ev.CalendarMembers) != 1 || ev.CalendarMembers[0].Action != EventDelete {
		t.Errorf("members = %+v", ev.CalendarMembers)
	}
}
