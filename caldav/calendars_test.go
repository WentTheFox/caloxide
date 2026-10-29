package caldav

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/protonmail"
)

// backendWithPollers builds a backend whose API lists the given calendars and has
// a fake "poller" registered for each of the given IDs.
func backendWithPollers(t *testing.T, listed []string, running ...string) (*backend, map[string]chan struct{}) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Code":1000,"Calendars":[`)
		for i, id := range listed {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"ID":%q}`, id)
		}
		fmt.Fprint(w, `]}`)
	}))
	t.Cleanup(srv.Close)
	config.SetConfigHome(t.TempDir())

	c := &protonmail.Client{RootURL: srv.URL, AppVersion: "Other"}
	c.SetSession("u", "t")
	b := &backend{c: c, caches: map[string]*calendarCache{}, pollers: map[string]bool{}, stops: map[string]chan struct{}{}}
	stops := map[string]chan struct{}{}
	for _, id := range running {
		b.caches[id] = &calendarCache{}
		b.pollers[id] = true
		b.stops[id] = make(chan struct{})
		stops[id] = b.stops[id]
		b.push.register(id)
	}
	return b, stops
}

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

func TestReconcileStopsOnlyRemovedCalendars(t *testing.T) {
	b, stops := backendWithPollers(t, []string{"keep"}, "keep", "gone")
	b.reconcileCalendars()

	if !closed(stops["gone"]) {
		t.Fatal("the poller of a calendar that is no longer listed must be stopped")
	}
	if closed(stops["keep"]) {
		t.Fatal("a calendar that is still listed must keep its poller")
	}
	if b.pollers["gone"] || b.caches["gone"] != nil || b.stops["gone"] != nil {
		t.Error("state of the removed calendar must be forgotten so a re-added calendar restarts cleanly")
	}
	if !b.pollers["keep"] || b.caches["keep"] == nil {
		t.Error("state of the kept calendar was touched")
	}
}

func TestReconcileKeepsEverythingWhenListingFails(t *testing.T) {
	b, stops := backendWithPollers(t, nil, "a")
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"Code":2001,"Error":"temporarily unavailable"}`)
	}))
	t.Cleanup(down.Close)
	b.c.RootURL = down.URL
	b.reconcileCalendars()
	if closed(stops["a"]) || !b.pollers["a"] {
		t.Fatal("a failed listing must not be read as every calendar having been removed")
	}
}

func TestRemoveCalendarTwiceIsHarmless(t *testing.T) {
	b, _ := backendWithPollers(t, nil, "a")
	b.removeCalendar("a")
	b.removeCalendar("a")
}
