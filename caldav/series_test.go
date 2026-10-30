package caldav

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	"github.com/mathewcsims/protoxide/protonmail"
)

func withETag(cal *ical.Calendar, etag string) caldav.CalendarObject {
	return caldav.CalendarObject{ETag: etag, ModTime: time.Unix(1700000000, 0), Data: cal}
}

func seriesObjects() map[string]caldav.CalendarObject {
	return map[string]caldav.CalendarObject{
		"plain":  withETag(event("plain-uid"), "E-plain"),
		"master": withETag(recurring("series", ""), "E-master"),
		"occ2":   withETag(recurring("series", "20260202T100000Z"), "E-occ2"),
		"occ1":   withETag(recurring("series", "20260126T100000Z"), "E-occ1"),
	}
}

func TestAnEventAloneUnderItsUIDIsServedExactlyAsCached(t *testing.T) {
	v := buildView("cal", seriesObjects())
	e, ok := v.byToken["plain-uid"]
	if !ok || len(e.ids) != 1 || e.ids[0] != "plain" {
		t.Fatalf("%+v", e)
	}
	if e.obj.ETag != "E-plain" || e.obj.Path != "/caldav/calendars/cal/plain-uid.ics" {
		t.Fatalf("an ordinary event must keep its ETag and address so clients do not fetch it again: %+v", e.obj)
	}
}

func TestASeriesAndItsOccurrencesAreOneResourceSeriesFirst(t *testing.T) {
	v := buildView("cal", seriesObjects())
	e, ok := v.byToken["series"]
	if !ok {
		t.Fatal("no resource for the series")
	}
	if got := strings.Join(e.ids, ","); got != "master,occ1,occ2" {
		t.Fatalf("members = %s, want the series, then the occurrences by RECURRENCE-ID", got)
	}
	evs := e.obj.Data.Events()
	if len(evs) != 3 {
		t.Fatalf("%d components, want 3", len(evs))
	}
	if evs[0].Props.Get(ical.PropRecurrenceID) != nil || evs[1].Props.Get(ical.PropRecurrenceID).Value != "20260126T100000Z" || evs[2].Props.Get(ical.PropRecurrenceID).Value != "20260202T100000Z" {
		t.Fatal("components are in the wrong order")
	}
	if e.obj.Path != "/caldav/calendars/cal/series.ics" || !strings.HasPrefix(e.obj.ETag, "G") {
		t.Fatalf("%+v", e.obj)
	}
	if e.obj.Data.Props.Get(ical.PropVersion) == nil {
		t.Error("the calendar-level properties were lost")
	}
	if len(v.objects) != 2 {
		t.Fatalf("%d resources for 4 events, want 2", len(v.objects))
	}
}

func TestTheViewIsIdenticalHoweverTheMapIsOrdered(t *testing.T) {
	first := buildView("cal", seriesObjects()).byToken["series"].obj.ETag
	for i := 0; i < 60; i++ {
		v := buildView("cal", seriesObjects())
		if got := v.byToken["series"].obj.ETag; got != first {
			t.Fatalf("run %d: ETag %s, then %s: clients would fetch the series again for nothing", i, first, got)
		}
		if fmt.Sprint(v.byToken["series"].ids) != "[master occ1 occ2]" {
			t.Fatalf("run %d: order %v", i, v.byToken["series"].ids)
		}
	}
}

func TestTheETagChangesWhenAnyEventOfTheSeriesChanges(t *testing.T) {
	base := buildView("cal", seriesObjects()).byToken["series"].obj.ETag
	for _, id := range []string{"master", "occ1", "occ2"} {
		objs := seriesObjects()
		o := objs[id]
		o.ETag = "CHANGED"
		objs[id] = o
		if got := buildView("cal", objs).byToken["series"].obj.ETag; got == base {
			t.Errorf("changing %s did not change the resource's ETag", id)
		}
	}
	objs := seriesObjects()
	delete(objs, "occ1")
	if got := buildView("cal", objs).byToken["series"].obj.ETag; got == base {
		t.Error("removing an occurrence did not change the ETag")
	}
	objs = seriesObjects()
	objs["occ3"] = withETag(recurring("series", "20260209T100000Z"), "E-occ3")
	if got := buildView("cal", objs).byToken["series"].obj.ETag; got == base {
		t.Error("adding an occurrence did not change the ETag")
	}
}

func TestAnOccurrenceWithoutItsSeriesIsStillServed(t *testing.T) {
	objs := map[string]caldav.CalendarObject{"only": withETag(recurring("orphan", "20260126T100000Z"), "E")}
	e, ok := buildView("cal", objs).byToken["orphan"]
	if !ok || len(e.ids) != 1 || e.obj.Path != "/caldav/calendars/cal/orphan.ics" {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestTheChangeTokenFollowsEveryEventOfASeries(t *testing.T) {
	b := &backend{caches: map[string]*calendarCache{}}
	cc := fresh()
	cc.loaded, cc.loadedAt = true, time.Now()
	for id, o := range seriesObjects() {
		cc.objects[id] = o
	}
	cc.changedLocked()
	b.caches["cal"] = cc

	before := b.cacheCTag("cal")
	if before == "" {
		t.Fatal("no change token")
	}
	if again := b.cacheCTag("cal"); again != before {
		t.Fatal("the token changed with nothing changing")
	}
	cc.mu.Lock()
	o := cc.objects["occ1"]
	o.ETag = "EDITED"
	cc.objects["occ1"] = o
	cc.changedLocked()
	cc.mu.Unlock()
	if after := b.cacheCTag("cal"); after == before {
		t.Fatal("editing an occurrence must change the token, or clients never look")
	}
}

// --- writes ---

func TestWritesThatWouldSplitOrMergeASeriesAreRefusedWithoutTouchingProton(t *testing.T) {
	b := &backend{caches: map[string]*calendarCache{}} // no Proton client: any call would panic
	cc := fresh()
	cc.loaded, cc.loadedAt = true, time.Now()
	for id, o := range seriesObjects() {
		cc.objects[id] = o
	}
	cc.changedLocked()
	b.caches["cal"] = cc

	multi := recurring("series", "")
	multi.Children = append(multi.Children, recurring("series", "20260126T100000Z").Children[0])

	for name, tc := range map[string]struct {
		path string
		cal  *ical.Calendar
	}{
		"several components":                 {"/caldav/calendars/cal/new-uid.ics", multi},
		"a series that has occurrences":      {"/caldav/calendars/cal/series.ics", recurring("series", "")},
		"an occurrence into an ordinary one": {"/caldav/calendars/cal/plain-uid.ics", recurring("plain-uid", "20260126T100000Z")},
	} {
		t.Run(name, func(t *testing.T) {
			// What the client sees: a real PUT through the real handler.
			req := httptest.NewRequest(http.MethodPut, tc.path, strings.NewReader(encodeText(t, tc.cal)))
			req.Header.Set("Content-Type", "text/calendar")
			rec := httptest.NewRecorder()
			(&caldav.Handler{Backend: b}).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403 so the client reverts the change and says why: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "edited occurrences") {
				t.Errorf("the reason must reach the client: %q", rec.Body.String())
			}
		})
	}
}

// deleteServer records Proton delete requests and can be told to fail one of them.
type deleteServer struct {
	mu     sync.Mutex
	order  []string
	failOn string
}

func (d *deleteServer) client(t *testing.T) *protonmail.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deleting is a PUT to .../events/sync with the event's ID in the JSON body.
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/events/sync") {
			http.NotFound(w, r)
			return
		}
		var body struct{ Events []struct{ ID string } }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Events) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := body.Events[0].ID
		d.mu.Lock()
		defer d.mu.Unlock()
		if id == d.failOn {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"Code":2001,"Error":"boom"}`)
			return
		}
		d.order = append(d.order, id)
		fmt.Fprint(w, `{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":1000}}]}`)
	}))
	t.Cleanup(srv.Close)
	c := &protonmail.Client{RootURL: srv.URL, AppVersion: "Other"}
	c.SetSession("u", "t")
	return c
}

func deletingBackend(t *testing.T, d *deleteServer) *backend {
	config := fresh()
	config.loaded, config.loadedAt = true, time.Now()
	for id, o := range seriesObjects() {
		config.objects[id] = o
	}
	config.changedLocked()
	return &backend{c: d.client(t), caches: map[string]*calendarCache{"cal": config}}
}

func TestDeletingASeriesDeletesAllItsEventsOccurrencesFirst(t *testing.T) {
	d := &deleteServer{}
	b := deletingBackend(t, d)
	if err := b.DeleteCalendarObject(nil, "/caldav/calendars/cal/series.ics"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.order, ","); got != "occ2,occ1,master" {
		t.Fatalf("deleted %s, want the occurrences first and the series last", got)
	}
	cc := b.caches["cal"]
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if len(cc.objects) != 1 || cc.objects["plain"].ETag == "" {
		t.Fatalf("the cache should keep only the unrelated event, got %d", len(cc.objects))
	}
	if _, ok := cc.viewLocked("cal").byToken["series"]; ok {
		t.Fatal("the series is still served")
	}
}

func TestDeletingAnOrdinaryEventDeletesOnlyThatEvent(t *testing.T) {
	d := &deleteServer{}
	b := deletingBackend(t, d)
	if err := b.DeleteCalendarObject(nil, "/caldav/calendars/cal/plain-uid.ics"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.order, ","); got != "plain" {
		t.Fatalf("deleted %q", got)
	}
}

func TestAFailureHalfwayThroughDeletingASeriesStopsAndReportsIt(t *testing.T) {
	d := &deleteServer{failOn: "occ1"}
	b := deletingBackend(t, d)
	err := b.DeleteCalendarObject(nil, "/caldav/calendars/cal/series.ics")
	if err == nil {
		t.Fatal("a failed delete must be reported")
	}
	if got := strings.Join(d.order, ","); got != "occ2" {
		t.Fatalf("deleted %q before the failure", got)
	}
	cc := b.caches["cal"]
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if _, ok := cc.objects["master"]; !ok {
		t.Fatal("the series must still be there: it was not deleted")
	}
	if _, ok := cc.objects["occ2"]; ok {
		t.Fatal("the deleted occurrence must be gone from the cache")
	}
}
