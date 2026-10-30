package protonmail

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEvents serves /calendar/v1/<id>/events with total events, 100 per page, each page
// taking delay. It records the highest number of requests it served at once.
type fakeEvents struct {
	total    int
	delay    time.Duration
	failPage int  // page index that answers 500, or -1
	repeat   bool // every page returns the same events (broken pagination)

	inflight, peak atomic.Int32
	requests       atomic.Int32
}

func (f *fakeEvents) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := f.inflight.Add(1)
		defer f.inflight.Add(-1)
		for {
			p := f.peak.Load()
			if n <= p || f.peak.CompareAndSwap(p, n) {
				break
			}
		}
		f.requests.Add(1)
		time.Sleep(f.delay)

		page, _ := strconv.Atoi(r.URL.Query().Get("Page"))
		if page == f.failPage {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"Code":2001,"Error":"boom"}`)
			return
		}
		from, to := page*100, page*100+100
		if f.repeat {
			from, to = 0, 100
		}
		if to > f.total {
			to = f.total
		}
		fmt.Fprint(w, `{"Code":1000,"Events":[`)
		for i := from; i < to; i++ {
			if i > from {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"ID":"e%04d"}`, i)
		}
		fmt.Fprint(w, `]}`)
	}
}

func listClient(t *testing.T, f *fakeEvents) *Client {
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := &Client{RootURL: srv.URL, AppVersion: "Other"}
	c.SetSession("u", "t")
	return c
}

func TestListAllReturnsEverythingInOrder(t *testing.T) {
	for _, total := range []int{0, 1, 99, 100, 101, 250, 300, 701} {
		f := &fakeEvents{total: total, failPage: -1}
		got, err := listClient(t, f).ListAllCalendarEvents("cal", nil)
		if err != nil {
			t.Fatalf("total=%d: %v", total, err)
		}
		if len(got) != total {
			t.Fatalf("total=%d: got %d events", total, len(got))
		}
		for i, e := range got {
			if e.ID != fmt.Sprintf("e%04d", i) {
				t.Fatalf("total=%d: event %d is %s, pages were merged out of order", total, i, e.ID)
			}
		}
	}
}

func TestListAllRequestsFewPagesPastTheEnd(t *testing.T) {
	f := &fakeEvents{total: 250, failPage: -1}
	listClient(t, f).ListAllCalendarEvents("cal", nil)
	// 3 real pages; at most listWindow-1 more may have been asked for needlessly.
	if n := int(f.requests.Load()); n < 3 || n > 3+listWindow-1 {
		t.Fatalf("%d requests for a 3-page calendar", n)
	}
}

func TestListAllFetchesPagesConcurrentlyButBounded(t *testing.T) {
	f := &fakeEvents{total: 1200, delay: 40 * time.Millisecond, failPage: -1}
	c := listClient(t, f)
	start := time.Now()
	got, err := c.ListAllCalendarEvents("cal", nil)
	if err != nil || len(got) != 1200 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	if peak := int(f.peak.Load()); peak < 2 || peak > listWindow {
		t.Fatalf("peak concurrency %d, want between 2 and %d", peak, listWindow)
	}
	// 13 pages of 40ms one by one would take 520ms; with 3 in flight, about a third.
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("took %s, pages do not seem to overlap", took)
	}
}

func TestListAllSlotsBoundAllCalendarsTogether(t *testing.T) {
	f := &fakeEvents{total: 1500, delay: 30 * time.Millisecond, failPage: -1}
	c := listClient(t, f)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // four big calendars loading at once, like a cold start
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := c.ListAllCalendarEvents("cal", nil); err != nil || len(got) != 1500 {
				t.Errorf("got %d, %v", len(got), err)
			}
		}()
	}
	wg.Wait()
	if peak := int(f.peak.Load()); peak > cap(listSlots) {
		t.Fatalf("peak %d requests at once across calendars, want at most %d", peak, cap(listSlots))
	}
}

func TestListAllReportsAPageError(t *testing.T) {
	f := &fakeEvents{total: 1000, failPage: 2}
	if _, err := listClient(t, f).ListAllCalendarEvents("cal", nil); err == nil {
		t.Fatal("a failing page must fail the listing, not return a silently truncated calendar")
	}
}

func TestListAllStopsWhenPaginationRepeats(t *testing.T) {
	f := &fakeEvents{total: 500, repeat: true, failPage: -1}
	got, err := listClient(t, f).ListAllCalendarEvents("cal", nil)
	if err != nil || len(got) != 100 {
		t.Fatalf("got %d, %v: repeated pages must stop the listing without duplicates", len(got), err)
	}
}
