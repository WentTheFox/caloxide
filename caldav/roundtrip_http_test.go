package caldav

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
	wdcaldav "github.com/emersion/go-webdav/caldav"
)

type multistatus struct {
	Responses []struct {
		Href     string `xml:"href"`
		Propstat []struct {
			Status string `xml:"status"`
			Prop   struct {
				ETag string `xml:"getetag"`
				Data string `xml:"calendar-data"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

// recurring builds an event with a recurrence rule and several EXDATE lines, and optionally
// the RECURRENCE-ID of a single edited occurrence.
func recurring(uid, rid string) *ical.Calendar {
	cal := event(uid)
	e := cal.Children[0]
	if rid == "" {
		e.Props.Set(&ical.Prop{Name: ical.PropRecurrenceRule, Value: "FREQ=WEEKLY;BYDAY=MO"})
		e.Props.Add(&ical.Prop{Name: "EXDATE", Value: "20260112T100000Z"})
		e.Props.Add(&ical.Prop{Name: "EXDATE", Value: "20260119T100000Z"})
	} else {
		e.Props.Set(&ical.Prop{Name: ical.PropRecurrenceID, Value: rid})
	}
	return cal
}

func httpFixture(t *testing.T, events map[string]*ical.Calendar) (*wdcaldav.Handler, map[string]string) {
	t.Helper()
	b := &backend{caches: map[string]*calendarCache{}}
	cc := fresh()
	cc.loaded, cc.loadedAt = true, time.Now()
	paths := map[string]string{}
	for id, d := range events {
		tok := objectToken(d, id)
		p := "/caldav/calendars/cal/" + tok + ".ics"
		cc.objects[id] = caldav.CalendarObject{Path: p, ETag: "E" + id, ModTime: time.Unix(1700000000, 0), Data: d}
		paths[id] = p
	}
	cc.byToken = buildTokenIndex(cc.objects)
	b.caches["cal"] = cc
	return &wdcaldav.Handler{Backend: b}, paths
}

func do(h http.Handler, method, path, depth, body string) (int, multistatus) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Depth", depth)
	req.Header.Set("Content-Type", "application/xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var ms multistatus
	xml.Unmarshal(rec.Body.Bytes(), &ms)
	return rec.Code, ms
}

// listQuery asks for every event's ETag the way a client lists a calendar: a calendar-query
// that reads the cached objects and addresses (the directory PROPFIND also calls Proton).
const listQuery = `<?xml version="1.0"?><C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/></C:comp-filter></C:filter></C:calendar-query>`

func multiget(hrefs ...string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/><C:calendar-data/></D:prop>`)
	for _, h := range hrefs {
		sb.WriteString("<D:href>" + h + "</D:href>")
	}
	sb.WriteString(`</C:calendar-multiget>`)
	return sb.String()
}

// Every address the listing hands out must serve back the same event with the same ETag,
// whichever way the client writes the address.
func TestEveryListedAddressServesTheSameEventAndETagBack(t *testing.T) {
	events := map[string]*ical.Calendar{
		"p1":  event("plain-uid"),
		"p2":  event("with@sign.proton.me"),
		"p3":  event("has space"),
		"p4":  event("percent%20sign"),
		"p5":  event("plus+sign"),
		"p6":  event("slash/inside"),
		"p7":  event("hash#and?query"),
		"p8":  event("日本語-uid"),
		"p9":  event(strings.Repeat("long", 80)),
		"r1":  recurring("series@proton.me", ""),
		"r2":  recurring("series@proton.me", "20260126T100000Z"),
		"r3":  recurring("series@proton.me", "20260202T100000Z"),
		"r4":  recurring("other series", ""),
		"r5":  recurring("other series", "20260126T100000Z"),
		"tz1": recurring("tz-series", "TZID=Europe/Budapest:20260126T100000"),
	}
	h, _ := httpFixture(t, events)

	code, listing := do(h, "REPORT", "/caldav/calendars/cal/", "1", listQuery)
	if code != http.StatusMultiStatus {
		t.Fatalf("listing: %d", code)
	}
	etags := map[string]string{}
	seen := map[string]bool{}
	for _, r := range listing.Responses {
		if strings.HasSuffix(r.Href, ".ics") {
			if seen[r.Href] {
				t.Errorf("the listing contains %q twice", r.Href)
			}
			seen[r.Href] = true
			for _, ps := range r.Propstat {
				if ps.Prop.ETag != "" {
					etags[r.Href] = ps.Prop.ETag
				}
			}
		}
	}
	if len(etags) != len(events) {
		t.Fatalf("the listing has %d events, the cache %d", len(etags), len(events))
	}

	encode := map[string]func(string) string{
		"as listed": func(h string) string { return h },
		"every segment percent-encoded": func(h string) string {
			parts := strings.Split(h, "/")
			for i, p := range parts {
				if dec, err := url.PathUnescape(p); err == nil {
					parts[i] = url.PathEscape(dec)
				}
			}
			return strings.Join(parts, "/")
		},
		"tilde as %7E": func(h string) string { return strings.ReplaceAll(h, "~", "%7E") },
	}
	for how, enc := range encode {
		for href, etag := range etags {
			_, ms := do(h, "REPORT", "/caldav/calendars/cal/", "1", multiget(xmlEscape(enc(href))))
			if len(ms.Responses) != 1 {
				t.Errorf("[%s] %s: %d responses", how, href, len(ms.Responses))
				continue
			}
			got := ms.Responses[0]
			ok := false
			for _, ps := range got.Propstat {
				if strings.Contains(ps.Status, "200") && ps.Prop.ETag == etag && strings.Contains(ps.Prop.Data, "BEGIN:VEVENT") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("[%s] %s: not served back with the listed ETag %q: %+v", how, href, etag, got.Propstat)
			}
		}
	}
}

func xmlEscape(s string) string {
	var sb strings.Builder
	xml.EscapeText(&sb, []byte(s))
	return sb.String()
}
