package caldav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wdcaldav "github.com/emersion/go-webdav/caldav"
)

// ctagBackend is the smallest backend the vendored CalDAV handler needs to answer a
// PROPFIND for calendars. The interface is embedded so anything else would panic loudly.
type ctagBackend struct {
	wdcaldav.Backend
	ctag string
}

func (b ctagBackend) CurrentUserPrincipal(context.Context) (string, error) {
	return "/caldav/", nil
}
func (b ctagBackend) CalendarHomeSetPath(context.Context) (string, error) {
	return "/caldav/calendars/", nil
}
func (b ctagBackend) cal() wdcaldav.Calendar {
	return wdcaldav.Calendar{Path: "/caldav/calendars/cal1/", Name: "Test", CTag: b.ctag}
}
func (b ctagBackend) ListCalendars(context.Context) ([]wdcaldav.Calendar, error) {
	return []wdcaldav.Calendar{b.cal()}, nil
}
func (b ctagBackend) GetCalendar(context.Context, string) (*wdcaldav.Calendar, error) {
	c := b.cal()
	return &c, nil
}

func propfind(t *testing.T, b wdcaldav.Backend, path, depth, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("PROPFIND", path, strings.NewReader(body))
	req.Header.Set("Depth", depth)
	req.Header.Set("Content-Type", "application/xml")
	rec := httptest.NewRecorder()
	(&wdcaldav.Handler{Backend: b}).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

const ctagQuery = `<?xml version="1.0"?>
<propfind xmlns="DAV:" xmlns:cs="http://calendarserver.org/ns/">
  <prop><cs:getctag/><displayname/><resourcetype/></prop>
</propfind>`

// The CTag is the whole reason go-webdav is vendored and patched: clients such as
// Thunderbird use it to see that something changed without listing every event.
func TestVendoredHandlerAdvertisesTheCTag(t *testing.T) {
	for _, tc := range []struct{ name, path, depth string }{
		{"the calendar itself", "/caldav/calendars/cal1/", "0"},
		{"listed from the calendar home", "/caldav/calendars/", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := propfind(t, ctagBackend{ctag: "tok-42"}, tc.path, tc.depth, ctagQuery)
			if code != http.StatusMultiStatus {
				t.Fatalf("status %d: %s", code, body)
			}
			for _, want := range []string{"getctag", "tok-42", "http://calendarserver.org/ns/", ">Test</displayname>"} {
				if !strings.Contains(body, want) {
					t.Errorf("response lacks %q:\n%s", want, body)
				}
			}
		})
	}
}

func TestCTagIsOmittedWhenThereIsNone(t *testing.T) {
	code, body := propfind(t, ctagBackend{}, "/caldav/calendars/cal1/", "0", ctagQuery)
	if code != http.StatusMultiStatus {
		t.Fatalf("status %d", code)
	}
	if strings.Contains(body, "tok-") || !strings.Contains(body, "404") {
		t.Errorf("an empty CTag must be reported as not found:\n%s", body)
	}
}
