package protonmail

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactBodyBlanksSecretsAndLongStrings(t *testing.T) {
	long := strings.Repeat("A", 500)
	body := fmt.Sprintf(`{"Code":1000,"AccessToken":"tok123","RefreshToken":"ref456","UID":"uid789","Error":"short message","Card":"%s","Nested":{"ServerProof":"proof"}}`, long)
	got := redactBody([]byte(body))
	for _, leak := range []string{"tok123", "ref456", "uid789", "proof", long[:100]} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked: %s", leak, got)
		}
	}
	for _, keep := range []string{`"Code":1000`, "short message", "[500 chars]", `"AccessToken":"[redacted]"`} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q: %s", keep, got)
		}
	}
}

func TestRedactBodyTruncatesNonJSON(t *testing.T) {
	got := redactBody([]byte("<html>" + strings.Repeat("x", 10000)))
	if !strings.HasPrefix(got, "<html>") || len(got) > diagBodyMax+40 || !strings.Contains(got, "more bytes") {
		t.Fatalf("len=%d %q", len(got), got[len(got)-40:])
	}
}

func TestRedactedHeadersHideCredentials(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "Session-Id=abc")
	h.Add("Set-Cookie", "Tag=def")
	h.Set("Authorization", "Bearer x")
	h.Set("X-Pm-Uid", "uid")
	h.Set("Retry-After", "30")
	h.Set("Content-Type", "text/html")
	got := redactedHeaders(h)
	for _, leak := range []string{"abc", "def", "Bearer", "=uid"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked: %s", leak, got)
		}
	}
	if !strings.Contains(got, "Retry-After=30") || !strings.Contains(got, "Content-Type=text/html") {
		t.Errorf("useful headers lost: %s", got)
	}
}

func serve(t *testing.T, h http.HandlerFunc) *Client {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	freshGate(srv.URL)
	c := &Client{RootURL: srv.URL, AppVersion: "Other"}
	c.SetSession("u", "t")
	return c
}

func TestUnexpectedResponsesAreLoggedWithStatusHeadersAndBody(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   []string
	}{
		{"gateway error", 502, "<html>Bad gateway</html>", []string{`why="server error"`, "status=502", "Bad gateway", "X-Edge=pop1"}},
		{"forbidden", 403, `{"Code":2011,"Error":"Not allowed"}`, []string{`why="unexpected status"`, "status=403", "Not allowed"}},
		{"redirect", 302, "", []string{`why="redirect"`, "status=302"}},
		{"garbage", 200, "not json at all", []string{`why="undecodable body"`, "status=200", "not json at all"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)
			c := serve(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Edge", "pop1")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			c.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			c.ListCalendars()
			for _, w := range tc.want {
				if !strings.Contains(logs.String(), w) {
					t.Errorf("log lacks %q:\n%s", w, logs.String())
				}
			}
		})
	}
}

func TestExpectedResponsesAreNotLoggedAsUnexpected(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{200, `{"Code":1000,"Calendars":[]}`},
		{422, `{"Code":8002,"Error":"Incorrect login credentials"}`},
		{422, `{"Code":9001,"Error":"Human verification required","Details":{}}`},
	} {
		logs := captureLog(t)
		c := serve(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		})
		c.ListCalendars()
		if strings.Contains(logs.String(), "unexpected response") {
			t.Errorf("status %d was logged as unexpected:\n%s", tc.status, logs.String())
		}
	}
}

func TestQueryStringNeverReachesTheLog(t *testing.T) {
	logs := captureLog(t)
	c := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	c.ListCalendarEvents("cal", &CalendarEventFilter{Timezone: "Secret/Zone", PageSize: 5})
	if strings.Contains(logs.String(), "Secret") || strings.Contains(logs.String(), "PageSize") {
		t.Fatalf("query leaked:\n%s", logs.String())
	}
}
