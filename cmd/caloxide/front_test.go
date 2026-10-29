package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserProbeGets404NotAChallenge(t *testing.T) {
	cases := []struct {
		method, path string
		creds        bool
		probe        bool
	}{
		{"GET", "/", false, true},
		{"HEAD", "/", false, true},
		{"GET", "/favicon.ico", false, true},
		{"GET", "/index.html", false, true},
		// CalDAV clients: other methods, or the CalDAV paths, keep the challenge.
		{"PROPFIND", "/", false, false},
		{"OPTIONS", "/", false, false},
		{"REPORT", "/", false, false},
		{"GET", "/caldav", false, false},
		{"GET", "/caldav/", false, false},
		{"GET", "/caldav/calendars/abc/", false, false},
		{"GET", "/.well-known/caldav", false, false},
		// With credentials the request is a client, never a stray browser visit.
		{"GET", "/", true, false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.creds {
			req.SetBasicAuth("a@b.c", "pw")
		}
		if got := isBrowserProbe(req); got != c.probe {
			t.Errorf("%s %s creds=%v: probe=%v, want %v", c.method, c.path, c.creds, got, c.probe)
		}
	}
}

func TestBrowserProbeResponseHasNoChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	if !isBrowserProbe(req) {
		t.Fatal("setup: not a probe")
	}
	http.NotFound(rec, req)
	if rec.Code != 404 || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("got %d with challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
