package protonmail

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserAgentAndAppVersionAreSent(t *testing.T) {
	var ua, av string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, av = r.Header.Get("User-Agent"), r.Header.Get("X-Pm-Appversion")
		fmt.Fprint(w, `{"Code":1000,"User":{"Keys":[]}}`)
	}))
	defer srv.Close()

	c := &Client{RootURL: srv.URL, HTTPClient: srv.Client(), AppVersion: "external-calendar-caloxide@0.2.0-stable"}
	if _, err := c.GetCurrentUser(); err != nil {
		t.Fatal(err)
	}
	if ua != defaultUserAgent {
		t.Errorf("default User-Agent changed: %q", ua)
	}
	if av != "external-calendar-caloxide@0.2.0-stable" {
		t.Errorf("app version = %q", av)
	}

	c.UserAgent = "caloxide/0.2.0"
	if _, err := c.GetCurrentUser(); err != nil {
		t.Fatal(err)
	}
	if ua != "caloxide/0.2.0" {
		t.Errorf("custom User-Agent not sent: %q", ua)
	}
	if d := c.Detached(); d.UserAgent != "caloxide/0.2.0" || d.AppVersion != c.AppVersion {
		t.Errorf("Detached must carry the identification: %+v", d)
	}
}
