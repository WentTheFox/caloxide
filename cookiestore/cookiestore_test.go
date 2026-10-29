package cookiestore

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	api = &url.URL{Scheme: "https", Host: "mail.proton.me", Path: "/api/auth/info"}
	// The standard library's inner jar judges expiry by the real clock, so the test
	// clock has to start at (about) the real time.
	t0 = time.Now()
)

func newJar() *Jar {
	j := New(ProtonHosts)
	j.now = func() time.Time { return t0 }
	return j
}

func sessionID() *http.Cookie {
	// What the live API sent on 2026-10-29 (value redacted).
	return &http.Cookie{Name: "Session-Id", Value: "SECRET-session-value", Domain: "proton.me", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode, MaxAge: 7776000}
}

func valueFor(j *Jar, u *url.URL, name string) string {
	for _, c := range j.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestSessionIDSurvivesExportImport(t *testing.T) {
	a := newJar()
	a.SetCookies(api, []*http.Cookie{sessionID(), {Name: "Tag", Value: "tag-val", Path: "/", Secure: true, MaxAge: 7776000}})
	if valueFor(a, api, "Session-Id") != "SECRET-session-value" {
		t.Fatal("the jar does not hand the cookie back within one run")
	}

	data, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}

	b := newJar() // "after a restart"
	if err := b.Import(data); err != nil {
		t.Fatal(err)
	}
	if got := valueFor(b, api, "Session-Id"); got != "SECRET-session-value" {
		t.Errorf("Session-Id lost across a restart: %q", got)
	}
	if got := valueFor(b, &url.URL{Scheme: "https", Host: "account.proton.me", Path: "/"}, "Session-Id"); got != "SECRET-session-value" {
		t.Errorf("a Domain=proton.me cookie must apply to sibling hosts, got %q", got)
	}
	if got := valueFor(b, api, "Tag"); got != "tag-val" {
		t.Errorf("Tag lost: %q", got)
	}
}

func TestSessionCookiesAreNotPersisted(t *testing.T) {
	j := newJar()
	j.SetCookies(api, []*http.Cookie{{Name: "tmp", Value: "x", Path: "/"}})
	data, _ := j.Export()
	if strings.Contains(string(data), "tmp") {
		t.Errorf("a session cookie was exported: %s", data)
	}
	if valueFor(j, api, "tmp") != "x" {
		t.Error("session cookies must still work within the process")
	}
}

func TestExpiredAndDeletedCookiesAreDropped(t *testing.T) {
	j := newJar()
	j.SetCookies(api, []*http.Cookie{sessionID()})
	j.SetCookies(api, []*http.Cookie{{Name: "Session-Id", Domain: "proton.me", Path: "/", MaxAge: -1}})
	if data, _ := j.Export(); strings.Contains(string(data), "Session-Id") {
		t.Errorf("a cookie the server deleted was still exported: %s", data)
	}

	j.SetCookies(api, []*http.Cookie{{Name: "old", Value: "v", Path: "/", MaxAge: 10}})
	data, _ := j.Export()
	later := newJar()
	later.now = func() time.Time { return t0.Add(time.Hour) }
	if err := later.Import(data); err != nil {
		t.Fatal(err)
	}
	if valueFor(later, api, "old") != "" {
		t.Error("an expired cookie was imported")
	}
}

func TestOnlyProtonHostsArePersisted(t *testing.T) {
	j := newJar()
	other := &url.URL{Scheme: "https", Host: "tracker.example.net", Path: "/"}
	lookalike := &url.URL{Scheme: "https", Host: "evilproton.me", Path: "/"}
	j.SetCookies(other, []*http.Cookie{{Name: "t", Value: "1", Path: "/", MaxAge: 100}})
	j.SetCookies(lookalike, []*http.Cookie{{Name: "l", Value: "1", Path: "/", MaxAge: 100}})
	data, _ := j.Export()
	if string(data) != "[]" {
		t.Errorf("non-Proton cookies were exported: %s", data)
	}
	if !ProtonHosts("mail.proton.me") || !ProtonHosts("proton.me") || ProtonHosts("evilproton.me") || ProtonHosts("proton.me.evil.example") {
		t.Error("ProtonHosts is wrong")
	}

	// A tampered export cannot plant a cookie for another host.
	forged := `[{"Host":"tracker.example.net","Name":"x","Value":"y","Path":"/","Expires":"2999-01-01T00:00:00Z"}]`
	k := newJar()
	if err := k.Import([]byte(forged)); err != nil {
		t.Fatal(err)
	}
	if valueFor(k, other, "x") != "" {
		t.Error("an imported cookie for a non-Proton host was accepted")
	}
}

func TestImportRejectsGarbageWithoutLeaking(t *testing.T) {
	j := newJar()
	for _, bad := range []string{"not json", `{"a":1}`, strings.Repeat("A", maxBytes+1)} {
		err := j.Import([]byte(bad))
		if err == nil {
			t.Errorf("%.20q should be rejected", bad)
			continue
		}
		if strings.Contains(err.Error(), "not json") {
			t.Errorf("error echoes the input: %v", err)
		}
	}
	if err := j.Import(nil); err != nil {
		t.Errorf("empty input must not be an error: %v", err)
	}
	j.SetCookies(api, []*http.Cookie{sessionID()}) // still usable afterwards
	if valueFor(j, api, "Session-Id") == "" {
		t.Error("jar unusable after a failed import")
	}
}

func TestExportIsDeterministic(t *testing.T) {
	j := newJar()
	j.SetCookies(api, []*http.Cookie{sessionID(), {Name: "Tag", Value: "t", Path: "/", MaxAge: 100}, {Name: "A", Value: "a", Path: "/", MaxAge: 100}})
	a, _ := j.Export()
	b, _ := j.Export()
	if string(a) != string(b) {
		t.Error("Export order is not stable, which would rewrite auth.json needlessly")
	}
}

func TestImportCapsTheNumberOfCookies(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < maxCookies+20; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"Host":"mail.proton.me","Name":"c` + string(rune('A'+i%26)) + string(rune('a'+i/26)) + `","Value":"v","Path":"/","Expires":"2999-01-01T00:00:00Z"}`)
	}
	sb.WriteString("]")
	j := newJar()
	if err := j.Import([]byte(sb.String())); err != nil {
		t.Fatal(err)
	}
	data, _ := j.Export()
	if n := strings.Count(string(data), `"Name"`); n > maxCookies {
		t.Errorf("imported %d cookies, cap is %d", n, maxCookies)
	}
}

func TestNamesListsNamesOnly(t *testing.T) {
	j := newJar()
	j.SetCookies(api, []*http.Cookie{sessionID(), {Name: "Tag", Value: "tag-val", Path: "/", MaxAge: 100}, {Name: "tmp", Value: "x", Path: "/"}})
	got := strings.Join(j.Names(), ",")
	if got != "Session-Id,Tag" {
		t.Errorf("Names() = %q, want the persistent cookies only", got)
	}
	if strings.Contains(got, "SECRET") || strings.Contains(got, "tag-val") {
		t.Errorf("Names() leaked a value: %q", got)
	}
}
