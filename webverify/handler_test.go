package webverify

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mathewcsims/protoxide/auth"
)

const goodToken = "GoodWindowToken-0123456789-abcdefghijklmnopqrstuvwxyz"

type fakeVerifier struct {
	open      string // the token that opens the window
	begins    int
	completes int
	challenge *auth.Challenge
	beginErr  error
	doneErr   error

	gotNonce, gotInput string
}

func (f *fakeVerifier) VerificationWindowOpen(t string) bool { return t == f.open && f.open != "" }
func (f *fakeVerifier) BeginVerification(string) (*auth.Challenge, error) {
	f.begins++
	return f.challenge, f.beginErr
}
func (f *fakeVerifier) CompleteVerification(_, nonce, input string) error {
	f.completes++
	f.gotNonce, f.gotInput = nonce, input
	return f.doneErr
}

func newFake() *fakeVerifier {
	return &fakeVerifier{open: goodToken, challenge: &auth.Challenge{Token: "ProtonChallenge", Nonce: "nonce-123"}}
}

func do(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEveryWrongRequestIsTheSame404(t *testing.T) {
	f := newFake()
	h := Handler(f)
	want := do(h, "GET", "/nothing-here", "")
	for _, target := range []string{
		"/verify/", "/verify", "/verify/wrong", "/verify/" + goodToken + "x", "/verify/" + goodToken[:20],
		"/verify/" + goodToken + "/extra", "/verify/../" + goodToken, "/verify//" + goodToken, "/other/" + goodToken, "/",
	} {
		for _, method := range []string{"GET", "POST", "PUT"} {
			rec := do(h, method, target, "input=x")
			if rec.Code != 404 {
				t.Errorf("%s %s: status %d, want 404", method, target, rec.Code)
				continue
			}
			if rec.Body.String() != want.Body.String() || rec.Header().Get("Content-Security-Policy") != "" {
				t.Errorf("%s %s: the 404 differs from an ordinary one, which would reveal the route", method, target)
			}
		}
	}
	if f.begins != 0 || f.completes != 0 {
		t.Errorf("a request without the token reached the login logic (begin %d, complete %d)", f.begins, f.completes)
	}
}

func TestChallengePageHeadersAndContent(t *testing.T) {
	f := newFake()
	rec := do(Handler(f), "GET", PathPrefix+goodToken, "")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	for _, need := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'self'", "base-uri 'none'", "script-src 'nonce-"} {
		if !strings.Contains(csp, need) {
			t.Errorf("CSP lacks %q: %s", need, csp)
		}
	}
	if h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing security headers: %v", h)
	}
	body := rec.Body.String()
	for _, need := range []string{`name="nonce" value="nonce-123"`, "verify-api.proton.me/core/v4/captcha", "Token=ProtonChallenge", "HV", "ForceWebMessaging=1"} {
		if !strings.Contains(body, need) {
			t.Errorf("page lacks %q", need)
		}
	}
	if strings.Contains(body, goodToken) {
		t.Error("the one-time URL token must not be echoed into the page")
	}
	// Every inline script/style carries the per-response nonce, so the CSP can block the rest.
	nonce := strings.TrimSuffix(strings.SplitN(strings.SplitN(csp, "script-src 'nonce-", 2)[1], "'", 2)[0], "")
	if !strings.Contains(body, `<script nonce="`+nonce+`">`) || !strings.Contains(body, `<style nonce="`+nonce+`">`) {
		t.Error("inline script/style do not carry the CSP nonce")
	}
	if f.begins != 1 {
		t.Errorf("one page load must start exactly one login, got %d", f.begins)
	}
}

func TestHostileChallengeDataCannotInjectScript(t *testing.T) {
	f := newFake()
	f.challenge = &auth.Challenge{Token: `x"</script><script>alert(1)</script>`, Nonce: `"><img src=x onerror=alert(2)>`}
	body := do(Handler(f), "GET", PathPrefix+goodToken, "").Body.String()
	// Dangerous means an unescaped quote or angle bracket from the attacker's data.
	for _, bad := range []string{"<script>alert(1)", "<img src=x", `"><img`, `</script><script>`} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped hostile data in the page: %q", bad)
		}
	}
	// The nonce lands in an attribute, where it must be HTML-escaped (inert text).
	if !strings.Contains(body, "&lt;img src=x onerror=alert(2)&gt;") {
		t.Error("the hostile nonce was not HTML-escaped inside the attribute")
	}
	// The popup URL carries the token percent-encoded.
	if !strings.Contains(body, "Token=x%22%3C%2Fscript%3E") && !strings.Contains(body, `Token=x"`) && !strings.Contains(body, "Token=x%22") {
		t.Errorf("the challenge token is not URL-encoded in the popup URL")
	}
}

func TestSubmitPaths(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		inBody string
	}{
		{"success", nil, 200, "logged in again"},
		{"bad paste", auth.ErrNoToken, 400, "Back button"},
		{"wrong message", auth.ErrWrongMessage, 400, "pm_captcha"},
		{"expired challenge", auth.ErrChallengeExpired, 400, "Reload this page"},
		{"rejected by Proton", auth.ErrVerificationRejected, 400, "Reload this page"},
		{"window gone", auth.ErrNoWindow, 404, "404"},
		{"other failure", errors.New("login failed: boom"), 502, "boom"},
	}
	for _, c := range cases {
		f := newFake()
		f.doneErr = c.err
		form := url.Values{"nonce": {"nonce-123"}, "input": {"HV {\"payload\":{\"token\":\"abc\"}}"}}.Encode()
		rec := do(Handler(f), "POST", PathPrefix+goodToken, form)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.inBody) {
			t.Errorf("%s: status %d body %q, want %d containing %q", c.name, rec.Code, rec.Body, c.status, c.inBody)
		}
		if f.gotNonce != "nonce-123" || !strings.Contains(f.gotInput, "abc") {
			t.Errorf("%s: the form fields did not reach the logic: %q %q", c.name, f.gotNonce, f.gotInput)
		}
		if f.begins != 0 {
			t.Errorf("%s: a POST must not start a new login", c.name)
		}
	}
}

func TestNothingToVerifyAndDoneAndErrors(t *testing.T) {
	f := newFake()
	f.beginErr = auth.ErrNotWaiting
	if rec := do(Handler(f), "GET", PathPrefix+goodToken, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "not waiting") {
		t.Errorf("not waiting: %d %s", rec.Code, rec.Body)
	}
	f = newFake()
	f.challenge = &auth.Challenge{Done: true}
	if rec := do(Handler(f), "GET", PathPrefix+goodToken, ""); !strings.Contains(rec.Body.String(), "did not ask for a CAPTCHA") {
		t.Errorf("done: %s", rec.Body)
	}
	f = newFake()
	f.challenge, f.beginErr = nil, errors.New("reading secrets: down")
	if rec := do(Handler(f), "GET", PathPrefix+goodToken, ""); rec.Code != 502 || !strings.Contains(rec.Body.String(), "reading secrets") {
		t.Errorf("error: %d %s", rec.Code, rec.Body)
	}
	f = newFake()
	f.beginErr = auth.ErrNoWindow // e.g. too many page loads
	if rec := do(Handler(f), "GET", PathPrefix+goodToken, ""); rec.Code != 404 {
		t.Errorf("begin limit: %d", rec.Code)
	}
}

func TestMethodsAndBodyLimit(t *testing.T) {
	f := newFake()
	h := Handler(f)
	if rec := do(h, "PUT", PathPrefix+goodToken, ""); rec.Code != 405 || rec.Header().Get("Allow") == "" {
		t.Errorf("PUT: %d", rec.Code)
	}
	big := "input=" + strings.Repeat("A", maxFormBytes+10)
	rec := do(h, "POST", PathPrefix+goodToken, big)
	if rec.Code != http.StatusRequestEntityTooLarge || f.completes != 0 {
		t.Errorf("oversized body: status %d, completes %d", rec.Code, f.completes)
	}
	_ = io.Discard
}

// The relay is what saves copying the result by hand, and it is also an input channel
// into the page, so its checks are pinned: the message must come from the popup this
// page opened and from Proton's CAPTCHA origin.
func TestRelayListenerOnlyTrustsThePopupItOpened(t *testing.T) {
	body := do(Handler(newFake()), "GET", PathPrefix+goodToken, "").Body.String()
	for _, need := range []string{
		"e.source !== popup",
		"e.origin !== 'https://verify-api.proton.me'",
		"typeof d.pxHV !== 'string'",
		"window.opener.postMessage({pxHV:d.token}",
		"JSON.stringify(location.origin)", // the relay names this page's origin, never '*'
		"pm_captcha",
	} {
		if !strings.Contains(body, need) {
			t.Errorf("page lacks %q", need)
		}
	}
	if strings.Contains(body, "noopener") {
		t.Error("the popup must keep window.opener or the relay cannot work")
	}
	if strings.Contains(body, `postMessage({pxHV:d.token},"*")`) || strings.Contains(body, "postMessage({pxHV:d.token},'*')") {
		t.Error("the relay must not broadcast the token to any origin")
	}
}

// The popup is closed once the CAPTCHA is solved, by the page that opened it: on the
// relayed token, and on a pasted pm_captcha line (not the other line the popup logs).
func TestPopupClosesWhenTheCaptchaIsPassed(t *testing.T) {
	body := do(Handler(newFake()), "GET", PathPrefix+goodToken, "").Body.String()
	for _, need := range []string{
		"function closePopup()",
		"popup.close()",
		"this.value.indexOf('pm_captcha') !== -1",
		"CAPTCHA passed, popup closed",
	} {
		if !strings.Contains(body, need) {
			t.Errorf("page lacks %q", need)
		}
	}
}

func TestPagesFollowTheBrowsersColourScheme(t *testing.T) {
	f := newFake()
	pages := map[string]string{
		"challenge": do(Handler(f), "GET", PathPrefix+goodToken, "").Body.String(),
	}
	f2 := newFake()
	f2.beginErr = auth.ErrNotWaiting
	pages["message"] = do(Handler(f2), "GET", PathPrefix+goodToken, "").Body.String()

	for name, body := range pages {
		for _, need := range []string{
			`<meta name="color-scheme" content="light dark">`,
			"color-scheme:light dark",
			"@media (prefers-color-scheme:dark)",
			"var(--bg)", "var(--fg)",
		} {
			if !strings.Contains(body, need) {
				t.Errorf("%s page lacks %q", name, need)
			}
		}
	}
	// Dark mode must not need script (a CSP-blocked script would leave a white page),
	// and the popup's theme is chosen from the browser, not hard-coded.
	body := pages["challenge"]
	if strings.Contains(body, "Dark=true\"") || strings.Contains(popupURL("t"), "Dark=") {
		t.Error("the popup URL must not hard-code a theme")
	}
	if !strings.Contains(body, "matchMedia('(prefers-color-scheme: dark)')") || !strings.Contains(body, "'&Dark=true'") {
		t.Error("the popup theme must follow the browser's colour scheme")
	}
}
