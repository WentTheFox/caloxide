package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/protonmail"
)

const solved = "SolvedCaptchaToken-0123456789abcdef-xyz"

type verifyEnv struct {
	m       *Manager
	api     *fakeAPI
	ck      *fakeClock
	pw      string // the bridge password
	adopted int
}

// newVerifyEnv builds a Manager whose only account has an open session that has just
// been stopped by a CAPTCHA, which is the state the web verification exists for.
func newVerifyEnv(t *testing.T) *verifyEnv {
	t.Helper()
	config.SetConfigHome(t.TempDir())
	var key [32]byte
	key[0] = 7
	e := &verifyEnv{pw: base64.StdEncoding.EncodeToString(key[:])}
	stored := withSeed(testSession()) // the record `protoxide auth` wrote: password and 2FA seed
	if err := EncryptAndSave(stored, "me", &key); err != nil {
		t.Fatal(err)
	}

	e.api = &fakeAPI{
		requireHV: true,
		hvDetails: &protonmail.HumanVerificationDetails{HumanVerificationMethods: []string{"captcha"}, HumanVerificationToken: "ProtonChallengeToken"},
		loginAuth: authWith(protonmail.PasswordSingle, 1, 1),
	}
	e.ck = &fakeClock{t: time.Now()}
	e.m = NewManager(func() *protonmail.Client { return &protonmail.Client{} })
	e.m.EnableRelogin()
	e.m.detach = func(*protonmail.Client) authAPI { return e.api }
	e.m.adopt = func(*protonmail.Client, authAPI) { e.adopted++ }
	e.m.now = e.ck.now
	e.m.rl.now, e.m.rl.sleep = e.ck.now, e.ck.sleep

	e.m.mu.Lock()
	_, err := e.m.openSession("me", e.pw)
	e.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e.m.rl.latchHumanVerification("me")
	return e
}

func (e *verifyEnv) openWindow(t *testing.T) string {
	t.Helper()
	tok, _, err := e.m.OpenVerificationWindow()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestWindowOnlyOpensWhileACaptchaIsPending(t *testing.T) {
	e := newVerifyEnv(t)
	if _, _, err := e.m.OpenVerificationWindow(); err != nil {
		t.Fatalf("a pending CAPTCHA must allow a window: %v", err)
	}

	e.m.rl.markSuccess() // the bridge is healthy again
	if _, _, err := e.m.OpenVerificationWindow(); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("a healthy bridge must refuse a window, got %v", err)
	}

	plain := NewManager(func() *protonmail.Client { return &protonmail.Client{} })
	if _, _, err := plain.OpenVerificationWindow(); !errors.Is(err, ErrReloginDisabled) {
		t.Errorf("without unattended re-login: %v", err)
	}
}

func TestWindowTokenIsRequiredAndExpires(t *testing.T) {
	e := newVerifyEnv(t)
	tok := e.openWindow(t)

	if len(tok) < 40 {
		t.Errorf("token too short to be 256 bits: %d chars", len(tok))
	}
	for _, bad := range []string{"", "x", tok + "x", tok[:len(tok)-1], strings.ToUpper(tok)} {
		if e.m.VerificationWindowOpen(bad) {
			t.Errorf("token %q must not open the window", bad)
		}
		if _, err := e.m.BeginVerification(bad); !errors.Is(err, ErrNoWindow) {
			t.Errorf("Begin with token %q: %v", bad, err)
		}
		if err := e.m.CompleteVerification(bad, "n", solved); !errors.Is(err, ErrNoWindow) {
			t.Errorf("Complete with token %q: %v", bad, err)
		}
	}
	if !e.m.VerificationWindowOpen(tok) {
		t.Fatal("the right token must open the window")
	}

	e.ck.t = e.ck.t.Add(windowTTL + time.Second)
	if e.m.VerificationWindowOpen(tok) {
		t.Error("the window must expire")
	}
	if _, err := e.m.BeginVerification(tok); !errors.Is(err, ErrNoWindow) {
		t.Errorf("an expired window must not start a login: %v", err)
	}
	if e.api.authCalls != 0 {
		t.Error("nothing may reach Proton without a live window")
	}
}

func TestWebVerificationEndToEnd(t *testing.T) {
	e := newVerifyEnv(t)
	tok := e.openWindow(t)

	ch, err := e.m.BeginVerification(tok)
	if err != nil || ch.Done || ch.Token != "ProtonChallengeToken" || ch.Nonce == "" {
		t.Fatalf("Begin: %+v, %v", ch, err)
	}

	// A wrong nonce, or a paste with no token in it, is refused but does not burn the
	// challenge: a stray request or a typo must not force a fresh login.
	if err := e.m.CompleteVerification(tok, "wrong", solved); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("wrong nonce: %v", err)
	}
	if err := e.m.CompleteVerification(tok, ch.Nonce, "oops, nothing useful"); !errors.Is(err, ErrNoToken) {
		t.Fatalf("garbage paste: %v", err)
	}
	if e.api.authCalls != 1 {
		t.Fatalf("a bad paste must not reach Proton (logins so far: %d)", e.api.authCalls)
	}

	pasted := `HV {"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"` + solved + `","type":"captcha"}}`
	if err := e.m.CompleteVerification(tok, ch.Nonce, pasted); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if e.api.hvTokenUsed != solved {
		t.Errorf("the login did not carry the solved token: %q", e.api.hvTokenUsed)
	}
	if e.api.hvToken != "" {
		t.Error("the one-shot token must be cleared after use")
	}
	if len(e.api.totpCodes) != 1 {
		t.Errorf("the 2FA challenge must be answered from the stored seed: %v", e.api.totpCodes)
	}
	if err := e.m.rl.blocked(); err != nil {
		t.Errorf("the CAPTCHA latch must be cleared: %v", err)
	}
	if e.m.VerificationWindowOpen(tok) {
		t.Error("the window must close once it has been used")
	}
	if err := e.m.CompleteVerification(tok, ch.Nonce, pasted); !errors.Is(err, ErrNoWindow) {
		t.Errorf("a used window must not accept a second submission: %v", err)
	}
	if e.adopted != 1 {
		t.Errorf("the new session was adopted %d times, want 1", e.adopted)
	}

	// The refreshed tokens reached disk, and the file stays encrypted: the password and
	// the 2FA seed are in the record (that is how the next re-login finds them) but
	// readable only with the bridge password.
	var key [32]byte
	key[0] = 7
	auths, _ := readCachedAuths()
	if strings.Contains(auths["me"], testLogin) || strings.Contains(auths["me"], testSeed) {
		t.Error("auth.json holds the password or the 2FA seed in the clear")
	}
	plain, err := decrypt(auths["me"], &key)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rt2", testLogin, testSeed} {
		if !strings.Contains(string(plain), want) {
			t.Errorf("the stored record lost %q: %s", want, plain)
		}
	}

	// And the next CalDAV request needs no further login.
	before := *e.api
	if _, _, err := e.m.Auth("me", e.pw); err != nil {
		t.Fatalf("Auth after web verification: %v", err)
	}
	if e.api.authCalls != before.authCalls || e.api.refreshCalls != before.refreshCalls {
		t.Error("a verified session must not log in again")
	}
}

func TestBeginIsLimitedPerWindow(t *testing.T) {
	e := newVerifyEnv(t)
	tok := e.openWindow(t)
	for i := 0; i < maxBegins; i++ {
		if _, err := e.m.BeginVerification(tok); err != nil {
			t.Fatalf("begin %d: %v", i+1, err)
		}
	}
	if _, err := e.m.BeginVerification(tok); !errors.Is(err, ErrNoWindow) {
		t.Errorf("a window must not allow unlimited login attempts, got %v", err)
	}
	if e.api.authCalls != maxBegins {
		t.Errorf("Proton saw %d logins, want %d", e.api.authCalls, maxBegins)
	}
}

func TestProtonRejectingTheTokenKeepsTheLatch(t *testing.T) {
	e := newVerifyEnv(t)
	tok := e.openWindow(t)
	ch, _ := e.m.BeginVerification(tok)
	e.api.rejectHV = true
	if err := e.m.CompleteVerification(tok, ch.Nonce, solved); !errors.Is(err, ErrVerificationRejected) {
		t.Fatalf("want ErrVerificationRejected, got %v", err)
	}
	if err := e.m.CompleteVerification(tok, ch.Nonce, solved); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("a challenge submitted to Proton is spent, got %v", err)
	}
	var hv *HumanVerificationError
	if !errors.As(e.m.rl.blocked(), &hv) {
		t.Error("a rejected token must leave the bridge waiting for a human")
	}
	if e.api.hvToken != "" {
		t.Error("a rejected token must not stay attached to the client")
	}
}

func TestBeginWithoutCaptchaJustLogsIn(t *testing.T) {
	e := newVerifyEnv(t)
	e.api.requireHV = false // Proton does not challenge this time
	tok := e.openWindow(t)
	ch, err := e.m.BeginVerification(tok)
	if err != nil || !ch.Done {
		t.Fatalf("want Done, got %+v, %v", ch, err)
	}
	if e.m.rl.blocked() != nil || e.m.VerificationWindowOpen(tok) {
		t.Error("a login that needed no CAPTCHA must clear the latch and close the window")
	}
}

func TestWhileLatchedAuthFailsFastWithoutNetwork(t *testing.T) {
	e := newVerifyEnv(t)
	before := *e.api
	_, _, err := e.m.Auth("me", e.pw)
	var hv *HumanVerificationError
	if !errors.As(err, &hv) {
		t.Fatalf("want the CAPTCHA error, got %v", err)
	}
	if e.api.refreshCalls != before.refreshCalls || e.api.authCalls != before.authCalls {
		t.Error("a latched bridge must not contact Proton")
	}
	if _, _, err := e.m.Auth("me", "d3Jvbmc="); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("a wrong bridge password must still be refused: %v", err)
	}
}

// Real CAPTCHA responses are long: the message is "<challenge id>:<response>".
func TestParseVerificationInputAcceptsRealisticLongTokens(t *testing.T) {
	long := "ChallengeId1234:P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + strings.Repeat("aB3-_x", 500) // ~3000 chars
	for name, in := range map[string]string{
		"bare":         long,
		"console line": `HV {"type":"pm_captcha","token":"` + long + `"}`,
		"wrapped":      `HV {"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"` + long + `","type":"captcha"}}`,
	} {
		got, err := ParseVerificationInput(in)
		if err != nil || got != long {
			t.Errorf("%s: a %d-char token was rejected or altered (err %v)", name, len(long), err)
		}
	}
	if _, err := ParseVerificationInput(strings.Repeat("A", maxTokenLen+1)); err == nil {
		t.Error("a token over the length cap must still be rejected")
	}
}

func TestParseVerificationInput(t *testing.T) {
	good := map[string]string{
		"bare":             solved,
		"quoted":           `"` + solved + `"`,
		"with spaces":      "  \n" + solved + "\n ",
		"HV label":         "HV " + solved,
		"console line":     `HV {"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"` + solved + `","type":"captcha"}}`,
		"bare json":        `{"payload":{"token":"` + solved + `"}}`,
		"flat json":        `{"token":"` + solved + `"}`,
		"data json":        `{"data":{"token":"` + solved + `"}}`,
		"line with prefix": `VM123:1 HV {"payload":{"token":"` + solved + `"}}`,
		"trailing garbage": `HV {"payload":{"token":"` + solved + `"}} (anonymous) @ VM123`,
	}
	for name, in := range good {
		got, err := ParseVerificationInput(in)
		if err != nil || got != solved {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
	bad := []string{"", "   ", "short", `{"payload":{}}`, `{"payload":{"token":"tiny"}}`, "{not json", `HV {"x":1}`,
		"has spaces inside the thing that is long enough", strings.Repeat("A", maxVerificationInput+1)}
	for _, in := range bad {
		got, err := ParseVerificationInput(in)
		if err == nil {
			t.Errorf("%.30q should be rejected, got token %q", in, got)
			continue
		}
		if strings.Contains(err.Error(), "short") || strings.Contains(err.Error(), "spaces") {
			t.Errorf("error echoes the input: %v", err)
		}
	}
}

// Proton's CAPTCHA sends two messages and the console logs both; only pm_captcha is
// what the login wants. Shapes below are the ones seen on the real CAPTCHA.
func TestParseVerificationInputPicksThePmCaptchaMessage(t *testing.T) {
	hex64 := strings.Repeat("ab12cd34", 8)
	first := `HV {"type":"proton_captcha","token":"` + hex64 + `","protoncaptcha":true} debugger eval code:1:68`
	second := `HV {"type":"pm_captcha","token":"` + solved + `"} debugger eval code:1:68`

	for name, in := range map[string]string{
		"both lines":           first + "\n" + second,
		"both lines, reversed": second + "\n" + first,
		"both, odd whitespace": "\n\n" + first + "\r\n\r\n" + second + "\n",
		"only the second":      second,
		"two on one line":      first + " " + second,
	} {
		got, err := ParseVerificationInput(in)
		if err != nil || got != solved {
			t.Errorf("%s: got %q, %v; want the pm_captcha token", name, got, err)
		}
	}

	if got, err := ParseVerificationInput(first); !errors.Is(err, ErrWrongMessage) || got != "" {
		t.Errorf("a lone proton_captcha line must be refused with an explanation, got %q, %v", got, err)
	}
	if strings.Contains(ErrWrongMessage.Error(), hex64) {
		t.Error("the error must not echo any token")
	}
	// A proton_captcha line alongside a wrapped success message still finds a token.
	wrapped := `HV {"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"` + solved + `","type":"captcha"}}`
	if got, err := ParseVerificationInput(first + "\n" + wrapped); err != nil || got != solved {
		t.Errorf("proton_captcha + wrapped success: got %q, %v", got, err)
	}
}
