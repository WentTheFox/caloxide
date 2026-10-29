package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/mathewcsims/protoxide/credstore"
	"github.com/mathewcsims/protoxide/notify"
	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/totp"
)

const (
	testLogin   = "LOGIN-pw-xyz"
	testMailbox = "MAILBOX-pw-xyz"
	testSeed    = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 test seed
)

type fakeProvider struct {
	sec   credstore.Secrets
	err   error
	calls int
}

func (p *fakeProvider) Get(context.Context) (credstore.Secrets, error) {
	p.calls++
	return p.sec, p.err
}

// fakeClock is advanced by sleep, so TOTP step handling can be tested instantly.
type fakeClock struct {
	t     time.Time
	slept []time.Duration
}

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(d time.Duration) {
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
}

type fakeAPI struct {
	storedValid  bool // if false, Unlock rejects the stored ("old") access token
	sessionUID   string
	sessionToken string
	refreshErr   error
	loginAuth    func() *protonmail.Auth // returned by Auth when authErr is nil
	authErr      error
	totpErr      error

	refreshCalls, infoCalls, unlockCalls int

	authCalls  int
	passwords  []string
	totpCodes  []string
	unlockPass []string
}

// SetSession records what the client would send as credentials, so the fake can
// behave like Proton's anonymous endpoints (see AuthInfo).
func (f *fakeAPI) SetSession(uid, token string) { f.sessionUID, f.sessionToken = uid, token }
func (f *fakeAPI) Unlock(a *protonmail.Auth, _ map[string][]byte, pass string) (openpgp.EntityList, error) {
	f.unlockCalls++
	f.unlockPass = append(f.unlockPass, pass)
	if a.AccessToken == "old" && !f.storedValid {
		return nil, &protonmail.APIError{Code: 401, Message: "access token expired"}
	}
	return openpgp.EntityList{}, nil
}
func (f *fakeAPI) AuthRefresh(*protonmail.Auth) (*protonmail.Auth, error) {
	f.refreshCalls++
	return nil, f.refreshErr
}

// AuthInfo and Auth are anonymous in Proton's API: a request that still carries an
// access token (even a dead one) is rejected with 401 "Invalid access token". That
// is exactly what broke the first real run, so the fake enforces it.
func (f *fakeAPI) AuthInfo(string) (*protonmail.AuthInfo, error) {
	f.infoCalls++
	if f.sessionToken != "" || f.sessionUID != "" {
		return nil, &protonmail.APIError{Code: 401, Message: "Invalid access token"}
	}
	return &protonmail.AuthInfo{}, nil
}
func (f *fakeAPI) Auth(_, password string, _ *protonmail.AuthInfo) (*protonmail.Auth, error) {
	f.authCalls++
	if f.sessionToken != "" || f.sessionUID != "" {
		return nil, &protonmail.APIError{Code: 401, Message: "Invalid access token"}
	}
	f.passwords = append(f.passwords, password)
	if f.authErr != nil {
		return nil, f.authErr
	}
	return f.loginAuth(), nil
}
func (f *fakeAPI) AuthTOTP(code string) (string, error) {
	f.totpCodes = append(f.totpCodes, code)
	return "full", f.totpErr
}

func deadRefresh() error { return &protonmail.APIError{Code: 10013, Message: "invalid refresh token"} }

func authWith(mode protonmail.PasswordMode, twoFA, totpMethod int) func() *protonmail.Auth {
	return func() *protonmail.Auth {
		a := &protonmail.Auth{UID: "u2", AccessToken: "at2", RefreshToken: "rt2", PasswordMode: mode}
		a.TwoFactor.Enabled, a.TwoFactor.TOTP = twoFA, totpMethod
		return a
	}
}

func newTest(p *fakeProvider) (*reloginer, *fakeClock) {
	ck := &fakeClock{t: time.Unix(1_700_000_010, 0)}
	r := newReloginer(p)
	r.now, r.sleep = ck.now, ck.sleep
	return r, ck
}

func testSession() *CachedAuth {
	return &CachedAuth{Auth: protonmail.Auth{UID: "u", AccessToken: "old", RefreshToken: "r", PasswordMode: protonmail.PasswordSingle}}
}

func TestReloginWithTOTPSucceeds(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin, TOTPSecret: testSeed}}
	r, ck := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	cached := testSession()
	want, _ := totp.Code(testSeed, ck.t)

	keys, err := authenticate(api, cached, "me", r)
	if err != nil || keys == nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(api.totpCodes) != 1 || api.totpCodes[0] != want {
		t.Errorf("TOTP codes sent = %v, want [%s]", api.totpCodes, want)
	}
	if len(api.passwords) != 1 || api.passwords[0] != testLogin {
		t.Errorf("login password sent = %v", api.passwords)
	}
	if got := api.unlockPass[len(api.unlockPass)-1]; got != testLogin {
		t.Errorf("single-password account must unlock with the login password, got %q", got)
	}
	if cached.Auth.RefreshToken != "rt2" || cached.Auth.Scope != "full" {
		t.Errorf("session not updated: %+v", cached.Auth)
	}
	if len(r.attempts) != 0 {
		t.Error("a successful login must reset the breaker")
	}
}

func TestTwoPasswordAccountNeedsMailboxPassword(t *testing.T) {
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordTwo, 0, 0)}

	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin, MailboxPassword: testMailbox}}
	r, _ := newTest(p)
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatal(err)
	}
	if got := api.unlockPass[len(api.unlockPass)-1]; got != testMailbox {
		t.Errorf("unlock used %q, want the mailbox password", got)
	}

	p2 := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r2, _ := newTest(p2)
	_, err := authenticate(&fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordTwo, 0, 0)}, testSession(), "me", r2)
	if err == nil || !strings.Contains(err.Error(), credstore.NameMailboxPassword) {
		t.Errorf("want an error naming %s, got %v", credstore.NameMailboxPassword, err)
	}
}

func TestTwoFactorWithoutSeedOrWithU2F(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, _ := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	_, err := authenticate(api, testSession(), "me", r)
	if err == nil || !strings.Contains(err.Error(), credstore.NameTOTPSecret) || len(api.totpCodes) != 0 {
		t.Errorf("no seed: err=%v codes=%v", err, api.totpCodes)
	}

	p2 := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin, TOTPSecret: testSeed}}
	r2, _ := newTest(p2)
	api2 := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 0)} // not TOTP
	_, err = authenticate(api2, testSession(), "me", r2)
	if err == nil || !strings.Contains(err.Error(), "only TOTP") || len(api2.totpCodes) != 0 {
		t.Errorf("non-TOTP 2FA: err=%v codes=%v", err, api2.totpCodes)
	}
}

func TestBreakerOpensAfterThreeFailedLogins(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, ck := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 8002, Message: "wrong password"}}

	for i := 0; i < maxAttempts; i++ {
		ck.t = ck.t.Add(5 * time.Minute) // well past any backoff delay, well inside the window
		if _, err := authenticate(api, testSession(), "me", r); err == nil || errors.As(err, new(*SuspendedError)) {
			t.Fatalf("attempt %d: want a plain login failure, got %v", i, err)
		}
	}
	if api.authCalls != maxAttempts {
		t.Fatalf("login attempts = %d, want %d", api.authCalls, maxAttempts)
	}

	ck.t = ck.t.Add(5 * time.Minute) // backoff is over, but the per-window cap is not
	before := *api
	_, err := authenticate(api, testSession(), "me", r)
	var sus *SuspendedError
	if !errors.As(err, &sus) || !strings.Contains(sus.Reason, "login attempts") {
		t.Fatalf("want the per-window cap, got %v", err)
	}
	if api.authCalls != before.authCalls || api.refreshCalls != before.refreshCalls || api.infoCalls != before.infoCalls || api.unlockCalls != before.unlockCalls {
		t.Error("while the breaker is open Proton must not be contacted at all")
	}

	ck.t = ck.t.Add(window + time.Second)
	api.authErr, api.loginAuth = nil, authWith(protonmail.PasswordSingle, 0, 0)
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("after the window the breaker should close: %v", err)
	}
}

func TestBackoffGrowsExponentiallyAndRecoveryResetsIt(t *testing.T) {
	p := &fakeProvider{err: errors.New("infisical login: unexpected HTTP status 503")}
	r, ck := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}

	for n := 1; n <= 8; n++ {
		if _, err := authenticate(api, testSession(), "me", r); err == nil {
			t.Fatalf("failure %d: expected an error", n)
		}
		delay := r.nextAttempt.Sub(ck.t)
		want := reloginBackoffBase << uint(n-1)
		if want > reloginBackoffMax {
			want = reloginBackoffMax
		}
		if delay < want*8/10 || delay > want*12/10 || delay > reloginBackoffMax {
			t.Fatalf("failure %d: delay %v, want about %v (+/-20%%, max %v)", n, delay, want, reloginBackoffMax)
		}

		// During the delay nothing is contacted: not Proton, not the secret store.
		calls, refreshes := p.calls, api.refreshCalls
		ck.t = ck.t.Add(delay / 2)
		var sus *SuspendedError
		if _, err := authenticate(api, testSession(), "me", r); !errors.As(err, &sus) {
			t.Fatalf("failure %d: want a SuspendedError during backoff, got %v", n, err)
		}
		if p.calls != calls || api.refreshCalls != refreshes {
			t.Fatalf("failure %d: backoff still contacted the secret store or Proton", n)
		}
		ck.t = r.nextAttempt.Add(time.Second)
	}

	p.err, p.sec = nil, credstore.Secrets{LoginPassword: testLogin}
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if r.bo.Failures() != 0 || !r.nextAttempt.IsZero() || r.blocked() != nil {
		t.Error("a successful login must reset the backoff")
	}
}

func TestCaptchaLatchesUntilRestartWithoutContactingProton(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, ck := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001, Message: "captcha"}}

	_, err := authenticate(api, testSession(), "me", r)
	var hv *HumanVerificationError
	if !errors.As(err, &hv) || !strings.Contains(err.Error(), "protoxide auth me") || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("want guidance to run auth and restart, got %v", err)
	}
	if !errors.As(r.blocked(), &hv) {
		t.Fatal("the gate must report the pending CAPTCHA")
	}

	calls := *api
	providerCalls := p.calls
	for _, wait := range []time.Duration{time.Minute, time.Hour, 48 * time.Hour} {
		ck.t = ck.t.Add(wait)
		if _, err := authenticate(api, testSession(), "me", r); !errors.As(err, &hv) {
			t.Fatalf("after %v: still must be blocked on the CAPTCHA, got %v", wait, err)
		}
	}
	if api.refreshCalls != calls.refreshCalls || api.infoCalls != calls.infoCalls || api.authCalls != calls.authCalls || p.calls != providerCalls {
		t.Error("a pending CAPTCHA must stop every Proton and secret-store request")
	}

	// A restart is a new process, and so a new reloginer.
	fresh, _ := newTest(p)
	if fresh.blocked() != nil {
		t.Error("a restarted bridge must try again")
	}
}

func TestGateIsOpenWhenNothingHasFailed(t *testing.T) {
	r, _ := newTest(&fakeProvider{})
	if err := r.blocked(); err != nil {
		t.Errorf("fresh reloginer is blocked: %v", err)
	}
}

func TestHumanVerificationIsReportedAndCounted(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, _ := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001, Message: "captcha"}}
	_, err := authenticate(api, testSession(), "me", r)
	if err == nil || !strings.Contains(err.Error(), "human verification") || !strings.Contains(err.Error(), "protoxide auth me") {
		t.Errorf("want guidance to run protoxide auth, got %v", err)
	}
	if len(r.attempts) != 1 {
		t.Errorf("a human-verification failure still counts as an attempt, got %d", len(r.attempts))
	}
}

func TestTOTPCodeIsNotReusedWithinOneStep(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin, TOTPSecret: testSeed}}
	r, ck := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}

	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatal(err)
	}
	if len(ck.slept) != 0 {
		t.Fatalf("first login must not wait, slept %v", ck.slept)
	}
	if _, err := authenticate(api, testSession(), "me", r); err != nil { // same 30 s step
		t.Fatal(err)
	}
	if len(ck.slept) != 1 || ck.slept[0] < stepMargin {
		t.Fatalf("second login in the same step must wait for the next one, slept %v", ck.slept)
	}
	if len(api.totpCodes) != 2 || api.totpCodes[0] == api.totpCodes[1] {
		t.Errorf("the same code was submitted twice: %v", api.totpCodes)
	}
}

func TestSecretStoreFailureDoesNotTouchProtonOrBreaker(t *testing.T) {
	p := &fakeProvider{err: errors.New("infisical login: unexpected HTTP status 403")}
	r, _ := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	_, err := authenticate(api, testSession(), "me", r)
	if err == nil || !strings.Contains(err.Error(), "reading secrets") {
		t.Fatalf("want a 'reading secrets' error, got %v", err)
	}
	if api.authCalls != 0 || len(r.attempts) != 0 {
		t.Error("a secret-store outage must not count as a login attempt or reach Proton")
	}
}

func TestHealthySessionNeverContactsTheSecretStore(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, _ := newTest(p)
	cached := testSession()
	cached.MailboxPassword = "already-in-memory"
	api := &fakeAPI{storedValid: true}
	if _, err := authenticate(api, cached, "me", r); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 {
		t.Errorf("secret store contacted %d times for a healthy session", p.calls)
	}
}

func TestPopulateLoadsSecretsIntoMemoryOnly(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin, MailboxPassword: testMailbox}}
	r, _ := newTest(p)
	cached := testSession()
	cached.Auth.PasswordMode = protonmail.PasswordTwo
	if err := r.populate(cached); err != nil {
		t.Fatal(err)
	}
	if cached.LoginPassword != testLogin || cached.MailboxPassword != testMailbox {
		t.Errorf("populate: %+v", cached)
	}
	p.err = errors.New("down")
	if err := r.populate(testSession()); err == nil {
		t.Error("populate must fail when the secret store is unreachable")
	}
}

func TestLegacyModeUnchanged(t *testing.T) {
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	cached := testSession()
	cached.LoginPassword = "x"
	_, err := authenticate(api, cached, "me", nil)
	if err == nil || !strings.Contains(err.Error(), "two factor authentication enabled, please login again manually") {
		t.Errorf("2FA without a secrets backend must still ask for a human, got %v", err)
	}
	_, err = authenticate(&fakeAPI{refreshErr: deadRefresh()}, testSession(), "me", nil)
	if err == nil || !strings.Contains(err.Error(), "no password is stored") {
		t.Errorf("empty stored password: %v", err)
	}
}

func TestErrorsNeverContainSecretValues(t *testing.T) {
	sec := credstore.Secrets{LoginPassword: testLogin, MailboxPassword: testMailbox, TOTPSecret: testSeed}
	scenarios := map[string]*fakeAPI{
		"wrong password": {refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 8002, Message: "bad"}},
		"hv":             {refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001}},
		"totp rejected":  {refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1), totpErr: errors.New("bad code")},
	}
	for name, api := range scenarios {
		r, _ := newTest(&fakeProvider{sec: sec})
		_, err := authenticate(api, testSession(), "me", r)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		for _, secret := range []string{testLogin, testMailbox, testSeed} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks a secret: %v", name, err)
			}
		}
	}
}

func TestFetchPublishesTheAlertWebhook(t *testing.T) {
	t.Setenv("PROTOXIDE_APPRISE_URL", "")
	t.Setenv("PROTOXIDE_DISCORD_WEBHOOK_URL", "")
	t.Setenv("PROTOXIDE_DISCORD_WEBHOOK_URL_FILE", "")
	t.Cleanup(func() { notify.SetDiscordWebhook("") })
	if notify.Configured() {
		t.Fatal("precondition: nothing configured")
	}

	// Published even when the fetch then fails on a missing password, so that very
	// problem can be alerted.
	p := &fakeProvider{sec: credstore.Secrets{DiscordWebhookURL: "https://discord.com/api/webhooks/1/tok"}}
	r, _ := newTest(p)
	if err := r.populate(testSession()); err == nil {
		t.Fatal("expected the missing-password error")
	}
	if !notify.Configured() {
		t.Error("the webhook from the secret store was not published to notify")
	}

	// A later fetch without it clears it again.
	p.sec = credstore.Secrets{LoginPassword: testLogin}
	if err := r.populate(testSession()); err != nil {
		t.Fatal(err)
	}
	if notify.Configured() {
		t.Error("removing the secret must clear the stored webhook")
	}
}

func TestMissingLoginPasswordIsReportedByName(t *testing.T) {
	// Optional at the store level, but a re-login and a session start both need it.
	p := &fakeProvider{sec: credstore.Secrets{TOTPSecret: testSeed}}
	r, _ := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	_, err := authenticate(api, testSession(), "me", r)
	if err == nil || !strings.Contains(err.Error(), credstore.NameLoginPassword) {
		t.Errorf("re-login: want an error naming %s, got %v", credstore.NameLoginPassword, err)
	}
	if api.authCalls != 0 {
		t.Error("must not contact Proton without a password")
	}
	if err := r.populate(testSession()); err == nil || !strings.Contains(err.Error(), credstore.NameLoginPassword) {
		t.Errorf("populate: want an error naming %s, got %v", credstore.NameLoginPassword, err)
	}
}

// The first real run failed here: the stale token was still attached when the
// re-login asked for /auth/info. Covers both the secrets backend and the legacy path.
func TestReloginSendsNoStaleCredentials(t *testing.T) {
	p := &fakeProvider{sec: credstore.Secrets{LoginPassword: testLogin}}
	r, _ := newTest(p)
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("secrets-backend re-login with a revoked session: %v", err)
	}

	legacy := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	cached := testSession()
	cached.LoginPassword = testLogin
	if _, err := authenticate(legacy, cached, "me", nil); err != nil {
		t.Fatalf("legacy re-login with a revoked session: %v", err)
	}
}
