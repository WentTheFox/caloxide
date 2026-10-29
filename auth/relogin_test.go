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
	storedValid bool // if false, Unlock rejects the stored ("old") access token
	refreshErr  error
	loginAuth   func() *protonmail.Auth // returned by Auth when authErr is nil
	authErr     error
	totpErr     error

	authCalls  int
	passwords  []string
	totpCodes  []string
	unlockPass []string
}

func (f *fakeAPI) SetSession(string, string) {}
func (f *fakeAPI) Unlock(a *protonmail.Auth, _ map[string][]byte, pass string) (openpgp.EntityList, error) {
	f.unlockPass = append(f.unlockPass, pass)
	if a.AccessToken == "old" && !f.storedValid {
		return nil, &protonmail.APIError{Code: 401, Message: "access token expired"}
	}
	return openpgp.EntityList{}, nil
}
func (f *fakeAPI) AuthRefresh(*protonmail.Auth) (*protonmail.Auth, error) {
	return nil, f.refreshErr
}
func (f *fakeAPI) AuthInfo(string) (*protonmail.AuthInfo, error) { return &protonmail.AuthInfo{}, nil }
func (f *fakeAPI) Auth(_, password string, _ *protonmail.AuthInfo) (*protonmail.Auth, error) {
	f.authCalls++
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
		if _, err := authenticate(api, testSession(), "me", r); err == nil || errors.As(err, new(*SuspendedError)) {
			t.Fatalf("attempt %d: want a plain login failure, got %v", i, err)
		}
	}
	if api.authCalls != maxAttempts {
		t.Fatalf("login attempts = %d, want %d", api.authCalls, maxAttempts)
	}

	_, err := authenticate(api, testSession(), "me", r)
	var sus *SuspendedError
	if !errors.As(err, &sus) {
		t.Fatalf("want SuspendedError once the breaker is open, got %v", err)
	}
	if api.authCalls != maxAttempts {
		t.Error("the breaker must stop contacting Proton's login endpoint")
	}

	ck.t = ck.t.Add(window + time.Second)
	api.authErr, api.loginAuth = nil, authWith(protonmail.PasswordSingle, 0, 0)
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("after the window the breaker should close: %v", err)
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
