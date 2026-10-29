package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/totp"
)

const (
	testLogin   = "LOGIN-pw-xyz"
	testMailbox = "MAILBOX-pw-xyz"
	testSeed    = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 test seed
)

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

	// requireHV makes Auth answer 9001 (with hvDetails) until a human-verification
	// token is attached; rejectHV makes it answer 9001 even with one.
	requireHV, rejectHV bool
	hvDetails           *protonmail.HumanVerificationDetails
	hvToken, hvType     string
	hvTokenUsed         string // the token present when Auth last succeeded

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
	if f.rejectHV || (f.requireHV && f.hvToken == "") {
		return nil, &protonmail.APIError{Code: 9001, Message: "captcha", HV: f.hvDetails}
	}
	f.hvTokenUsed = f.hvToken
	return f.loginAuth(), nil
}

func (f *fakeAPI) SetHumanVerification(token, tokenType string) {
	f.hvToken, f.hvType = token, tokenType
}
func (f *fakeAPI) ClearHumanVerification() { f.hvToken, f.hvType = "", "" }
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

func newTest() (*reloginer, *fakeClock) {
	ck := &fakeClock{t: time.Unix(1_700_000_010, 0)}
	r := newReloginer()
	r.now, r.sleep = ck.now, ck.sleep
	return r, ck
}

// testSession is a decrypted session record as `protoxide auth` stores it: an expired
// access token and the account's password. withSeed and withMailbox add the rest.
func testSession() *CachedAuth {
	return &CachedAuth{
		Auth:          protonmail.Auth{UID: "u", AccessToken: "old", RefreshToken: "r", PasswordMode: protonmail.PasswordSingle},
		LoginPassword: testLogin,
	}
}

func withSeed(c *CachedAuth) *CachedAuth    { c.TOTPSecret = testSeed; return c }
func withMailbox(c *CachedAuth) *CachedAuth { c.MailboxPassword = testMailbox; return c }
func withoutPassword(c *CachedAuth) *CachedAuth {
	c.LoginPassword = ""
	return c
}

func TestReloginWithTOTPSucceeds(t *testing.T) {
	r, ck := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	cached := withSeed(testSession())
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
	if cached.TOTPSecret != testSeed || cached.LoginPassword != testLogin {
		t.Error("the stored credentials must survive a re-login (they are what the next one needs)")
	}
	if len(r.attempts) != 0 {
		t.Error("a successful login must reset the breaker")
	}
}

func TestTwoPasswordAccountNeedsItsMailboxPassword(t *testing.T) {
	r, _ := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordTwo, 0, 0)}
	if _, err := authenticate(api, withMailbox(testSession()), "me", r); err != nil {
		t.Fatal(err)
	}
	if got := api.unlockPass[len(api.unlockPass)-1]; got != testMailbox {
		t.Errorf("unlock used %q, want the mailbox password", got)
	}

	r2, _ := newTest()
	_, err := authenticate(&fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordTwo, 0, 0)}, testSession(), "me", r2)
	if err == nil || !strings.Contains(err.Error(), "mailbox password") || !strings.Contains(err.Error(), "protoxide auth") {
		t.Errorf("want guidance about the missing mailbox password, got %v", err)
	}
}

func TestTwoFactorWithoutSeedOrWithU2F(t *testing.T) {
	r, _ := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	_, err := authenticate(api, testSession(), "me", r) // no seed stored
	if err == nil || !strings.Contains(err.Error(), "2FA seed") || !strings.Contains(err.Error(), "protoxide auth") || len(api.totpCodes) != 0 {
		t.Errorf("no seed: err=%v codes=%v", err, api.totpCodes)
	}

	r2, _ := newTest()
	api2 := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 0)} // not TOTP
	_, err = authenticate(api2, withSeed(testSession()), "me", r2)
	if err == nil || !strings.Contains(err.Error(), "only TOTP") || len(api2.totpCodes) != 0 {
		t.Errorf("non-TOTP 2FA: err=%v codes=%v", err, api2.totpCodes)
	}
}

func TestBreakerOpensAfterThreeFailedLogins(t *testing.T) {
	r, ck := newTest()
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
	r, ck := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}

	for n := 1; n <= 8; n++ {
		// A record with no stored password fails before Proton is contacted for a login.
		if _, err := authenticate(api, withoutPassword(testSession()), "me", r); err == nil {
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

		// During the delay nothing is contacted.
		refreshes := api.refreshCalls
		ck.t = ck.t.Add(delay / 2)
		var sus *SuspendedError
		if _, err := authenticate(api, testSession(), "me", r); !errors.As(err, &sus) {
			t.Fatalf("failure %d: want a SuspendedError during backoff, got %v", n, err)
		}
		if api.refreshCalls != refreshes {
			t.Fatalf("failure %d: backoff still contacted Proton", n)
		}
		ck.t = r.nextAttempt.Add(time.Second)
	}

	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if r.bo.Failures() != 0 || !r.nextAttempt.IsZero() || r.blocked() != nil {
		t.Error("a successful login must reset the backoff")
	}
}

func TestHumanVerificationIsReportedAndCounted(t *testing.T) {
	r, _ := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001, Message: "captcha"}}
	_, err := authenticate(api, testSession(), "me", r)
	if err == nil || !strings.Contains(err.Error(), "human verification") || !strings.Contains(err.Error(), "protoxide auth me") {
		t.Errorf("want guidance to run protoxide auth, got %v", err)
	}
	if len(r.attempts) != 1 {
		t.Errorf("a human-verification failure still counts as an attempt, got %d", len(r.attempts))
	}
}

func TestCaptchaLatchesUntilRestartWithoutContactingProton(t *testing.T) {
	r, ck := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001, Message: "captcha"}}

	_, err := authenticate(api, testSession(), "me", r)
	var hv *HumanVerificationError
	if !errors.As(err, &hv) || !strings.Contains(err.Error(), "protoxide auth me") || !strings.Contains(err.Error(), "protoxide verify") {
		t.Fatalf("want guidance to verify or re-auth, got %v", err)
	}
	if !errors.As(r.blocked(), &hv) {
		t.Fatal("the gate must report the pending CAPTCHA")
	}

	calls := *api
	for _, wait := range []time.Duration{time.Minute, time.Hour, 48 * time.Hour} {
		ck.t = ck.t.Add(wait)
		if _, err := authenticate(api, testSession(), "me", r); !errors.As(err, &hv) {
			t.Fatalf("after %v: still must be blocked on the CAPTCHA, got %v", wait, err)
		}
	}
	if api.refreshCalls != calls.refreshCalls || api.infoCalls != calls.infoCalls || api.authCalls != calls.authCalls {
		t.Error("a pending CAPTCHA must stop every Proton request")
	}

	// A restart is a new process, and so a new reloginer.
	fresh, _ := newTest()
	if fresh.blocked() != nil {
		t.Error("a restarted bridge must try again")
	}
}

func TestGateIsOpenWhenNothingHasFailed(t *testing.T) {
	r, _ := newTest()
	if err := r.blocked(); err != nil {
		t.Errorf("fresh reloginer is blocked: %v", err)
	}
}

func TestTOTPCodeIsNotReusedWithinOneStep(t *testing.T) {
	r, ck := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}

	if _, err := authenticate(api, withSeed(testSession()), "me", r); err != nil {
		t.Fatal(err)
	}
	if len(ck.slept) != 0 {
		t.Fatalf("first login must not wait, slept %v", ck.slept)
	}
	if _, err := authenticate(api, withSeed(testSession()), "me", r); err != nil { // same 30 s step
		t.Fatal(err)
	}
	if len(ck.slept) != 1 || ck.slept[0] < stepMargin {
		t.Fatalf("second login in the same step must wait for the next one, slept %v", ck.slept)
	}
	if len(api.totpCodes) != 2 || api.totpCodes[0] == api.totpCodes[1] {
		t.Errorf("the same code was submitted twice: %v", api.totpCodes)
	}
}

func TestMissingPasswordNeverReachesProtonAndSaysWhatToDo(t *testing.T) {
	r, _ := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	_, err := authenticate(api, withoutPassword(testSession()), "me", r)
	if err == nil || !strings.Contains(err.Error(), "no password is stored") || !strings.Contains(err.Error(), "protoxide auth") {
		t.Fatalf("want guidance to run protoxide auth, got %v", err)
	}
	if api.authCalls != 0 || api.infoCalls != 0 || len(r.attempts) != 0 {
		t.Error("with nothing to log in with, Proton must not be contacted or the breaker charged")
	}
}

func TestLegacyModeUnchanged(t *testing.T) {
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1)}
	cached := testSession()
	_, err := authenticate(api, cached, "me", nil)
	if err == nil || !strings.Contains(err.Error(), "two factor authentication enabled, please login again manually") {
		t.Errorf("without unattended re-login, 2FA must still ask for a human, got %v", err)
	}
	_, err = authenticate(&fakeAPI{refreshErr: deadRefresh()}, withoutPassword(testSession()), "me", nil)
	if err == nil || !strings.Contains(err.Error(), "no password is stored") {
		t.Errorf("empty stored password: %v", err)
	}
}

func TestErrorsNeverContainStoredSecrets(t *testing.T) {
	scenarios := map[string]*fakeAPI{
		"wrong password": {refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 8002, Message: "bad"}},
		"hv":             {refreshErr: deadRefresh(), authErr: &protonmail.APIError{Code: 9001}},
		"totp rejected":  {refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 1, 1), totpErr: errors.New("bad code")},
	}
	for name, api := range scenarios {
		r, _ := newTest()
		_, err := authenticate(api, withMailbox(withSeed(testSession())), "me", r)
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

func TestReloginSendsNoStaleCredentials(t *testing.T) {
	r, _ := newTest()
	api := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	if _, err := authenticate(api, testSession(), "me", r); err != nil {
		t.Fatalf("re-login with a revoked session: %v", err)
	}

	legacy := &fakeAPI{refreshErr: deadRefresh(), loginAuth: authWith(protonmail.PasswordSingle, 0, 0)}
	if _, err := authenticate(legacy, testSession(), "me", nil); err != nil {
		t.Fatalf("legacy re-login with a revoked session: %v", err)
	}
}
