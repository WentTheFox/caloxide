package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/mathewcsims/protoxide/backoff"
	"github.com/mathewcsims/protoxide/credstore"
	"github.com/mathewcsims/protoxide/notify"
	"github.com/mathewcsims/protoxide/protonmail"
	"github.com/mathewcsims/protoxide/totp"
)

// protonAPI is the part of *protonmail.Client the authentication flow needs. It
// exists so the flow can be tested with a fake instead of the real Proton API.
type protonAPI interface {
	SetSession(uid, accessToken string)
	Unlock(auth *protonmail.Auth, keySalts map[string][]byte, passphrase string) (openpgp.EntityList, error)
	AuthRefresh(expiredAuth *protonmail.Auth) (*protonmail.Auth, error)
	AuthInfo(username string) (*protonmail.AuthInfo, error)
	Auth(username, password string, info *protonmail.AuthInfo) (*protonmail.Auth, error)
	AuthTOTP(code string) (scope string, err error)
}

// authAPI adds the human-verification calls used by the web verification flow.
type authAPI interface {
	protonAPI
	SetHumanVerification(token, tokenType string)
	ClearHumanVerification()
}

var (
	_ protonAPI = (*protonmail.Client)(nil)
	_ authAPI   = (*protonmail.Client)(nil)
)

const (
	apiCodeInvalidRefreshToken = 10013
	apiCodeHumanVerification   = 9001

	// Proton locks accounts after repeated failed logins, so unattended retries are
	// capped twice over: each failure delays the next attempt exponentially, and no
	// more than maxAttempts logins are submitted per window.
	maxAttempts = 3
	window      = time.Hour

	reloginBackoffBase = 30 * time.Second // then 1m, 2m, 4m ... up to the max
	reloginBackoffMax  = 30 * time.Minute

	secretsTimeout = 30 * time.Second
	// A code is single-use inside its 30 s step; wait this long past the step
	// boundary so clock skew cannot land us in the old step.
	stepMargin = 500 * time.Millisecond
)

// SuspendedError is returned while unattended re-authentication is paused, either
// backing off after a failure or because the per-window cap was reached.
type SuspendedError struct {
	Until  time.Time
	Reason string
}

func (e *SuspendedError) Error() string {
	return fmt.Sprintf("unattended re-authentication paused (%s); next attempt not before %s, or run `protoxide auth` and restart the bridge",
		e.Reason, e.Until.Format(time.RFC3339))
}

// HumanVerificationError means Proton demanded a CAPTCHA. That cannot be answered
// unattended and retrying only looks abusive, so the bridge stops calling Proton
// until a human runs `protoxide auth` and restarts it.
type HumanVerificationError struct{ Username string }

func (e *HumanVerificationError) Error() string {
	return fmt.Sprintf("Proton wants human verification, which cannot be done unattended; run `protoxide verify` inside the container for a one-time link, or `protoxide auth %s` on a workstation and restart the bridge", e.Username)
}

// reloginer logs in to Proton again, unattended, using secrets from an external
// store. It is only created when a secrets backend is configured; without one the
// legacy behaviour (cached password, no 2FA) is unchanged.
type reloginer struct {
	provider credstore.Provider

	now   func() time.Time
	sleep func(time.Duration)
	bo    *backoff.Backoff

	mu sync.Mutex // serialises re-logins; held across network calls

	st          sync.Mutex // guards the fields below; never held across I/O
	attempts    []time.Time
	nextAttempt time.Time
	humanNeeded *HumanVerificationError

	lastStep int64 // TOTP step last submitted, -1 if none; only touched under mu
}

func newReloginer(p credstore.Provider) *reloginer {
	return &reloginer{
		provider: p,
		now:      time.Now,
		sleep:    time.Sleep,
		bo:       backoff.New(reloginBackoffBase, reloginBackoffMax),
		lastStep: -1,
	}
}

func (r *reloginer) fetch() (credstore.Secrets, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretsTimeout)
	defer cancel()
	sec, err := r.provider.Get(ctx)
	if err != nil {
		return credstore.Secrets{}, err
	}
	// Hand the alert webhook over first, so even a problem found below (such as a
	// missing password) can be reported.
	if err := notify.SetDiscordWebhook(sec.DiscordWebhookURL); err != nil {
		log.Printf("notify: %v", err)
	}
	if sec.LoginPassword == "" {
		return credstore.Secrets{}, errors.New(credstore.NameLoginPassword + " is not set in the secret store")
	}
	return sec, nil
}

// apply copies the secrets into the in-memory session. The mailbox password is the
// login password for single-password accounts. Nothing here is ever persisted.
func apply(cached *CachedAuth, sec credstore.Secrets, mode protonmail.PasswordMode) error {
	cached.LoginPassword = sec.LoginPassword
	if mode == protonmail.PasswordTwo {
		if sec.MailboxPassword == "" {
			return errors.New("this is a two-password account but " + credstore.NameMailboxPassword + " is not set in the secret store")
		}
		cached.MailboxPassword = sec.MailboxPassword
	} else {
		cached.MailboxPassword = sec.LoginPassword
	}
	return nil
}

// populate loads the secrets into a freshly decrypted session (first request
// after a start). The store is not contacted again until a re-login is needed.
func (r *reloginer) populate(cached *CachedAuth) error {
	sec, err := r.fetch()
	if err != nil {
		return fmt.Errorf("reading secrets from the secret store: %w", err)
	}
	return apply(cached, sec, cached.Auth.PasswordMode)
}

// blocked reports whether unattended re-authentication is currently off limits:
// a CAPTCHA is pending (until restart), the per-window cap is reached, or an
// exponential backoff delay has not elapsed. It never blocks on network I/O, so it
// can serve as the protonmail.Client gate: while it returns an error, requests that
// carry a (dead) token fail locally and Proton is not contacted at all.
func (r *reloginer) blocked() error {
	r.st.Lock()
	defer r.st.Unlock()
	if r.humanNeeded != nil {
		return r.humanNeeded
	}
	now := r.now()
	if until, open := r.breakerOpen(now); open {
		return &SuspendedError{Until: until, Reason: fmt.Sprintf("%d login attempts in the last %s", maxAttempts, window)}
	}
	if now.Before(r.nextAttempt) {
		return &SuspendedError{Until: r.nextAttempt, Reason: fmt.Sprintf("backing off after %d failed attempt(s)", r.bo.Failures())}
	}
	return nil
}

// reauth performs SRP login, answers a TOTP challenge when needed, and updates the
// in-memory secrets. The caller unlocks the keys afterwards.
func (r *reloginer) reauth(c protonAPI, cached *CachedAuth, username string) (*protonmail.Auth, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.blocked(); err != nil {
		var hv *HumanVerificationError
		if !errors.As(err, &hv) { // a CAPTCHA was already alerted when it happened
			log.Printf("auth: %v", err)
			notify.Send("failure", "relogin-suspended", "protoxide: re-authentication paused",
				fmt.Sprintf("Account %q: %v", username, err))
		}
		return nil, err
	}

	sec, err := r.fetch()
	if err != nil {
		return nil, r.fail(username, "relogin-secrets", fmt.Errorf("cannot re-authenticate: reading secrets: %w", err))
	}

	info, err := c.AuthInfo(username)
	if err != nil {
		return nil, r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: failed to get auth info: %w", err))
	}

	r.st.Lock()
	r.attempts = append(r.attempts, r.now()) // counted before the login, whatever its outcome
	n := len(r.attempts)
	r.st.Unlock()
	log.Printf("auth: Proton session expired; logging in again with credentials from the secret store (attempt %d of %d allowed per %s)", n, maxAttempts, window)

	auth, err := c.Auth(username, sec.LoginPassword, info)
	if err != nil {
		var apiErr *protonmail.APIError
		if errors.As(err, &apiErr) && apiErr.Code == apiCodeHumanVerification {
			return nil, r.latchHumanVerification(username)
		}
		return nil, r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
	}

	if err := r.finishLogin(c, cached, sec, auth, username); err != nil {
		return nil, err
	}
	return auth, nil
}

// finishLogin completes a login Proton accepted: it answers a TOTP challenge if one
// is pending, loads the secrets into the in-memory session, and records the success
// (which clears the backoff, the cap and any CAPTCHA latch). The caller holds r.mu.
func (r *reloginer) finishLogin(c protonAPI, cached *CachedAuth, sec credstore.Secrets, auth *protonmail.Auth, username string) error {
	if auth.TwoFactor.Enabled != 0 {
		if auth.TwoFactor.TOTP != 1 {
			return r.fail(username, "relogin-failed", errors.New("cannot re-authenticate: only TOTP is supported as a 2FA method; run `protoxide auth`"))
		}
		if sec.TOTPSecret == "" {
			return r.fail(username, "relogin-failed", errors.New("cannot re-authenticate: 2FA is enabled but "+credstore.NameTOTPSecret+" is not set in the secret store"))
		}
		scope, err := r.answerTOTP(c, sec.TOTPSecret)
		if err != nil {
			return r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
		}
		auth.Scope = scope
	}

	if err := apply(cached, sec, auth.PasswordMode); err != nil {
		return r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
	}

	r.markSuccess()
	log.Printf("auth: re-authenticated unattended (2FA answered: %v)", auth.TwoFactor.Enabled != 0)
	notify.Send("success", "relogin-ok", "protoxide: re-authenticated",
		fmt.Sprintf("Account %q logged in again unattended.", username))
	return nil
}

// markSuccess resets the breaker, the backoff and the CAPTCHA latch.
func (r *reloginer) markSuccess() {
	r.st.Lock()
	r.attempts = nil
	r.nextAttempt = time.Time{}
	r.humanNeeded = nil
	r.st.Unlock()
	r.bo.Reset()
}

// pendingHumanVerification returns the CAPTCHA latch, or nil if there is none.
func (r *reloginer) pendingHumanVerification() *HumanVerificationError {
	r.st.Lock()
	defer r.st.Unlock()
	return r.humanNeeded
}

// answerTOTP submits a code, first waiting out the current step if a code was
// already used in it (Proton rejects a reused code).
func (r *reloginer) answerTOTP(c protonAPI, seed string) (string, error) {
	step := func() int64 { return r.now().Unix() / int64(totp.Period/time.Second) }
	if step() <= r.lastStep {
		r.sleep(totp.UntilNextStep(r.now()) + stepMargin)
	}
	code, err := totp.Code(seed, r.now())
	if err != nil {
		return "", fmt.Errorf("could not generate a 2FA code: %w", err)
	}
	r.lastStep = step()
	scope, err := c.AuthTOTP(code)
	if err != nil {
		return "", fmt.Errorf("2FA code rejected: %w", err)
	}
	return scope, nil
}

// breakerOpen reports whether maxAttempts logins already happened inside the
// window. The caller holds r.st.
func (r *reloginer) breakerOpen(now time.Time) (time.Time, bool) {
	kept := r.attempts[:0]
	for _, t := range r.attempts {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	r.attempts = kept
	if len(r.attempts) >= maxAttempts {
		return r.attempts[0].Add(window), true
	}
	return time.Time{}, false
}

// latchHumanVerification records that Proton wants a CAPTCHA. Retrying cannot help
// and every extra attempt makes the client look more like abuse, so the bridge
// stops calling Proton until a human intervenes.
func (r *reloginer) latchHumanVerification(username string) error {
	hv := &HumanVerificationError{Username: username}
	r.st.Lock()
	r.humanNeeded = hv
	r.st.Unlock()
	log.Printf("auth: unattended re-authentication stopped: %v", hv)
	notify.Send("failure", "relogin-human", "protoxide: Proton wants a CAPTCHA",
		fmt.Sprintf("Account %q: %v. The bridge makes no more Proton requests until then.", username, hv))
	return hv
}

// fail logs and alerts (debounced by key), schedules the next attempt with
// exponential backoff, and returns err unchanged. Errors reaching here carry no
// secret values: credstore and totp scrub theirs, and Proton API errors contain
// only the API's own message.
func (r *reloginer) fail(username, key string, err error) error {
	wait := r.bo.Next()
	r.st.Lock()
	r.nextAttempt = r.now().Add(wait)
	r.st.Unlock()
	log.Printf("auth: unattended re-authentication failed: %v (next attempt in %s)", err, wait.Round(time.Second))
	notify.Send("failure", key, "protoxide: re-authentication failed",
		fmt.Sprintf("Account %q: %v", username, err))
	return err
}
