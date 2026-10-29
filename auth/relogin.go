package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

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

var _ protonAPI = (*protonmail.Client)(nil)

const (
	apiCodeInvalidRefreshToken = 10013
	apiCodeHumanVerification   = 9001

	// Proton locks accounts after repeated failed logins, so unattended retries
	// are capped: maxAttempts logins per window, then the breaker opens until the
	// oldest attempt ages out (or a human runs `protoxide auth`).
	maxAttempts = 3
	window      = time.Hour

	secretsTimeout = 30 * time.Second
	// A code is single-use inside its 30 s step; wait this long past the step
	// boundary so clock skew cannot land us in the old step.
	stepMargin = 500 * time.Millisecond
)

// SuspendedError is returned while the retry breaker is open.
type SuspendedError struct{ Until time.Time }

func (e *SuspendedError) Error() string {
	return fmt.Sprintf("unattended re-authentication suspended after %d failed attempts; retry after %s or run `protoxide auth`",
		maxAttempts, e.Until.Format(time.RFC3339))
}

// reloginer logs in to Proton again, unattended, using secrets from an external
// store. It is only created when a secrets backend is configured; without one the
// legacy behaviour (cached password, no 2FA) is unchanged.
type reloginer struct {
	provider credstore.Provider

	now   func() time.Time
	sleep func(time.Duration)

	mu       sync.Mutex
	attempts []time.Time
	lastStep int64 // TOTP step last submitted, -1 if none
}

func newReloginer(p credstore.Provider) *reloginer {
	return &reloginer{provider: p, now: time.Now, sleep: time.Sleep, lastStep: -1}
}

func (r *reloginer) fetch() (credstore.Secrets, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretsTimeout)
	defer cancel()
	sec, err := r.provider.Get(ctx)
	if err != nil {
		return credstore.Secrets{}, err
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

// reauth performs SRP login, answers a TOTP challenge when needed, and updates the
// in-memory secrets. The caller unlocks the keys afterwards.
func (r *reloginer) reauth(c protonAPI, cached *CachedAuth, username string) (*protonmail.Auth, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if until, open := r.breakerOpen(now); open {
		err := &SuspendedError{Until: until}
		log.Printf("auth: %v", err)
		notify.Send("failure", "relogin-suspended", "protoxide: re-authentication suspended",
			fmt.Sprintf("Account %q: %v", username, err))
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

	r.attempts = append(r.attempts, now) // counted before the login, whatever its outcome
	log.Printf("auth: Proton session expired; logging in again with credentials from the secret store (attempt %d of %d allowed per %s)", len(r.attempts), maxAttempts, window)
	auth, err := c.Auth(username, sec.LoginPassword, info)
	if err != nil {
		var apiErr *protonmail.APIError
		if errors.As(err, &apiErr) && apiErr.Code == apiCodeHumanVerification {
			return nil, r.fail(username, "relogin-failed", fmt.Errorf(
				"cannot re-authenticate: Proton wants human verification, which cannot be done unattended; run `protoxide auth %s`", username))
		}
		return nil, r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
	}

	if auth.TwoFactor.Enabled != 0 {
		if auth.TwoFactor.TOTP != 1 {
			return nil, r.fail(username, "relogin-failed", errors.New("cannot re-authenticate: only TOTP is supported as a 2FA method; run `protoxide auth`"))
		}
		if sec.TOTPSecret == "" {
			return nil, r.fail(username, "relogin-failed", errors.New("cannot re-authenticate: 2FA is enabled but "+credstore.NameTOTPSecret+" is not set in the secret store"))
		}
		scope, err := r.answerTOTP(c, sec.TOTPSecret)
		if err != nil {
			return nil, r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
		}
		auth.Scope = scope
	}

	if err := apply(cached, sec, auth.PasswordMode); err != nil {
		return nil, r.fail(username, "relogin-failed", fmt.Errorf("cannot re-authenticate: %w", err))
	}

	r.attempts = nil // a successful login resets the breaker
	log.Printf("auth: re-authenticated unattended (2FA answered: %v)", auth.TwoFactor.Enabled != 0)
	notify.Send("success", "relogin-ok", "protoxide: re-authenticated",
		fmt.Sprintf("Account %q logged in again unattended.", username))
	return auth, nil
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

// breakerOpen reports whether maxAttempts logins already happened inside the window.
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

// fail alerts (debounced by key) and returns err unchanged. Errors reaching here
// carry no secret values: credstore and totp scrub theirs, and Proton API errors
// contain only the API's own message.
func (r *reloginer) fail(username, key string, err error) error {
	log.Printf("auth: unattended re-authentication failed: %v", err)
	notify.Send("failure", key, "protoxide: re-authentication failed",
		fmt.Sprintf("Account %q: %v", username, err))
	return err
}
