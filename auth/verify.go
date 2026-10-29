package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/mathewcsims/protoxide/credstore"
	"github.com/mathewcsims/protoxide/protonmail"
)

// Web verification lets a human answer Proton's CAPTCHA through a page served by the
// running bridge, without restarting it. It is reachable only inside a verification
// window, which exists only while a CAPTCHA is pending AND someone with command-line
// access to the container asked for one (`protoxide verify`). A window is a random
// 256-bit token in the URL, valid for windowTTL, and nothing else about the page is
// reachable without it.

const (
	windowTTL = 10 * time.Minute
	// maxBegins bounds how many fresh login attempts one window can trigger (each page
	// load asks Proton for a new challenge).
	maxBegins = 3
	hvMethod  = "captcha"
)

var (
	// ErrNoWindow is returned for a missing, expired or wrong token. It is deliberately
	// uninformative: callers answer 404 so nothing reveals that the route exists.
	ErrNoWindow             = errors.New("no verification window is open")
	ErrNotWaiting           = errors.New("the bridge is not waiting for human verification")
	ErrNoSecretsBackend     = errors.New("web verification needs the secrets backend (PROTOXIDE_SECRETS_BACKEND)")
	ErrChallengeExpired     = errors.New("the verification challenge expired or was already used; reload the page")
	ErrNoToken              = errors.New("could not find a verification token in what was pasted")
	ErrWrongMessage         = errors.New("that is the proton_captcha line; the token needed is on the line whose type is pm_captcha (the second HV line)")
	ErrVerificationRejected = errors.New("Proton did not accept that verification; reload the page for a fresh challenge")
)

type verifyWindow struct {
	token   string
	expires time.Time
	begins  int
}

type verifyChallenge struct {
	nonce   string
	created time.Time
}

// Challenge is what the page needs to show after a login attempt.
type Challenge struct {
	// Token is Proton's human-verification token, used to build the CAPTCHA popup URL.
	Token string
	// Nonce must come back with the pasted result; it ties the answer to this challenge.
	Nonce string
	// Done means Proton did not ask for a CAPTCHA this time and the login succeeded.
	Done bool
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// OpenVerificationWindow starts a time-limited window and returns its URL token. It
// fails unless a CAPTCHA is actually pending. A previous window is replaced.
func (m *Manager) OpenVerificationWindow() (token string, expires time.Time, err error) {
	if m.rl == nil {
		return "", time.Time{}, ErrNoSecretsBackend
	}
	if m.rl.pendingHumanVerification() == nil {
		return "", time.Time{}, ErrNotWaiting
	}
	token, err = randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires = m.now().Add(windowTTL)
	m.wmu.Lock()
	m.win = &verifyWindow{token: token, expires: expires}
	m.wmu.Unlock()
	log.Printf("auth: verification window opened, valid until %s", expires.Format(time.RFC3339))
	return token, expires, nil
}

func (m *Manager) closeWindow() {
	m.wmu.Lock()
	m.win = nil
	m.wmu.Unlock()
}

// VerificationWindowOpen reports whether token opens a live window. It consumes
// nothing, so the HTTP layer can use it to decide between the page and a 404.
func (m *Manager) VerificationWindowOpen(token string) bool {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.windowMatches(token)
}

// windowMatches is constant-time in the token. The caller holds m.wmu.
func (m *Manager) windowMatches(token string) bool {
	w := m.win
	if w == nil || m.now().After(w.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(w.token)) == 1
}

// windowSession validates the window and returns the account's session. Beginning a
// verification is counted against maxBegins.
func (m *Manager) windowSession(token string, countBegin bool) (*session, error) {
	if m.rl == nil {
		return nil, ErrNoSecretsBackend
	}
	m.wmu.Lock()
	if !m.windowMatches(token) || (countBegin && m.win.begins >= maxBegins) {
		m.wmu.Unlock()
		return nil, ErrNoWindow
	}
	if countBegin {
		m.win.begins++
	}
	m.wmu.Unlock()

	hv := m.rl.pendingHumanVerification()
	if hv == nil {
		return nil, ErrNotWaiting
	}
	m.mu.Lock()
	s := m.sessions[hv.Username]
	m.mu.Unlock()
	if s == nil {
		return nil, ErrNotWaiting
	}
	return s, nil
}

// BeginVerification logs in again with the stored credentials to obtain a fresh
// CAPTCHA challenge. If Proton does not ask for one this time, the login simply
// completes.
func (m *Manager) BeginVerification(token string) (*Challenge, error) {
	s, err := m.windowSession(token, true)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.rl.mu.Lock()
	defer m.rl.mu.Unlock()

	sec, err := m.rl.fetch()
	if err != nil {
		return nil, fmt.Errorf("reading secrets: %w", err)
	}
	d := m.detach(s.c)
	info, err := d.AuthInfo(s.username)
	if err != nil {
		return nil, fmt.Errorf("asking Proton to log in: %w", err)
	}
	auth, err := d.Auth(s.username, sec.LoginPassword, info)
	if err != nil {
		var apiErr *protonmail.APIError
		if errors.As(err, &apiErr) && apiErr.Code == apiCodeHumanVerification && apiErr.HV != nil {
			if !hasMethod(apiErr.HV.HumanVerificationMethods, hvMethod) {
				return nil, fmt.Errorf("Proton offered only unsupported verification methods %v", apiErr.HV.HumanVerificationMethods)
			}
			nonce, err := randomToken(24)
			if err != nil {
				return nil, err
			}
			s.challenge = &verifyChallenge{nonce: nonce, created: m.now()}
			return &Challenge{Token: apiErr.HV.HumanVerificationToken, Nonce: nonce}, nil
		}
		return nil, fmt.Errorf("login failed: %w", err)
	}
	if err := m.finishWebLogin(s, d, sec, auth); err != nil {
		return nil, err
	}
	return &Challenge{Done: true}, nil
}

// CompleteVerification submits what the person pasted (see ParseVerificationInput)
// and finishes the login.
func (m *Manager) CompleteVerification(token, nonce, input string) error {
	s, err := m.windowSession(token, false)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.rl.mu.Lock()
	defer m.rl.mu.Unlock()

	ch := s.challenge
	if ch == nil || m.now().Sub(ch.created) > windowTTL || subtle.ConstantTimeCompare([]byte(nonce), []byte(ch.nonce)) != 1 {
		return ErrChallengeExpired
	}
	// A paste that holds no token leaves the challenge intact so the person can paste
	// again; it is consumed only once it is actually submitted to Proton.
	hv, err := ParseVerificationInput(input)
	if err != nil {
		return err
	}
	s.challenge = nil // single use

	sec, err := m.rl.fetch()
	if err != nil {
		return fmt.Errorf("reading secrets: %w", err)
	}
	d := m.detach(s.c)
	d.SetHumanVerification(hv, hvMethod)
	defer d.ClearHumanVerification()
	info, err := d.AuthInfo(s.username)
	if err != nil {
		return fmt.Errorf("asking Proton to log in: %w", err)
	}
	auth, err := d.Auth(s.username, sec.LoginPassword, info)
	if err != nil {
		var apiErr *protonmail.APIError
		if errors.As(err, &apiErr) && apiErr.Code == apiCodeHumanVerification {
			return ErrVerificationRejected
		}
		return fmt.Errorf("login failed: %w", err)
	}
	return m.finishWebLogin(s, d, sec, auth)
}

// finishWebLogin turns an accepted login into a working session, exactly like the
// unattended path, and closes the window. The caller holds s.mu and m.rl.mu.
func (m *Manager) finishWebLogin(s *session, d authAPI, sec credstore.Secrets, auth *protonmail.Auth) error {
	if err := m.rl.finishLogin(d, &s.cached, sec, auth, s.username); err != nil {
		return err
	}
	s.cached.Auth = *auth
	keys, err := d.Unlock(auth, s.cached.KeySalts, s.cached.MailboxPassword)
	if err != nil {
		return fmt.Errorf("unlocking the account's keys: %w", err)
	}
	m.adopt(s.c, d)
	s.privateKeys = keys
	s.ready = true
	if err := m.persist(s); err != nil {
		return err
	}
	m.closeWindow()
	return nil
}

func hasMethod(methods []string, want string) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

// plainToken is the character set of a token. Its length is checked separately: the
// message Proton's CAPTCHA sends is "<challenge id>:<CAPTCHA response>", and the
// response alone is routinely over 1000 characters (RE2 caps bounded repeats at 1000).
var plainToken = regexp.MustCompile(`^[A-Za-z0-9._~+/=:-]+$`)

const (
	minTokenLen = 16
	maxTokenLen = 12 << 10
	// maxVerificationInput bounds what is parsed from a pasted value.
	maxVerificationInput = 16 << 10
)

func validToken(t string) bool {
	return len(t) >= minTokenLen && len(t) <= maxTokenLen && plainToken.MatchString(t)
}

// ParseVerificationInput extracts the token from whatever was pasted: the bare
// token, or the console line(s) the capture snippet prints, or just the JSON.
//
// Proton's CAPTCHA sends TWO messages, and both are logged: a `proton_captcha` one
// (64 hex digits, not what the login wants) and the `pm_captcha` one, whose token is
// "<challenge id>:<CAPTCHA response>". If several lines are pasted at once the
// pm_captcha token wins wherever it appears; a lone proton_captcha line is refused
// with an explanation. The error never contains the input.
func ParseVerificationInput(input string) (string, error) {
	in := strings.TrimSpace(input)
	if in == "" || len(in) > maxVerificationInput {
		return "", ErrNoToken
	}
	if strings.Contains(in, "{") {
		type msg struct {
			Type    string `json:"type"`
			Token   string `json:"token"`
			Payload struct {
				Token string `json:"token"`
			} `json:"payload"`
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		var pm, other string
		sawProtonCaptcha := false
		for i := 0; i < len(in); i++ {
			if in[i] != '{' {
				continue
			}
			dec := json.NewDecoder(strings.NewReader(in[i:]))
			var v msg
			if err := dec.Decode(&v); err != nil {
				continue
			}
			i += int(dec.InputOffset()) - 1 // skip the object just read
			switch v.Type {
			case "pm_captcha":
				if t := strings.TrimSpace(v.Token); pm == "" && validToken(t) {
					pm = t
				}
			case "proton_captcha":
				sawProtonCaptcha = true
			default:
				for _, t := range []string{v.Payload.Token, v.Token, v.Data.Token} {
					if t = strings.TrimSpace(t); other == "" && validToken(t) {
						other = t
					}
				}
			}
		}
		switch {
		case pm != "":
			return pm, nil
		case other != "":
			return other, nil
		case sawProtonCaptcha:
			return "", ErrWrongMessage
		}
		return "", ErrNoToken
	}
	// Tolerate surrounding quotes and a leading "HV " label.
	in = strings.Trim(strings.TrimPrefix(in, "HV"), " \t\r\n\"'`")
	if validToken(in) {
		return in, nil
	}
	return "", ErrNoToken
}
