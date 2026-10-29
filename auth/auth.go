package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/cookiestore"
	"github.com/mathewcsims/protoxide/protonmail"
)

func authFilePath() (string, error) {
	return config.Path("auth.json")
}

type CachedAuth struct {
	protonmail.Auth
	LoginPassword   string
	MailboxPassword string
	KeySalts        map[string][]byte
	// TOTPSecret is the base32 seed of the account's authenticator, so a dead session
	// can be renewed without a person typing a code. Optional; it lives only in this
	// encrypted record (the key is the bridge password, which only the client supplies).
	TOTPSecret string
	// Cookies are the persistent cookies Proton's API set (see package cookiestore),
	// so a later login presents the same Session-Id as an earlier one. They identify
	// this client to Proton, so they live in this encrypted record like the tokens.
	Cookies []byte
	// TODO: add padding
}

// attachCookieJar gives c a cookie jar seeded from saved and returns it, so the
// caller can export it again when the session is stored. The jar is attached to a
// copy of c's http.Client, and the detached clients used for re-authentication
// inherit it. A saved value that cannot be read is ignored, never fatal.
func attachCookieJar(c *protonmail.Client, saved []byte, allow func(host string) bool) *cookiestore.Jar {
	jar := cookiestore.New(allow)
	if err := jar.Import(saved); err != nil {
		log.Printf("cookies: ignoring unreadable saved cookies: %v", err)
	} else if names := jar.Names(); len(names) > 0 {
		log.Printf("cookies: restored saved Proton cookies: %s", strings.Join(names, ", "))
	} else {
		log.Printf("cookies: none saved yet; Proton will see a brand-new client until the next login stores them")
	}
	hc := http.Client{}
	if c.HTTPClient != nil {
		hc = *c.HTTPClient
	}
	hc.Jar = jar
	c.HTTPClient = &hc
	return jar
}

// NewCookieJar attaches an empty jar for Proton's hosts to c, for the interactive
// login: the cookies it collects are stored with the session (CachedAuth.Cookies).
func NewCookieJar(c *protonmail.Client) *cookiestore.Jar {
	return attachCookieJar(c, nil, cookiestore.ProtonHosts)
}

func readCachedAuths() (map[string]string, error) {
	p, err := authFilePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get auth file path: %v", err)
	}

	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to open cached auth file: %v", err)
	}
	defer f.Close()

	auths := make(map[string]string)
	if err := json.NewDecoder(f).Decode(&auths); err != nil {
		return nil, fmt.Errorf("failed to read cached auth file: %v", err)
	}

	return auths, nil
}

func saveAuths(auths map[string]string) error {
	p, err := authFilePath()
	if err != nil {
		return fmt.Errorf("failed to get auth file path: %v", err)
	}
	// 0600: the session (encrypted at rest, but still a long-lived credential)
	// must not be readable by other local users.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create cached auth file: %v", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(auths); err != nil {
		return fmt.Errorf("failed to write cached auth file: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close cached auth file: %v", err)
	}
	return nil
}

func encrypt(msg []byte, secretKey *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := secretbox.Seal(nonce[:], msg, &nonce, secretKey)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(encryptedString string, secretKey *[32]byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted string: %v", err)
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

func EncryptAndSave(auth *CachedAuth, username string, secretKey *[32]byte) error {
	cleartext, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("failed to format cached auth: %v", err)
	}

	encrypted, err := encrypt(cleartext, secretKey)
	if err != nil {
		return err
	}

	auths, err := readCachedAuths()
	if err != nil {
		return err
	}

	if auths == nil {
		auths = make(map[string]string)
	}
	auths[username] = encrypted

	return saveAuths(auths)
}

// authenticate unlocks the session, refreshing or re-establishing it as needed.
// rl is nil unless a secrets backend is configured; without it a dead refresh token
// is handled with the cached password exactly as before (and 2FA needs a human).
func authenticate(c protonAPI, cachedAuth *CachedAuth, username string, rl *reloginer) (openpgp.EntityList, error) {
	// While unattended re-login is paused (CAPTCHA pending, backing off, cap reached)
	// do not touch Proton at all, not even the refresh endpoint.
	if rl != nil {
		if err := rl.blocked(); err != nil {
			return nil, err
		}
	}
	// Use the stored access token directly first. Refreshing prematurely discards
	// a still-valid token, and Proton's refresh endpoint is currently unreliable
	// for third-party sessions; the client's own 401 handler will refresh only
	// once the token has actually expired.
	if cachedAuth.Auth.AccessToken != "" {
		c.SetSession(cachedAuth.Auth.UID, cachedAuth.Auth.AccessToken)
		if keyRing, err := c.Unlock(&cachedAuth.Auth, cachedAuth.KeySalts, cachedAuth.MailboxPassword); err == nil {
			return keyRing, nil
		}
	}

	auth, err := c.AuthRefresh(&cachedAuth.Auth)
	if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == apiCodeInvalidRefreshToken {
		// Invalid refresh token, re-authenticate. The client still holds the dead
		// access token from the attempt above; /auth/info and /auth are anonymous
		// requests and Proton answers 401 "Invalid access token" if one is attached.
		c.SetSession("", "")
		if rl != nil {
			if auth, err = rl.reauth(c, cachedAuth, username); err != nil {
				return nil, err
			}
		} else {
			if cachedAuth.LoginPassword == "" {
				return nil, fmt.Errorf("cannot re-authenticate: no password is stored; run `protoxide auth %s`", username)
			}
			authInfo, err := c.AuthInfo(username)
			if err != nil {
				return nil, fmt.Errorf("cannot re-authenticate: failed to get auth info: %v", err)
			}

			auth, err = c.Auth(username, cachedAuth.LoginPassword, authInfo)
			if err != nil {
				return nil, fmt.Errorf("cannot re-authenticate: %v", err)
			}

			if auth.TwoFactor.Enabled != 0 {
				return nil, fmt.Errorf("cannot re-authenticate: two factor authentication enabled, please login again manually")
			}
		}
	} else if err != nil {
		return nil, err
	}
	cachedAuth.Auth = *auth

	return c.Unlock(auth, cachedAuth.KeySalts, cachedAuth.MailboxPassword)
}

// reauthenticate runs authenticate on a detached client (one with no ReAuth of its
// own) and, on success, hands the session and unlocked keys to c. Running it on c
// directly recursed forever when the stored access token had expired: Unlock got a
// 401, which called ReAuth, which called authenticate, which called Unlock again.
func reauthenticate(c *protonmail.Client, cached *CachedAuth, username string, rl *reloginer) (openpgp.EntityList, error) {
	d := c.Detached()
	keys, err := authenticate(d, cached, username, rl)
	if err != nil {
		return nil, err
	}
	c.AdoptSession(d)
	return keys, nil
}

func ListUsernames() ([]string, error) {
	auths, err := readCachedAuths()
	if err != nil {
		return nil, err
	}

	l := make([]string, 0, len(auths))
	for username := range auths {
		l = append(l, username)
	}
	return l, nil
}

func GeneratePassword() (secretKey *[32]byte, password string, err error) {
	var key [32]byte
	if _, err = io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %v", err)
	}
	password = base64.StdEncoding.EncodeToString(key[:])
	return &key, password, nil
}

// session is one account's state inside the process. It can exist before it is
// ready: opening it only decrypts auth.json (no network), so the bridge password can
// be checked, and the web verification page can finish a login, even when the very
// first attempt to establish the session was stopped by a CAPTCHA.
type session struct {
	username        string
	hashedSecretKey []byte
	key             [32]byte // the bridge password's key; in memory only, as before
	c               *protonmail.Client
	jar             *cookiestore.Jar

	// mu serialises re-authentication and web verification, and guards the fields
	// below. Lock order is always session.mu, then reloginer.mu.
	mu          sync.Mutex
	cached      CachedAuth
	privateKeys openpgp.EntityList
	ready       bool
	challenge   *verifyChallenge
}

var ErrUnauthorized = errors.New("invalid username or password")

type Manager struct {
	newClient func() *protonmail.Client
	mu        sync.Mutex // guards sessions, and serialises opening and establishing them
	sessions  map[string]*session

	// rl is non-nil once EnableRelogin has been called (the caldav server does).
	rl *reloginer

	// Seams so the web verification flow can be tested without Proton's SRP login.
	detach func(c *protonmail.Client) authAPI
	adopt  func(c *protonmail.Client, d authAPI)
	now    func() time.Time

	// The verification window (see verify.go) has its own lock so that checking a
	// URL token never waits for a login in progress.
	wmu sync.Mutex
	win *verifyWindow
}

// EnableRelogin turns on unattended re-login from the credentials stored in
// auth.json: a dead refresh token is replaced by a fresh login (answering a TOTP
// challenge from the stored seed), with exponential backoff, a cap on logins, and a
// full stop when Proton demands a CAPTCHA. It also gates requests while paused and
// makes the one-time web verification available. Call before the first Auth.
func (m *Manager) EnableRelogin() {
	m.rl = newReloginer()
}

// ReloginEnabled reports whether EnableRelogin was called.
func (m *Manager) ReloginEnabled() bool { return m.rl != nil }

// persistSession stores the session together with the jar's current cookies.
func (m *Manager) persistSession(c *CachedAuth, jar *cookiestore.Jar, username string, key *[32]byte) error {
	if b, err := jar.Export(); err == nil {
		c.Cookies = b
	}
	return EncryptAndSave(c, username, key)
}

// persist stores s. The caller holds s.mu.
func (m *Manager) persist(s *session) error {
	return m.persistSession(&s.cached, s.jar, s.username, &s.key)
}

// openSession returns the account's session, creating it from auth.json if needed.
// It verifies the bridge password but never touches the network. The caller holds
// m.mu.
func (m *Manager) openSession(username, password string) (*session, error) {
	var secretKey [32]byte
	passwordBytes, err := base64.StdEncoding.DecodeString(password)
	if err != nil || len(passwordBytes) != len(secretKey) {
		return nil, ErrUnauthorized
	}
	copy(secretKey[:], passwordBytes)

	if s, ok := m.sessions[username]; ok {
		if err := bcrypt.CompareHashAndPassword(s.hashedSecretKey, secretKey[:]); err != nil {
			return nil, ErrUnauthorized
		}
		return s, nil
	}

	auths, err := readCachedAuths()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	encrypted, ok := auths[username]
	if !ok {
		return nil, ErrUnauthorized
	}
	decrypted, err := decrypt(encrypted, &secretKey)
	if err != nil {
		return nil, ErrUnauthorized
	}
	var cachedAuth CachedAuth
	if err := json.Unmarshal(decrypted, &cachedAuth); err != nil {
		return nil, err
	}
	hashed, err := bcrypt.GenerateFromPassword(secretKey[:], bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	c := m.newClient()
	if m.rl != nil {
		// Authenticated requests fail locally while re-login is paused, instead of
		// hammering Proton with a dead token (see reloginer.blocked).
		c.Gate = m.rl.blocked
	}
	s := &session{
		username:        username,
		hashedSecretKey: hashed,
		key:             secretKey,
		c:               c,
		cached:          cachedAuth,
	}
	s.jar = attachCookieJar(c, cachedAuth.Cookies, cookiestore.ProtonHosts)
	// ReAuth runs on a 401 from any goroutine using this client (requests, the
	// event poller); serialise it, since it rewrites s.cached.
	c.ReAuth = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, err := reauthenticate(c, &s.cached, username, m.rl); err != nil {
			return err
		}
		return m.persist(s)
	}
	m.sessions[username] = s
	return s, nil
}

// establish makes s usable by authenticating it.
// A failure leaves the session open but not ready, and a later call tries again
// unless re-login is paused. The caller holds m.mu.
func (m *Manager) establish(s *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return nil
	}
	if m.rl != nil {
		if err := m.rl.blocked(); err != nil {
			return err
		}
	}
	// reauthenticate updates s.cached with the new refresh token. c is not shared
	// with other goroutines yet, so no extra lock is needed beyond s.mu.
	keys, err := reauthenticate(s.c, &s.cached, s.username, m.rl)
	if err != nil {
		return err
	}
	if err := m.persist(s); err != nil {
		return err
	}
	s.privateKeys = keys
	s.ready = true
	return nil
}

func (m *Manager) Auth(username, password string) (*protonmail.Client, openpgp.EntityList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.openSession(username, password)
	if err != nil {
		return nil, nil, err
	}
	if err := m.establish(s); err != nil {
		return nil, nil, err
	}
	return s.c, s.privateKeys, nil
}

func NewManager(newClient func() *protonmail.Client) *Manager {
	return &Manager{
		newClient: newClient,
		sessions:  make(map[string]*session),
		now:       time.Now,
		detach:    func(c *protonmail.Client) authAPI { return c.Detached() },
		adopt: func(c *protonmail.Client, d authAPI) {
			if dc, ok := d.(*protonmail.Client); ok {
				c.AdoptSession(dc)
			}
		},
	}
}
