// Package cookiestore is an http.CookieJar whose contents can be exported and
// imported, so the cookies Proton's API sets (notably Session-Id, valid for 90
// days) survive a restart. Without it every login arrives as a brand-new,
// never-seen client, and Proton's anti-abuse checks answer with a CAPTCHA. The
// official Proton Bridge persists its cookies for the same reason.
//
// The exported bytes identify a client to Proton and must be stored with the same
// care as a session token (protoxide keeps them inside the encrypted auth.json).
package cookiestore

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxCookies = 50
	maxBytes   = 64 << 10
)

// ProtonHosts reports whether host belongs to Proton. Only these cookies are kept.
func ProtonHosts(host string) bool {
	host = strings.ToLower(host)
	return host == "proton.me" || strings.HasSuffix(host, ".proton.me")
}

type entry struct {
	Host     string
	Name     string
	Value    string
	Domain   string
	Path     string
	Expires  time.Time
	Secure   bool
	HttpOnly bool
	SameSite int
}

// Jar implements http.CookieJar. Only persistent cookies (with an expiry) for hosts
// accepted by allow are remembered for export; session cookies live as long as the
// process, as in a browser.
type Jar struct {
	allow func(host string) bool
	now   func() time.Time

	mu    sync.Mutex
	inner *cookiejar.Jar
	saved map[string]entry
}

// New returns an empty jar that persists cookies for hosts accepted by allow.
func New(allow func(host string) bool) *Jar {
	inner, _ := cookiejar.New(nil) // never fails with nil options
	return &Jar{allow: allow, now: time.Now, inner: inner, saved: map[string]entry{}}
}

func key(e entry) string { return strings.Join([]string{e.Host, e.Name, e.Domain, e.Path}, "\x00") }

// SetCookies implements http.CookieJar.
func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.inner.SetCookies(u, cookies)
	if !j.allow(u.Hostname()) {
		return
	}
	for _, c := range cookies {
		e := entry{Host: u.Hostname(), Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: int(c.SameSite)}
		switch {
		case c.MaxAge < 0:
			delete(j.saved, key(e)) // the server deleted it
			continue
		case c.MaxAge > 0:
			e.Expires = j.now().Add(time.Duration(c.MaxAge) * time.Second)
		case !c.Expires.IsZero():
			e.Expires = c.Expires
		default:
			continue // a session cookie: not persisted
		}
		if !e.Expires.After(j.now()) {
			delete(j.saved, key(e))
			continue
		}
		j.saved[key(e)] = e
	}
}

// Cookies implements http.CookieJar.
func (j *Jar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.inner.Cookies(u)
}

// Export returns the persistent, unexpired cookies as JSON, in a stable order.
func (j *Jar) Export() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]entry, 0, len(j.saved))
	for k, e := range j.saved {
		if !e.Expires.After(j.now()) {
			delete(j.saved, k)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return key(out[a]) < key(out[b]) })
	return json.Marshal(out)
}

// Names lists the names (never the values) of the persistent cookies held, sorted
// and de-duplicated, for diagnostics.
func (j *Jar) Names() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range j.saved {
		if e.Expires.After(j.now()) && !seen[e.Name] {
			seen[e.Name] = true
			out = append(out, e.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Import loads cookies produced by Export. Expired entries, entries for hosts the
// jar does not accept, and anything past the size limits are ignored. Empty input
// is not an error. Errors never contain cookie values.
func (j *Jar) Import(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) > maxBytes {
		return errors.New("cookiestore: saved cookies are too large")
	}
	var in []entry
	if err := json.Unmarshal(data, &in); err != nil {
		return errors.New("cookiestore: saved cookies are not valid")
	}
	if len(in) > maxCookies {
		in = in[:maxCookies]
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range in {
		if e.Name == "" || e.Host == "" || !j.allow(e.Host) || !e.Expires.After(j.now()) {
			continue
		}
		u := &url.URL{Scheme: "https", Host: e.Host, Path: "/"}
		j.inner.SetCookies(u, []*http.Cookie{{
			Name: e.Name, Value: e.Value, Domain: e.Domain, Path: e.Path, Expires: e.Expires,
			Secure: e.Secure, HttpOnly: e.HttpOnly, SameSite: http.SameSite(e.SameSite),
		}})
		j.saved[key(e)] = e
	}
	return nil
}
