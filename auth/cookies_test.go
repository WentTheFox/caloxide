package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mathewcsims/protoxide/config"
	"github.com/mathewcsims/protoxide/cookiestore"
	"github.com/mathewcsims/protoxide/protonmail"
)

func anyHost(string) bool { return true } // the test server is on 127.0.0.1

// fakeProton hands out a Session-Id cookie on first contact and records what each
// request presented, like Proton's API does.
type fakeProton struct {
	mu       sync.Mutex
	presents []string // Session-Id value presented per request ("" = none)
	srv      *httptest.Server
}

func newFakeProton(t *testing.T) *fakeProton {
	f := &fakeProton{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := ""
		if c, err := r.Cookie("Session-Id"); err == nil {
			got = c.Value
		}
		f.mu.Lock()
		f.presents = append(f.presents, got)
		f.mu.Unlock()
		if got == "" {
			http.SetCookie(w, &http.Cookie{Name: "Session-Id", Value: "device-1", Path: "/", MaxAge: 7776000, HttpOnly: true})
		}
		fmt.Fprint(w, `{"Code":1000,"User":{"Keys":[]}}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProton) client() *protonmail.Client {
	return &protonmail.Client{RootURL: f.srv.URL, HTTPClient: f.srv.Client()}
}

func TestCookiesSurviveARestartThroughTheSessionRecord(t *testing.T) {
	proton := newFakeProton(t)

	// First run: a brand-new client; Proton sets Session-Id.
	c1 := proton.client()
	jar1 := attachCookieJar(c1, nil, anyHost)
	if _, err := c1.GetCurrentUser(); err != nil {
		t.Fatal(err)
	}
	saved, err := jar1.Export()
	if err != nil {
		t.Fatal(err)
	}

	// The cookies travel inside the encrypted session record (JSON round trip).
	blob, _ := json.Marshal(&CachedAuth{Cookies: saved})
	var restored CachedAuth
	if err := json.Unmarshal(blob, &restored); err != nil {
		t.Fatal(err)
	}

	// After a restart: a new client, seeded from the record, presents the same id,
	// and so does the detached client used for re-authentication.
	c2 := proton.client()
	attachCookieJar(c2, restored.Cookies, anyHost)
	if _, err := c2.GetCurrentUser(); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Detached().GetCurrentUser(); err != nil {
		t.Fatal(err)
	}

	proton.mu.Lock()
	defer proton.mu.Unlock()
	want := []string{"", "device-1", "device-1"}
	if fmt.Sprint(proton.presents) != fmt.Sprint(want) {
		t.Errorf("Session-Id presented per request = %q, want %q", proton.presents, want)
	}
}

func TestAttachCookieJarDoesNotMutateTheCallersHTTPClient(t *testing.T) {
	shared := &http.Client{}
	c := &protonmail.Client{HTTPClient: shared}
	attachCookieJar(c, nil, anyHost)
	if shared.Jar != nil {
		t.Error("the caller's http.Client was modified")
	}
	if c.HTTPClient == shared || c.HTTPClient.Jar == nil {
		t.Error("the client did not get its own jar-carrying http.Client")
	}
	if (&protonmail.Client{}).HTTPClient != nil {
		t.Fatal("test assumption")
	}
	nilClient := &protonmail.Client{}
	attachCookieJar(nilClient, nil, anyHost)
	if nilClient.HTTPClient == nil || nilClient.HTTPClient.Jar == nil {
		t.Error("a client without an http.Client must get one")
	}
}

func TestGarbageSavedCookiesAreIgnored(t *testing.T) {
	proton := newFakeProton(t)
	c := proton.client()
	attachCookieJar(c, []byte("definitely not json"), anyHost)
	if _, err := c.GetCurrentUser(); err != nil {
		t.Fatalf("unreadable saved cookies must not break the client: %v", err)
	}
}

func TestCookiesSurviveWithoutSecrets(t *testing.T) {
	c := &CachedAuth{LoginPassword: "p", Cookies: []byte(`[]`)}
	if got := c.WithoutSecrets(); string(got.Cookies) != "[]" || got.LoginPassword != "" {
		t.Errorf("WithoutSecrets must keep the cookies and drop only the passwords: %+v", got)
	}
}

func TestPersistSessionStoresCookiesEncryptedAndKeepsPasswordsOutWhenBackendIsOn(t *testing.T) {
	config.SetConfigHome(t.TempDir())
	var key [32]byte
	key[0] = 9

	jar := cookiestore.New(anyHost)
	u := &url.URL{Scheme: "https", Host: "127.0.0.1", Path: "/"}
	jar.SetCookies(u, []*http.Cookie{{Name: "Session-Id", Value: "device-1", Path: "/", MaxAge: 7776000}})

	m := NewManager(func() *protonmail.Client { return &protonmail.Client{} })
	m.UseSecrets(&fakeProvider{})
	cached := &CachedAuth{Auth: protonmail.Auth{RefreshToken: "r"}, LoginPassword: "PW"}
	if err := m.persistSession(cached, jar, "me", &key); err != nil {
		t.Fatal(err)
	}

	auths, err := readCachedAuths()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auths["me"], "device-1") {
		t.Error("the stored record is not encrypted: the cookie value is visible")
	}
	plain, err := decrypt(auths["me"], &key)
	if err != nil {
		t.Fatal(err)
	}
	var got CachedAuth
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got.Cookies), "device-1") {
		t.Errorf("cookies were not written into the session record: %s", got.Cookies)
	}
	if got.LoginPassword != "" {
		t.Error("the password reached disk although a secrets backend is configured")
	}
}
