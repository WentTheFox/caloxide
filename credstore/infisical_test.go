package credstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testClientID     = "client-id-123"
	testClientSecret = "SUPER-client-secret-456"
	testToken        = "access-token-789"
)

type fakeInfisical struct {
	srv     *httptest.Server
	secrets map[string]string // name -> value; absent = 404
	hidden  map[string]bool
	kinds   map[string]string // name -> type override
	logins  atomic.Int32
	gets    []*http.Request
}

func newFake(t *testing.T) *fakeInfisical {
	t.Helper()
	f := &fakeInfisical{secrets: map[string]string{}, hidden: map[string]bool{}, kinds: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeInfisical) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/universal-auth/login":
		f.logins.Add(1)
		var in struct{ ClientID, ClientSecret string }
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(b, &m)
		in.ClientID, in.ClientSecret = m["clientId"], m["clientSecret"]
		if in.ClientID != testClientID || in.ClientSecret != testClientSecret {
			http.Error(w, `{"message":"bad creds echoing `+in.ClientSecret+`"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"accessToken": testToken, "expiresIn": 7200, "tokenType": "Bearer"})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
		f.gets = append(f.gets, r.Clone(context.Background()))
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
		val, ok := f.secrets[name]
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		typ := "shared"
		if k, ok := f.kinds[name]; ok {
			typ = k
		}
		json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{
			"secretKey": name, "secretValue": val, "secretValueHidden": f.hidden[name], "type": typ,
		}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeInfisical) cfg() InfisicalConfig {
	return InfisicalConfig{
		BaseURL: f.srv.URL, ClientID: testClientID, ClientSecret: testClientSecret,
		ProjectID: "proj-1", Environment: "prod", SecretPath: "/protoxide",
	}
}

func newClient(t *testing.T, f *fakeInfisical) *Infisical {
	t.Helper()
	c, err := NewInfisical(f.cfg())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetAllSecretsAndRequestShape(t *testing.T) {
	f := newFake(t)
	f.secrets[NameUsername] = "me@example.com"
	f.secrets[NameLoginPassword] = "pw"
	f.secrets[NameMailboxPassword] = "mbox"
	f.secrets[NameTOTPSecret] = "JBSWY3DPEHPK3PXP"
	f.secrets[NameDiscordWebhook] = "https://discord.com/api/webhooks/1/tok"

	got, err := newClient(t, f).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := Secrets{Username: "me@example.com", LoginPassword: "pw", MailboxPassword: "mbox", TOTPSecret: "JBSWY3DPEHPK3PXP",
		DiscordWebhookURL: "https://discord.com/api/webhooks/1/tok"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if n := f.logins.Load(); n != 1 {
		t.Errorf("expected exactly one login per Get, got %d", n)
	}
	if len(f.gets) != 5 {
		t.Fatalf("expected 5 secret reads, got %d", len(f.gets))
	}
	q := f.gets[0].URL.Query()
	for k, v := range map[string]string{
		"workspaceId": "proj-1", "environment": "prod", "secretPath": "/protoxide",
		"type": "shared", "viewSecretValue": "true", "expandSecretReferences": "false",
	} {
		if q.Get(k) != v {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), v)
		}
	}
}

func TestOptionalSecretsMayBeAbsentOrEmpty(t *testing.T) {
	f := newFake(t)
	f.secrets[NameLoginPassword] = "pw"
	f.secrets[NameTOTPSecret] = "" // empty counts as absent
	got, err := newClient(t, f).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.LoginPassword != "pw" || got.MailboxPassword != "" || got.TOTPSecret != "" {
		t.Errorf("unexpected result %+v", got)
	}
}

// Requiring the login password is the caller's job (auth.reloginer); the store
// reports whatever exists so `protoxide auth` can prompt for just the rest.
func TestEverySecretIsOptionalAtTheStoreLevel(t *testing.T) {
	f := newFake(t)
	got, err := newClient(t, f).Get(context.Background())
	if err != nil {
		t.Fatalf("an empty folder must not be an error: %v", err)
	}
	if got != (Secrets{}) {
		t.Errorf("want zero Secrets, got %+v", got)
	}
}

func TestBadCredentialsDoNotLeak(t *testing.T) {
	f := newFake(t)
	cfg := f.cfg()
	cfg.ClientSecret = "WRONG-secret-xyz"
	c, err := NewInfisical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if err == nil {
		t.Fatal("expected a login failure")
	}
	for _, leak := range []string{"WRONG-secret-xyz", testClientSecret, testToken} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should carry the status code: %v", err)
	}
}

func TestHiddenValueIsAnError(t *testing.T) {
	f := newFake(t)
	f.secrets[NameLoginPassword] = ""
	f.hidden[NameLoginPassword] = true
	if _, err := newClient(t, f).Get(context.Background()); err == nil || !strings.Contains(err.Error(), "not read its value") {
		t.Fatalf("want a 'cannot read value' error, got %v", err)
	}
}

func TestPersonalSecretRejected(t *testing.T) {
	f := newFake(t)
	f.secrets[NameLoginPassword] = "pw"
	f.kinds[NameLoginPassword] = "personal"
	if _, err := newClient(t, f).Get(context.Background()); err == nil {
		t.Fatal("a personal-type secret must be rejected")
	}
}

func TestRedirectIsRefusedAndNotFollowed(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()

	c, err := NewInfisical(InfisicalConfig{BaseURL: redir.URL, ClientID: "a", ClientSecret: "b", ProjectID: "p", Environment: "e"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("want a redirect refusal, got %v", err)
	}
	if evilHits.Load() != 0 {
		t.Fatal("the client followed a redirect and sent credentials to another host")
	}
}

func TestOversizeResponseRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accessToken":"` + strings.Repeat("A", maxResponseSize+10) + `"}`))
	}))
	defer srv.Close()
	c, _ := NewInfisical(InfisicalConfig{BaseURL: srv.URL, ClientID: "a", ClientSecret: "b", ProjectID: "p", Environment: "e"})
	if _, err := c.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want 'too large', got %v", err)
	}
}

func TestContextCancellationStopsSlowServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release) // runs first, so Close does not wait on the blocked handler
	c, _ := NewInfisical(InfisicalConfig{BaseURL: srv.URL, ClientID: "a", ClientSecret: "b", ProjectID: "p", Environment: "e"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Get(ctx); err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("context cancellation was not honoured")
	}
}

func TestNewInfisicalValidation(t *testing.T) {
	ok := InfisicalConfig{BaseURL: "https://infisical.example.lan", ClientID: "a", ClientSecret: "b", ProjectID: "p", Environment: "e"}
	if _, err := NewInfisical(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*InfisicalConfig){
		"plain http to a LAN host": func(c *InfisicalConfig) { c.BaseURL = "http://infisical.went.local" },
		"credentials in URL":       func(c *InfisicalConfig) { c.BaseURL = "https://user:pw@host" },
		"query in URL":             func(c *InfisicalConfig) { c.BaseURL = "https://host/?a=b" },
		"fragment in URL":          func(c *InfisicalConfig) { c.BaseURL = "https://host/#x" },
		"unsupported scheme":       func(c *InfisicalConfig) { c.BaseURL = "ftp://host" },
		"no host":                  func(c *InfisicalConfig) { c.BaseURL = "https://" },
		"missing client id":        func(c *InfisicalConfig) { c.ClientID = " " },
		"missing client secret":    func(c *InfisicalConfig) { c.ClientSecret = "" },
		"missing project":          func(c *InfisicalConfig) { c.ProjectID = "" },
		"missing environment":      func(c *InfisicalConfig) { c.Environment = "" },
	} {
		c := ok
		mutate(&c)
		if _, err := NewInfisical(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8093", "http://localhost:8093", "http://[::1]:8093"} {
		c := ok
		c.BaseURL = u
		if _, err := NewInfisical(c); err != nil {
			t.Errorf("loopback %s should be allowed over http: %v", u, err)
		}
	}
}

func TestCallerHTTPClientNotMutated(t *testing.T) {
	hc := &http.Client{Timeout: time.Hour}
	_, err := NewInfisical(InfisicalConfig{BaseURL: "https://h", ClientID: "a", ClientSecret: "b", ProjectID: "p", Environment: "e", HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	if hc.Timeout != time.Hour || hc.CheckRedirect != nil {
		t.Error("NewInfisical modified the caller's http.Client")
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{
		"PROTOXIDE_INFISICAL_URL":           "https://infisical.example.lan",
		"PROTOXIDE_INFISICAL_CLIENT_ID":     "id",
		"PROTOXIDE_INFISICAL_CLIENT_SECRET": "",
		"PROTOXIDE_INFISICAL_PROJECT_ID":    "p",
		"PROTOXIDE_INFISICAL_ENV":           "prod",
	}
	files := map[string]string{"/run/secrets/cs": "  from-file\n"}
	getenv := func(k string) string { return env[k] }
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}

	env["PROTOXIDE_INFISICAL_CLIENT_SECRET_FILE"] = "/run/secrets/cs"
	c, err := infisicalFromEnv(getenv, readFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.ClientSecret != "from-file" {
		t.Errorf("file value not trimmed/used: %q", c.cfg.ClientSecret)
	}
	if c.cfg.SecretPath != "/" {
		t.Errorf("default secret path = %q, want /", c.cfg.SecretPath)
	}

	env["PROTOXIDE_INFISICAL_CLIENT_SECRET"] = "direct"
	if _, err := infisicalFromEnv(getenv, readFile); err == nil {
		t.Error("setting both X and X_FILE must be an error")
	}

	env["PROTOXIDE_INFISICAL_CLIENT_SECRET"] = ""
	env["PROTOXIDE_INFISICAL_CLIENT_SECRET_FILE"] = "/nope"
	if _, err = infisicalFromEnv(getenv, readFile); err == nil {
		t.Error("an unreadable _FILE must be an error")
	}
}

func TestFromEnvBackendSelection(t *testing.T) {
	readFile := func(string) ([]byte, error) { return nil, errors.New("unused") }
	base := map[string]string{
		"PROTOXIDE_INFISICAL_URL": "https://infisical.example.lan", "PROTOXIDE_INFISICAL_CLIENT_ID": "id",
		"PROTOXIDE_INFISICAL_CLIENT_SECRET": "s", "PROTOXIDE_INFISICAL_PROJECT_ID": "p", "PROTOXIDE_INFISICAL_ENV": "prod",
	}
	with := func(backend string) func(string) string {
		return func(k string) string {
			if k == BackendEnv {
				return backend
			}
			return base[k]
		}
	}
	for _, b := range []string{"", "local"} {
		p, err := fromEnv(with(b), readFile)
		if err != nil || p != nil {
			t.Errorf("backend %q: got (%v, %v), want (nil, nil)", b, p, err)
		}
	}
	p, err := fromEnv(with("infisical"), readFile)
	if err != nil || p == nil {
		t.Errorf("infisical: got (%v, %v)", p, err)
	}
	if _, err := fromEnv(with("vault"), readFile); err == nil {
		t.Error("an unknown backend must be an error, not a silent fallback to local")
	}
	if _, err := fromEnv(func(k string) string {
		if k == BackendEnv {
			return "infisical"
		}
		return ""
	}, readFile); err == nil {
		t.Error("infisical without its settings must be an error")
	}
}

func TestDescribeNeverPrintsValues(t *testing.T) {
	out := Secrets{Username: "me@example.com", LoginPassword: "hunter2-xq", TOTPSecret: "JBSWY3DPEHPK3PXP",
		DiscordWebhookURL: "https://discord.com/api/webhooks/1/hooktoken"}.Describe()
	for _, leak := range []string{"me@example", "hunter2", "xq", "JBSWY3DP", "hooktoken", "discord.com", "16", "10"} {
		if strings.Contains(out, leak) {
			t.Errorf("Describe leaks %q: %s", leak, out)
		}
	}
	for _, want := range []string{NameUsername + ": present", NameLoginPassword + ": present", NameMailboxPassword + ": missing", NameTOTPSecret + ": present", NameDiscordWebhook + ": present"} {
		if !strings.Contains(out, want) {
			t.Errorf("Describe missing %q in:\n%s", want, out)
		}
	}
}
