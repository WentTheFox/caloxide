package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	tokenSecret = "TOKEN-abc-SECRET-123"
	hookURL     = "https://discord.com/api/webhooks/123456/" + tokenSecret
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func reply(code int, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(""))}
}

// fakeDiscord swaps the transport only (keeping the production CheckRedirect) and
// captures every request and everything written to the log.
type fakeDiscord struct {
	requests []*http.Request
	bodies   [][]byte
	logs     bytes.Buffer
}

func newFake(t *testing.T, respond func(*http.Request) (*http.Response, error)) *fakeDiscord {
	t.Helper()
	f := &fakeDiscord{}
	old := discordClient.Transport
	discordClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		f.requests, f.bodies = append(f.requests, r), append(f.bodies, b)
		return respond(r)
	})
	log.SetOutput(&f.logs)
	t.Cleanup(func() { discordClient.Transport = old; log.SetOutput(os.Stderr) })
	t.Setenv("CALOXIDE_APPRISE_URL", "")
	t.Setenv(discordEnv, hookURL)
	t.Setenv(discordEnv+"_FILE", "")
	return f
}

func TestValidateDiscordURL(t *testing.T) {
	ok := []string{
		hookURL,
		"https://discordapp.com/api/webhooks/1/abc",
		"https://canary.discord.com/api/webhooks/1/abc",
		"https://DISCORD.com:443/api/webhooks/1/abc",
	}
	for _, u := range ok {
		if err := validateDiscordURL(u); err != nil {
			t.Errorf("%s should be valid: %v", u, err)
		}
	}
	bad := map[string]string{
		"http scheme":             "http://discord.com/api/webhooks/1/abc",
		"other host":              "https://example.com/api/webhooks/1/abc",
		"suffix lookalike":        "https://discord.com.evil.example/api/webhooks/1/abc",
		"prefix lookalike":        "https://evildiscord.com/api/webhooks/1/abc",
		"userinfo trick":          "https://discord.com@evil.example/api/webhooks/1/abc",
		"custom port":             "https://discord.com:8443/api/webhooks/1/abc",
		"fragment":                "https://discord.com/api/webhooks/1/abc#x",
		"wrong path":              "https://discord.com/api/channels/1/abc",
		"missing token":           "https://discord.com/api/webhooks/1",
		"extra segment":           "https://discord.com/api/webhooks/1/abc/slack",
		"empty id":                "https://discord.com/api/webhooks//abc",
		"not a url":               "::::",
		"loopback (for tests no)": "https://127.0.0.1/api/webhooks/1/abc",
	}
	for name, u := range bad {
		err := validateDiscordURL(u)
		if err == nil {
			t.Errorf("%s: %q must be rejected", name, u)
			continue
		}
		if strings.Contains(err.Error(), "abc") && strings.Contains(u, "abc") {
			t.Errorf("%s: error echoes the URL: %v", name, err)
		}
	}
}

func TestDiscordPayload(t *testing.T) {
	f := newFake(t, func(*http.Request) (*http.Response, error) { return reply(204, nil), nil })
	SendSync("failure", "caloxide: re-authentication failed", "Account \"me\": boom @everyone <@&123>")

	if len(f.requests) != 1 {
		t.Fatalf("want one request, got %d", len(f.requests))
	}
	r := f.requests[0]
	if r.Method != http.MethodPost || r.URL.String() != hookURL {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Host)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q", r.Header.Get("Content-Type"))
	}
	var got struct {
		Content         string `json:"content"`
		Username        string `json:"username"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal(f.bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Content, "re-authentication failed") || !strings.Contains(got.Content, "🚫") {
		t.Errorf("content = %q", got.Content)
	}
	if !strings.Contains(string(f.bodies[0]), `"parse":[]`) {
		t.Errorf("allowed_mentions.parse must be an explicit empty list so nothing can ping: %s", f.bodies[0])
	}
	if strings.Contains(f.logs.String(), tokenSecret) {
		t.Errorf("token reached the log: %s", f.logs.String())
	}
}

func TestDiscordContentIsTruncated(t *testing.T) {
	f := newFake(t, func(*http.Request) (*http.Response, error) { return reply(204, nil), nil })
	SendSync("info", "t", strings.Repeat("é", 5000))
	var got struct{ Content string }
	json.Unmarshal(f.bodies[0], &got)
	if n := utf8.RuneCountInString(got.Content); n > discordMaxContent || n < discordMaxContent-5 {
		t.Errorf("content has %d runes, want about %d", n, discordMaxContent)
	}
	if !utf8.ValidString(got.Content) {
		t.Error("truncation split a multi-byte character")
	}
}

func TestTokenNeverReachesTheLog(t *testing.T) {
	cases := map[string]func(*http.Request) (*http.Response, error){
		"transport error": func(r *http.Request) (*http.Response, error) { return nil, errors.New("connection refused") },
		"http 500":        func(*http.Request) (*http.Response, error) { return reply(500, nil), nil },
		"rate limited":    func(*http.Request) (*http.Response, error) { return reply(429, nil), nil },
	}
	for name, respond := range cases {
		f := newFake(t, respond)
		SendSync("failure", "t", "b")
		if f.logs.Len() == 0 {
			t.Errorf("%s: expected a log line", name)
		}
		if strings.Contains(f.logs.String(), tokenSecret) || strings.Contains(f.logs.String(), "/api/webhooks/") {
			t.Errorf("%s: webhook URL/token leaked into the log: %s", name, f.logs.String())
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	f := newFake(t, func(*http.Request) (*http.Response, error) {
		return reply(307, map[string]string{"Location": "https://evil.example/steal"}), nil
	})
	SendSync("failure", "t", "b")
	if len(f.requests) != 1 {
		t.Fatalf("a redirect was followed: %d requests", len(f.requests))
	}
	if !strings.Contains(f.logs.String(), "HTTP 307") {
		t.Errorf("log = %q", f.logs.String())
	}
}

func TestMisconfigurationNeverSends(t *testing.T) {
	f := newFake(t, func(*http.Request) (*http.Response, error) { return reply(204, nil), nil })

	t.Setenv(discordEnv, "https://evil.example/api/webhooks/1/"+tokenSecret)
	SendSync("failure", "t", "b")
	t.Setenv(discordEnv, hookURL)
	t.Setenv(discordEnv+"_FILE", "/some/file")
	SendSync("failure", "t", "b")
	t.Setenv(discordEnv, "")
	t.Setenv(discordEnv+"_FILE", filepath.Join(t.TempDir(), "missing"))
	SendSync("failure", "t", "b")

	if len(f.requests) != 0 {
		t.Fatalf("a misconfigured webhook must not send anything, got %d requests", len(f.requests))
	}
	if strings.Contains(f.logs.String(), tokenSecret) {
		t.Errorf("token leaked: %s", f.logs.String())
	}
}

func TestWebhookFromFile(t *testing.T) {
	f := newFake(t, func(*http.Request) (*http.Response, error) { return reply(204, nil), nil })
	path := filepath.Join(t.TempDir(), "hook")
	os.WriteFile(path, []byte("  "+hookURL+"\n"), 0o600)
	t.Setenv(discordEnv, "")
	t.Setenv(discordEnv+"_FILE", path)
	SendSync("success", "t", "b")
	if len(f.requests) != 1 || f.requests[0].URL.String() != hookURL {
		t.Fatalf("file-provided webhook not used: %+v", f.requests)
	}
}

func TestConfigured(t *testing.T) {
	t.Setenv("CALOXIDE_APPRISE_URL", "")
	t.Setenv(discordEnv, "")
	t.Setenv(discordEnv+"_FILE", "")
	if Configured() {
		t.Error("nothing configured, Configured() = true")
	}
	t.Setenv(discordEnv, hookURL)
	if !Configured() {
		t.Error("Discord configured but Configured() = false")
	}
}

func TestScrubDropsTheURL(t *testing.T) {
	err := &url.Error{Op: "Post", URL: hookURL, Err: errors.New("dial tcp: i/o timeout")}
	if got := scrub(err); strings.Contains(got.Error(), tokenSecret) || got.Error() != "dial tcp: i/o timeout" {
		t.Errorf("scrub = %q", got)
	}
	plain := errors.New("plain")
	if scrub(plain) != plain {
		t.Error("scrub must pass non-URL errors through")
	}
}

// The audit script only sees hosts written as https://... literals, so the webhook
// host allowlist (bare names in a map) is pinned here instead: widening it must be a
// deliberate change to this test too, visible in review.
func TestDiscordHostAllowlistIsPinned(t *testing.T) {
	want := map[string]bool{"discord.com": true, "canary.discord.com": true, "ptb.discord.com": true, "discordapp.com": true}
	if len(discordHosts) != len(want) {
		t.Fatalf("discordHosts has %d entries, want %d: %v", len(discordHosts), len(want), discordHosts)
	}
	for h := range want {
		if !discordHosts[h] {
			t.Errorf("%s missing from discordHosts", h)
		}
	}
}
