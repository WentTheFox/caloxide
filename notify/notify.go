// Package notify delivers best-effort operational alerts to an Apprise endpoint
// (which can fan out to ntfy and anything else Apprise supports) and/or a Discord
// webhook. It is a no-op unless one is configured, never blocks the caller, and
// never returns an error — alerting must never be able to break the bridge.
//
// Configuration (environment):
//
//	CALOXIDE_DISCORD_WEBHOOK_URL   A Discord webhook URL. It contains a secret
//	                                token, so CALOXIDE_DISCORD_WEBHOOK_URL_FILE
//	                                (a path, for Docker secrets) is also accepted.
//	                                Only https URLs on discord.com with the path
//	                                /api/webhooks/<id>/<token> are accepted.
//
//	CALOXIDE_APPRISE_URL   Apprise notify endpoint. For a persistent Apprise
//	                        config this is http://<host>:8000/notify/<key>.
//	CALOXIDE_APPRISE_URLS  Optional. For Apprise's stateless endpoint
//	                        (http://<host>:8000/notify), the target URL(s), e.g.
//	                        "ntfy://<host>/caloxide". Included as "urls" in the body.
package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mathewcsims/protoxide/config"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// debounce suppresses repeated alerts sharing a key, so a persistent fault (e.g.
// an expired session hit on every client poll) produces one alert, not a flood.
const debounce = 10 * time.Minute

var (
	mu       sync.Mutex
	lastSent = map[string]time.Time{}
	client   = &http.Client{Timeout: 10 * time.Second}

	// discordClient never follows redirects: the webhook token must only ever be
	// sent to the host it was validated against.
	discordClient = &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
)

const (
	discordEnv = "CALOXIDE_DISCORD_WEBHOOK_URL"
	// Discord rejects messages over 2000 characters.
	discordMaxContent = 1900
)

// discordHosts are the only hosts a webhook URL may point at.
var discordHosts = map[string]bool{
	"discord.com": true, "canary.discord.com": true, "ptb.discord.com": true, "discordapp.com": true,
}

func endpoint() string { return config.Getenv("CALOXIDE_APPRISE_URL") }

// Configured reports whether any alert sink is enabled.
func Configured() bool {
	return endpoint() != "" || config.Getenv(discordEnv) != "" || config.Getenv(discordEnv+"_FILE") != ""
}

// scrub drops the request URL from a transport error: webhook URLs and Apprise
// keys are secrets and must not reach the logs.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// validateDiscordURL accepts only https://<discord host>/api/webhooks/<id>/<token>.
// The error never contains the URL.
func validateDiscordURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("must be an https URL")
	}
	if u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("must not contain credentials, a fragment or a custom port")
	}
	if !discordHosts[strings.ToLower(u.Hostname())] {
		return errors.New("host must be discord.com")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "webhooks" || parts[2] == "" || parts[3] == "" {
		return errors.New("path must be /api/webhooks/<id>/<token>")
	}
	return nil
}

// discordURL resolves the webhook from the environment, or from the file named by
// the _FILE variant. ("", nil) means Discord is not configured.
func discordURL() (string, error) {
	direct, file := config.Getenv(discordEnv), config.Getenv(discordEnv+"_FILE")
	if direct != "" && file != "" {
		return "", fmt.Errorf("%s and %s_FILE are both set; use one", discordEnv, discordEnv)
	}
	if direct == "" && file == "" {
		return "", nil
	}
	raw := direct
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: could not read file", discordEnv)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return "", nil
	}
	if err := validateDiscordURL(raw); err != nil {
		return "", fmt.Errorf("%s: %v", discordEnv, err)
	}
	return raw, nil
}

// Send delivers an alert. typ is an Apprise type ("info", "success", "warning",
// "failure"). key debounces repeated alerts of the same kind. It returns
// immediately; delivery happens on a background goroutine.
func Send(typ, key, title, body string) {
	if !Configured() {
		return
	}
	mu.Lock()
	if t, ok := lastSent[key]; ok && time.Since(t) < debounce {
		mu.Unlock()
		return
	}
	lastSent[key] = time.Now()
	mu.Unlock()

	go post(typ, title, body)
}

// SendSync delivers an alert immediately on the calling goroutine, bypassing the
// debounce. Use for one-shot terminal events (e.g. a fatal exit) where the
// process may not live long enough for a background goroutine to run.
func SendSync(typ, title, body string) {
	if !Configured() {
		return
	}
	post(typ, title, body)
}

// emojiPrefix matches the self-hosted stack's notification convention of
// prefixing the title with a severity emoji for at-a-glance scanning in the
// shared Discord/ntfy feed.
func emojiPrefix(typ string) string {
	switch typ {
	case "failure":
		return "🚫 "
	case "warning":
		return "⚠️ "
	case "success":
		return "✅ "
	default:
		return "🔔 "
	}
}

// post delivers to every configured sink; one failing never affects the other.
func post(typ, title, body string) {
	if endpoint() != "" {
		postApprise(typ, title, body)
	}
	hook, err := discordURL()
	if err != nil {
		log.Printf("notify: Discord disabled: %v", err)
		return
	}
	if hook != "" {
		postDiscord(hook, typ, title, body)
	}
}

// truncate shortens s to at most max runes.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

func postDiscord(hook, typ, title, body string) {
	payload := map[string]any{
		"username": "caloxide",
		"content":  truncate(fmt.Sprintf("**%s%s**\n%s", emojiPrefix(typ), title, body), discordMaxContent),
		// Alert text can contain arbitrary strings from Proton's API; never let
		// it ping @everyone, roles or users.
		"allowed_mentions": map[string][]string{"parse": {}},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, hook, bytes.NewReader(buf))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := discordClient.Do(req)
	if err != nil {
		log.Printf("notify: could not reach Discord: %v", scrub(err))
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		log.Printf("notify: Discord rate-limited the webhook (HTTP 429); alert dropped")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		log.Printf("notify: Discord rejected the webhook (HTTP %d)", resp.StatusCode)
	}
}

func postApprise(typ, title, body string) {
	payload := map[string]string{"title": emojiPrefix(typ) + title, "body": body, "type": typ}
	if urls := config.Getenv("CALOXIDE_APPRISE_URLS"); urls != "" {
		payload["urls"] = urls
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, endpoint(), bytes.NewReader(buf))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("notify: could not reach Apprise: %v", scrub(err))
		return
	}
	resp.Body.Close()
}
