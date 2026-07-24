// Package notify delivers best-effort operational alerts to an Apprise endpoint
// (which can fan out to ntfy and anything else Apprise supports). It is a no-op
// unless PROTOXIDE_APPRISE_URL is set, never blocks the caller, and never returns
// an error — alerting must never be able to break the bridge.
//
// Configuration (environment):
//
//	PROTOXIDE_APPRISE_URL   Apprise notify endpoint. For a persistent Apprise
//	                        config this is http://<host>:8000/notify/<key>.
//	PROTOXIDE_APPRISE_URLS  Optional. For Apprise's stateless endpoint
//	                        (http://<host>:8000/notify), the target URL(s), e.g.
//	                        "ntfy://<host>/protoxide". Included as "urls" in the body.
package notify

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
)

func endpoint() string { return os.Getenv("PROTOXIDE_APPRISE_URL") }

// Configured reports whether alerting is enabled.
func Configured() bool { return endpoint() != "" }

// Send delivers an alert. typ is an Apprise type ("info", "success", "warning",
// "failure"). key debounces repeated alerts of the same kind. It returns
// immediately; delivery happens on a background goroutine.
func Send(typ, key, title, body string) {
	if endpoint() == "" {
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
	if endpoint() == "" {
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

func post(typ, title, body string) {
	payload := map[string]string{"title": emojiPrefix(typ) + title, "body": body, "type": typ}
	if urls := os.Getenv("PROTOXIDE_APPRISE_URLS"); urls != "" {
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
		log.Printf("notify: could not reach Apprise: %v", err)
		return
	}
	resp.Body.Close()
}
