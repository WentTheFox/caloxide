package protonmail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mathewcsims/protoxide/backoff"
)

// The event notifier ("Ping-o-matic") is Proton's push channel: a server-sent
// events stream that says "something changed in loop X" so a client can fetch its
// event loop now instead of waiting for the next poll. Proton's web client treats it
// as an optimisation on top of polling, and so does this one: every failure here is
// reported through OnState and otherwise ignored.
//
// STATUS (2026-10-29): not available. Proton added this in WebClients in September
// 2026 behind the Unleash flag PingOMatic, only the mail app uses it, and
// mail.proton.me/api answers 404 "Path not found" for the route, exactly like for
// an invented path, with or without credentials. Until that changes, everything
// below stays idle and polling is the only mechanism. See FORK.md.
//
// Protocol, from ProtonMail/WebClients packages/shared/lib/eventNotifier:
//
//	GET  event-notifier/v1/events                    -> text/event-stream
//	  Hello   {"id": "<connection id>"}
//	  Ping    {"type": "calendar", "identifier": "<calendar or user id>"}
//	  Goodbye
//	  Error   "<message>"
//	POST event-notifier/v1/connection/<id>/loops     {"Add": [{"Type","Identifier"}], "Remove": []}
const (
	notifierEventsPath = "/event-notifier/v1/events"

	// NotifierLoopCalendar is the loop type for calendars. The identifier is the
	// calendar ID for a calendar's model loop, the user ID for user-scoped changes.
	NotifierLoopCalendar = "calendar"

	// maxSSELine bounds one SSE line. Everything on the stream is server-controlled
	// input, so it must not be able to grow memory without limit.
	maxSSELine = 64 << 10

	notifierMaxBackoff = 10 * time.Minute
	// notifierPermanentRetry is the wait after the server says the channel is not
	// available to us (feature off, not allowed). As of October 2026 the route
	// answers 404 for everyone, so there is little to learn from asking often.
	notifierPermanentRetry = 6 * time.Hour
	// notifierStable is how long a connection has to survive before the backoff is
	// forgotten, so a stream that opens and immediately drops keeps backing off.
	notifierStable = time.Minute
)

// NotifierLoop names one event loop to be pushed for.
type NotifierLoop struct {
	Type       string `json:"Type"`
	Identifier string `json:"Identifier"`
}

// NotifierPing is one "this loop has new events" message.
type NotifierPing struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// Notifier keeps one event-notifier stream open for a client.
type Notifier struct {
	c *Client

	// OnPing is called from the stream goroutine for every ping; it must not block.
	OnPing func(NotifierPing)
	// OnState is called when the push channel becomes usable (up=true) or stops
	// being usable. detail is a short human-readable reason, never a credential.
	OnState func(up bool, detail string)

	mu     sync.Mutex
	loops  []NotifierLoop
	connID string
}

// NewNotifier returns a notifier that is idle until Run is called.
func (c *Client) NewNotifier() *Notifier {
	return &Notifier{c: c}
}

// Subscribe adds loops to the set pushed for. They are sent right away when a
// stream is open, and again on every reconnect, so an error from the immediate
// send is not fatal: it only means these loops start with the next connection.
func (n *Notifier) Subscribe(loops ...NotifierLoop) error {
	n.mu.Lock()
	var fresh []NotifierLoop
	for _, l := range loops {
		if !n.hasLoop(l) {
			n.loops = append(n.loops, l)
			fresh = append(fresh, l)
		}
	}
	id := n.connID
	n.mu.Unlock()

	if id == "" {
		return nil
	}
	return n.postLoops(id, fresh)
}

func (n *Notifier) hasLoop(l NotifierLoop) bool {
	for _, have := range n.loops {
		if have == l {
			return true
		}
	}
	return false
}

func (n *Notifier) state(up bool, detail string) {
	if n.OnState != nil {
		n.OnState(up, detail)
	}
}

type notifierStatusError struct {
	status int
	body   string
}

func (e *notifierStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

// permanent reports statuses that mean "this will keep failing", as opposed to a
// blip: the endpoint or flag is off for us, or the request is not acceptable.
func (e *notifierStatusError) permanent() bool {
	switch e.status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound,
		http.StatusMethodNotAllowed, http.StatusUnprocessableEntity, http.StatusNotImplemented:
		return true
	}
	return false
}

var errGoodbye = errors.New("server said goodbye")

// Run keeps the stream connected until ctx is cancelled, reconnecting with an
// exponential backoff. It blocks.
func (n *Notifier) Run(ctx context.Context) {
	bo := backoff.New(30*time.Second, notifierMaxBackoff)
	for ctx.Err() == nil {
		started := time.Now()
		err := n.session(ctx)
		n.mu.Lock()
		n.connID = ""
		n.mu.Unlock()
		if ctx.Err() != nil {
			return
		}

		if time.Since(started) >= notifierStable {
			bo.Reset()
		}

		var wait time.Duration
		var se *notifierStatusError
		switch {
		case errors.Is(err, errGoodbye):
			wait = 2 * time.Second
		case errors.As(err, &se) && se.permanent():
			wait = notifierPermanentRetry
		default:
			wait = bo.Next()
		}
		n.state(false, fmt.Sprintf("%v (retrying in %s)", err, wait.Round(time.Second)))

		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
}

// streamClient is the client's HTTP client without an overall timeout, which would
// cut a stream that is meant to stay open for hours. Its cookie jar is kept.
func (c *Client) streamClient() *http.Client {
	var hc http.Client
	if c.HTTPClient != nil {
		hc = *c.HTTPClient
	}
	hc.Timeout = 0
	return &hc
}

func (n *Notifier) session(ctx context.Context) error {
	c := n.c
	req, err := c.newRequest(http.MethodGet, notifierEventsPath, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", c.userAgent())

	// The web client cannot set headers on an EventSource and passes what the API
	// needs to authenticate as query parameters named like the headers. Sending the
	// same values both ways costs nothing and covers either way the API reads them.
	q := url.Values{}
	for _, h := range []string{"X-Pm-Uid", "X-Pm-Appversion"} {
		if v := req.Header.Get(h); v != "" {
			q.Set(strings.ToLower(h), v)
		}
	}
	req.URL.RawQuery = q.Encode()

	if _, authed := req.Header["Authorization"]; authed && c.Gate != nil {
		if err := c.Gate(); err != nil {
			return err
		}
	}

	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized && c.ReAuth != nil {
		// A stream cannot be replayed like a request, so refresh the token here and let
		// Run reconnect.
		if err := c.ReAuth(); err != nil {
			return fmt.Errorf("session refresh failed: %w", err)
		}
		return &notifierStatusError{status: resp.StatusCode, body: "token refreshed"}
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return &notifierStatusError{status: resp.StatusCode, body: strings.TrimSpace(string(snippet))}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		return fmt.Errorf("unexpected content type %q", ct)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), maxSSELine)
	var name string
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if name != "" || len(data) > 0 {
				if err := n.dispatch(name, strings.Join(data, "\n")); err != nil {
					return err
				}
			}
			name, data = "", nil
		case strings.HasPrefix(line, ":"):
			// comment / keep-alive
		default:
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				name = value
			case "data":
				data = append(data, value)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

func (n *Notifier) dispatch(name, data string) error {
	switch name {
	case "Hello":
		var h struct {
			ID string `json:"id"`
		}
		if json.Unmarshal([]byte(data), &h) != nil || h.ID == "" {
			return errors.New("malformed Hello")
		}
		n.mu.Lock()
		loops := append([]NotifierLoop(nil), n.loops...)
		n.mu.Unlock()
		if err := n.postLoops(h.ID, loops); err != nil {
			return fmt.Errorf("subscribe failed: %w", err)
		}
		n.mu.Lock()
		n.connID = h.ID
		n.mu.Unlock()
		n.state(true, fmt.Sprintf("connected, %d loop(s)", len(loops)))
	case "Ping":
		var p NotifierPing
		if json.Unmarshal([]byte(data), &p) != nil || p.Type == "" {
			return nil // unknown or malformed frames are dropped, as the web client does
		}
		if n.OnPing != nil {
			n.OnPing(p)
		}
	case "Goodbye":
		return errGoodbye
	case "Error":
		return fmt.Errorf("server error: %.200s", data)
	}
	return nil
}

func (n *Notifier) postLoops(connID string, add []NotifierLoop) error {
	if len(add) == 0 {
		return nil
	}
	body := struct {
		Add    []NotifierLoop
		Remove []NotifierLoop
	}{Add: add, Remove: []NotifierLoop{}}
	req, err := n.c.newJSONRequest(http.MethodPost,
		"/event-notifier/v1/connection/"+url.PathEscape(connID)+"/loops", body)
	if err != nil {
		return err
	}
	resp, err := n.c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return &notifierStatusError{status: resp.StatusCode, body: strings.TrimSpace(string(snippet))}
	}
	return nil
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return defaultUserAgent
}
