package protonmail

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proton does not publish its rate limits, so the rule is: when it says slow down
// (HTTP 429, or 503 with a Retry-After), every request to that API host stops until the
// time it named has passed, nothing is sent while the pause is in force, and a few
// retries with growing waits are the most that is ever attempted. The pause is shared
// by every client of the process (pollers, cache loads, re-login), because Proton
// limits by account and address and not by goroutine. The gate is keyed by API host,
// so all calendars of an account share one budget; with several accounts in one
// process they share it too, which is deliberately on the safe side.
const (
	// maxInlineWait is the longest a request waits for a pause to end. Longer pauses
	// fail the request at once with a RateLimitedError; the pause stays in force, so
	// later requests fail the same way until it is over, without touching Proton.
	maxInlineWait = 2 * time.Minute
	// maxRetryAfter caps what a (possibly bogus) header can make us sit out.
	maxRetryAfter = time.Hour
	// maxRateRetries is how many times one request is retried after being limited.
	maxRateRetries = 3
	// minRequestSpacing is the shortest time between two request starts to one API host,
	// across all calendars and clients: at most four requests a second. It turns the
	// burst of pollers that wake on the same tick into a short queue.
	// (A variable so tests can turn it off.)
	// coolDown is how long after a limit the client stays conservative (one page at a
	// time when listing a calendar).
	coolDown = 10 * time.Minute
)

var minRequestSpacing = 250 * time.Millisecond

// RateLimitedError is returned when Proton asked us to slow down and the request was
// not (or could not be) completed after waiting.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited by Proton, retry in %s", e.RetryAfter.Round(time.Second))
}

// Seams for tests.
var (
	rlNow   = time.Now
	rlSleep = time.Sleep
)

type rateGate struct {
	mu    sync.Mutex
	until time.Time // no request may be sent before this
	next  time.Time // earliest start of the next request, for spacing
	cool  time.Time // stay conservative until this
}

var gates sync.Map // API root URL -> *rateGate

func (c *Client) rateGate() *rateGate {
	g, _ := gates.LoadOrStore(c.RootURL, &rateGate{})
	return g.(*rateGate)
}

// remaining is how long requests must still wait.
func (g *rateGate) remaining() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if d := g.until.Sub(rlNow()); d > 0 {
		return d
	}
	return 0
}

// reserve books the next request slot and returns how long to wait for it. Calls from
// all calendars queue up one minRequestSpacing apart.
func (g *rateGate) reserve() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := rlNow()
	start := now
	if g.next.After(start) {
		start = g.next
	}
	g.next = start.Add(minRequestSpacing)
	return start.Sub(now)
}

// limit extends the pause (it never shortens one) and starts the cool-down.
func (g *rateGate) limit(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := rlNow()
	if t := now.Add(d); t.After(g.until) {
		g.until = t
	}
	g.cool = now.Add(coolDown)
}

// Cooling reports whether a limit was hit recently, so callers can ask for less.
func (g *rateGate) cooling() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return rlNow().Before(g.cool)
}

// parseRetryAfter reads a Retry-After value: delta-seconds or an HTTP date.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// isRateLimit reports a response that means "slow down".
func isRateLimit(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusServiceUnavailable:
		return resp.Header.Get("Retry-After") != ""
	}
	return false
}

// backoffWithoutHeader is the wait when Proton limits us but names no time: 10 s,
// 20 s, 40 s, with a little jitter.
func backoffWithoutHeader(attempt int) time.Duration {
	d := 10 * time.Second << attempt
	return d + time.Duration(rand.Int63n(int64(d)/5+1))
}

// sendRateLimited performs the request, honouring the shared pause before sending and
// retrying a limited request a few times. The returned response is never a limited one.
func (c *Client) sendRateLimited(httpClient *http.Client, req *http.Request) (*http.Response, error) {
	g := c.rateGate()
	canRetry := req.Body == nil || req.GetBody != nil
	for attempt := 0; ; attempt++ {
		if d := g.remaining(); d > 0 {
			if d > maxInlineWait {
				return nil, &RateLimitedError{RetryAfter: d}
			}
			rlSleep(d)
		}
		if d := g.reserve(); d > 0 {
			rlSleep(d)
		}

		resp, err := httpClient.Do(req)
		if err != nil || !isRateLimit(resp) {
			return resp, err
		}
		logUnexpected(req, resp, readBounded(resp.Body), "rate limited")
		resp.Body.Close()

		wait, named := parseRetryAfter(resp.Header.Get("Retry-After"), rlNow())
		if !named {
			wait = backoffWithoutHeader(attempt)
		}
		if wait > maxRetryAfter {
			wait = maxRetryAfter
		}
		g.limit(wait)
		log.Printf("rate limited by Proton on %s %s (HTTP %d): pausing all requests for %s (attempt %d of %d)",
			req.Method, req.URL.Path, resp.StatusCode, wait.Round(time.Second), attempt+1, maxRateRetries+1)
		if c.OnRateLimited != nil {
			c.OnRateLimited(wait)
		}

		if attempt >= maxRateRetries || !canRetry {
			return nil, &RateLimitedError{RetryAfter: wait}
		}
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}
	}
}

// RateLimitPause is how much longer requests to the API are paused because Proton asked
// us to slow down, or zero.
func (c *Client) RateLimitPause() time.Duration {
	return c.rateGate().remaining()
}
