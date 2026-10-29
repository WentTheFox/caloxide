package protonmail

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// serverAccepting returns 200 only for the given bearer token and counts requests.
func serverAccepting(t *testing.T, token string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":401,"Error":"Invalid access token"}`)
			return
		}
		fmt.Fprint(w, `{"Code":1000,"User":{"Keys":[]}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Regression for the stuck bridge seen in the first revoked-session test: do()
// blanked the token before ReAuth and never restored it, so after one failed ReAuth
// no request carried an Authorization header, ReAuth was never called again, and the
// bridge stayed dead until restarted, even if the failure was transient.
func TestFailedReAuthDoesNotStrandTheClient(t *testing.T) {
	var hits atomic.Int32
	srv := serverAccepting(t, "new", &hits)
	c := &Client{RootURL: srv.URL, HTTPClient: srv.Client()}
	c.SetSession("u", "old")

	var calls atomic.Int32
	c.ReAuth = func() error {
		if calls.Add(1) == 1 {
			return errors.New("secret store unreachable") // a transient failure
		}
		c.SetSession("u", "new")
		return nil
	}

	if _, err := c.GetCurrentUser(); err == nil {
		t.Fatal("the first request must fail while ReAuth fails")
	}
	if _, err := c.GetCurrentUser(); err != nil {
		t.Fatalf("the client must recover once ReAuth works again: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("ReAuth called %d times, want 2 (the second request must try again)", n)
	}
}

func TestGateFailsAuthenticatedRequestsWithoutTouchingTheNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := serverAccepting(t, "tok", &hits)
	c := &Client{RootURL: srv.URL, HTTPClient: srv.Client()}
	c.SetSession("u", "tok")

	blocked := errors.New("needs a human")
	c.Gate = func() error { return blocked }
	var reauths atomic.Int32
	c.ReAuth = func() error { reauths.Add(1); return nil }

	if _, err := c.GetCurrentUser(); !errors.Is(err, blocked) {
		t.Fatalf("want the gate's error, got %v", err)
	}
	if hits.Load() != 0 || reauths.Load() != 0 {
		t.Errorf("a gated request reached the network (%d) or ReAuth (%d)", hits.Load(), reauths.Load())
	}

	c.Gate = func() error { return nil } // reopened
	if _, err := c.GetCurrentUser(); err != nil {
		t.Fatalf("an open gate must let requests through: %v", err)
	}
}

func TestGateNeverBlocksAnonymousRequests(t *testing.T) {
	var hits atomic.Int32
	srv := serverAccepting(t, "tok", &hits)
	c := &Client{RootURL: srv.URL, HTTPClient: srv.Client()}
	c.Gate = func() error { return errors.New("blocked") }

	// No credentials set: this is how /auth/info and /auth are sent. They must reach
	// the server even while authenticated calls are blocked, or a re-login could
	// never happen once the gate reopens.
	c.GetCurrentUser() // fails with 401 from the server, not from the gate
	if hits.Load() != 1 {
		t.Errorf("an anonymous request was blocked locally (server hits = %d)", hits.Load())
	}
}

func TestDetachedClientHasNoGateOrReAuth(t *testing.T) {
	c := &Client{RootURL: "https://x", Gate: func() error { return errors.New("g") }, ReAuth: func() error { return nil }}
	d := c.Detached()
	if d.Gate != nil || d.ReAuth != nil {
		t.Error("the client used for re-authentication must not be gated or re-enter ReAuth")
	}
}
