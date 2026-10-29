package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mathewcsims/protoxide/protonmail"
)

// Regression: with an expired access token and a valid refresh token, the 401 on
// Unlock used to call ReAuth from inside ReAuth, recursing until the stack
// overflowed (a throwaway test reached depth 20 with 21 refresh calls in 30 ms).
func TestExpiredAccessTokenRefreshesOnceWithoutRecursion(t *testing.T) {
	var refreshes, users atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/refresh":
			refreshes.Add(1)
			fmt.Fprint(w, `{"Code":1000,"UID":"u","AccessToken":"new","RefreshToken":"r2","ExpiresIn":3600}`)
		case "/users":
			users.Add(1)
			if r.Header.Get("Authorization") == "Bearer old" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"Code":401,"Error":"expired"}`)
				return
			}
			fmt.Fprint(w, `{"Code":1000,"User":{"Keys":[]}}`)
		default:
			fmt.Fprint(w, `{"Code":1000,"Addresses":[]}`)
		}
	}))
	defer srv.Close()

	c := &protonmail.Client{RootURL: srv.URL, HTTPClient: srv.Client()}
	cached := &CachedAuth{Auth: protonmail.Auth{UID: "u", AccessToken: "old", RefreshToken: "r1"}}
	var reauths atomic.Int32
	c.ReAuth = func() error {
		if reauths.Add(1) > 3 {
			return fmt.Errorf("runaway ReAuth recursion")
		}
		_, err := reauthenticate(c, cached, "me", nil)
		return err
	}

	// The unlock itself fails at the end (the fake serves no keys); what matters
	// is how many times we hit the API on the way.
	_, err := reauthenticate(c, cached, "me", nil)
	if err == nil || err.Error() != "failed to unlock any key" {
		t.Fatalf("unexpected result: %v", err)
	}
	if n := reauths.Load(); n != 0 {
		t.Errorf("ReAuth was called %d times from inside the auth flow; want 0", n)
	}
	if n := refreshes.Load(); n != 1 {
		t.Errorf("refresh endpoint hit %d times, want exactly 1", n)
	}
	if n := users.Load(); n > 3 {
		t.Errorf("/users hit %d times, want at most 3", n)
	}
	if cached.Auth.AccessToken != "new" || cached.Auth.RefreshToken != "r2" {
		t.Errorf("tokens were not rotated: %+v", cached.Auth)
	}
}
