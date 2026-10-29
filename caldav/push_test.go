package caldav

import (
	"testing"
	"time"

	"github.com/mathewcsims/protoxide/protonmail"
)

func recv(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

func TestPingWakesOnlyTheNamedCalendar(t *testing.T) {
	var p pushState
	a, b := p.register("a"), p.register("b")
	p.handlePing(protonmail.NotifierPing{Type: "calendar", Identifier: "a"})
	if !recv(a) || recv(b) {
		t.Fatal("a ping for calendar a must wake a and not b")
	}
}

func TestUserScopedCalendarPingWakesAll(t *testing.T) {
	var p pushState
	a, b := p.register("a"), p.register("b")
	p.handlePing(protonmail.NotifierPing{Type: "calendar", Identifier: "user-id"})
	if !recv(a) || !recv(b) {
		t.Fatal("an unknown calendar identifier must wake every poller")
	}
}

func TestNonCalendarPingsAreIgnored(t *testing.T) {
	var p pushState
	a := p.register("a")
	p.handlePing(protonmail.NotifierPing{Type: "mail", Identifier: "a"})
	p.handlePing(protonmail.NotifierPing{Type: "core"})
	if recv(a) {
		t.Fatal("only calendar pings may wake the calendar pollers")
	}
}

func TestPingBurstCoalescesToOneWake(t *testing.T) {
	var p pushState
	a := p.register("a")
	for i := 0; i < 50; i++ {
		p.handlePing(protonmail.NotifierPing{Type: "calendar", Identifier: "a"})
	}
	if !recv(a) || recv(a) {
		t.Fatal("a burst must leave exactly one pending wake")
	}
}

func TestIntervalFollowsPushHealth(t *testing.T) {
	var p pushState
	if got := p.interval(); got != calendarPollInterval {
		t.Fatalf("push down: %s", got)
	}
	p.up.Store(true)
	if got := p.interval(); got != calendarPushFallbackInterval {
		t.Fatalf("push up: %s", got)
	}
}
