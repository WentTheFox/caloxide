package caldav

import (
	"errors"
	"strings"
	"testing"
)

func TestErrTail(t *testing.T) {
	if got := errTail(errors.New("short"), 20); got != "short" {
		t.Errorf("short error changed: %q", got)
	}
	long := errors.New("GetCalendarModelEvents: " + strings.Repeat("u", 300) + ": connection reset by peer")
	got := errTail(long, 40)
	if !strings.HasSuffix(got, "connection reset by peer") {
		t.Errorf("cause missing from tail: %q", got)
	}
	if n := len([]rune(got)); n != 41 { // 40 runes plus the ellipsis
		t.Errorf("tail is %d runes, want 41", n)
	}
	if strings.Contains(got, "GetCalendarModelEvents") {
		t.Errorf("start of the error leaked into the tail: %q", got)
	}
}
