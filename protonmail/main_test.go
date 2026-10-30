package protonmail

import (
	"os"
	"testing"
)

// The pacing between requests is exercised on its own; every other test would only
// get slower for it.
func TestMain(m *testing.M) {
	minRequestSpacing = 0
	os.Exit(m.Run())
}
