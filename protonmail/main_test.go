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

// freshGate forgets what an earlier test left in the per-host rate gate. Test servers
// reuse ports, and the gate is keyed by the server's address.
func freshGate(rootURL string) { gates.Delete(rootURL) }

// resetAllGates forgets every per-host rate gate. Tests that fake the clock or set a pause
// leave state in gates, and test servers reuse ports, so the next test to get the same
// address would inherit it.
func resetAllGates() {
	gates.Range(func(k, _ any) bool { gates.Delete(k); return true })
}
