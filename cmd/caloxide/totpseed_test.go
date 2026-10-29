package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The seed is read from the environment or a file so a script (or a Docker secret) can
// supply it without a prompt; the interactive fallback needs a terminal and is not tested.
func TestLocalTOTPSeedFromEnvironmentAndFile(t *testing.T) {
	t.Setenv("CALOXIDE_TOTP_SECRET", "  GEZDGNBVGY3TQOJQ \n")
	t.Setenv("CALOXIDE_TOTP_SECRET_FILE", "")
	if got := localTOTPSeed(); got != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("from the environment: %q (must be trimmed)", got)
	}

	path := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(path, []byte("\nJBSWY3DPEHPK3PXP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALOXIDE_TOTP_SECRET", "")
	t.Setenv("CALOXIDE_TOTP_SECRET_FILE", path)
	if got := localTOTPSeed(); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("from the file: %q (must be trimmed)", got)
	}
}
