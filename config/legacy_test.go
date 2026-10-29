package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetenvPrefersTheNewNameAndFallsBackToTheOld(t *testing.T) {
	t.Setenv("PROTOXIDE_X_TEST", "old")
	if got := Getenv("CALOXIDE_X_TEST"); got != "old" {
		t.Fatalf("fallback = %q, want old", got)
	}
	t.Setenv("CALOXIDE_X_TEST", "new")
	if got := Getenv("CALOXIDE_X_TEST"); got != "new" {
		t.Fatalf("new name must win, got %q", got)
	}
}

func TestGetenvDoesNotInventFallbacksForOtherNames(t *testing.T) {
	t.Setenv("HYDROXIDE_BRIDGE_PASS", "p")
	if got := Getenv("SOMETHING_ELSE"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := Getenv("HYDROXIDE_BRIDGE_PASS"); got != "p" {
		t.Fatalf("got %q", got)
	}
}

func TestAppDirUsesTheOldDirectoryOnlyWhenItIsTheOnlyOne(t *testing.T) {
	home := t.TempDir()
	if got := appDir(home); got != filepath.Join(home, "caloxide") {
		t.Fatalf("fresh install = %s", got)
	}
	os.Mkdir(filepath.Join(home, "protoxide"), 0o700)
	if got := appDir(home); got != filepath.Join(home, "protoxide") {
		t.Fatalf("existing old state must keep being used, got %s", got)
	}
	os.Mkdir(filepath.Join(home, "caloxide"), 0o700)
	if got := appDir(home); got != filepath.Join(home, "caloxide") {
		t.Fatalf("new directory must win once it exists, got %s", got)
	}
}
