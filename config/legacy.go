package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Upstream (mathewcsims/protoxide) uses PROTOXIDE_* environment variables and a
// protoxide state directory. Both are still honoured, so caloxide can replace an
// existing upstream installation without touching its configuration or state. The
// CALOXIDE_* name and the caloxide directory always win when present.
const (
	envPrefix       = "CALOXIDE_"
	legacyEnvPrefix = "PROTOXIDE_"
	dirName         = "caloxide"
	legacyDirName   = "protoxide"
)

var warned sync.Map

func warnOnce(key, msg string, args ...any) {
	if _, dup := warned.LoadOrStore(key, true); !dup {
		log.Printf(msg, args...)
	}
}

// Getenv returns the value of a CALOXIDE_* variable, falling back to the PROTOXIDE_*
// variable of the same name. Names without the CALOXIDE_ prefix are read as they are.
func Getenv(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if !strings.HasPrefix(name, envPrefix) {
		return ""
	}
	old := legacyEnvPrefix + strings.TrimPrefix(name, envPrefix)
	v := os.Getenv(old)
	if v != "" {
		warnOnce(old, "%s is still read as a fallback for %s; the CALOXIDE_ name is preferred", old, name)
	}
	return v
}

// appDir picks the directory under home that holds the state: caloxide, or the old
// protoxide one if that is the only one present, so nothing is lost to the rename.
func appDir(home string) string {
	current := filepath.Join(home, dirName)
	if _, err := os.Stat(current); err == nil {
		return current
	}
	legacy := filepath.Join(home, legacyDirName)
	if fi, err := os.Stat(legacy); err == nil && fi.IsDir() {
		warnOnce("dir", "using the existing state directory %s; a new one would be created at %s", legacy, current)
		return legacy
	}
	return current
}
