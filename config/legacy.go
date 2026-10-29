package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The project was called protoxide before it was renamed to caloxide. So that an
// existing deployment keeps working through the rename, the old environment variable
// names and the old config directory are still honoured, with a log line asking for
// the new names. The new name always wins.
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
		warnOnce(old, "%s is the old name of %s and is still read; rename it before the next release", old, name)
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
		warnOnce("dir", "using the old state directory %s; rename it to %s to finish the rename", legacy, current)
		return legacy
	}
	return current
}
