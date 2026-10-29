package main

import (
	"strings"
	"testing"
)

func TestResolveAppVersionPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		given     bool
		flagValue string
		env       string
		want      string
	}{
		{"default when nothing is set", false, defaultAppVersion, "", defaultAppVersion},
		{"environment applies without a flag", false, defaultAppVersion, "external-drive-caloxide@0.2.1-stable", "external-drive-caloxide@0.2.1-stable"},
		{"a flag beats the environment", true, "flag-value@1.0.0", "env-value@2.0.0", "flag-value@1.0.0"},
		{"a flag equal to the default still beats the environment", true, defaultAppVersion, "env-value@2.0.0", defaultAppVersion},
		{"the flag alone", true, "only-flag@3", "", "only-flag@3"},
	}
	for _, c := range cases {
		got, err := resolveAppVersion(c.given, c.flagValue, c.env)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestResolveAppVersionRejectsAnythingUnsafeForAHeader(t *testing.T) {
	bad := []string{
		"", "has space", "tab\there", "new\nline", "carriage\rreturn", "crlf\r\nX-Injected: 1",
		"semi;colon", "quote\"", "unicode-é", strings.Repeat("a", 129),
	}
	for _, v := range bad {
		if _, err := resolveAppVersion(true, v, ""); err == nil {
			t.Errorf("flag value %q should be rejected", v)
		}
		if _, err := resolveAppVersion(false, defaultAppVersion, v); v != "" && err == nil {
			t.Errorf("environment value %q should be rejected", v)
		}
	}
	if _, err := resolveAppVersion(true, strings.Repeat("a", 128), ""); err != nil {
		t.Errorf("128 characters is the limit and must be accepted: %v", err)
	}
	// The error must not echo the value (it may come from an environment file).
	_, err := resolveAppVersion(false, defaultAppVersion, "secret value with spaces")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the value: %v", err)
	}
}
