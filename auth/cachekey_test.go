package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCacheKeyIsDeterministicAndDiffersFromTheSessionKey(t *testing.T) {
	secret, password, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	a, err := CacheKey(password)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := CacheKey(password)
	if *a != *b {
		t.Fatal("the same password must give the same cache key, or a restart could not read its own cache")
	}
	if bytes.Equal(a[:], secret[:]) {
		t.Fatal("the cache must not be sealed with the same key as auth.json")
	}
}

func TestDifferentPasswordsGiveDifferentCacheKeys(t *testing.T) {
	_, p1, _ := GeneratePassword()
	_, p2, _ := GeneratePassword()
	a, _ := CacheKey(p1)
	b, _ := CacheKey(p2)
	if *a == *b {
		t.Fatal("two bridge passwords produced the same cache key")
	}
}

func TestCacheKeyRejectsAnythingThatIsNotABridgePassword(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, bad := range []string{"", "not base64!", short, "AAAA"} {
		if k, err := CacheKey(bad); err == nil || k != nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
