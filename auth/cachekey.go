package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// cacheKeyContext separates the key that seals the calendar cache from the one that
// seals auth.json, although both come from the bridge password. Changing it would make
// every existing sealed cache unreadable.
const cacheKeyContext = "caloxide calendar cache v1"

// CacheKey derives the key that seals the on-disk calendar cache from the bridge
// password. The password is the base64 of 32 random bytes (see GeneratePassword), so an
// HMAC keyed with them is a sound way to derive a separate key from it. It fails for
// anything that is not such a password.
func CacheKey(password string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(password)
	if err != nil || len(raw) != 32 {
		return nil, ErrUnauthorized
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(cacheKeyContext))
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return &key, nil
}
