// Package totp implements RFC 6238 time-based one-time passwords with the
// parameters Proton uses (HMAC-SHA1, 30 second step, 6 digits). Standard library
// only, so it adds no module to the dependency set.
//
// The idea of generating the login code from a stored seed instead of prompting
// for it comes from rclone's Proton Drive backend (otp_secret_key); the
// algorithm itself is the public RFC and no rclone code is used.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// Period is the length of one time step.
	Period = 30 * time.Second
	digits = 6
)

// ErrEmptySecret is returned for a blank or whitespace-only seed.
var ErrEmptySecret = errors.New("totp: empty secret")

// DecodeSecret parses a base32 seed as shown by authenticator enrolment screens:
// case-insensitive, with optional spaces, hyphens and '=' padding.
func DecodeSecret(secret string) ([]byte, error) {
	cleaned := strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "", "\r", "").Replace(secret)
	cleaned = strings.TrimRight(strings.ToUpper(cleaned), "=")
	if cleaned == "" {
		return nil, ErrEmptySecret
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		// Do not include the secret (or any part of it) in the error.
		return nil, errors.New("totp: secret is not valid base32")
	}
	return key, nil
}

// Code returns the 6-digit code for the time step containing t.
func Code(secret string, t time.Time) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix())/uint64(Period/time.Second)), nil
}

// UntilNextStep reports how long the code valid at t remains valid. Callers that
// must not reuse a code within one step can wait this long.
func UntilNextStep(t time.Time) time.Duration {
	return Period - time.Duration(t.UnixNano())%Period
}

// hotp is RFC 4226 dynamic truncation over HMAC-SHA1.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}
