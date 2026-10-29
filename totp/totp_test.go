package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 seed "12345678901234567890". The RFC lists 8-digit
// codes; the 6-digit code is the same number modulo 10^6, i.e. its last 6 digits.
const rfcSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSeedBase32, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("t=%d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("t=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestCodeStableWithinStep(t *testing.T) {
	a, _ := Code(rfcSeedBase32, time.Unix(60, 0))
	b, _ := Code(rfcSeedBase32, time.Unix(89, 999999999))
	c, _ := Code(rfcSeedBase32, time.Unix(90, 0))
	if a != b {
		t.Errorf("code changed inside one 30 s step: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("code did not change across a step boundary: %s", a)
	}
}

func TestDecodeSecretFormats(t *testing.T) {
	want, _ := Code(rfcSeedBase32, time.Unix(59, 0))
	for _, in := range []string{
		strings.ToLower(rfcSeedBase32),
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
		"gezd-gnbv-gy3t-qojq-gezd-gnbv-gy3t-qojq",
		rfcSeedBase32 + "====",
		"  " + rfcSeedBase32 + "\n",
	} {
		got, err := Code(in, time.Unix(59, 0))
		if err != nil || got != want {
			t.Errorf("Code(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestDecodeSecretErrors(t *testing.T) {
	for _, in := range []string{"", "   ", "====", "-- --"} {
		if _, err := DecodeSecret(in); err != ErrEmptySecret {
			t.Errorf("DecodeSecret(%q) error = %v, want ErrEmptySecret", in, err)
		}
	}
	const bad = "SECRET-1-0-8-9" // 0, 1, 8 and 9 are not base32
	_, err := DecodeSecret(bad)
	if err == nil {
		t.Fatal("expected an error for invalid base32")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(strings.ToLower(err.Error()), "secret-") {
		t.Errorf("error leaks the secret: %v", err)
	}
}

func TestUntilNextStep(t *testing.T) {
	cases := []struct {
		at   time.Time
		want time.Duration
	}{
		{time.Unix(60, 0), 30 * time.Second},
		{time.Unix(61, 0), 29 * time.Second},
		{time.Unix(89, 0), 1 * time.Second},
		{time.Unix(89, 500_000_000), 500 * time.Millisecond},
	}
	for _, c := range cases {
		if got := UntilNextStep(c.at); got != c.want {
			t.Errorf("UntilNextStep(%v) = %v, want %v", c.at.Unix(), got, c.want)
		}
	}
}
