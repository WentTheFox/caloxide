// Package credstore fetches the static Proton secrets (login password, mailbox
// password, TOTP seed) from an external store so they need not live in auth.json.
// See docs/design/unattended-reauth.md for the threat model and trade-offs.
package credstore

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Secrets are the static credentials needed to log in to Proton. Every field is
// optional at the store level (an absent or empty secret comes back as ""); callers
// decide what they require. Username is only a convenience for `protoxide auth`,
// MailboxPassword applies to two-password accounts and TOTPSecret to accounts with
// 2FA enabled.
type Secrets struct {
	Username        string
	LoginPassword   string
	MailboxPassword string
	TOTPSecret      string
}

// Describe reports which secrets are set, by name. It never includes a value or a
// length, so its output is safe to print or paste.
func (s Secrets) Describe() string {
	state := func(v string) string {
		if v == "" {
			return "missing"
		}
		return "present"
	}
	return fmt.Sprintf("%s: %s (optional; lets `protoxide auth` run without an argument)\n%s: %s\n%s: %s (only needed for two-password accounts)\n%s: %s (only needed for accounts with 2FA)",
		NameUsername, state(s.Username),
		NameLoginPassword, state(s.LoginPassword),
		NameMailboxPassword, state(s.MailboxPassword),
		NameTOTPSecret, state(s.TOTPSecret))
}

// Provider returns the current secrets. Implementations must not log secret
// values or include them in errors.
type Provider interface {
	Get(ctx context.Context) (Secrets, error)
}

// ErrNotFound means a secret does not exist in the store (as opposed to the store
// being unreachable or refusing access).
var ErrNotFound = errors.New("credstore: secret not found")

// BackendEnv selects where static Proton secrets come from: "local" (default,
// they stay in auth.json) or "infisical".
const BackendEnv = "PROTOXIDE_SECRETS_BACKEND"

// FromEnv returns the configured Provider, or nil when the default local backend
// is in use (in which case callers keep today's behaviour).
func FromEnv() (Provider, error) {
	return fromEnv(os.Getenv, os.ReadFile)
}

func fromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (Provider, error) {
	switch backend := getenv(BackendEnv); backend {
	case "", "local":
		return nil, nil
	case "infisical":
		p, err := infisicalFromEnv(getenv, readFile)
		if err != nil {
			return nil, err
		}
		return p, nil
	default:
		return nil, fmt.Errorf("%s: unknown backend %q (use local or infisical)", BackendEnv, backend)
	}
}
