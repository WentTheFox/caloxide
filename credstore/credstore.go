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

// Secrets are the static credentials needed to log in to Proton again.
// MailboxPassword is only set for two-password accounts and TOTPSecret only for
// accounts with 2FA enabled; LoginPassword is always required.
type Secrets struct {
	LoginPassword   string
	MailboxPassword string
	TOTPSecret      string
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
