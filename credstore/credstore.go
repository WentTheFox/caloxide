// Package credstore fetches the static Proton secrets (login password, mailbox
// password, TOTP seed) from an external store so they need not live in auth.json.
// See docs/design/unattended-reauth.md for the threat model and trade-offs.
package credstore

import (
	"context"
	"errors"
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
