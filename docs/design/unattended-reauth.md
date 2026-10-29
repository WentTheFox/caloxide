# Design: unattended re-authentication and external secret storage

Status: approved. Implemented so far: `totp` (RFC 6238) and `credstore` (Infisical client).
Not yet wired into `auth/`. Target: v0.2.0, opt-in, off by default.

## Problem

Protoxide holds a Proton session. When Proton invalidates the refresh token
(error 10013) the bridge must log in again:

- `auth/auth.go` `authenticate()` re-logs in with the cached login password, but
  returns "two factor authentication enabled, please login again manually" when the
  account has 2FA. A 2FA account therefore needs a human every time the session dies.
- The login and mailbox passwords currently sit in `auth.json`, encrypted with the
  bridge password. That protects them at rest, but it puts every secret in one file
  next to the process that uses them.

## Goals

1. A 2FA account can recover from an expired session with nobody present.
2. Static secrets (login password, mailbox password, TOTP seed) can live in
   Infisical, behind a read-only machine identity scoped to one project, so they are
   not stored on the bridge's volume.
3. Default behaviour is unchanged. Everything here is opt-in.

## Non-goals

- Storing rotating session tokens anywhere but the local encrypted `auth.json`.
- Supporting 2FA methods other than TOTP (U2F/FIDO2 stays interactive).
- Multi-account support, mail, IMAP/SMTP/CardDAV.
- Making this safe against a compromised container (see the trade-off below).

## The trade-off, stated plainly

Today the server cannot authenticate to Proton by itself: the stored session is
encrypted with a key that only the CalDAV client supplies, per request. With this
feature, the process can read the login password and TOTP seed from Infisical and
mint a new Proton session on its own. **A compromised container, or anyone who
obtains the machine identity's credentials, can then do the same.** A TOTP seed
stored beside the password removes the second factor for that account.

Infisical narrows this (one scoped, read-only, revocable, audited identity; nothing
on the volume) but does not remove it, because the identity's client secret has to
be given to the container somehow. Hence: opt-in, documented, default off.

## Design

### TOTP generation

RFC 6238 (HMAC-SHA1, 30 s step, 6 digits), implemented with the standard library
only (`crypto/hmac`, `crypto/sha1`, `encoding/base32`). No new Go module, so the
dependency allowlist stays unchanged.

- Seed input: base32, case-insensitive, spaces/hyphens and `=` padding tolerated.
- Test vectors (RFC 6238 appendix B, seed ASCII `12345678901234567890`, i.e. base32
  `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`), 6-digit truncation:
  T=59 -> 287082, T=1111111109 -> 081804, T=1111111111 -> 050471,
  T=1234567890 -> 005924, T=2000000000 -> 279037.
- Proton may reject a code reused within the same 30 s window. Re-authentication is
  serialised, and a second attempt in the same window waits for the next one.

Credit: the idea of storing the TOTP seed to re-authenticate comes from rclone's
Proton Drive backend (`otp_secret_key`, MIT). No rclone code is copied; the
algorithm is the public RFC.

### Secret provider

A small interface in a new `credstore` package:

    type Secrets struct { LoginPassword, MailboxPassword, TOTPSecret string }
    type Provider interface { Get(ctx context.Context) (Secrets, error) }

Backends:

- `local` (default): today's behaviour, values come from the decrypted `auth.json`.
- `infisical`: read-only, fetched on demand at re-authentication time and not kept
  in memory longer than the login attempt.

`auth.authenticate()` gets the provider and, on error 10013, loads secrets, performs
the SRP login, and if `TwoFactor.Enabled` is set and `TOTP == 1` calls the existing
`Client.AuthTOTP(code)` with a generated code. Any other 2FA type still fails with
the current message. With the `infisical` backend, `LoginPassword` and
`MailboxPassword` are not written to `auth.json`; only the rotating tokens and the
public key salts are.

### Infisical client

Plain REST with `net/http`, no SDK.

- Auth: Universal Auth machine identity (`clientId` + `clientSecret`) exchanged for a
  short-lived access token, then one read per secret.
- Scope: the identity gets read access to a single project, environment and folder,
  nothing else. Use the identity's trusted-IP restriction if the deployed Infisical
  version supports it.
- Transport: https required, except `localhost`/`127.0.0.1` for local testing. TLS
  verification stays on. Redirects to a different host are refused. Requests have a
  timeout and a capped response size.
- Verified on 2026-10-29 against the OpenAPI spec served by the homelab instance
  (`infisical/infisical:v0.167.4`): `POST /api/v1/auth/universal-auth/login`
  (`clientId`, `clientSecret` -> `accessToken`) and
  `GET /api/v3/secrets/raw/{secretName}` (query `workspaceId`, `environment`,
  `secretPath`, `type=shared`, `viewSecretValue=true`; response `secret.secretValue`
  and `secret.secretValueHidden`). Re-check the spec at `/api/docs/json` after an
  Infisical upgrade.
- Secret values are never logged, never put in error strings, and never sent to the
  notifier.

### Configuration (environment, all optional)

    PROTOXIDE_SECRETS_BACKEND=local|infisical        (default local)
    PROTOXIDE_INFISICAL_URL=https://infisical.example.lan
    PROTOXIDE_INFISICAL_CLIENT_ID=...   (or ..._FILE)
    PROTOXIDE_INFISICAL_CLIENT_SECRET=...  (or ..._FILE)
    PROTOXIDE_INFISICAL_PROJECT_ID=...
    PROTOXIDE_INFISICAL_ENV=prod
    PROTOXIDE_INFISICAL_PATH=/protoxide

Secret names in that folder (note: the repository's `.gitignore` excludes `secrets*`, which
is why the package is called `credstore`): `PROTON_LOGIN_PASSWORD`, `PROTON_MAILBOX_PASSWORD`
(only for two-password accounts), `PROTON_TOTP_SECRET`.

### Safety rails

- Re-authentication is rate-limited with backoff and a circuit breaker (for example
  at most 3 attempts per hour) so a wrong secret cannot trigger Proton's failed-login
  lockout. When the breaker opens, an alert goes out through the existing notifier and
  the bridge stays in the "needs `protoxide auth`" state.
- Fail closed: if Infisical is unreachable or returns an error, re-authentication
  fails with a clear message; the bridge never falls back to guessing.
- Infisical is only contacted when a re-login is actually needed. If it is down
  while the session is healthy, nothing changes.

### Failure modes

| Situation | Behaviour |
|---|---|
| Session healthy, Infisical down | Unaffected |
| Session expired, Infisical down | Re-auth fails, alert, CalDAV returns 401/503 until fixed |
| Wrong/rotated password in Infisical | Breaker opens after the attempt limit, alert |
| Account uses a non-TOTP 2FA method | Interactive `protoxide auth` required (unchanged) |
| Identity revoked | Same as Infisical down; revoke is the kill switch |

## Impact on the repository's guardrails

- New Go files that use `net/http` and environment access show up in
  `audit-source.sh` as new (pattern, file) pairs. Update
  `.github/audit/sensitive-api-baseline.txt` in the same change and review the diff.
- The Infisical host comes from the environment, so it is not a literal in code and
  `egress-hosts.txt` does not change. This is the same shape as the Apprise URL and is
  called out in `FORK.md`.
- No new module; `go-modules.txt` and the release-age gate are unaffected.

## Testing

- Unit: TOTP against the RFC vectors and base32 edge cases; Infisical client against
  an `httptest` server (success, 401/403, timeout, oversize body, cross-host redirect,
  plain-http to a non-loopback host); the re-auth state machine with a fake provider
  and a fake Proton client (this needs a small interface seam around the concrete
  `*protonmail.Client`).
- Manual, by the owner, on a real account: let a session expire (or revoke it in
  Proton's security settings), confirm unattended recovery with TOTP, then confirm
  the breaker and the alert with a deliberately wrong secret. These cannot run in CI.

## Rollout

1. Implement behind the env flag; defaults unchanged; ship as v0.2.0.
2. Document creating the machine identity (read-only, one folder) in `FORK.md`.
3. Homelab: pass the identity through `.env` / Docker secrets, never the Proton
   secrets themselves.

## Open questions

- Whether Proton rejects TOTP reuse inside a 30 s window (assumed yes; the wait is
  cheap either way).
- Whether to keep the mailbox password in Infisical for single-password accounts
  (probably not needed: it equals the login password).
