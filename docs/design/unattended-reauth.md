# Design: unattended re-authentication and external secret storage

Status: implemented (`totp`, `credstore`, and the wiring in `auth/`), opt-in, off by default.
Ships in v0.2.0. Needs the manual end-to-end test described under Testing.

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
(only for two-password accounts), `PROTON_TOTP_SECRET`, and `PROTON_USERNAME`.

Every one of them is optional at the store level: a missing or empty secret reads as
"". What is *required* depends on the caller. A session start and a re-login need
`PROTON_LOGIN_PASSWORD` (and the mailbox password for a two-password account, and the
TOTP seed for a 2FA account) and fail with an error naming the missing secret. A secret
the identity may list but not read is always an error, never treated as missing.

`protoxide auth` and `protoxide import-session` use whatever the store holds and prompt
only for the rest: the address comes from the argument, else `PROTON_USERNAME`; the
password, mailbox password and 2FA code come from the store when present (the 2FA code is
generated from `PROTON_TOTP_SECRET`; if Proton rejects it the command falls back to a
manual prompt). An unreachable store is fatal rather than a silent fallback to prompting.
`PROTON_USERNAME` is only a convenience for those two commands. The CalDAV username a
client sends is unchanged and is still the key into `auth.json`.

### When the secret store is contacted

Because the passwords are no longer in `auth.json`, the process needs them to unlock
the account's keys, not only to log in again:

1. On the first client request after a start, once the bridge password has decrypted
   the session: the three secrets are read into memory.
2. At each re-login, so a rotated password or seed is picked up.

They live in memory for the life of the process, exactly as the cached passwords do
today, and are never written to disk. The consequence: a running process with a healthy
session is unaffected by an Infisical outage, but after a restart the first request
fails until Infisical is reachable (compose start order on one host matters; clients
retry). Persisting only the derived key passphrase instead would remove that
dependency; it is left as a possible follow-up.

### Prerequisite fix: re-authentication recursion

Found while implementing this, and fixed for all configurations: with an expired
access token and a still-valid refresh token, `ReAuth` called `authenticate`, whose
first step `Unlock` got a 401 and called `ReAuth` again, recursing until the stack
overflowed (a reproduction hit depth 20 with 21 refresh calls in 30 ms before being
stopped). Authentication now runs on a detached client that has no `ReAuth`
(`protonmail.Client.Detached`) and hands the result back (`AdoptSession`). A regression
test covers it with a fake Proton server. This also removes a failure mode that would
have made unattended recovery pointless. `Manager` now has a mutex around its session
map, which was previously unguarded under concurrent requests.

### Finding: the CAPTCHA wall, and persistent cookies

The first real test (a revoked session) got as far as submitting a fresh login, and
Proton answered with a human-verification CAPTCHA (code 9001), which cannot be answered
unattended. Observed facts: Proton's API sets `Session-Id` (90-day `Max-Age`) and `Tag`
cookies on the very first anonymous request; protoxide had no cookie jar, so every login
arrived as a brand-new client; the official Bridge keeps a persistent cookie jar in its
encrypted vault. Hypothesis, not proven: a login that presents the `Session-Id` from an
earlier session is treated as a known client and is challenged less often.

So protoxide now keeps the cookies Proton's own hosts set (`cookiestore`: persistent
cookies only, `proton.me` hosts only, size-capped), seeds a jar from them on every
start, shares it with the detached authentication client, and stores them inside the
already-encrypted session record. `protoxide auth` saves the cookies of the login it
performed, so the unattended re-logins that follow present the same `Session-Id`.

**Result (2026-10-29, revoked session, cookies stored by the preceding login):** Proton
still answered the fresh login with a CAPTCHA (9001). Either the cookies do not lower the
risk for a revoked session, or they were not effective (the revoked session's `Session-Id`
may be invalidated with it); the bridge now logs which cookie *names* it restored so the
next test can tell. Treat **recovery after a revoked session as impossible without a
human**. Unattended re-login can still help when Proton does not challenge it.

The same test exposed a worse problem: after the failed re-login the client was left
with no token, so nothing ever retried, while the event loop and six calendar pollers kept
sending seven doomed requests every 30 seconds. Fixed as follows.

- **CAPTCHA is a latched state.** Once Proton demands one, the bridge sends one alert and
  makes **no further Proton requests** until a human runs `protoxide auth` and the bridge
  is restarted.
- **A gate on the client.** While re-login is paused (CAPTCHA pending, backing off, or the
  per-window cap reached) every request that carries a token fails locally, with no
  network traffic; anonymous login requests are never gated.
- **Exponential backoff.** Failures delay the next unattended attempt 30s, 1m, 2m, 4m, ...
  up to 30 minutes (with +/-20% jitter), on top of the cap of 3 submitted logins per hour.
  The event loop and the calendar pollers back off the same way (30s up to 10 minutes) and
  reset on success.
- **A failed re-login no longer strands the client.** The old token stays in place, so
  the next request after the delay tries again. The client's credentials are now guarded
  by a mutex (poller, handlers and the session hand-over share one client).

### Answering a CAPTCHA without a workstation: the verification window

A latched bridge can be unstuck from the browser, but only deliberately:

1. Someone with command-line access to the container runs `protoxide verify` (for
   example `docker exec protoxide /protoxide -config-home /data verify`). It talks to
   the running bridge over a unix socket in the private config directory (mode 0600,
   only the bridge's own user can connect; it is not a network service).
2. The bridge opens a **verification window** if, and only if, a CAPTCHA is actually
   pending, and prints a one-time link `<PROTOXIDE_PUBLIC_URL>/verify/<token>`. The token
   is 256 random bits, lives in memory only, and the window lasts 10 minutes. Opening
   the page starts at most 3 fresh login attempts per window.
3. Every other request, with any other token or none, gets the same plain 404 as an
   unknown path, so nothing reveals that the route exists. There is no setting that
   leaves it open.
4. On the page the person answers the CAPTCHA; the bridge logs in again with the
   credentials from the secret store, answers the TOTP challenge, adopts the session,
   persists it and clears the latch. No restart, no workstation, and the bridge password
   does not change.

The page is served with a strict CSP (per-response nonce, `default-src 'none'`,
`frame-ancestors 'none'`), `Referrer-Policy: no-referrer` (the URL holds the token),
`Cache-Control: no-store`, and every dynamic value escaped. A cross-site POST cannot
succeed without the per-challenge nonce, which only the page itself receives.

**Why the person still has to do something in the popup.** Proton's CAPTCHA page reports
its result with `window.parent.postMessage({type:"pm_captcha", token:"<id>:<response>"},
'*')`. That is written for an iframe. In a popup `window.parent` is the popup itself, not
the window that opened it, so the opener never sees the message. Embedding is not possible
either: the CAPTCHA page sets `frame-ancestors https://verify.proton.me`, and
`verify.proton.me` in turn only allows `mail`, `calendar` and `drive.proton.me`. (Proton's
native apps use webview message hooks instead.) The original author's helper listened on
the opener, which never receives anything, and added a console snippet as the "reliable"
fallback. The only place the message can be caught is inside the popup, so the page shows
a snippet to paste into the popup's console. It logs the message (the manual fallback) and
relays the token to `window.opener`, which the page accepts only from the popup it opened
and only from Proton's CAPTCHA origin. A userscript manager could install the same listener
automatically; that is a possible follow-up. The relay was verified against a faked DOM,
not against Proton's real CAPTCHA.

### Safety rails

- Re-authentication is rate-limited with backoff and a circuit breaker (for example
  at most 3 attempts per hour) so a wrong secret cannot trigger Proton's failed-login
  lockout. When the breaker opens, an alert goes out through the existing notifier and
  the bridge stays in the "needs `protoxide auth`" state.
- Fail closed: if Infisical is unreachable or returns an error, re-authentication
  fails with a clear message; the bridge never falls back to guessing.
- Logins that never reach Proton (secret store unreachable, bad config) do not count
  toward the breaker; only actual login attempts do. A human-verification challenge
  (code 9001) cannot be answered unattended and is reported with the exact command to run.

### Failure modes

| Situation | Behaviour |
|---|---|
| Session healthy, Infisical down | Running process unaffected; after a restart the first request fails until Infisical is back |
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
