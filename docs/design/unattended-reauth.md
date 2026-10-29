# Design: unattended re-authentication

Status: implemented. Applies to the `caldav` server.

## Problem

Proton ends sessions: a refresh token expires or is revoked (error 10013) and the bridge
must log in again. The original code could only do that for accounts without 2FA, recursed
without bound when the access token had merely expired, and, once a re-login failed,
stranded the client so nothing ever retried while it hammered Proton with dead tokens.

## What is stored, and where

`protoxide auth` writes one record per account to `auth.json`, **encrypted with the bridge
password** (NaCl secretbox, key = the bridge password's 32 random bytes, which only the
client supplies; the server never stores it):

- the rotating session tokens and the key salts;
- the account password (and the mailbox password for two-password accounts);
- optionally the **2FA seed** (base32), stored only after Proton accepted a code generated
  from it, so a wrong seed is never saved;
- Proton's cookies (see below).

Consequences, deliberately accepted:

- At rest, `auth.json` is ciphertext. Stealing the disk or a backup yields nothing usable
  without the bridge password, which is not on the server.
- While running, the process holds everything in memory after the first request unlocks
  the file, so unattended re-login works for as long as it lives. After a restart the first
  CalDAV request unlocks it again.
- Password and 2FA seed share one blob, so for someone who obtains both the file *and* the
  key, 2FA is no longer a separate barrier. The bridge password is a random 256-bit key and
  the program accepts nothing weaker; treat it as the root secret.

An external secret store (Infisical) was tried and removed: its client secret had to live
in `.env` on the same host, so it added a startup dependency and a network path without
removing a credential from the disk.

## Unattended re-login

Triggered by error 10013 on a refresh. Implemented by `reloginer` (`auth/relogin.go`),
enabled for the `caldav` server by `Manager.EnableRelogin`.

1. **TOTP** (RFC 6238, standard library only): answers the 2FA challenge from the stored
   seed and never reuses a code inside its 30 s step (it waits for the next one).
2. **Exponential backoff** (`backoff` package) after any failed attempt: 30 s, 1 m, 2 m, ...
   up to 30 min, with +/-20% jitter. The event loop and the calendar pollers back off the
   same way (30 s up to 10 min) and reset on success.
3. **Cap**: at most 3 submitted logins per hour.
4. **CAPTCHA latch**: Proton's human verification (code 9001) cannot be answered unattended.
   The bridge alerts once and **stops calling Proton** until a human acts.
5. **Gate**: while paused (latch, backoff or cap) every request that carries a token fails
   locally with no network traffic (`protonmail.Client.Gate`). Anonymous login requests are
   never gated.
6. Authentication runs on a **detached client** with no `ReAuth` of its own
   (`Client.Detached`/`AdoptSession`). Running it on the shared client recursed until the
   stack overflowed: `Unlock` got a 401, which called `ReAuth`, which called `Unlock`.
   The old token also stays in place while `ReAuth` runs, so a failed re-login no longer
   leaves the client unable to retry.
7. The client's credentials are guarded by a mutex (poller, handlers and the session
   hand-over share one client), and `Manager`'s session map is lock-protected.

A record with no stored password, or a 2FA account with no stored seed, fails with an
instruction to run `protoxide auth`; it does not contact Proton and does not charge the
login cap.

## Answering a CAPTCHA: the verification window

1. Someone with command-line access to the container runs `protoxide verify` (for example
   `docker exec protoxide /protoxide -config-home /data verify`). It talks to the running
   bridge over a unix socket in the private config directory (mode 0600; only the bridge's
   own user can connect; not a network service).
2. The bridge opens a **verification window** if, and only if, a CAPTCHA is pending, and
   prints `<PROTOXIDE_PUBLIC_URL>/verify/<token>`: 256 random bits, memory only, valid
   10 minutes, at most 3 login attempts per window.
3. Every other request, with any other token or none, gets the same plain 404 as an unknown
   path. There is no setting that leaves the page open.
4. On the page the person answers the CAPTCHA; the bridge logs in again with the stored
   credentials, answers TOTP, adopts and persists the session and clears the latch. No
   restart, no workstation, and the bridge password does not change.

The page has a strict CSP (per-response nonce, `default-src 'none'`, `frame-ancestors 'none'`),
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`, every dynamic value escaped, and a
per-challenge nonce so another site cannot post to it. It follows the browser's colour scheme.
`protoxide auth` on a workstation serves the same page on a loopback port.

**Why a snippet must be pasted in the popup.** Proton's CAPTCHA reports its result with
`window.parent.postMessage({type:"pm_captcha", token:"<id>:<response>"}, '*')`, written for an
iframe. In a popup `window.parent` is the popup itself, not the window that opened it, so
the opener never sees the message. Embedding is impossible: the CAPTCHA sets
`frame-ancestors https://verify.proton.me`, and `verify.proton.me` only allows `mail`,
`calendar` and `drive.proton.me`. The only place the message can be caught is inside the
popup, so the page shows a snippet to paste into its console. It logs the message (the manual
fallback) and relays the token to `window.opener`, which the page accepts only from the popup
it opened and only from Proton's CAPTCHA origin. The CAPTCHA logs two messages; only the
`pm_captcha` one is right, and the parser picks it even when both lines are pasted. The relay
logic was verified against a faked DOM, not against Proton's real CAPTCHA.

## Findings from the real API

- **Cookies.** Proton sets `Session-Id` (90 days) and `Tag` on the first request; the
  official Bridge persists them. Protoxide now does too (inside the encrypted record). It did
  **not** prevent a CAPTCHA on a fresh login after a revoked session: treat recovery from a
  revoked session as needing a human. Unattended re-login still helps when Proton does not
  challenge it.
- **App version** (`X-Pm-Appversion`). Proton validates it and grants scopes by it:
  `Other` works; `external-calendar-*` is rejected (5002); rclone's documented
  `external-drive-<project>@<version>` logs in but every calendar endpoint answers 9100
  (insufficient scope). Keep the default. See `FORK.md`.
- A CAPTCHA token is long (`<id>:<response>`, often over a thousand characters).

## Testing

Unit tests cover TOTP (RFC 6238 vectors), the backoff, the cookie jar, every re-login path
with a fake Proton API (a fake that, like the real one, rejects an anonymous request that still
carries a token), the verification window and web page (token, expiry, nonce, attempt cap,
escaping, headers), and a regression test for the recursion against a fake HTTP server. Safety
properties were mutation-checked. What cannot run in CI: a real session expiring, a real CAPTCHA,
and a real TOTP login; those need the owner's account.
