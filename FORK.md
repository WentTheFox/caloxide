# About this fork

`WentTheFox/caloxide` is a pinned, audited fork of
[mathewcsims/protoxide](https://github.com/mathewcsims/protoxide) (itself a fork of
ferroxide / hydroxide). It exists so the code that holds a Proton session is code
somebody reviewed, and does not change underneath us.

## Policy

- **Upstream is never merged automatically.** `upstream-watch` reports new commits
  weekly and runs the guardrail audit over the incoming tree; a human reviews and merges.
- **Dependencies move slowly.** A new or changed Go module version must be at least
  14 days old (`check-release-age.sh`), and Dependabot has a 14-day cooldown.
  Urgent security fix: add `module@version  # reason` to
  `.github/audit/release-age-exceptions.txt`, visible in review.
- **Everything executable is pinned.** Actions are pinned to commit SHAs and the
  Dockerfile base image to a digest (`check-action-pins.sh`; GitHub also enforces SHA
  pinning for this repository).
- **New capability needs a human.** `audit-source.sh` fails on any new outbound
  host, new use of exec/sockets/HTTP/env/file-write APIs, new Go module, extra
  `replace` directive, new binary file, hidden Unicode, or text addressed to AI agents.
  Review the change, then update the allowlists in `.github/audit/`.
- **Vendored `go-webdav`** must equal upstream v0.6.0 plus `.github/audit/go-webdav.patch`.
- `govulncheck` (reachability-aware), CodeQL and dependency review run on every change
  and weekly.

## Container image

Published to `ghcr.io/wentthefox/caloxide` for linux/amd64 and linux/arm64 when a
`vX.Y.Z` tag on `main` is pushed. The image is a static binary on `scratch`, runs as
uid/gid 65532, has no shell, and carries an SBOM and a signed provenance attestation:

    gh attestation verify oci://ghcr.io/wentthefox/caloxide@sha256:<digest> --repo WentTheFox/caloxide

Pin the digest, not the tag.

The same tag also creates a GitHub release with static binaries for linux, macOS and
Windows, each for amd64 and arm64 (`caloxide_<version>_<os>_<arch>`), a `SHA256SUMS`
file, and a signed provenance attestation per binary (built by
`.github/scripts/build-release.sh`, run it locally to reproduce). Use one to run
`caloxide auth` on a workstation:

    gh attestation verify caloxide_v0.3.0_linux_amd64 --repo WentTheFox/caloxide

Runtime notes:
- Config and the encrypted session live in `/data/caloxide/` (mount a volume owned by 65532:65532).
- The server speaks **plain HTTP with Basic auth**. The Basic-auth password (the "bridge
  password") is also the key that decrypts the stored Proton session, so publish the
  port on `127.0.0.1` only and terminate TLS in a reverse proxy.
- `caloxide auth <address>` needs a browser if Proton shows its human-verification step,
  so run it on a workstation, then copy `auth.json` into the volume. It asks for the
  account password and, for a 2FA account, optionally the **2FA secret key** (the base32
  seed shown when 2FA was enabled; or set `CALOXIDE_TOTP_SECRET` / `CALOXIDE_TOTP_SECRET_FILE`).
  Everything it stores goes into `auth.json`, encrypted with the bridge password it prints.
  The seed is stored only after Proton accepted a code generated from it; with it the bridge
  can log in again by itself, without it a person must type a code (`caloxide auth` again).

## Alerts

Failures that need a human (session expired and could not be renewed, breaker open,
write failed, server stopped) are reported by `notify`. Sinks, each optional:

- **Discord:** `CALOXIDE_DISCORD_WEBHOOK_URL`, or `..._FILE` (a path, for Docker secrets).
  The URL contains a secret token: it is validated (https, `discord.com` or
  `discordapp.com` only, path `/api/webhooks/<id>/<token>`), never followed through a
  redirect, and never written to logs. Messages cannot mention anyone, and are
  debounced to one per kind per 10 minutes.
- **Apprise:** `CALOXIDE_APPRISE_URL` (and `..._URLS`), as before.

A misconfigured webhook sends nothing and logs why (without the URL).

## When Proton asks for a CAPTCHA

A fresh login (which a dead session forces) can trigger Proton's CAPTCHA, which cannot be
answered unattended. The bridge then stops calling Proton, alerts once, and waits. To
continue, run `caloxide verify` inside the container for a one-time, 10-minute link (for
example `docker exec caloxide /caloxide -config-home /data verify`), open it, and follow
the page. Set `CALOXIDE_PUBLIC_URL` (the https address clients use) so the link is complete.
The page does not exist otherwise: it answers 404 unless a window was opened that way, and
a window can only be opened while a CAPTCHA is pending. Alternatively run `caloxide auth`
on a workstation and restart the bridge. Details: `docs/design/unattended-reauth.md`.

## App version

The `X-Pm-Appversion` header defaults to `Other`. It can be set with `-app-version` or
`--protondrive-app-version` (the name of rclone's option; same setting, last one given
wins), or the `CALOXIDE_PROTONDRIVE_APP_VERSION` environment variable, which applies only
when neither flag is given. Letters, digits and `. _ @ + -` only, up to 128 characters.
Proton validates the value, shows it in the session list, and **grants the session permissions
according to it**. Tested 2026-10-29:

| App version | Result |
|---|---|
| `Other` (default) | login works, calendar API works |
| `external-calendar-<name>@x.y.z` | rejected at login: `5002 Invalid app version` |
| `external-drive-<name>@x.y.z` (rclone's documented form for Proton **Drive** integrations) | login works, even with no CAPTCHA that time, but every calendar endpoint answers `9100 Access token does not have sufficient scope` |

So the Drive form is not usable for this calendar bridge, and there is no known calendar
equivalent: keep the default. Run `caloxide auth` with the same value the bridge uses.

The exact value used in that test, for anyone who wants to reproduce it. It is **not** shipped
as a default anywhere (neither the binary, the image nor the Homelab compose file), and it
is not recommended:

    # example only: logs in, but calendar endpoints then answer 9100
    CALOXIDE_PROTONDRIVE_APP_VERSION=external-drive-caloxide@0.2.1-stable
    # or:  caloxide --protondrive-app-version external-drive-caloxide@0.2.1-stable auth <address>

Use a separate `-config-home` so the experiment cannot disturb a working session, and revoke
its session in Proton afterwards (it shows as "Proton Drive Generic Client").

## Push notifications (not available yet)

Proton's web client has a server-sent-events channel ("Ping-o-matic",
`GET /event-notifier/v1/events`) that tells a client to fetch its event loop now
instead of waiting for the next poll. It was added to `ProtonMail/WebClients` on
2026-09-21 behind the Unleash flag `PingOMatic`, and only the mail app uses it.

As of 2026-10-29 it cannot be used:

- `https://mail.proton.me/api/event-notifier/v1/events` answers `404 Path not
  found`, the same as an invented path, with and without credentials, while a real
  route such as `core/v4/users` answers `401`.
- The flag is absent from the flags the web app receives for the author's account.

`protonmail/notifier.go` and `caldav/push.go` implement the client anyway. It is
dormant: it asks again every 6 hours, and while it is down the calendar pollers
run at the usual 30 seconds (with backoff after failures). If Proton enables the
route, pings wake the matching poller and the safety-net poll relaxes to 5 minutes;
if the stream drops, polling goes back to 30 seconds at once.

`caloxide push-probe <address>` connects and prints the stream state and every
ping, which is the way to check whether it has started working. In the browser,
open DevTools > Network on mail.proton.me, filter `event-notifier`, and look for
`PingOMatic` in the `feature/v2/frontend` response.
