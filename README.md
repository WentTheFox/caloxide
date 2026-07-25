# Protoxide

![Protoxide Logo](protoxide-logo.png?v=2)

A local bridge that exposes **Proton Calendar over CalDAV** on `localhost`, so a
standards-compliant calendar client (developed against **Thunderbird**) can read
**and write** your Proton calendar with near-real-time two-way sync — instead of
the read-only, hours-stale ICS feed that is otherwise the only option.

It is a fork of [`acheong08/ferroxide`](https://github.com/acheong08/ferroxide),
itself a fork of [`emersion/hydroxide`](https://github.com/emersion/hydroxide) —
third-party, open-source bridges that speak Proton's internal API locally and
re-expose it over standard protocols (the same idea as the official Proton Mail
Bridge, which covers mail only). Protoxide narrows the focus to the
calendar/CalDAV path and hardens it for daily use.

## Why this exists

Proton Calendar has no CalDAV support and no public API — a deliberate
consequence of its end-to-end encryption, where the server cannot read events by
design. The only way to get live, writable desktop access is a local process
that holds your session, does the PGP work on your machine, and serves a standard
protocol locally. That is what this is.

## Status: what works

Tested end-to-end against the author's own Proton account (a ~3,100-event
calendar) driven from Thunderbird:

- **Read** — the entire calendar is fetched, decrypted locally, and served over
  CalDAV, including encrypted-and-unsigned events and recurring-event overrides.
- **Write** — create, edit, and delete round-trip to Proton and appear in the
  Proton web app; a client-created event stays visible in the client immediately
  (no manual refresh).
- **Inbound sync** — changes made in Proton (or on another device) are pulled
  into the local cache within ~30 s by polling Proton's calendar event loop, and
  surfaced to the client via a CalendarServer **CTag** so it re-syncs promptly
  instead of on its slow default interval.
- **On-disk cache** — decrypted events are cached locally, so restarts are
  instant and per-request queries are served from memory rather than re-walking
  and re-decrypting the whole calendar.

**Please read the [Limitations & caveats](#limitations--caveats) section below
before relying on this.** It is an unofficial bridge over a reverse-engineered,
end-to-end-encrypted service and comes with real, specific caveats.

## Design intent

Protoxide is built to be driven by a CalDAV client that handles its own
invitation scheduling **client-side** (Thunderbird's "Prefer client-side email
scheduling" option). Under that model the bridge never implements CalDAV
server-side scheduling (RFC 6638): the client sends iTIP/iMIP invitations over
its own SMTP identity and processes RSVP replies, while the bridge only has to
store and serve events as ordinary CalDAV objects. This keeps the bridge
substantially smaller than a full scheduling server.

## Limitations & caveats

These are deliberate, known, and in most cases inherent to what this is. Read
them.

**Reliability / trust**

- **Unofficial & reverse-engineered.** This talks to Proton's private, internal
  API, which has no stability guarantee and no Proton QA. It can break without
  warning whenever Proton changes their internals. Treat it as best-effort, not
  as infrastructure.
- **Single-account, single-developer testing.** It has been exercised against one
  Proton account and its calendars only. Multi-account, multi-calendar, and
  many edge cases are unverified.
- **Not a backup.** Do not treat the local cache as a backup, and do not rely on
  this as the only path to your calendar data.

**Authentication / session**

- **Session durability is not seamless.** The bridge holds a Proton session
  locally. When Proton's access/refresh token expires or is invalidated, the
  bridge stops working and you must re-authenticate (`protoxide auth`). There is
  no proven long-lived silent refresh yet. If [alerting](#alerting-apprise--ntfy-etc)
  is configured you'll be notified when this happens.
- **One-time human verification (CAPTCHA) on login.** Proton's anti-abuse system
  challenges new logins; the `auth` flow opens a browser popup to solve it. This
  is expected on first login and occasionally thereafter.

**Sync behaviour**

- **Near-real-time, not instant push.** Inbound latency ≈ the ~30 s event-loop
  poll **plus** your client's own refresh interval. Set the client's calendar
  refresh interval low (e.g. 1 minute) — with CTag, those polls are cheap.
- **Cold start is slow for large calendars.** The first run (or any run after the
  cache is deleted) fetches and decrypts the entire calendar, which for a few
  thousand events takes a few minutes. During that window the server returns
  `503 / still loading` so the client waits and retries rather than seeing an
  empty calendar. Subsequent starts are instant from the on-disk cache.

**Feature gaps**

- **No server-side scheduling (RFC 6638)** — by design (see *Design intent*).
  Attendee scheduling is the client's job.
- **Attendee data round-trip is not implemented.** `ATTENDEE` properties are not
  yet written to or read from Proton's encrypted attendee cards.
- **Recurring-exception edits are limited.** Editing a *single occurrence* of a
  recurring series is not fully mapped to Proton's single-edit model and may not
  round-trip correctly.
- **Two upstream-disabled cryptographic checks remain disabled** (calendar
  passphrase signature verification; the read-path MDC check). Some old/imported
  events are served with an *unverified* signature — this is logged, not silent —
  because decryptability was prioritised over signature verification for a
  personal read bridge.

**Data-at-rest / exposure**

- **The on-disk cache holds decrypted event data**, at
  `<config-dir>/protoxide/calcache-*.json` (mode `0600`). This is the same
  trade-off every local calendar client makes (e.g. Thunderbird's own cache), but
  it does mean plaintext calendar data sits on disk in your home directory.
  Delete those files to purge it.
- **The session is stored encrypted at rest** (NaCl secretbox, keyed by your
  bridge password) at `<config-dir>/protoxide/auth.json`. It is still a
  long-lived credential on your disk — protect it accordingly.
- **Plain HTTP on localhost with HTTP Basic auth.** The CalDAV server binds to
  `127.0.0.1:8081` by default and is not TLS-protected. **Keep it bound to
  localhost. Do not expose it to a network.**

**Scope**

- **Mail / IMAP / SMTP / CardDAV are inherited from hydroxide and are _not_ the
  focus of this fork.** They are not hardened or tested here and may or may not
  work. Use the official Proton Mail Bridge for mail.
- **Developed and tested on macOS.** The config-directory location follows Go's
  `os.UserConfigDir` and should work cross-platform, but only macOS has been
  exercised.

## Setup

Requires Go (see `go.mod`).

```bash
go build -o protoxide ./cmd/protoxide
```

**1. Authenticate** (interactive — the tool only ever receives your credentials
from your own terminal, never from this repo or anywhere else). This opens a
browser popup for Proton's human-verification challenge and prints a **bridge
password** at the end; keep it:

```bash
./protoxide auth <your-proton-address>
```

**2. Run the CalDAV server:**

```bash
./protoxide caldav
```

It listens on `http://127.0.0.1:8081` and logs the first request from a client.

**3. Point your client at the calendar.** In Thunderbird, add a network calendar
of type **CalDAV** using the *direct calendar URL* (not the base path):

```
http://127.0.0.1:8081/caldav/calendars/<your-calendar-id>
```

Authenticate with your **Proton address** as the username and the **bridge
password** as the password. Enable **"Prefer client-side email scheduling"** in
the calendar's properties, and set the **refresh interval to 1 minute**.

> Discovering `<your-calendar-id>`: the base CalDAV endpoint lists your
> calendars; the ID is the last path segment of the calendar's href.

## Running as a service (macOS)

To run the CalDAV bridge headlessly — starting at login, restarting if it
crashes, and coming back after a reboot — install it as a per-user `launchd`
agent:

```bash
# optionally set alerting first (see below)
./service/install.sh
```

The installer builds protoxide, copies the binary and a runner into
`~/Library/Application Support/protoxide/bin/`, writes a LaunchAgent to
`~/Library/LaunchAgents/com.mathewcsims.protoxide.caldav.plist`, and loads it.
Re-run it any time to rebuild and reload. Manage it with:

```bash
launchctl list | grep protoxide          # is it running?
./service/uninstall.sh                    # remove (add --purge to delete the binary too)
```

Logs go to `~/Library/Logs/protoxide/caldav.log` (size-rotated at 10 MiB on
restart). Per-request logging is off unless you run with `-debug`, so the log
stays small in normal use.

**Prerequisite:** the service uses the encrypted session created by
`./protoxide auth <your-proton-address>`, which you must run once first (it is
interactive — CAPTCHA and bridge password). If the Proton session later expires,
the service can't refresh it silently; you'll need to re-run `auth`.

### Running a manual session (debugging)

Once the service is installed it is the **only** thing that should bind
`127.0.0.1:8081`. If you start protoxide by hand while the service is running,
the second instance will fail to bind the port and (under launchd) crash-loop.
So **stop the service first**, run your manual session, then start it again:

```bash
PLIST=~/Library/LaunchAgents/com.mathewcsims.protoxide.caldav.plist

launchctl unload "$PLIST"          # stop the managed service
./protoxide -debug caldav          # manual session with verbose per-request logs
                                   # (Ctrl-C to stop)
launchctl load -w "$PLIST"         # hand control back to the service
```

Use `-debug` for the verbose per-request logging that is otherwise suppressed.
The manual instance shares the same on-disk cache and session as the service, so
nothing needs re-syncing when you switch back.

## Alerting (Apprise → ntfy, etc.)

protoxide can push operational problems to an [Apprise](https://github.com/caronc/apprise)
endpoint (which can fan out to ntfy and anything else Apprise supports). It's
**off unless configured** and never blocks or breaks the bridge if the endpoint
is unreachable. Configure via environment variables (the installer bakes them
into the LaunchAgent; for a manual run, export them first):

| Variable | Meaning |
| --- | --- |
| `PROTOXIDE_APPRISE_URL` | Apprise notify endpoint. For a persistent Apprise config: `http://<host>:8000/notify/<key>`. Required to enable alerts. |
| `PROTOXIDE_APPRISE_URLS` | Only for Apprise's *stateless* endpoint (`…/notify`): the target URL(s), e.g. `ntfy://<host>/protoxide`. Leave blank when using a `/notify/<key>` config endpoint. |

Alerts are sent (and de-duplicated for 10 minutes per kind, so a persistent
fault doesn't flood you) for:

- **Auth failure** — a rejected CalDAV request, most often an **expired Proton
  session** (you'll be told to re-run `auth`).
- **Inbound poll failing / degraded** — the calendar event-loop poller can't
  reach Proton (inbound sync stalled — usually also a session issue).
- **Calendar write failed** — an event couldn't be written back to Proton.
- **Handler panic** — an unexpected fault while serving a request.
- **Process crash** — the service was killed by a signal (the runner reports
  this on the way down; `launchd` then restarts it).

Test your endpoint independently, e.g.:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"title":"protoxide test","body":"hello","type":"info"}' \
  "$PROTOXIDE_APPRISE_URL"
```

## How it works

- **Auth** (`auth/`, `protonmail/`): SRP login against Proton, with a
  browser-popup flow for the human-verification (CAPTCHA) challenge. The session
  is sealed with NaCl secretbox under your bridge password.
- **Cache** (`caldav/cache.go`): the whole calendar is fetched and decrypted once
  into an in-memory map (indexed by a URL/XML-safe path token → Proton event ID
  for O(1) lookups), persisted to disk, and served from memory. Local writes are
  protected from being clobbered by a concurrent reload.
- **Poller** (`caldav/poller.go`): polls Proton's calendar event loop
  (`/calendar/v1/{cal}/modelevents/{cursor}`) every 30 s and patches only the
  changed events into the cache.
- **CTag** (`third_party/go-webdav`): upstream go-webdav can't advertise a change
  token, so it is vendored (v0.6.0, MIT) with a small additive patch to emit the
  CalendarServer `getctag` property. See
  [`third_party/go-webdav/PROTOXIDE-PATCH.md`](third_party/go-webdav/PROTOXIDE-PATCH.md).
  The token is a content hash that changes on any add/edit/delete and is stable
  across restarts.

## Changes from upstream

- **Renamed / re-moduled** as `protoxide`; full MIT attribution to hydroxide and
  ferroxide retained (`LICENSE`, `README.upstream.md`).
- **Write path made to actually work.** Fixed the create/edit round-trip through
  a chain of real bugs: SEQUENCE monotonicity and the `SEQUENCE;VALUE=TEXT`
  malformation Proton rejects with a 500; address-key signing; and preserving the
  client's UID as the stable CalDAV path so created events are recognised by the
  client immediately.
- **Decryption fix** — `CalendarEventCardType.Encrypted()` didn't recognise the
  encrypted-but-unsigned card type (type 1), so those events were served as raw
  ciphertext and dropped. Now decrypted.
- **URL/XML-safe path tokens** — event hrefs are derived from the iCalendar UID,
  hex-encoded when the UID contains characters that would break the href.
- **Cache, poller, and CTag** as described above (on-disk cache, inbound
  event-loop delta sync, change token).
- **Pagination fix** — calendar listings follow Proton's pagination to completion
  instead of silently truncating large calendars.

### Still to do

- Durable, silent session refresh at token expiry.
- Attendee data round-trip through Proton's encrypted attendee cards.
- Recurring-occurrence single-edit mapping.
- Re-enabling the two upstream-disabled cryptographic checks, validated live.

## Security & trust

This talks to an **unofficial, reverse-engineered** Proton API and holds your
**decrypted session locally** — the same trust model as the official Bridge, but
without Proton's QA. Run it only against your own account, on a machine you
control. Your session and keys live in a local config directory (never in this
repository); do not commit that directory or any exported keys. See
[Limitations & caveats](#limitations--caveats) for the full picture.

## License

MIT — Copyright (c) 2017 emersion, (c) 2023 acheong08, (c) 2026 Mathew Sims.
See [`LICENSE`](LICENSE). The original upstream README is preserved as
[`README.upstream.md`](README.upstream.md). The vendored dependency under
`third_party/go-webdav` retains its own MIT license.
```
