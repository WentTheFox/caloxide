# Caloxide

![Caloxide Logo](caloxide-logo.png?v=2)

A local bridge that exposes **Proton Calendar over CalDAV**, so a standards-compliant
calendar client (developed against **Thunderbird**) can read **and write** your Proton
calendar with two-way sync that is current to within about a minute, instead of the read-only, hours-stale ICS
feed that is otherwise the only option.

It is a pinned, audited fork of [`mathewcsims/protoxide`](https://github.com/mathewcsims/protoxide)
(itself a fork of [`acheong08/ferroxide`](https://github.com/acheong08/ferroxide) and
[`emersion/hydroxide`](https://github.com/emersion/hydroxide)): third-party, open-source
bridges that speak Proton's internal API locally and re-expose it over standard
protocols. Caloxide narrows the focus to the calendar path and adds what is needed to run
it unattended on a server.

Proton Calendar has no CalDAV and no public API, because of its end-to-end encryption.
Live, writable desktop access needs a local process that holds your session, does the PGP
work on your machine, and serves a standard protocol.

> **Unofficial and reverse-engineered.** It talks to Proton's private API, which has no
> stability guarantee, and it holds a decrypted Proton session. Run it only against your
> own account on a machine you control. See [Limitations](#limitations).

## What it does

- **Read and write.** The calendar is fetched, decrypted locally and served over CalDAV.
  Create, edit and delete round-trip to Proton and show up in the Proton web app.
- **Inbound sync.** Each calendar's event loop is polled every 30 s and only the changed
  events are patched into the cache. A CalendarServer **CTag** (a content hash) tells
  the client to re-sync promptly. Calendars added or removed in Proton are noticed from
  the account event loop; a removed calendar's poller and cache are dropped.
- **On-disk cache.** Decrypted events are cached, so restarts are instant and queries are
  served from memory.
- **Unattended re-login.** The login password, 2FA (TOTP) seed and mailbox
  password can be stored, encrypted, so an expired session is renewed by the bridge
  itself, with exponential backoff and a cap of 3 attempts per hour.
- **CAPTCHA recovery.** When Proton demands human verification, the bridge stops
  calling Proton and waits. You run `caloxide verify`,
  open a one-time link, answer the CAPTCHA, and it logs in again by itself. The popup
  closes on its own once the CAPTCHA is passed.
- **Alerts.** Problems are sent to a Discord webhook and/or an
  [Apprise](https://github.com/caronc/apprise) endpoint, de-duplicated per kind.
- **Container image and binaries.** A read-only, non-root image and, from the first
  release after v0.3.0, static binaries, both with provenance attestations. See
  [Supply chain](#supply-chain-and-releases).

Mail, IMAP, SMTP and CardDAV code is inherited from hydroxide and is not the focus here.

## Quick start

### 1. Sign in (on a workstation, with a browser)

```bash
caloxide auth <your-proton-address>
```

It asks for your Proton password and, for a 2FA account, optionally the **2FA secret key**
(the base32 seed shown when 2FA was enabled, or set `CALOXIDE_TOTP_SECRET` /
`CALOXIDE_TOTP_SECRET_FILE`). Providing it lets the bridge answer the 2FA challenge itself
later; the seed is only stored after Proton accepted a code generated from it. If Proton
shows a CAPTCHA, a local page opens to answer it.

It prints a **bridge password** at the end. Keep it: it is the password your calendar
client uses, **and** the key that encrypts everything stored in `auth.json`. The server
never stores it.

### 2. Run the server

Container (recommended), with the state directory owned by uid 65532:

```bash
sudo install -d -o 65532 -g 65532 -m 0700 /srv/caloxide
sudo cp ~/.config/caloxide/auth.json /srv/caloxide/caloxide/   # from step 1
docker run -d --name caloxide --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v /srv/caloxide:/data -p 127.0.0.1:8081:8081 \
  ghcr.io/wentthefox/caloxide@sha256:<digest>
```

Pin the **digest**, not a tag, and verify it first:

```bash
gh attestation verify oci://ghcr.io/wentthefox/caloxide@sha256:<digest> --repo WentTheFox/caloxide
```

Or run the binary directly: `caloxide caldav` (listens on `127.0.0.1:8081`).

### 3. Add the calendar in Thunderbird

Add a network calendar of type **CalDAV** using the direct calendar URL:

```
http://127.0.0.1:8081/caldav/calendars/<your-calendar-id>
```

User = your Proton address, password = the bridge password. Enable **Prefer client-side
email scheduling** and set the refresh interval to 1 minute. The first sync of a big
calendar takes minutes; the server answers `503` until it is loaded. The base CalDAV
endpoint lists your calendars, and the ID is the last path segment of a calendar's href.

The server speaks **plain HTTP with Basic auth**, and that password is also the key to
your stored session. Keep it on `127.0.0.1`, or put it behind a TLS reverse proxy with a
LAN-only access list. Never expose it to the internet.

## When Proton asks for a CAPTCHA

The bridge latches into a waiting state (no calls to Proton) and alerts you. Then:

```bash
caloxide verify            # in the container: docker exec caloxide /caloxide -config-home /data verify
```

It prints a link built from `CALOXIDE_PUBLIC_URL`, valid for 10 minutes and usable once.
The page only exists while a window is open (otherwise it answers 404) and the command is
refused unless a CAPTCHA is actually pending. Open it, press *Open the CAPTCHA*, follow the
steps on the page, and the bridge logs in again with no restart and no new bridge password.
Both pages follow your browser's light or dark theme. The mechanism and the findings behind
it are in [`docs/design/unattended-reauth.md`](docs/design/unattended-reauth.md).

## Configuration

State lives in `<config-home>/caloxide/` (`auth.json`, `calcache-*.json`, the control
socket). `-config-home` sets it; the image uses `/data`. To be a drop-in replacement for
upstream, `PROTOXIDE_*` variables and an existing `protoxide` state directory are still
honoured when their `CALOXIDE_*` / `caloxide` counterparts are absent.

| Setting | Meaning |
| --- | --- |
| `CALOXIDE_PUBLIC_URL` | Address clients use; the one-time CAPTCHA link is built from it. |
| `CALOXIDE_TOTP_SECRET`, `CALOXIDE_TOTP_SECRET_FILE` | 2FA seed for `auth` (or enter it at the prompt). |
| `CALOXIDE_DISCORD_WEBHOOK_URL`, `…_FILE` | Discord alerts (mentions disabled; the URL is never logged). |
| `CALOXIDE_APPRISE_URL`, `CALOXIDE_APPRISE_URLS` | Apprise alerts: a `/notify/<key>` endpoint, or the stateless `/notify` endpoint plus target URLs. |
| `CALOXIDE_EARLY_SYNC` | `on` serves a calendar while it is still loading for the first time, as events are decoded. **Off by default**; for the initial import only, see [Sync behaviour](#sync-behaviour). |
| `CALOXIDE_LOAD_ALERTS` | Alerts about a calendar's first load: `off`, `done` (default, one message when everything has loaded) or `progress` (also a status message every `…_EVERY`). |
| `CALOXIDE_LOAD_ALERT_AFTER`, `CALOXIDE_LOAD_ALERT_EVERY` | Loads that finish sooner than `…_AFTER` (default 1m) send nothing. In `progress` mode a status message goes out every `…_EVERY` (default 30m, at least 5m). |
| `CALOXIDE_STANDBY`, `CALOXIDE_STANDBY_AFTER`, `CALOXIDE_STANDBY_INTERVAL` | Standby (default **on**): after `…_AFTER` (default 5m) without a client request, polling slows to `…_INTERVAL` (default 15m). See [Sync behaviour](#sync-behaviour). |
| `CALOXIDE_PROTONDRIVE_APP_VERSION` | App version to present (same name as rclone's option). Leave unset: see [`FORK.md`](FORK.md). |
| `HYDROXIDE_BRIDGE_PASS` | Bridge password, to skip the prompt (inherited name). |

Useful flags: `-caldav-host`, `-caldav-port`, `-config-home`, `-debug`, `-app-version`
(alias `-protondrive-app-version`), `-user-agent`, `-proxy-url`, `-tls-cert`/`-tls-key`.
Run `caloxide -h` for all of them and the commands (`auth`, `caldav`, `verify`, `status`,
`push-probe`, and the inherited mail ones).

Alerts are sent for: a rejected CalDAV login (usually an expired session), a stalled
inbound poll, Proton rate limiting us, (optionally) a long calendar load, a failed calendar write, a handler panic, a re-login that needs you, and
(when run as a service) a crash.

## Sync behaviour

- **Latency** is about the 30 s poll plus your client's refresh interval. Set the client
  to refresh every minute; with the CTag those polls are cheap.
- **Failures back off** exponentially (30 s up to 10 min) instead of retrying a dead
  session every 30 s.
- **Push is not available yet.** Proton's web client has a push channel (server-sent
  events, behind the `PingOMatic` flag) that caloxide already implements, but Proton's API
  currently answers 404 for it, so polling is the only mechanism. If Proton enables it,
  pings will wake the pollers and the safety-net poll relaxes to 5 minutes by itself.
  Details and how to check: [`FORK.md`](FORK.md). `caloxide push-probe <address>` prints
  what the channel does, read-only.
- **Cold start** (first run, or after deleting the cache) fetches the whole calendar and
  decrypts it. The wait is almost all network latency (100 events per page, seconds per
  page; decrypting 700 events takes about a second), so up to two pages per calendar and
  three overall are fetched at once. Each page is decoded as it arrives. Until a calendar
  is loaded the server answers `503`, and clients retry.
- **Progress is always logged and visible.** The page lines say `running total 1200 of 3100,
  38%` (the total comes from Proton's `events/count`), the 503 text says how far the load has
  got, and `caloxide status` prints one line per calendar (state, events, elapsed), the
  rate-limit pause, the push channel and standby. In a container:
  `docker exec caloxide /caloxide -config-home /data status`. It talks to the running server
  over the control socket only, never over the network.
- **The on-disk cache is encrypted and never passes itself off as complete.** The file is
  sealed (see Limitations). Events are stored as their structure (not as iCalendar text), so every
  event comes back as it went in, and a file also records how many events it was meant to hold.
  Without a key (which cannot happen in normal use) nothing is saved, never a plaintext copy. If a restore finds fewer, the calendar counts as
  not loaded and is fetched from Proton again in full, with a log line saying how many events
  were unreadable and why. Caches from earlier versions are still read and are replaced by sealed
  ones (a `calcache-*.json.bak` left by version 0.6.1 is deleted). This only ever reads from Proton,
  nothing is written to it.
- **Every event has to be sendable.** The CalDAV library encodes an event as iCalendar for every
  response, and its encoder is strict (exactly one `UID` and `DTSTAMP`, at most one of many other
  properties, no `DTEND` together with `DURATION`, no raw line break inside a value). An event
  that fails is listed to the client but its data comes back as an error, so it never appears.
  Events are therefore repaired from the encoder's own complaints, both as they are assembled from
  Proton's cards and when a cache is restored: a missing `VERSION`, `PRODID`, `DTSTAMP` or `UID`
  is filled in, the first of several single-value properties is kept, `DURATION` goes when `DTEND`
  is there, line breaks inside a value are escaped. This changes the copy held here and nothing
  is written to Proton. The log summarises what was repaired, and anything beyond repair, once per
  load, with no event text.
- **Repeated properties are all kept.** Merging an event's cards used to keep only the last value
  of a property that appears more than once, so a recurring event lost all but one `EXDATE` (the
  excluded occurrences came back) and an event lost all but one `ATTENDEE`.
- **Events must not share an address.** A client keys an event by its URL, which comes from the
  event's `UID` (plus its `RECURRENCE-ID` for a single edited occurrence). Two events at one URL
  cannot both be delivered, and which one is served can change whenever the cache is rebuilt, so
  recurring events can seem to vanish and return. A load, a restore and `cache-check` count such
  shared addresses, and each load also counts events whose data does not show what Proton's own
  record says (a recurrence id, excluded dates or a recurrence rule that only the record has).
  These are measurements, not repairs.
- **One resource per series.** RFC 4791 (section 4.1) wants a recurring series and its edited
  occurrences in a single calendar object resource, and a client such as Thunderbird keys an item
  by `UID`. Proton keeps each edited occurrence as an event of its own, and serving them as
  separate resources made Thunderbird download the same group of events again on every full sync
  and let recurring events blink out of view meanwhile. Events are therefore grouped by `UID` for
  clients: an ordinary event is served exactly as before (same address and ETag), and a series
  with edited occurrences is one resource (the series first, then its occurrences in date order)
  whose ETag changes when any of them does. Inside the cache each Proton event stays separate.
  Deleting such a resource deletes the series and all its occurrences (occurrences first); a
  failed delete stops and is reported. Writes are limited for now: an ordinary event can be
  created, edited and deleted as before, but a write that would split or merge a series with
  edited occurrences is refused (HTTP 403 with the reason) instead of being guessed at, so change
  those in Proton Calendar. Loads, restores and `cache-check` count the series that have edited
  occurrences.
- **`caloxide cache-check`** is the dry run: it reads the cache files and reports, per calendar,
  how many events read back and whether the server would trust the file. It changes nothing,
  never contacts Proton, prints counts and error classes but never event text, and exits non-zero
  if any calendar would be loaded again. Sealed caches need the bridge password to be opened:
  it asks for it (or reads `HYDROXIDE_BRIDGE_PASS`), only if there is a sealed file to check. In a container:
  `docker exec caloxide /caloxide -config-home /data cache-check`.
- **Load alerts** (`CALOXIDE_LOAD_ALERTS`) are for first loads that may take seconds or hours.
  Quick loads send nothing. With `progress`, a message every interval lists each calendar's
  progress (or says the total is unknown), flags a calendar that made no progress since the
  last message, and mentions any rate-limit pause.
- **Early sync** (`CALOXIDE_EARLY_SYNC=on`, off by default) serves a calendar as soon as
  its first page is decoded instead of when everything is loaded. Every decoded page changes
  the CTag, so a client refreshing every minute sees the calendar fill in; CalDAV has no way
  to push it. It is meant for the **initial import** and should be unset afterwards. The risk
  it carries: if the server has no cache for a calendar while a client still holds a full
  local copy (for example after deleting the cache), the client drops what it cannot see yet
  from its own copy until it arrives. Nothing is deleted from Proton, and an empty calendar is
  never served.
- **Standby** (default on). Thunderbird asks about once a minute while it is open. After five
  minutes without an authenticated request the calendar pollers and the account event loop
  drop to a 15 minute pace. The first request after that waits (at most 15 s) while every
  calendar is polled once, so what it reads is as fresh as normally, and polling returns to
  30 s. It watches CalDAV requests only, so it switches itself off when `caloxide serve` also
  runs IMAP, SMTP or CardDAV.
- **Checking a calendar does not ask Proton.** A client's change-token check (about once per
  calendar per refresh) needs the calendar's name and keys from Proton's calendar list. That list
  is reused for 30 seconds, shared by checks that arrive together, fetched fresh when Proton's
  account events report a calendar being added, removed or changed, and an older copy (up to an
  hour) keeps checks working while Proton cannot be asked. The change token itself comes from the
  local cache on every call, so a change to an event still shows at once. Six calendars at a
  one-minute refresh therefore cost about two requests a minute instead of six.
- **Rate limits are shared.** Proton does not publish its limits, so every request to the
  API goes through one budget for the whole process, whichever calendar it is for: at most
  four request starts a second, and when Proton answers `429` (or `503` with `Retry-After`)
  all requests pause for the time it names (or 10, 20, 40 s without one), retrying at most
  three times. A pause longer than two minutes fails requests at once without contacting
  Proton. After any limit, calendars load one page at a time for ten minutes. You get an
  alert the first time it happens.
- **Unexpected responses are logged** with status, headers and body (`unexpected response:
  ...` lines), so they can be understood later. Cookies, tokens and other credentials are
  blanked, JSON strings over 80 characters are replaced by their length, bodies are cut at
  4 KiB, and query strings are never logged.

## Limitations

- **Unofficial.** It can break whenever Proton changes its internals. Treat it as
  best-effort, keep the read-only ICS subscription as a fallback, and do not treat the
  cache as a backup.
- **Little real-world testing.** One account, a handful of calendars. Re-login and CAPTCHA
  recovery are tested against a fake API; the full cycle on a real revoked session has not
  been run yet.
- **Series with edited occurrences are read-only through the bridge** (see above); everything
  else can be created, edited and deleted.
- **No server-side scheduling (RFC 6638).** Invitations are the client's job, hence the
  *client-side scheduling* setting.
- **Attendee data does not round-trip** through Proton's encrypted attendee cards, and
  editing a single occurrence of a recurring series is not fully mapped.
- **Signatures are not enforced on read.** An event whose signature does not verify is
  served and logged ("serving event with unverified signature"), not dropped, so that old
  or imported events stay visible.
- **Secrets on disk.** `auth.json` holds the session and, if you provided them, the login
  password and 2FA seed, sealed with NaCl secretbox under the bridge password. The calendar
  cache (`calcache-*.json`) is sealed the same way, with a key derived from the bridge password
  and kept only in memory, so it opens only after a client has authenticated. Whoever has the
  bridge password can open both; whoever has only the files cannot. Visible without it: the
  calendar IDs in the file names and roughly how big each calendar is. Caches written by earlier
  versions were plaintext and are replaced by sealed ones; the old content may linger in free
  disk blocks (flash storage cannot be reliably wiped from software), so use disk encryption if
  that matters. Changing the bridge password makes the old cache unreadable; it is then loaded
  from Proton again.
- **Scope.** Calendar is what is maintained. Mail, IMAP, SMTP and CardDAV are inherited
  and untested; use the official Proton Mail Bridge for mail.

## Supply chain and releases

The fork exists so that the code holding a Proton session has been reviewed and does not
change underneath you. Upstream is never merged automatically; Go modules must be at least 14 days old; every
action is pinned to a commit SHA and the base image to a digest; a source audit fails on
any new outbound host, sensitive API, module, binary or hidden text; the vendored
`go-webdav` must equal upstream plus a recorded patch; `govulncheck` and CodeQL run on
every change. The full policy is in [`FORK.md`](FORK.md).

Pushing a `vX.Y.Z` tag on `main` publishes the multi-arch (amd64, arm64) image to
`ghcr.io/wentthefox/caloxide` with an SBOM and a signed provenance attestation, then
creates a GitHub release with static binaries for Linux, macOS and Windows (amd64 and
arm64), a `SHA256SUMS` file and an attestation per binary:

```bash
gh attestation verify caloxide_vX.Y.Z_linux_amd64 --repo WentTheFox/caloxide
```

`.github/scripts/build-release.sh <version>` builds the same binaries locally.

## Running as a service

Both installers run the server as you (no root), restart it if it crashes, and expect a
prior `caloxide auth <address>`. Alert settings come from the environment when you run
them: `CALOXIDE_DISCORD_WEBHOOK_URL`, `CALOXIDE_APPRISE_URL`, `CALOXIDE_APPRISE_URLS`.

**Linux (systemd).** `./service/install-systemd.sh` builds caloxide (or installs a
downloaded release binary: `CALOXIDE_BINARY=/path/to/caloxide ./service/install-systemd.sh`)
and installs `caloxide-caldav.service` as a user unit. Add `--linger` to start it at boot
without a login. The unit sandboxes the process (read-only filesystem except the state
directory, no new privileges, IP and unix sockets only), keeps alert settings in an
owner-only `~/.config/caloxide.env`, and runs a small script after every stop that alerts
if the process was killed by a signal or the OOM killer, which it cannot report itself.

```bash
systemctl --user status caloxide-caldav.service
journalctl --user -u caloxide-caldav.service -f
./service/uninstall-systemd.sh          # --purge also removes the binary and alert settings
```

**macOS (launchd).** `./service/install.sh` builds caloxide and installs a LaunchAgent
(`tf.went.caloxide.caldav`) that starts at login; logs go to
`~/Library/Logs/caloxide/caldav.log`. `./service/uninstall.sh` removes it.

Only one process can bind `127.0.0.1:8081`, so stop the service before a manual session
(`systemctl --user stop caloxide-caldav.service`, or `launchctl unload` the agent). To
change the port or host, add flags to the unit with `systemctl --user edit`.

## How it works

- `auth/`, `protonmail/`: SRP login, session handling, re-login with backoff, the
  verification window, and the Proton API client.
- `caldav/`: CalDAV backend, the decrypted cache, per-calendar pollers, and the optional
  push wiring.
- `webverify/`: the one-time CAPTCHA page and the control socket behind `caloxide verify`.
- `notify/`: Discord and Apprise alerts. `cookiestore/`, `totp/`, `backoff/`: small
  single-purpose packages.
- `third_party/go-webdav`: vendored v0.7.0 with a small patch to emit the CTag, see
  [`CALOXIDE-PATCH.md`](third_party/go-webdav/CALOXIDE-PATCH.md).

## Changes from upstream

Beyond the original write-path, decryption and pagination fixes (create/edit round-trip,
unsigned-card decryption, URL-safe event paths, full calendar listings), this fork adds
the on-disk cache, event-loop delta sync and CTag; the unattended re-login with stored
credentials and TOTP; the bounded recursion and request gate that stop a dead session
from hammering Proton; the CAPTCHA verification window; Discord alerts; persistent
Proton cookies; the dormant push client; the removed-calendar handling; the container
image, release binaries and audit guardrails.

## License

MIT. Copyright (c) 2017 emersion, (c) 2023 acheong08, (c) 2026 Mathew Sims; modifications
by WentTheFox under the same license. See [`LICENSE`](LICENSE). The original README is
kept as [`README.upstream.md`](README.upstream.md). The vendored dependency under
`third_party/go-webdav` keeps its own MIT license.
