# Protoxide

A local bridge that exposes **Proton Calendar over CalDAV** on `localhost`, so a
standards-compliant calendar client can read and write your Proton calendar with
real, near-real-time two-way sync — instead of the read-only, hours-stale ICS
feed that is otherwise the only option.

It is a fork of [`acheong08/ferroxide`](https://github.com/acheong08/ferroxide),
itself a fork of [`emersion/hydroxide`](https://github.com/emersion/hydroxide) —
third-party, open-source bridges that speak Proton's internal API locally and
re-expose it over standard protocols (the same idea as the official Proton Mail
Bridge, which covers mail only). Protoxide narrows the focus to the calendar/CalDAV
path and hardens it for daily use.

## Why this exists

Proton Calendar has no CalDAV support and no public API — a deliberate
consequence of its end-to-end encryption, where the server cannot read events by
design. The only way to get live, writable desktop access is a local process
that holds your session, does the PGP work on your machine, and serves a standard
protocol locally. That is what this is.

## Design intent

Protoxide is built to be driven by a CalDAV client that handles its own
invitation scheduling **client-side** (Thunderbird's "Prefer client-side email
scheduling" option). Under that model the bridge never implements CalDAV
server-side scheduling (RFC 6638): the client sends iTIP/iMIP invitations over
its own SMTP identity and processes RSVP replies, while the bridge only has to
store and serve events (attendees included) as ordinary CalDAV objects. This
keeps the bridge substantially smaller than a full scheduling server.

## Changes from upstream

- **Renamed** and re-moduled as `protoxide`; retains full MIT attribution to
  hydroxide and ferroxide (see `LICENSE`).
- **SEQUENCE monotonicity fix** — Proton silently rejects an edit whose iCalendar
  `SEQUENCE` does not strictly increase over the stored event. Protoxide reads the
  prior value from Proton's signed (cleartext) shared card and forces
  `SEQUENCE ≥ old+1` on every update, and ensures a `SEQUENCE:0` on create. This
  addresses the known upstream write-corruption bug.
- **Pagination fix** — calendar listings now follow Proton's pagination to
  completion (with a hard page cap) instead of returning only the first page and
  silently truncating large calendars.

### Planned / in progress

- Re-enabling the two upstream-disabled cryptographic checks (calendar passphrase
  signature verification; the read-path MDC check), validated against a live
  session rather than enabled blind.
- Recurring-event exception edits (single-occurrence PUTs mapped to Proton's
  single-edit fields).
- Attendee data round-trip through Proton's encrypted attendee cards (read +
  write of `ATTENDEE` properties — the *data*, not scheduling, which the client
  owns per the design intent above).

## Security & trust

This talks to an **unofficial, reverse-engineered** Proton API and holds your
**decrypted session locally** — the same trust model as the official Bridge, but
without Proton's QA. Run it only against your own account, on a machine you
control. It can break whenever Proton changes their internal API. Your session
and keys are stored in a local config directory (never in this repository); do
not commit that directory or any exported keys.

## Build

Requires Go (see `go.mod`). Standard build:

```bash
go build ./cmd/protoxide
```

Authentication is interactive and is performed by you — the tool never receives
your credentials from anywhere but your own terminal:

```bash
./protoxide auth <your-proton-address>
./protoxide caldav
```

## License

MIT — Copyright (c) 2017 emersion, (c) 2023 acheong08, (c) 2026 Mathew Sims.
See [`LICENSE`](LICENSE). The original upstream README is preserved as
[`README.upstream.md`](README.upstream.md).
