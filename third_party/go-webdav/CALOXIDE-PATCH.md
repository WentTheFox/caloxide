# Vendored fork of go-webdav

This is a vendored copy of [github.com/emersion/go-webdav](https://github.com/emersion/go-webdav)
v0.6.0 (MIT, see `LICENSE`), used via a `replace` directive in the caloxide
`go.mod`.

## Why it's vendored

Upstream go-webdav's CalDAV server exposes no hook to advertise the
CalendarServer `getctag` property (`http://calendarserver.org/ns/`), and the
`caldav.Calendar` property set is hard-coded. Without `getctag`, a client such
as Thunderbird has no cheap change signal and only re-syncs on its full refresh
interval. caloxide's on-disk cache and calendar event-loop poller keep the
served data live, so a change token lets clients pick up changes promptly.

## The patch

Minimal, additive, and backwards-compatible:

- `caldav/caldav.go` — added a `CTag string` field to `Calendar`.
- `caldav/elements.go` — added the `getctag` element and its
  `http://calendarserver.org/ns/` namespace.
- `caldav/server.go` — in `propFindCalendar`, advertise `getctag` when
  `Calendar.CTag` is non-empty.

This is upstreamable; if accepted upstream the fork can be dropped and the
`replace` directive removed.
