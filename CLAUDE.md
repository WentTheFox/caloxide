# protoxide (WentTheFox fork)

Pinned, audited fork of a Proton Calendar CalDAV bridge. It holds a live Proton
session and calendar plaintext, so the code that runs here is deliberately boring and
reviewed. Read `FORK.md` for the policy. For anything touching `auth/`, `notify/`,
credentials or secret storage, read `docs/design/unattended-reauth.md` first.

## Rules

- Never add a Go module, an outbound host, or use of exec/sockets/env/file-write APIs
  without saying so explicitly; the guardrails fail on them on purpose. Do not edit the
  allowlists in `.github/audit/` just to make a check pass: surface the change and let
  the owner decide.
- New or bumped module versions must be at least 14 days old. Actions are pinned to
  commit SHAs and Docker bases to digests.
- Never log, print or commit secrets, tokens, cookies or the bridge password. Do not
  run `protoxide auth` or handle real Proton credentials.
- Upstream (mathewcsims/protoxide) is never merged automatically.
- Commit as the repo's configured identity (WentTheFox). No branches unless asked.
  Push and tag only when asked; a `v*.*.*` tag on main publishes an image.

## Checks (run before committing)

    .github/scripts/audit-source.sh
    .github/scripts/check-action-pins.sh
    .github/scripts/check-vendored-webdav.sh
    .github/scripts/check-release-age.sh <base-ref>

## Gotchas

- `audit-source.sh` uses `git grep`, which only sees tracked files: `git add` new files
  before running it.
- This WSL checkout has `core.autocrlf=true`, so working-tree files may show as CRLF
  while the index is LF. The scripts read git's index where it matters.
- No system Go toolchain. Fetch the official tarball into a scratch directory and verify
  its sha256 (`curl -L`, or you get a redirect page). Use `GOFLAGS=-mod=readonly`,
  `GOTOOLCHAIN=local`. `go test` runs repo code; CI does that.
- When pinning an action or tag by SHA, use the commit SHA, not the annotated tag
  object's SHA.
