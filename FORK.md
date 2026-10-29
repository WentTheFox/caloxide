# About this fork

`WentTheFox/protoxide` is a pinned, audited fork of
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

Published to `ghcr.io/wentthefox/protoxide` for linux/amd64 and linux/arm64 when a
`vX.Y.Z` tag on `main` is pushed. The image is a static binary on `scratch`, runs as
uid/gid 65532, has no shell, and carries an SBOM and a signed provenance attestation:

    gh attestation verify oci://ghcr.io/wentthefox/protoxide@sha256:<digest> --repo WentTheFox/protoxide

Pin the digest, not the tag.

Runtime notes:
- Config and the encrypted session live in `/data/protoxide/` (mount a volume owned by 65532:65532).
- The server speaks **plain HTTP with Basic auth**. The Basic-auth password (the "bridge
  password") is also the key that decrypts the stored Proton session, so publish the
  port on `127.0.0.1` only and terminate TLS in a reverse proxy.
- `protoxide auth <address>` needs a browser for Proton's human-verification step, so run
  it on a workstation, then copy `auth.json` into the volume.

## Alerts

Failures that need a human (session expired and could not be renewed, breaker open,
write failed, server stopped) are reported by `notify`. Sinks, each optional:

- **Discord:** `PROTOXIDE_DISCORD_WEBHOOK_URL`, or `..._FILE` (a path, for Docker secrets).
  The URL contains a secret token: it is validated (https, `discord.com` or
  `discordapp.com` only, path `/api/webhooks/<id>/<token>`), never followed through a
  redirect, and never written to logs. Messages cannot mention anyone, and are
  debounced to one per kind per 10 minutes.
  With the Infisical backend it can instead live in the secret store as
  `DISCORD_WEBHOOK_URL`; an environment webhook always wins. It is loaded into memory
  at start and on every session load and re-login (and cleared if the secret is
  removed), so an Infisical outage *after* start can still be reported. On a cold
  start while Infisical is down nothing is known yet, so no alert can be sent: set the
  environment variable too if you need alerts for that case.
- **Apprise:** `PROTOXIDE_APPRISE_URL` (and `..._URLS`), as before.

A misconfigured webhook sends nothing and logs why (without the URL).

