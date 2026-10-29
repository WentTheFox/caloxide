#!/usr/bin/env bash
# Verifies third_party/go-webdav is exactly upstream emersion/go-webdav v0.6.0
# plus the patch recorded in .github/audit/go-webdav.patch, and nothing else.
# Upstream is fetched by commit SHA (not tag), so a moved tag can't fool it.
#
#   check-vendored-webdav.sh                  verify (default)
#   check-vendored-webdav.sh --update-expected  rewrite the recorded patch
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
UPSTREAM_URL=https://github.com/emersion/go-webdav.git
UPSTREAM_SHA=7f8c17ad71358ddb6e1462e4f204e022e3a83399 # v0.6.0 (commit, not the annotated tag object)
EXPECTED="$ROOT/.github/audit/go-webdav.patch"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/a"
git -C "$work/a" init -q
git -C "$work/a" fetch -q --depth 1 "$UPSTREAM_URL" "$UPSTREAM_SHA"
git -C "$work/a" -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C "$work/a" rev-parse HEAD)" = "$UPSTREAM_SHA" ] || { echo "fetched the wrong commit"; exit 1; }
rm -rf "$work/a/.git"

# Read git's index, not the working tree, so local CRLF/autocrlf settings can't cause drift.
git -C "$ROOT" ls-files -z -- third_party/go-webdav | (cd "$ROOT" && xargs -0 git checkout-index --prefix="$work/full/" --)
mv "$work/full/third_party/go-webdav" "$work/b"
rm -f "$work/b/PROTOXIDE-PATCH.md"

actual="$work/actual.patch"
(cd "$work" && git diff --no-index --no-color a b > "$actual") || true

if [ "${1:-}" = "--update-expected" ]; then
  mkdir -p "$(dirname "$EXPECTED")"
  cp "$actual" "$EXPECTED"
  echo "wrote $EXPECTED ($(grep -c '^diff --git' "$actual") files differ from upstream)"
  exit 0
fi

if diff -u "$EXPECTED" "$actual"; then
  echo "ok: third_party/go-webdav == upstream $UPSTREAM_SHA + recorded patch"
else
  echo "::error::third_party/go-webdav differs from upstream v0.6.0 + the recorded patch (diff above)"
  exit 1
fi
