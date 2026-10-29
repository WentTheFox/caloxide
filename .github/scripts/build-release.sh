#!/usr/bin/env bash
# Builds the release binaries into <outdir> (default dist/) and writes SHA256SUMS.
# Static (CGO off), stripped, -trimpath, so the same commit builds the same bytes
# for a given Go version. Used by the publish workflow; runnable locally:
#   .github/scripts/build-release.sh v0.3.0 dist
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

version=${1:?usage: build-release.sh <version, e.g. v0.3.0> [outdir]}
out=${2:-dist}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like v1.2.3, got: $version" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  ext=""
  [ "$os" = windows ] && ext=".exe"
  name="protoxide_${version}_${os}_${arch}${ext}"
  echo "building $name"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$out/$name" ./cmd/protoxide
done

(cd "$out" && sha256sum protoxide_* > SHA256SUMS)
echo "wrote $out/SHA256SUMS"
