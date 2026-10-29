#!/usr/bin/env bash
# Fails if any workflow references a third-party action by a mutable ref
# (tag/branch) instead of a full 40-char commit SHA, or fetches/executes
# unpinned code (`@latest`, curl|sh). A tag can be moved to malicious code after
# the fact; a commit SHA cannot.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

fail=0
shopt -s nullglob
files=(.github/workflows/*.yml .github/workflows/*.yaml)
[ "${#files[@]}" -gt 0 ] || { echo "no workflows found"; exit 0; }

for f in "${files[@]}"; do
  while IFS= read -r line; do
    n=${line%%:*}
    ref=$(sed -E 's/^[0-9]+:[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^["'"'"']//; s/["'"'"']$//' <<<"$line")
    case "$ref" in
      ./*) continue ;;
      docker://*@sha256:????????????????????????????????????????????????????????????????) continue ;;
      docker://*) echo "::error file=$f,line=$n::docker image not pinned by digest: $ref"; fail=1; continue ;;
    esac
    if ! [[ "$ref" =~ ^[A-Za-z0-9._/-]+@[0-9a-f]{40}$ ]]; then
      echo "::error file=$f,line=$n::action not pinned to a full commit SHA: $ref"
      fail=1
    fi
  done < <(grep -n -E '^[[:space:]]*-?[[:space:]]*uses:' "$f" || true)

  while IFS= read -r line; do
    echo "::error file=$f,line=${line%%:*}::unpinned fetch/execute in workflow: ${line#*:}"
    fail=1
  done < <(grep -n -E '@latest\b|(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh\b' "$f" || true)
done

# Dockerfile base images must be pinned by digest (scratch and earlier build stages excepted).
if [ -f Dockerfile ]; then
  declare -A stage=()
  while IFS= read -r l; do
    n=${l%%:*}
    read -r -a w <<<"${l#*:}"            # FROM [--platform=x] image [AS name]
    i=1; while [[ "${w[$i]}" == --* ]]; do i=$((i + 1)); done
    img=${w[$i]}
    if [ "${img,,}" != scratch ] && [ -z "${stage[${img,,}]:-}" ]; then
      [[ "$img" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "::error file=Dockerfile,line=$n::base image not pinned by digest: $img"; fail=1; }
    fi
    if [ "${w[$((i + 1))]:-}" != "" ] && [ "${w[$((i + 1))],,}" = as ]; then stage[${w[$((i + 2))],,}]=1; fi
  done < <(grep -n -i -E '^FROM[[:space:]]' Dockerfile)
fi

[ "$fail" -eq 0 ] && echo "ok: every action and Dockerfile base image is pinned"
exit "$fail"
