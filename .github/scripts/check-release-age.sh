#!/usr/bin/env bash
# Go has no built-in "minimum release age" (npm's min-release-age). This is the
# equivalent as a CI gate: any module version that is new or changed in go.mod
# relative to BASE must have been published at least MIN_DAYS ago, per the Go
# module proxy's own timestamp. A freshly pushed malicious release therefore
# can't be adopted before the community has had time to notice it.
#
#   check-release-age.sh <base-ref-or-sha> [min-days=14]
#
# Urgent security fix? Add "module@version  # reason" to
# .github/audit/release-age-exceptions.txt in the same change (visible in review).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

BASE=${1:?usage: check-release-age.sh <base-ref-or-sha> [min-days]}
MIN_DAYS=${2:-14}
EXC=.github/audit/release-age-exceptions.txt
PROXY=${GOPROXY_URL:-https://proxy.golang.org}

mods() { # go.mod from stdin -> "module@version" lines (requires only)
  tr -d '\r' | awk '
    /^require[[:space:]]*\(/ {b=1; next}
    b && /^\)/ {b=0}
    b && NF >= 2 {print $1 "@" $2}
    /^require[[:space:]]+[^(]/ {print $2 "@" $3}' | LC_ALL=C sort -u
}
# Go proxy path escaping: uppercase letters become "!" + lowercase.
escape() { sed -E 's/[A-Z]/!\L&/g' <<<"$1"; }

if [[ "$BASE" =~ ^0+$ ]] || ! git cat-file -e "$BASE:go.mod" 2>/dev/null; then
  echo "no base go.mod to compare against; treating every module as unchanged"
  exit 0
fi

changed=$(LC_ALL=C comm -13 <(git show "$BASE:go.mod" | mods) <(git show HEAD:go.mod | mods))
[ -n "$changed" ] || { echo "ok: no module versions added or changed"; exit 0; }

now=$(date +%s)
fail=0
while IFS= read -r mv; do
  [ -z "$mv" ] && continue
  mod=${mv%@*}; ver=${mv#*@}
  if [ -f "$EXC" ] && grep -qE "^$(sed 's/[.[\*^$/]/\\&/g' <<<"$mv")([[:space:]]|\$)" "$EXC"; then
    echo "exception: $mv (listed in $EXC)"; continue
  fi
  info=$(curl -fsS -m 20 "$PROXY/$(escape "$mod")/@v/$ver.info") || { echo "::error::could not look up $mv on $PROXY"; fail=1; continue; }
  published=$(jq -r .Time <<<"$info")
  age_days=$(( (now - $(date -d "$published" +%s)) / 86400 ))
  if [ "$age_days" -lt "$MIN_DAYS" ]; then
    echo "::error::$mv was published $published (${age_days}d ago); minimum is ${MIN_DAYS}d"
    fail=1
  else
    echo "ok: $mv published ${age_days}d ago"
  fi
done <<<"$changed"
exit "$fail"
