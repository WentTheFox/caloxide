#!/usr/bin/env bash
# Static guardrails against a change that adds a way to leak credentials or
# smuggle in instructions. It is deliberately dumb and strict: anything new fails
# the build until a human reviews it and updates the allowlists in .github/audit/.
#
#   audit-source.sh [target-dir]            check the git tree at target-dir (default .)
#   audit-source.sh --update-baseline [dir] regenerate .github/audit/sensitive-api-baseline.txt
#
# Checks (tracked files only):
#   1. every hostname in non-comment Go code is in egress-hosts.txt
#   2. every (sensitive API, file) pair is in sensitive-api-baseline.txt
#      (exec, sockets, HTTP clients/servers, env access, file writes, unsafe, cgo...)
#   3. go.mod has no replace directive other than the known vendored go-webdav
#   4. no tracked binary files beyond those in the baseline
#   5. no hidden/bidirectional Unicode (Trojan Source, zero-width, tag characters)
#   6. no text addressed to AI agents / prompt-injection phrasing
set -euo pipefail

AUDIT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../audit" && pwd)
HOSTS_FILE="$AUDIT_DIR/egress-hosts.txt"
BASELINE="$AUDIT_DIR/sensitive-api-baseline.txt"
UPDATE=0
if [ "${1:-}" = "--update-baseline" ]; then UPDATE=1; shift; fi
cd "${1:-.}"

fail=0
err() { echo "::error::$*"; fail=1; }

GO=(-- '*.go' ':!third_party' ':!*_test.go')

# 1. egress hosts -------------------------------------------------------------
allowed=$(grep -v -E '^\s*(#|$)' "$HOSTS_FILE" | sort -u)
found=$(git grep -n -I -E 'https?://[A-Za-z0-9._-]+' "${GO[@]}" \
  | awk '{ l=$0; sub(/^[^:]*:[0-9]+:/, "", l); if (l !~ /^[[:space:]]*\/\//) print $0 }' \
  | grep -o -E 'https?://[A-Za-z0-9._-]+' | sed -E 's#^https?://##' | sort -u || true)
while IFS= read -r h; do
  [ -z "$h" ] && continue
  grep -qxF "$h" <<<"$allowed" || err "egress: host '$h' appears in Go code but is not in .github/audit/egress-hosts.txt"
done <<<"$found"

# Dependency names, read from git's index so working-tree line endings don't matter.
GOMOD=$(git show :go.mod | tr -d '\r')
MODS_FILE="$AUDIT_DIR/go-modules.txt"
mods=$(awk '/^require[[:space:]]*\(/{b=1;next} b&&/^\)/{b=0} b{print $1} /^require[[:space:]]+[^(]/{print $2}' <<<"$GOMOD" | LC_ALL=C sort -u)

# 2. sensitive API usage -----------------------------------------------------
PATTERNS=(
  'os/exec|exec\.Command'
  'net\.(Dial|DialTimeout|Listen|ListenPacket|LookupHost|LookupIP|LookupAddr|LookupTXT|LookupCNAME)'
  'tls\.(Dial|Listen)'
  'http\.(Get|Post|PostForm|Head|NewRequest|NewRequestWithContext|ListenAndServe|ListenAndServeTLS|DefaultClient|DefaultTransport|Client\{|Transport\{|Server\{)'
  'InsecureSkipVerify'
  'syscall\.'
  'unsafe\.'
  'plugin\.Open|"plugin"'
  'import "C"'
  '//go:(linkname|embed)'
  'os\.(Getenv|LookupEnv|Environ|Setenv)'
  'os\.(WriteFile|OpenFile|Create|Remove|RemoveAll|Rename|Chmod|Symlink)|ioutil\.WriteFile'
)
current=$(mktemp)
trap 'rm -f "$current"' EXIT
for p in "${PATTERNS[@]}"; do
  git grep -l -I -E "$p" "${GO[@]}" | while IFS= read -r f; do printf '%s\t%s\n' "$p" "$f"; done || true
done | LC_ALL=C sort -u > "$current"
git ls-files --eol | awk '$1 == "i/-text" { print "binary\t" $4 }' | LC_ALL=C sort -u >> "$current"
LC_ALL=C sort -u -o "$current" "$current"

if [ "$UPDATE" -eq 1 ]; then
  { echo "# Reviewed baseline: <pattern><TAB><file>. New pairs fail .github/scripts/audit-source.sh."
    echo "# Regenerate with: .github/scripts/audit-source.sh --update-baseline  (then READ the diff)."
    cat "$current"; } > "$BASELINE"
  echo "wrote $BASELINE ($(wc -l < "$current") entries)"
  { echo "# Reviewed set of Go module paths (versions may float; NEW modules fail audit-source.sh)."; echo "$mods"; } > "$MODS_FILE"
  echo "wrote $MODS_FILE ($(wc -l <<<"$mods") modules)"
  exit 0
fi

expected=$(mktemp)
trap 'rm -f "$current" "$expected"' EXIT
grep -v -E '^(#|$)' "$BASELINE" | LC_ALL=C sort -u > "$expected"
while IFS=$'\t' read -r pat file; do
  err "new sensitive usage: '$pat' in $file (not in baseline; review, then update .github/audit/sensitive-api-baseline.txt)"
done < <(LC_ALL=C comm -13 "$expected" "$current")
while IFS=$'\t' read -r pat file; do
  echo "note: baseline entry no longer present ('$pat' in $file); consider pruning"
done < <(LC_ALL=C comm -23 "$expected" "$current")

# 3. go.mod replace directives -------------------------------------------------
if grep -n -E '^\s*replace\s*\(' <<<"$GOMOD" >/dev/null; then
  err "go.mod uses a replace block; only a single known replace line is allowed"
fi
bad=$(grep -E '^\s*replace\s' <<<"$GOMOD" | grep -v -x 'replace github.com/emersion/go-webdav => ./third_party/go-webdav' || true)
[ -z "$bad" ] || err "go.mod has an unexpected replace directive: $bad"

# 7. dependency set: a new module is new code that can run in init() -- needs a human.
reviewed=$(grep -v -E '^(#|$)' "$MODS_FILE" | LC_ALL=C sort -u)
while IFS= read -r m; do
  [ -z "$m" ] || grep -qxF "$m" <<<"$reviewed" || err "new Go dependency '$m' not in .github/audit/go-modules.txt (review it, then add it)"
done <<<"$mods"

# 5. hidden / bidirectional Unicode (all tracked text files) -----------------
if hits=$(git grep -n -I -P '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{E0000}-\x{E007F}\x{00AD}\x{180E}]' 2>/dev/null); then
  err "hidden/bidirectional Unicode characters found:"; echo "$hits" | cut -c1-200
fi

# 6. text aimed at AI agents / prompt-injection phrasing ----------------------
if hits=$(git grep -n -I -i -E \
  'ignore (all |any |the )?(previous|prior|above) (instructions|prompts?|messages?)|disregard (all |any |the )?(previous|prior|above)|system prompt|as an? (ai|llm|language model)\b|\bai (agent|assistant)\b|\bcoding (agent|assistant)\b|you are (now )?an? (ai|assistant|llm)\b|do not (tell|reveal|inform|mention)[^.]{0,40}\b(user|human)\b|im_start|\[INST\]|BEGIN (SYSTEM|INSTRUCTIONS?)' \
  -- . ':!.github/scripts' ':!.github/audit' 2>/dev/null); then
  err "text that looks addressed to an AI agent / prompt-injection phrasing:"; echo "$hits" | cut -c1-200
fi

[ "$fail" -eq 0 ] && echo "ok: source audit passed"
exit "$fail"
