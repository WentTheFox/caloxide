#!/bin/sh
# Runner for the caloxide CalDAV service under launchd.
#
# Responsibilities beyond just exec'ing the binary:
#   - Append caloxide's output to a size-rotated log file (caloxide itself has
#     no log rotation, and a long-running service would otherwise grow unbounded).
#   - Alert Apprise if the process is killed by a signal (crash / OOM / kill),
#     which in-process alerting cannot report because the process is already gone.
#
# Environment (set by the launchd plist; see service/install.sh):
#   CALOXIDE_BIN           absolute path to the caloxide binary (required)
#   CALOXIDE_LOG           log file path (required)
#   CALOXIDE_APPRISE_URL   Apprise notify endpoint (optional; enables alerts)
#   CALOXIDE_APPRISE_URLS  Apprise stateless target URL(s) (optional)
#
# launchd (KeepAlive) restarts this script; it runs one caloxide instance and
# exits with caloxide's exit code.

set -u

BIN="${CALOXIDE_BIN:-caloxide}"
LOG="${CALOXIDE_LOG:-$HOME/Library/Logs/caloxide/caldav.log}"
MAX_BYTES=10485760 # 10 MiB

mkdir -p "$(dirname "$LOG")"

# Rotate at start if the current log is large. Restarts are the natural rotation
# point; between restarts a healthy process logs little now that per-request logs
# are gated behind -debug.
if [ -f "$LOG" ]; then
	size=$(stat -f%z "$LOG" 2>/dev/null || echo 0)
	if [ "$size" -gt "$MAX_BYTES" ]; then
		mv -f "$LOG" "$LOG.1"
	fi
fi

echo "--- caloxide caldav starting $(date) ---" >>"$LOG"
"$BIN" caldav >>"$LOG" 2>&1
code=$?
echo "--- caloxide caldav exited (code $code) $(date) ---" >>"$LOG"

# Signal deaths (>128) are crashes the process couldn't self-report. Graceful/
# fatal Go exits already alert from inside caloxide, so don't duplicate those.
if [ "$code" -gt 128 ] && [ -n "${CALOXIDE_APPRISE_URL:-}" ]; then
	body="caloxide caldav was killed by a signal (exit $code) on $(hostname). launchd will restart it."
	data="{\"title\":\"caloxide: CalDAV process crashed\",\"body\":\"$body\",\"type\":\"failure\""
	if [ -n "${CALOXIDE_APPRISE_URLS:-}" ]; then
		data="$data,\"urls\":\"$CALOXIDE_APPRISE_URLS\""
	fi
	data="$data}"
	curl -s -m 10 -H 'Content-Type: application/json' -d "$data" "$CALOXIDE_APPRISE_URL" >/dev/null 2>&1 || true
fi

exit "$code"
