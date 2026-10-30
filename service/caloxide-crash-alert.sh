#!/bin/sh
# Run by systemd (ExecStopPost) every time the caloxide service stops. It alerts when
# the process was killed (a signal, the OOM killer, a core dump), which caloxide cannot
# report itself because it is already gone. A normal exit or a Go fatal error is not
# alerted from here: caloxide sends those alerts from inside.
#
# Environment (systemd sets SERVICE_RESULT; the rest comes from the service's
# EnvironmentFile): CALOXIDE_APPRISE_URL, CALOXIDE_APPRISE_URLS, CALOXIDE_DISCORD_WEBHOOK_URL.

set -u

case "${SERVICE_RESULT:-}" in
signal | core-dump | oom-kill | watchdog | timeout) ;;
*) exit 0 ;;
esac

host=$(hostname 2>/dev/null || echo unknown)
msg="caloxide caldav stopped abnormally (${SERVICE_RESULT}, exit ${EXIT_STATUS:-?}) on $host. systemd will restart it."

if [ -n "${CALOXIDE_APPRISE_URL:-}" ]; then
	data="{\"title\":\"caloxide: CalDAV process crashed\",\"body\":\"$msg\",\"type\":\"failure\""
	if [ -n "${CALOXIDE_APPRISE_URLS:-}" ]; then
		data="$data,\"urls\":\"$CALOXIDE_APPRISE_URLS\""
	fi
	data="$data}"
	curl -s -m 10 -H 'Content-Type: application/json' -d "$data" "$CALOXIDE_APPRISE_URL" >/dev/null 2>&1 || true
fi

if [ -n "${CALOXIDE_DISCORD_WEBHOOK_URL:-}" ]; then
	curl -s -m 10 -H 'Content-Type: application/json' \
		-d "{\"content\":\"**caloxide: CalDAV process crashed**\\n$msg\",\"allowed_mentions\":{\"parse\":[]}}" \
		"$CALOXIDE_DISCORD_WEBHOOK_URL" >/dev/null 2>&1 || true
fi

exit 0
