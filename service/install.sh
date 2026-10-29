#!/bin/sh
# Install caloxide's CalDAV bridge as a per-user launchd service (macOS).
#
# It starts at login, restarts if it crashes, and comes back after a reboot
# (a reboot leads to a login, which loads the agent). Optionally wires up
# Apprise alerting.
#
# Usage:
#   ./service/install.sh
#   CALOXIDE_APPRISE_URL=http://host:8000/notify/caloxide ./service/install.sh
#
# Re-run any time to rebuild and reload with new settings.

set -eu

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
APP_DIR="$HOME/Library/Application Support/caloxide"
BIN_DIR="$APP_DIR/bin"
LOG_DIR="$HOME/Library/Logs/caloxide"
LA_DIR="$HOME/Library/LaunchAgents"
LABEL="com.wentthefox.caloxide.caldav"
PLIST="$LA_DIR/$LABEL.plist"
LOG="$LOG_DIR/caldav.log"

APPRISE_URL="${CALOXIDE_APPRISE_URL:-}"
APPRISE_URLS="${CALOXIDE_APPRISE_URLS:-}"
if [ -z "$APPRISE_URL" ]; then
	printf "Apprise notify URL for alerts (e.g. http://host:8000/notify/caloxide)\n  [blank = no alerts]: "
	read -r APPRISE_URL || APPRISE_URL=""
fi
if [ -n "$APPRISE_URL" ] && [ -z "$APPRISE_URLS" ]; then
	printf "Apprise stateless target URL(s) — ONLY if your endpoint is the bare /notify\n  (e.g. ntfy://host/caloxide); blank for a /notify/<key> config endpoint: "
	read -r APPRISE_URLS || APPRISE_URLS=""
fi

echo "Building caloxide..."
mkdir -p "$BIN_DIR" "$LOG_DIR" "$LA_DIR"
( cd "$REPO_DIR" && go build -o "$BIN_DIR/caloxide" ./cmd/caloxide )
install -m 0755 "$REPO_DIR/service/caloxide-caldav-run.sh" "$BIN_DIR/caloxide-caldav-run.sh"

# Unload any previous instance before rewriting the plist.
launchctl unload "$PLIST" 2>/dev/null || true

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN_DIR/caloxide-caldav-run.sh</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>CALOXIDE_BIN</key>
		<string>$BIN_DIR/caloxide</string>
		<key>CALOXIDE_LOG</key>
		<string>$LOG</string>
		<key>CALOXIDE_APPRISE_URL</key>
		<string>$APPRISE_URL</string>
		<key>CALOXIDE_APPRISE_URLS</key>
		<string>$APPRISE_URLS</string>
		<key>PATH</key>
		<string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>StandardOutPath</key>
	<string>$LOG_DIR/launchd.log</string>
	<key>StandardErrorPath</key>
	<string>$LOG_DIR/launchd.log</string>
	<key>WorkingDirectory</key>
	<string>$APP_DIR</string>
</dict>
</plist>
EOF

# The plist may contain an Apprise URL with a secret key — keep it owner-only.
chmod 600 "$PLIST"

launchctl load -w "$PLIST"

echo
echo "Installed and started: $LABEL"
echo "  binary : $BIN_DIR/caloxide"
echo "  logs   : $LOG (and $LOG_DIR/launchd.log)"
echo "  plist  : $PLIST"
if [ -n "$APPRISE_URL" ]; then
	echo "  alerts : ON -> $APPRISE_URL"
else
	echo "  alerts : OFF (set CALOXIDE_APPRISE_URL and re-run to enable)"
fi
echo
echo "It is listening on http://127.0.0.1:8081. Manage with:"
echo "  launchctl list | grep caloxide"
echo "  launchctl unload $PLIST   # stop"
echo "  launchctl load -w $PLIST  # start"
echo "  ./service/uninstall.sh    # remove"
echo
echo "NOTE: this needs a prior './caloxide auth <your-proton-address>' so the"
echo "encrypted session exists. If the Proton session later expires you'll get an"
echo "alert (if configured) and must re-run auth."
