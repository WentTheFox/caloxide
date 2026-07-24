#!/bin/sh
# Remove the protoxide CalDAV launchd service. Leaves the built binary, logs, and
# your Proton session in place; pass --purge to also remove the installed binary
# and runner (never touches your session or calendar cache).

set -eu

LABEL="com.mathewcsims.protoxide.caldav"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
BIN_DIR="$HOME/Library/Application Support/protoxide/bin"

launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
echo "Unloaded and removed $PLIST"

if [ "${1:-}" = "--purge" ]; then
	rm -f "$BIN_DIR/protoxide" "$BIN_DIR/protoxide-caldav-run.sh"
	echo "Removed installed binary and runner from $BIN_DIR"
fi

echo "Done. Your Proton session and calendar cache were left untouched."
