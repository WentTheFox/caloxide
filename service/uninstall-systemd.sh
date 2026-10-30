#!/bin/sh
# Remove the caloxide CalDAV systemd service. Leaves the installed binary, the alert
# settings, your Proton session and the calendar cache alone; --purge also removes the
# binary, the crash-alert script and the alert settings (never the session or cache).

set -eu

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
UNIT_NAME="caloxide-caldav.service"
UNIT="$CONFIG_HOME/systemd/user/$UNIT_NAME"
BIN_DIR="$DATA_HOME/caloxide/bin"

systemctl --user disable --now "$UNIT_NAME" 2>/dev/null || true
rm -f "$UNIT"
systemctl --user daemon-reload
echo "Stopped and removed $UNIT"

if [ "${1:-}" = "--purge" ]; then
	rm -f "$BIN_DIR/caloxide" "$BIN_DIR/caloxide-crash-alert.sh" "$CONFIG_HOME/caloxide.env"
	rmdir "$BIN_DIR" "$DATA_HOME/caloxide" 2>/dev/null || true
	echo "Removed the installed binary, the crash-alert script and the alert settings"
fi

echo "Done. Your Proton session and calendar cache were left untouched."
