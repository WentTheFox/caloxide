#!/bin/sh
# Install caloxide's CalDAV bridge as a per-user systemd service (Linux).
#
# It runs as you, starts when your user manager starts, and restarts if it crashes.
# Logs go to the journal. With --linger it also starts at boot, without a login.
#
# Usage:
#   ./service/install-systemd.sh [--linger]
#
# Environment (all optional):
#   CALOXIDE_BINARY               use this binary (e.g. a downloaded release) instead of
#                                 building from source, which needs Go
#   CALOXIDE_APPRISE_URL, CALOXIDE_APPRISE_URLS, CALOXIDE_DISCORD_WEBHOOK_URL
#                                 alert settings, saved to a 0600 environment file. With
#                                 none given an existing file is kept as it is.
#
# Re-run any time to rebuild and restart. Needs a prior 'caloxide auth <address>' so the
# encrypted session exists.

set -eu

LINGER=0
for arg in "$@"; do
	case "$arg" in
	--linger) LINGER=1 ;;
	*) echo "unknown option: $arg" >&2; exit 2 ;;
	esac
done

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
UNIT_NAME="caloxide-caldav.service"
UNIT_DIR="$CONFIG_HOME/systemd/user"
BIN_DIR="$DATA_HOME/caloxide/bin"
ENV_FILE="$CONFIG_HOME/caloxide.env"

mkdir -p "$BIN_DIR" "$UNIT_DIR"

if [ -n "${CALOXIDE_BINARY:-}" ]; then
	echo "Installing $CALOXIDE_BINARY..."
	install -m 0755 "$CALOXIDE_BINARY" "$BIN_DIR/caloxide"
else
	command -v go >/dev/null 2>&1 || {
		echo "Go is not installed. Install it, or download a release binary (and verify it with" >&2
		echo "'gh attestation verify') and run:  CALOXIDE_BINARY=/path/to/caloxide $0" >&2
		exit 1
	}
	echo "Building caloxide..."
	( cd "$REPO_DIR" && go build -trimpath -o "$BIN_DIR/caloxide" ./cmd/caloxide )
fi
install -m 0755 "$REPO_DIR/service/caloxide-crash-alert.sh" "$BIN_DIR/caloxide-crash-alert.sh"

# Alert settings go in an owner-only file, never in the unit (which is world-readable).
if [ -n "${CALOXIDE_APPRISE_URL:-}${CALOXIDE_APPRISE_URLS:-}${CALOXIDE_DISCORD_WEBHOOK_URL:-}" ]; then
	umask 077
	{
		for name in CALOXIDE_APPRISE_URL CALOXIDE_APPRISE_URLS CALOXIDE_DISCORD_WEBHOOK_URL; do
			eval "value=\${$name:-}"
			[ -n "$value" ] && printf '%s=%s\n' "$name" "$value"
		done
	} >"$ENV_FILE"
	chmod 600 "$ENV_FILE"
	echo "Saved alert settings to $ENV_FILE"
fi

cat >"$UNIT_DIR/$UNIT_NAME" <<UNIT
[Unit]
Description=Caloxide: Proton Calendar CalDAV bridge
Documentation=https://github.com/WentTheFox/caloxide
After=network-online.target
Wants=network-online.target

[Service]
ExecStart="$BIN_DIR/caloxide" -config-home "$CONFIG_HOME" caldav
ExecStopPost=$BIN_DIR/caloxide-crash-alert.sh
EnvironmentFile=-$ENV_FILE
Restart=on-failure
RestartSec=30

# Sandbox: read-only filesystem except the state directory, no new privileges, IP and
# unix sockets only. None of this needs root.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=-$CONFIG_HOME/caloxide -$CONFIG_HOME/protoxide
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable "$UNIT_NAME" >/dev/null
systemctl --user restart "$UNIT_NAME"

if [ "$LINGER" = 1 ]; then
	loginctl enable-linger "$USER"
	echo "Lingering enabled: it now starts at boot, without a login."
fi

echo
echo "Installed and started: $UNIT_NAME"
echo "  binary : $BIN_DIR/caloxide"
echo "  unit   : $UNIT_DIR/$UNIT_NAME"
if [ -f "$ENV_FILE" ]; then
	echo "  alerts : settings in $ENV_FILE"
else
	echo "  alerts : OFF (set CALOXIDE_DISCORD_WEBHOOK_URL or CALOXIDE_APPRISE_URL and re-run)"
fi
echo
echo "It is listening on http://127.0.0.1:8081. Manage with:"
echo "  systemctl --user status $UNIT_NAME"
echo "  journalctl --user -u $UNIT_NAME -f"
echo "  systemctl --user restart $UNIT_NAME"
echo "  systemctl --user edit $UNIT_NAME    # e.g. to add -caldav-port to ExecStart"
echo "  ./service/uninstall-systemd.sh      # remove"
if [ "$LINGER" != 1 ]; then
	echo
	echo "Without a login session it stops when you log out. To start at boot, run"
	echo "'loginctl enable-linger $USER' or re-run this script with --linger."
fi
echo
echo "NOTE: this needs a prior 'caloxide auth <your-proton-address>' so the encrypted"
echo "session exists. If Proton later needs a CAPTCHA, run 'caloxide verify'."
