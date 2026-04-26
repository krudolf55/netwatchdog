#!/usr/bin/env bash
# Install netwatchdog as a systemd service.
# Run as root on the target host.
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
VENV_DIR=/opt/netwatchdog/venv
CONFIG_DIR=/etc/netwatchdog
SERVICE_FILE=/etc/systemd/system/netwatchdog.service

# ── 1. System dependencies ───────────────────────────────────────────────────
apt-get install -y nmap masscan python3 python3-pip python3-venv

# ── 2. Install the Python package into a virtualenv ──────────────────────────
mkdir -p /opt/netwatchdog
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "$(dirname "$0")/.."

# Expose the CLI on PATH
ln -sf "$VENV_DIR/bin/netwatchdog" "$INSTALL_PREFIX/bin/netwatchdog"

# ── 3. Create system user ────────────────────────────────────────────────────
install -m 644 "$(dirname "$0")/netwatchdog.sysusers" \
    /usr/lib/sysusers.d/netwatchdog.conf
systemd-sysusers netwatchdog.conf

# ── 4. Install config (skip if already present) ──────────────────────────────
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/netwatchdog.yaml" ]; then
    install -m 640 -o root -g netwatchdog \
        "$(dirname "$0")/../config/netwatchdog.example.yaml" \
        "$CONFIG_DIR/netwatchdog.yaml"
    echo ""
    echo "  !! Edit $CONFIG_DIR/netwatchdog.yaml before starting:"
    echo "     - Set web.secret_key to a random string"
    echo "     - Configure hosts.addresses"
    echo "     - Configure notifications if needed"
    echo ""
fi

# ── 5. Install and enable the systemd unit ───────────────────────────────────
install -m 644 "$(dirname "$0")/netwatchdog.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable netwatchdog

echo "Installation complete. Start with: systemctl start netwatchdog"
echo "Check status with:                 systemctl status netwatchdog"
echo "Follow logs with:                  journalctl -u netwatchdog -f"
