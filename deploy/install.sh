#!/usr/bin/env bash
# Install netwatchdog as a systemd service.
# Run as root on the target host.
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CONFIG_DIR=/etc/netwatchdog
SERVICE_FILE=/etc/systemd/system/netwatchdog.service

# ── 1. System dependencies ───────────────────────────────────────────────────
apt-get install -y nmap masscan python3 python3-pip

# ── 2. Install the Python package ────────────────────────────────────────────
pip3 install --break-system-packages "$(dirname "$0")/.."

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
