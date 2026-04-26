#!/usr/bin/env bash
# Install periscan as a systemd service.
# Run as root on the target host.
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
VENV_DIR=/opt/periscan/venv
CONFIG_DIR=/etc/periscan
SERVICE_FILE=/etc/systemd/system/periscan.service

# ── 1. System dependencies ───────────────────────────────────────────────────
apt-get install -y nmap masscan python3 python3-pip python3-venv

# ── 2. Install the Python package into a virtualenv ──────────────────────────
mkdir -p /opt/periscan
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "$(dirname "$0")/.."

# Expose the CLI on PATH
ln -sf "$VENV_DIR/bin/periscan" "$INSTALL_PREFIX/bin/periscan"

# ── 3. Create system user ────────────────────────────────────────────────────
install -m 644 "$(dirname "$0")/periscan.sysusers" \
    /usr/lib/sysusers.d/periscan.conf
systemd-sysusers periscan.conf

# ── 4. Create data and log directories ──────────────────────────────────────
install -d -m 750 -o periscan -g periscan /var/lib/periscan
install -d -m 750 -o periscan -g periscan /var/log/periscan

# ── 5. Install config (skip if already present) ──────────────────────────────
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/periscan.yaml" ]; then
    # 644 so any user can read it for manual CLI commands.
    # Use env vars (PERISCAN__...) for secrets rather than storing them in plain text.
    install -m 644 -o root -g periscan \
        "$(dirname "$0")/../config/periscan.example.yaml" \
        "$CONFIG_DIR/periscan.yaml"
    echo ""
    echo "  !! Edit $CONFIG_DIR/periscan.yaml before starting:"
    echo "     - Set web.secret_key to a random string"
    echo "     - Configure hosts.addresses"
    echo "     - Configure notifications if needed"
    echo ""
fi

# ── 6. Add the installing user to the periscan group ─────────────────────────
if [ -n "${SUDO_USER:-}" ]; then
    usermod -aG periscan "$SUDO_USER"
    echo "  Added $SUDO_USER to the 'periscan' group."
    echo "  Log out and back in for group membership to take effect."
    echo ""
fi

# ── 7. Install and enable the systemd unit ───────────────────────────────────
install -m 644 "$(dirname "$0")/periscan.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable periscan

echo "Installation complete. Start with: systemctl start periscan"
echo "Check status with:                 systemctl status periscan"
echo "Follow logs with:                  journalctl -u periscan -f"
