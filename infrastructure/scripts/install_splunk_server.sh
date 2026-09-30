<![CDATA[#!/bin/bash
# ============================================================
# Splunk Enterprise Server Installation Script
# Target: Ubuntu 22.04 (Splunk Server VM)
# ============================================================
set -euo pipefail

SPLUNK_VERSION="9.3.2"
SPLUNK_DEB="splunk-${SPLUNK_VERSION}-d8bb32809498-linux-2.6-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_DEB}"
SPLUNK_HOME="/opt/splunk"
SPLUNK_ADMIN_USER="admin"
SPLUNK_ADMIN_PASS="P@ssw0rd_SIEM_Lab!"  # Change in production

echo "========================================="
echo "[*] SIEM Lab — Splunk Server Setup"
echo "========================================="

# ── System Updates ──
echo "[+] Updating system packages..."
apt-get update -y && apt-get upgrade -y
apt-get install -y wget curl net-tools

# ── Download & Install Splunk ──
echo "[+] Downloading Splunk Enterprise ${SPLUNK_VERSION}..."
if [ ! -f "/tmp/${SPLUNK_DEB}" ]; then
    wget -q -O "/tmp/${SPLUNK_DEB}" "${SPLUNK_URL}" || {
        echo "[!] Download failed. Please download Splunk manually from https://www.splunk.com/en_us/download.html"
        echo "[!] Place the .deb file at /tmp/${SPLUNK_DEB} and re-run this script."
        exit 1
    }
fi

echo "[+] Installing Splunk Enterprise..."
dpkg -i "/tmp/${SPLUNK_DEB}"

# ── Initial Configuration ──
echo "[+] Starting Splunk and accepting license..."
${SPLUNK_HOME}/bin/splunk start --accept-license --answer-yes \
    --seed-passwd "${SPLUNK_ADMIN_PASS}" --no-prompt

# ── Enable Boot Start ──
echo "[+] Enabling Splunk to start on boot..."
${SPLUNK_HOME}/bin/splunk enable boot-start -user splunk

# ── Configure Receiving Port ──
echo "[+] Enabling receiving on port 9997..."
${SPLUNK_HOME}/bin/splunk enable listen 9997 \
    -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"

# ── Create Indexes ──
echo "[+] Creating custom indexes..."
cat > ${SPLUNK_HOME}/etc/system/local/indexes.conf << 'INDEXES_EOF'
[sysmon]
coldPath = $SPLUNK_DB/sysmon/colddb
homePath = $SPLUNK_DB/sysmon/db
thawedPath = $SPLUNK_DB/sysmon/thaweddb
maxTotalDataSizeMB = 10240

[wineventlog]
coldPath = $SPLUNK_DB/wineventlog/colddb
homePath = $SPLUNK_DB/wineventlog/db
thawedPath = $SPLUNK_DB/wineventlog/thaweddb
maxTotalDataSizeMB = 10240

[linux]
coldPath = $SPLUNK_DB/linux/colddb
homePath = $SPLUNK_DB/linux/db
thawedPath = $SPLUNK_DB/linux/thaweddb
maxTotalDataSizeMB = 5120

[attack_logs]
coldPath = $SPLUNK_DB/attack_logs/colddb
homePath = $SPLUNK_DB/attack_logs/db
thawedPath = $SPLUNK_DB/attack_logs/thaweddb
maxTotalDataSizeMB = 5120
INDEXES_EOF

# ── Restart to Apply ──
echo "[+] Restarting Splunk to apply configuration..."
${SPLUNK_HOME}/bin/splunk restart

# ── Firewall Rules ──
echo "[+] Configuring firewall..."
ufw allow 8000/tcp   # Splunk Web
ufw allow 9997/tcp   # Forwarder receiving
ufw allow 8089/tcp   # Management port
ufw --force enable

# ── Verification ──
echo ""
echo "========================================="
echo "[✓] Splunk Enterprise Installation Complete"
echo "========================================="
echo "  Web UI:    http://10.0.0.100:8000"
echo "  Username:  ${SPLUNK_ADMIN_USER}"
echo "  Password:  ${SPLUNK_ADMIN_PASS}"
echo "  Receiving: Port 9997 (TCP)"
echo "========================================="
]]>
