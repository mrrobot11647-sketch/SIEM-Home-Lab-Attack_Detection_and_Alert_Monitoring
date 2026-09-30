<![CDATA[#!/bin/bash
# ============================================================
# Linux Logging & Splunk UF Configuration Script
# Target: Ubuntu 22.04 (Linux Target VM)
# ============================================================
set -euo pipefail

SPLUNK_SERVER="10.0.0.100"
RECEIVING_PORT="9997"
UF_VERSION="9.3.2"
UF_DEB="splunkforwarder-${UF_VERSION}-d8bb32809498-linux-2.6-amd64.deb"
UF_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/${UF_DEB}"
UF_HOME="/opt/splunkforwarder"

echo "========================================="
echo "[*] SIEM Lab — Linux Logging Setup"
echo "========================================="

# ── System Updates ──
echo "[+] Updating system packages..."
apt-get update -y
apt-get install -y rsyslog auditd audispd-plugins openssh-server wget curl

# ── Configure rsyslog ──
echo "[+] Configuring rsyslog..."
systemctl enable rsyslog
systemctl start rsyslog

# ── Configure auditd ──
echo "[+] Configuring auditd rules..."
cat > /etc/audit/rules.d/siem-lab.rules << 'AUDIT_EOF'
# ============================================================
# SIEM Home Lab — Audit Rules
# ============================================================

# Remove any existing rules
-D

# Set buffer size
-b 8192

# Set failure mode (1 = printk, 2 = panic)
-f 1

# ── Identity & Access Management ──
-w /etc/passwd -p wa -k identity_mod
-w /etc/shadow -p wa -k identity_mod
-w /etc/group -p wa -k identity_mod
-w /etc/gshadow -p wa -k identity_mod
-w /etc/sudoers -p wa -k sudoers_mod
-w /etc/sudoers.d/ -p wa -k sudoers_mod

# ── Authentication ──
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k auth_log
-w /var/log/lastlog -p wa -k auth_log

# ── Privilege Escalation ──
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_esc
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_esc
-w /usr/bin/sudo -p x -k sudo_exec
-w /usr/bin/su -p x -k su_exec

# ── SSH Configuration ──
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/ -p wa -k ssh_config

# ── Cron & Scheduled Tasks ──
-w /etc/crontab -p wa -k cron_mod
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/cron.daily/ -p wa -k cron_mod
-w /etc/cron.hourly/ -p wa -k cron_mod
-w /var/spool/cron/ -p wa -k cron_mod
-w /var/spool/cron/crontabs/ -p wa -k cron_mod

# ── Network Configuration ──
-w /etc/hosts -p wa -k network_mod
-w /etc/network/ -p wa -k network_mod
-w /etc/netplan/ -p wa -k network_mod

# ── Suspicious Commands ──
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k netcat_exec
-w /usr/bin/ncat -p x -k netcat_exec
-w /usr/bin/base64 -p x -k encoding_tool

# Make rules immutable (requires reboot to change)
-e 2
AUDIT_EOF

augenrules --load
systemctl restart auditd

# ── Configure SSH for Monitoring ──
echo "[+] Configuring SSH for attack detection..."
# Ensure password authentication is enabled (for brute force testing)
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 6/' /etc/ssh/sshd_config
systemctl restart sshd

# ── Install Splunk Universal Forwarder ──
echo "[+] Downloading Splunk Universal Forwarder ${UF_VERSION}..."
if [ ! -f "/tmp/${UF_DEB}" ]; then
    wget -q -O "/tmp/${UF_DEB}" "${UF_URL}" || {
        echo "[!] Download failed. Please download manually."
        exit 1
    }
fi

echo "[+] Installing Splunk Universal Forwarder..."
dpkg -i "/tmp/${UF_DEB}"

# ── Configure Inputs ──
echo "[+] Configuring log inputs..."
cat > ${UF_HOME}/etc/system/local/inputs.conf << 'INPUTS_EOF'
# ============================================================
# Splunk Universal Forwarder — Linux Inputs Configuration
# ============================================================

[default]
host = linux-target

# ── Authentication Logs ──
[monitor:///var/log/auth.log]
disabled = false
index = linux
sourcetype = linux:auth
followTail = 0

# ── Syslog ──
[monitor:///var/log/syslog]
disabled = false
index = linux
sourcetype = syslog
followTail = 0

# ── Audit Logs ──
[monitor:///var/log/audit/audit.log]
disabled = false
index = linux
sourcetype = linux:audit
followTail = 0

# ── Kernel Log ──
[monitor:///var/log/kern.log]
disabled = false
index = linux
sourcetype = linux:kern
followTail = 0

# ── dpkg/apt Logs ──
[monitor:///var/log/dpkg.log]
disabled = false
index = linux
sourcetype = linux:dpkg
followTail = 0
INPUTS_EOF

# ── Configure Outputs ──
cat > ${UF_HOME}/etc/system/local/outputs.conf << OUTPUTS_EOF
[tcpout]
defaultGroup = splunk-server

[tcpout:splunk-server]
server = ${SPLUNK_SERVER}:${RECEIVING_PORT}
OUTPUTS_EOF

# ── Start Splunk UF ──
echo "[+] Starting Splunk Universal Forwarder..."
${UF_HOME}/bin/splunk start --accept-license --answer-yes --seed-passwd 'ForwarderPass123!' --no-prompt
${UF_HOME}/bin/splunk enable boot-start -user root

echo ""
echo "========================================="
echo "[✓] Linux Logging Setup Complete"
echo "========================================="
echo "  rsyslog:     Active"
echo "  auditd:      Active (with custom rules)"
echo "  SSH:         Configured for monitoring"
echo "  Splunk UF:   Forwarding to ${SPLUNK_SERVER}:${RECEIVING_PORT}"
echo "  Log Sources: auth.log, syslog, audit.log, kern.log, dpkg.log"
echo "========================================="
]]>
