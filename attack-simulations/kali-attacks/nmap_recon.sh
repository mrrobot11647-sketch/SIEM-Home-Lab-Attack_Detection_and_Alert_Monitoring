<![CDATA[#!/bin/bash
# ============================================================
# Nmap Reconnaissance Script
# Attacker: Kali Linux
# Target: Lab Network
# MITRE ATT&CK: T1046 — Network Service Scanning
# ============================================================

set -euo pipefail

TARGET="${1:-10.0.0.0/24}"
OUTPUT_DIR="/tmp/nmap_siem_lab"

echo "============================================="
echo " RECON: Nmap Network Scan (T1046)"
echo " Target: ${TARGET}"
echo "============================================="
echo ""

mkdir -p "${OUTPUT_DIR}"

# ── Phase 1: Host Discovery ──
echo "[*] Phase 1: Host Discovery..."
nmap -sn "${TARGET}" -oN "${OUTPUT_DIR}/host_discovery.txt" 2>/dev/null
echo "[✓] Host discovery complete"

# ── Phase 2: Port Scan ──
echo ""
echo "[*] Phase 2: Top 1000 Port Scan..."
nmap -sS -sV --top-ports 1000 "${TARGET}" -oN "${OUTPUT_DIR}/port_scan.txt" -oX "${OUTPUT_DIR}/port_scan.xml" 2>/dev/null
echo "[✓] Port scan complete"

# ── Phase 3: OS Detection ──
echo ""
echo "[*] Phase 3: OS Detection..."
nmap -O "${TARGET}" -oN "${OUTPUT_DIR}/os_detection.txt" 2>/dev/null
echo "[✓] OS detection complete"

# ── Phase 4: Vulnerability Scan ──
echo ""
echo "[*] Phase 4: Script-based vulnerability scan..."
nmap --script=vuln "${TARGET}" -oN "${OUTPUT_DIR}/vuln_scan.txt" 2>/dev/null
echo "[✓] Vulnerability scan complete"

echo ""
echo "[✓] All scans complete. Results in: ${OUTPUT_DIR}/"
echo "[*] Check Splunk: index=sysmon EventCode=3 (network connections)"
ls -la "${OUTPUT_DIR}/"
]]>
