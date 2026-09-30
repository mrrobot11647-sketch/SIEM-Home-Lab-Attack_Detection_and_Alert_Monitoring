<![CDATA[# 📋 Incident Report: IR-001 — RDP Brute Force Attack

---

## Incident Details

| Field | Value |
|---|---|
| **Report ID** | IR-001 |
| **Date/Time** | 2024-10-05 14:32 UTC |
| **Analyst** | SOC Analyst (Home Lab) |
| **Severity** | High |
| **Status** | Closed |
| **Classification** | ✅ True Positive |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique ID** | T1110.001 |
| **Technique Name** | Brute Force: Password Guessing |
| **Tactic** | Credential Access |
| **Reference** | https://attack.mitre.org/techniques/T1110/001/ |

---

## Alert Information

| Field | Value |
|---|---|
| **Alert Name** | ALERT - T1110.001 - RDP Brute Force Detected |
| **Detection Rule** | Failed login threshold (>10 in 5 min from single IP) |
| **Data Source** | Windows Security Event Log (Event ID 4625) |
| **Triggered At** | 2024-10-05 14:35 UTC |

---

## Executive Summary

> A brute force attack targeting the RDP service on the Windows Server (10.0.0.20) was detected originating from the Kali attacker machine (10.0.0.10). The attack generated 147 failed login attempts against the Administrator account over a 3-minute period. The attack was simulated using Hydra and was successfully detected by the T1110.001 alert rule.

---

## Affected Assets

| Asset | IP Address | OS | Role |
|---|---|---|---|
| win-target | 10.0.0.20 | Windows Server 2022 | Target Endpoint |
| kali-attacker | 10.0.0.10 | Kali Linux 2024.3 | Attack Source |

---

## Timeline of Events

| Timestamp | Event | Source |
|---|---|---|
| 14:32:01 | Hydra RDP brute force launched from Kali | Kali terminal |
| 14:32:05 | First failed logon event (4625) recorded | Windows Security Log |
| 14:32:05 – 14:35:12 | 147 failed logon attempts (Logon Type 10) | Windows Security Log |
| 14:35:15 | Splunk alert triggered: "RDP Brute Force Detected" | Splunk |
| 14:35:30 | Sysmon Event 3 — multiple connections to port 3389 from 10.0.0.10 | Sysmon |
| 14:36:00 | Attack ceased (Hydra exhausted wordlist) | Kali terminal |

---

## Investigation Details

### Initial Triage

The alert fired at 14:35 UTC indicating 147 failed RDP login attempts from source IP 10.0.0.10 targeting the Administrator account on win-target (10.0.0.20). The Logon Type was 10 (Remote Interactive / RDP), confirming this was an RDP-specific attack.

### Evidence Collection

**Splunk Query — Failed Logins:**
```spl
index=wineventlog EventCode=4625 Logon_Type=10 src_ip="10.0.0.10"
| bin _time span=1m
| stats count by _time, Account_Name, src_ip
| sort _time
```

**Results:**
| Time | Account | Source IP | Count |
|---|---|---|---|
| 14:32 | Administrator | 10.0.0.10 | 48 |
| 14:33 | Administrator | 10.0.0.10 | 52 |
| 14:34 | Administrator | 10.0.0.10 | 47 |

**Splunk Query — Network Connections:**
```spl
index=sysmon EventCode=3 DestinationPort=3389 SourceIp="10.0.0.10"
| stats count by SourceIp, DestinationIp, DestinationPort
```

**Results:** 147 network connections from 10.0.0.10 to 10.0.0.20:3389

**Splunk Query — Successful Login Check:**
```spl
index=wineventlog EventCode=4624 Logon_Type=10 src_ip="10.0.0.10"
| stats count
```

**Results:** 0 successful logins — attack was **unsuccessful**.

### Root Cause Analysis

The attack was a simulated brute force attempt using Hydra from the Kali attacker machine. The attack used the rockyou.txt wordlist targeting the Administrator account via RDP. No credentials were compromised as the password was not in the wordlist.

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP Address | 10.0.0.10 | Attack source (Kali Linux) |
| Port | 3389/TCP | Targeted service (RDP) |
| Account | Administrator | Targeted account |
| Event Pattern | 147 Event 4625 in 3 min | Brute force signature |
| Tool | Hydra v9.5 | Attack tool (identified by connection pattern) |

---

## Impact Assessment

- **Confidentiality**: None (no credentials compromised)
- **Integrity**: None
- **Availability**: Low (RDP service under load during attack)

---

## Remediation Actions

- [x] Verified no successful authentication from attacker IP
- [x] Confirmed attack was simulated (lab exercise)
- [x] Validated detection rule triggered correctly
- [x] Documented findings in incident report

### Production Recommendations

- [ ] Implement account lockout after 5 failed attempts
- [ ] Deploy Network Level Authentication (NLA) for RDP
- [ ] Restrict RDP access via firewall to authorized IPs only
- [ ] Consider deploying a VPN for remote access instead of exposed RDP

---

## Lessons Learned

1. **Detection works**: The T1110.001 rule successfully detected the brute force attack within 3 minutes of the first failed attempt.
2. **Threshold tuning**: The original threshold of 5 attempts generated false positives from legitimate typos; 10 provides a better signal-to-noise ratio.
3. **Correlation value**: Combining Event 4625 with Sysmon Event 3 (network connections) provides additional confidence in the alert.

---

## Detection Tuning Recommendations

| Recommendation | Priority |
|---|---|
| Add correlation with successful login (4624) for higher severity | High |
| Track unique accounts targeted per source IP | Medium |
| Add geo-IP enrichment for source IP | Low |

---

*Report generated on: 2024-10-05*
*Classification: True Positive — Simulated Attack*
]]>
