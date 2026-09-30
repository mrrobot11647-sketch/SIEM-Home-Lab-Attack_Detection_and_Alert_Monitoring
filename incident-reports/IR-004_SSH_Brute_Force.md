<![CDATA[# 📋 Incident Report: IR-004 — SSH Brute Force Attack

---

## Incident Details

| Field | Value |
|---|---|
| **Report ID** | IR-004 |
| **Date/Time** | 2024-10-12 11:20 UTC |
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
| **Alert Name** | ALERT - T1110.001 - SSH Brute Force Detected |
| **Detection Rule** | Failed SSH auth threshold (>10 in 5 min from single IP) |
| **Data Source** | Linux auth.log |
| **Triggered At** | 2024-10-12 11:24 UTC |

---

## Executive Summary

> An SSH brute force attack targeting the Linux server (10.0.0.30) was detected from the Kali attacker machine (10.0.0.10). The attack generated 89 failed password attempts against the `ubuntu` user account over a 2-minute period using the Hydra tool. The attack was unsuccessful — no valid credentials were compromised. The T1110.001 SSH alert triggered correctly within 4 minutes of the first failed attempt.

---

## Affected Assets

| Asset | IP Address | OS | Role |
|---|---|---|---|
| linux-target | 10.0.0.30 | Ubuntu 22.04 LTS | Target Endpoint |
| kali-attacker | 10.0.0.10 | Kali Linux 2024.3 | Attack Source |

---

## Timeline of Events

| Timestamp | Event | Source |
|---|---|---|
| 11:20:00 | Hydra SSH brute force launched from Kali | Kali terminal |
| 11:20:03 | First "Failed password" entry in auth.log | auth.log |
| 11:20:03 – 11:22:15 | 89 failed password attempts from 10.0.0.10 | auth.log |
| 11:21:00 | `Invalid user` attempts for non-existent accounts | auth.log |
| 11:22:15 | Attack completed (wordlist exhausted) | Kali terminal |
| 11:24:00 | Splunk alert triggered | Splunk |

---

## Investigation Details

### Initial Triage

The alert indicated 89 failed SSH authentication attempts from 10.0.0.10 targeting the `ubuntu` user account on the Linux server. The rapid rate (~45 attempts/minute) is consistent with automated brute force tools.

### Evidence Collection

**Splunk Query — Failed SSH Logins:**
```spl
index=linux sourcetype=linux:auth "Failed password" src_ip="10.0.0.10"
| rex "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+) port (?<src_port>\d+)"
| bin _time span=1m
| stats count by _time, target_user, src_ip
| sort _time
```

**Results:**
| Time | User | Source IP | Count |
|---|---|---|---|
| 11:20 | ubuntu | 10.0.0.10 | 42 |
| 11:21 | ubuntu | 10.0.0.10 | 35 |
| 11:22 | ubuntu | 10.0.0.10 | 12 |

**Splunk Query — Successful Login Check:**
```spl
index=linux sourcetype=linux:auth "Accepted password" src_ip="10.0.0.10"
| stats count
```

**Results:** 0 successful logins — attack **failed**.

**Splunk Query — auditd Correlation:**
```spl
index=linux sourcetype=linux:audit type=USER_LOGIN
| where res="failed"
| stats count by addr
```

**Results:** Corroborating audit entries from 10.0.0.10.

### Root Cause Analysis

The attack was a simulated SSH brute force using Hydra with a password wordlist. The target account (`ubuntu`) had a strong password not present in the wordlist, preventing successful compromise. The SSH service was configured with `MaxAuthTries 6`, but Hydra managed rapid reconnections to bypass per-connection limits.

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP Address | 10.0.0.10 | Attack source (Kali) |
| Port | 22/TCP | Targeted service (SSH) |
| Account | ubuntu | Primary target account |
| Pattern | 89 "Failed password" in 2 min | Brute force signature |
| Tool | Hydra | Identified by connection pattern |

---

## Impact Assessment

- **Confidentiality**: None (no credentials compromised)
- **Integrity**: None
- **Availability**: Low (SSH service under load)

---

## Remediation Actions

- [x] Verified no successful authentication from attacker IP
- [x] Confirmed attack was simulated (lab exercise)
- [x] Validated SSH brute force alert triggered correctly
- [x] Cross-referenced with auditd logs for additional evidence

### Production Recommendations

- [ ] Install and configure fail2ban (ban after 5 failures)
- [ ] Disable password authentication; require SSH keys only
- [ ] Change SSH port from 22 to non-standard port
- [ ] Implement firewall rate limiting on port 22
- [ ] Deploy SSH certificate-based authentication

---

## Lessons Learned

1. **Linux auth.log is the primary data source**: The `Failed password` pattern in auth.log provided clear, parseable evidence of the brute force attack.
2. **auditd provides corroboration**: `USER_LOGIN` audit events with `res=failed` provided an independent confirmation source.
3. **SSH LogLevel VERBOSE improves visibility**: Verbose logging captured additional details like port numbers and protocol versions that aided investigation.

---

*Report generated on: 2024-10-12*
*Classification: True Positive — Simulated Attack*
]]>
