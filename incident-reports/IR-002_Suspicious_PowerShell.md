<![CDATA[# 📋 Incident Report: IR-002 — Suspicious PowerShell Execution

---

## Incident Details

| Field | Value |
|---|---|
| **Report ID** | IR-002 |
| **Date/Time** | 2024-10-07 09:15 UTC |
| **Analyst** | SOC Analyst (Home Lab) |
| **Severity** | Critical |
| **Status** | Closed |
| **Classification** | ✅ True Positive |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique ID** | T1059.001 |
| **Technique Name** | Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Reference** | https://attack.mitre.org/techniques/T1059/001/ |

---

## Alert Information

| Field | Value |
|---|---|
| **Alert Name** | ALERT - T1059.001 - Suspicious PowerShell Execution |
| **Detection Rule** | Encoded commands, download cradles, suspicious parameters |
| **Data Source** | Sysmon Event ID 1, PowerShell Event ID 4104 |
| **Triggered At** | 2024-10-07 09:18 UTC |

---

## Executive Summary

> Multiple instances of suspicious PowerShell activity were detected on the Windows Server (10.0.0.20), including encoded command execution, download cradle attempts, and hidden window operations. The activity was identified as an Atomic Red Team T1059.001 simulation with additional manual techniques. Five distinct suspicious PowerShell executions were recorded over a 4-minute window, with risk scores ranging from 60 to 90.

---

## Affected Assets

| Asset | IP Address | OS | Role |
|---|---|---|---|
| win-target | 10.0.0.20 | Windows Server 2022 | Target Endpoint |

---

## Timeline of Events

| Timestamp | Event | Source |
|---|---|---|
| 09:15:00 | Atomic Red Team T1059.001 tests initiated | PowerShell Console |
| 09:15:12 | Encoded command execution (`-EncodedCommand`) | Sysmon Event 1 |
| 09:15:30 | Second encoded command with Base64 payload | Sysmon Event 1 |
| 09:16:05 | Download cradle (`IEX ... DownloadString`) | Sysmon Event 1 |
| 09:16:22 | Hidden window execution (`-WindowStyle Hidden`) | Sysmon Event 1 |
| 09:16:45 | Execution policy bypass (`-ExecutionPolicy Bypass`) | Sysmon Event 1 |
| 09:17:00 | Script block logged (Event 4104) — full command content | PowerShell Log |
| 09:18:00 | Splunk alert triggered | Splunk |

---

## Investigation Details

### Initial Triage

The alert fired with 5 matching events, each carrying risk scores above 60. The highest risk score (90) was assigned to a download cradle attempt using `Net.WebClient.DownloadString()`.

### Evidence Collection

**Splunk Query — Suspicious PowerShell:**
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
  (CommandLine="*-EncodedCommand*" OR CommandLine="*DownloadString*"
   OR CommandLine="*IEX*" OR CommandLine="*-WindowStyle Hidden*")
| eval risk=case(
    like(CommandLine, "%DownloadString%"), 90,
    like(CommandLine, "%EncodedCommand%"), 80,
    like(CommandLine, "%Hidden%"), 70,
    1=1, 60)
| table _time, User, ParentImage, CommandLine, risk
| sort -risk
```

**Key Findings:**

| Time | Risk | Indicator | Command (truncated) |
|---|---|---|---|
| 09:16:05 | 90 | Download Cradle | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| 09:15:12 | 80 | Encoded Command | `powershell.exe -EncodedCommand SQBFAF...` |
| 09:15:30 | 80 | Encoded Command | `powershell.exe -enc RQBJA...` |
| 09:16:22 | 70 | Hidden Window | `powershell.exe -WindowStyle Hidden -NoProfile...` |
| 09:16:45 | 60 | Policy Bypass | `powershell.exe -ExecutionPolicy Bypass -NonInteractive...` |

**Script Block Content (Event 4104):**
```
Write-Host 'SIEM Lab Test - Encoded PowerShell Execution'
Get-Process | Select-Object -First 5
```

### Root Cause Analysis

The activity was a simulated attack using the Atomic Red Team framework (T1059.001 test cases) combined with manual techniques. All commands were benign in nature but used obfuscation and evasion patterns commonly associated with malware delivery and post-exploitation frameworks.

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Process | powershell.exe | Execution engine |
| Parameter | `-EncodedCommand` | Base64 encoded payload |
| Parameter | `-WindowStyle Hidden` | Stealth execution |
| Parameter | `-ExecutionPolicy Bypass` | Security bypass |
| Pattern | `IEX (New-Object Net.WebClient)` | Download cradle |
| Pattern | `FromBase64String` | Encoded payload decode |

---

## Impact Assessment

- **Confidentiality**: None (benign test commands)
- **Integrity**: None
- **Availability**: None

---

## Remediation Actions

- [x] Confirmed all commands were benign simulation content
- [x] Verified no outbound network connections from download cradles
- [x] Validated detection rule triggers for all 5 techniques
- [x] Confirmed Script Block Logging captured full command content

### Production Recommendations

- [ ] Deploy PowerShell Constrained Language Mode on servers
- [ ] Implement AppLocker or WDAC to restrict PowerShell execution
- [ ] Enable AMSI (Antimalware Scan Interface) integration
- [ ] Block encoded commands via Group Policy where not required

---

## Lessons Learned

1. **Script Block Logging is essential**: Event 4104 revealed the full decoded command content, which was critical for determining benign intent.
2. **Risk scoring improves prioritization**: Download cradles (risk 90) were correctly prioritized over policy bypass (risk 60).
3. **False positive tuning needed**: Initial rule flagged Windows Update using encoded commands (svchost.exe → powershell.exe). Whitelist added in v1.2.

---

*Report generated on: 2024-10-07*
*Classification: True Positive — Simulated Attack*
]]>
