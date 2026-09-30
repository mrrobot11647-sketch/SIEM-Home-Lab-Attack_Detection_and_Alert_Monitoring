<![CDATA[# 📋 Incident Report: IR-003 — Privilege Escalation (UAC Bypass)

---

## Incident Details

| Field | Value |
|---|---|
| **Report ID** | IR-003 |
| **Date/Time** | 2024-10-10 16:42 UTC |
| **Analyst** | SOC Analyst (Home Lab) |
| **Severity** | Critical |
| **Status** | Closed |
| **Classification** | ✅ True Positive |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique ID** | T1548.002 |
| **Technique Name** | Abuse Elevation Control Mechanism: Bypass User Account Control |
| **Tactic** | Privilege Escalation, Defense Evasion |
| **Reference** | https://attack.mitre.org/techniques/T1548/002/ |

---

## Alert Information

| Field | Value |
|---|---|
| **Alert Name** | ALERT - T1548.002 - UAC Bypass Attempt Detected |
| **Detection Rule** | Registry modification of ms-settings/mscfile shell handlers |
| **Data Source** | Sysmon Event ID 13 (Registry Value Set) |
| **Triggered At** | 2024-10-10 16:44 UTC |

---

## Executive Summary

> A UAC bypass attempt was detected via the Fodhelper technique on the Windows Server (10.0.0.20). The attacker created registry entries under `HKCU\Software\Classes\ms-settings\Shell\Open\command` to hijack the auto-elevation behavior of fodhelper.exe. Two distinct bypass techniques (Fodhelper and EventVwr/mscfile) were observed in sequence, indicating a deliberate privilege escalation attempt. Risk score: 95.

---

## Affected Assets

| Asset | IP Address | OS | Role |
|---|---|---|---|
| win-target | 10.0.0.20 | Windows Server 2022 | Target Endpoint |

---

## Timeline of Events

| Timestamp | Event | Source |
|---|---|---|
| 16:42:00 | Attack simulation script launched | PowerShell Console |
| 16:42:05 | Registry key created: `HKCU\...\ms-settings\Shell\Open\command` | Sysmon Event 13 |
| 16:42:06 | Registry value set: `(Default)` → `cmd.exe /c echo ...` | Sysmon Event 13 |
| 16:42:07 | Registry value set: `DelegateExecute` → `""` | Sysmon Event 13 |
| 16:42:10 | fodhelper.exe launched | Sysmon Event 1 |
| 16:42:12 | Elevated cmd.exe spawned by fodhelper.exe | Sysmon Event 1 |
| 16:42:15 | Registry cleanup performed | Sysmon Event 12 |
| 16:42:20 | mscfile registry hijack created | Sysmon Event 13 |
| 16:42:23 | mscfile cleanup performed | Sysmon Event 12 |
| 16:44:00 | Splunk alert triggered (risk score: 95) | Splunk |

---

## Investigation Details

### Initial Triage

Alert triggered on Sysmon Event 13 showing registry modification under `ms-settings\Shell\Open\command` — a well-known UAC bypass path. The modification was performed by powershell.exe running under a standard user context, targeting auto-elevation through fodhelper.exe.

### Evidence Collection

**Splunk Query — Registry Modifications:**
```spl
index=sysmon EventCode=13
  (TargetObject="*\\ms-settings\\Shell\\Open\\command*"
   OR TargetObject="*\\mscfile\\Shell\\Open\\command*")
| table _time, Computer, User, Image, TargetObject, Details
| sort _time
```

**Results:**
| Time | User | Target Object | Details |
|---|---|---|---|
| 16:42:05 | WORKGROUP\analyst | `ms-settings\Shell\Open\command\(Default)` | `cmd.exe /c echo ...` |
| 16:42:07 | WORKGROUP\analyst | `ms-settings\Shell\Open\command\DelegateExecute` | `(Empty)` |
| 16:42:20 | WORKGROUP\analyst | `mscfile\Shell\Open\command\(Default)` | `cmd.exe /c echo ...` |

**Splunk Query — Process Execution Chain:**
```spl
index=sysmon EventCode=1
  (Image="*fodhelper.exe" OR ParentImage="*fodhelper.exe"
   OR Image="*eventvwr.exe" OR ParentImage="*eventvwr.exe")
| table _time, User, ParentImage, Image, CommandLine, IntegrityLevel
```

**Results:**
| Time | Parent | Process | Integrity Level |
|---|---|---|---|
| 16:42:10 | powershell.exe | fodhelper.exe | Medium |
| 16:42:12 | fodhelper.exe | cmd.exe | High ⚠️ |

### Root Cause Analysis

The Fodhelper UAC bypass exploits the auto-elevation behavior of `fodhelper.exe` (a Windows binary that runs with elevated privileges without prompting UAC). By hijacking its shell handler registry key, any command placed in the `(Default)` value is executed with High integrity (elevated privileges). The `DelegateExecute` value must be set to empty to redirect execution through the command key.

**Attack Chain:**
```
1. Attacker creates HKCU:\...\ms-settings\Shell\Open\command
2. Sets (Default) = malicious command
3. Sets DelegateExecute = "" (empty)
4. Launches fodhelper.exe (auto-elevates without UAC prompt)
5. fodhelper.exe reads ms-settings handler → executes attacker's command as High integrity
```

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Registry Key | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | UAC bypass hijack |
| Registry Value | `DelegateExecute = ""` | Bypass enabler |
| Process | fodhelper.exe | Auto-elevating binary |
| Process Chain | fodhelper.exe → cmd.exe (High) | Elevation indicator |
| Integrity Level | High (from Medium parent) | Privilege escalation |

---

## Impact Assessment

- **Confidentiality**: Medium (elevated privileges could access protected resources)
- **Integrity**: High (elevated code execution)
- **Availability**: None

---

## Remediation Actions

- [x] Verified registry keys were cleaned up post-simulation
- [x] Confirmed no persistent elevated access was established
- [x] Validated Sysmon Event 13 detection for both ms-settings and mscfile paths
- [x] Confirmed process ancestry tracking shows elevation chain

### Production Recommendations

- [ ] Set UAC to "Always notify" (highest setting)
- [ ] Deploy Windows Defender Credential Guard
- [ ] Monitor and alert on HKCU\Software\Classes modifications
- [ ] Consider removing fodhelper.exe if not needed (AppLocker block)

---

## Lessons Learned

1. **Registry monitoring is critical**: Sysmon Event 13 is the primary detection vector for UAC bypass techniques. Without it, this attack would be invisible.
2. **Process integrity levels matter**: The jump from Medium to High integrity in the process tree is a reliable indicator of successful UAC bypass.
3. **Cleanup doesn't erase evidence**: Even though the attacker cleaned up registry keys, Sysmon's real-time logging captured all modifications.

---

*Report generated on: 2024-10-10*
*Classification: True Positive — Simulated Attack*
]]>
