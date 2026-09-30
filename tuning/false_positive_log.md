<![CDATA[# 📊 False Positive Tracking Log

This document tracks all false positive findings encountered during detection rule testing, along with the root cause analysis and tuning actions taken to reduce noise.

---

## Summary Metrics

| Metric | Pre-Tuning | Post-Tuning | Improvement |
|---|---|---|---|
| Overall FP Rate | ~35% | ~8% | 77% reduction |
| T1110 Brute Force FP Rate | 25% | 5% | 80% reduction |
| T1059.001 PowerShell FP Rate | 40% | 8% | 80% reduction |
| T1053 Scheduled Task FP Rate | 50% | 10% | 80% reduction |
| T1003 LSASS Access FP Rate | 30% | 5% | 83% reduction |
| T1548 UAC Bypass FP Rate | 20% | 5% | 75% reduction |

---

## FP Log Entries

### FP-001: Windows Update PowerShell (T1059.001)

| Field | Value |
|---|---|
| **Date** | 2024-10-02 |
| **Rule** | T1059.001 — Suspicious PowerShell Execution |
| **Classification** | Benign True Positive |
| **Frequency** | Multiple times daily |

**Description**: Windows Update service spawns PowerShell with `-EncodedCommand` flag via svchost.exe running as SYSTEM. The encoded payload contains update verification scripts.

**Evidence**:
```
ParentImage: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\SYSTEM
CommandLine: powershell.exe -EncodedCommand WwBTAH... (Windows Update payload)
```

**Tuning Action**: Added whitelist exclusion:
```spl
NOT (ParentImage="*\\svchost.exe" User="NT AUTHORITY\\SYSTEM" CommandLine="*WindowsUpdate*")
```

**Result**: Eliminated 15+ daily false positives.

---

### FP-002: Legitimate Service Account Logins (T1110)

| Field | Value |
|---|---|
| **Date** | 2024-10-03 |
| **Rule** | T1110 — Brute Force Detection |
| **Classification** | False Positive |
| **Frequency** | 2-3 times per hour |

**Description**: Service accounts (svc_backup, svc_monitor) generate multiple failed logins when their passwords are rotated or services restart with cached credentials.

**Evidence**:
```
EventCode: 4625
Account_Name: svc_backup
src_ip: 10.0.0.20 (local)
Failed attempts: 6-8 per occurrence
```

**Tuning Action**: Raised threshold from 5 to 10 attempts AND excluded known service accounts:
```spl
| where failed_attempts > 10
NOT Account_Name IN ("svc_backup", "svc_monitor", "SYSTEM", "LOCAL SERVICE")
```

**Result**: Eliminated hourly false positives from service accounts.

---

### FP-003: Windows Defender LSASS Access (T1003.001)

| Field | Value |
|---|---|
| **Date** | 2024-10-04 |
| **Rule** | T1003.001 — LSASS Memory Access |
| **Classification** | Benign True Positive |
| **Frequency** | Continuous (every scan cycle) |

**Description**: Windows Defender (MsMpEng.exe) and Windows Security Health Service regularly access LSASS for security scanning purposes.

**Evidence**:
```
SourceImage: C:\ProgramData\Microsoft\Windows Defender\Platform\...\MsMpEng.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1410
```

**Tuning Action**: Excluded known security products:
```spl
| where NOT match(SourceImage, "(?i)(MsMpEng|NisSrv|SecurityHealthService)\.exe$")
```

**Result**: Eliminated ~20 daily false positives from Defender scanning.

---

### FP-004: Scheduled Task Manager (T1053.005)

| Field | Value |
|---|---|
| **Date** | 2024-10-06 |
| **Rule** | T1053 — Scheduled Task Detection |
| **Classification** | False Positive |
| **Frequency** | Several times daily |

**Description**: Legitimate system services (services.exe, wmiprvse.exe) create and modify scheduled tasks as part of normal Windows operations. Task Scheduler (taskeng.exe) also triggers legitimate schtasks.exe calls.

**Evidence**:
```
ParentImage: C:\Windows\System32\services.exe
Image: C:\Windows\System32\schtasks.exe
CommandLine: schtasks /create /tn "Microsoft\Windows\..." /ru SYSTEM
```

**Tuning Action**: Excluded legitimate parent processes:
```spl
| where NOT match(ParentImage, "(?i)(services|taskeng|wmiprvse|svchost|mmc)\.exe$")
```

**Result**: Reduced from 50% FP rate to 10%.

---

### FP-005: File Association Changes (T1548.002)

| Field | Value |
|---|---|
| **Date** | 2024-10-08 |
| **Rule** | T1548.002 — UAC Bypass Detection |
| **Classification** | False Positive |
| **Frequency** | Occasional (during software installs) |

**Description**: Software installations occasionally modify shell handler registry keys under `HKCU\Software\Classes`, which overlaps with the UAC bypass detection pattern.

**Evidence**:
```
Image: C:\Windows\System32\msiexec.exe
TargetObject: HKCU\Software\Classes\*\Shell\Open\command
```

**Tuning Action**: Narrowed detection to specific UAC bypass paths only:
```spl
(TargetObject="*\\ms-settings\\Shell\\Open\\command*"
 OR TargetObject="*\\mscfile\\Shell\\Open\\command*")
```

**Result**: Eliminated installation-related false positives.

---

## Tuning Decision Criteria

| Criteria | Action |
|---|---|
| FP caused by known-good process | Add to whitelist |
| FP caused by too-low threshold | Raise threshold with justification |
| FP caused by overly broad pattern | Narrow pattern specificity |
| BTP from authorized activity | Evaluate risk; whitelist or suppress |
| Repeated FP from same source | Investigate root cause before suppressing |
]]>
