<![CDATA[# 🔧 Detection Rule Tuning Changelog

Chronological record of all changes made to detection rules, including rationale, impact, and validation results.

---

## Changelog

### 2024-10-15 — T1110 Brute Force v1.3

**Rule**: ALERT - T1110.001 - RDP Brute Force Detected

| Field | Value |
|---|---|
| **Change Type** | Filter Enhancement |
| **Author** | SOC Analyst |
| **FP Impact** | 25% → 5% |

**Changes**:
- Added `Logon_Type=10` filter to isolate RDP-specific brute force from other logon failures
- Raised threshold from 5 to 10 failed attempts per 5-minute window
- Excluded service accounts: `svc_backup`, `svc_monitor`, `SYSTEM`
- Added severity categorization: Medium (>10), High (>25), Critical (>50)

**Before**:
```spl
index=wineventlog EventCode=4625
| stats count by src_ip | where count > 5
```

**After**:
```spl
index=wineventlog EventCode=4625 Logon_Type=10
| bin _time span=5m
| stats count as failed_attempts by src_ip, _time, ComputerName
| where failed_attempts > 10
| eval severity=case(failed_attempts>50, "Critical", failed_attempts>25, "High", failed_attempts>10, "Medium")
```

**Validation**: Ran 3 brute force simulations — all detected. 0 false positives in 24h observation.

---

### 2024-10-20 — T1059.001 PowerShell v1.4

**Rule**: ALERT - T1059.001 - Suspicious PowerShell Execution

| Field | Value |
|---|---|
| **Change Type** | Whitelist + Risk Scoring |
| **Author** | SOC Analyst |
| **FP Impact** | 40% → 8% |

**Changes**:
- Added Windows Update whitelist (`svchost.exe → powershell.exe` as SYSTEM with `WindowsUpdate` in CommandLine)
- Added SCCM whitelist (`ccmexec.exe` parent process)
- Implemented risk scoring: 60 (baseline), 80 (encoded), 90 (download cradle), 100 (offensive tools)
- Added additional indicators: `FromBase64String`, `-nop`, `-noni`

**Validation**: All 5 PowerShell attack simulations detected. Windows Update no longer triggers false alerts.

---

### 2024-10-18 — T1053.005 Scheduled Task v1.2

**Rule**: ALERT - T1053.005 - Suspicious Scheduled Task Created

| Field | Value |
|---|---|
| **Change Type** | Parent Process Filtering |
| **Author** | SOC Analyst |
| **FP Impact** | 50% → 10% |

**Changes**:
- Excluded legitimate parent processes: `services.exe`, `taskeng.exe`, `wmiprvse.exe`, `svchost.exe`, `mmc.exe`
- Added risk scoring for SYSTEM/onlogon/Hidden flags
- Restricted to `/create` command only (excluded `/query`, `/delete`)

**Validation**: Manual schtasks.exe creation from cmd.exe/powershell.exe correctly detected. System-created tasks no longer alert.

---

### 2024-10-20 — T1003.001 LSASS v1.4

**Rule**: ALERT - T1003.001 - LSASS Memory Access Detected

| Field | Value |
|---|---|
| **Change Type** | Whitelist Expansion |
| **Author** | SOC Analyst |
| **FP Impact** | 30% → 5% |

**Changes**:
- Excluded: `csrss.exe`, `wininit.exe`, `wmiprvse.exe`, `svchost.exe`
- Excluded security products: `MsMpEng.exe`, `NisSrv.exe`, `SecurityHealthService.exe`, `taskhostw.exe`
- Added GrantedAccess-based risk scoring (0x1FFFFF=100, 0x143A=90, 0x1010=80)

**Validation**: comsvcs.dll MiniDump and direct process access both detected. Defender scans no longer trigger alerts.

---

### 2024-10-18 — T1548.002 UAC Bypass v1.2

**Rule**: ALERT - T1548.002 - UAC Bypass Attempt Detected

| Field | Value |
|---|---|
| **Change Type** | Path Specificity |
| **Author** | SOC Analyst |
| **FP Impact** | 20% → 5% |

**Changes**:
- Narrowed from all `Shell\Open\command` modifications to specific paths: `ms-settings`, `mscfile`, `exefile`
- Added process-based correlation query for higher confidence
- Added correlation with auto-elevating binaries (fodhelper, computerdefaults, sdclt, eventvwr)

**Validation**: Both Fodhelper and EventVwr bypass techniques detected. Software installations no longer trigger false alerts.

---

## Tuning Metrics Summary

| Rule | v1.0 FP Rate | Current FP Rate | Iterations | Status |
|---|---|---|---|---|
| T1110 Brute Force | 25% | 5% | 3 | Stable |
| T1059.001 PowerShell | 40% | 8% | 4 | Stable |
| T1053.005 Scheduled Task | 50% | 10% | 2 | Monitoring |
| T1003.001 LSASS Access | 30% | 5% | 4 | Stable |
| T1548.002 UAC Bypass | 20% | 5% | 2 | Stable |

---

## Next Steps

- [ ] Add T1055 (Process Injection) detection rule
- [ ] Implement T1021.001 (RDP lateral movement) correlation
- [ ] Add DNS tunneling detection (Sysmon Event 22)
- [ ] Deploy Sigma rule conversion for community detections
]]>
