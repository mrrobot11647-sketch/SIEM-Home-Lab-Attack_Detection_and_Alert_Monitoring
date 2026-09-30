<![CDATA[# ============================================================
# Atomic Red Team Simulation: T1053.005 — Scheduled Task
# Target: Windows Server (run locally on target)
# MITRE ATT&CK: T1053.005 — Scheduled Task/Job
# ============================================================
#Requires -RunAsAdministrator

Write-Host "=============================================" -ForegroundColor Red
Write-Host " ATTACK SIMULATION: T1053.005 — Sched Task" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""

# ── Method 1: Atomic Red Team ──
Write-Host "[*] Method 1: Atomic Red Team T1053.005..." -ForegroundColor Yellow
try {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1053.005 -TestNumbers 1,2 -ErrorAction SilentlyContinue
    Write-Host "[✓] Atomic Red Team tests completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Atomic Red Team not installed, using manual simulation" -ForegroundColor Yellow
}

# ── Method 2: Create Persistence Task (SYSTEM) ──
Write-Host ""
Write-Host "[*] Method 2: Creating scheduled task running as SYSTEM..." -ForegroundColor Yellow
schtasks /create /tn "SIEM-Lab-Persistence-Test" /tr "powershell.exe -WindowStyle Hidden -Command 'Start-Sleep -Seconds 30'" /sc onlogon /ru SYSTEM /f 2>$null
Write-Host "[✓] Task 'SIEM-Lab-Persistence-Test' created" -ForegroundColor Green

# ── Method 3: Create Daily Task ──
Write-Host ""
Write-Host "[*] Method 3: Creating daily scheduled task..." -ForegroundColor Yellow
schtasks /create /tn "SIEM-Lab-Daily-Beacon" /tr "cmd.exe /c echo beacon" /sc daily /st 02:00 /f 2>$null
Write-Host "[✓] Task 'SIEM-Lab-Daily-Beacon' created" -ForegroundColor Green

# ── Method 4: Create On-Start Task ──
Write-Host ""
Write-Host "[*] Method 4: Creating on-start task..." -ForegroundColor Yellow
schtasks /create /tn "SIEM-Lab-Startup-Task" /tr "cmd.exe /c whoami > C:\Windows\Temp\whoami.txt" /sc onstart /ru SYSTEM /f 2>$null
Write-Host "[✓] Task 'SIEM-Lab-Startup-Task' created" -ForegroundColor Green

# ── Verification ──
Write-Host ""
Write-Host "[*] Listing created tasks:" -ForegroundColor Yellow
schtasks /query /tn "SIEM-Lab-Persistence-Test" /fo LIST 2>$null
schtasks /query /tn "SIEM-Lab-Daily-Beacon" /fo LIST 2>$null
schtasks /query /tn "SIEM-Lab-Startup-Task" /fo LIST 2>$null

# ── Cleanup ──
Write-Host ""
Write-Host "[*] Cleaning up test tasks..." -ForegroundColor Yellow
schtasks /delete /tn "SIEM-Lab-Persistence-Test" /f 2>$null
schtasks /delete /tn "SIEM-Lab-Daily-Beacon" /f 2>$null
schtasks /delete /tn "SIEM-Lab-Startup-Task" /f 2>$null
Write-Host "[✓] Cleanup complete" -ForegroundColor Green

Write-Host ""
Write-Host "[✓] Scheduled task simulation complete" -ForegroundColor Green
Write-Host "[*] Check Splunk: index=sysmon EventCode=1 Image=*schtasks.exe*" -ForegroundColor Cyan
Write-Host "[*] Check Splunk: index=wineventlog EventCode=4698" -ForegroundColor Cyan
]]>
