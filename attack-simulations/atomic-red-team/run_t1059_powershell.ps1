<![CDATA[# ============================================================
# Atomic Red Team Simulation: T1059.001 — PowerShell
# Target: Windows Server (run locally on target)
# MITRE ATT&CK: T1059.001 — PowerShell Execution
# ============================================================
#Requires -RunAsAdministrator

Write-Host "=============================================" -ForegroundColor Red
Write-Host " ATTACK SIMULATION: T1059.001 — PowerShell" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""

# ── Method 1: Atomic Red Team ──
Write-Host "[*] Method 1: Atomic Red Team T1059.001..." -ForegroundColor Yellow
try {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3 -ErrorAction SilentlyContinue
    Write-Host "[✓] Atomic Red Team tests completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Atomic Red Team not installed, using manual simulation" -ForegroundColor Yellow
}

# ── Method 2: Encoded Command Execution ──
Write-Host ""
Write-Host "[*] Method 2: Encoded command execution..." -ForegroundColor Yellow

$commands = @(
    "Write-Host 'SIEM Lab Test - Encoded PowerShell Execution'",
    "Get-Process | Select-Object -First 5",
    "Get-Service | Where-Object {`$_.Status -eq 'Running'} | Select-Object -First 5",
    "[System.Net.Dns]::GetHostAddresses('localhost')"
)

foreach ($cmd in $commands) {
    $encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    Write-Host "  [+] Running encoded: $($cmd.Substring(0, [Math]::Min(50, $cmd.Length)))..." -ForegroundColor Gray
    powershell.exe -EncodedCommand $encodedCmd 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

# ── Method 3: Download Cradle (Safe — points to localhost) ──
Write-Host ""
Write-Host "[*] Method 3: Download cradle simulation..." -ForegroundColor Yellow

# Create a benign test script
$testScript = "Write-Host 'SIEM Lab - Download Cradle Test Complete'"
$testScript | Out-File -FilePath "C:\Windows\Temp\test_payload.ps1" -Force

Write-Host "  [+] IEX download cradle (localhost)..." -ForegroundColor Gray
try {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (Get-Content 'C:\Windows\Temp\test_payload.ps1' -Raw)" 2>$null | Out-Null
} catch { }

Write-Host "  [+] Net.WebClient simulation..." -ForegroundColor Gray
try {
    powershell.exe -Command "(New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')" 2>$null | Out-Null
} catch { }

# ── Method 4: Hidden Window Execution ──
Write-Host ""
Write-Host "[*] Method 4: Hidden window execution..." -ForegroundColor Yellow
powershell.exe -WindowStyle Hidden -NoProfile -Command "Start-Sleep -Seconds 2" 2>$null | Out-Null

# ── Method 5: Bypass Execution Policy ──
Write-Host ""
Write-Host "[*] Method 5: Execution policy bypass..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "Get-Date" 2>$null | Out-Null

# ── Cleanup ──
Remove-Item "C:\Windows\Temp\test_payload.ps1" -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[✓] PowerShell simulation complete" -ForegroundColor Green
Write-Host "[*] Check Splunk: index=sysmon EventCode=1 Image=*powershell.exe*" -ForegroundColor Cyan
Write-Host "[*] Check Splunk: index=wineventlog EventCode=4104" -ForegroundColor Cyan
Write-Host ""

# ── Verification ──
Write-Host "[*] Recent Sysmon Process Creation events for PowerShell:" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 10 |
    Where-Object { $_.Message -match "powershell" } |
    Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "`n" | Select-String "CommandLine:").ToString().Trim()}} |
    Format-Table -AutoSize
]]>
