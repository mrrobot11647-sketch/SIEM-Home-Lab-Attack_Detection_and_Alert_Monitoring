<![CDATA[# ============================================================
# Sysmon Installation Script
# Target: Windows Server 2022 (Windows Target VM)
# ============================================================
#Requires -RunAsAdministrator

param(
    [string]$SysmonConfigPath = "C:\vagrant\sysmon\sysmon-config.xml",
    [string]$SplunkServer = "10.0.0.100:9997"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[*] SIEM Lab - Sysmon Installation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# ── Download Sysmon ──
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "C:\Windows\Temp\Sysmon.zip"
$sysmonDir = "C:\Sysmon"

Write-Host "[+] Downloading Sysmon..."
if (-not (Test-Path $sysmonDir)) {
    New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

# ── Copy Sysmon Config ──
Write-Host "[+] Copying Sysmon configuration..."
if (Test-Path $SysmonConfigPath) {
    Copy-Item -Path $SysmonConfigPath -Destination "$sysmonDir\sysmon-config.xml" -Force
} else {
    Write-Warning "Sysmon config not found at $SysmonConfigPath. Using default."
}

# ── Install Sysmon ──
Write-Host "[+] Installing Sysmon64..."
$sysmonExe = Join-Path $sysmonDir "Sysmon64.exe"
& $sysmonExe -accepteula -i "$sysmonDir\sysmon-config.xml"

# ── Verify Installation ──
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "[✓] Sysmon64 service is running" -ForegroundColor Green
} else {
    Write-Host "[!] Sysmon64 service is not running" -ForegroundColor Red
    exit 1
}

# ── Enable Windows Security Auditing ──
Write-Host "[+] Configuring Windows audit policies..."

# Logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Process auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Object access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# ── Enable Command-Line Logging ──
Write-Host "[+] Enabling command-line process creation logging..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

# ── Enable PowerShell Logging ──
Write-Host "[+] Enabling PowerShell Script Block Logging..."
$psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Script Block Logging
New-Item -Path "$psLoggingPath\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Module Logging
New-Item -Path "$psLoggingPath\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "$psLoggingPath\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\ModuleLogging\ModuleNames" -Name "*" -Value "*"

# Transcription
New-Item -Path "$psLoggingPath\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "$psLoggingPath\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
New-Item -ItemType Directory -Path "C:\PSTranscripts" -Force | Out-Null

# ── Enable RDP ──
Write-Host "[+] Enabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=tcp localport=3389

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[✓] Sysmon + Windows Auditing Complete" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Sysmon Service:  Running" -ForegroundColor Green
Write-Host "  Audit Policies:  Configured" -ForegroundColor Green
Write-Host "  PowerShell Logs: Enabled" -ForegroundColor Green
Write-Host "  RDP:             Enabled" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
]]>
