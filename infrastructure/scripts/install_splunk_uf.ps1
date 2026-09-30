<![CDATA[# ============================================================
# Splunk Universal Forwarder Installation Script
# Target: Windows Server 2022 (Windows Target VM)
# ============================================================
#Requires -RunAsAdministrator

param(
    [string]$SplunkServer = "10.0.0.100",
    [string]$ReceivingPort = "9997"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[*] SIEM Lab - Splunk UF Installation" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# ── Variables ──
$ufVersion = "9.3.2"
$ufInstaller = "splunkforwarder-${ufVersion}-d8bb32809498-x64-release.msi"
$ufUrl = "https://download.splunk.com/products/universalforwarder/releases/${ufVersion}/windows/${ufInstaller}"
$ufHome = "C:\Program Files\SplunkUniversalForwarder"
$tempDir = "C:\Windows\Temp"

# ── Download ──
Write-Host "[+] Downloading Splunk Universal Forwarder ${ufVersion}..."
$ufPath = Join-Path $tempDir $ufInstaller
if (-not (Test-Path $ufPath)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ufUrl -OutFile $ufPath -UseBasicParsing
}

# ── Install ──
Write-Host "[+] Installing Splunk Universal Forwarder..."
$installArgs = @(
    "/i", $ufPath,
    "RECEIVING_INDEXER=${SplunkServer}:${ReceivingPort}",
    "AGREETOLICENSE=yes",
    "LAUNCHSPLUNK=0",
    "/quiet"
)
Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow

# ── Configure Inputs ──
Write-Host "[+] Configuring data inputs..."
$inputsConf = @"
# ============================================================
# Splunk Universal Forwarder — Windows Inputs Configuration
# ============================================================

[default]
host = win-target

# ── Sysmon Operational Log ──
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

# ── Windows Security Events ──
[WinEventLog://Security]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Security
evt_resolve_ad_obj = 1
blacklist1 = EventCode="5156" Message="Windows Filtering Platform"
blacklist2 = EventCode="4689"

# ── Windows System Events ──
[WinEventLog://System]
disabled = false
index = wineventlog
sourcetype = WinEventLog:System

# ── PowerShell Operational Log ──
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Microsoft-Windows-PowerShell/Operational

# ── Windows Defender Operational Log ──
[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Microsoft-Windows-Windows Defender/Operational
"@

$inputsPath = Join-Path $ufHome "etc\system\local\inputs.conf"
$inputsConf | Out-File -FilePath $inputsPath -Encoding UTF8 -Force

# ── Configure Outputs ──
Write-Host "[+] Configuring forward server..."
$outputsConf = @"
[tcpout]
defaultGroup = splunk-server

[tcpout:splunk-server]
server = ${SplunkServer}:${ReceivingPort}
"@

$outputsPath = Join-Path $ufHome "etc\system\local\outputs.conf"
$outputsConf | Out-File -FilePath $outputsPath -Encoding UTF8 -Force

# ── Start Service ──
Write-Host "[+] Starting Splunk Universal Forwarder..."
Start-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
Set-Service -Name "SplunkForwarder" -StartupType Automatic

# ── Verification ──
$ufService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
if ($ufService -and $ufService.Status -eq "Running") {
    Write-Host "[✓] Splunk Universal Forwarder is running" -ForegroundColor Green
} else {
    Write-Host "[!] Starting Splunk UF via CLI..."
    & "$ufHome\bin\splunk.exe" start --accept-license --answer-yes --seed-passwd "Forwarder123!"
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[✓] Splunk UF Installation Complete" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Forward Server: ${SplunkServer}:${ReceivingPort}" -ForegroundColor Green
Write-Host "  Indexes: sysmon, wineventlog" -ForegroundColor Green
Write-Host "  Sources: Sysmon, Security, System, PowerShell, Defender" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
]]>
