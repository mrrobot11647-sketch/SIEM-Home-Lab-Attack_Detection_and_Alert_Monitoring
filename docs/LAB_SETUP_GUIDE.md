<![CDATA[# 🏗️ Lab Setup Guide

Complete step-by-step guide to building the SIEM Home Lab from scratch.

---

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Network Architecture](#network-architecture)
3. [VM Provisioning](#vm-provisioning)
4. [Splunk Enterprise Setup](#splunk-enterprise-setup)
5. [Windows Endpoint Setup](#windows-endpoint-setup)
6. [Linux Endpoint Setup](#linux-endpoint-setup)
7. [Validation Checklist](#validation-checklist)

---

## Hardware Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 16 GB | 32 GB |
| Disk | 100 GB SSD | 250 GB SSD |
| Network | NAT + Host-Only | NAT + Host-Only |

### VM Resource Allocation

| VM | OS | CPU | RAM | Disk | IP Address |
|---|---|---|---|---|---|
| Splunk Server | Ubuntu 22.04 | 2 vCPU | 6 GB | 50 GB | 10.0.0.100 |
| Windows Target | Windows Server 2022 | 2 vCPU | 4 GB | 40 GB | 10.0.0.20 |
| Linux Target | Ubuntu 22.04 | 1 vCPU | 2 GB | 20 GB | 10.0.0.30 |
| Kali Attacker | Kali Linux 2024.x | 2 vCPU | 4 GB | 30 GB | 10.0.0.10 |

---

## Network Architecture

All VMs are connected via an **Internal Network** (named `siem-lab`) for isolated attack traffic, plus a **NAT** adapter for internet access during setup.

### VirtualBox Network Setup

```
Adapter 1: NAT (internet access for packages/updates)
Adapter 2: Internal Network (Name: "siem-lab")
    Subnet: 10.0.0.0/24
    Gateway: 10.0.0.1
```

### Static IP Configuration

**Windows Server (10.0.0.20)**:
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 10.0.0.20 -PrefixLength 24 -DefaultGateway 10.0.0.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses 8.8.8.8,8.8.4.4
```

**Ubuntu Server (10.0.0.30)**:
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```
```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      dhcp4: no
      addresses: [10.0.0.30/24]
      gateway4: 10.0.0.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```
```bash
sudo netplan apply
```

---

## VM Provisioning

### Option A: Manual VM Creation

1. Download ISOs for all operating systems
2. Create VMs in VirtualBox/VMware with the specs above
3. Install each OS and configure networking

### Option B: Vagrant (Automated)

```bash
cd infrastructure/
vagrant up
```

The `Vagrantfile` will automatically provision all four VMs with correct networking.

---

## Splunk Enterprise Setup

### 1. Install Splunk Enterprise

```bash
# Download Splunk Enterprise (Ubuntu/Debian)
wget -O splunk-9.3.2-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/9.3.2/linux/splunk-9.3.2-d8bb32809498-linux-2.6-amd64.deb"

# Install
sudo dpkg -i splunk-9.3.2-linux-amd64.deb

# Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --seed-passwd 'YourStrongPassword123!'

# Enable boot start
sudo /opt/splunk/bin/splunk enable boot-start
```

### 2. Configure Receiving Port

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:YourStrongPassword123!
```

### 3. Create Indexes

Copy `splunk/indexes.conf` to `/opt/splunk/etc/system/local/indexes.conf`:

```bash
sudo cp splunk/indexes.conf /opt/splunk/etc/system/local/indexes.conf
sudo /opt/splunk/bin/splunk restart
```

### 4. Import Dashboards

For each dashboard XML in `splunk/dashboards/`:

1. Log into Splunk Web (http://10.0.0.100:8000)
2. Navigate to **Settings → User Interface → Views**
3. Click **New Dashboard** → **Source Editor**
4. Paste the XML content
5. Save

### 5. Import Saved Searches (Alerts)

```bash
sudo cp splunk/savedsearches.conf /opt/splunk/etc/system/local/savedsearches.conf
sudo /opt/splunk/bin/splunk restart
```

---

## Windows Endpoint Setup

### 1. Install Sysmon

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"

# Install with custom config
C:\Sysmon\Sysmon64.exe -accepteula -i sysmon-config.xml
```

Copy `sysmon/sysmon-config.xml` to the Windows endpoint before running the install command.

### 2. Enable Windows Security Auditing

```powershell
# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable command-line logging in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell Script Block Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable PowerShell Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
```

### 3. Install Splunk Universal Forwarder

```powershell
# Download and install Splunk UF
# Run the MSI installer with:
msiexec.exe /i splunkforwarder-9.3.2-x64.msi RECEIVING_INDEXER="10.0.0.100:9997" AGREETOLICENSE=yes /quiet

# Configure inputs
# Copy the inputs.conf content for Windows to:
# C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

### 4. Install Atomic Red Team

```powershell
# Install prerequisites
Install-Module -Name Posh-SYSMON -Force
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force

# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

---

## Linux Endpoint Setup

### 1. Configure rsyslog

```bash
# Ensure rsyslog is installed
sudo apt update && sudo apt install -y rsyslog

# Verify auth logging
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

### 2. Install auditd

```bash
sudo apt install -y auditd audispd-plugins

# Add custom audit rules
sudo tee /etc/audit/rules.d/siem-lab.rules << 'EOF'
# Monitor authentication files
-w /etc/passwd -p wa -k identity_mod
-w /etc/shadow -p wa -k identity_mod
-w /etc/group -p wa -k identity_mod
-w /etc/sudoers -p wa -k sudoers_mod

# Monitor privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_esc

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron_mod
-w /var/spool/cron/ -p wa -k cron_mod
EOF

sudo augenrules --load
sudo systemctl restart auditd
```

### 3. Install Splunk Universal Forwarder

```bash
wget -O splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/9.3.2/linux/splunkforwarder-9.3.2-d8bb32809498-linux-2.6-amd64.deb"
sudo dpkg -i splunkforwarder.deb

# Start and configure
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --seed-passwd 'ForwarderPass123!'
sudo /opt/splunkforwarder/bin/splunk add forward-server 10.0.0.100:9997 -auth admin:ForwarderPass123!

# Add monitored log files
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index linux -sourcetype linux:auth
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog -index linux -sourcetype syslog
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log -index linux -sourcetype linux:audit

sudo /opt/splunkforwarder/bin/splunk enable boot-start
```

---

## Validation Checklist

After completing setup, verify each component:

### Splunk Server
- [ ] Splunk Web accessible at `http://10.0.0.100:8000`
- [ ] Receiving port 9997 is listening: `netstat -tlnp | grep 9997`
- [ ] Indexes created: `sysmon`, `wineventlog`, `linux`, `attack_logs`

### Windows Endpoint
- [ ] Sysmon service running: `Get-Service Sysmon64`
- [ ] Sysmon events visible: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5`
- [ ] Splunk UF running: `Get-Service SplunkForwarder`
- [ ] Events appearing in Splunk: search `index=sysmon` and `index=wineventlog`

### Linux Endpoint
- [ ] rsyslog running: `systemctl status rsyslog`
- [ ] auditd running: `systemctl status auditd`
- [ ] Splunk UF running: `systemctl status SplunkForwarder`
- [ ] Events appearing in Splunk: search `index=linux`

### Kali Attacker
- [ ] Network connectivity to targets: `ping 10.0.0.20` and `ping 10.0.0.30`
- [ ] Hydra installed: `hydra -h`
- [ ] Nmap installed: `nmap --version`
- [ ] Metasploit installed: `msfconsole --version`

### Dashboards & Alerts
- [ ] All 5 dashboards visible in Splunk
- [ ] All detection alerts configured and enabled
- [ ] Test alert triggers with sample searches

---

> **Next Steps**: Once validated, proceed to [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) to begin adversary simulations.
]]>
