<![CDATA[# 🛡️ SIEM Home Lab — Attack Detection & Alert Monitoring

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org/)
[![Splunk](https://img.shields.io/badge/Splunk-9.x-green)](https://www.splunk.com/)
[![Sysmon](https://img.shields.io/badge/Sysmon-v15-orange)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

A production-grade Security Operations Center (SOC) home lab featuring **Splunk SIEM**, **Sysmon telemetry**, and adversary simulation using **Atomic Red Team** and **Kali Linux**. This project demonstrates end-to-end detection engineering — from log ingestion to alert triage and incident response documentation.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ATTACK NETWORK (NAT)                          │
│                                                                         │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
│  │  Kali Linux  │     │   Windows    │     │    Ubuntu     │            │
│  │  (Attacker)  │────▶│   Server     │     │   Server     │            │
│  │  10.0.0.10   │     │  10.0.0.20   │     │  10.0.0.30   │            │
│  │              │     │  Sysmon +    │     │  auditd +    │            │
│  │  • Hydra     │     │  WinEventLog │     │  auth.log    │            │
│  │  • Nmap      │     │  + Splunk UF │     │  + Splunk UF │            │
│  │  • Metasploit│     │              │     │              │            │
│  └──────────────┘     └──────┬───────┘     └──────┬───────┘            │
│                              │                     │                    │
│                              │  Log Forwarding     │                    │
│                              │  (TCP 9997)         │                    │
│                              ▼                     ▼                    │
│                       ┌──────────────────────────────┐                 │
│                       │      Splunk Enterprise       │                 │
│                       │       10.0.0.100:8000        │                 │
│                       │                              │                 │
│                       │  • Indexes: sysmon, winevent │                 │
│                       │    linux, attack_logs         │                 │
│                       │  • Dashboards & Alerts       │                 │
│                       │  • MITRE ATT&CK Mapping      │                 │
│                       └──────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🗂️ Project Structure

```
SIEM-Home-Lab-Attack_Detection_and_Alert_Monitoring/
├── README.md
├── LICENSE
├── docs/
│   ├── LAB_SETUP_GUIDE.md          # Full environment build guide
│   ├── ATTACK_PLAYBOOK.md          # Attack simulation procedures
│   └── TRIAGE_WORKFLOW.md          # Alert triage & tuning methodology
├── infrastructure/
│   ├── Vagrantfile                 # Automated VM provisioning
│   ├── ansible/
│   │   ├── playbook.yml            # Master orchestration playbook
│   │   ├── roles/
│   │   │   ├── splunk-server/      # Splunk Enterprise deployment
│   │   │   ├── splunk-forwarder/   # Universal Forwarder config
│   │   │   ├── sysmon/             # Sysmon installation + config
│   │   │   └── linux-logging/      # auditd + rsyslog setup
│   │   └── inventory.ini           # Host inventory
│   └── scripts/
│       ├── install_splunk_server.sh
│       ├── install_splunk_uf.ps1
│       ├── install_sysmon.ps1
│       └── configure_linux_logging.sh
├── sysmon/
│   └── sysmon-config.xml           # Tuned Sysmon configuration
├── splunk/
│   ├── indexes.conf                # Index definitions
│   ├── inputs.conf                 # Data input configuration
│   ├── props.conf                  # Field extractions
│   ├── transforms.conf             # Field transforms
│   ├── savedsearches.conf          # Detection alerts
│   └── dashboards/
│       ├── soc_overview.xml        # SOC operations dashboard
│       ├── failed_logins.xml       # Authentication monitoring
│       ├── process_creation.xml    # Process execution tracking
│       ├── network_activity.xml    # Network connection monitoring
│       └── mitre_attack_matrix.xml # ATT&CK technique heatmap
├── detection-rules/
│   ├── T1110_brute_force.yml       # Brute Force detection
│   ├── T1059.001_powershell.yml    # PowerShell execution detection
│   ├── T1053_scheduled_task.yml    # Scheduled task persistence
│   ├── T1003_credential_dump.yml   # Credential access detection
│   ├── T1548_privilege_escalation.yml # Privilege escalation
│   └── README.md                   # Detection rule documentation
├── attack-simulations/
│   ├── atomic-red-team/
│   │   ├── run_t1110_bruteforce.ps1
│   │   ├── run_t1059_powershell.ps1
│   │   ├── run_t1053_scheduled_task.ps1
│   │   ├── run_t1003_credential_dump.ps1
│   │   └── run_t1548_privesc.ps1
│   ├── kali-attacks/
│   │   ├── ssh_bruteforce.sh
│   │   ├── rdp_bruteforce.sh
│   │   ├── nmap_recon.sh
│   │   └── metasploit_exploit.rc
│   └── README.md
├── incident-reports/
│   ├── TEMPLATE.md                 # Incident report template
│   ├── IR-001_RDP_Brute_Force.md
│   ├── IR-002_Suspicious_PowerShell.md
│   ├── IR-003_Privilege_Escalation.md
│   └── IR-004_SSH_Brute_Force.md
├── tuning/
│   ├── false_positive_log.md       # FP tracking & tuning decisions
│   └── tuning_changelog.md         # Detection rule change history
└── .gitignore
```

## 🎯 Key Capabilities

| Capability | Implementation |
|---|---|
| **Log Collection** | Sysmon (Event IDs 1, 3, 7, 8, 10, 11, 13), Windows Security Events (4625, 4624, 4688), Linux auth/syslog |
| **SIEM Platform** | Splunk Enterprise 9.x with custom indexes, field extractions, and data models |
| **Attack Simulation** | Atomic Red Team (PowerShell), Kali Linux (Hydra, Nmap, Metasploit) |
| **Detection Rules** | 5 custom alerts mapped to MITRE ATT&CK techniques |
| **Dashboards** | SOC Overview, Failed Logins, Process Creation, Network Activity, MITRE Heatmap |
| **Incident Response** | 4 documented incident reports with triage analysis and remediation |
| **Tuning** | False positive tracking, rule iteration, noise reduction documentation |

## 🚀 Quick Start

### Prerequisites

- **Hypervisor**: VirtualBox 7.x or VMware Workstation
- **Vagrant**: 2.4+ (for automated provisioning)
- **RAM**: Minimum 16 GB (recommended 32 GB)
- **Disk**: 100 GB free space
- **ISOs**: Windows Server 2022, Ubuntu 22.04, Kali Linux 2024.x

### Option 1: Automated Setup (Vagrant + Ansible)

```bash
# Clone the repository
git clone https://github.com/mrrobot11647-sketch/SIEM-Home-Lab-Attack_Detection_and_Alert_Monitoring.git
cd SIEM-Home-Lab-Attack_Detection_and_Alert_Monitoring

# Provision all VMs
cd infrastructure
vagrant up

# Run Ansible playbooks for configuration
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml
```

### Option 2: Manual Setup

Follow the step-by-step guide in [`docs/LAB_SETUP_GUIDE.md`](docs/LAB_SETUP_GUIDE.md).

## 🔍 MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Detection Method |
|---|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | Failed login threshold (>5 in 5 min) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | Encoded commands, suspicious cmdlets |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Persistence | Sysmon Event ID 1 + schtasks.exe |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access | Sysmon Event ID 10 targeting lsass.exe |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | UAC Bypass | Privilege Escalation | Registry modification + elevated process |

## 📊 Dashboards

- **SOC Overview** — Real-time summary of alerts, event volume, and top attack sources
- **Failed Logins** — Authentication failures across Windows (4625) and Linux (auth.log)
- **Process Creation** — Sysmon Event ID 1 tracking with parent-child process trees
- **Network Activity** — Sysmon Event ID 3 connection monitoring with GeoIP
- **MITRE ATT&CK Matrix** — Heatmap of detected techniques across the kill chain

## 📝 Incident Reports

Each simulated attack is documented with a full incident report:

| Report | Attack Type | Verdict | MITRE Technique |
|---|---|---|---|
| [IR-001](incident-reports/IR-001_RDP_Brute_Force.md) | RDP Brute Force | True Positive | T1110.001 |
| [IR-002](incident-reports/IR-002_Suspicious_PowerShell.md) | Suspicious PowerShell | True Positive | T1059.001 |
| [IR-003](incident-reports/IR-003_Privilege_Escalation.md) | UAC Bypass | True Positive | T1548.002 |
| [IR-004](incident-reports/IR-004_SSH_Brute_Force.md) | SSH Brute Force | True Positive | T1110.001 |

## 🔧 Detection Tuning

Detection rules were iteratively tuned to reduce false positives:

- **Initial FP Rate**: ~35% across all rules
- **Post-Tuning FP Rate**: ~8%
- **Key Tuning Actions**: Whitelisted system accounts, adjusted thresholds, added process ancestry checks

See [`tuning/false_positive_log.md`](tuning/false_positive_log.md) for the full tuning journal.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -m 'Add T1055 process injection detection'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project is for **educational and authorized testing purposes only**. All attack simulations are performed in an isolated lab environment. Never run these tools against systems without explicit written authorization.

---

**Built with 🔒 by [mrrobot11647-sketch](https://github.com/mrrobot11647-sketch)**
]]>
