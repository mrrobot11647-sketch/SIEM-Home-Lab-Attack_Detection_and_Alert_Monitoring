<![CDATA[# Attack Simulations — SIEM Home Lab

This directory contains scripts for simulating adversary behavior to test detection rules.

## ⚠️ Disclaimer

These scripts are for **authorized testing in isolated lab environments only**. Never run against production systems or systems you do not own.

## Structure

```
attack-simulations/
├── atomic-red-team/          # Windows-based (Atomic Red Team + manual)
│   ├── run_t1110_bruteforce.ps1
│   ├── run_t1059_powershell.ps1
│   ├── run_t1053_scheduled_task.ps1
│   ├── run_t1003_credential_dump.ps1
│   └── run_t1548_privesc.ps1
└── kali-attacks/             # Kali Linux-based
    ├── ssh_bruteforce.sh
    ├── rdp_bruteforce.sh
    ├── nmap_recon.sh
    └── metasploit_exploit.rc
```

## Usage

### Atomic Red Team (Windows Target)

```powershell
# Import Atomic Red Team module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Run individual simulation
.\run_t1110_bruteforce.ps1
```

### Kali Linux Attacks

```bash
# Make executable
chmod +x kali-attacks/*.sh

# Run SSH brute force
./kali-attacks/ssh_bruteforce.sh 10.0.0.30 ubuntu
```

## Expected Outcomes

Each script is designed to generate specific telemetry. Check `docs/ATTACK_PLAYBOOK.md` for the expected log entries and Splunk verification queries.
]]>
