<![CDATA[# Detection Rules — SIEM Home Lab

This directory contains custom detection rules mapped to the MITRE ATT&CK framework. Each rule is defined in YAML format following a standardized schema for documentation and reproducibility.

## Rule Schema

Each detection rule includes:

| Field | Description |
|---|---|
| `title` | Human-readable rule name |
| `id` | Unique rule identifier |
| `status` | Development status (experimental, test, production) |
| `description` | What the rule detects |
| `mitre_attack` | Mapped MITRE ATT&CK technique(s) |
| `data_sources` | Required log sources |
| `detection.query` | Splunk SPL search query |
| `detection.condition` | Trigger condition |
| `false_positives` | Known FP sources |
| `tuning_notes` | Applied tuning actions |
| `level` | Severity (low, medium, high, critical) |

## Rules Inventory

| File | Technique | Tactic | Status |
|---|---|---|---|
| `T1110_brute_force.yml` | T1110 — Brute Force | Credential Access | Production |
| `T1059.001_powershell.yml` | T1059.001 — PowerShell | Execution | Production |
| `T1053_scheduled_task.yml` | T1053.005 — Scheduled Task | Persistence | Production |
| `T1003_credential_dump.yml` | T1003.001 — LSASS Memory | Credential Access | Production |
| `T1548_privilege_escalation.yml` | T1548.002 — UAC Bypass | Privilege Escalation | Production |

## Importing Rules

Detection rules are imported into Splunk via `savedsearches.conf`. The YAML files serve as documentation and version-controlled rule definitions.

```bash
# Copy saved searches to Splunk
cp ../splunk/savedsearches.conf /opt/splunk/etc/system/local/savedsearches.conf
/opt/splunk/bin/splunk restart
```
]]>
