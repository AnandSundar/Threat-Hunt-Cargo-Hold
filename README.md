# Incident Response Report: Azuki Import/Export — 梓貿易株式会社

---

# Index

- [Executive Summary](#executive-summary)
- [Technical Analysis](#technical-analysis)
- [Affected Systems & Accounts](#affected-systems--accounts)
- [Evidence Sources & Analysis](#evidence-sources--analysis)
- [Indicators of Compromise](#indicators-of-compromise)
- [Root Cause Analysis](#root-cause-analysis)
- [Nature of the Attack](#nature-of-the-attack)
- [Impact Analysis](#impact-analysis)
- [Response & Recovery](#response--recovery)
- [Immediate Response Actions](#immediate-response-actions)
- [Eradication Measures](#eradication-measures)
- [Recovery Steps](#recovery-steps)
- [Post-Incident Actions](#post-incident-actions)
- [Annex A — Technical Timeline](#annex-a--technical-timeline)
- [Annex B — MITRE ATT&CK Mapping](#annex-b--mitre-attck-mapping)

---

# Executive Summary

## Incident ID
`INC2025-0011-022`

## Incident Severity
**Severity 1 — Critical**

## Incident Status
**Resolved**

## Threat Actor Attribution
**JADE SPIDER** (Aliases: APT-SL44, SilentLynx)
- Motivation: Financial
- Confidence: Moderate
- Last Observed: November 2025
- Typical Dwell Time: 21–45 days

## Incident Overview

A financially motivated threat actor attributed to JADE SPIDER established initial access to Azuki Import/Export's environment on November 19, 2025, via a compromised user account on device `azuki-sl`. Following a deliberate dwell period of approximately 72 hours — consistent with JADE SPIDER's known operational pattern — the adversary returned using a rotated source IP at `2025-11-22T00:27:58Z`. The actor then conducted lateral movement to the file server `azuki-fileserver01`, performed systematic discovery and credential harvesting, staged and exfiltrated sensitive data, established persistence, and attempted to destroy forensic evidence before containment.

## Key Findings

The attacker returned via IP `159.26.106.98` using the previously compromised account `kenji.sato` on the beachhead device `azuki-sl`. Using the native Windows RDP client `mstsc.exe`, the actor pivoted to `azuki-fileserver01` and accessed the administrative account `fileadmin`. A staging directory `C:\Windows\Logs\CBS\` was created and hidden using `attrib +h +s` to blend with protected OS directories.

A PowerShell payload `ex.ps1` was retrieved from C2 server `78.141.196.6` via `certutil.exe`. Network share contents were bulk-copied using `xcopy.exe` and compressed with `tar.exe`. A renamed credential dumping tool `pd.exe` (ProcDump) was used to dump LSASS memory. The archive was exfiltrated to the anonymous cloud service `file.io` using `curl.exe`. Persistence was established via a registry Run key named `FileShareSync` pointing to a masqueraded beacon script `svchost.ps1`. As a final anti-forensic measure, the PowerShell command history file `ConsoleHost_history.txt` was deleted.

## Immediate Actions Taken

- Compromised devices `azuki-sl` and `azuki-fileserver01` were isolated from the network via VLAN segmentation
- Firewall rules updated to block C2 IP `78.141.196.6`
- Accounts `kenji.sato` and `fileadmin` disabled and credentials reset
- All affected systems enrolled in host security solution for full telemetry collection
- Event logs captured and preserved in SIEM for forensic analysis

## Stakeholder Impact

### Customers
Credentials stored on the file server may have been exfiltrated, creating risk of impersonation and potential exposure of customer data. Temporary service disruption during containment may affect customer trust and carries financial implications currently being assessed.

### Employees
The accounts `kenji.sato` and `fileadmin` were directly compromised. Sensitive employee records housed on `azuki-fileserver01` are at risk of exposure, raising concerns around identity theft and targeted phishing against staff.

### Business Partners
The file server contained data pertaining to business partner relationships and proprietary logistics information. Unintended disclosure of this data may have reputational and contractual consequences for Azuki Import/Export's partnerships.

### Regulatory Bodies
Depending on the classification of the exfiltrated data, this incident may trigger notification obligations under applicable data protection regulations. Regulatory review and potential sanctions are possible outcomes.

### Shareholders
Short-term confidence impact is expected due to the nature of the breach and the potential for credential reuse across systems. Long-term impact will depend on the completeness of remediation and the organisation's transparency in response.

---

# Technical Analysis

## Affected Systems & Accounts

### Compromised Devices
| Device | Role | How Compromised |
|---|---|---|
| `azuki-sl` | Beachhead — user workstation | Initial access via `kenji.sato` (ref: Port of Entry incident) |
| `azuki-fileserver01` | File server — primary target | Lateral movement via `mstsc.exe` from `azuki-sl` |

### Compromised Accounts
| Account | Type | Usage by Attacker |
|---|---|---|
| `kenji.sato` | Domain user | Re-entry at `2025-11-22T00:27:58Z` from IP `159.26.106.98` |
| `fileadmin` | Local administrator | Used for all discovery, staging, and exfiltration activity on file server |

---

## Evidence Sources & Analysis

Investigation was conducted using Microsoft Defender for Endpoint (MDE) Advanced Hunting and Microsoft Sentinel, querying `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, and `DeviceRegistryEvents`.

### Return Connection — Initial Access
The compromised account `kenji.sato` was used from source IP `159.26.106.98` to log into `azuki-sl` at `2025-11-22T00:27:58Z`. This IP was distinct from the original November 19 compromise IP, consistent with JADE SPIDER's infrastructure rotation pattern between sessions.

**KQL Reference:**
```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-11-23))
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network")
| where not(ipv4_is_private(RemoteIP))
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
