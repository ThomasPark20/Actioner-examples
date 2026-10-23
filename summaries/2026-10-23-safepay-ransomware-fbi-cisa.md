# Technical Analysis Report: SafePay Ransomware (2026-10-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-23
Version: 1.1

## Executive Summary

SafePay is an affiliate-free ransomware group active since August 2024 that has compromised at least 600 organizations across North America, South America, Europe, and Australia. On October 20, 2026, the FBI, CISA, U.S. Secret Service, Germany's Landeskriminalamt (LKA) Rheinland-Pfalz, and two UK law enforcement agencies (NCA and North West Regional Organised Crime Unit) issued joint advisory AA26-293A warning of SafePay's escalating operations against multiple critical infrastructure sectors. The group employs a double-extortion model -- stealing data before encrypting it with a ChaCha20/RSA hybrid scheme, appending the `.SafePay` extension to encrypted files, and threatening to publish stolen data on a Tor-based leak site. Secondary coverage describes it as one of the most active ransomware groups of 2026 and speculates (unverified) about lineage or rebrand links to LockBit, ALPHV/BlackCat and INC Ransomware.

Initial access vectors include stolen/brute-forced credentials, VPN exploitation (often via Mullvad VPN IP addresses), phishing, and automated exploitation of edge-device vulnerabilities (CVE-2020-3259, CVE-2023-20269, CVE-2023-27532, CVE-2024-40711, CVE-2024-40766). Post-compromise, the actors use PsExec, WinRM, RDP, Mimikatz, AnyDesk, TeamViewer, and a suite of exfiltration tools (FileZilla, RClone, WinSCP, OneDrive, Backblaze B2) before deploying the locker payload.

## Background: SafePay Ransomware Group

SafePay emerged in August 2024 as an unusual ransomware operation: it runs without an affiliate program, operating as a closed group. Some secondary reporting speculates SafePay may be a rebrand of or share lineage with LockBit, ALPHV/BlackCat and INC Ransomware; the advisory does not state this and it should be treated as unverified. The group targets multiple critical infrastructure sectors, with reported concentration on German victims (secondary reporting, not confirmed by the advisory). The advisory IOC observation window spans November 2024 through August 2026.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 2024 | SafePay operations first observed |
| November 2024 - August 2026 | IOC observation window per CISA advisory AA26-293A |
| October 20, 2026 | CISA/FBI/USSS/LKA/NCA joint advisory AA26-293A published |

## Root Cause: Multiple Initial Access Vectors

SafePay operators gain initial access through several vectors, often in combination:

1. **Credential Exposure and Brute Force (T1110):** Stolen or exposed credentials and brute-force password attacks against VPN and RDP services. Traffic from Mullvad VPN IP addresses has been observed as a precursor to victim intrusions.

2. **VPN Exploitation (T1133, T1190):** Exploitation of vulnerabilities in edge devices and VPN appliances, including Cisco ASA/FTD (CVE-2020-3259, CVE-2023-20269), Veeam Backup & Replication (CVE-2023-27532, CVE-2024-40711), and SonicWall (CVE-2024-40766). Automated scripts scan for and exploit internet-exposed systems.

3. **Phishing (T1566.002 spearphishing link or T1566.001 attachment; advisory does not specify):** Phished account profiles used to gain access to victim networks (advisory cites phishing without sub-technique).

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Foothold

SafePay actors establish initial foothold through compromised VPN accounts and exploited edge devices. They install remote access tools (AnyDesk, TeamViewer, ScreenConnect) for persistence and to facilitate payload delivery. New admin accounts may be created, and existing account passwords changed to lock out legitimate users and hinder incident response.

### 2. Discovery, Credential Access, and Lateral Movement

Once inside, the operators use:

- **ShareFinder.ps1 / SharpShares.exe** -- PowerShell and .NET tools for discovering network shares and valuable data
- **NetExec (nxc.exe)** -- Network enumeration and lateral movement
- **netscan.exe** -- Network scanning (with netscan.lic, netscan.xml configs)
- **dcsync.exe** -- Active Directory credential extraction (DCSync attack)
- **Mimikatz** -- Credential harvesting
- **PsExec, WinRM, RDP** -- Lateral movement across the network
- **nltest.exe** -- Domain trust enumeration

### 3. Data Staging and Exfiltration

Before encryption, data is archived and exfiltrated using:

- **7-Zip and WinRAR** -- Archive creation, including RAR segmentation for large datasets
- **FileZilla, RClone, WinSCP** -- File transfer protocols for exfiltration
- **Backblaze B2 CLI (b2.exe)** -- Cloud storage exfiltration
- **OneDrive** -- Cloud-based exfiltration via web service (T1567)
- **libsmb2.dll** -- SMB library for data access

### 4. Ransomware Deployment and Encryption

The ransomware payload uses a hybrid encryption scheme:

- **ChaCha20** stream cipher for file encryption
- **RSA** public-key cryptography for key exchange
- Full or partial encryption depending on file type and size
- Encrypted files receive the `.SafePay` extension
- Key file names: `locker.dll`, `DYRasWtb.exe`, `1.exe`, `wa_3rd_party_host_*.exe`
- **soc.dll** acts as a C2 component communicating with `88.119.167[.]239`

### 5. Anti-Forensics / Evasion Techniques

- **Volume Shadow Copy deletion** -- Halts the VSS service and deletes shadow copies
- **NAS factory reset** -- Resets network-attached backup devices to factory settings
- **Security software disabling** -- Disables security tools and updates before lateral movement (T1685)
- **Software packing** -- VM-based protection and software packing to conceal code (T1027.002)
- **UAC bypass** -- COM elevated process for privilege escalation (T1548.002)
- **Token impersonation** -- Security token theft for privilege escalation (T1134.001)
- **Self-deletion** -- Ransomware deletes itself after encryption (T1070.004)
- **LOLBin usage** -- System Binary Proxy Execution for evasion (T1218)
- **Masquerading** -- Files named `Socks_werfault.exe`, `svchost.exe` (outside System32), CCleaner binaries

### 6. Double Extortion

- Ransom note placed on desktop or root directory directing victims to a Tor `.onion` chat portal
- Victim ID used as login credential for the portal
- Ransom demand: a subset of company revenue in cryptocurrency
- Phone calls from group representatives to pressure victims
- Stolen data published on leak site if ransom is not paid

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | File Name | Hash (SHA-256) | Description |
|----------|-----------|----------------|-------------|
| Windows | soc.dll | 921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae | C2 component |
| Windows | RunPE DLL | 6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a | RunPE bundled DLL |
| Windows | Injected PE | e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346 | Injected PE payload |
| Windows | locker.dll | 327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917 | Locker DLL (PE32) |
| Windows | locker.dll | a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526 | Locker DLL variant |
| Windows | SharpShares.exe | bbdd3620a67aedec4b9a68b2c9cc880b6631215e129816aea19902a6f4bc6f41 | Share discovery tool |

| Platform | File Name | Hash (SHA-1) | Description |
|----------|-----------|--------------|-------------|
| Windows | 1.exe | 07353237350c35d6dc2c8f143b649cd07c71f62b | Ransomware binary |
| Windows | Locker.dll | b498a2683640c983bb069fa2ea9e67cef4a3797d | Locker DLL |
| Windows | locker.dll | bbfed53e3bb1f306f4da97d995cf4ae5b73ad081 | Locker DLL variant |
| Windows | nxc | d711a5af5aed48a3b36b98f4fcf52809aebef7a2 | NetExec tool |

### Additional Suspicious Files (from Advisory Table 3)

| File Name | Description |
|-----------|-------------|
| 1 - Copy.bat | Batch script (staging/deployment) |
| dcsync.exe | AD credential extraction |
| DYRasWtb.exe | Ransomware component |
| locker.dll | Encryption payload |
| netscan.exe, netscan.lic, netscan.xml | Network scanning toolkit |
| netscanNEW.zip | Compressed scanner package |
| Socks.exe | Proxy/tunneling tool |
| Socks_werfault.exe | Disguised proxy tool (masquerading as werfault) |
| wa_3rd_party_host_*.exe | Ransomware loader (wildcard) |
| subs.txt, domains.txt, oui.txt, ping.txt | Reconnaissance data files |
| portable.dat, scan.xml | Scanning configuration/output |
| libsmb2.dll | SMB library |
| Libwa*.dll | Supporting DLLs (wildcard) |

### Suspicious Hostnames

| Hostname | Context |
|----------|---------|
| WIN-SBOE3CPNAL | Associated with SafePay operations |
| WIN-3IUUOFVTQAR | Associated with SafePay operations |
| WIN-DK18BI83M0S | Associated with SafePay operations |
| WIN-I1HRRJHCEIV | Associated with SafePay operations |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 88.119.167[.]239 | soc.dll command and control |
| IP | 5.255.11[.]134 | Data exfiltration |
| IP | 37.10.71[.]188 | Data exfiltration |
| IP | 167.235.225[.]149 | Client login panels |
| IP | 77.37.49[.]40 | Victim intrusion |
| IP | 104.26.2[.]223 | Victim intrusion |
| IP | 140.82.114[.]4 | Victim intrusion |
| IP | 185.199.108[.]133 | Victim intrusion |
| IP | 173.194.194[.]94 | Hosts victim data |

**Note:** The advisory states IPs should be investigated in context before blocking. Some IPs (e.g., 140.82.114[.]4 is a GitHub IP, 173.194.194[.]94 is a Google IP) may represent shared infrastructure. The C2 IP (88.119.167[.]239) and exfiltration IPs (5.255.11[.]134, 37.10.71[.]188) are highest-confidence network IOCs.

### CVEs Exploited

| CVE | Affected Product | CWE | Usage |
|-----|-----------------|-----|-------|
| CVE-2020-3259 | Cisco ASA/FTD | CWE-200 | Edge device exploitation for initial access |
| CVE-2023-20269 | Cisco ASA/FTD | CWE-288 | Edge device exploitation for initial access |
| CVE-2023-27532 | Veeam Backup & Replication | CWE-306 | Automated exploitation of internet-exposed systems |
| CVE-2024-40711 | Veeam Backup & Replication | CWE-502 | Unauthenticated RCE for initial access |
| CVE-2024-40766 | SonicWall | CWE-284 | Automated exploitation of internet-exposed systems |

### Behavioral

- Execution of ShareFinder.ps1 or SharpShares.exe for network share discovery
- Deployment of AnyDesk, TeamViewer, or ScreenConnect in environments where they are not standard
- Unexpected use of PsExec, WinRM, or RDP from unusual source accounts
- Archive creation (7-Zip, WinRAR) followed by outbound file transfers via FileZilla, RClone, or cloud storage
- Volume Shadow Copy deletion followed by file encryption activity
- New local/domain admin account creation followed by security software disabling
- Connections originating from Mullvad VPN IP address ranges
- Files renamed with `.SafePay` extension in rapid succession

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1133 | External Remote Services | VPN access to victim networks |
| T1190 | Exploit Public-Facing Application | Exploitation of Cisco, Veeam, SonicWall CVEs |
| T1110 | Brute Force | Password brute-forcing against VPN and RDP |
| T1566 | Phishing | Phished account profiles for network access (advisory-level; sub-technique unspecified) |
| T1059.001 | PowerShell | ShareFinder.ps1 execution, general PowerShell use |
| T1059.003 | Windows Command Shell | Batch scripts (1 - Copy.bat), cmd execution |
| T1569.002 | Service Execution | PsExec for remote command execution |
| T1098 | Account Manipulation | Creating admin accounts, changing passwords |
| T1136 | Create Account | New admin account creation (advisory cites T1136 without sub-technique; likely .001/.002) |
| T1548.002 | Bypass User Account Control | COM elevated process for privilege escalation |
| T1134.001 | Token Impersonation/Theft | Security token reuse for privilege escalation |
| T1218 | System Binary Proxy Execution | LOLBin abuse for defense evasion |
| T1027.002 | Software Packing | VM-based protection to conceal code |
| T1070.004 | File Deletion | Self-deletion after encryption |
| T1685 | Disable or Modify Tools | Disabling security software and updates (listed in advisory, ATT&CK v20) |
| T1021.001 | Remote Desktop Protocol | RDP for lateral movement |
| T1021.002 | SMB/Windows Admin Shares | PsExec and SMB-based lateral movement |
| T1021.006 | Windows Remote Management | WinRM for lateral movement |
| T1560.001 | Archive via Utility | 7-Zip and WinRAR for data staging |
| T1048 | Exfiltration Over Alternative Protocol | FileZilla, RClone, WinSCP data exfiltration |
| T1567 | Exfiltration Over Web Service | OneDrive and Backblaze B2 exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Analyst-added: Backblaze B2 / OneDrive |
| T1486 | Data Encrypted for Impact | ChaCha20/RSA hybrid encryption with .SafePay extension |
| T1490 | Inhibit System Recovery | VSS deletion, NAS factory reset |
| T1078 | Valid Accounts | Analyst-added: stolen/brute-forced credentials used over VPN/RDP |
| T1219 | Remote Access Software | Analyst-added: AnyDesk, TeamViewer, ScreenConnect |
| T1003.001 | LSASS Memory | Analyst-added: Mimikatz |
| T1003.006 | DCSync | Analyst-added: dcsync.exe |
| T1135 | Network Share Discovery | Analyst-added: ShareFinder.ps1, SharpShares.exe |
| T1482 | Domain Trust Discovery | Analyst-added: nltest.exe |
| T1090 | Proxy | Analyst-added: Socks.exe / Socks_werfault.exe |
| T1036.005 | Match Legitimate Name or Location | Analyst-added: Socks_werfault.exe, svchost.exe outside System32, wa_3rd_party_host_*.exe |

## Impact Assessment

SafePay has affected at least 600 organizations since August 2024, making it one of the most active ransomware groups in 2026. Victims span multiple critical infrastructure sectors across North America, South America, Europe, and Australia, with particular concentration in Germany. The double-extortion model creates dual impact: operational disruption from encryption and reputational/regulatory damage from data exposure. The group's use of legitimate tools and living-off-the-land techniques makes detection challenging without behavioral analytics.

## Detection & Remediation

### Immediate Detection

> Advisory-derived and unvalidated against live SafePay activity; scope paths to your environment and expect to tune.

Windows cmd:

```bat
:: Encrypted files (scope to data volumes as needed)
dir /s /b D:\*.SafePay 2>nul
```

PowerShell (scope the hash scan to likely drop paths; a full-disk scan is slow):

```powershell
# Known SHA-256 hashes (locker.dll variants, soc.dll) in user-writable paths
$h = @("921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526","327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917")
Get-ChildItem -Path C:\Users,C:\ProgramData,C:\Windows\Temp -Recurse -File -Include *.dll,*.exe -ErrorAction SilentlyContinue |
  Get-FileHash -Algorithm SHA256 | Where-Object { $_.Hash -in $h }

# Named tooling from the advisory (omit generic names)
Get-Process | Where-Object { $_.Name -match "^(dcsync|DYRasWtb|Socks_werfault|wa_3rd_party_host_.*)$" }

# Remote access tools present (registry uninstall keys; avoids slow Win32_Product)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -match "AnyDesk|TeamViewer|ScreenConnect" } | Select-Object DisplayName,Publisher
```

Network: search firewall/proxy/DNS logs for 88.119.167[.]239 (C2), 5.255.11[.]134 and 37.10.71[.]188 (exfiltration). The advisory IOC window is Nov 2024 - Aug 2026, so treat hits as retrospective leads.

### Remediation

1. **Containment:** Isolate affected systems immediately. Block C2 IPs (88.119.167[.]239, 5.255.11[.]134, 37.10.71[.]188) at the network perimeter.
2. **Credential Reset:** Force password resets for all accounts, prioritizing admin and service accounts. Revoke all VPN tokens and reissue.
3. **Patch Exploitation Vectors:** Apply patches for CVE-2020-3259, CVE-2023-20269, CVE-2023-27532, CVE-2024-40711, CVE-2024-40766 immediately.
4. **Remove Unauthorized Tools:** Uninstall any unauthorized instances of AnyDesk, TeamViewer, ScreenConnect.
5. **Restore from Clean Backups:** Use offline/air-gapped backups for restoration; verify backup integrity before restoring.
6. **Forensic Investigation:** Analyze authentication logs for Mullvad VPN IPs, new account creation, and lateral movement patterns.

### Long-Term Hardening

- Implement MFA on all VPN and remote access services
- Deploy network segmentation to limit lateral movement
- Enable and monitor PowerShell script block logging
- Maintain offline/air-gapped backups with regular integrity verification
- Implement application whitelisting to prevent unauthorized tool execution
- Monitor for Mullvad VPN IP connections to internal resources
- Deploy EDR with behavioral detection for credential dumping and shadow copy deletion
- Review and restrict PsExec, WinRM, and RDP access to only authorized administrators

## Detection Rules

Advisory-specific (strict) detections keyed on AA26-293A artifacts: file hashes (SHA-1 and SHA-256), named tools and masquerade patterns, the `.SafePay` extension, and the three highest-confidence IPs. The advisory carries no distinctive SafePay command lines, so generic VSS-deletion logic was deliberately not included. Sigma rules were validated with `sigma convert --without-pipeline` to Splunk and CrowdStrike LogScale (exit 0); `sigma check` was blocked by the proxy, so Sigma status below is "convert-only". Hash rules assume Sysmon-style `Hashes` fields (EID 1 / EID 7); no pipeline was applied, so field names are Sigma-native. Snort/Suricata compilers are not installed.

### Sigma: SafePay Ransomware Known Executable Hashes
Matches process creation hashes for 1.exe, nxc and SharpShares.exe (SHA-1/SHA-256). Requires Sysmon EID 1 Hashes with the relevant algorithms enabled.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: sigma check blocked (proxy). Hash IOCs exact-match; nxc/SharpShares hashes are dual-use tools. t1486 tag dropped as these are not ransomware binaries. revision: moved file_event->process_creation (Sysmon EID 11 has no Hashes). -->
```yaml
title: SafePay Ransomware Known Executable Hashes
id: 8a1e3f7b-4c2d-4e9a-b8f1-6d3a5c7e9b2f
status: experimental
description: >
    Detects process creation where the image hash matches an executable listed in
    CISA advisory AA26-293A (1.exe, nxc, SharpShares.exe). Requires the Sysmon
    Hashes field (EID 1) or equivalent EDR mapping with SHA1/SHA256 enabled.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
            - '07353237350c35d6dc2c8f143b649cd07c71f62b'  # 1.exe (SHA-1)
            - 'd711a5af5aed48a3b36b98f4fcf52809aebef7a2'  # nxc (SHA-1, NetExec; dual-use)
            - 'bbdd3620a67aedec4b9a68b2c9cc880b6631215e129816aea19902a6f4bc6f41'  # SharpShares.exe (SHA-256)
    condition: selection
falsepositives:
    - NetExec and SharpShares hashes may match authorized penetration-test tooling
level: high
```

### Sigma: SafePay Ransomware Known DLL Hashes
Matches image loads of soc.dll, RunPE DLL, locker.dll variants and the injected PE by hash. Requires Sysmon EID 7 with hashing.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: injected PE file type is not stated in the advisory and may never appear as an image load. Locker/ransomware may run as EXE; the process_creation rule does not cover those hashes. -->
```yaml
title: SafePay Ransomware Known DLL Hashes
id: 9b2f4a8c-5d3e-4f0b-c9a2-7e4b6d8f0c3a
status: experimental
description: >
    Detects image loads where the DLL hash matches a SafePay component listed in
    CISA advisory AA26-293A (soc.dll, RunPE DLL, locker.dll variants, injected PE).
    Requires Sysmon EID 7 with hashing enabled or equivalent EDR mapping.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Hashes|contains:
            - '921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae'  # soc.dll
            - '6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a'  # RunPE DLL
            - 'e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346'  # injected PE (file type unconfirmed)
            - '327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917'  # locker.dll
            - 'a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526'  # locker.dll variant
            - 'b498a2683640c983bb069fa2ea9e67cef4a3797d'  # Locker.dll (SHA-1)
            - 'bbfed53e3bb1f306f4da97d995cf4ae5b73ad081'  # locker.dll variant (SHA-1)
    condition: selection
falsepositives:
    - Unlikely
level: high
```

### Sigma: SafePay Ransomware Named Tool and Loader Execution
Flags execution of dcsync.exe, DYRasWtb.exe, Socks_werfault.exe and the wa_3rd_party_host_*.exe loader pattern named in the advisory.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: names are advisory-listed but trivially renamable. Socks.exe dropped (generic FP). OriginalFileName not added: none known for these. -->
```yaml
title: SafePay Ransomware Named Tool and Loader Execution
id: 2b4d6f8a-1e3c-5a7b-9d0f-4c8e2a6b1d3f
status: experimental
description: >
    Detects execution of file names called out in CISA advisory AA26-293A as SafePay
    tooling or masquerading: dcsync.exe, DYRasWtb.exe, Socks_werfault.exe (fake
    werfault) and the wa_3rd_party_host_*.exe loader pattern.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.credential-access
    - attack.t1003.006
    - attack.defense-evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_names:
        Image|endswith:
            - '\dcsync.exe'
            - '\DYRasWtb.exe'
            - '\Socks_werfault.exe'
    selection_loader:
        Image|contains: '\wa_3rd_party_host_'
        Image|endswith: '.exe'
    condition: selection_names or selection_loader
falsepositives:
    - A legitimate tool that happens to be named dcsync.exe
level: high
```

### Sigma: SafePay Ransomware Associated Dual-Use Tools
Lower-confidence hunt for nxc.exe, SharpShares.exe and ShareFinder.ps1; expect pentest overlap.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: split from named-tool rule per critic; OriginalFileName only for SharpShares. -->
```yaml
title: SafePay Ransomware Associated Dual-Use Tools
id: 6f8a0c2e-7b9d-4d1f-a3c5-8e0b2d4f6a9c
status: experimental
description: >
    Lower-confidence detection of dual-use tools named in CISA advisory AA26-293A
    (NetExec nxc.exe, SharpShares.exe, ShareFinder.ps1). Triage against
    authorized pentest activity; these are not SafePay-exclusive.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.discovery
    - attack.t1135
logsource:
    category: process_creation
    product: windows
detection:
    selection_binaries:
        - Image|endswith:
              - '\nxc.exe'
              - '\SharpShares.exe'
        - OriginalFileName: 'SharpShares.exe'
    selection_script:
        CommandLine|contains: 'ShareFinder.ps1'
    condition: selection_binaries or selection_script
falsepositives:
    - Authorized penetration testing and red team exercises
    - Administrators auditing share exposure
level: medium
```

### Sigma: SafePay Ransomware Libwa DLL Load
Detects Libwa*.dll loads, the supporting DLLs of the wa_3rd_party_host loader.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: wildcard names from advisory Table 3; Libwa prefix could collide with unrelated software. -->
```yaml
title: SafePay Ransomware Libwa DLL Load
id: 1c3e5a7b-8d0f-4e2a-b4d6-9f1c3e5a7b8d
status: experimental
description: >
    Detects loading of a DLL named Libwa*.dll, listed in CISA advisory AA26-293A as
    a supporting DLL of the SafePay wa_3rd_party_host loader.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.defense-evasion
    - attack.t1036.005
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: '\Libwa'
        ImageLoaded|endswith: '.dll'
    condition: selection
falsepositives:
    - Unrelated software shipping a DLL with a Libwa prefix
level: medium
```

### Sigma: SafePay Ransomware File Extension
Detects file creation with the `.SafePay` extension (active encryption).
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: high
<!-- audit: revision: file_rename category replaced with file_event (Sysmon EID 11). Operators can change extension in other builds. -->
```yaml
title: SafePay Ransomware File Extension
id: 3c5e7a9b-2f4d-6b8c-0e1a-5d9f3b7c4e6a
status: experimental
description: >
    Detects creation of files with the .SafePay extension, indicating active
    SafePay ransomware encryption as described in CISA advisory AA26-293A.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.SafePay'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

### Sigma: SafePay Ransomware C2 and Exfiltration IP Communication
Detects outbound connections to the soc.dll C2 IP and two exfiltration IPs. Retrospective hunting only; IOCs date Nov 2024 - Aug 2026.
**Status:** compile ⚠️ convert-only (splunk/log_scale exit 0) · confidence: medium
<!-- audit: revision: removed 77.37.49.40 (advisory labels it only 'victim intrusion', direction unstated) and 167.235.225.149 ('client login panels'); fixed unsupported t1071.001 tag. -->
```yaml
title: SafePay Ransomware C2 and Exfiltration IP Communication
id: 4d6f8b0c-3a5e-7c9d-1f2b-6e0a4c8d2f7b
status: experimental
description: >
    Detects outbound connections to the soc.dll C2 IP and the two exfiltration IPs
    listed in CISA advisory AA26-293A. IOCs were observed Nov 2024 - Aug 2026 and
    may have been reassigned; use for retrospective hunting.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.command-and-control
    - attack.exfiltration
    - attack.t1048
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '88.119.167.239'
            - '5.255.11.134'
            - '37.10.71.188'
    condition: selection
falsepositives:
    - Reassigned or shared hosting addresses since the advisory observation window
level: medium
```

### Suricata: SafePay C2 and Exfiltration IPs
Alerts on established TCP sessions to the C2 IP 88.119.167[.]239 and exfiltration IPs 5.255.11[.]134 and 37.10.71[.]188.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: suricata not installed. revision: alert ip->alert tcp, SIDs moved to local 1000001-1000003. IP-only matching; IOCs may be reassigned. -->
```suricata
alert tcp $HOME_NET any -> 88.119.167.239 any (msg:"Actioner - SafePay soc.dll C2 IP (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026_10_23; sid:1000001; rev:2;)
alert tcp $HOME_NET any -> 5.255.11.134 any (msg:"Actioner - SafePay exfiltration IP (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026_10_23; sid:1000002; rev:2;)
alert tcp $HOME_NET any -> 37.10.71.188 any (msg:"Actioner - SafePay exfiltration IP 2 (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026_10_23; sid:1000003; rev:2;)
```

### Snort: SafePay C2 and Exfiltration IPs
Snort equivalent of the Suricata rules above.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: snort not installed. revision: alert ip->alert tcp, SIDs local 1000101-1000103 (previous 2100xxx was GPL range). -->
```snort
alert tcp $HOME_NET any -> 88.119.167.239 any (msg:"Actioner - SafePay soc.dll C2 IP (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner; sid:1000101; rev:2;)
alert tcp $HOME_NET any -> 5.255.11.134 any (msg:"Actioner - SafePay exfiltration IP (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner; sid:1000102; rev:2;)
alert tcp $HOME_NET any -> 37.10.71.188 any (msg:"Actioner - SafePay exfiltration IP 2 (AA26-293A)"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner; sid:1000103; rev:2;)
```

### YARA: SafePay Ransomware Locker
Requires a PE containing `.SafePay`, the ChaCha constant `expand 32-byte k`, and `locker.dll` or `DYRasWtb`. Strings come from advisory text, not a sample.
**Status:** compile ✅ compiles (yarac exit 0) · confidence: low
<!-- audit: revision: removed unverified hash meta lines and the false 'PE imports' claim, removed VSS/bcdedit strings and $mutex1 overlap. Untested against any sample; may miss builds that drop the plain-text extension string. -->
```yara
rule SafePay_Ransomware_Locker
{
    meta:
        description = "SafePay locker: .SafePay extension plus ChaCha constant plus advisory-named locker component"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a"
        confidence = "low - strings derived from advisory text, not from a detonated sample"

    strings:
        // Advisory: encrypted files receive the .SafePay extension
        $ext = ".SafePay" ascii wide
        // Advisory: ChaCha20 used for file encryption (standard ChaCha sigma constant)
        $chacha = "expand 32-byte k" ascii
        // Advisory Table 3: component file names
        $name1 = "locker.dll" ascii wide nocase
        $name2 = "DYRasWtb" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ext and $chacha and 1 of ($name*)
}
```

<!-- revision: dropped Sigma VSS deletion rule (generic TTP, violates advisory-specific altitude); dropped YARA SafePay_Soc_DLL (fullword "soc.dll" too broad; hash covered by Sigma DLL hash rule). -->

## Lessons Learned

1. **VPN and edge-device hygiene remains critical.** SafePay's initial access relies heavily on exploiting known vulnerabilities (some from 2020) in Cisco, Veeam, and SonicWall products. Organizations that have not patched these CVEs remain exposed years after fixes were available.

2. **Credential-based attacks dominate.** Brute force and stolen credentials remain the most common entry point. MFA on all remote access services is a baseline requirement, not an optional hardening step.

3. **Living-off-the-land detection is essential.** SafePay's heavy use of legitimate tools (PsExec, WinRM, RDP, PowerShell, 7-Zip, WinRAR) means that signature-based detection alone is insufficient. Behavioral analytics that detect abnormal use of these tools -- unexpected source accounts, unusual hours, rapid lateral movement -- are necessary.

4. **A closed (affiliate-free) model may mean more consistent TTPs.** This is an inference, not an advisory finding: a single operator group could reuse the same tooling and file names, which favors specific IOC-based hunting in the near term.

5. **Backup integrity and isolation are non-negotiable.** SafePay's tactic of resetting NAS devices to factory settings and deleting Volume Shadow Copies demonstrates that network-accessible backups are a single point of failure. Air-gapped and immutable backup strategies are essential.

## Sources

- [CISA Advisory AA26-293A: #StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a) -- Primary joint advisory from FBI, CISA, USSS, LKA Rheinland-Pfalz, and UK law enforcement with IOCs, TTPs, and mitigations
- [CISA AA26-293A PDF](https://www.cisa.gov/sites/default/files/2026-10/aa26-293a-stopransomware-safepay-ransomware-508c_0.pdf) -- Full advisory document in PDF format
- [CISA AA26-293A STIX XML](https://www.cisa.gov/sites/default/files/2026-10/AA26-293A-stix.xml) -- Machine-readable IOC feed (STIX XML)
- [CISA AA26-293A STIX JSON](https://www.cisa.gov/sites/default/files/2026-10/AA26-293A-stix.json) -- Machine-readable IOC feed (STIX JSON)
- [Security Affairs: FBI and CISA Warn of SafePay Ransomware Attacks on 600 Organizations](https://securityaffairs.com/201464/cyber-crime/fbi-and-cisa-warn-of-safepay-ransomware-attacks-on-600-organizations.html) -- Secondary reporting with summary of advisory
- [Infosecurity Magazine: SafePay Has Compromised 600 Critical Infrastructure Victims Worldwide, CISA Warns](https://www.infosecurity-magazine.com/news/safepay-compromised-critical/) -- Reporting on scope, attribution to LockBit lineage, and notable victims
- [The Record: FBI Says SafePay Ransomware Gang Among Most Active, 600 Victims](https://therecord.media/fbi-says-safepay-ransomware-gang-among-most-active-600-victims) -- Additional context on CVEs and scale
- [CybersecurityNews: SafePay Ransomware Has Affected 600+ Organizations](https://cybersecuritynews.com/safepay-ransomware/) -- Detailed IOC tables and hash listings from advisory
- [Cybersecurity Dive: FBI, CISA warn of SafePay ransomware threat](https://www.cybersecuritydive.com/news/fbi-cisa-warn-safepay-ransomware-threat-critical-infrastructure/833589/) -- Secondary reporting on scale and lineage speculation
- [BleepingComputer: CISA and FBI: SafePay ransomware has hit over 600 critical infrastructure organizations](https://www.bleepingcomputer.com/news/security/cisa-and-fbi-safepay-ransomware-has-hit-over-600-critical-infrastructure-organizations/) -- Secondary reporting
- [CISA Press Release: CISA, FBI and Partners Warn Organizations of SafePay Ransomware](https://www.cisa.gov/news-events/news/cisa-fbi-and-partners-warn-organizations-safepay-ransomware-actors-targeting-multiple-critical) -- Official press release

---
*Report generated by Actioner*
