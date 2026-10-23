# Technical Analysis Report: SafePay Ransomware (2026-10-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-23
Version: 1.0 (DRAFT)

## Executive Summary

SafePay is an affiliate-free ransomware group active since August 2024 that has compromised at least 600 organizations across North America, South America, Europe, and Australia. On October 20, 2026, the FBI, CISA, U.S. Secret Service, Germany's Landeskriminalamt (LKA) Rheinland-Pfalz, and two UK law enforcement agencies (NCA and North West Regional Organised Crime Unit) issued joint advisory AA26-293A warning of SafePay's escalating operations against multiple critical infrastructure sectors. The group employs a double-extortion model -- stealing data before encrypting it with a ChaCha20/RSA hybrid scheme, appending the `.SafePay` extension to encrypted files, and threatening to publish stolen data on a Tor-based leak site. SafePay was the most active ransomware group in May 2026 with 70 claimed attacks (NCC Group), and is believed to share code lineage with LockBit.

Initial access vectors include stolen/brute-forced credentials, VPN exploitation (often via Mullvad VPN IP addresses), phishing, and automated exploitation of edge-device vulnerabilities (CVE-2020-3259, CVE-2023-20269, CVE-2023-27532, CVE-2024-40711, CVE-2024-40766). Post-compromise, the actors use PsExec, WinRM, RDP, Mimikatz, AnyDesk, TeamViewer, and a suite of exfiltration tools (FileZilla, RClone, WinSCP, OneDrive, Backblaze B2) before deploying the locker payload.

## Background: SafePay Ransomware Group

SafePay emerged in August 2024 as an unusual ransomware operation: it runs without an affiliate program, operating as a closed group. Security researchers at Halcyon have identified code similarities between SafePay and the LockBit ransomware family, suggesting possible reuse or rebrand lineage from LockBit, ALPHV/BlackCat, and INC Ransomware. The group targets critical infrastructure sectors indiscriminately and has claimed high-profile victims including Conduent (November 2024, resulting in an $80M class-action settlement), Ingram Micro, and Microlise. BlacKite ranked SafePay as the third most active ransomware group from January to April 2026 with particular focus on German targets. The advisory IOC observation window spans November 2024 through August 2026.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 2024 | SafePay operations first observed |
| November 2024 | Conduent ransomware attack attributed to SafePay |
| November 2024 - August 2026 | IOC observation window per CISA advisory AA26-293A |
| May 2026 | SafePay ranked most active ransomware group (70 attacks) by NCC Group |
| October 20, 2026 | CISA/FBI/USSS/LKA/NCA joint advisory AA26-293A published |

## Root Cause: Multiple Initial Access Vectors

SafePay operators gain initial access through several vectors, often in combination:

1. **Credential Exposure and Brute Force (T1110):** Stolen or exposed credentials and brute-force password attacks against VPN and RDP services. Traffic from Mullvad VPN IP addresses has been observed as a precursor to victim intrusions.

2. **VPN Exploitation (T1133, T1190):** Exploitation of vulnerabilities in edge devices and VPN appliances, including Cisco ASA/FTD (CVE-2020-3259, CVE-2023-20269), Veeam Backup & Replication (CVE-2023-27532, CVE-2024-40711), and SonicWall (CVE-2024-40766). Automated scripts scan for and exploit internet-exposed systems.

3. **Phishing (T1566):** Phished account profiles used to gain access to victim networks.

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
| T1566 | Phishing | Phished account profiles for network access |
| T1059.001 | PowerShell | ShareFinder.ps1 execution, general PowerShell use |
| T1059.003 | Windows Command Shell | Batch scripts (1 - Copy.bat), cmd execution |
| T1569.002 | Service Execution | PsExec for remote command execution |
| T1098 | Account Manipulation | Creating admin accounts, changing passwords |
| T1136 | Create Account | New admin account creation for persistence |
| T1548.002 | Bypass User Account Control | COM elevated process for privilege escalation |
| T1134.001 | Token Impersonation/Theft | Security token reuse for privilege escalation |
| T1218 | System Binary Proxy Execution | LOLBin abuse for defense evasion |
| T1027.002 | Software Packing | VM-based protection to conceal code |
| T1070.004 | File Deletion | Self-deletion after encryption |
| T1685 | Disable or Modify Tools | Disabling security software and updates |
| T1021.001 | Remote Desktop Protocol | RDP for lateral movement |
| T1021.002 | SMB/Windows Admin Shares | PsExec and SMB-based lateral movement |
| T1021.006 | Windows Remote Management | WinRM for lateral movement |
| T1560.001 | Archive via Utility | 7-Zip and WinRAR for data staging |
| T1048 | Exfiltration Over Alternative Protocol | FileZilla, RClone, WinSCP data exfiltration |
| T1567 | Exfiltration Over Web Service | OneDrive and Backblaze B2 exfiltration |
| T1486 | Data Encrypted for Impact | ChaCha20/RSA hybrid encryption with .SafePay extension |
| T1490 | Inhibit System Recovery | VSS deletion, NAS factory reset |

## Impact Assessment

SafePay has affected at least 600 organizations since August 2024, making it one of the most active ransomware groups in 2026. Victims span multiple critical infrastructure sectors across North America, South America, Europe, and Australia, with particular concentration in Germany. The double-extortion model creates dual impact: operational disruption from encryption and reputational/regulatory damage from data exposure. The Conduent attack alone resulted in an $80M class-action settlement, demonstrating the financial severity. The group's use of legitimate tools and living-off-the-land techniques makes detection challenging without behavioral analytics.

## Detection & Remediation

### Immediate Detection

```bash
# Check for .SafePay file extension on Windows endpoints
dir /s /b C:\*.SafePay 2>nul

# Check for known malicious hashes (PowerShell)
Get-FileHash -Algorithm SHA256 -Path (Get-ChildItem -Recurse -File) | Where-Object { $_.Hash -in @("921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526","327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917") }

# Check for suspicious process names
Get-Process | Where-Object { $_.Name -match "dcsync|DYRasWtb|Socks_werfault|locker" }

# Check firewall/proxy logs for C2 IP
# Search for: 88.119.167.239, 5.255.11.134, 37.10.71.188, 167.235.225.149

# Check for unusual AnyDesk/TeamViewer/ScreenConnect installations
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "AnyDesk|TeamViewer|ScreenConnect" }

# Check for recent VSS deletions (Windows Event Log)
Get-WinEvent -FilterHashtable @{LogName='Application';ID=8224} -MaxEvents 10
```

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

These detections target SafePay ransomware at advisory-specific altitude (strict), keying on concrete artifacts from CISA advisory AA26-293A: file hashes, C2 IPs, tool file names, and the `.SafePay` extension. All Sigma rules convert to Splunk and CrowdStrike LogScale; YARA compiles; Snort/Suricata rules are structurally validated only (compilers not installed). `sigma check` could not run due to a network error fetching MITRE ATT&CK data (proxy-blocked); portability was proven via `sigma convert`.

### Sigma: SafePay Ransomware Known File Hashes
Detects files matching SHA-256 hashes of SafePay ransomware components (locker.dll, soc.dll, RunPE DLL, injected PE) from CISA AA26-293A.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, proxy env); splunk convert exit 0; log_scale convert exit 0. Hash IOCs are exact-match, zero FP risk on correct hash field. Field name "Hashes" matches Sysmon EID 1/7/11/15 schema. -->
```yaml
title: SafePay Ransomware Known File Hashes
id: 8a1e3f7b-4c2d-4e9a-b8f1-6d3a5c7e9b2f
status: experimental
description: >
    Detects files matching SHA-256 hashes associated with SafePay ransomware
    components (locker.dll, soc.dll, RunPE DLL, injected PE) as reported in
    CISA advisory AA26-293A.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
    - https://securityaffairs.com/201464/cyber-crime/fbi-and-cisa-warn-of-safepay-ransomware-attacks-on-600-organizations.html
author: Actioner
date: 2026/10/23
tags:
    - attack.t1486
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains:
            - '921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae'
            - '6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a'
            - 'e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346'
            - '327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917'
            - 'a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526'
    condition: selection
falsepositives:
    - Unlikely - known malicious file hashes
level: critical
```

### Sigma: SafePay Ransomware Associated Tool Execution
Detects execution of tools specifically named in CISA AA26-293A (dcsync.exe, DYRasWtb.exe, Socks.exe, Socks_werfault.exe, ShareFinder.ps1, SharpShares.exe, nxc.exe).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence: nxc.exe and SharpShares.exe are dual-use tools that may appear in authorized pentests; other tool names (DYRasWtb.exe, Socks_werfault.exe, dcsync.exe) are more distinctive. -->
```yaml
title: SafePay Ransomware Associated Tool Execution
id: 2b4d6f8a-1e3c-5a7b-9d0f-4c8e2a6b1d3f
status: experimental
description: >
    Detects execution of tools specifically associated with SafePay ransomware
    operations including dcsync.exe, DYRasWtb.exe, Socks.exe, Socks_werfault.exe,
    ShareFinder.ps1, and SharpShares.exe as listed in CISA advisory AA26-293A.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.t1059
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_binaries:
        Image|endswith:
            - '\dcsync.exe'
            - '\DYRasWtb.exe'
            - '\Socks.exe'
            - '\Socks_werfault.exe'
            - '\SharpShares.exe'
            - '\nxc.exe'
    selection_scripts:
        CommandLine|contains:
            - 'ShareFinder.ps1'
            - 'sharefinder.ps1'
    condition: selection_binaries or selection_scripts
falsepositives:
    - Legitimate use of NetExec (nxc.exe) by penetration testers
    - SharpShares used in authorized security assessments
level: high
```

### Sigma: SafePay Ransomware File Extension
Detects file rename operations appending the `.SafePay` extension, indicating active encryption.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. ".SafePay" is a highly distinctive extension with no known legitimate use. -->
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
    - attack.t1486
logsource:
    category: file_rename
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.SafePay'
    condition: selection
falsepositives:
    - Unlikely - distinctive ransomware file extension
level: critical
```

### Sigma: SafePay C2 and Exfiltration IP Communication
Detects network connections to the highest-confidence SafePay IPs: the soc.dll C2 server and exfiltration endpoints.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence: IPs are from the advisory but may rotate; shared hosting risk for some IPs. The 5 selected IPs exclude GitHub/Google IPs that are likely shared infrastructure. -->
```yaml
title: SafePay Ransomware C2 and Exfiltration IP Communication
id: 4d6f8b0c-3a5e-7c9d-1f2b-6e0a4c8d2f7b
status: experimental
description: >
    Detects network connections to IP addresses associated with SafePay
    ransomware C2 and exfiltration infrastructure as reported in CISA
    advisory AA26-293A. Includes the soc.dll C2 server and exfiltration
    endpoints.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '88.119.167.239'
            - '5.255.11.134'
            - '37.10.71.188'
            - '167.235.225.149'
            - '77.37.49.40'
    condition: selection
falsepositives:
    - Shared hosting infrastructure may cause false positives for some IPs
level: high
```

### Sigma: Volume Shadow Copy Deletion (SafePay Context)
Detects VSS deletion activity consistent with SafePay's backup destruction behavior. Scope to SafePay investigations; this pattern is common across ransomware families.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence: VSS deletion is used by many ransomware families and occasionally by legitimate backup operations. Distinctive in combination with other SafePay IOCs. -->
```yaml
title: SafePay Ransomware Volume Shadow Copy Deletion
id: 5e7a9c1d-4b6f-8d0e-2a3c-7f1b5d9e3a8c
status: experimental
description: >
    Detects Volume Shadow Copy service stop or deletion activity consistent
    with SafePay ransomware backup destruction behavior as described in
    CISA advisory AA26-293A. SafePay halts the Volume Shadow Copy Service
    and deletes shadow copies before encryption.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
author: Actioner
date: 2026/10/23
tags:
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    selection_sc_stop:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'stop'
            - 'VSS'
    condition: selection_vssadmin or selection_wmic or selection_sc_stop
falsepositives:
    - Legitimate backup management operations
    - System administrators managing Volume Shadow Copies
level: high
```

### Suricata: SafePay C2 IP Communication
Detects connections to the SafePay soc.dll C2 server at 88.119.167[.]239.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural validation: dot-notation N/A (ip protocol), semicolons correct, msg/sid/rev present, flow set. IP is the highest-confidence C2 indicator from the advisory. -->
```suricata
alert ip $HOME_NET any -> 88.119.167.239 any (msg:"Actioner - SafePay Ransomware soc.dll C2 Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2200001; rev:1;)
```

### Suricata: SafePay Exfiltration IPs
Detects connections to SafePay exfiltration endpoints at 5.255.11[.]134 and 37.10.71[.]188.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: suricata not installed; structural validation passed. Medium confidence: exfiltration IPs may rotate or be shared hosting. -->
```suricata
alert ip $HOME_NET any -> 5.255.11.134 any (msg:"Actioner - SafePay Ransomware Data Exfiltration Endpoint"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2200002; rev:1;)

alert ip $HOME_NET any -> 37.10.71.188 any (msg:"Actioner - SafePay Ransomware Data Exfiltration Endpoint 2"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2200003; rev:1;)
```

### Snort: SafePay C2 and Exfiltration IP Communication
Detects connections to SafePay C2 (88.119.167[.]239) and exfiltration infrastructure. Equivalent coverage to the Suricata rules above for Snort deployments.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural validation: correct protocol (ip), semicolons, msg/sid/rev present, flow set. Same IP IOCs as the Suricata rules. -->
```snort
alert ip $HOME_NET any -> 88.119.167.239 any (msg:"Actioner - SafePay Ransomware soc.dll C2 Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2100001; rev:1;)

alert ip $HOME_NET any -> 5.255.11.134 any (msg:"Actioner - SafePay Ransomware Data Exfiltration Endpoint"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2100002; rev:1;)

alert ip $HOME_NET any -> 37.10.71.188 any (msg:"Actioner - SafePay Ransomware Data Exfiltration Endpoint 2"; flow:established,to_server; classtype:trojan-activity; reference:url,www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a; metadata:author Actioner, created_at 2026-10-23; sid:2100003; rev:1;)
```

### YARA: SafePay Ransomware Locker Component
Detects SafePay ransomware locker via the `.SafePay` extension string combined with characteristic ransomware strings (ransom note reference, ChaCha20, locker.dll, VSS deletion commands).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Medium confidence: string-based detection without a confirmed sample to fire against; strings are derived from advisory descriptions and file naming conventions, not extracted from a detonated sample. The .SafePay extension + locker.dll + chacha20 combination is distinctive but not sample-grounded. -->
```yara
rule SafePay_Ransomware_Locker
{
    meta:
        description = "Detects SafePay ransomware locker component via characteristic strings and PE imports"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a"
        hash = "a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526"
        hash2 = "327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext = ".SafePay" ascii wide
        $note1 = "readme_safepay" ascii wide nocase
        $note2 = "SAFEPAY" ascii wide
        $chacha1 = "chacha20" ascii wide nocase
        $tool1 = "locker.dll" ascii wide
        $mutex1 = "SafePay" ascii wide fullword
        $cmd1 = "vssadmin" ascii wide nocase
        $cmd2 = "delete shadows" ascii wide nocase
        $cmd3 = "bcdedit" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($ext and 2 of ($note*, $chacha1, $mutex1, $tool1)) or
            ($ext and 2 of ($cmd*)) or
            (3 of ($note*, $ext, $chacha1, $mutex1, $tool1))
        )
}

rule SafePay_Soc_DLL
{
    meta:
        description = "Detects SafePay soc.dll C2 component by internal name string"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a"
        hash = "921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $s1 = "soc.dll" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $s1
}
```

## Lessons Learned

1. **VPN and edge-device hygiene remains critical.** SafePay's initial access relies heavily on exploiting known vulnerabilities (some from 2020) in Cisco, Veeam, and SonicWall products. Organizations that have not patched these CVEs remain exposed years after fixes were available.

2. **Credential-based attacks dominate.** Brute force and stolen credentials remain the most common entry point. MFA on all remote access services is a baseline requirement, not an optional hardening step.

3. **Living-off-the-land detection is essential.** SafePay's heavy use of legitimate tools (PsExec, WinRM, RDP, PowerShell, 7-Zip, WinRAR) means that signature-based detection alone is insufficient. Behavioral analytics that detect abnormal use of these tools -- unexpected source accounts, unusual hours, rapid lateral movement -- are necessary.

4. **Affiliate-free groups reduce the signal.** Without affiliates operating independently, SafePay maintains tighter operational security and more consistent TTPs, making attribution easier but initial detection harder due to fewer operational mistakes.

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
- [CISA Press Release: CISA, FBI and Partners Warn Organizations of SafePay Ransomware](https://www.cisa.gov/news-events/news/cisa-fbi-and-partners-warn-organizations-safepay-ransomware-actors-targeting-multiple-critical) -- Official press release

---
*Report generated by Actioner*
