# Technical Analysis Report: GodDamn Ransomware with PoisonX BYOVD (2026-07-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-10
Version: 1.0 (DRAFT)

## Executive Summary

GodDamn is the latest ransomware iteration from the Hyadina threat group, following Monster (March 2022) and Beast (June 2024). First observed on May 21, 2026, GodDamn represents a significant escalation in the group's defense evasion capability through its adoption of the PoisonX kernel driver -- a Microsoft-signed malicious driver that terminates security processes at the kernel level via BYOVD (Bring Your Own Vulnerable Driver) techniques.

In an analyzed attack in early June 2026, the Hyadina operators followed a five-day intrusion lifecycle: establishing remote access via AnyDesk, deploying the PoisonX driver and a user-mode defense evasion tool disguised as a Symantec product (`symantec.exe`), harvesting credentials with a comprehensive NirSoft toolkit and Mimikatz, moving laterally via PsExec and administrative shares, and finally deploying the GodDamn encryptor on June 3. The ransomware appends the `.God8Damn` extension to encrypted files. The group targets U.S. organizations while avoiding CIS countries. PoisonX has also been adopted by The Gentlemen RaaS operation, broadening the threat surface of this driver.

## Background: Hyadina Threat Group and Ransomware Lineage

Hyadina is a ransomware-as-a-service (RaaS) operation tracked by Broadcom's Symantec Threat Hunter Team since 2022. The developer behind the operation has produced three ransomware families over four years:

- **Monster** (March 2022): Delphi-based ransomware targeting 32-bit Windows systems. Used NirSoft tools and Mimikatz in observed attacks. Avoided CIS region targets.
- **Beast** (June 2024): Rebrand of Monster with code improvements, added Linux and VMware ESXi support, enhanced encryption performance, and multilingual support including Chinese.
- **GodDamn** (May 2026): Latest iteration with significant code overlap with Beast, but a major escalation in defense evasion through adoption of the PoisonX malicious kernel driver.

The PoisonX driver was first observed in early 2026 in campaigns targeting CrowdStrike Falcon. It was reverse-engineered by Xcitium ThreatLabs, who documented its process-kill primitive via IOCTL `0x22E010` and its use of `ZwOpenProcess`/`ZwTerminateProcess` to bypass Protected Process Light (PPL) protections. The driver carries a valid Microsoft Hardware Compatibility Publisher signature, achieving 0/71 detections on VirusTotal at discovery.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | GodDamn ransomware first observed in the wild |
| 2026-05-29 | Initial attacker access established; AnyDesk deployed to `%USERPROFILE%\Music\anydesk.exe` |
| 2026-05-30 | Defense evasion tools deployed: `symantec.exe` (user-mode evasion) and `g11.sys` (PoisonX kernel driver). NirSoft credential harvesting toolkit staged in `%USERPROFILE%\Music\mimik\pass\` |
| 2026-06-01 | Lateral movement begins via PsExec; administrative shares mounted with stolen credentials |
| 2026-06-02 | AnyDesk deployed to 10+ hosts with unattended access configuration; registered as auto-start Windows services |
| 2026-06-03 | GodDamn ransomware deployed on separate network segment; files encrypted with `.God8Damn` extension |

## Root Cause: Initial Access Vector

The initial access vector for this intrusion remains unknown. The earliest confirmed activity on May 29, 2026 shows AnyDesk already placed in a non-standard directory (`%USERPROFILE%\Music\`), suggesting prior compromise via an undetermined method. The four-day dwell period between initial access and ransomware deployment is consistent with a staged operation involving data exfiltration and reconnaissance before triggering encryption.

## Technical Analysis of the Malicious Payload

### 1. Defense Evasion: PoisonX Kernel Driver (g11.sys)

The PoisonX driver is a Microsoft-signed malicious kernel driver deployed via BYOVD technique. It is dropped into the system driver store at `%SystemRoot%\System32\drivers\g11.sys` by the `symantec.exe` dropper.

**Driver Technical Details:**
- **File**: `g11.sys`
- **SHA-256**: `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d`
- **Signing**: Microsoft Windows Hardware Compatibility Publisher
- **IOCTL**: `0x22E010` (maps to `procKiller` function)
- **Device symbolic link**: `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- **Kernel functions**: `ZwOpenProcess`, `ZwTerminateProcess`, `RtlCopyMemory`

**Kill mechanism**: The driver accepts a target PID as a decimal ASCII string via the IOCTL interface, converts it with `atoi()`, opens the process with `ZwOpenProcess` (which bypasses PPL restrictions from kernel mode), and terminates it with `ZwTerminateProcess`. Returns "ok" on success.

### 2. User-Mode Defense Evasion: symantec.exe

A defense evasion tool disguised as a legitimate Symantec security product. Staged in `%USERPROFILE%\Music\symantec.exe`.

- **SHA-256**: `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8`
- **Function**: Drops PoisonX kernel driver into the system driver store and orchestrates its loading
- **Additional action**: PowerShell command executed to disable Windows Defender real-time monitoring:
  ```
  powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
  ```

### 3. Credential Access: NirSoft Toolkit and Mimikatz

A comprehensive credential harvesting toolkit was staged at `%USERPROFILE%\Music\mimik\pass\` containing 14 tools:

| Tool | Filename | SHA-256 |
|------|----------|---------|
| Mimikatz | mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` |
| WebBrowserPassView | webbrowserpassview64.exe | `8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167` |
| ChromePass | chromepass.exe | `5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404` |
| PasswordFox | passwordfox64.exe | `faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395` |
| MessengerPass | mspass.exe | `7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26` |
| VNCPassView | vncpassview.exe | `816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019` |
| MailPassView | mailpv.exe | `5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd` |
| SniffPass | sniffpass64.exe | `c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620` |
| OperaPassView | operapassview.exe | `8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8` |
| CredentialsFileView | credentialsfileview64.exe | `35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c` |
| WirelessKeyView | wirelesskeyview64.exe | `19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d` |
| ExtPassword | extpassword.exe | `ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046` |
| PSTPassword | pstpassword.exe | `5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6` |
| NetPass | netpass64.exe | `17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180` |

### 4. Lateral Movement and Persistence

**PsExec lateral movement:**
- **SHA-256**: `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944`
- Process chain: `psexesvc.exe` -> `services.exe` -> `wininit.exe`
- Administrative shares mounted: `net use \\192.168.0[.]25\c$ /user:[REDACTED] [REDACTED]`

**AnyDesk persistence:**
- **SHA-256**: `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220`
- Configured for unattended access: `ad.security.interactive_access=2`
- Registered as two auto-start Windows services:
  ```
  sc create AnyDeskService binPath= "<drive>\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk Service"
  sc create AnyDesk_D binPath= "<drive>\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk D-Drive Service"
  ```
- PowerShell installer variant: `anydesk.exe --install "CSIDL_PROGRAM_FILESX86\anydesk" --start-with-win --silent --accept-3rd-party-licenses`

**Network discovery:**
- Netscan tool (SHA-256: `9fae3f15900e13ec3860a109555ecd33ca43d38907c63438c50a2d6d91bfee1d`)
- Host enumeration via `ipconfig` and `tasklist`

### 5. Ransomware Deployment

- **Binary**: `encrypter-windows-gui-x86.exe`
- **SHA-256**: `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69`
- **Encryption extension**: `.God8Damn` (or victim organization name used as extension)
- **Contact methods**: Email and qTox encrypted messaging
- Process termination followed by machine reboot prior to deployment

### 6. Anti-Forensics / Evasion Techniques

- Kernel-level process termination bypassing PPL protections via PoisonX driver
- User-mode API hook removal by PoisonX
- Masquerading as legitimate Symantec product (`symantec.exe`)
- Microsoft-signed driver to bypass driver signature enforcement
- Use of legitimate remote access tools (AnyDesk) to blend with authorized traffic
- Non-standard staging directories (`Music`, `Downloads`) to avoid detection by tools monitoring typical malware paths

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | %SystemRoot%\System32\drivers\g11.sys | `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` | PoisonX malicious kernel driver |
| Windows | %USERPROFILE%\Music\symantec.exe | `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8` | User-mode defense evasion dropper |
| Windows | %USERPROFILE%\Downloads\encrypter-windows-gui-x86.exe | `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69` | GodDamn ransomware binary |
| Windows | %USERPROFILE%\Music\encrypter-windows-gui-x86.exe | `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69` | GodDamn ransomware binary (alt. location) |
| Windows | %USERPROFILE%\Music\anydesk.exe | `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220` | AnyDesk remote access tool |
| Windows | %USERPROFILE%\Music\mimik\pass\mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` | Mimikatz credential dumper |
| Windows | (various) | `9fae3f15900e13ec3860a109555ecd33ca43d38907c63438c50a2d6d91bfee1d` | Netscan network mapping tool |
| Windows | (various) | `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944` | PsExec lateral movement tool |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `15.235.230[.]188` | Hyadina/GodDamn infrastructure |
| IP | `185.229.191[.]39` | Hyadina/GodDamn infrastructure |
| IP | `141.95.145[.]210` | Hyadina/GodDamn infrastructure |
| IP | `162.19.171[.]150` | Hyadina/GodDamn infrastructure |

### Behavioral

- **PoisonX driver load**: Loading of `g11.sys` into `%SystemRoot%\System32\drivers\` via `symantec.exe`
- **AnyDesk persistence pattern**: Two auto-start services created with custom `--conf-dir` and `--data-dir` pointing to `d:\ad_data`
- **Credential toolkit staging**: 14+ NirSoft tools staged in `%USERPROFILE%\Music\mimik\pass\`
- **PsExec lateral movement**: Process chain `psexesvc.exe` -> `services.exe` -> `wininit.exe` across multiple hosts
- **Defender disablement**: PowerShell `Set-MpPreference -DisableRealtimeMonitoring $true`
- **Administrative share access**: `net use \\<target>\c$ /user:<user> <pass>` for lateral movement

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1219 | Remote Access Software | AnyDesk deployed for persistent remote access with unattended configuration |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense evasion tool named `symantec.exe` to impersonate legitimate Symantec product |
| T1014 | Rootkit | PoisonX kernel driver loaded to operate at Ring 0 for defense impairment |
| T1562.001 | Impair Defenses: Disable or Modify Tools | PoisonX driver terminates security processes; PowerShell disables Defender real-time monitoring |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz deployment for credential extraction |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | NirSoft toolkit (ChromePass, WebBrowserPassView, PasswordFox, OperaPassView) for browser credential theft |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Mounting administrative C$ shares with stolen credentials for lateral movement |
| T1570 | Lateral Tool Transfer | PsExec used to distribute tools and ransomware across the network |
| T1543.003 | Create or Modify System Process: Windows Service | AnyDesk registered as two auto-start Windows services for persistence |
| T1486 | Data Encrypted for Impact | GodDamn ransomware encrypts files with `.God8Damn` extension |
| T1082 | System Information Discovery | `ipconfig` and `tasklist` executed for host reconnaissance |
| T1018 | Remote System Discovery | Netscan tool deployed for network mapping |

## Impact Assessment

GodDamn ransomware represents the continued evolution of a four-year-old RaaS operation. The adoption of the PoisonX kernel driver marks a significant escalation: by operating at Ring 0 with a valid Microsoft signature, the driver can terminate even Protected Process Light (PPL) security tools -- including CrowdStrike Falcon. The driver's adoption by multiple ransomware groups (Hyadina and The Gentlemen) suggests it is being commoditized across the RaaS ecosystem. The targeting focus on U.S. organizations with CIS-country exclusion indicates a likely Eastern European operator. The five-day dwell period and methodical credential harvesting suggest possible double extortion with data exfiltration before encryption.

## Detection & Remediation

### Immediate Detection

Check for PoisonX driver presence:
```powershell
# Check for g11.sys driver
Get-ChildItem -Path "$env:SystemRoot\System32\drivers\g11.sys" -ErrorAction SilentlyContinue

# Check for PoisonX device object
Get-WmiObject Win32_SystemDriver | Where-Object {$_.PathName -like '*g11*'}

# Check for suspicious AnyDesk services
Get-Service | Where-Object {$_.Name -match 'AnyDesk'}

# Check for symantec.exe in user profile directories
Get-ChildItem -Path "$env:USERPROFILE\Music\symantec.exe", "$env:USERPROFILE\Downloads\symantec.exe" -ErrorAction SilentlyContinue

# Check for NirSoft toolkit staging
Get-ChildItem -Path "$env:USERPROFILE\Music\mimik\pass\" -ErrorAction SilentlyContinue

# Check for known hashes (PoisonX driver)
Get-FileHash "$env:SystemRoot\System32\drivers\g11.sys" -Algorithm SHA256 -ErrorAction SilentlyContinue | Where-Object {$_.Hash -eq '2D91A78E739891C9854C254F5B2A6B84C0E167DFA253466CBCCD2CDD1C20145D'}
```

Check network connections:
```powershell
# Check for connections to known infrastructure IPs
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -in @('15.235.230.188','185.229.191.39','141.95.145.210','162.19.171.150')}
```

### Remediation

1. **Immediate containment**: Isolate affected systems from the network. Block the four known infrastructure IPs at the perimeter firewall.
2. **Driver removal**: Boot into Safe Mode. Remove `g11.sys` from `%SystemRoot%\System32\drivers\`. Verify no related services remain registered.
3. **AnyDesk cleanup**: Remove unauthorized AnyDesk installations. Delete the `AnyDeskService` and `AnyDesk_D` services. Remove `d:\ad_data\` configuration directories.
4. **Credential rotation**: Assume all credentials on compromised hosts are stolen. Perform enterprise-wide password resets. Rotate service account credentials. Revoke and reissue Kerberos tickets.
5. **Review driver signing**: Implement WDAC (Windows Defender Application Control) or equivalent driver blocklist policies to prevent loading of the PoisonX driver hash.
6. **Restore from backups**: Encrypted files (`.God8Damn` extension) should be restored from offline/immutable backups.

### Long-Term Hardening

- **WDAC/HVCI**: Enable Hypervisor-protected Code Integrity and Windows Defender Application Control to block unsigned or known-malicious kernel drivers.
- **Microsoft Vulnerable Driver Blocklist**: Ensure the Microsoft driver blocklist is enabled and updated to include the PoisonX driver hash.
- **Credential hygiene**: Deploy LAPS for local admin passwords. Implement tiered administration. Monitor for NirSoft tool execution.
- **Remote access governance**: Maintain an allowlist of authorized remote access tools. Alert on AnyDesk installations outside sanctioned channels.
- **Network segmentation**: Segment critical assets to limit lateral movement via administrative shares.

## Detection Rules

These detections cover the GodDamn/Hyadina intrusion chain: PoisonX driver loading, ransomware execution, defense evasion masquerading, AnyDesk persistence, NirSoft toolkit deployment, and network infrastructure. All Sigma rules convert to both Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline before production deployment.

### Sigma: PoisonX Malicious Kernel Driver Load (g11.sys)

Detects loading of the PoisonX kernel driver by image path or SHA-256 hash.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag — proxy blocks MITRE API); splunk 0, log_scale 0. driver_load category → Sysmon EID 6. ImageLoaded endswith and Hashes contains are standard fields. Hash is the published Broadcom IOC. No encoding issues (Windows paths, hex hashes). -->
```yaml
title: PoisonX Malicious Kernel Driver Load (g11.sys)
id: 8a3b7c1e-4d2f-4e9a-b5c6-d7e8f9012345
status: experimental
description: >
    Detects the loading of the PoisonX malicious kernel driver (g11.sys) used by the Hyadina
    threat group (GodDamn ransomware) to terminate security processes at the kernel level via
    BYOVD. The driver carries a Microsoft Hardware Compatibility Publisher signature.
references:
    - https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html
    - https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses
    - https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/
author: Actioner
date: 2026/07/10
tags:
    - attack.t1014
    - attack.t1562.001
logsource:
    category: driver_load
    product: windows
detection:
    selection_name:
        ImageLoaded|endswith: '\g11.sys'
    selection_hash:
        Hashes|contains: '2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d'
    condition: selection_name or selection_hash
falsepositives:
    - Unknown legitimate software using g11.sys driver name
level: critical
```

### Sigma: GodDamn Ransomware Binary Execution

Detects execution of the GodDamn ransomware binary by distinctive filename or SHA-256 hash.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag); splunk 0, log_scale 0. process_creation category. Filename "encrypter-windows-gui-x86.exe" is highly distinctive — unlikely benign collision. Hash from Broadcom bulletin. -->
```yaml
title: GodDamn Ransomware Binary Execution
id: 2f4a8b1c-6d3e-4f7a-9c5b-e1d2f3a4b567
status: experimental
description: >
    Detects execution of the GodDamn ransomware binary (encrypter-windows-gui-x86.exe)
    associated with the Hyadina threat group. The binary encrypts files and appends
    the .God8Damn extension.
references:
    - https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html
    - https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses
author: Actioner
date: 2026/07/10
tags:
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        Image|endswith: '\encrypter-windows-gui-x86.exe'
    selection_hash:
        Hashes|contains: 'e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69'
    condition: selection_name or selection_hash
falsepositives:
    - Extremely unlikely given the distinctive filename
level: critical
```

### Sigma: Hyadina Defense Evasion Tool Masquerading as Symantec Product

Detects the Hyadina defense evasion dropper (`symantec.exe`) by hash, or by filename when launched from atypical user profile directories.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag); splunk 0, log_scale 0. Hash-based selection is high-confidence anchor; path-based selection requires both filename AND suspicious directory (AND logic in selection_path) to reduce FP on legitimate Symantec executables. -->
```yaml
title: Hyadina Defense Evasion Tool Masquerading as Symantec Product
id: 9c5d7e2f-1a3b-4c6d-8e9f-0a1b2c3d4e56
status: experimental
description: >
    Detects execution of the Hyadina defense evasion dropper disguised as symantec.exe,
    which drops the PoisonX kernel driver (g11.sys) into the system driver store. In the
    observed attack this binary was staged in the user Music folder.
references:
    - https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html
    - https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses
author: Actioner
date: 2026/07/10
tags:
    - attack.t1036.005
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains: 'b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8'
    selection_path:
        Image|endswith: '\symantec.exe'
        Image|contains:
            - '\Music\'
            - '\Downloads\'
            - '\Temp\'
            - '\AppData\'
    condition: selection_hash or selection_path
falsepositives:
    - Legitimate Symantec executables would not reside in user profile Music or Downloads folders
level: high
```

### Sigma: Suspicious AnyDesk Service Installation with Custom Data Directory

Detects creation of AnyDesk services with custom `--conf-dir` and `--data-dir` flags, a persistence pattern specific to the Hyadina campaign.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag); splunk 0, log_scale 0. CommandLine contains|all produces AND logic. Enterprise AnyDesk may use custom dirs — FP possible in managed deployments; tune per environment. -->
```yaml
title: Suspicious AnyDesk Service Installation with Custom Data Directory
id: 3e7f9a1b-2c4d-5e6f-a8b9-c0d1e2f3a456
status: experimental
description: >
    Detects creation of AnyDesk services with custom configuration and data directories
    (--conf-dir and --data-dir flags), a persistence technique used by the Hyadina threat
    group during GodDamn ransomware deployments to establish unattended remote access.
references:
    - https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html
    - https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses
author: Actioner
date: 2026/07/10
tags:
    - attack.t1543.003
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'anydesk'
            - '--service'
            - '--conf-dir'
            - '--data-dir'
    condition: selection
falsepositives:
    - Enterprise AnyDesk deployments using custom data directories for centralized management
level: high
```

### Sigma: NirSoft Credential Harvesting Toolkit Execution

Detects execution of NirSoft credential harvesting tools by campaign-specific hashes or by known tool filenames from the Hyadina toolkit.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag); splunk 0, log_scale 0. Hash-based selection uses 14 campaign-specific hashes from Broadcom bulletin. Filename-based selection covers the renamed/original NirSoft tool names observed. Individual NirSoft tools are legitimate — combined deployment is suspicious. FP: IT administrators using NirSoft for password recovery. -->
```yaml
title: NirSoft Credential Harvesting Toolkit Execution
id: 4f8a0b2c-3d5e-6f7a-b9c0-d1e2f3a4b567
status: experimental
description: >
    Detects execution of NirSoft credential harvesting tools used by the Hyadina threat group
    for credential access during GodDamn ransomware operations. Matches known tool hashes
    from the observed campaign and common NirSoft tool filenames.
references:
    - https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html
    - https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses
author: Actioner
date: 2026/07/10
tags:
    - attack.t1555.003
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_hashes:
        Hashes|contains:
            - '31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc'
            - '8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167'
            - '5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404'
            - 'faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395'
            - '7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26'
            - '816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019'
            - '5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd'
            - 'c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620'
            - '8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8'
            - '35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c'
            - '19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d'
            - 'ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046'
            - '5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6'
            - '17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180'
    selection_names:
        Image|endswith:
            - '\mimik.exe'
            - '\chromepass.exe'
            - '\webbrowserpassview64.exe'
            - '\passwordfox64.exe'
            - '\mspass.exe'
            - '\vncpassview.exe'
            - '\mailpv.exe'
            - '\sniffpass64.exe'
            - '\operapassview.exe'
            - '\credentialsfileview64.exe'
            - '\wirelesskeyview64.exe'
            - '\extpassword.exe'
            - '\pstpassword.exe'
            - '\netpass64.exe'
    condition: selection_hashes or selection_names
falsepositives:
    - Legitimate use of individual NirSoft tools by system administrators for password recovery
level: high
```

### Snort: Connection to GodDamn/Hyadina Infrastructure IPs

Detects outbound connections to known Hyadina infrastructure IP addresses.
**Status:** compile ⚠️ uncompiled (Snort not installed; structural check only) · confidence: medium
<!-- audit: Snort 3 not installed in this environment. Structural check: alert ip header valid, vars correct, msg/sid/rev/classtype present, one rule per IP. IPs will rotate — time-boxed value. -->
```snort
alert ip $HOME_NET any -> 15.235.230.188 any (msg:"Actioner - Connection to GodDamn/Hyadina Infrastructure IP 1"; classtype:trojan-activity; reference:url,www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses; metadata:author Actioner, created 2026-07-10; sid:2100001; rev:1;)
alert ip $HOME_NET any -> 185.229.191.39 any (msg:"Actioner - Connection to GodDamn/Hyadina Infrastructure IP 2"; classtype:trojan-activity; reference:url,www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses; metadata:author Actioner, created 2026-07-10; sid:2100002; rev:1;)
alert ip $HOME_NET any -> 141.95.145.210 any (msg:"Actioner - Connection to GodDamn/Hyadina Infrastructure IP 3"; classtype:trojan-activity; reference:url,www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses; metadata:author Actioner, created 2026-07-10; sid:2100003; rev:1;)
alert ip $HOME_NET any -> 162.19.171.150 any (msg:"Actioner - Connection to GodDamn/Hyadina Infrastructure IP 4"; classtype:trojan-activity; reference:url,www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses; metadata:author Actioner, created 2026-07-10; sid:2100004; rev:1;)
```

### Suricata: Connection to GodDamn/Hyadina Infrastructure IPs

Detects outbound connections to known Hyadina infrastructure IP addresses using Suricata IP group syntax.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. IP group in header is valid Suricata syntax. IPs sourced from Broadcom security bulletin. Time-boxed value — IPs rotate; re-evaluate monthly. -->
```suricata
alert ip $HOME_NET any -> [15.235.230.188,185.229.191.39,141.95.145.210,162.19.171.150] any (msg:"Actioner - Connection to Known GodDamn/Hyadina Ransomware Infrastructure"; classtype:trojan-activity; reference:url,www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses; metadata:author Actioner, created_at 2026-07-10; sid:2200001; rev:1;)
```

### YARA: PoisonX BYOVD Kernel Driver

Detects the PoisonX kernel driver binary by its unique device GUID, kernel API imports, and device path strings.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Condition requires PE header + guid + both ZwOpenProcess/ZwTerminateProcess + device path — conjunction reduces FP. GUID {F8284233-48F4-4680-ADDD-F8284233} is from Xcitium reverse engineering report (published). No sample available for fire test — confidence capped at medium. filesize < 500KB scopes to reasonable driver size. -->
```yara
import "pe"

rule Malware_PoisonX_BYOVD_Driver
{
    meta:
        description = "Detects the PoisonX malicious kernel driver used for BYOVD attacks to terminate security processes at the kernel level"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $guid = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii
        $devpath1 = "\\Device\\" ascii wide
        $devpath2 = "\\DosDevices\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $guid and
        $api1 and $api2 and
        1 of ($devpath*)
}
```

### YARA: GodDamn Ransomware Binary

Detects the GodDamn ransomware binary based on distinctive extension strings and naming patterns from the Hyadina threat group.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Strings sourced from Broadcom bulletin and multiple secondary reports. Condition requires PE + size < 10MB + conjunction of distinctive strings (.God8Damn + name, or name+ransom+qTox, or ext+qTox). No sample for fire test — medium confidence. "qTox" may appear in other ransomware — combined with extension/name reduces FP. -->
```yara
rule Ransomware_GodDamn_Hyadina
{
    meta:
        description = "Detects the GodDamn ransomware binary from the Hyadina threat group based on distinctive strings and file characteristics"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $name1 = "encrypter-windows-gui-x86" ascii wide
        $name2 = "GodDamn" ascii wide
        $note1 = "qTox" ascii wide
        $ransom1 = "God8Damn" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($ext1 and 1 of ($name*)) or
            (2 of ($name*, $ransom1) and $note1) or
            ($ext1 and $note1)
        )
}
```

## Lessons Learned

1. **BYOVD remains a critical blind spot.** The PoisonX driver's Microsoft Hardware Compatibility signature allowed it to bypass all driver signature enforcement mechanisms. Organizations that rely solely on driver signature verification without additional WDAC/HVCI policies remain vulnerable. The commoditization of PoisonX across multiple RaaS groups (Hyadina and The Gentlemen) indicates this attack vector is being industrialized.

2. **Defense evasion sophistication is escalating.** Hyadina's progression from Gmer rootkit scanners and Defender Control (2025) to a kernel-level signed driver (2026) shows rapid capability maturation. The masquerading of the dropper as a Symantec product adds social engineering at the file system level.

3. **NirSoft tools as a credential-theft multiplier.** The deployment of 14 NirSoft password recovery tools alongside Mimikatz demonstrates a "vacuum everything" approach to credential access. Organizations should monitor for NirSoft tool execution as a high-fidelity indicator of hands-on-keyboard intrusions, particularly when multiple tools appear on the same host.

4. **AnyDesk as dual-purpose persistence.** The registration of AnyDesk as multiple auto-start services with custom data directories, combined with unattended access configuration (`interactive_access=2`), creates a resilient persistence mechanism that blends with legitimate remote access traffic.

## Sources

- [SecurityAffairs - GodDamn Ransomware Uses PoisonX to Blind Security Software](https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html) — initial reporting and attack overview
- [Broadcom/Symantec - GodDamn Ransomware Protection Bulletin](https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses) — primary vendor analysis with IOCs and SHA-256 hashes
- [SECURITY.COM - GodDamn Ransomware: Latest Beast Rebrand](https://www.security.com/blog-post/goddamn-ransomware-beast-rebrand) — comprehensive technical analysis with full IOC listing, file paths, and attack timeline
- [The Hacker News - GodDamn Ransomware Uses PoisonX Driver to Disable Endpoint Defenses](https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html) — secondary reporting with MITRE ATT&CK context
- [Dark Reading - GodDamn Ransomware Uses BYOVD to Smite US Companies](https://www.darkreading.com/cyberattacks-data-breaches/goddamn-ransomware-byovd-smite-companies) — industry analysis and broader threat context
- [Xcitium ThreatLabs - Reverse Engineering PoisonX BYOVD Driver](https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/) — PoisonX driver reverse engineering with IOCTL codes, kernel functions, and device path details
- [GBHackers - GodDamn Ransomware Attack Uses PsExec and NirSoft Toolkit](https://gbhackers.com/goddamn-ransomware-attack/) — lateral movement and credential theft details
- [CybersecurityNews - GodDamn Ransomware Rebrands From Beast](https://cybersecuritynews.com/goddamn-ransomware-rebrands-from-beast/) — historical lineage and rebranding context
- [Microsoft Security Blog - The Gentlemen Ransomware](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/) — related threat group also using PoisonX driver

---
*Report generated by Actioner*
