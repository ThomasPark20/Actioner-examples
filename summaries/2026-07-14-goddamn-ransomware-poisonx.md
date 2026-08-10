# Technical Analysis Report: GodDamn Ransomware + PoisonX Driver BYOVD (2026-07-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-14
Version: 1.1 FINAL

## Executive Summary

**GodDamn** is a new ransomware family first observed in the wild on May 21, 2026, assessed as a rebrand of the **Beast** ransomware (itself a successor to **Monster**, a Delphi-based ransomware first seen in March 2022). The operation is attributed to the threat actor tracked as **Hyadina**, operating a ransomware-as-a-service (RaaS) model. GodDamn employs the **PoisonX** kernel driver (G11.sys) in a Bring Your Own Vulnerable Driver (BYOVD) attack to disable endpoint security software before encrypting files with the `.God8Damn` extension (or, in some cases, using the victim organization's name as the extension).

The attack chain involves AnyDesk for persistent remote access, a 14-tool NirSoft-based credential harvesting kit, PsExec for lateral movement, and a user-mode defense evasion tool masquerading as `symantec.exe` that works in tandem with the PoisonX kernel driver to blind endpoint defenses. Symantec's Threat Hunter Team analyzed an incident from early June 2026 with a four-day dwell time before ransomware deployment.

**Prior Coverage Note:** The PoisonX driver (G11.sys) and its use by the GentleKiller EDR-killer framework were previously documented in [GentleKiller EDR Framework Analysis (2026-06-23)](/home/user/Actioner-examples/summaries/2026-06-23-gentlekiller-edr-framework.md). The existing YARA rule `Malware_PoisonX_BYOVD_Driver` and Sigma rule `GentleKiller BYOVD Vulnerable Driver Load` already cover PoisonX driver loading. This report focuses on **GodDamn-specific** detection: the ransomware binary, encryption behavior, credential toolkit, and persistence patterns unique to Hyadina's GodDamn operation.

## Background: Hyadina RaaS Operation

Hyadina is a ransomware-as-a-service operation with a four-year history of rebranding:

| Period | Name | Key Changes |
|--------|------|-------------|
| March 2022 | Monster | Delphi-based, 32-bit Windows, avoided CIS targets |
| June 2024 | Beast | Expanded to Linux and VMware ESXi, multi-language support |
| May 2026 | GodDamn | Added PoisonX BYOVD for EDR disablement, GUI-based encryptor |

GodDamn shares significant code overlap with Beast, confirming the lineage. The operation works with affiliates who deploy the toolset using their own initial access methods.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | GodDamn ransomware first documented in the wild |
| 2026-05-29 | Initial AnyDesk deployment observed on victim network |
| 2026-05-30 | Defense evasion tools (symantec.exe) and PoisonX driver (G11.sys) staged |
| 2026-06-01 | Lateral movement begins via PsExec |
| 2026-06-02 | AnyDesk deployed across 10+ hosts; credential harvesting toolkit executed |
| 2026-06-03 | Ransomware encryption phase triggered; AnyDesk processes terminated, machines rebooted |
| 2026-07-09 | Symantec publishes detailed technical analysis |
| 2026-07-10 | The Hacker News and multiple outlets publish coverage |

## Root Cause: Initial Access

In the analyzed incident, the specific initial access vector was not disclosed. The threat actors used **AnyDesk** for remote access, registering it as an auto-start Windows service with non-standard configuration directories and interactive access consent suppressed. The Hyadina operation is known to work with affiliates who bring their own initial access.

## Technical Analysis of the Malicious Payload

### 1. Remote Access & Persistence (AnyDesk)

AnyDesk was deployed to `csidl_profile\music\anydesk.exe` (an atypical path) and configured with suppressed interactive access consent:

```
powershell -Command "New-Item -ItemType Directory -Force -Path 'CSIDL_DRIVE_FIXED\ad_data'; Set-Content -Path 'CSIDL_DRIVE_FIXED\ad_data\system.conf' -Value 'ad.security.interactive_access=2'"
```

Two Windows services were created for redundant persistence:

```
sc create AnyDeskService binPath= "CSIDL_DRIVE_FIXED\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto
```

Service names: `AnyDeskService` and `AnyDesk_D`, both pointing to custom `d:\ad_data` directory.

### 2. Credential Harvesting (NirSoft Toolkit)

A 14-tool NirSoft-based credential harvesting suite was deployed to `csidl_profile\music\mimik\pass\`, covering:

| Tool | Target |
|------|--------|
| WebBrowserPassView | Browser passwords (generic) |
| ChromePass | Chrome passwords |
| PasswordFox | Firefox passwords |
| OperaPassView | Opera passwords |
| CredentialsFileView | Windows Credential Manager |
| MailPassView | Email client passwords |
| MessengerPass | Instant messenger passwords |
| VNCPassView | VNC passwords |
| WirelessKeyView | Wi-Fi profiles |
| SniffPass | Network traffic credentials |
| ExtPassword | Extended password recovery |
| PSTPassword | Outlook PST passwords |
| NetPass | Cached network credentials |
| Mimikatz (mimik.exe) | Windows credential dumping |

Additionally, **Netscan.exe** was used for network mapping.

### 3. Defense Evasion (PoisonX + User-Mode Tool)

Defense evasion employs two components working in tandem:

1. **PoisonX kernel driver** (G11.sys): Microsoft-signed BYOVD driver installed to `csidl_system\drivers\g11.sys`. Terminates security processes at kernel level via IOCTL `0x22E010` to device `\\.\{F8284233-48F4-4680-ADDD-F8284233}`. (Covered by existing GentleKiller detection rules.)

2. **User-mode defense evasion tool** (symantec.exe): Deployed to `csidl_profile\music\symantec.exe`, masquerading as a Symantec product. Works alongside PoisonX to remove user-mode API hooks and fully disable endpoint visibility.

Windows Defender was also explicitly disabled:

```
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### 4. Lateral Movement (PsExec)

PsExec was used to move across the network, deploying AnyDesk and the ransomware to additional hosts. Process lineage: `psexesvc.exe` -> `services.exe` -> `wininit.exe`. Administrative shares were mounted using stolen credentials:

```
net use \\192.168.0[.]25\c$ /user:[credentials]
```

### 5. Ransomware Encryption

The GodDamn encryptor binary (`encrypter-windows-gui-x86.exe`) is a GUI-based Windows executable. Before encryption:

- Running AnyDesk processes were terminated: `taskkill /f /im anydesk.exe`
- A brief wait period occurred
- Machines were rebooted: `shutdown -r -t 0`

Encrypted files receive the `.God8Damn` extension, though in the investigated incident, the victim organization's name was used as the file extension instead.

### 6. Anti-Forensics / Evasion Techniques

- **Masquerading:** Defense tool named `symantec.exe` to impersonate legitimate Symantec software
- **Atypical staging paths:** Tools placed in `Music` and `Downloads` folders rather than standard installation directories
- **BYOVD:** Microsoft-signed PoisonX driver bypasses driver signature enforcement
- **Redundant persistence:** Two AnyDesk service registrations for resilience
- **Consent suppression:** AnyDesk configured with `interactive_access=2` to avoid alerting users

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### File System

#### GodDamn Ransomware & Defense Tools

| Filename | SHA-256 | Description |
|----------|---------|-------------|
| encrypter-windows-gui-x86.exe | `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69` | GodDamn ransomware encryptor |
| G11.sys | `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` | PoisonX BYOVD kernel driver |
| symantec.exe | `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8` | User-mode defense evasion tool |
| PsExec | `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944` | Lateral movement tool |

#### NirSoft Credential Harvesting Toolkit

| Filename | SHA-256 | Description |
|----------|---------|-------------|
| netpass64.exe | `17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180` | NetPass (cached network credentials) |
| WirelessKeyView | `19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d` | Wi-Fi profile passwords |
| mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` | Mimikatz credential dumper |
| CredentialsFileView | `35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c` | Windows Credential Manager |
| anydesk.exe | `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220` | AnyDesk remote access tool |
| MailPassView | `5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd` | Email client passwords |
| ChromePass | `5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404` | Chrome passwords |
| PstPassword | `5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6` | Outlook PST passwords |
| MessengerPass | `7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26` | Instant messenger passwords |
| VNCPassView | `816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019` | VNC passwords |
| OperaPassView | `8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8` | Opera passwords |
| WebBrowserPassView | `8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167` | Browser passwords (generic) |
| Netscan.exe | `9fae3f15900e13ec3860a109555ecd33ca43d38907c63438c50a2d6d91bfee1d` | Network mapping tool |
| SniffPass | `c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620` | Network traffic credentials |
| ExtPassword | `ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046` | Extended password recovery |
| PasswordFox | `faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395` | Firefox passwords |

#### File Paths (CSIDL notation)

| Path | Description |
|------|-------------|
| `csidl_profile\music\anydesk.exe` | AnyDesk deployment location |
| `csidl_profile\music\symantec.exe` | Defense evasion tool |
| `csidl_profile\music\mimik\pass\` | NirSoft toolkit staging directory |
| `csidl_system\drivers\g11.sys` | PoisonX driver installation path |
| `csidl_profile\downloads\encrypter-windows-gui-x86.exe` | Ransomware binary |
| `csidl_profile\music\encrypter-windows-gui-x86.exe` | Ransomware binary (alternate) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `15.235.230[.]188` | AnyDesk relay server contacted during attack |
| IP | `185.229.191[.]39` | AnyDesk relay server contacted during attack |
| IP | `141.95.145[.]210` | AnyDesk relay server contacted during attack |
| IP | `162.19.171[.]150` | AnyDesk relay server contacted during attack |

**Note:** These IPs are AnyDesk relay infrastructure and may serve legitimate AnyDesk users. They are included for forensic correlation in the context of the full attack chain, not as standalone blocklist candidates.

### Behavioral

- File rename operations appending `.God8Damn` extension (or victim organization name)
- AnyDesk installed to `Music` folder with custom config directory (`d:\ad_data`)
- AnyDesk service creation with `--conf-dir` and `--data-dir` pointing to non-standard paths
- AnyDesk configured with `ad.security.interactive_access=2` (consent suppression)
- 14+ NirSoft credential tools executed from `mimik\pass\` directory
- PsExec-driven lateral movement with `psexesvc.exe` process lineage
- Windows Defender disabled via `Set-MpPreference -DisableRealtimeMonitoring $true`
- Pre-encryption reboot cycle: `taskkill /f /im anydesk.exe` followed by `shutdown -r -t 0`
- PoisonX IOCTL `0x22E010` sent to device `\\.\{F8284233-48F4-4680-ADDD-F8284233}`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1219 | Remote Access Software | AnyDesk deployed for persistent remote access with custom configuration |
| T1543.003 | Create or Modify System Process: Windows Service | AnyDesk registered as auto-start Windows services (AnyDeskService, AnyDesk_D) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | PoisonX driver + symantec.exe used to terminate security processes; Windows Defender disabled via PowerShell |
| T1068 | Exploitation for Privilege Escalation | BYOVD exploitation of Microsoft-signed PoisonX driver for kernel-level process termination |
| T1036 | Masquerading | Defense tool named symantec.exe; AnyDesk in Music folder |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | NirSoft toolkit targeting Chrome, Firefox, Opera browser credential stores |
| T1003 | OS Credential Dumping | Mimikatz (mimik.exe) for Windows credential dumping |
| T1555 | Credentials from Password Stores | CredentialsFileView, VNCPassView, MailPassView, WirelessKeyView targeting diverse credential stores |
| T1570 | Lateral Tool Transfer | PsExec used to deploy tools across the network via administrative shares |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Administrative shares mounted via `net use \\host\c$` with stolen credentials |
| T1486 | Data Encrypted for Impact | GodDamn encryptor encrypts files with .God8Damn extension |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used for AnyDesk configuration and Defender disablement |

## Impact Assessment

GodDamn represents a continuation of the Hyadina operation's evolution toward more sophisticated defense evasion. The integration of PoisonX BYOVD into the ransomware deployment chain -- leveraging a Microsoft-signed driver to disable endpoint security at kernel level -- significantly reduces the likelihood that traditional EDR solutions will detect or prevent the encryption phase.

The four-day dwell time observed in the analyzed incident (May 29 to June 3) indicates a methodical, hands-on-keyboard operation with distinct phases: access establishment, credential harvesting, lateral movement, and finally ransomware deployment. The breadth of the credential harvesting toolkit (14 NirSoft tools + Mimikatz) suggests thorough credential collection for potential data exfiltration or future access.

Organizations running endpoint security products targeted by PoisonX are at risk of having their defenses silently disabled before ransomware deployment.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for GodDamn ransomware binary
Get-ChildItem -Path C:\ -Recurse -Include encrypter-windows-gui-x86.exe -ErrorAction SilentlyContinue

# Check for God8Damn encrypted files
Get-ChildItem -Path C:\ -Recurse -Filter "*.God8Damn" -ErrorAction SilentlyContinue | Select-Object -First 10

# Check for defense evasion tool in Music/Downloads folders
Get-ChildItem -Path "$env:USERPROFILE\Music","$env:USERPROFILE\Downloads" -Include symantec.exe,anydesk.exe -ErrorAction SilentlyContinue

# Check for NirSoft toolkit staging directory
Test-Path "$env:USERPROFILE\Music\mimik\pass"

# Check for suspicious AnyDesk services with custom config
Get-Service | Where-Object { $_.Name -like "*AnyDesk*" } | Select-Object Name, Status, StartType
Get-WmiObject Win32_Service | Where-Object { $_.PathName -like "*--conf-dir=*" }

# Check for PoisonX driver (covered by GentleKiller report but included for completeness)
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "G11\.sys" }
```

### Remediation

1. **Contain**: Isolate affected endpoints from the network immediately; disable AnyDesk services
2. **Identify**: Scan for IOC hashes across the environment; check for `.God8Damn` encrypted files
3. **Remove**: Unload PoisonX driver (`sc stop G11; sc delete G11`); delete symantec.exe, encryptor binary, NirSoft tools
4. **Restore**: Restart terminated security services; verify EDR sensor health
5. **Credential rotation**: Assume ALL credentials on compromised hosts are stolen -- rotate domain admin, service accounts, VPN, Wi-Fi, email, and browser-stored passwords
6. **AnyDesk audit**: Check for unauthorized AnyDesk installations across the environment; review `d:\ad_data` and similar non-standard config directories

### Long-Term Hardening

- Enable **Windows Defender Application Control (WDAC)** or **Hypervisor-Protected Code Integrity (HVCI)** to block unauthorized kernel drivers
- Deploy the **Microsoft Vulnerable Driver Blocklist** and keep it current
- Monitor for unexpected driver loads via Sysmon Event ID 6 (driver loaded)
- Monitor for Windows service creation (Event ID 7045) involving AnyDesk with non-standard paths
- Block unauthorized remote access tools (AnyDesk, TeamViewer) via application control policies
- Implement network segmentation to limit lateral movement via administrative shares
- Enable PowerShell script block logging and constrained language mode

## Detection Rules

The rules below cover GodDamn-specific detection surfaces: ransomware binary execution, file encryption activity, defense evasion tool identification, credential harvesting toolkit, and AnyDesk persistence patterns. PoisonX driver detection is handled by existing rules in the [GentleKiller EDR Framework report (2026-06-23)](/home/user/Actioner-examples/summaries/2026-06-23-gentlekiller-edr-framework.md). No network-level rules (Snort/Suricata) are generated because the disclosed IPs are legitimate AnyDesk relay servers, not attacker-controlled C2 infrastructure.

### Sigma: GodDamn Ransomware Encryptor Execution

Detects execution of the GodDamn ransomware encryptor binary by SHA-256 hash or the distinctive filename `encrypter-windows-gui-x86.exe`.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk succeeds. sigma check fails due to MITRE ATT&CK data fetch issue in the environment (proxy block), not a rule error. Hash detection is authoritative; filename is distinctive to GodDamn. -->

```yaml
title: GodDamn Ransomware Encryptor Execution
id: 8a3e7c12-4f9b-4d2e-a1c6-5b8d0e3f7a9c
status: experimental
description: >
    Detects execution of the GodDamn ransomware encryptor binary
    (encrypter-windows-gui-x86.exe) by SHA-256 hash or distinctive filename.
    GodDamn is assessed as a rebrand of Beast ransomware operated by the
    Hyadina group. First observed May 2026.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/14
tags:
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - 'e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69'
    selection_name:
        Image|endswith: '\encrypter-windows-gui-x86.exe'
    condition: selection_hash or selection_name
falsepositives:
    - Unlikely - hash detection is highly specific; filename is distinctive to the GodDamn ransomware
level: critical
```

### Sigma: GodDamn Ransomware File Encryption (.God8Damn Extension)

Detects file rename operations appending the `.God8Damn` extension, indicating active GodDamn ransomware encryption.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk succeeds. The .God8Damn extension is unique to this ransomware family. The file_rename log source requires Sysmon v14+ (which introduced file rename telemetry) or equivalent EDR telemetry capable of logging file rename operations with target filenames; environments without this telemetry will not generate events for this rule. -->

```yaml
title: GodDamn Ransomware File Encryption (.God8Damn Extension)
id: 3c5d8e1f-7a2b-4f6c-9d0e-2b4a6c8f1d3e
status: experimental
description: >
    Detects file rename operations appending the .God8Damn extension,
    indicating active GodDamn ransomware encryption. This extension is
    specific to the GodDamn ransomware family operated by the Hyadina group.
    NOTE: The file_rename log source requires Sysmon v14+ (Event ID 23 for
    FileDelete / file rename telemetry) or equivalent EDR telemetry capable
    of logging file rename operations with target filenames.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/14
tags:
    - attack.t1486
logsource:
    category: file_rename
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.God8Damn'
    condition: selection
falsepositives:
    - None expected - the .God8Damn extension is unique to this ransomware family
level: critical
```

### Sigma: GodDamn Defense Evasion Tool Execution (Symantec Masquerade)

Detects execution of the user-mode defense evasion tool (symantec.exe) deployed alongside PoisonX in GodDamn ransomware attacks, by SHA-256 hash. Filename detection is intentionally excluded to avoid false positives from legitimate Symantec binaries.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk succeeds. Pure hash-based detection; zero expected false positives. Symantec.exe filename excluded from detection to prevent FP on legitimate Symantec products. This tool is distinct from the GentleKiller "G11 variant" Symantec.exe (SHA-1: D29670E6...) -- different hash, same masquerade technique. -->

```yaml
title: GodDamn Defense Evasion Tool Execution (Symantec Masquerade)
id: 4d6e9f2a-8b3c-4a7d-be1f-3c5a7d9e0f2b
status: experimental
description: >
    Detects execution of the user-mode defense evasion tool deployed alongside
    PoisonX in GodDamn ransomware attacks. The tool masquerades as a Symantec
    product (symantec.exe) and works in tandem with the PoisonX kernel driver
    to disable endpoint defenses. Detection is by SHA-256 hash only to avoid
    false positives from legitimate Symantec binaries.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/14
tags:
    - attack.t1562.001
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - 'b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8'
    condition: selection_hash
falsepositives:
    - None expected - hash-based detection is highly specific
level: critical
```

### Sigma: GodDamn Credential Harvesting Toolkit

Detects execution of the 13 NirSoft credential harvesting tools and Mimikatz deployed by the GodDamn ransomware operation, identified by SHA-256 hashes of the specific builds used by the Hyadina group. Note: includes Mimikatz (mimik.exe, hash 31eb1de7...) which is not a NirSoft product.

**Status:** compile ✅ compiles -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk succeeds. 14 SHA-256 hashes covering 13 NirSoft tools and Mimikatz (mimik.exe, hash 31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc -- NOT a NirSoft product). Title renamed from "NirSoft Credential Harvesting Toolkit" to "GodDamn Credential Harvesting Toolkit" to accurately reflect mixed tool provenance. Hash-based detection avoids FP from legitimate NirSoft usage. -->

```yaml
title: GodDamn Credential Harvesting Toolkit
id: 5e7f0a3b-9c4d-4b8e-cf2a-4d6b8e0f1a3c
status: experimental
description: >
    Detects execution of credential harvesting tools deployed by the GodDamn
    ransomware operation. The toolkit comprises 13 NirSoft utilities and
    Mimikatz, targeting browser passwords, email credentials, VNC, Wi-Fi
    profiles, and Windows cached credentials. Detection is by SHA-256 hash
    of the specific versions deployed by the Hyadina group. Includes both
    NirSoft tools and Mimikatz (mimik.exe, hash 31eb1de7...).
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/14
tags:
    - attack.t1555.003
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180'
            - '19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d'
            - '31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc'
            - '35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c'
            - '5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd'
            - '5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404'
            - '5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6'
            - '7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26'
            - '816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019'
            - '8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8'
            - '8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167'
            - 'c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620'
            - 'ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046'
            - 'faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395'
    condition: selection_hash
falsepositives:
    - Legitimate use of these specific NirSoft tool builds is unlikely in enterprise environments
level: high
```

### Sigma: AnyDesk Persistence Service with Custom Configuration

Detects creation of AnyDesk services using non-standard configuration directories or AnyDesk interactive access consent suppression, as observed in GodDamn ransomware attacks. **BEHAVIORAL RULE:** AnyDesk with custom --conf-dir is a generic TTP used by multiple threat actors, not specific to GodDamn. Requires additional context for attribution.

**Status:** compile ✅ compiles -- confidence: low

<!-- audit: sigma convert --without-pipeline -t splunk succeeds. selection_sc matches sc.exe creating AnyDesk services with custom --conf-dir (non-standard path indicates malicious deployment). selection_powershell matches the consent suppression configuration using 'interactive_access=2' as a single token (fixed from bare '2' which would match any '2' in the command line). Downgraded from medium to low confidence: AnyDesk with --conf-dir is a generic TTP used by multiple actors, not GodDamn-specific. Moderate FP risk from legitimate AnyDesk deployments using custom config directories; organizations should tune against IT-approved configurations. -->

```yaml
title: AnyDesk Persistence Service with Custom Configuration
id: 6f8a1b4c-0d5e-4c9f-da3b-5e7c9f1a2b4d
status: experimental
description: >
    Detects creation of AnyDesk Windows services using non-standard
    configuration and data directories, or AnyDesk interactive access consent
    suppression. Observed in GodDamn ransomware attacks but this is a
    BEHAVIORAL rule -- AnyDesk with custom --conf-dir is a generic TTP used
    by multiple threat actors (including but not limited to Hyadina/GodDamn).
    This rule is NOT specific to GodDamn and should be treated as a
    behavioral indicator requiring additional context for attribution.
    Organizations should tune against IT-approved AnyDesk configurations.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/14
tags:
    - attack.t1543.003
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'AnyDesk'
            - '--service'
            - '--conf-dir='
    selection_powershell:
        CommandLine|contains|all:
            - 'ad.security.interactive_access'
            - 'interactive_access=2'
    condition: selection_sc or selection_powershell
falsepositives:
    - Legitimate AnyDesk deployments using custom configuration directories
    - IT-managed AnyDesk installations with consent suppression for unattended access
level: low
```

### YARA: GodDamn Ransomware Encryptor Binary

Detects GodDamn ransomware encryptor PE executables by the combination of the distinctive `.God8Damn` file extension string and ransomware-related indicators embedded in the binary.

**Status:** compile ✅ compiles -- confidence: medium

<!-- audit: yarac exit code 0. Rule keys on the unique .God8Damn extension string combined with encryptor filename or encryption-related function strings. Standalone ($name1) path removed per review: "encrypter-windows-gui" without $ext1 is overly broad and could match unrelated PE files. All condition branches now require $ext1 (.God8Damn). -->

```yara
rule Malware_GodDamn_Ransomware_Encryptor
{
    meta:
        description = "Detects GodDamn ransomware encryptor binary by embedded strings including the distinctive .God8Damn file extension and ransomware GUI indicators. GodDamn is a Beast ransomware rebrand operated by the Hyadina group."
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $name1 = "encrypter-windows-gui" ascii wide
        $name2 = "GodDamn" ascii wide
        $gui1 = "encrypter" ascii wide
        $func1 = "encrypt" ascii wide nocase
        $func2 = "ransom" ascii wide nocase
        $func3 = "decrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($ext1 and 1 of ($name*, $gui1)) or
            ($ext1 and 2 of ($func*))
        )
}
```

### YARA: GodDamn Defense Evasion Tool

Detects the GodDamn user-mode defense evasion tool that works alongside the PoisonX kernel driver, identified by the PoisonX device GUID combined with security product process names or driver references.

**Status:** compile ✅ compiles -- confidence: medium

<!-- audit: yarac exit code 0. Rule keys on PoisonX device GUID {F8284233-48F4-4680-ADDD-F8284233} combined with security process names (indicating EDR killer intent), or G11.sys driver reference combined with process termination APIs and targeted process names. Complements the existing Malware_PoisonX_BYOVD_Driver YARA rule from GentleKiller report (which targets the driver itself); this rule targets the user-mode component. OVERLAP NOTE: the GentleKiller EDR Framework report (2026-06-23) contains a related YARA rule for the GentleKiller variant of the PoisonX user-mode tool; environments deploying both rule sets will get overlapping coverage on samples carrying the PoisonX device GUID -- this is acceptable as the rules target distinct binaries (different hashes). INCONSISTENT .EXE SUFFIXES: $proc05 (avp.exe) and $proc06 (ekrn.exe) include .exe suffixes while $proc01-$proc04, $proc07-$proc08 use bare service/process names; this reflects how the strings appear in the binary (both forms are used for different targets). -->

```yara
rule Malware_GodDamn_Defense_Evasion_Tool
{
    meta:
        description = "Detects the GodDamn user-mode defense evasion tool that works alongside the PoisonX kernel driver. The tool masquerades as symantec.exe and terminates security processes and removes API hooks to blind endpoint security before ransomware deployment."
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $drv = "g11.sys" ascii wide nocase
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii
        $api3 = "NtOpenProcess" ascii
        $api4 = "NtTerminateProcess" ascii
        $proc01 = "CSFalconService" ascii wide
        $proc02 = "MsMpEng" ascii wide
        $proc03 = "SentinelAgent" ascii wide
        $proc04 = "SophosHealth" ascii wide
        $proc05 = "avp.exe" ascii wide
        $proc06 = "ekrn.exe" ascii wide
        $proc07 = "CylanceSvc" ascii wide
        $proc08 = "cbdefense" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($dev and 3 of ($proc*)) or
            ($drv and 1 of ($api*) and 3 of ($proc*))
        )
}
```

### Network Rules

No Snort or Suricata rules generated. The AnyDesk relay IPs disclosed in the Symantec report (`15.235.230[.]188`, `185.229.191[.]39`, `141.95.145[.]210`, `162.19.171[.]150`) are legitimate AnyDesk relay infrastructure, not attacker-controlled C2 servers. Blocking or alerting on these IPs would produce extensive false positives from legitimate AnyDesk usage. No other network-level indicators (C2 domains, exfiltration URLs, or attacker-controlled infrastructure) were disclosed in the available sources.

## Lessons Learned

1. **BYOVD as a ransomware standard**: The adoption of PoisonX BYOVD by a second major operation (GodDamn/Hyadina, after GentleKiller/Gentlemen) within weeks demonstrates that effective BYOVD drivers are rapidly shared or sold across the ransomware ecosystem. The same driver, signed by Microsoft, is now used by at least two distinct RaaS operations.

2. **Credential harvesting breadth signals data theft**: The deployment of 14 NirSoft tools plus Mimikatz -- targeting browsers, email clients, VNC, Wi-Fi, Windows credentials, and network traffic -- suggests comprehensive credential collection beyond what is needed for lateral movement alone. Organizations should assume data exfiltration occurred even if not directly observed.

3. **Legitimate remote access tools as persistence**: AnyDesk configured with consent suppression (`interactive_access=2`) and non-standard service paths is a persistent access pattern that survives remediation focused only on malware removal. Organizations should audit all remote access tool installations and block unauthorized deployments.

4. **Toolset overlap enables cross-operation detection**: GodDamn's use of PoisonX -- already covered by GentleKiller detection rules -- demonstrates that detecting shared tooling provides coverage across multiple threat actors. Organizations with existing PoisonX/GentleKiller detections already have partial coverage of GodDamn's defense evasion phase.

## Sources

- [Symantec Threat Hunter Team - GodDamn Ransomware: Latest Beast Rebrand Uses Malicious Driver to Disable Defenses](https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand) -- primary technical analysis with SHA-256 IOCs, attack timeline, NirSoft toolkit enumeration, and PoisonX integration details
- [The Hacker News - GodDamn Ransomware Uses PoisonX Driver to Disable Endpoint Defenses](https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html) -- news coverage summarizing Symantec findings with Beast/Monster lineage context
- [Dark Reading - GodDamn Ransomware Uses BYOVD to Smite US Companies](https://www.darkreading.com/cyberattacks-data-breaches/goddamn-ransomware-byovd-smite-companies) -- secondary coverage with US targeting context
- [Broadcom - GodDamn Ransomware Protection Bulletin](https://www.broadcom.com/support/security-center/protection-bulletin/goddamn-ransomware-latest-beast-rebrand-uses-malicious-driver-to-disable-defenses) -- Broadcom/Symantec protection bulletin
- [Actioner - GentleKiller EDR Framework Analysis (2026-06-23)](/home/user/Actioner-examples/summaries/2026-06-23-gentlekiller-edr-framework.md) -- prior coverage of PoisonX driver with existing detection rules

<!-- revision: v1.0 DRAFT -> v1.1 FINAL (2026-07-14)
Changes applied from critic review:
1. Sigma "GodDamn File Encryption": Fixed audit comment -- removed incorrect "Sysmon Event ID 2" reference; replaced with accurate file_rename telemetry note (Sysmon v14+ or EDR required). Added caveat to rule description.
2. Sigma "NirSoft Credential Harvesting Toolkit": Renamed to "GodDamn Credential Harvesting Toolkit" -- title was inaccurate because hash 31eb1de7... is Mimikatz (mimik.exe), not a NirSoft product. Description updated to note mixed provenance (13 NirSoft + Mimikatz).
3. Sigma "AnyDesk Persistence Service": TWO fixes applied -- (a) selection_powershell changed bare '2' token to 'interactive_access=2' to prevent matching any '2' in command line; (b) Downgraded from medium/high to low confidence because AnyDesk with --conf-dir is a generic TTP used by multiple actors, not GodDamn-specific. Added prominent behavioral caveat to description. Removed "GodDamn" from title.
4. YARA "GodDamn Ransomware Encryptor": Removed standalone ($name1) condition branch -- "encrypter-windows-gui" alone is overly broad without requiring .God8Damn extension. All condition branches now require $ext1.
5. YARA "GodDamn Defense Evasion Tool": Added audit comment noting overlap with GentleKiller YARA rule and documenting intentional inconsistency in .exe suffixes on process name strings.
6. All audit comments updated to remove incorrect "log_scale" backend references (not installed).
No rules dropped. -->

---
*Report generated by Actioner*
