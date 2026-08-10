# Technical Analysis Report: GodDamn Ransomware with PoisonX BYOVD Driver (2026-07-12)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-12
Version: 1.0

## Executive Summary

**GodDamn** is a ransomware family operated by the **Hyadina** group, assessed as a rebrand of Beast ransomware (itself an evolution of Monster, a Delphi-based ransomware active since March 2022). First observed in the wild on May 21, 2026, and publicly reported by Broadcom's Symantec Threat Hunter Team on July 9, 2026, GodDamn deploys a Microsoft-signed malicious kernel driver called **PoisonX** (`g11.sys`) via a Bring-Your-Own-Vulnerable-Driver (BYOVD) attack to forcibly disable endpoint detection and response (EDR) and antivirus products before encrypting files.

In a documented intrusion spanning May 29 to June 3, 2026, Hyadina operators established persistence via AnyDesk (configured as auto-start services), harvested credentials using a 14-tool NirSoft-based toolkit and Mimikatz, moved laterally across at least 10 hosts using PsExec, disabled endpoint security with `symantec.exe` (a masqueraded defense evasion loader) and the PoisonX driver, and ultimately deployed the GodDamn encrypter. Encrypted files receive the `.God8Damn` extension or a victim-specific name. Ransom communication occurs via email or qTox encrypted messenger. Four AnyDesk relay infrastructure IPs were identified. PoisonX is also used by the separate GentleKiller EDR-killer framework (Gentlemen RaaS); this report focuses on GodDamn-specific indicators.

## Background: Beast/Monster Ransomware Lineage

The Hyadina group has operated continuously since March 2022, progressing through three ransomware brands:

- **Monster** (March 2022): Delphi-based ransomware, the original family
- **Beast** (June 2024): Enhanced version with added Linux and VMware ESXi targeting, improved encryption performance and customization
- **GodDamn** (May 2026): Latest rebrand, retaining Beast's core capabilities while adopting BYOVD-based EDR evasion via PoisonX

The operation follows a ransomware-as-a-service (RaaS) model with affiliates. Geographic avoidance of Commonwealth of Independent States (CIS) countries and CIS language support in the tooling suggest a CIS-based developer. The PoisonX driver is shared infrastructure -- it is also used by the Gentlemen RaaS operation's GentleKiller framework (documented separately in `summaries/2026-06-23-gentlekiller-edr-framework.md`), indicating either supply-chain overlap or shared tooling within the criminal ecosystem.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | GodDamn ransomware first documented in the wild |
| 2026-05-29 | Initial AnyDesk activity detected at `csidl_profile\music\anydesk.exe` on victim network |
| 2026-05-30 | Defense evasion tools deployed; PoisonX kernel driver staged to `csidl_system\drivers\g11.sys` |
| 2026-06-01 | Lateral movement commenced across enterprise network via PsExec |
| 2026-06-02 | AnyDesk deployment repeated across 10+ hosts; credential harvesting with NirSoft toolkit |
| 2026-06-03 | Ransomware encryption phase on separate network segment; GodDamn encrypter deployed |
| 2026-07-09 | Broadcom Symantec Threat Hunter Team publishes analysis |

## Root Cause: Initial Access

The initial access vector for the documented intrusion is not fully detailed in available reporting. The first observed attacker activity was the deployment of AnyDesk to `csidl_profile\music\anydesk.exe` on May 29, 2026, suggesting the attacker had already gained a foothold -- potentially through compromised credentials, exposed remote access services, or another vector. The Hyadina group's historical reliance on exposed FortiGate configurations (documented in prior Monster/Beast campaigns) and exploitation of remote access products is consistent with their known TTPs.

## Technical Analysis of the Malicious Payload

### 1. Persistence: AnyDesk Remote Access

The attackers deployed AnyDesk as a persistent remote access mechanism, staging the binary in atypical locations (`csidl_profile\music\`) and registering it as auto-start Windows services.

**Service creation commands observed:**

```
sc create AnyDeskService binPath= "CSIDL_DRIVE_FIXED\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk Service"

sc create AnyDesk_D binPath= "CSIDL_DRIVE_FIXED\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk D-Drive Service"
```

**AnyDesk configuration** set `ad.security.interactive_access=2` to suppress interactive consent prompts, enabling fully unattended access. A PowerShell script (`install_ad.ps1`) was pre-staged at `CSIDL_SYSTEM_DRIVE\apps\` for automated AnyDesk installation:

```
powershell.exe -ExecutionPolicy Bypass -File CSIDL_SYSTEM_DRIVE\apps\install_ad.ps1
```

The standard AnyDesk installer was also invoked silently:

```
CSIDL_DRIVE_FIXED\anydesk.exe --install "CSIDL_PROGRAM_FILESX86\anydesk" --start-with-win --silent --accept-3rd-party-licenses
```

### 2. Credential Harvesting: NirSoft Toolkit and Mimikatz

A comprehensive 14-tool credential harvesting toolkit was deployed to `csidl_profile\music\mimik\pass\`, covering the full breadth of Windows credential storage:

| Tool | Filename | Target |
|------|----------|--------|
| WebBrowserPassView | webbrowserpassview64.exe | All browser passwords |
| ChromePass | chromepass.exe | Chrome stored passwords |
| PasswordFox | passwordfox64.exe | Firefox stored passwords |
| OperaPassView | operapassview.exe | Opera stored passwords |
| CredentialsFileView | credentialsfileview64.exe | Windows Credential Manager |
| NetPass | netpass64.exe | Cached domain credentials |
| WirelessKeyView | wirelesskeyview64.exe | Wi-Fi profiles/keys |
| VNCPassView | vncpassview.exe | VNC session passwords |
| MailPassView | mailpv.exe | Email client passwords |
| MessengerPass | mspass.exe | Instant messenger passwords |
| PstPassword | pstpassword.exe | Outlook PST passwords |
| ExtPassword | extpassword.exe | External/third-party passwords |
| SniffPass | sniffpass64.exe | Network traffic password sniffing |
| Mimikatz | mimik.exe | Windows authentication credentials |

Additionally, `netscan.exe` (SoftPerfect Network Scanner) was used for network reconnaissance.

### 3. Defense Evasion: symantec.exe and PoisonX Driver

The defense evasion stage used a two-component approach:

1. **symantec.exe** -- A user-mode loader masquerading as a Symantec security product, staged at `csidl_profile\music\symantec.exe` and launched via:
   ```
   cmd /c "start /b D:\symantec.exe"
   ```

2. **g11.sys (PoisonX)** -- A malicious kernel driver installed to `csidl_system\drivers\g11.sys`, signed by "Microsoft Windows Hardware Compatibility Publisher." PoisonX is not a vulnerable legitimate driver being exploited -- it is a deliberately malicious driver that passed Microsoft's signing review. Technical details:
   - Uses device symbolic link: `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
   - Kill command IOCTL: `0x22E010`
   - Accepts null-terminated ASCII decimal PID string, converts via `atoi()`, calls `ZwOpenProcess` then `ZwTerminateProcess`
   - No signature checks, ACLs, or privilege validation on the IOCTL interface
   - Over 15 versions identified in the wild

Windows Defender was also explicitly disabled via PowerShell:
```
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### 4. Lateral Movement: PsExec

All lateral movement was conducted via PsExec (`psexesvc.exe`), with all malicious commands sharing a process lineage through `psexesvc.exe -> services.exe -> wininit.exe`. The attacker also mounted administrative shares using harvested credentials:

```
net use \\192.168.0.25\c$ /user:[REDACTED] [REDACTED]
```

By June 2, the attacker had established presence on at least 10 hosts within the victim's network.

### 5. Encryption: GodDamn Ransomware

The ransomware binary `encrypter-windows-gui-x86.exe` was deployed from `csidl_profile\downloads\` and `csidl_profile\music\`. Encrypted files receive the `.God8Damn` extension (standard) or the victim organization's name as the extension (variant behavior). Ransom communication is conducted via email or qTox encrypted messenger.

### 6. Anti-Forensics / Evasion Techniques

- **Masquerading**: Defense evasion tool named `symantec.exe` to impersonate legitimate Symantec product
- **Staging in user profile directories**: Tools deployed to `\Music\` and `\Downloads\` rather than system directories
- **Microsoft-signed malicious driver**: PoisonX bypasses driver signature enforcement by holding a legitimate Microsoft signature
- **Unattended AnyDesk configuration**: Interactive access consent suppressed to avoid alerting users
- **Process termination and reboot**: `taskkill /f /im anydesk.exe` followed by `shutdown -r -t 0` for cleanup

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots

### File System

| Filename | SHA-256 | Description |
|----------|---------|-------------|
| encrypter-windows-gui-x86.exe | `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69` | GodDamn ransomware encrypter |
| g11.sys | `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` | PoisonX kernel driver |
| symantec.exe | `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8` | Defense evasion loader (masqueraded) |
| mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` | Mimikatz |
| psexesvc.exe | `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944` | PsExec service binary |
| anydesk.exe | `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220` | AnyDesk remote access |
| netpass64.exe | `17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180` | NirSoft NetPass |
| wirelesskeyview64.exe | `19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d` | NirSoft WirelessKeyView |
| credentialsfileview64.exe | `35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c` | NirSoft CredentialsFileView |
| mailpv.exe | `5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd` | NirSoft MailPassView |
| chromepass.exe | `5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404` | NirSoft ChromePass |
| pstpassword.exe | `5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6` | NirSoft PstPassword |
| mspass.exe | `7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26` | NirSoft MessengerPass |
| vncpassview.exe | `816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019` | NirSoft VNCPassView |
| operapassview.exe | `8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8` | NirSoft OperaPassView |
| webbrowserpassview64.exe | `8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167` | NirSoft WebBrowserPassView |
| netscan.exe | `9fae3f15900e13ec3860a109555ecd33ca43d38907c63438c50a2d6d91bfee1d` | SoftPerfect Network Scanner |
| sniffpass64.exe | `c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620` | NirSoft SniffPass |
| extpassword.exe | `ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046` | NirSoft ExtPassword |
| passwordfox64.exe | `faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395` | NirSoft PasswordFox |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 15.235.230[.]188 | AnyDesk relay infrastructure |
| IP | 185.229.191[.]39 | AnyDesk relay infrastructure |
| IP | 141.95.145[.]210 | AnyDesk relay infrastructure |
| IP | 162.19.171[.]150 | AnyDesk relay infrastructure |

### Behavioral

- PoisonX driver loaded from `%SystemRoot%\System32\drivers\g11.sys` with IOCTL `0x22E010` sent to device `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- AnyDesk service registration with non-standard names (`AnyDesk_D`) and custom `--conf-dir`/`--data-dir` parameters
- AnyDesk configuration setting `ad.security.interactive_access=2` (unattended access)
- Files staged in `%USERPROFILE%\Music\` and `%USERPROFILE%\Downloads\` rather than system directories
- PsExec lateral movement chain: `psexesvc.exe -> services.exe -> wininit.exe`
- Encrypted files with `.God8Damn` extension or victim organization name as extension
- Windows Defender real-time monitoring disabled via `Set-MpPreference -DisableRealtimeMonitoring $true`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1219 | Remote Access Software | AnyDesk deployed as auto-start service for persistent remote access |
| T1543.003 | Create or Modify System Process: Windows Service | AnyDesk registered as auto-start services (AnyDeskService, AnyDesk_D); PoisonX driver installed as service |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used for AnyDesk configuration, Defender disabling, and installation scripts |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | NirSoft ChromePass, WebBrowserPassView, PasswordFox, OperaPassView targeting browser credentials |
| T1555 | Credentials from Password Stores | NirSoft toolkit harvesting credentials from Windows Credential Manager, VNC, email clients, Wi-Fi profiles |
| T1003 | OS Credential Dumping | Mimikatz (mimik.exe) for Windows authentication credential extraction |
| T1036 | Masquerading | Defense evasion tool named symantec.exe to impersonate Symantec security product |
| T1562.001 | Impair Defenses: Disable or Modify Tools | PoisonX driver terminates EDR/AV processes; PowerShell disables Windows Defender |
| T1553.002 | Subvert Trust Controls: Code Signing | PoisonX is a deliberately malicious driver that obtained a legitimate Microsoft signature, subverting code-signing trust rather than exploiting a software vulnerability |
| T1569.002 | System Services: Service Execution | PsExec service installation for remote command execution |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Administrative share mounting via `net use \\host\c$` for lateral movement |
| T1486 | Data Encrypted for Impact | GodDamn ransomware encrypting files with .God8Damn extension |
| T1018 | Remote System Discovery | Network scanning via netscan.exe |

## Impact Assessment

The GodDamn ransomware deployment demonstrates a mature, staged intrusion methodology with a four-day dwell time between initial access and encryption. The use of a Microsoft-signed malicious driver (PoisonX) to disable endpoint security is particularly concerning because it renders standard EDR products structurally inoperative -- not evaded or circumvented, but forcibly terminated at the kernel level.

The documented attack compromised at least 10 hosts within the victim network before encryption. The comprehensive 14-tool credential harvesting toolkit suggests that stolen credentials may enable further attacks or be sold in underground markets. The PoisonX driver's presence in both the GodDamn and GentleKiller toolchains indicates it has become shared criminal infrastructure, increasing the number of threat groups that can leverage it.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for PoisonX driver on disk
Get-ChildItem -Path C:\ -Recurse -Include g11.sys -ErrorAction SilentlyContinue

# Check for GodDamn staging artifacts
Get-ChildItem -Path $env:USERPROFILE\Music,$env:USERPROFILE\Downloads -Include symantec.exe,encrypter-windows-gui-x86.exe,mimik.exe -ErrorAction SilentlyContinue

# Check for NirSoft credential harvesting tools
Get-ChildItem -Path C:\ -Recurse -Include netpass64.exe,wirelesskeyview64.exe,credentialsfileview64.exe,chromepass.exe,webbrowserpassview64.exe,sniffpass64.exe -ErrorAction SilentlyContinue

# Check for PoisonX device symbolic link
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "g11\.sys" }

# Check for suspicious AnyDesk service registrations
Get-Service | Where-Object { $_.Name -like "AnyDesk*" -and $_.Name -ne "AnyDesk" }

# Check for AnyDesk unattended access configuration
Get-ChildItem -Path D:\ad_data,C:\ad_data -Include system.conf -ErrorAction SilentlyContinue | Select-String "interactive_access=2"

# Check loaded drivers for PoisonX
driverquery /v | findstr /i "g11"

# Check for .God8Damn encrypted files
Get-ChildItem -Path C:\ -Recurse -Filter "*.God8Damn" -ErrorAction SilentlyContinue | Select-Object -First 5
```

### Remediation

1. **Contain**: Isolate affected endpoints from the network immediately; block relay IPs (15.235.230[.]188, 185.229.191[.]39, 141.95.145[.]210, 162.19.171[.]150) at the firewall
2. **Disable PoisonX**: Unload the g11.sys driver (`sc stop g11; sc delete g11`); delete from `%SystemRoot%\System32\drivers\`
3. **Remove AnyDesk persistence**: Delete AnyDesk services (`sc delete AnyDeskService; sc delete AnyDesk_D`); remove ad_data configuration directories
4. **Credential rotation**: Assume ALL credentials stored on compromised hosts are compromised -- rotate domain passwords, browser-saved credentials, Wi-Fi keys, VNC passwords, email passwords
5. **Scan for IOCs**: Search for all SHA-256 hashes from the IOC table across the environment
6. **Restore**: Restore encrypted files from offline backups; verify EDR sensor health post-driver removal

### Long-Term Hardening

- Enable **Windows Defender Application Control (WDAC)** or **Hypervisor-Protected Code Integrity (HVCI)** to block unsigned/malicious kernel drivers
- Deploy and maintain the **Microsoft Vulnerable Driver Blocklist** (and advocate for PoisonX's inclusion)
- Monitor driver load events via **Sysmon Event ID 6** and service creation via **Windows Event ID 7045**
- Restrict AnyDesk and other remote access software to authorized installations via application control policies
- Enforce credential hygiene: disable browser password saving via GPO; deploy enterprise password managers
- Implement network segmentation to limit lateral movement via PsExec/SMB

## Detection Rules

The rules below cover GodDamn's primary detection surfaces: PoisonX driver loading, masqueraded defense evasion tool, AnyDesk persistence, NirSoft credential harvesting, ransomware execution, and relay infrastructure communication. PoisonX is shared with GentleKiller; GodDamn-specific rules use the SHA-256 hashes from the Symantec analysis. The NirSoft filenames are legitimate tool names -- hash-gated detection is authoritative while filename detection may require tuning in environments with authorized NirSoft usage.

> **Dropped rule -- PsExec Service Installation**: A generic PsExec detection rule (keyed solely on `ServiceName: 'PSEXESVC'`) was removed during review. The default PsExec service name is used by any operator; the rule contained no GodDamn-specific artifact and does not meet the specific-altitude, strict-leniency bar for this report. Organizations should rely on their existing PsExec detection coverage.

### Sigma: PoisonX Kernel Driver Load

Detects loading of the PoisonX kernel driver (g11.sys) by SHA-256/SHA-1 hash or filename in Sysmon driver_load events.

**Status:** compile ✅ converts (splunk, log_scale) -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeed. sigma check fails due to MITRE ATT&CK data fetch (403 proxy; environment limitation, not rule error). Hashes|contains used because Sysmon Hashes field is multi-algo formatted (e.g. "SHA256=2d91a78e..."). SHA-256 from Symantec/GodDamn analysis; SHA-1 from ESET/GentleKiller analysis (may be different PoisonX samples). g11.sys filename alone may produce FP if used by unrelated software; hash selections are authoritative. -->

```yaml
title: PoisonX Kernel Driver Load - GodDamn Ransomware BYOVD
id: d3a7f8b1-4e2c-4f9a-b5d6-8c1e3f7a9d2b
status: experimental
description: >
    Detects loading of the PoisonX kernel driver (g11.sys), a Microsoft-signed
    malicious driver used by GodDamn ransomware (Hyadina group) and GentleKiller
    to disable EDR/AV via BYOVD. The driver uses device GUID
    {F8284233-48F4-4680-ADDD-F8284233} and terminates security processes via
    ZwTerminateProcess.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026-07-12
tags:
    - attack.t1553.002
    - attack.t1562.001
logsource:
    category: driver_load
    product: windows
detection:
    selection_hash_sha256:
        Hashes|contains: '2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d'
    selection_hash_sha1:
        Hashes|contains: '56BEE9DF5833A637F5C54D5911DF98B0812FE643'
    selection_name:
        ImageLoaded|endswith: '\g11.sys'
    condition: selection_hash_sha256 or selection_hash_sha1 or selection_name
falsepositives:
    - Unknown legitimate use of g11.sys filename - verify loaded driver hash against known PoisonX samples
level: high
```

### Sigma: GodDamn Defense Evasion Tool Masquerading as Symantec

Detects execution of symantec.exe, the defense evasion tool that loads PoisonX, by hash (authoritative) or by filename from suspicious staging paths.

**Status:** compile ✅ converts (splunk, log_scale) -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Hash detection is authoritative. Filename detection gated behind suspicious staging paths (\Music\, \Downloads\, \Temp\, \AppData\, \ProgramData\) to avoid FP from legitimate Symantec binaries in Program Files. The GentleKiller report similarly removed \Symantec.exe from generic filename selections for this reason. -->

```yaml
title: GodDamn Defense Evasion Tool Masquerading as Symantec
id: a1b8c9d2-3e4f-5a6b-7c8d-9e0f1a2b3c4d
status: experimental
description: >
    Detects execution of the GodDamn ransomware defense evasion tool
    (symantec.exe) that masquerades as a legitimate Symantec product to load the
    PoisonX kernel driver. Detection by SHA-256 hash is authoritative. Filename
    detection is gated behind suspicious staging paths (Music, Downloads, Temp,
    AppData) to avoid false positives from legitimate Symantec binaries.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026-07-12
tags:
    - attack.t1036
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains: 'b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8'
    selection_name_path:
        Image|endswith: '\symantec.exe'
        Image|contains:
            - '\Music\'
            - '\Downloads\'
            - '\Temp\'
            - '\AppData\'
            - '\ProgramData\'
    condition: selection_hash or selection_name_path
falsepositives:
    - Legitimate Symantec product binaries located in user profile directories (unlikely)
level: critical
```

### Sigma: Suspicious AnyDesk Service Installation

Detects creation of AnyDesk services with non-standard names or custom configuration directories as observed in GodDamn ransomware persistence.

**Status:** compile ✅ converts (splunk, log_scale) -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Service name "AnyDesk_D" is non-standard (legitimate AnyDesk creates "AnyDesk Service" or "AnyDesk"). Custom --conf-dir in ImagePath indicates attacker-configured deployment. May produce FP in enterprise environments with IT-managed AnyDesk deployments using custom config paths. -->

```yaml
title: Suspicious AnyDesk Service Installation - GodDamn Ransomware Persistence
id: b2c9d0e3-4f5a-6b7c-8d9e-0f1a2b3c4d5e
status: experimental
description: >
    Detects creation of AnyDesk services with non-standard names or custom
    configuration directories as observed in GodDamn ransomware deployments. The
    attacker creates services named AnyDesk_D or services with --conf-dir flags
    pointing to non-standard locations for unattended remote access persistence.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026-07-12
tags:
    - attack.t1543.003
    - attack.t1219
logsource:
    product: windows
    service: system
detection:
    selection_custom_service:
        EventID: 7045
        ServiceName|contains: 'AnyDesk_'
    selection_custom_config:
        EventID: 7045
        ImagePath|contains|all:
            - 'anydesk'
            - '--conf-dir'
    condition: selection_custom_service or selection_custom_config
falsepositives:
    - Legitimate AnyDesk Enterprise deployments with custom configuration directories managed by IT
level: high
```

### Sigma: NirSoft Credential Harvesting Toolkit Execution

Detects execution of NirSoft password recovery tools deployed by GodDamn operators, by SHA-256 hash (authoritative) or distinctive filenames.

**Status:** compile ✅ converts (splunk, log_scale) -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeed. 13 NirSoft tool hashes from Symantec analysis (Mimikatz excluded -- covered by dedicated Mimikatz rules). Filenames are legitimate NirSoft tool names; hash detection is authoritative. Filename detection may produce FP in environments where NirSoft tools are authorized for IT use. -->

```yaml
title: NirSoft Credential Harvesting Toolkit Execution - GodDamn Ransomware
id: c3d0e1f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
description: >
    Detects execution of NirSoft password recovery tools used by GodDamn
    ransomware operators for credential harvesting. The toolkit comprises 14
    tools targeting browser passwords, Windows Credential Manager, cached domain
    credentials, VNC sessions, email clients, Wi-Fi profiles, and network traffic.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026-07-12
tags:
    - attack.t1555.003
    - attack.t1555
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180'
            - '19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d'
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
    selection_name:
        Image|endswith:
            - '\netpass64.exe'
            - '\wirelesskeyview64.exe'
            - '\credentialsfileview64.exe'
            - '\mailpv.exe'
            - '\chromepass.exe'
            - '\pstpassword.exe'
            - '\mspass.exe'
            - '\vncpassview.exe'
            - '\operapassview.exe'
            - '\webbrowserpassview64.exe'
            - '\sniffpass64.exe'
            - '\extpassword.exe'
            - '\passwordfox64.exe'
    condition: selection_hash or selection_name
falsepositives:
    - Legitimate NirSoft tool usage by IT administrators for authorized password recovery or auditing
level: high
```

### Sigma: GodDamn Ransomware Encrypter Execution

Detects execution of the GodDamn ransomware encrypter by SHA-256 hash or distinctive filename pattern.

**Status:** compile ✅ converts (splunk, log_scale) -- confidence: high

<!-- audit: sigma convert --without-pipeline -t splunk and -t log_scale both succeed. Hash detection is authoritative. Filename "encrypter-windows-gui-x86.exe" appears to be a ransomware builder output name and is sufficiently distinctive for detection, though it could be reused across Beast/GodDamn variants. -->

```yaml
title: GodDamn Ransomware Encrypter Execution
id: f6a3b4c7-8d9e-0f1a-2b3c-4d5e6f7a8b9c
status: experimental
description: >
    Detects execution of the GodDamn ransomware encrypter by SHA-256 hash or
    distinctive filename pattern. GodDamn is a Beast/Monster rebrand operated by
    the Hyadina group, first observed May 21, 2026.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026-07-12
tags:
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains: 'e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69'
    selection_name:
        Image|endswith: '\encrypter-windows-gui-x86.exe'
    condition: selection_hash or selection_name
falsepositives:
    - None expected - hash and filename are highly specific to GodDamn ransomware
level: critical
```

### YARA: GodDamn Ransomware Encrypter

Detects GodDamn ransomware encrypter PE binaries via the distinctive `.God8Damn` file extension string embedded in the binary.

**Status:** compile ✅ yarac -- confidence: medium

<!-- audit: yarac exit code 0. Unused `import "pe"` removed (MZ check uses raw uint16, filesize is a built-in; no pe module features used). Detection keys on the ".God8Damn" extension string which must be embedded in the ransomware binary to append it during encryption. $ext2 with fullword modifier catches "God8Damn" without the leading dot. Condition requires MZ header + size < 10MB. May not detect samples where the extension is dynamically configured (variant using victim name as extension). -->

```yara
rule Ransomware_GodDamn_Encrypter
{
    meta:
        description = "Detects GodDamn ransomware encrypter (Beast/Monster rebrand by Hyadina group) via the distinctive .God8Damn file extension string embedded in the PE binary"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ext1 = ".God8Damn" ascii wide
        $ext2 = "God8Damn" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($ext*)
}
```

### YARA: PoisonX BYOVD Driver

Detects the PoisonX kernel driver by its unique device GUID and kernel process termination API imports.

**Status:** compile ✅ yarac -- confidence: high

<!-- audit: yarac exit code 0. Keys on unique PoisonX device GUID {F8284233-48F4-4680-ADDD-F8284233} combined with ZwOpenProcess and ZwTerminateProcess API names. GUID is unique to PoisonX; no known legitimate use. This rule is functionally equivalent to the PoisonX rule in the GentleKiller report (2026-06-23) but includes the SHA-256 hash from the GodDamn campaign. -->

```yara
rule Malware_PoisonX_BYOVD_Driver_GodDamn
{
    meta:
        description = "Detects PoisonX kernel driver (g11.sys) used by GodDamn ransomware and GentleKiller to terminate EDR/AV processes at kernel level. The driver is Microsoft-signed and uses a unique device GUID for IOCTL communication."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and
        ($api1 and $api2)
}
```

### Snort: AnyDesk Relay Infrastructure Communication

Detects outbound TCP connections to known GodDamn AnyDesk relay infrastructure IPs.

**Status:** ⚠️ uncompiled (snort not installed) -- confidence: medium

<!-- audit: Structural check only. Rule uses tcp protocol with flow:established,to_server. IP list in destination field uses Snort bracket notation. classtype, reference, metadata, sid, rev all present. Relay IPs may be shared AnyDesk infrastructure and could produce FP; verify with AnyDesk legitimate relay IP ranges before deploying. -->

```
alert tcp $HOME_NET any -> [15.235.230.188,185.229.191.39,141.95.145.210,162.19.171.150] any (msg:"Actioner - GodDamn Ransomware AnyDesk Relay Infrastructure Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand; metadata:author Actioner, created 2026-07-12; sid:2100010; rev:1;)
```

### Suricata: AnyDesk Relay Infrastructure Communication

Detects outbound TCP connections to known GodDamn AnyDesk relay infrastructure IPs.

**Status:** compile ✅ suricata -T -- confidence: medium

<!-- audit: suricata -T -S exit code 0 (Suricata 7.0.3). Rule uses tcp protocol with flow:established,to_server. Dot-notation not required as no app-layer sticky buffers are used. Relay IPs may be shared AnyDesk infrastructure; verify against legitimate relay IP ranges before deploying to avoid FP. -->

```
alert tcp $HOME_NET any -> [15.235.230.188,185.229.191.39,141.95.145.210,162.19.171.150] any (msg:"Actioner - GodDamn Ransomware AnyDesk Relay Infrastructure Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand; metadata:author Actioner, created_at 2026-07-12; sid:2200010; rev:1;)
```

## Lessons Learned

1. **Microsoft-signed malicious drivers represent a systemic trust failure**: PoisonX is not a legitimate driver being abused -- it is a deliberately malicious driver that passed Microsoft's Hardware Compatibility signing process. This undermines the fundamental assumption that Microsoft-signed drivers are trustworthy and highlights the need for behavioral driver monitoring beyond signature validation.

2. **BYOVD tooling is becoming shared criminal infrastructure**: PoisonX appears in both the GodDamn (Hyadina) and GentleKiller (Gentlemen) toolchains, indicating either a shared supply chain or underground market for BYOVD tools. Defenders should treat PoisonX detections as potentially indicative of multiple threat groups.

3. **Comprehensive credential harvesting is now standard pre-ransomware procedure**: The deployment of 14 separate credential recovery tools covering every credential store on a Windows system demonstrates that credential harvesting is no longer an opportunistic add-on but a systematic phase of ransomware operations.

4. **User profile directories as staging locations bypass some monitoring**: Tools staged in `%USERPROFILE%\Music\` and `%USERPROFILE%\Downloads\` may evade monitoring focused on system directories, temporary folders, or known malware paths. Detection rules should account for executables in atypical user profile locations.

## Sources

- [Symantec/Broadcom - GodDamn Ransomware: Latest Beast Rebrand Uses Malicious Driver to Disable Defenses](https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand) -- primary technical analysis with full IOC table, attack timeline, SHA-256 hashes, command lines, and network indicators
- [The Hacker News - GodDamn Ransomware Uses PoisonX Driver to Disable Endpoint Defenses](https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html) -- news coverage summarizing Symantec findings
- [Security Affairs - GodDamn Ransomware Uses PoisonX to Blind Security Software](https://securityaffairs.com/195042/malware/goddamn-ransomware-uses-poisonx-to-blind-security-software.html) -- additional coverage with deployment detail
- [Dark Reading - GodDamn Ransomware Uses BYOVD to Smite US Companies](https://www.darkreading.com/cyberattacks-data-breaches/goddamn-ransomware-byovd-smite-companies) -- industry coverage with geographic targeting context
- [Xcitium ThreatLabs - Reverse Engineering a 0-day: PoisonX BYOVD Driver](https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/) -- PoisonX driver reverse engineering (IOCTL interface, device GUID, API mechanism)
- [ESET WeLiveSecurity - GentleKiller EDR Framework](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/) -- prior PoisonX coverage in GentleKiller context (separate threat group)

---
*Report generated by Actioner*
