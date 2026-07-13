# Technical Analysis Report: GodDamn Ransomware with PoisonX Driver (2026-07-13)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-13
Version: 1.0 (DRAFT)

## Executive Summary

GodDamn is the latest rebrand of the Beast ransomware family (Monster, March 2022 -> Beast, June 2024 -> GodDamn, May 2026), developed by the threat group tracked as Hyadina. The ransomware employs a novel kernel-level defense evasion technique using the PoisonX driver (`g11.sys`), a malicious Windows kernel driver that its developers succeeded in getting signed by Microsoft via the Windows Hardware Compatibility Publisher (WHCP) program. PoisonX terminates security product processes -- including PPL-protected sensors such as CrowdStrike Falcon -- by issuing crafted IOCTL commands (`0x22E010`) from kernel mode, bypassing Protected Process Light restrictions entirely. The driver was initially documented in April 2026 by Xcitium in spear-phishing campaigns targeting Japan and China, and has since been adopted by The Gentlemen RaaS as part of its GentleKiller EDR-killer framework.

In the investigated intrusion, attackers deployed AnyDesk for persistent remote access (hidden in the user's Music folder with unattended access configured), used PsExec for lateral movement across at least 10 hosts, staged a comprehensive NirSoft-based credential harvesting toolkit alongside Mimikatz, disabled Windows Defender via PowerShell, and finally deployed the GodDamn encryptor which appends the `.God8Damn` extension to encrypted files. At the time of initial discovery, PoisonX had 0/71 detections on VirusTotal.

## Background: Beast/GodDamn Ransomware Family

The Beast ransomware family originated as Monster, a Delphi-based, 32-bit Windows ransomware first deployed in March 2022. It was rebranded as Beast in June 2024, adding support for targeting Linux and VMware ESXi operating systems. GodDamn is the latest iteration, first publicly observed on May 21, 2026. The developer group is tracked as Hyadina. In June 2025, Beast ransomware attackers were observed using a custom tool for finding valid admin credentials, alongside the Gmer rootkit scanner and IObit Unlocker.

PoisonX is not exclusive to GodDamn. The Gentlemen ransomware-as-a-service (RaaS) scheme has integrated it into a custom EDR-killer framework called GentleKiller, which targets processes from 48 distinct security vendors using eight different vulnerable/malicious driver variants.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | GodDamn ransomware first documented in the wild |
| 2026-05-29 | AnyDesk deployed on Computer 1 (initial foothold), staged in `%USERPROFILE%\Music\` |
| 2026-05-30 | Defense evasion tool (`symantec.exe`) and NirSoft/Mimikatz credential harvesting toolkit deployed |
| 2026-06-01 | Lateral movement begins via PsExec; AnyDesk pushed to remote hosts |
| 2026-06-02 | AnyDesk deployed across at least 10 hosts with auto-start service configuration |
| 2026-06-03 | GodDamn ransomware encryptor deployed on separate network segment |

## Root Cause: Initial Access

The exact initial access vector remains undisclosed in available reporting. The attack sequence begins with remote access tool deployment (AnyDesk), suggesting prior credential compromise or exploitation of an externally-facing service. Credential harvesting with NirSoft tools and Mimikatz enabled lateral movement via administrative share access and PsExec.

## Technical Analysis of the Malicious Payload

### 1. Remote Access -- AnyDesk Deployment

Attackers staged AnyDesk in the user's Music folder (`%USERPROFILE%\Music\anydesk.exe`) with SHA-256 hash `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220`. The tool was configured for unattended access by setting `ad.security.interactive_access=2` in its configuration file, which suppresses the standard interactive consent prompt and allows incoming connections without local user approval.

Two persistence services were created:
- `AnyDeskService` -- primary service with auto-start
- `AnyDesk_D` -- fallback service on D: drive

Service creation commands observed:
```
sc create AnyDeskService binPath= "D:\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk Service"
sc create AnyDesk_D binPath= "D:\anydesk.exe --service --conf-dir=d:\ad_data --data-dir=d:\ad_data" start= auto DisplayName= "AnyDesk D-Drive Service"
```

A pre-staged PowerShell installation script (`C:\apps\install_ad.ps1`) was also used on some hosts for standardized deployment with `--start-with-win --silent --accept-3rd-party-licenses` flags.

### 2. Defense Evasion -- PoisonX Driver (BYOVD)

The PoisonX driver (`g11.sys`) is a malicious kernel driver that its developers succeeded in getting signed by Microsoft via the WHCP program. Unlike traditional BYOVD attacks that abuse a legitimate-but-vulnerable driver, PoisonX is purpose-built malware with a valid Microsoft signature. At initial discovery, it had 0/71 detections on VirusTotal, and 15+ variants have been identified -- all Microsoft-signed.

**Driver technical details:**
- **Filename:** `g11.sys`
- **Drop location:** `%SystemRoot%\System32\drivers\g11.sys`
- **SHA-256:** `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d`
- **Signature:** Microsoft Windows Hardware Compatibility Publisher
- **Symbolic link:** `\\.\{F8284233-48F4-4680-ADDD-F8284233}`
- **Device interface GUID:** `{F8284233-48F4-4680-ADDD-F8284233}`
- **Primary IOCTL:** `0x22E010` (triggers `procKiller` routine)
- **Input format:** Null-terminated ASCII decimal string of the target PID
- **Output on success:** Literal string `"ok"`

**Kernel functions called:**
1. `ZwOpenProcess` -- opens handle to target process, bypasses PPL restrictions since the call originates from kernel mode
2. `ZwTerminateProcess` -- kills the opened process
3. `RtlCopyMemory` -- copies success response string

The user-mode component (`symantec.exe`, SHA-256: `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8`) masquerades as a Symantec product and is launched via `cmd /c "start /b D:\symantec.exe"`. It loads the PoisonX driver and sends crafted IOCTL commands to terminate security product processes. Additionally, Windows Defender real-time monitoring was disabled via:
```
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### 3. Credential Harvesting

A comprehensive credential harvesting toolkit comprising 14 NirSoft tools and Mimikatz was staged in `%USERPROFILE%\Music\mimik\pass\`:

| Tool | Filename | SHA-256 |
|------|----------|---------|
| Mimikatz | mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` |
| WebBrowserPassView | webbrowserpassview.exe | `8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167` |
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
| PstPassword | pstpassword.exe | `5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6` |
| Netpass | netpass64.exe | `17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180` |

Together these recover credentials from browsers, Windows Credential Manager, cached domain credentials, VNC sessions, email clients, Wi-Fi profiles, and live network traffic.

### 4. Lateral Movement

PsExec (SHA-256: `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944`) was used to push commands to remote targets, with process lineage running through `psexesvc.exe` -> `services.exe` -> `wininit.exe`. Administrative shares were mounted using stolen credentials:
```
net use \\[TARGET_IP]\c$ /user:[DOMAIN\USER] [PASSWORD]
```

The AnyDesk deployment was repeated across at least 10 hosts over two days, creating a redundant remote access mesh across the network.

### 5. Ransomware Deployment

The GodDamn encryptor (`encrypter-windows-gui-x86.exe`, SHA-256: `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69`) was deployed from `%USERPROFILE%\Downloads\` and `%USERPROFILE%\Music\`. Encrypted files are renamed with the `.God8Damn` extension (standard variant), though in the investigated incident the victim organization's name was used as the extension instead. Ransom negotiations are conducted via email or the qTox encrypted messaging application.

### 6. Anti-Forensics / Evasion Techniques

- Microsoft-signed malicious driver bypasses driver signature enforcement and most AV detections (0/71 on VT)
- User-mode API hook removal by PoisonX prevents behavioral detection
- Masquerading defense evasion tool as `symantec.exe`
- AnyDesk hidden in `Music` folder rather than standard installation paths
- Process termination followed by reboot sequence (`taskkill /f /im anydesk.exe` -> `timeout /t 3` -> `shutdown -r -t 0`)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `192.168.0[.]25`)

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|---------------|-------------|
| Windows | %SystemRoot%\System32\drivers\g11.sys | `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` | PoisonX kernel driver |
| Windows | %USERPROFILE%\Music\symantec.exe | `b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8` | Defense evasion tool (loads PoisonX) |
| Windows | %USERPROFILE%\Downloads\encrypter-windows-gui-x86.exe | `e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69` | GodDamn ransomware encryptor |
| Windows | %USERPROFILE%\Music\mimik.exe | `31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc` | Mimikatz (renamed) |
| Windows | %USERPROFILE%\Music\anydesk.exe | `45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220` | AnyDesk remote access |
| Windows | psexesvc.exe | `141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944` | PsExec service binary |
| Windows | D:\ad_data\system.conf | N/A | AnyDesk config (interactive_access=2) |
| Windows | C:\apps\install_ad.ps1 | N/A | AnyDesk deployment PowerShell script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 15.235.230[.]188 | AnyDesk relay infrastructure (may be shared/legitimate) |
| IP | 185.229.191[.]39 | AnyDesk relay infrastructure (may be shared/legitimate) |
| IP | 141.95.145[.]210 | AnyDesk relay infrastructure (may be shared/legitimate) |
| IP | 162.19.171[.]150 | AnyDesk relay infrastructure (may be shared/legitimate) |
| IP | 192.168.0[.]25 | Internal lateral movement target (admin share mount) |

> **Note:** The AnyDesk relay IPs may be legitimate shared AnyDesk infrastructure; use them for correlation, not standalone blocking.

### Behavioral

- PoisonX driver creates device with symbolic link `\\.\{F8284233-48F4-4680-ADDD-F8284233}` and responds to IOCTL `0x22E010`
- User-mode component sends target PID as null-terminated ASCII decimal string; receives `"ok"` on successful kill
- AnyDesk services created with non-standard config directory on D: drive (`--conf-dir=d:\ad_data`)
- Credential toolkit staged in `%USERPROFILE%\Music\mimik\pass\` as password-protected self-extracting archive
- Windows Defender real-time monitoring disabled via `Set-MpPreference -DisableRealtimeMonitoring $true`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1562.001 | Impair Defenses: Disable or Modify Tools | PoisonX driver terminates EDR/AV processes via kernel-mode IOCTL; Windows Defender disabled via Set-MpPreference |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense evasion tool named `symantec.exe` to appear as Symantec product |
| T1486 | Data Encrypted for Impact | GodDamn ransomware encrypts files with .God8Damn extension |
| T1555 | Credentials from Password Stores | NirSoft toolkit extracts credentials from browsers, email clients, VNC, Wi-Fi profiles |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz (mimik.exe) deployed for credential extraction |
| T1219 | Remote Access Software | AnyDesk deployed with unattended access for persistent remote control |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec and `net use` for lateral movement via admin shares |
| T1543.003 | Create or Modify System Process: Windows Service | AnyDesk registered as auto-start Windows service (AnyDeskService, AnyDesk_D) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell scripts for AnyDesk deployment and Defender disabling |

## Impact Assessment

GodDamn ransomware with PoisonX represents a significant escalation in ransomware defense evasion capabilities. The use of a Microsoft-signed malicious driver (rather than a vulnerable legitimate driver) makes detection substantially harder -- the driver passes signature verification and had zero antivirus detections on VirusTotal at discovery. The PPL bypass enables termination of even the most hardened EDR sensors. With PoisonX now available through The Gentlemen RaaS and its GentleKiller framework, the technique is accessible to a broad range of affiliates, increasing the likely scope of future incidents.

## Detection & Remediation

### Immediate Detection

Check for the PoisonX driver and related artifacts:
```powershell
# Check for PoisonX driver
Get-ChildItem -Path "$env:SystemRoot\System32\drivers\g11.sys" -ErrorAction SilentlyContinue

# Check for the defense evasion tool
Get-ChildItem -Path "$env:USERPROFILE\Music\symantec.exe" -ErrorAction SilentlyContinue

# Check for suspicious AnyDesk services
Get-Service -Name "AnyDeskService","AnyDesk_D" -ErrorAction SilentlyContinue

# Check for PoisonX device symbolic link
Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -like "*F8284233*" }

# Check for credential toolkit staging
Get-ChildItem -Path "$env:USERPROFILE\Music\mimik" -Recurse -ErrorAction SilentlyContinue

# Check for GodDamn encrypted files
Get-ChildItem -Path C:\ -Filter "*.God8Damn" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
```

### Remediation

1. **Contain:** Isolate affected hosts from the network immediately; disable AnyDesk services and block AnyDesk relay IPs at the perimeter
2. **Eradicate:** Remove `g11.sys` from `%SystemRoot%\System32\drivers\`, delete `symantec.exe` and the credential toolkit from Music folders, remove AnyDesk services and binaries
3. **Recover:** Restore encrypted files from offline backups; validate backup integrity before restoration
4. **Credential rotation:** Assume all credentials on affected hosts are compromised -- rotate domain admin, service account, and local administrator passwords; invalidate all Kerberos tickets
5. **Driver audit:** Review all loaded kernel drivers against known-good baselines; implement WDAC/HVCI policies to restrict driver loading

### Long-Term Hardening

- **WDAC (Windows Defender Application Control):** Deploy WDAC policies with HVCI (Hypervisor-protected Code Integrity) to block unsigned or known-malicious kernel drivers
- **Driver blocklist:** Maintain and enforce the Microsoft Recommended Driver Block Rules list
- **PPL enforcement:** Ensure EDR sensors run as PPL where supported; monitor for PPL bypass attempts
- **Remote access policy:** Block or monitor unauthorized remote access tools (AnyDesk, TeamViewer, etc.) via application control policies
- **Credential hygiene:** Implement tiered administration, restrict LSASS access with Credential Guard, and deploy PAWs for sensitive operations

## Detection Rules

These detections target the specific PoisonX driver, GodDamn defense evasion tool, ransomware encryptor, and credential harvesting toolkit using campaign-specific hashes, file names, and paths. PoC/advisory-specific altitude (default); all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify rules against your telemetry pipeline.

### Sigma: PoisonX Malicious Driver Load

Detects loading of the PoisonX kernel driver (`g11.sys`) or its known hash via Sysmon driver load events.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (with -x attacktag due to MITRE API network restriction in CI); splunk convert exit 0; log_scale convert exit 0. driver_load category maps to Sysmon EID 6. Hashes field uses contains modifier for SHA256= prefix format. No FP risk — g11.sys is a unique malicious driver name and hash is exact-match. -->
```yaml
title: PoisonX Malicious Driver Load - GodDamn Ransomware
id: 8a3f1c2e-4b5d-6e7f-9a0b-1c2d3e4f5a6b
status: experimental
description: >
    Detects loading of the PoisonX kernel driver (g11.sys) used by GodDamn ransomware
    operators to terminate security product processes and strip user-mode API hooks via
    BYOVD technique. The driver carries a legitimate Microsoft WHCP signature.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/13
tags:
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
    - Unknown
level: critical
```

### Sigma: GodDamn Defense Evasion Tool Masquerading as Symantec

Detects execution of `symantec.exe` from user Music folder or by its known hash -- the user-mode component that loads PoisonX.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (-x attacktag); splunk/log_scale exit 0. selection_path uses endswith on \music\symantec.exe which is highly specific staging path. Hash is exact-match. Symantec does not ship a binary named symantec.exe. -->
```yaml
title: GodDamn Ransomware Defense Evasion Tool Masquerading as Symantec
id: 7b4e2d1f-5c6a-8e9d-0f1a-2b3c4d5e6f7a
status: experimental
description: >
    Detects execution of the GodDamn ransomware defense evasion tool (symantec.exe)
    that loads the PoisonX driver to disable endpoint security. The tool masquerades
    as a Symantec product and is typically staged in the user Music folder.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/13
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
        Image|endswith: '\music\symantec.exe'
    condition: selection_hash or selection_path
falsepositives:
    - Unknown
level: critical
```

### Sigma: GodDamn Ransomware Encryptor Execution

Detects execution of the GodDamn encryptor binary by its distinctive original filename or known hash.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (-x attacktag); splunk/log_scale exit 0. encrypter-windows-gui-x86.exe is a highly distinctive and uncommon filename. Hash is exact-match. -->
```yaml
title: GodDamn Ransomware Encryptor Execution
id: 9c5f3e2d-6a7b-0f1e-2d3c-4e5f6a7b8c9d
status: experimental
description: >
    Detects execution of the GodDamn ransomware encryptor binary
    (encrypter-windows-gui-x86.exe), the latest rebrand of Beast ransomware.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
    - https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html
author: Actioner
date: 2026/07/13
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
    - Unknown
level: critical
```

### Sigma: GodDamn NirSoft Credential Harvesting Toolkit

Detects execution of NirSoft credential tools or renamed Mimikatz (mimik.exe) by their campaign-specific hashes or staging path. Legitimate IT use of NirSoft tools is possible but uncommon in enterprise environments.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (-x attacktag); splunk/log_scale exit 0. 14 NirSoft hashes + Mimikatz hash from Symantec report. Path selection targets music\mimik staging directory. FP: IT admins legitimately using NirSoft tools -- rare in enterprise. -->
```yaml
title: GodDamn Ransomware NirSoft Credential Harvesting Toolkit
id: 0d6a4f3e-7b8c-1a2d-3e4f-5a6b7c8d9e0f
status: experimental
description: >
    Detects execution of NirSoft credential harvesting tools and renamed Mimikatz
    binary (mimik.exe) used in GodDamn ransomware intrusions. The toolkit is typically
    staged under the user profile Music folder.
references:
    - https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
author: Actioner
date: 2026/07/13
tags:
    - attack.t1555
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_mimikatz:
        Hashes|contains: '31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc'
    selection_nirsoft_hashes:
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
    selection_path:
        Image|contains: '\music\mimik'
    condition: selection_mimikatz or selection_nirsoft_hashes or selection_path
falsepositives:
    - Legitimate use of NirSoft password recovery tools by IT administrators
level: high
```

### Snort: N/A

No attacker-controlled C2 infrastructure (domains, IPs, URLs) was disclosed. The AnyDesk relay IPs are potentially shared legitimate infrastructure and would generate excessive false positives as Snort rules.

### Suricata: N/A

No attacker-controlled C2 infrastructure (domains, IPs, URLs) was disclosed. The AnyDesk relay IPs are potentially shared legitimate infrastructure and would generate excessive false positives as Suricata rules.

### YARA: GodDamn Ransomware Encryptor

Detects the GodDamn ransomware encryptor via the distinctive `.God8Damn` file extension string or original filename combined with family identifiers.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: constructed positive with MZ header + .God8Damn string fired correctly; negative with benign MZ content stayed quiet. Confidence medium (not high) because string-only matching without binary sample analysis — the published .God8Damn extension is distinctive but an adversary could change it per-victim (as observed in the investigated incident). -->
```yara
rule Ransomware_GodDamn_Encryptor
{
    meta:
        description = "Detects GodDamn ransomware encryptor binary via distinctive strings (.God8Damn extension, original filename)"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69"
        severity = "critical"

    strings:
        $ext = ".God8Damn" ascii wide
        $name = "encrypter-windows-gui-x86" ascii wide
        $family1 = "GodDamn" ascii wide
        $family2 = "Beast" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($ext or ($name and 1 of ($family*)))
}
```

### YARA: PoisonX EDR Killer Driver

Detects the PoisonX kernel driver via its device interface GUID (`{F8284233-48F4-4680-ADDD-F8284233}`) or driver name combined with kernel process termination imports.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: constructed positive with MZ header + GUID string fired correctly; positive with g11.sys + ZwOpenProcess also fired; negative stayed quiet. GUID is a highly distinctive artifact from reverse engineering. Confidence medium because we lack the actual binary sample for full validation — strings are from published analysis. -->
```yara
rule Driver_PoisonX_EDRKiller
{
    meta:
        description = "Detects the PoisonX malicious kernel driver used to terminate security product processes via BYOVD technique with IOCTL 0x22E010"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand"
        hash = "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d"
        severity = "critical"

    strings:
        $guid = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide nocase
        $drv_name = "g11.sys" ascii wide
        $nt_func1 = "ZwOpenProcess" ascii
        $nt_func2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($guid or ($drv_name and 1 of ($nt_func*)))
}
```

## Lessons Learned

1. **BYOVD evolution:** PoisonX represents a dangerous evolution beyond traditional BYOVD -- rather than exploiting a vulnerable legitimate driver, attackers obtained genuine Microsoft WHCP signatures for purpose-built malicious code. This undermines the trust model of driver signing and requires defenders to move beyond signature-based driver trust to behavior-based driver monitoring.

2. **RaaS commoditization of EDR killers:** The adoption of PoisonX by The Gentlemen RaaS (via GentleKiller) demonstrates that advanced defense evasion techniques are being rapidly commoditized and distributed to affiliates. Organizations cannot assume EDR alone provides sufficient protection without kernel-level hardening (WDAC/HVCI).

3. **Credential toolkit breadth:** The comprehensive 14-tool NirSoft credential harvesting kit covers virtually every credential store on a Windows host. This underscores the importance of credential hygiene, tiered administration, and Credential Guard -- a single compromised workstation can yield credentials sufficient for full domain compromise.

## Sources

- [Symantec Threat Hunter Team -- GodDamn Ransomware: Latest Beast Rebrand Uses Malicious Driver to Disable Defenses](https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand) -- primary technical analysis with full IOC set, attack timeline, and PoisonX reverse engineering
- [The Hacker News -- GodDamn Ransomware Uses PoisonX Driver to Disable Endpoint Defenses](https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html) -- secondary reporting with additional context on The Gentlemen RaaS and GentleKiller
- [Infosecurity Magazine -- Ransomware Removes Cybersecurity](https://www.infosecurity-magazine.com/news/ransomware-removes-cybersecurity/) -- secondary reporting confirming key findings
- [Xcitium ThreatLabs -- Reverse-Engineering a 0-Day: PoisonX BYOVD Driver Bypasses CrowdStrike EDR](https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/) -- initial PoisonX driver analysis from April 2026
- [ESET WeLiveSecurity -- Killing Me Gently: Inside Gentlemen's EDR Killer Framework](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/) -- GentleKiller framework analysis

---
*Report generated by Actioner*
