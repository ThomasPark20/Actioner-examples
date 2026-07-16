# Technical Analysis Report: UAT-11795 Starland RAT & WLDR C2 Campaign (2026-07-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-16
Version: DRAFT 1.0

## Executive Summary

UAT-11795 is a Russian-speaking, financially motivated threat actor active since at least June 2025, targeting users predominantly in the United States with secondary victims in Germany, Romania, and Venezuela. The actor distributes trojanized installers for popular software (MobaXterm, WebEx, Zoom, DBeaver, Faceit) via ClickFix social engineering, leading to the deployment of a novel Python-based RAT ("Starland RAT") and a bespoke PowerShell C2 implant ("WLDR"). The campaign chain culminates in the delivery of CastleStealer (a .NET infostealer) and Remcos RAT for credential harvesting, cryptocurrency wallet theft, and persistent remote access. The actor leverages blockchain-based fallback C2 resolution via a Polygon smart contract, AMSI/ETW bypasses, and AES-256-CBC encrypted C2 communications.

## Background: Targeted Software & Users

UAT-11795 targets users who search for and download popular software utilities. The trojanized installers mimic legitimate versions of MobaXterm v26.1, Cisco WebEx Client, Zoom, DBeaver CE, and Faceit. Victims are lured via social engineering (ClickFix technique) that entices them to execute a command which downloads and runs a weaponized HTA file. The campaign focuses on stealing credentials from web browsers, cryptocurrency wallet applications (over 40 wallet types including desktop cold wallets and browser extensions), Discord sessions, Telegram sessions, and Steam accounts.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-06-05 | Telegram channel "stuk komanda" created for C2/exfiltration |
| 2025-06+ | Campaign begins with trojanized installer distribution |
| 2026-07-16 | Cisco Talos publishes detailed technical analysis |

## Root Cause: ClickFix Social Engineering & Trojanized Installers

The initial access vector is a ClickFix social engineering technique that entices victims to execute a command (likely copied from a malicious webpage), which stealthily downloads and executes a remotely hosted weaponized HTA file via `mshta.exe`. The HTA files are hosted on staging domains and contain embedded VBScript with Russian-language comments (e.g., the persistence setup comment translates to "Adding a command to autostart for the current user"). The legitimate software installer runs in parallel to maintain the illusion of normalcy while the malicious payload executes in the background.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader: Weaponized HTA via Mshta

The attack begins when `mshta.exe` executes a remotely hosted HTA file from one of several staging domains. The HTA contains embedded VBScript that:
- Drops a batch file to the user's %TEMP% directory
- Establishes registry Run key persistence (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value name "MyApp" pointing to mshta.exe)
- Downloads a compressed archive containing the Python-based Starland RAT loader

The VBScript includes the Russian-language comment: "Dobavelenie komandy v avtozapusk dlya tekushchego pol'zovatelya" (Adding a command to autostart for the current user).

### 2. Starland RAT: Python-based Reconnaissance & Loader

The Starland RAT is delivered as a compiled Python loader disguised as `LICENSE.txt`, executed via `pythonw.exe LICENSE.txt`. Key characteristics:

**Persistence mechanisms (three methods):**
- Registry Run key (MyApp via mshta.exe HTA)
- Scheduled task: `PythonLauncher-{3 random chars}` with AtLogOn trigger and RunLevel Highest
- Startup folder: LNK shortcut targeting `pythonw.exe` with `LICENSE.txt` argument

**Reconnaissance commands executed:**
- `Get-CimInstance -Class Win32_ComputerSystemProduct.UUID` (hardware UUID)
- `wmic memorychip get Capacity` (memory enumeration)
- `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct` (AV detection)
- `Get-WmiObject Win32_ComputerSystem.Domain` (domain membership)
- `whoami && systeminfo && net user {USERNAME} /dom && nltest /dclist` (AD reconnaissance)
- `whoami /all` (privilege enumeration)

**Encryption:**
- XOR key `198` (0xC6) for embedded payload encryption
- XOR key `helo1` for JSON reconnaissance data encoding
- Reconnaissance data sent via HTTP POST to C2

**C2 beacon pattern:** GET requests every 50-60 seconds with HWID-parameterized URL paths for victim-specific payload delivery.

**UAC elevation:** Attempts privilege escalation via `ShellExecuteW` with `runas` verb.

### 3. C2 Infrastructure

**Staging domains:**
- eorthopaedics[.]com (paths: `/feed/note`, `/feed/cew78zwvd2/`, `/feed/gnsmetadyx54/`)
- sastoro[.]com (paths: `/alpha/nrpilqjnut/`, `/alpha/dpyb8w3ycih8/`)
- web-devtools[.]com (paths: `/starlandfox`, `/x32remka`, `/dopfile`, `/file.zip`)
- zynaris[.]io
- alphabitcapital[.]info
- niggerdemon[.]in

**C2 domains:**
- windowscreenrepairnearme[.]com (path: `/command`)
- aipythondevs[.]com

**C2 IP addresses:**
- 104[.]248[.]233[.]104 (staging/C2)
- 192[.]81[.]216[.]250 (staging/C2)
- 74[.]114[.]119[.]201 (staging)
- 178[.]255[.]126[.]39 (staging)
- 193[.]149[.]176[.]254 (C2)
- 185[.]238[.]191[.]234 (C2)

**Blockchain fallback C2:** Polygon smart contract at address `0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba` with function selector `0xc659f3b8`, queried via `polygon-rpc[.]com` JSON-RPC endpoint. The returned data is XOR-decrypted with key `$m7\*rYpry3` to obtain a fallback C2 domain.

**Public IP resolution:** `api64[.]ipify[.]org`

**WLDR C2 agent communication:**
- HTTPS polling every 10 seconds to `/command` endpoint
- AES-256-CBC with HMAC-SHA256 (encrypt-then-MAC)
- PBKDF2-SHA256 key derivation with 5,000 iterations
- Protocol version tag `WSv1` for MAC computation
- Hardcoded session password: `odg5t8mvssvh`
- All encrypted payloads Base64-encoded
- Mutex: `f2j398fj239d8j23dkkskskkkkkkkkk`

**User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`

### 4. Secondary Payloads

**CastleStealer (.NET infostealer):**
- Delivered via x64 shellcode through process injection
- Targets 40+ cryptocurrency wallets (desktop cold wallets and browser extensions)
- Steals credentials from Chromium-family and Firefox browsers (SQLite databases, DPAPI-protected credentials, AES-GCM application-bound encryption)
- Exfiltrates Discord sessions, Telegram sessions, and Steam credentials
- Clipboard monitoring for cryptocurrency addresses
- Russian locale exclusion check (does not execute on Russian-language systems)
- Hardcoded build expiry timestamp for containment
- Exfiltration via Telegram bots: `8384531459` ("skuefq_bot") and `7993597060` ("komandastuk_bot")
- Telegram channel: "stuk komanda" (created June 5, 2025)

**Remcos RAT (referred to as "Remka"):**
- Delivered via x32 shellcode through APC injection
- Commercial RAT for persistent remote access

### 5. Anti-Forensics / Evasion Techniques

**Sandbox detection:**
- Checks for hardcoded username `WDAGUtilityAccount` (Windows Defender Application Guard)
- Checks for hostnames associated with analysis environments (Cuckoo, Any.run, Joe Sandbox, Hybrid Analysis)
- Zone.Identifier alternate data stream check on Downloads folder

**Defense bypasses (WLDR):**
- AMSI bypass: `AmsiScanBuffer` patching in `amsi.dll`
- ETW bypass: `EtwEventWrite` patching in `ntdll.dll`
- Fallback via `VirtualProtect` memory page protection modification

**Process injection techniques:**
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- Asynchronous Procedure Call (APC) injection for shellcode execution
- Reflective PE injection for .NET binaries
- `ICorRuntimeHost` COM interface for .NET CLR loading
- PowerShell Runspace for script execution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| MobaXterm | MobaXterm_v26.1.exe | Trojanized installer bundled with Starland RAT |
| Cisco WebEx | WebEx_Client.exe | Trojanized installer bundled with Starland RAT |
| Zoom | Zoom installer | Trojanized installer bundled with Starland RAT |
| DBeaver CE | dbeaver-ce-windows-x86_64.exe | Trojanized installer bundled with Starland RAT |
| Faceit | FaceitInstaller_x64.exe | Trojanized installer bundled with Starland RAT |

### File System

| Platform | Path / Artifact | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Windows | Trojanized installers | 6ca7a458985350ac082a9c9820d7f8d39128a4c4bda2f5d32f169a45b7b22bc6 | Trojan Installer |
| Windows | Trojanized installers | 6ae334ce60d1a9b7fb96d1d0d0eda5ec7c2c31d3f0cf3e4d7e3056504d50043d | Trojan Installer |
| Windows | Trojanized installers | 1a01ad25712d306f27f526332fdccf959f2de53207b54e4e80f60faa804d6cb6 | Trojan Installer |
| Windows | Trojanized installers | ddcf66ecc61dc6b8cd36748d284d8cb45a470201b5373dd2bfc47700c7da32e1 | Trojan Installer |
| Windows | Trojanized installers | 603fd9724de346a06e00c1b8502c2ac1180812a18bbf30032dab8d469e5c18e1 | Trojan installer |
| Windows | Trojanized installers | f4491736743a16f1278b8ba01649ee93343764e35ae5e1c0d5e0c0e1d7e32c14 | Trojan installer |
| Windows | Malicious HTA files | 2c7a99f137efd718f89cf8b260379c99af89ea1939568df09314918f2c5999a3 | Malicious HTA |
| Windows | Malicious HTA files | 5b9bf7957a9f8869c87ace1a6d76b48e2623073e72739ad0636b5dfa4bb2e0c3 | Malicious HTA |
| Windows | Malicious HTA files | 7dc77a5abab119960fbe42b1535c957020cce1b8e0a3cf58d4eddc51b5bf9940 | Malicious HTA |
| Windows | Malicious HTA files | 36e3838d07978f49ebe6546d57d2f311b8d6566558bcd58448e921c988cc346a | Malicious HTA |
| Windows | Malicious HTA files | 575ce92c473e6d47810321e309a4e29dd7f52f4152526b0bdca80f54b53aed2f | Malicious HTA |
| Windows | Malicious HTA files | 964256d3259b6e0c701ec04116c45cf0ec381c1c209dc29b09a7930cd7a4810b | Malicious HTA |
| Windows | Malicious HTA files | a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9 | Malicious HTA |
| Windows | Batch script dropper | a32ac345e39cb7606322e2155bd7b4d6941c1678619e48d1f14d9301ee53e6c0 | Windows batch script |
| Windows | Malicious package | 2751281d3800d82ecd3fad7c1d2293f3b947875a343b0672b4f4024a261165d2 | Malicious package ZIP |
| Windows | Python scripts | 47dedb08385449d48d8b6543030310317c92cddafa25e14ee0cb9a32d53ced5c | Python scripts |
| Windows | LICENSE.txt (compiled Python loader) | 162e436f18fe6099c57855c8d63fd747493624e87702dc749b242eb9a6b758ca | Starland RAT |
| Windows | PowerShell scripts | 451ac8ca34d5bcdfe476465f69eb517b2608f267c7e8d69f8ef36197a6f1d949 | PowerShell script |
| Windows | PowerShell scripts | 365024336c7681ac0854321ac6c140a245b9593285da02d2a590124cdc592370 | PowerShell script |
| Windows | PowerShell scripts | a080b5380ccc8fc40b24c02151d305efc32d931dc547881e01a2e6f2b070c7dc | PowerShell Script |
| Windows | PowerShell scripts | 17e41d66ebfd56edc960f58f4285697ceceaa812514bb15092672c747979896e | PowerShell Script |
| Windows | PowerShell scripts | f8da52ff98e66b137b5d31908f0a5d0fa1eb446034337f8bba3d5bba60f586be | PowerShell script |
| Windows | WLDR C2 agent | d52540621dec5ed56cac8532f0e4fe10a7575c3e17e984f59646909fa587dd35 | WLDR C2 agent |
| Windows | C2 response | a59742d3086924c5f511d248df01601bfbf723359590fb3f3ba355f2792cc455 | JSON C2 response |
| Windows | Shellcode loaders | 2a27b3415114b874da295c19cce5227a8b8d9525cc2da331034a1f45528eecae | Shellcode loader |
| Windows | Shellcode loaders | 1b46f761719dce44baa2d7b417c5214fc41c080f7f9ba485e7e489d949097f1f | Shellcode loader |
| Windows | CastleStealer | 896185a89bd7eb0520b03fdcfb8db0be98b43cf15f14041d73b23d3988c1bcab | CastleStealer infostealer |
| Windows | Remcos RAT | a1835d333ac3db961a8ff1f4864e3c10a6f73a872c040599091390a009ac7804 | Remcos RAT (Remka) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | eorthopaedics[.]com | Staging/C2 - hosts HTA files and PowerShell payloads |
| Domain | sastoro[.]com | Staging/C2 - hosts PowerShell payloads |
| Domain | zynaris[.]io | Staging |
| Domain | alphabitcapital[.]info | Staging |
| Domain | niggerdemon[.]in | Staging |
| Domain | web-devtools[.]com | Staging - hosts shellcode and archives |
| Domain | aipythondevs[.]com | C2 |
| Domain | windowscreenrepairnearme[.]com | C2 - WLDR command endpoint |
| IP | 104[.]248[.]233[.]104 | Staging/C2 |
| IP | 192[.]81[.]216[.]250 | Staging/C2 |
| IP | 74[.]114[.]119[.]201 | Staging |
| IP | 178[.]255[.]126[.]39 | Staging |
| IP | 193[.]149[.]176[.]254 | C2 |
| IP | 185[.]238[.]191[.]234 | C2 |
| URL | hxxps://eorthopaedics[.]com/feed/note | HTA staging |
| URL | hxxps://web-devtools[.]com/starlandfox | x64 shellcode (CastleStealer) |
| URL | hxxps://web-devtools[.]com/x32remka | x32 shellcode (Remcos RAT) |
| URL | hxxps://web-devtools[.]com/dopfile | Compressed archive payload |
| URL | hxxps://web-devtools[.]com/file[.]zip | Malicious package ZIP |
| URL | hxxps://eorthopaedics[.]com/feed/cew78zwvd2/ | C2 endpoint |
| URL | hxxps://eorthopaedics[.]com/feed/gnsmetadyx54/ | C2 endpoint |
| URL | hxxps://sastoro[.]com/alpha/nrpilqjnut/ | C2 endpoint |
| URL | hxxps://sastoro[.]com/alpha/dpyb8w3ycih8/ | C2 endpoint |
| URL | hxxps://windowscreenrepairnearme[.]com/command | WLDR C2 command endpoint |
| Blockchain | 0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba | Polygon smart contract for fallback C2 |

### Behavioral

- **Mshta.exe execution** of remotely hosted HTA files from staging domains via ClickFix social engineering
- **pythonw.exe executing LICENSE.txt** - compiled Python loader masquerading as a license file
- **Scheduled task creation** with naming pattern `PythonLauncher-{3 random chars}` (AtLogOn trigger, RunLevel Highest)
- **Registry Run key** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyApp` pointing to mshta.exe
- **Startup folder LNK** shortcut targeting pythonw.exe with LICENSE.txt argument
- **HTTP GET beaconing** every 50-60 seconds (Starland RAT) or every 10 seconds (WLDR)
- **AMSI/ETW patching** of AmsiScanBuffer in amsi.dll and EtwEventWrite in ntdll.dll
- **Process injection** via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread and APC injection
- **Mutex creation:** `f2j398fj239d8j23dkkskskkkkkkkkk` (WLDR agent)
- **Telegram exfiltration** via bot IDs 8384531459 and 7993597060

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | ClickFix social engineering entices user to run command that downloads HTA |
| T1218.005 | System Binary Proxy Execution: Mshta | mshta.exe executes weaponized HTA files from staging domains |
| T1059.001 | Command and Scripting Interpreter: PowerShell | WLDR C2 agent is PowerShell-based; extensive PS reconnaissance commands |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | HTA files contain embedded VBScript |
| T1059.006 | Command and Scripting Interpreter: Python | Starland RAT is a compiled Python loader |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MyApp Run key persistence via mshta.exe |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | Startup folder LNK shortcut for pythonw.exe |
| T1053.005 | Scheduled Task/Job: Scheduled Task | PythonLauncher-{3 chars} scheduled task at logon |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption with multiple keys (0xC6, "helo1", "$m7\*rYpry3") |
| T1082 | System Information Discovery | systeminfo, hardware UUID, memory capacity enumeration |
| T1087.002 | Account Discovery: Domain Account | net user /dom, nltest /dclist for AD reconnaissance |
| T1518.001 | Software Discovery: Security Software | Get-CimInstance AntiVirusProduct query |
| T1055.001 | Process Injection: Dynamic-link Library Injection | VirtualAllocEx/WriteProcessMemory/CreateRemoteThread injection |
| T1055.004 | Process Injection: Asynchronous Procedure Call | APC injection for shellcode execution |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass (AmsiScanBuffer patch) and ETW bypass (EtwEventWrite patch) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS C2 communications with Chrome UA mimicry |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC with HMAC-SHA256 for WLDR C2 |
| T1008 | Fallback Channels | Blockchain-based fallback C2 via Polygon smart contract |
| T1105 | Ingress Tool Transfer | curl-based download of additional payloads from staging |
| T1005 | Data from Local System | Credential and cryptocurrency wallet theft |
| T1115 | Clipboard Data | Clipboard monitoring for cryptocurrency addresses |
| T1539 | Steal Web Session Cookie | Browser session and credential extraction |
| T1041 | Exfiltration Over C2 Channel | Stolen data exfiltrated via Telegram bots |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Starland RAT loader disguised as LICENSE.txt |

## Impact Assessment

The campaign primarily targets individual users and small organizations seeking popular software tools. The impact includes:
- **Credential theft:** Browser-stored credentials, DPAPI-protected secrets, and AES-GCM application-bound encrypted data from Chromium and Firefox browsers
- **Cryptocurrency loss:** Over 40 wallet types targeted (desktop cold wallets and browser extensions)
- **Session hijacking:** Discord, Telegram, and Steam session data stolen
- **Persistent access:** Multiple persistence mechanisms and Remcos RAT deployment enable long-term access
- **Geographic scope:** Predominantly United States; secondary targets in Germany, Romania, and Venezuela

## Detection & Remediation

### Immediate Detection

Check for the following indicators:

```powershell
# Check for WLDR mutex
Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -match "f2j398fj239d8j23dkkskskkkkkkkkk" }

# Check for PythonLauncher scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -match "PythonLauncher-" }

# Check for MyApp Run key persistence
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyApp" -ErrorAction SilentlyContinue

# Check for pythonw.exe executing LICENSE.txt
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1} | Where-Object { $_.Message -match "pythonw.exe.*LICENSE.txt" }

# Check DNS logs for C2 domains
Get-DnsClientCache | Where-Object { $_.Entry -match "windowscreenrepairnearme|aipythondevs|eorthopaedics|sastoro|web-devtools" }
```

### Remediation

1. **Contain:** Isolate affected systems from the network immediately
2. **Eradicate:**
   - Remove registry Run key `HKCU\...\Run\MyApp`
   - Delete PythonLauncher scheduled tasks
   - Remove Startup folder LNK shortcuts
   - Kill processes executing pythonw.exe with LICENSE.txt
   - Scan and remove CastleStealer and Remcos RAT artifacts
3. **Recover:**
   - Rotate all credentials stored in browsers
   - Transfer cryptocurrency assets to new wallets with fresh keys
   - Revoke Discord, Telegram, and Steam sessions
   - Reset DPAPI master keys if compromise is confirmed
4. **Monitor:** Deploy detection rules (below) to catch re-infection attempts

### Long-Term Hardening

- Block execution of mshta.exe via AppLocker/WDAC for non-administrative users
- Deploy PowerShell Constrained Language Mode to limit AMSI/ETW bypass effectiveness
- Enable ScriptBlock logging and Module logging for PowerShell
- Block known staging and C2 domains/IPs at the network perimeter
- Implement application whitelisting to prevent trojanized installer execution
- Monitor for suspicious Python installations in non-standard paths

## Detection Rules

These detections target UAT-11795 campaign artifacts at PoC/advisory-specific altitude: known domains, C2 paths, mutex, persistence patterns, and malware strings. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles =/= fires -- verify in your pipeline.

### Sigma: Mshta HTA Execution from UAT-11795 Staging Domains

Detects mshta.exe executing HTA files from known UAT-11795 staging domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Rule keys on specific known-malicious domains in mshta command line — highly distinctive, no benign overlap expected. -->
```yaml
title: UAT-11795 Starland RAT - Mshta HTA Execution via ClickFix
id: 8e3f1a27-4b5c-4d9e-a1f0-2c8b7d6e5f3a
status: experimental
description: >
    Detects mshta.exe executing remotely hosted HTA files from staging domains
    associated with UAT-11795 Starland RAT campaign.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
    - https://github.com/Cisco-Talos/IOCs/tree/main/2026/07
author: Actioner
date: 2026/07/16
tags:
    - attack.t1218.005
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_mshta:
        Image|endswith: '\mshta.exe'
    selection_domains:
        CommandLine|contains:
            - 'eorthopaedics.com'
            - 'sastoro.com'
            - 'zynaris.io'
            - 'alphabitcapital.info'
            - 'web-devtools.com'
    condition: selection_mshta and selection_domains
falsepositives:
    - Unlikely - these are known malicious domains
level: high
```

### Sigma: Pythonw Executing LICENSE.txt Loader

Detects pythonw.exe executing a file named LICENSE.txt, the distinctive Starland RAT loader disguise.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. pythonw.exe with LICENSE.txt as argument is a unique campaign artifact — no legitimate software uses this pattern. -->
```yaml
title: UAT-11795 Starland RAT - Pythonw Executing LICENSE.txt Loader
id: 2d9e4f1b-7a3c-5e8d-b2f1-4a6c8d7e9f0b
status: experimental
description: >
    Detects pythonw.exe executing a file named LICENSE.txt, consistent with
    Starland RAT's compiled Python loader disguised as a license file.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1059.006
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pythonw.exe'
        CommandLine|endswith: 'LICENSE.txt'
    condition: selection
falsepositives:
    - Legitimate Python applications using LICENSE.txt as an argument is extremely uncommon
level: high
```

### Sigma: PythonLauncher Scheduled Task Persistence

Detects scheduled task creation matching the `PythonLauncher-{3 chars}` naming pattern used for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Task name pattern is distinctive to this campaign. -->
```yaml
title: UAT-11795 Starland RAT - PythonLauncher Scheduled Task Persistence
id: 5c8d2e7f-9a1b-4f3d-c6e0-7b4a8d5f1e2c
status: experimental
description: >
    Detects creation of scheduled tasks matching the naming pattern
    PythonLauncher-{3 chars} used by Starland RAT for persistence.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\schtasks.exe'
        CommandLine|contains: 'PythonLauncher-'
    condition: selection
falsepositives:
    - Legitimate software using PythonLauncher task naming convention
level: high
```

### Sigma: Registry Run Key Persistence via MyApp

Detects mshta.exe-based persistence via a registry Run key named MyApp.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Combination of MyApp value name + mshta in Details is distinctive. -->
```yaml
title: UAT-11795 Starland RAT - Registry Run Key Persistence via MyApp
id: 3f8a2b4c-6d7e-9f0a-b1c2-5e4d3a7f8b9c
status: experimental
description: >
    Detects mshta.exe-based persistence via a registry Run key named MyApp,
    consistent with UAT-11795 HTA persistence mechanism.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1547.001
    - attack.t1218.005
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\MyApp'
        Details|contains: 'mshta'
    condition: selection
falsepositives:
    - Legitimate applications using the generic MyApp run key name with mshta
level: high
```

### Sigma: WLDR C2 Agent Mutex in Command Line

Detects the hardcoded WLDR C2 agent mutex string in process command lines.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Mutex is a 33-char unique string — no benign collision expected. Note: mutex may appear in CreateMutex API call rather than command line; this rule catches it when visible in PowerShell ScriptBlock or command-line logging. -->
```yaml
title: UAT-11795 WLDR C2 Agent Mutex Creation
id: 1a7b3c4d-5e6f-8a9b-d0c1-2e3f4a5b6c7d
status: experimental
description: >
    Detects creation of the mutex f2j398fj239d8j23dkkskskkkkkkkkk associated
    with the WLDR C2 agent used by UAT-11795.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1106
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'f2j398fj239d8j23dkkskskkkkkkkkk'
    condition: selection
falsepositives:
    - None known
level: critical
```

### Sigma: AMSI and ETW Bypass via Script Block Logging

Detects PowerShell script blocks referencing AmsiScanBuffer or EtwEventWrite patching, consistent with WLDR evasion.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. AMSI/ETW bypass strings are used by multiple offensive tools (Cobalt Strike, manual red team), not exclusive to WLDR — medium confidence. -->
```yaml
title: UAT-11795 WLDR - AMSI and ETW Bypass Indicators
id: 9b0c1d2e-3f4a-5b6c-7d8e-9f0a1b2c3d4e
status: experimental
description: >
    Detects PowerShell script block content referencing AmsiScanBuffer or
    EtwEventWrite patching, consistent with WLDR C2 agent evasion techniques.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1562.001
logsource:
    category: ps_script
    product: windows
detection:
    selection_amsi:
        ScriptBlockText|contains|all:
            - 'AmsiScanBuffer'
            - 'amsi.dll'
    selection_etw:
        ScriptBlockText|contains|all:
            - 'EtwEventWrite'
            - 'ntdll'
    condition: selection_amsi or selection_etw
falsepositives:
    - Security research and testing tools
    - Red team exercises
level: high
```

### Sigma: DNS Query to Known UAT-11795 C2 Domains

Detects DNS queries to all known UAT-11795 campaign domains (staging and C2).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Domain list from Cisco Talos IOC repository. All confirmed malicious. -->
```yaml
title: UAT-11795 Campaign - DNS Query to Known C2 Domains
id: 4e5f6a7b-8c9d-0e1f-2a3b-4c5d6e7f8a9b
status: experimental
description: >
    Detects DNS queries to domains associated with UAT-11795 C2 and staging
    infrastructure used for Starland RAT and WLDR implant delivery.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
    - https://github.com/Cisco-Talos/IOCs/tree/main/2026/07
author: Actioner
date: 2026/07/16
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'eorthopaedics.com'
            - 'sastoro.com'
            - 'zynaris.io'
            - 'alphabitcapital.info'
            - 'niggerdemon.in'
            - 'web-devtools.com'
            - 'aipythondevs.com'
            - 'windowscreenrepairnearme.com'
    condition: selection
falsepositives:
    - None known - these are confirmed malicious domains
level: critical
```

### Snort: Starland RAT C2 Beacon to /feed/ Endpoint

Detects HTTP traffic to /feed/ with Chrome/138 User-Agent consistent with Starland RAT beaconing.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort not available in environment; structural check passed (correct service, sticky buffers, semicolons, required fields). -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT C2 Beacon to /feed/ Endpoint"; flow:established,to_server; http_uri; content:"/feed/", fast_pattern; http_header; content:"Chrome/138.0.0.0"; sid:2100001; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/;)
```

### Snort: WLDR C2 Agent Command Polling

Detects HTTP requests to /command on the WLDR C2 domain.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort not available; structural check passed. Keys on specific C2 domain + path combination. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 WLDR C2 Agent Command Polling"; flow:established,to_server; http_uri; content:"/command", fast_pattern; http_header; field host; content:"windowscreenrepairnearme.com"; sid:2100002; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/;)
```

### Snort: Shellcode Download from /starlandfox

Detects HTTP requests to /starlandfox on the staging domain used to serve CastleStealer shellcode.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort not available; structural check passed. Highly specific URI path + domain combination. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Shellcode Download from /starlandfox"; flow:established,to_server; http_uri; content:"/starlandfox", fast_pattern; http_header; field host; content:"web-devtools.com"; sid:2100003; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/;)
```

### Suricata: Starland RAT C2 Beacon to /feed/ Endpoint

Detects HTTP traffic to /feed/ with Chrome/138 User-Agent matching Starland RAT beacon pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Combination of /feed/ URI + Chrome/138.0.0.0 UA narrows to campaign traffic. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT C2 Beacon to /feed/ Endpoint"; flow:established,to_server; http.uri; content:"/feed/"; startswith; http.user_agent; content:"Chrome/138.0.0.0"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200001; rev:1;)
```

### Suricata: WLDR C2 Agent Command Polling

Detects HTTP requests to /command on the WLDR C2 domain windowscreenrepairnearme[.]com.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Domain + path combination is unique to this C2. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 WLDR C2 Agent Command Polling"; flow:established,to_server; http.uri; content:"/command"; http.host; content:"windowscreenrepairnearme.com"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200002; rev:1;)
```

### Suricata: Starland RAT Shellcode Download from /starlandfox

Detects download of CastleStealer x64 shellcode from the /starlandfox endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Highly specific URI + domain. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT Shellcode Download from /starlandfox"; flow:established,to_server; http.uri; content:"/starlandfox"; fast_pattern; http.host; content:"web-devtools.com"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200003; rev:1;)
```

### Suricata: Remcos RAT Shellcode Download from /x32remka

Detects download of Remcos RAT x32 shellcode from the /x32remka endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Highly specific URI + domain. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Remcos RAT Shellcode Download from /x32remka"; flow:established,to_server; http.uri; content:"/x32remka"; fast_pattern; http.host; content:"web-devtools.com"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200004; rev:1;)
```

### Suricata: DNS Query to C2 Domains (4 rules)

Detects DNS queries to primary UAT-11795 C2 and staging domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (all 8 rules in file validated together). Known-malicious domains from Talos IOC repo. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 DNS Query to C2 Domain windowscreenrepairnearme.com"; dns.query; content:"windowscreenrepairnearme.com"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 DNS Query to C2 Domain aipythondevs.com"; dns.query; content:"aipythondevs.com"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 DNS Query to Staging Domain eorthopaedics.com"; dns.query; content:"eorthopaedics.com"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200007; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 DNS Query to Staging Domain web-devtools.com"; dns.query; content:"web-devtools.com"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-16; sid:2200008; rev:1;)
```

### YARA: Starland RAT Strings

Detects Starland RAT via characteristic XOR keys, C2 paths, and blockchain contract artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive (published strings: helo1, /starlandfox, windowscreenrepairnearme.com, /dopfile, 0xc659f3b8); quiet on negative (benign text). Strings sourced from Talos report. -->
```yara
rule Malware_StarlandRAT_Strings
{
    meta:
        description = "Detects Starland RAT Python loader via characteristic strings including XOR key, beacon paths, and encryption markers"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $xor_key1 = "helo1" ascii wide
        $xor_key2 = "$m7\\*rYpry3" ascii wide
        $uri1 = "/starlandfox" ascii wide
        $uri2 = "/x32remka" ascii wide
        $uri3 = "/dopfile" ascii wide
        $c2_1 = "windowscreenrepairnearme.com" ascii wide
        $c2_2 = "aipythondevs.com" ascii wide
        $beacon = "/feed/" ascii wide
        $polygon = "0xc659f3b8" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide

    condition:
        3 of them
}
```

### YARA: WLDR C2 Agent

Detects WLDR PowerShell C2 agent via unique mutex, protocol tag, and hardcoded encryption password.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive (published strings: mutex, WSv1, odg5t8mvssvh, /command, AmsiScanBuffer, EtwEventWrite); quiet on negative. Hash d52540621dec5ed56cac8532f0e4fe10a7575c3e17e984f59646909fa587dd35. -->
```yara
rule Malware_WLDR_C2_Agent
{
    meta:
        description = "Detects WLDR PowerShell C2 agent via mutex, protocol version tag, and encryption markers"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        hash = "d52540621dec5ed56cac8532f0e4fe10a7575c3e17e984f59646909fa587dd35"
        severity = "high"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $proto = "WSv1" ascii wide
        $pwd = "odg5t8mvssvh" ascii wide
        $c2path = "/command" ascii wide
        $amsi1 = "AmsiScanBuffer" ascii wide
        $etw1 = "EtwEventWrite" ascii wide

    condition:
        3 of them
}
```

### YARA: CastleStealer Strings

Detects CastleStealer .NET infostealer via Telegram bot identifiers and sandbox detection strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive (published strings: skuefq_bot, komandastuk_bot, WDAGUtilityAccount, Chrome/138.0.0.0); quiet on negative. Hash 896185a89bd7eb0520b03fdcfb8db0be98b43cf15f14041d73b23d3988c1bcab. -->
```yara
rule Malware_CastleStealer_Strings
{
    meta:
        description = "Detects CastleStealer .NET infostealer via characteristic Russian language artifacts and crypto wallet targeting"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        hash = "896185a89bd7eb0520b03fdcfb8db0be98b43cf15f14041d73b23d3988c1bcab"
        severity = "high"

    strings:
        $tg_bot1 = "skuefq_bot" ascii wide
        $tg_bot2 = "komandastuk_bot" ascii wide
        $tg_channel = "stuk komanda" ascii wide
        $sandbox1 = "WDAGUtilityAccount" ascii wide nocase
        $ua = "Chrome/138.0.0.0" ascii wide

    condition:
        2 of them
}
```

## Lessons Learned

1. **Blockchain-based fallback C2 is emerging:** UAT-11795's use of a Polygon smart contract for resilient C2 domain resolution demonstrates that financially motivated actors, not just APTs, are adopting decentralized infrastructure for resilience against takedowns.

2. **ClickFix continues to be effective:** The social engineering technique of prompting users to copy-paste commands remains an effective initial access vector, bypassing email-based security controls and relying on user trust in the software download process.

3. **Multi-stage, multi-tool chains complicate detection:** The campaign uses at least four distinct malware families (HTA dropper, Starland RAT, WLDR, CastleStealer/Remcos) with different implementation languages (VBScript, Python, PowerShell, .NET, C++), requiring detection coverage across multiple log sources and rule types.

4. **AMSI/ETW bypass is now standard:** The routine inclusion of AMSI and ETW bypasses in commodity malware underscores the need for defense-in-depth beyond endpoint script monitoring, including network-level detection of C2 communications.

## Sources

- [Cisco Talos Blog - UAT-11795 Deploys Novel Starland RAT and Bespoke WLDR C2 Implant](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/) -- primary technical analysis
- [Cisco Talos IOC Repository (July 2026)](https://github.com/Cisco-Talos/IOCs/tree/main/2026/07) -- SHA256 hashes, domains, IPs, URLs

---
*Report generated by Actioner*
