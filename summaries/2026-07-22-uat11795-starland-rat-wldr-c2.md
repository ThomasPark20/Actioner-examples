# Technical Analysis Report: UAT-11795 -- Starland RAT and WLDR C2 Implant (2026-07-22)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-22
Version: 1.0 (DRAFT)

## Executive Summary

UAT-11795 is a Russian-speaking, financially motivated threat actor tracked by Cisco Talos, active since at least June 2025, conducting an opportunistic campaign targeting US and European users through trojanized software installers. The actor distributes weaponized versions of popular software (MobaXterm, WebEx, Zoom, DBeaver, FACEIT) via ClickFix social engineering to deploy a multi-stage infection chain culminating in a Python-based remote access trojan ("Starland RAT") and a PowerShell-based memory-only C2 implant ("WLDR agent"). The campaign is financially motivated, targeting browser credentials and 40+ cryptocurrency wallet applications.

The infection chain begins with mshta.exe executing a weaponized HTA file containing VBScript with Russian-language developer comments, which drops a batch file that downloads the trojanized installer and sends a Telegram beacon. The Starland RAT performs extensive reconnaissance, establishes persistence via scheduled tasks and Startup folder LNK files, and communicates with C2 infrastructure using XOR encryption (key "helo1") over HTTP. A blockchain-based fallback C2 mechanism queries a Polygon smart contract for an encrypted backup domain. The WLDR agent, delivered as a second-stage payload via Starland RAT, operates entirely in memory using AES-256-CBC encryption with PBKDF2-SHA256 key derivation (hardcoded password "odg5t8mvssvh") and supports concurrent PowerShell Runspace execution.

## Background: UAT-11795 Campaign

Cisco Talos identified UAT-11795 as a Russian-speaking actor based on Cyrillic developer comments embedded in the VBScript HTA dropper. The actor operates with a volume-driven, opportunistic distribution model targeting multiple victim profiles simultaneously across developers, IT administrators, gamers, and enterprise collaboration users. Infrastructure domains are chosen to blend into legitimate traffic categories: developer tooling portals, technology startups, and hijacked healthcare services. The campaign demonstrates sophisticated capabilities including custom malware development, smart contract-based C2 resilience, and commercial tool integration (Remcos RAT). Additional payloads in the actor's arsenal include CastleStealer (a credential stealer with Russian locale exclusion and hardcoded build expiry) and Remcos RAT.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-06 (est.) | Campaign begins targeting US and European users |
| 2025-06-05 | Telegram channel "stuk komanda" created for operator notifications |
| 2026-07-16 | Cisco Talos publishes technical analysis of UAT-11795 campaign |

## Root Cause: ClickFix Social Engineering via Trojanized Installers

The initial access vector relies on ClickFix social engineering, where victims are tricked into executing a command that downloads a weaponized HTA file via mshta.exe. The HTA file contains embedded VBScript that drops a Windows batch file to the user's temp folder. This batch file downloads a trojanized installer from staging infrastructure (eorthopaedics[.]com or sastoro[.]com), sends a Telegram notification beacon to bot ID 8384531459 (skuefq_bot), and establishes HKCU Run key persistence pointing back to mshta.exe for subsequent execution.

## Technical Analysis of the Malicious Payload

### 1. HTA Dropper and Batch File Stage

The weaponized HTA file is hosted on actor-controlled domains (zynaris[.]io) and executed via `mshta.exe`. It contains VBScript with a Russian-language developer comment ("Dobavlenie komandy v avtozapusk dlya tekushchego pol'zovatelya" -- "Adding command to autostart for current user"). The VBScript drops a batch file to the user profile application temp folder, which:

1. Downloads the trojanized installer from staging domains via C2 URL paths `/feed/` or `/alpha/`
2. Sends a Telegram beacon to bot 8384531459 confirming successful execution
3. Creates a Registry Run key persistence entry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value "MyApp" pointing to mshta.exe

### 2. Trojanized Installer and Python Loader

The trojanized installer uses an NSIS script to execute a bundled Python runtime (`pythonw.exe`) with a compiled Python loader disguised as `LICENSE.txt`. The loader contains extensive junk/obfuscation functions but only six lines of actual execution logic. It decrypts the embedded Starland RAT payload using XOR with key byte 0xC6 (198 decimal) and executes it in memory.

Observed trojanized installer filenames:
- `MobaXterm_v26.1.exe`
- `WebEx_Client.exe`
- Zoom installer
- `dbeaver-ce-windows-x86_64.exe`
- `FaceitInstaller_x64.exe`

### 3. Starland RAT Core

The Starland RAT is a Python-based remote access trojan that performs the following after execution:

**Anti-Analysis / Sandbox Detection:**
- Username comparison against `WDAGUtilityAccount` and recognized service accounts
- Hostname validation against known sandbox hostnames (Cuckoo, Any.Run, Joe Sandbox, Hybrid Analysis)
- Zone.Identifier alternate data stream verification on downloaded files

**AMSI/ETW Bypass:**
- Runtime API resolution to locate `AmsiScanBuffer` in amsi.dll and `EtwEventWrite` in ntdll.dll
- Memory patching via `VirtualProtect` to disable both security mechanisms

**Persistence (dual mechanism):**
- Scheduled task via PowerShell `New-ScheduledTask` with randomized names following the pattern `PythonLauncher-{3 random characters}`
- Startup folder LNK shortcut targeting `pythonw.exe` with `LICENSE.txt` as argument

**UAC Elevation:**
- `ShellExecuteW` with `runas` verb for privilege escalation attempts

**System Reconnaissance:**
```
Get-CimInstance -Class Win32_ComputerSystemProduct.UUID
wmic memorychip get Capacity
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
```

For domain-joined hosts:
```
Get-WmiObject Win32_ComputerSystem.Domain
whoami && systeminfo && net user {USERNAME} /dom && nltest /dclist
```

For workgroup hosts: `whoami /all`

**Credential and Wallet Theft:**
- Full Chromium browser family and Firefox credential extraction via direct SQLite database access
- Decryption support for both legacy DPAPI-protected credentials and AES-GCM application-bound encryption
- Enumeration of 40+ desktop and browser extension cryptocurrency wallets
- Targeting of Discord, Telegram session files, and Steam credentials

**Screenshot Capture:**
- Desktop screenshot in PNG format, Base64-encoded, deleted after transmission

**C2 Communication (Starland RAT):**
- HTTP GET polling every 50-60 seconds with minimal JSON payload
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`
- XOR encryption with key `helo1` + Base64 encoding
- HWID appended as final URL path component
- HTTP POST for initial registration with encrypted reconnaissance data

**C2 Command Table:**

| Command | Action |
|---------|--------|
| shellexecute | Run arbitrary shell command via `cmd /c` or PowerShell |
| x32 | Execute 32-bit shellcode via APC injection |
| x64 | Execute 64-bit shellcode via APC injection |
| download | Download EXE/MSI/DLL/ZIP to %TEMP% and execute |
| HTTP 403 | Kill switch triggering self-deletion |

**Process Injection APIs (resolved via ctypes from kernel32.dll):**
- `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- `VirtualProtectEx`, `CreateProcessA`, `QueueUserAPC`, `ResumeThread`
- Custom Structure subclasses for `SECURITY_ATTRIBUTES`, `STARTUPINFO`, `PROCESS_INFORMATION`

**Blockchain Fallback C2:**
- If primary C2 fails, queries Polygon smart contract at address `0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba`
- Function selector: `0xc659f3b8`
- RPC endpoint: polygon-rpc[.]com
- XOR decryption key for fallback domain: `$m7*rYpry3`

**Telegram Pre-Registration Beacon:**
- Sends victim IP, HWID, and wallet inventory to bot 8384531459 (skuefq_bot) and/or 7993597060 (komandastuk_bot)
- Channel name: "stuk komanda" (created June 5, 2025)

### 4. WLDR C2 Agent

The WLDR agent is delivered as a second-stage payload through the Starland RAT `shellexecute` command, which executes a curl command to download a PowerShell stager script from C2 infrastructure. The WLDR chain consists of multiple stages:

**Stage 1 (Stager):** PowerShell script with runtime alias creation, obfuscated string construction for .NET Base64/byte conversion, and dynamically computed XOR key for decrypting the next stage.

**Stage 2 (Downloader):** Extracts C: drive volume serial number, converts hexadecimal to decimal to derive an HWID, constructs HWID-parameterized C2 URLs, and derives a 64-byte key from the plaintext password. Injects C2 URL and session password into PowerShell global scope variables.

**Stage 3 (Agent):** Memory-only PowerShell C2 implant with the following characteristics:
- **Mutex:** `f2j398fj239d8j23dkkskskkkkkkkkk` (prevents duplicate instances)
- **Encryption:** AES-256-CBC with HMAC-SHA256 authentication
- **Key Derivation:** PBKDF2-SHA256 with random salt (5,000 iterations)
- **Hardcoded Password:** `odg5t8mvssvh`
- **Protocol Version:** WSv1 bound to every MAC computation
- **Beaconing:** HTTPS polling every 10 seconds with Chrome v124 mimicking headers
- **Connection Retry:** 30 seconds on failure
- **JSON Response Structure:** Base64-encoded salt, initialization vector, encrypted data, and authentication tag fields

**WLDR Execution Engine:**
- PowerShell Runspace engine supporting up to 10 concurrent threads with synchronous event handlers on output/error/warning streams
- Fallback to PowerShell background jobs for failed Runspace initialization
- .NET CLR loading through `ICorRuntimeHost` COM interface for reflective PE injection

**WLDR Reconnaissance (post-handshake):**
- WMI queries for antivirus products, network adapters, OS version/build, domain membership, CPU, RAM, administrative status, UAC policy
- Hardware identifier derivation from C: drive volume serial number
- System locale and region detection

### 5. Additional Payloads

**CastleStealer:** TCP socket-based credential stealer with Russian locale exclusion check and hardcoded build expiry timestamp. Supports full Chromium and Firefox credential decryption including both legacy DPAPI and AES-GCM application-bound encryption. Exfiltrates via TCP socket to attacker infrastructure.

**Remcos RAT:** Commercial RAT deployed as an alternative implant in the UAT-11795 arsenal.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation: URLs use `hxxps://`, domains use `[.]`, IP addresses use `[.]`.

### File System

| SHA256 Hash | Description |
|-------------|-------------|
| `6ca7a458985350ac082a9c9820d7f8d39128a4c4bda2f5d32f169a45b7b22bc6` | Campaign artifact |
| `6ae334ce60d1a9b7fb96d1d0d0eda5ec7c2c31d3f0cf3e4d7e3056504d50043d` | Campaign artifact |
| `1a01ad25712d306f27f526332fdccf959f2de53207b54e4e80f60faa804d6cb6` | Campaign artifact |
| `ddcf66ecc61dc6b8cd36748d284d8cb45a470201b5373dd2bfc47700c7da32e1` | Campaign artifact |
| `603fd9724de346a06e00c1b8502c2ac1180812a18bbf30032dab8d469e5c18e1` | Campaign artifact |
| `f4491736743a16f1278b8ba01649ee93343764e35ae5e1c0d5e0c0e1d7e32c14` | Campaign artifact |
| `2c7a99f137efd718f89cf8b260379c99af89ea1939568df09314918f2c5999a3` | Campaign artifact |
| `5b9bf7957a9f8869c87ace1a6d76b48e2623073e72739ad0636b5dfa4bb2e0c3` | Campaign artifact |
| `7dc77a5abab119960fbe42b1535c957020cce1b8e0a3cf58d4eddc51b5bf9940` | Campaign artifact |
| `36e3838d07978f49ebe6546d57d2f311b8d6566558bcd58448e921c988cc346a` | Campaign artifact |
| `575ce92c473e6d47810321e309a4e29dd7f52f4152526b0bdca80f54b53aed2f` | Campaign artifact |
| `964256d3259b6e0c701ec04116c45cf0ec381c1c209dc29b09a7930cd7a4810b` | Campaign artifact |
| `a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9` | Campaign artifact |
| `a32ac345e39cb7606322e2155bd7b4d6941c1678619e48d1f14d9301ee53e6c0` | Campaign artifact |
| `2751281d3800d82ecd3fad7c1d2293f3b947875a343b0672b4f4024a261165d2` | Campaign artifact |
| `47dedb08385449d48d8b6543030310317c92cddafa25e14ee0cb9a32d53ced5c` | Campaign artifact |
| `162e436f18fe6099c57855c8d63fd747493624e87702dc749b242eb9a6b758ca` | Campaign artifact |
| `451ac8ca34d5bcdfe476465f69eb517b2608f267c7e8d69f8ef36197a6f1d949` | Campaign artifact |
| `365024336c7681ac0854321ac6c140a245b9593285da02d2a590124cdc592370` | Campaign artifact |
| `a080b5380ccc8fc40b24c02151d305efc32d931dc547881e01a2e6f2b070c7dc` | Campaign artifact |
| `17e41d66ebfd56edc960f58f4285697ceceaa812514bb15092672c747979896e` | Campaign artifact |
| `f8da52ff98e66b137b5d31908f0a5d0fa1eb446034337f8bba3d5bba60f586be` | Campaign artifact |
| `d52540621dec5ed56cac8532f0e4fe10a7575c3e17e984f59646909fa587dd35` | Campaign artifact |
| `a59742d3086924c5f511d248df01601bfbf723359590fb3f3ba355f2792cc455` | Campaign artifact |
| `2a27b3415114b874da295c19cce5227a8b8d9525cc2da331034a1f45528eecae` | Campaign artifact |
| `1b46f761719dce44baa2d7b417c5214fc41c080f7f9ba485e7e489d949097f1f` | Campaign artifact |
| `896185a89bd7eb0520b03fdcfb8db0be98b43cf15f14041d73b23d3988c1bcab` | Campaign artifact |
| `a1835d333ac3db961a8ff1f4864e3c10a6f73a872c040599091390a009ac7804` | Campaign artifact |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `eorthopaedics[.]com` | Payload staging and C2 |
| Domain | `sastoro[.]com` | Payload staging and C2 |
| Domain | `zynaris[.]io` | HTA stager and trojanized installer hosting |
| Domain | `web-devtools[.]com` | Shellcode payload hosting |
| Domain | `aipythondevs[.]com` | Starland RAT primary C2 |
| Domain | `windowscreenrepairnearme[.]com` | Starland RAT primary C2 |
| Domain | `alphabitcapital[.]info` | Campaign infrastructure |
| IP | `104[.]248[.]233[.]104` | C2 infrastructure |
| IP | `192[.]81[.]216[.]250` | C2 infrastructure |
| IP | `74[.]114[.]119[.]201` | C2 infrastructure |
| IP | `178[.]255[.]126[.]39` | C2 infrastructure |
| IP | `193[.]149[.]176[.]254` | C2 infrastructure |
| IP | `185[.]238[.]191[.]234` | C2 infrastructure |
| URL | `hxxps://eorthopaedics[.]com/feed/note` | WLDR stager download |
| URL | `hxxps://web-devtools[.]com/starlandfox` | Shellcode payload |
| URL | `hxxps://web-devtools[.]com/x32remka` | 32-bit shellcode |
| URL | `hxxps://web-devtools[.]com/dopfile` | Compressed archive |
| URL | `hxxps://web-devtools[.]com/file[.]zip` | Archive payload |
| URL | `hxxps://eorthopaedics[.]com/feed/cew78zwvd2/` | WLDR stage chain |
| URL | `hxxps://eorthopaedics[.]com/feed/gnsmetadyx54/` | WLDR stage chain |
| URL | `hxxps://sastoro[.]com/alpha/nrpilqjnut/` | WLDR stage chain |
| URL | `hxxps://sastoro[.]com/alpha/dpyb8w3ycih8/` | WLDR stage chain |
| URL | `hxxps://windowscreenrepairnearme[.]com/command` | Starland RAT C2 |
| URL Pattern | `/feed/` | PowerShell stage chain path |
| URL Pattern | `/alpha/` | Alternative stage chain path |
| URL Pattern | `/command` | Starland RAT C2 command endpoint |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Smart Contract | `0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba` | Polygon fallback C2 resolver |
| Function Selector | `0xc659f3b8` | Smart contract query function |
| RPC Endpoint | `polygon-rpc[.]com` | Polygon blockchain RPC |

### Telegram

| Type | Value | Context |
|------|-------|---------|
| Bot ID | `8384531459` (skuefq_bot) | Pre-registration beacon and notifications |
| Bot ID | `7993597060` (komandastuk_bot) | Operator notifications |
| Channel | "stuk komanda" | Operator coordination channel (created 2025-06-05) |

### Behavioral

| Indicator | Value | Context |
|-----------|-------|---------|
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` "MyApp" | HTA persistence via mshta.exe |
| Scheduled Task | `PythonLauncher-{3 random chars}` | Starland RAT persistence |
| Startup Folder | LNK shortcut targeting `pythonw.exe` with `LICENSE.txt` argument | Starland RAT persistence |
| Mutex | `f2j398fj239d8j23dkkskskkkkkkkkk` | WLDR agent single-instance check |
| Python Loader | `LICENSE.txt` (compiled Python, XOR key 0xC6) | Starland RAT loader disguise |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36` | Starland RAT HTTP beaconing |
| XOR Key | `helo1` | Starland RAT C2 data encryption |
| XOR Key | `$m7*rYpry3` | Blockchain fallback domain decryption |
| PBKDF2 Password | `odg5t8mvssvh` | WLDR session key derivation |
| Protocol Version | `WSv1` | WLDR agent MAC computation binding |

### Encryption Keys

| Key | Value | Usage |
|-----|-------|-------|
| XOR byte | `0xC6` (198 decimal) | Starland RAT payload decryption |
| XOR string | `helo1` | C2 reconnaissance data encryption |
| XOR string | `$m7*rYpry3` | Blockchain fallback domain decryption |
| PBKDF2 password | `odg5t8mvssvh` | WLDR AES-256-CBC key derivation |
| PBKDF2 iterations | 5,000 | WLDR key derivation |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1218.005 | Mshta | HTA file execution via mshta.exe for initial payload delivery |
| T1204.002 | User Execution: Malicious File | ClickFix social engineering tricks user into running command |
| T1059.001 | PowerShell | WLDR agent stages, reconnaissance commands, scheduled task creation |
| T1059.003 | Windows Command Shell | Batch file execution, cmd /c shell commands from Starland RAT |
| T1059.006 | Python | Starland RAT core implemented in compiled Python via pythonw.exe |
| T1547.001 | Registry Run Keys / Startup Folder | HKCU Run key "MyApp" and Startup folder LNK persistence |
| T1053.005 | Scheduled Task/Job | PythonLauncher-{3 chars} scheduled tasks via New-ScheduledTask |
| T1055.004 | Asynchronous Procedure Call | Shellcode injection via QueueUserAPC into suspended process |
| T1562.001 | Disable or Modify Tools | AMSI bypass (AmsiScanBuffer patch) and ETW bypass (EtwEventWrite patch) |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption of payloads, Base64 encoding of C2 data |
| T1082 | System Information Discovery | WMI/PowerShell queries for UUID, RAM, OS, domain membership |
| T1518.001 | Security Software Discovery | CIM queries for AntiVirusProduct via SecurityCenter2 namespace |
| T1016 | System Network Configuration Discovery | Network adapter enumeration via WMI |
| T1087.002 | Domain Account Discovery | `net user /dom` and `nltest /dclist` for AD enumeration |
| T1113 | Screen Capture | Desktop screenshot in PNG format, Base64-encoded |
| T1005 | Data from Local System | Browser credential extraction, wallet data collection |
| T1555.003 | Credentials from Web Browsers | Chromium/Firefox SQLite DB access with DPAPI/AES-GCM decryption |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS C2 with JSON payloads |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | XOR + Base64 (Starland), AES-256-CBC + HMAC-SHA256 (WLDR) |
| T1102 | Web Service | Polygon blockchain smart contract as fallback C2 resolver |
| T1008 | Fallback Channels | Blockchain-derived backup C2 domain when primary fails |
| T1027 | Obfuscated Files or Information | Junk functions in Python loader, XOR-encrypted payloads |
| T1548.002 | Bypass User Account Control | ShellExecuteW with runas verb for privilege escalation |
| T1497.001 | System Checks | Sandbox username/hostname validation, Zone.Identifier ADS check |
| T1041 | Exfiltration Over C2 Channel | Encrypted JSON exfiltration via HTTP POST to C2 |
| T1567 | Exfiltration Over Web Service | Telegram bot notifications with victim profiles and wallet inventory |

## Impact Assessment

UAT-11795 presents a significant threat to individual users and enterprises alike due to its broad targeting of popular software installers across multiple categories (SSH tools, video conferencing, database management, gaming). The dual-implant architecture -- Starland RAT for initial access and reconnaissance followed by WLDR agent for persistent C2 -- provides operational resilience. The blockchain fallback C2 mechanism using Polygon smart contracts makes infrastructure takedown more difficult. The campaign's financial motivation is evident in the comprehensive cryptocurrency wallet enumeration (40+ types) and browser credential theft capabilities. The WLDR agent's memory-only execution, AES-256-CBC encryption with PBKDF2 key derivation, and PowerShell Runspace engine supporting 10 concurrent execution threads demonstrate a high level of sophistication. Passive DNS data indicates victims primarily in the United States, with secondary targeting in Germany, Romania, and Venezuela.

## Detection & Remediation

### Immediate Detection

```
# Check for Starland RAT scheduled task persistence
schtasks /query /fo TABLE | findstr "PythonLauncher-"

# Check for Startup folder LNK targeting pythonw with LICENSE.txt
dir /s "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" 2>nul

# Check for HTA persistence in Run key
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyApp 2>nul

# Check for WLDR mutex
handle.exe -a "f2j398fj239d8j23dkkskskkkkkkkkk" 2>nul

# Check for pythonw.exe with LICENSE.txt argument
wmic process where "CommandLine like '%LICENSE.txt%'" get ProcessId,CommandLine 2>nul
```

### Remediation

1. **Containment**: Isolate affected hosts; block all C2 domains (`eorthopaedics[.]com`, `sastoro[.]com`, `zynaris[.]io`, `web-devtools[.]com`, `aipythondevs[.]com`, `windowscreenrepairnearme[.]com`, `alphabitcapital[.]info`) and IPs (`104[.]248[.]233[.]104`, `192[.]81[.]216[.]250`, `74[.]114[.]119[.]201`, `178[.]255[.]126[.]39`, `193[.]149[.]176[.]254`, `185[.]238[.]191[.]234`) at perimeter
2. **Eradication**: Remove scheduled tasks matching `PythonLauncher-*` pattern, delete Startup folder LNK shortcuts targeting pythonw.exe, remove `HKCU\...\Run\MyApp` registry value, kill pythonw.exe processes executing LICENSE.txt
3. **Recovery**: Rotate all credentials accessed from affected hosts; revoke and regenerate cryptocurrency wallet keys; audit Telegram, Discord, and Steam sessions from compromised systems
4. **Secret Rotation**: Assume all browser-stored credentials, cryptocurrency wallet data, and session tokens on affected systems are compromised

### Long-Term Hardening

- Implement application allowlisting to prevent execution of unsigned Python runtimes from temp directories
- Block mshta.exe execution via AppLocker or WDAC policies where not required
- Monitor for Telegram bot API communications from internal endpoints
- Deploy network monitoring for Polygon RPC endpoint queries from non-cryptocurrency environments
- Enforce software installation policies requiring verified/signed installers from official sources only

## Detection Rules

The following rules target UAT-11795 IOCs and behavioral patterns at host, file, and network layers. Sigma rules cover mshta.exe delivery, scheduled task persistence, C2 domain queries, reconnaissance commands, Python loader execution, WLDR HWID derivation, and trojanized installer behavior. YARA rules detect the Starland RAT, WLDR agent, HTA dropper, and shellcode payloads by characteristic strings, encryption keys, and domain indicators. Snort and Suricata rules identify C2 HTTP traffic patterns, known C2 domain DNS queries, and Starland RAT beaconing.

### Sigma: UAT-11795 Starland RAT HTA Delivery via Mshta.exe
Detects mshta.exe execution with command-line references to known UAT-11795 C2 domains, consistent with the ClickFix HTA delivery chain.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT HTA Delivery via Mshta.exe
id: a3c7e1d2-5b94-4f68-b2e0-8d1a3c5e7f09
status: experimental
description: >
    Detects mshta.exe execution patterns consistent with UAT-11795 ClickFix
    delivery chain. The actor uses mshta.exe to execute weaponized HTA files
    hosted on known C2 infrastructure domains.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/new-starland-rat-and-WLDR-implant-campaign.txt
author: Actioner
date: 2026-07-22
tags:
    - attack.t1218.005
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'eorthopaedics.com'
            - 'sastoro.com'
            - 'zynaris.io'
            - 'alphabitcapital.info'
    condition: selection_mshta
falsepositives:
    - Unlikely - domains are known UAT-11795 infrastructure
level: critical
```

<!-- audit: IOC-anchored rule. Domains from Cisco Talos report and GitHub IOC dump. Validated: sigma check 0 errors 0 issues (tag validators excluded due to network restriction), sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. Field names match Sysmon EID 1 schema. No defanged values in detection. -->

### Sigma: UAT-11795 Starland RAT Scheduled Task Persistence
Detects scheduled task creation matching the Starland RAT PythonLauncher naming pattern with pythonw.exe execution. Caveat: legitimate Python apps could theoretically use similar naming, but the PythonLauncher-{3chars} pattern is highly specific.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT Scheduled Task Persistence Pattern
id: b4d8f2e3-6ca5-4079-c3f1-9e2b4d6f8a10
status: experimental
description: >
    Detects creation of scheduled tasks matching the Starland RAT persistence
    naming convention PythonLauncher-{3 random chars} targeting pythonw.exe
    with LICENSE.txt argument. This is the primary persistence mechanism for
    the Python-based Starland RAT.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-22
tags:
    - attack.t1053.005
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'PythonLauncher-'
            - 'pythonw'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'New-ScheduledTask'
            - 'PythonLauncher-'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Python application using PythonLauncher-prefixed scheduled tasks
level: high
```

<!-- audit: TTP-anchored rule with IOC-level specificity due to the PythonLauncher- prefix pattern. Two detection branches cover both schtasks.exe CLI and PowerShell New-ScheduledTask cmdlet. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: UAT-11795 Known C2 Domain DNS Query
Detects DNS resolution of all seven known UAT-11795 infrastructure domains identified by Cisco Talos.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT and WLDR Known C2 Domain DNS Query
id: c5e9a3f4-7db6-4180-d4a2-0f3c5e7a9b21
status: experimental
description: >
    Detects DNS queries to known UAT-11795 C2 infrastructure domains used
    for Starland RAT command-and-control, payload staging, and WLDR agent
    communication. These domains were identified by Cisco Talos in July 2026.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/new-starland-rat-and-WLDR-implant-campaign.txt
author: Actioner
date: 2026-07-22
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
            - 'web-devtools.com'
            - 'aipythondevs.com'
            - 'windowscreenrepairnearme.com'
            - 'alphabitcapital.info'
    condition: selection
falsepositives:
    - Unlikely - known malicious infrastructure
level: critical
```

<!-- audit: IOC-anchored domain rule. All 7 domains from Cisco Talos GitHub IOC dump, not defanged in detection. Critical level appropriate for confirmed malicious infrastructure. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. endswith modifier catches subdomains. -->

### Sigma: UAT-11795 Starland RAT Reconnaissance Command
Detects WMI and PowerShell reconnaissance commands characteristic of Starland RAT victim profiling. Caveat: individual commands may appear in legitimate administration scripts; correlation of multiple hits increases confidence.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: medium**

```yaml
title: UAT-11795 Starland RAT Reconnaissance Command
id: d6fab4a5-8ec7-4291-e5b3-1a4d6f8b0c32
status: experimental
description: >
    Detects the system reconnaissance command patterns used by Starland RAT
    after initial infection. The RAT executes WMI and PowerShell commands to
    collect antivirus products, hardware UUIDs, memory capacity, and domain
    membership information for victim profiling.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-22
tags:
    - attack.t1082
    - attack.t1518.001
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection_uuid:
        CommandLine|contains|all:
            - 'Win32_ComputerSystemProduct'
            - 'UUID'
    selection_av:
        CommandLine|contains|all:
            - 'root/SecurityCenter2'
            - 'AntiVirusProduct'
    selection_mem:
        CommandLine|contains|all:
            - 'wmic'
            - 'memorychip'
            - 'Capacity'
    condition: 1 of selection_*
falsepositives:
    - System administration scripts performing inventory collection
    - Endpoint management tools querying hardware information
level: medium
```

<!-- audit: TTP-level rule. Each selection is independently useful but not uniquely malicious -- medium level appropriate. Combined with temporal proximity (within same infection chain), any single hit should trigger investigation. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: UAT-11795 Starland RAT Python Loader Execution
Detects pythonw.exe or python.exe launched with LICENSE.txt as argument, the characteristic execution pattern of the obfuscated Starland RAT loader.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT Python Loader Execution
id: e7abc5b6-9fd8-4302-f6c4-2b5e7a9c1d43
status: experimental
description: >
    Detects pythonw.exe or python.exe execution with LICENSE.txt as an
    argument, the characteristic invocation pattern of the Starland RAT
    obfuscated Python loader deployed via trojanized NSIS installers.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-22
tags:
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_python_loader:
        Image|endswith:
            - '\pythonw.exe'
            - '\python.exe'
        CommandLine|endswith: 'LICENSE.txt'
    condition: selection_python_loader
falsepositives:
    - Legitimate Python applications launched with LICENSE.txt as an argument (uncommon)
level: high
```

<!-- audit: IOC-adjacent rule. pythonw.exe executing LICENSE.txt is a highly unusual pattern -- LICENSE.txt is not a valid Python script name in any standard toolchain. The endswith modifier anchors to the argument position. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: UAT-11795 WLDR Agent Volume Serial HWID Derivation
Detects PowerShell commands extracting C: drive volume serial number with Global scope variable injection, consistent with WLDR agent HWID construction.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: medium**

```yaml
title: UAT-11795 WLDR Agent PowerShell Execution with Volume Serial HWID
id: f8bcd6c7-0ae9-4413-a7d5-3c6f8b0d2e54
status: experimental
description: >
    Detects PowerShell command-line patterns consistent with the WLDR C2
    agent deriving a hardware identifier from the C: drive volume serial
    number. The WLDR downloader extracts the volume serial number and
    converts it to construct HWID-parameterized C2 URLs.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-22
tags:
    - attack.t1059.001
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'volume'
            - 'serial'
            - 'Global:'
    condition: selection
falsepositives:
    - Administrative scripts querying volume serial numbers with global scope variables
level: medium
```

<!-- audit: TTP-level rule. The combination of volume/serial extraction with Global: scope injection is unusual but not uniquely malicious. Medium level appropriate. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: UAT-11795 Trojanized Installer Spawning Python Runtime
Detects known UAT-11795 trojanized installer parent processes spawning Python runtime, covering all five observed installer filenames.
**compile: sigma check pass (0 errors, 0 issues) | sigma convert splunk pass | sigma convert log_scale pass** | **confidence: high**

```yaml
title: UAT-11795 Trojanized Software Installer Spawning Python Runtime
id: a9cde7d8-1bf0-4524-b8e6-4d7a9c1e3f65
status: experimental
description: >
    Detects known trojanized installer filenames used by UAT-11795 spawning
    Python runtime processes. The actor distributes trojanized versions of
    MobaXterm, WebEx, Zoom, DBeaver, and FACEIT installers that execute an
    embedded NSIS script launching pythonw.exe with a compiled Python loader.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-22
tags:
    - attack.t1204.002
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains:
            - 'MobaXterm_v26.1'
            - 'WebEx_Client'
            - 'dbeaver-ce-windows-x86_64'
            - 'FaceitInstaller_x64'
        Image|endswith:
            - '\pythonw.exe'
            - '\python.exe'
    condition: selection
falsepositives:
    - Legitimate installers for these products bundling Python (unlikely)
level: high
```

<!-- audit: IOC-anchored rule. ParentCommandLine matching specific trojanized installer filenames + Python child process. Legitimate versions of these products do not bundle Python runtimes. Validated: sigma check 0 errors 0 issues, sigma convert --without-pipeline -t splunk pass, sigma convert --without-pipeline -t log_scale pass. -->

### YARA: Starland RAT, WLDR Agent, HTA Dropper, and Shellcode Payload Detection (4 rules)
Four YARA rules targeting: (1) Starland RAT Python loader via C2 domains, API resolution, XOR key, and command strings; (2) WLDR agent via hardcoded password, mutex, protocol version, and crypto configuration; (3) HTA dropper via staging domains, Russian-language comments, and Telegram bot IDs; (4) shellcode payloads via staging URLs and blockchain contract indicators.
**compile: yarac pass** | **confidence: high** (Starland RAT), **high** (WLDR agent), **high** (HTA dropper), **high** (shellcode payload)

```yara
rule Malware_Starland_RAT_Python_Loader
{
    meta:
        description = "Detects compiled Python-based Starland RAT loader via characteristic XOR key, C2 paths, sandbox check strings, and API resolution patterns used by UAT-11795"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $c2_1 = "windowscreenrepairnearme.com" ascii wide
        $c2_2 = "aipythondevs.com" ascii wide
        $c2_cmd = "/command" ascii wide

        $sandbox_1 = "WDAGUtilityAccount" ascii wide
        $sandbox_2 = "Cuckoo" ascii wide
        $sandbox_3 = "Any.Run" ascii wide

        $api_1 = "VirtualAllocEx" ascii wide
        $api_2 = "WriteProcessMemory" ascii wide
        $api_3 = "CreateRemoteThread" ascii wide
        $api_4 = "QueueUserAPC" ascii wide
        $api_5 = "ResumeThread" ascii wide
        $api_6 = "CreateProcessA" ascii wide

        $cmd_1 = "shellexecute" ascii wide
        $cmd_2 = "x32" ascii wide
        $cmd_3 = "x64" ascii wide
        $cmd_4 = "download" ascii wide

        $enc_key = "helo1" ascii wide
        $license = "LICENSE.txt" ascii wide

    condition:
        filesize < 50MB and
        (
            (1 of ($c2_*) and 2 of ($api_*)) or
            (1 of ($c2_*) and $enc_key) or
            (2 of ($sandbox_*) and 2 of ($api_*) and $enc_key) or
            (3 of ($cmd_*) and 1 of ($c2_*)) or
            ($license and $enc_key and 2 of ($api_*))
        )
}

rule Malware_WLDR_C2_Agent_PowerShell
{
    meta:
        description = "Detects WLDR C2 PowerShell agent via hardcoded encryption password, mutex string, protocol identifiers, and AES/PBKDF2 configuration used by UAT-11795"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $password = "odg5t8mvssvh" ascii wide nocase
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $proto = "WSv1" ascii wide

        $crypto_1 = "PBKDF2" ascii wide nocase
        $crypto_2 = "AES" ascii wide nocase
        $crypto_3 = "HMAC" ascii wide nocase
        $crypto_4 = "SHA256" ascii wide nocase

        $ps_1 = "Runspace" ascii wide nocase
        $ps_2 = "ICorRuntimeHost" ascii wide nocase
        $ps_3 = "AmsiScanBuffer" ascii wide nocase
        $ps_4 = "EtwEventWrite" ascii wide nocase
        $ps_5 = "VirtualProtect" ascii wide nocase

        $wldr_1 = "New-ScheduledTask" ascii wide nocase
        $wldr_2 = "Global:" ascii wide nocase

    condition:
        filesize < 10MB and
        (
            $password or
            $mutex or
            ($proto and 2 of ($crypto_*)) or
            ($proto and 2 of ($ps_*)) or
            (2 of ($ps_*) and 2 of ($crypto_*) and 1 of ($wldr_*))
        )
}

rule Malware_Starland_RAT_HTA_Dropper
{
    meta:
        description = "Detects HTA dropper files used in UAT-11795 ClickFix delivery chain via embedded VBScript with Russian language comments and staging domain references"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $hta_tag = "<HTA:APPLICATION" ascii nocase
        $vbs_tag = "<script language" ascii nocase

        $ru_comment = {D0 94 D0 BE D0 B1 D0 B0 D0 B2 D0 BB D0 B5 D0 BD D0 B8 D0 B5}

        $domain_1 = "eorthopaedics.com" ascii wide
        $domain_2 = "sastoro.com" ascii wide
        $domain_3 = "zynaris.io" ascii wide
        $domain_4 = "alphabitcapital.info" ascii wide

        $staging_1 = "/feed/" ascii wide
        $staging_2 = "/alpha/" ascii wide

        $bot_1 = "8384531459" ascii wide
        $bot_2 = "7993597060" ascii wide

    condition:
        filesize < 2MB and
        (
            ($hta_tag and 1 of ($domain_*)) or
            ($vbs_tag and 1 of ($domain_*) and 1 of ($staging_*)) or
            ($hta_tag and $ru_comment and 1 of ($staging_*)) or
            (1 of ($domain_*) and 1 of ($bot_*))
        )
}

rule Malware_UAT11795_Shellcode_Payload
{
    meta:
        description = "Detects shellcode payloads hosted on UAT-11795 infrastructure by matching staging URL paths and domain indicators"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $url_1 = "web-devtools.com/starlandfox" ascii wide
        $url_2 = "web-devtools.com/x32remka" ascii wide
        $url_3 = "web-devtools.com/dopfile" ascii wide
        $url_4 = "web-devtools.com/file.zip" ascii wide

        $fallback_key = "$m7*rYpry3" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide nocase
        $selector = "0xc659f3b8" ascii wide

    condition:
        filesize < 50MB and
        (
            1 of ($url_*) or
            ($contract and $selector) or
            ($fallback_key and ($contract or $selector))
        )
}
```

<!-- audit: Four YARA rules compiled clean via yarac (exit code 0). Starland RAT rule uses combination logic to require C2 domain + API resolution or encryption key presence, avoiding single-string false positives. WLDR agent rule anchors on hardcoded password "odg5t8mvssvh" and mutex "f2j398fj239d8j23dkkskskkkkkkkkk" which are unique IOCs. HTA dropper rule requires HTA tag + domain or Russian comment. Shellcode rule uses staging URLs and blockchain contract address. All string values are real (not defanged). Removed single-byte $xor_key and unreferenced $telegram from initial draft to fix yarac errors. -->

### Snort: UAT-11795 Starland RAT and WLDR Network Detection (8 rules)
Eight Snort rules covering Starland RAT C2 beaconing with Chrome/138 User-Agent on known C2 domain, five known C2 domain DNS queries, WLDR stager download path, and Telegram bot notification exfiltration.
**compile: structural check only** | **confidence: high** (all rules -- domain-anchored or IOC-anchored)

```
# Starland RAT C2 beaconing with characteristic Chrome/138.0.0.0 User-Agent and /command path on known C2 domain
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11795 Starland RAT C2 Beacon with Chrome 138 UA"; flow:established,to_server; content:"GET"; http_method; content:"/command"; http_uri; content:"windowscreenrepairnearme.com"; http_header; content:"Chrome/138.0.0.0 Safari/537.36"; http_header; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100001; rev:2;)

# Known UAT-11795 C2 domain in DNS query - eorthopaedics.com
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 Domain DNS Query eorthopaedics.com"; content:"|0e|eorthopaedics|03|com|00|"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100002; rev:1;)

# Known UAT-11795 C2 domain in DNS query - windowscreenrepairnearme.com
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 Domain DNS Query windowscreenrepairnearme.com"; content:"|18|windowscreenrepairnearme|03|com|00|"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100003; rev:1;)

# Known UAT-11795 C2 domain in DNS query - sastoro.com
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 Domain DNS Query sastoro.com"; content:"|07|sastoro|03|com|00|"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100006; rev:1;)

# Known UAT-11795 C2 domain in DNS query - zynaris.io
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 Domain DNS Query zynaris.io"; content:"|07|zynaris|02|io|00|"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100007; rev:1;)

# Known UAT-11795 C2 domain in DNS query - alphabitcapital.info
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 Domain DNS Query alphabitcapital.info"; content:"|10|alphabitcapital|04|info|00|"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100008; rev:1;)

# WLDR stager download via /feed/ path on known staging domains
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11795 WLDR Stager Download via /feed/ Path"; flow:established,to_server; content:"GET"; http_method; content:"/feed/"; http_uri; content:"eorthopaedics.com"; http_header; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100004; rev:1;)

# Starland RAT Telegram bot exfiltration beacon
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11795 Starland RAT Telegram Bot Exfiltration"; flow:established,to_server; content:"api.telegram.org"; http_header; content:"/bot"; http_uri; content:"8384531459"; http_uri; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_22; sid:9100005; rev:1;)
```

<!-- audit: 8 Snort rules. structural check only -- no snort binary available for compilation. SID 9100001 matches Starland RAT C2 polling GET with Chrome/138 UA, /command path, and windowscreenrepairnearme.com Host header (domain-anchored, rev:2). SIDs 9100002-9100003, 9100006-9100008 use DNS wire format for domain matching (length prefix byte + label) covering all 5 C2 domains. SID 9100004 combines /feed/ URI with eorthopaedics.com Host header (domain-anchored, high confidence). SID 9100005 targets Telegram bot API exfiltration with specific bot ID (IOC-anchored, high confidence). All use flow:established,to_server for TCP rules. DNS rules use UDP port 53. -->

### Suricata: UAT-11795 Starland RAT and WLDR Network Detection (10 rules)
Ten Suricata rules using sticky buffers for Starland RAT C2 beaconing on known C2 domain, seven known C2 domain DNS queries, WLDR stage chain downloads, and Telegram bot exfiltration.
**compile: structural check only** | **confidence: high** (all rules -- domain-anchored or IOC-anchored)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT C2 Beacon Chrome 138 UA"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/command"; http.host; content:"windowscreenrepairnearme.com"; http.user_agent; content:"Chrome/138.0.0.0 Safari/537.36"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100201; rev:2;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 C2 Domain eorthopaedics.com"; dns.query; content:"eorthopaedics.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100202; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 C2 Domain windowscreenrepairnearme.com"; dns.query; content:"windowscreenrepairnearme.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100203; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 C2 Domain aipythondevs.com"; dns.query; content:"aipythondevs.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100204; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 C2 Domain web-devtools.com"; dns.query; content:"web-devtools.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100205; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 WLDR Stager Download /feed/ Path"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/feed/"; fast_pattern; http.host; content:"eorthopaedics.com"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100206; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT Telegram Bot Exfil"; flow:established,to_server; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"8384531459"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-22; sid:2100207; rev:1;)
```

<!-- audit: 7 Suricata rules. structural check only -- no suricata binary available for compilation. Dot-notation sticky buffers used (http.method, http.uri, http.user_agent, http.host, dns.query). All options semicolon-terminated. Flow established for HTTP. SID 2100201 combines Chrome/138 UA with /command path. SIDs 2100202-2100205 cover four primary C2 domains via dns.query. SID 2100206 pairs /feed/ URI with eorthopaedics.com host header. SID 2100207 targets Telegram bot API with specific bot ID. SIDs in custom 2100200+ range. No defanged values. -->

### Dropped: Sigma: WLDR AMSI/ETW Bypass via AmsiScanBuffer Patching
**DROPPED** -- AmsiScanBuffer and EtwEventWrite patching detection via Sigma process_creation is not actionable because the patching occurs in-memory via runtime API resolution and ctypes calls, which do not appear in command-line arguments. Script block logging (EID 4104) would be more appropriate but the WLDR agent operates entirely in memory without touching PowerShell script files, making Sigma detection of this specific bypass impractical without custom ETW telemetry.

### Dropped: Sigma: Starland RAT Blockchain C2 Fallback via Polygon RPC
**DROPPED** -- Polygon RPC queries are routine for any Web3/DeFi application or cryptocurrency wallet. DNS or HTTP detection for polygon-rpc[.]com would generate unacceptable false positive rates in environments with any blockchain tooling. The smart contract address and function selector are better covered by the YARA rule `Malware_UAT11795_Shellcode_Payload`.

## Lessons Learned

1. **ClickFix social engineering continues to evolve**: UAT-11795 demonstrates that ClickFix delivery remains effective when combined with trojanized versions of widely trusted software. The use of popular tools across multiple categories (SSH, conferencing, gaming, databases) maximizes the attack surface and indicates the actor's confidence in the technique.

2. **Blockchain C2 resilience**: The Polygon smart contract fallback mechanism provides infrastructure survivability against traditional domain takedowns. Defenders should consider monitoring for unexpected blockchain RPC queries from non-crypto environments and tracking known contract addresses.

3. **Memory-only implants defeat disk-based detection**: The WLDR agent's entirely in-memory execution, combined with AES-256-CBC encryption and PBKDF2 key derivation, makes detection dependent on behavioral monitoring (PowerShell Runspace creation, volume serial enumeration, mutex creation) rather than file scanning.

4. **Dual-implant architecture for operational resilience**: The separation of Starland RAT (initial access, recon, persistence) from WLDR agent (persistent C2, advanced execution) provides defense-in-depth for the attacker -- even if one implant is detected, the other may persist.

5. **Russian locale exclusion pattern**: CastleStealer's Russian locale check is consistent with the Eastern European cybercrime convention of avoiding domestic targets, reinforcing the Russian-speaking attribution.

## ClamAV Signatures (Vendor-Published)

The following ClamAV signatures were published by Cisco Talos:

| Signature | Description |
|-----------|-------------|
| Txt.Downloader.Agent-10060312-0 | Downloader component |
| Html.Downloader.Agent-10060313-0, -10060314-0 | HTA downloader |
| Py.Loader.Agent-10060315-0, -10060316-0 | Python loader |
| Ps1.Trojan.Agent-10060317-0, -10060318-0 | PowerShell trojan stages |
| Ps1.Trojan.WLDRAgent-10060319-0 | WLDR agent |
| Ps1.Downloader.Agent-10060320-0 | PowerShell downloader |
| Win.Trojan.CastleStealer-10060341-0 | CastleStealer |
| Win.Trojan.Starland_Installer-10060342-0 | Trojanized installer |
| Win.Malware.Starland-10060343-0 | Starland RAT |
| Win.Malware.Remka-10060344-0 | Remcos variant |

Snort SIDs published by Talos: 66787-66790, 301580

## Sources

- [Cisco Talos - UAT-11795 deploys novel Starland RAT and bespoke WLDR C2 implant in financially motivated campaign](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/) -- primary technical analysis of UAT-11795 campaign, Starland RAT, and WLDR agent internals
- [Cisco Talos IOCs - GitHub](https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/new-starland-rat-and-WLDR-implant-campaign.txt) -- complete IOC dump with 28 SHA256 hashes, 8 domains, 6 IPs, and 10 URLs
- [BleepingComputer - Russian hackers trojanize WebEx, Zoom apps to push Starland malware](https://www.bleepingcomputer.com/news/security/russian-hackers-trojanize-webex-zoom-apps-to-push-starland-malware/) -- secondary reporting on campaign scope and trojanized installer distribution
- [GBHackers - New Starland RAT Steals Browser Credentials and Scans for Over 40 Crypto Wallets](https://gbhackers.com/starland-rat-steals-browser-credentials/) -- supplementary coverage of credential theft capabilities
- [SecurityAffairs - New Russian Campaign Uses Fake Webex and Zoom Installers to Deploy Starland RAT](https://securityaffairs.com/195532/malware/new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat.html) -- additional campaign context and targeting analysis

<!-- revision: v1.0 2026-07-22 DRAFT. 7 Sigma rules (1 IOC-anchored mshta delivery, 1 scheduled task persistence, 1 C2 domain DNS, 1 recon commands, 1 Python loader execution, 1 WLDR HWID derivation, 1 trojanized installer). 4 YARA rules (Starland RAT loader, WLDR agent, HTA dropper, shellcode payload). 5 Snort rules (C2 beacon, 2 DNS domain, WLDR stager, Telegram exfil). 7 Suricata rules (C2 beacon, 4 DNS domain, WLDR stager, Telegram exfil). DROPPED 2 Sigma rules (AMSI/ETW bypass not visible in cmdline, Polygon RPC too noisy). sigma check: all 7 pass 0 errors 0 issues (tag validators excluded due to MITRE ATT&CK data fetch 403). sigma convert: all 7 pass both splunk and log_scale. yarac: all 4 rules compile clean (exit 0). Snort/Suricata: structural check only, no compiler available. -->

---
*Report generated by Actioner*
