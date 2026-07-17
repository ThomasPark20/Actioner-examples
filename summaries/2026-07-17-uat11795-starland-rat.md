# Technical Analysis Report: UAT-11795 Deploys Starland RAT and WLDR C2 Implant (2026-07-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-17
Version: 1.0 (DRAFT)

## Executive Summary

Russian-speaking threat actor UAT-11795 has been conducting a financially motivated campaign since at least June 2025, deploying custom malware through trojanized software installers for widely used applications including Cisco WebEx, Zoom, MobaXterm, DBeaver, and FACEIT. The campaign uses ClickFix social engineering to deliver weaponized HTA files that drop NSIS-packaged trojanized installers containing a Python-based remote access trojan called Starland RAT. Starland RAT performs extensive system reconnaissance including cryptocurrency wallet enumeration across 40+ wallet types, establishes persistence via scheduled tasks and startup folder shortcuts, and delivers secondary payloads including CastleStealer (a .NET info-stealer) and Remcos RAT through shellcode injection. A bespoke memory-only PowerShell C2 framework called WLDR is deployed as a second-stage implant, featuring AES-256-CBC encryption with HMAC-SHA256, real-time output streaming via RunspacePool concurrency, and a novel blockchain-based fallback C2 mechanism using an Ethereum smart contract on the Polygon network. Primary victims are located in the United States, with secondary targeting in Germany, Romania, and Venezuela.

## Background: Trojanized Software Installers

Trojanized installers remain a high-efficacy delivery vector because they bundle legitimate software functionality with malicious payloads, reducing user suspicion. UAT-11795 targets applications commonly used by IT administrators, developers, and enterprise users -- populations more likely to have elevated privileges and access to sensitive infrastructure. The use of Nullsoft Scriptable Install System (NSIS) as the installer framework allows the actor to package the legitimate application alongside a compiled Python loader disguised as LICENSE.txt, executed transparently during installation via custom NSI script instructions.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-06-05 | Telegram channel "stuk komanda" created for campaign operations |
| 2025-06 (est.) | Campaign begins with initial trojanized installer distribution |
| 2025-06 -- 2026-07 | Ongoing distribution of trojanized WebEx, Zoom, MobaXterm, DBeaver, FACEIT installers |
| 2026-07-16 | Cisco Talos publishes comprehensive analysis of UAT-11795 campaign |

## Root Cause: ClickFix Social Engineering

Initial access is achieved via ClickFix social engineering, where victims are induced to execute a command that downloads and launches a weaponized HTA file. The HTA contains embedded VBScript with a Russian-language developer comment ("Dobavlenie komandy v avtozapusk dlya tekushchego polzovatelya" -- "Adding command to autorun for current user"). The VBScript drops a Windows batch file to the user's temporary folder, which downloads the trojanized installer from a staging domain and creates a registry Run key for persistence pointing to the HTA via mshta.exe.

## Technical Analysis of the Malicious Payload

### 1. Trojanized NSIS Installer (Initial Loader)

The trojanized installers are built using NSIS (Nullsoft Scriptable Install System) and impersonate legitimate software:

- MobaXterm_v26.1.exe
- WebEx_Client.exe
- Zoom installer
- dbeaver-ce-windows-x86_64.exe
- FaceitInstaller_x64.exe

Each installer packages the legitimate application alongside `pythonw.exe` (the windowless Python runtime) and a compiled Python loader disguised as `LICENSE.txt`. Custom NSI script instructions execute the Python loader via `pythonw.exe LICENSE.txt` during installation. The Python loader is heavily obfuscated with junk functions containing random arithmetic operations; the actual payload logic is only six lines, using single-byte XOR decryption (key: 0xC6 / decimal 198) to decrypt and execute Starland RAT directly in memory.

### 2. Starland RAT (Primary Implant)

**Anti-Analysis Checks:**
- Compares the logged-on username against a hardcoded sandbox account list (including WDAGUtilityAccount for Windows Defender Application Guard)
- Verifies the computer name against known sandbox hostnames (Cuckoo, Any.Run, Joe Sandbox, Hybrid Analysis)
- Examines the Downloads folder for a Zone.Identifier alternate data stream on the trojanized installer file
- Terminates immediately if any check matches

**Persistence Mechanisms:**
1. **Scheduled Task:** Created via PowerShell `Register-ScheduledTask` with a randomized name following the pattern `PythonLauncher-{3 random chars}`, using `AtLogOn` trigger with `RunLevel Highest`
2. **Startup Folder LNK:** Uses WScript.Shell COM object to create a shortcut in the Startup folder targeting `pythonw.exe` with `LICENSE.txt` as the argument
3. **Registry Run Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value name "MyApp"
4. **UAC Elevation:** Attempts `ShellExecuteW` with "runas" verb for privilege escalation

**System Reconnaissance:**
- `Get-CimInstance -Class Win32_ComputerSystemProduct.UUID` (hardware UUID)
- `wmic memorychip get Capacity` (RAM enumeration)
- `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct` (AV detection)
- For domain-joined hosts: `whoami && systeminfo && net user {USERNAME} /dom && nltest /dclist`
- For workgroup hosts: `whoami /all`
- Enumerates 40+ cryptocurrency desktop and browser extension wallets

**C2 Registration:**
- Assembles JSON with HWID, RAM size, AV products, domain info, Base64-encoded screenshot, wallet inventory
- XOR encryption with 5-byte key "helo1", then Base64 encoding
- HTTP POST with User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`

**Starland RAT Commands:**
| Command | Function |
|---------|----------|
| `shellexecute` | Arbitrary shell command via cmd /c or PowerShell |
| `x32` | Receives 32-bit shellcode URL, executes via APC injection |
| `x64` | Receives 64-bit shellcode URL, executes via APC injection |
| `download` | Downloads to %TEMP%, executes by extension (EXE, MSI, DLL, ZIP) |
| HTTP 403 | Kill switch: triggers self-deletion and process exit |

**Process Injection:**
Uses Windows API functions resolved via ctypes from kernel32.dll: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `VirtualProtectEx`, `CreateProcessA`, `QueueUserAPC`, `ResumeThread`. Primary injection method is Asynchronous Procedure Call (APC) injection.

### 3. C2 Infrastructure

**Primary C2 Domains (Starland RAT):**
- windowscreenrepairnearme[.]com
- aipythondevs[.]com

**WLDR C2 Domains:**
- eorthopaedics[.]com
- sastoro[.]com

**Staging Domains:**
- web-devtools[.]com
- zynaris[.]io

**C2 URL Patterns:**
- Staging paths: `/feed/`, `/alpha/`
- Payload paths: `/starlandfox`, `/x32remka`, `/dopfile`
- HWID-parameterized paths for victim-specific operations

**C2 Polling:** Every 50-60 seconds (Starland), every 10 seconds (WLDR), minimal JSON payload with two randomly named junk fields plus bot ID.

**Blockchain Fallback Mechanism:**
When primary C2 is unreachable, Starland RAT performs an `eth_call` via JSON-RPC to `polygon-rpc[.]com`, targeting Ethereum smart contract `0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba` with function selector `0xc659f3b8`. The response contains a XOR-encrypted hexadecimal string (key: `$m7\*rYpry3`) that decodes to the fallback C2 domain. This abuses public blockchain infrastructure for resilient C2 resolution.

**Telegram Infrastructure:**
- Bot 1: 8384531459 (skuefq_bot) -- receives initial execution beacons
- Bot 2: 7993597060 (komandastuk_bot) -- receives victim profile data
- Private channel "stuk komanda" (created June 5, 2025) for operational messaging
- Notifications include victim public IP (resolved via `api64.ipify[.]org`), build name, locale, computer name, OS info, processor string, and detected wallet extensions

### 4. WLDR C2 Framework (Second-Stage Implant)

WLDR is a bespoke, memory-only PowerShell C2 framework deployed via Starland RAT's `shellexecute` command. It operates through a three-stage loader chain:

**Stage 1 -- Stager:** PowerShell script with obfuscated string construction, runtime alias creation, and inline XOR decryption with a dynamically computed key to decrypt the embedded downloader.

**Stage 2 -- Downloader:** Derives HWID from the C: drive volume serial number (hex-to-decimal conversion), appends it to two hardcoded C2 URLs, and issues an HTTP GET. The C2 validates pre-registered HWIDs before responding. Response is an encrypted JSON envelope containing Base64 salt, initialization vector, encrypted data, and authentication tag. Decryption uses a 64-byte key derived via PBKDF2-SHA256 from hardcoded password `odg5t8mvssvh` plus salt. The downloader injects the C2 URL and plaintext password into the global PowerShell scope before executing the agent.

**Stage 3 -- Agent:** Full-featured remote access client operating entirely in memory. Key features:
- **Mutex:** `f2j398fj239d8j23dkkskskkkkkkkkk` prevents duplicate instances
- **Encryption:** AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC), PBKDF2-SHA256 key derivation (5,000 iterations), protocol version tag `WSv1` bound to every MAC computation, new random IV per message
- **HWID Fallback Chain:** (1) C: drive volume serial, (2) machine registry GUID, (3) hostname checksum
- **C2 Communication:** Initial HTTP POST with victim profile and protocol version 2.0.0, subsequent traffic over HTTPS, Chrome version 124 header spoofing, 10-second polling interval, 30-second connection retry
- **Execution Engines:** (1) RunspacePool supporting up to 10 concurrent threads with real-time output streaming; (2) PowerShell background jobs as fallback for batch tasks
- **WMI Reconnaissance:** AV products, network adapters, OS version/build, domain status, CPU, RAM, admin privileges, UAC policy

### 5. Secondary Payloads

**CastleStealer (.NET Info-Stealer):**
- Delivered via x64 shellcode through Starland RAT
- Russian locale exclusion check (does not execute on Russian-locale systems)
- Hardcoded build expiry timestamp
- Credential theft from Chromium and Firefox browsers via direct SQLite database access
- Legacy DPAPI-protected credential decryption and AES-GCM application-bound encryption scheme
- Enumerates cryptocurrency wallet extensions, Discord/Telegram sessions, Steam credentials
- Data exfiltration via TCP socket to attacker infrastructure
- Secondary capability: process injection or PowerShell script execution

**Remcos RAT:**
- Delivered via x32 shellcode
- Commercial RAT abused since 2016
- Capabilities: keylogging, screen/webcam/audio capture, file management, shell execution, clipboard monitoring, encrypted C2

### 6. Anti-Forensics / Evasion Techniques

**AMSI Bypass (Shellcode Loader):**
- Runtime hash-based API resolution for `AmsiScanBuffer` in amsi.dll
- Memory patch forcing "clean scan" return value
- Fallback: VirtualProtect to RWX, write patch, restore original protection

**ETW Bypass:**
- Runtime hash-based API resolution for `EtwEventWrite` in ntdll.dll
- Memory patch forcing immediate function return
- Same VirtualProtect fallback technique

**Shellcode Loader:**
- Enumerates loaded modules in memory and iterates export directories
- Compares function name hashes against stored targets for API resolution
- LZX decompression of encrypted payload into newly allocated memory
- Dispatch by type: reflective PE injection (native), ICorRuntimeHost COM interface (.NET), PowerShell Runspace (scripts)

**Code Obfuscation:**
- Python loader: extensive junk functions with random arithmetic
- PowerShell stagers: dynamic string construction and heavy obfuscation
- Multi-layer encoding: XOR + Base64

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: URLs use `hxxps://`, domains use `[.]`, IPs use `[.]`, emails use `[at]`.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| MobaXterm | MobaXterm_v26.1.exe | Trojanized NSIS installer bundling Starland RAT loader |
| WebEx | WebEx_Client.exe | Trojanized NSIS installer bundling Starland RAT loader |
| Zoom | Zoom installer | Trojanized NSIS installer bundling Starland RAT loader |
| DBeaver | dbeaver-ce-windows-x86_64.exe | Trojanized NSIS installer bundling Starland RAT loader |
| FACEIT | FaceitInstaller_x64.exe | Trojanized NSIS installer bundling Starland RAT loader |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | LICENSE.txt (in installer directory) | N/A (varies per build) | Compiled Python loader disguised as license file |
| Windows | pythonw.exe (in installer directory) | N/A (legitimate binary) | Windowless Python runtime used to execute loader |
| Windows | %TEMP%\* | N/A | Downloaded payloads staged for execution |
| Windows | Startup folder\*.lnk | N/A | Persistence shortcut targeting pythonw.exe + LICENSE.txt |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | windowscreenrepairnearme[.]com | Starland RAT primary C2 |
| Domain | aipythondevs[.]com | Starland RAT primary C2 |
| Domain | eorthopaedics[.]com | WLDR C2 |
| Domain | sastoro[.]com | WLDR C2 |
| Domain | web-devtools[.]com | Staging / payload delivery |
| Domain | zynaris[.]io | Staging / payload delivery |
| Domain | polygon-rpc[.]com | Blockchain fallback RPC endpoint |
| Domain | api64.ipify[.]org | Public IP resolution service |
| Smart Contract | 0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba | Polygon blockchain fallback C2 resolution |
| Telegram Bot | 8384531459 (skuefq_bot) | Execution beacon notifications |
| Telegram Bot | 7993597060 (komandastuk_bot) | Victim profile notifications |
| URL Pattern | /feed/, /alpha/ | Staging paths on C2 domains |
| URL Pattern | /starlandfox, /x32remka, /dopfile | Shellcode payload paths |

### Behavioral

- **Mutex:** `f2j398fj239d8j23dkkskskkkkkkkkk` (WLDR agent instance guard)
- **Registry Persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value "MyApp" pointing to mshta.exe with HTA URL
- **Scheduled Task Pattern:** `PythonLauncher-{3 random chars}` with AtLogOn trigger, Highest RunLevel
- **Process Chain:** mshta.exe -> VBScript -> batch file -> trojanized NSIS installer -> pythonw.exe LICENSE.txt -> Starland RAT (in-memory)
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`
- **XOR Keys:** 0xC6 (Python loader), "helo1" (Starland C2 data), "$m7\*rYpry3" (blockchain fallback)
- **WLDR Password:** `odg5t8mvssvh` (PBKDF2-SHA256 key derivation, 5000 iterations)
- **WLDR Protocol Version:** WSv1, connection protocol 2.0.0
- **C2 Polling:** 50-60 seconds (Starland), 10 seconds (WLDR)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | ClickFix induces user to execute HTA file |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | HTA contains VBScript that drops batch file and creates persistence |
| T1059.006 | Command and Scripting Interpreter: Python | pythonw.exe executes compiled Python loader (LICENSE.txt) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | WLDR C2 framework, scheduled task creation, reconnaissance commands |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd /c execution via shellexecute command |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Python loader disguised as LICENSE.txt in NSIS installer |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | HKCU Run key with "MyApp" value pointing to mshta.exe |
| T1053.005 | Scheduled Task/Job: Scheduled Task | PythonLauncher-{random} task with AtLogOn trigger |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | Startup folder LNK targeting pythonw.exe + LICENSE.txt |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | ShellExecuteW with "runas" verb for privilege escalation |
| T1082 | System Information Discovery | WMI queries for UUID, RAM, OS version, network adapters |
| T1518.001 | Software Discovery: Security Software Discovery | Enumeration of AV products via SecurityCenter2 WMI |
| T1087.002 | Account Discovery: Domain Account | net user /dom and nltest /dclist on domain-joined hosts |
| T1083 | File and Directory Discovery | Cryptocurrency wallet enumeration across 40+ wallets |
| T1113 | Screen Capture | Base64-encoded screenshot sent during C2 registration |
| T1055.004 | Process Injection: Asynchronous Procedure Call | APC injection via QueueUserAPC for shellcode execution |
| T1055.001 | Process Injection: Dynamic-link Library Injection | Reflective PE injection for native payloads |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass (AmsiScanBuffer patch) and ETW bypass (EtwEventWrite patch) |
| T1106 | Native API | Direct kernel32.dll function resolution via ctypes |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption of payloads (keys: 0xC6, "helo1", "$m7\*rYpry3") |
| T1027 | Obfuscated Files or Information | Junk functions in Python loader, obfuscated PowerShell stagers |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS C2 communication with Chrome UA spoofing |
| T1568.003 | Dynamic Resolution: DNS Calculation | Blockchain smart contract for fallback C2 domain resolution |
| T1105 | Ingress Tool Transfer | Download command fetches secondary payloads to %TEMP% |
| T1005 | Data from Local System | CastleStealer harvests browser credentials, wallet data, session files |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | CastleStealer SQLite access to Chromium/Firefox credential stores |
| T1041 | Exfiltration Over C2 Channel | Stolen data transmitted via HTTP/HTTPS and TCP sockets |

## Impact Assessment

This campaign represents a significant financial threat targeting a broad user base. The opportunistic, volume-driven distribution model using popular software installers maximizes reach across IT administrators (MobaXterm, DBeaver), enterprise users (WebEx, Zoom), and consumers (FACEIT). The combination of Starland RAT's extensive cryptocurrency wallet enumeration (40+ wallets), CastleStealer's credential harvesting capabilities, and Remcos RAT's surveillance features creates a comprehensive theft toolkit. The blockchain-based fallback C2 mechanism using Polygon smart contracts demonstrates infrastructure resilience that complicates takedown efforts. The memory-only WLDR framework's AES-256-CBC encryption with HMAC-SHA256 and HWID-bound payload delivery significantly raises the bar for detection and forensic analysis.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for PythonLauncher scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "PythonLauncher-*" }

# Check for suspicious registry Run key
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Where-Object { $_.MyApp -ne $null }

# Check for WLDR mutex
Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -match "f2j398fj239d8j23dkkskskkkkkkkkk" } 2>$null

# Check for pythonw.exe executing LICENSE.txt
Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*pythonw*LICENSE.txt*" }

# Check for DNS queries to known C2 domains
Get-DnsClientCache | Where-Object { $_.Entry -match "windowscreenrepairnearme|aipythondevs|eorthopaedics|sastoro|web-devtools|zynaris" }
```

### Remediation

1. **Containment:** Immediately isolate affected hosts from the network. Block all C2 domains (windowscreenrepairnearme[.]com, aipythondevs[.]com, eorthopaedics[.]com, sastoro[.]com, web-devtools[.]com, zynaris[.]io) at the DNS and proxy level.
2. **Eradication:** Remove PythonLauncher-* scheduled tasks, delete the "MyApp" registry Run key, remove Startup folder LNK files, and terminate any pythonw.exe processes executing LICENSE.txt.
3. **Credential Rotation:** Assume all browser-stored credentials, cryptocurrency wallet keys, Discord/Telegram sessions, and Steam credentials on affected hosts are compromised. Rotate all passwords and revoke active sessions. Transfer cryptocurrency assets to new wallets immediately.
4. **Forensic Review:** Examine %TEMP% for downloaded payloads. Review Sysmon/EDR logs for APC injection activity (QueueUserAPC, VirtualAllocEx, WriteProcessMemory). Check for AMSI/ETW bypass artifacts.
5. **Network Monitoring:** Monitor for blockchain RPC calls to polygon-rpc[.]com with the smart contract address. Monitor Telegram API traffic to the identified bot IDs.

### Long-Term Hardening

- Implement application whitelisting to prevent execution of pythonw.exe from non-standard directories.
- Deploy AMSI and ETW tamper detection to alert on memory patches to AmsiScanBuffer and EtwEventWrite.
- Block mshta.exe execution for non-administrative users via AppLocker or WDAC.
- Enforce software installation policies requiring signed installers from verified sources only.
- Monitor for scheduled task creation with randomized names, particularly those matching the PythonLauncher-* pattern.
- Consider blocking outbound JSON-RPC calls to public blockchain endpoints from endpoints that should not require them.

## Detection Rules

These detections target UAT-11795's Starland RAT and WLDR C2 campaign at the PoC/advisory-specific altitude, keying on distinctive artifacts from the Cisco Talos analysis. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; Suricata rules compile against v7.0.3. Compiles does not equal fires -- verify in your pipeline against representative telemetry before promoting to production.

### Sigma: Starland RAT Trojanized Installer Execution via pythonw.exe

Detects pythonw.exe executing a file named LICENSE.txt, the distinctive loader execution pattern used by UAT-11795's trojanized NSIS installers.
**Status:** compile ✅ compiles · confidence: high · sample: N/A
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403 in sandboxed env); splunk convert exit 0, log_scale convert exit 0, splunk_windows pipeline exit 0. pythonw.exe + LICENSE.txt as argument is highly distinctive — legitimate Python applications do not pass license files as script arguments. -->

```yaml
title: UAT-11795 Starland RAT Trojanized Installer Execution via pythonw.exe
id: 7c3a1d8e-4f2b-4e9a-b6c1-d5e8f0a3c2b1
status: experimental
description: >
    Detects execution of pythonw.exe with a LICENSE.txt argument, consistent with UAT-11795's
    trojanized NSIS installer technique where a compiled Python loader is disguised as LICENSE.txt
    and executed via the bundled Python runtime.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1059.006
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pythonw.exe'
        CommandLine|contains: 'LICENSE.txt'
    condition: selection
falsepositives:
    - Legitimate Python applications that reference a LICENSE.txt file as an argument (unlikely in normal operations)
level: high
```

### Sigma: Starland RAT Scheduled Task Persistence (PythonLauncher)

Detects PowerShell-based scheduled task registration with the PythonLauncher- naming pattern used by Starland RAT for logon persistence.
**Status:** compile ✅ compiles · confidence: high · sample: N/A
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403); splunk convert exit 0, log_scale convert exit 0, splunk_windows pipeline exit 0. PythonLauncher- prefix combined with Register-ScheduledTask is distinctive to this campaign. -->

```yaml
title: UAT-11795 Starland RAT Scheduled Task Persistence
id: 9a4b2c6d-3e7f-4d1a-8b5c-0f9e8d7c6b5a
status: experimental
description: >
    Detects creation of scheduled tasks matching the PythonLauncher naming pattern used by
    Starland RAT for persistence. The task is created via PowerShell New-ScheduledTask with
    AtLogOn trigger and Highest RunLevel.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_task:
        CommandLine|contains|all:
            - 'Register-ScheduledTask'
            - 'PythonLauncher-'
    condition: selection_ps and selection_task
falsepositives:
    - Legitimate Python applications using scheduled tasks with the PythonLauncher prefix (uncommon)
level: high
```

### Snort: UAT-11795 C2 Domain DNS Queries

Detects DNS queries to known UAT-11795 C2 and staging domains via DNS wire-format content matching.
**Status:** compile ⚠️ uncompiled (structural check only -- snort not installed) · confidence: high
<!-- audit: snort binary not available in environment. Structural check: all rules use udp protocol on port 53, DNS label-length encoding verified (0x18=24 chars for windowscreenrepairnearme, 0x0c=12 for aipythondevs, 0x0d=13 for eorthopaedics, 0x07=7 for sastoro, 0x0c=12 for web-devtools, 0x07=7 for zynaris), flow:to_server present, all required fields (msg, sid, rev, classtype) present, SIDs in 2100000+ range. -->

```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 Starland RAT C2 DNS Query (windowscreenrepairnearme.com)"; flow:to_server; content:"|18|windowscreenrepairnearme|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100001; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 Starland RAT C2 DNS Query (aipythondevs.com)"; flow:to_server; content:"|0c|aipythondevs|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100002; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 WLDR C2 DNS Query (eorthopaedics.com)"; flow:to_server; content:"|0d|eorthopaedics|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100003; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 WLDR C2 DNS Query (sastoro.com)"; flow:to_server; content:"|07|sastoro|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100004; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 Staging DNS Query (web-devtools.com)"; flow:to_server; content:"|0c|web-devtools|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100005; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 Staging DNS Query (zynaris.io)"; flow:to_server; content:"|07|zynaris|02|io|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created 2026-07-17; sid:2100006; rev:1;)
```

### Suricata: UAT-11795 C2 Domain DNS Queries

Detects DNS queries to the six known UAT-11795 C2 and staging domains using Suricata's dns.query sticky buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (v7.0.3). Six rules covering all known C2 and staging domains. dns.query buffer with nocase for case-insensitive domain matching. SIDs 2200001-2200006. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Starland RAT C2 Domain (windowscreenrepairnearme.com)"; flow:to_server; dns.query; content:"windowscreenrepairnearme.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Starland RAT C2 Domain (aipythondevs.com)"; flow:to_server; dns.query; content:"aipythondevs.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 WLDR C2 Domain (eorthopaedics.com)"; flow:to_server; dns.query; content:"eorthopaedics.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 WLDR C2 Domain (sastoro.com)"; flow:to_server; dns.query; content:"sastoro.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Staging Domain (web-devtools.com)"; flow:to_server; dns.query; content:"web-devtools.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200005; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Staging Domain (zynaris.io)"; flow:to_server; dns.query; content:"zynaris.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026-07-17; sid:2200006; rev:1;)
```

### YARA: Starland RAT / WLDR C2 Implant Artifacts

Detects Starland RAT and WLDR C2 artifacts via distinctive strings including the WLDR mutex, encryption keys, C2 domains, smart contract address, and Telegram bot IDs. Fires on 2+ matches from the indicator set.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive (mutex + C2 domain + WLDR password) fired Malware_UAT11795_Starland_WLDR_Indicators; negative (benign text) clean. Strings sourced from published Talos indicators. The 2-of-them threshold balances coverage against FP risk — individual strings like "helo1" or "WSv1" are too short alone but combined with any other campaign indicator are decisive. -->

```yara
rule Malware_UAT11795_Starland_WLDR_Indicators
{
    meta:
        description = "Detects Starland RAT and WLDR C2 implant artifacts from UAT-11795 campaign via distinctive strings including mutex, encryption keys, C2 domains, and smart contract address"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $xor_key1 = "helo1" ascii wide
        $xor_key2 = "$m7\\*rYpry3" ascii wide
        $wldr_pass = "odg5t8mvssvh" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide nocase
        $func_sel = "0xc659f3b8" ascii wide nocase
        $c2_1 = "windowscreenrepairnearme.com" ascii wide nocase
        $c2_2 = "aipythondevs.com" ascii wide nocase
        $c2_3 = "eorthopaedics.com" ascii wide nocase
        $c2_4 = "sastoro.com" ascii wide nocase
        $staging_1 = "web-devtools.com" ascii wide nocase
        $staging_2 = "zynaris.io" ascii wide nocase
        $task_prefix = "PythonLauncher-" ascii wide
        $proto_ver = "WSv1" ascii wide
        $tg_bot1 = "8384531459" ascii wide
        $tg_bot2 = "7993597060" ascii wide

    condition:
        2 of them
}

rule Malware_UAT11795_CastleStealer_Strings
{
    meta:
        description = "Detects CastleStealer info-stealer deployed by UAT-11795 via characteristic wallet enumeration and credential theft patterns"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $s1 = "CastleStealer" ascii wide nocase
        $s2 = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $s3 = "odg5t8mvssvh" ascii wide
        $c2_1 = "windowscreenrepairnearme.com" ascii wide nocase
        $c2_2 = "aipythondevs.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($s1 or (2 of ($s*, $c2_*)))
}
```

## Lessons Learned

This campaign highlights several evolving adversary techniques: (1) blockchain-anchored C2 fallback via Ethereum smart contracts on the Polygon network is a durable resilience mechanism that resists traditional domain takedown; (2) the use of compiled Python bytecode disguised as LICENSE.txt within NSIS installers is a creative masquerading technique that evades signature-based detection at the installer level; (3) the memory-only WLDR PowerShell framework with AES-256-CBC/HMAC-SHA256 encryption, RunspacePool concurrency, and HWID-bound payload delivery represents a significant step up in PowerShell-based C2 sophistication; (4) the combination of an initial Python RAT with a secondary PowerShell C2 framework provides operational redundancy while maintaining distinct detection profiles. Defenders should prioritize monitoring for pythonw.exe executing non-standard scripts, scheduled task creation with randomized names, and outbound connections to blockchain RPC endpoints from endpoints that should not require them.

## Sources

- [Cisco Talos Blog](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/) -- primary technical analysis with full IOCs, TTPs, and malware architecture
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/russian-hackers-trojanize-webex-zoom-apps-to-push-starland-malware/) -- news coverage with campaign summary and targeting details
- [Security Affairs](https://securityaffairs.com/195532/malware/new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat.html) -- additional coverage with encryption key details and TTP summary

---
*Report generated by Actioner*
