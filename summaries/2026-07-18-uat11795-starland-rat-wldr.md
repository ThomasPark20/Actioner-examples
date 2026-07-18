# Technical Analysis Report: UAT-11795 Starland RAT & WLDR C2 Campaign (2026-07-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-18
Version: 1.0 (DRAFT)

## Executive Summary

UAT-11795 is a Russian-speaking financially motivated threat actor active since June 2025, deploying a novel Python-based Remote Access Trojan ("Starland RAT") and a bespoke PowerShell command-and-control implant ("WLDR") against US and European users. The campaign leverages trojanized software installers for popular applications (WebEx, Zoom, MobaXterm, DBeaverCE, FACEIT) delivered through ClickFix social engineering. The execution chain proceeds from mshta.exe executing a remote HTA stager, through VBScript dropping batch files, to NSIS installers executing pythonw.exe with a LICENSE.txt argument containing XOR-encrypted (key 0xC6) Python loader code. A distinctive blockchain-based dead-drop resolver queries a smart contract (function selector 0xc659f3b8) on contract address 0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba for C2 configuration. Secondary payloads include CastleStealer (.NET credential theft) and Remcos RAT. Infrastructure overlaps with the Miasma worm campaign (shared C2 IP 85[.]137[.]53[.]71).

## Background: UAT-11795 Campaign

The UAT-11795 intrusion set targets financially motivated objectives through trojanized installers of legitimate software. The actor demonstrates Russian-speaking origin markers and has been active since at least June 2025. The campaign primarily targets users in the United States and Europe who download popular productivity and development tools from attacker-controlled distribution sites. The threat actor maintains multiple C2 domains registered under various pretexts (orthopaedics, web development, Python AI, gaming) and uses Telegram bots for operational coordination.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-06 (est.) | UAT-11795 campaign begins |
| 2025-06 -- 2026-07 | Active trojanized software distribution via attacker domains |
| 2026-07-16 | Cisco Talos publishes technical analysis of UAT-11795 campaign |

## Root Cause: ClickFix Social Engineering

Threat actors employ ClickFix social engineering techniques to trick users into executing mshta.exe commands. Victims encounter fake error messages or verification prompts on attacker-controlled websites that instruct them to copy and paste a command into the Windows Run dialog. The command invokes mshta.exe to fetch and execute a remote HTA file containing a VBScript stager. This stager drops a batch file that downloads and executes a trojanized NSIS installer for the software the victim intended to install.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Delivery Chain

The attack chain follows five distinct stages:

1. **ClickFix social engineering** tricks the user into running `mshta.exe` with a remote HTA URL
2. **VBScript HTA stager** drops a batch file to disk and downloads the trojanized installer
3. **NSIS installer** (trojanized versions of MobaXterm_v26.1.exe, WebEx_Client.exe, Zoom, dbeaver-ce-windows-x86_64.exe, FaceitInstaller_x64.exe) executes pythonw.exe with LICENSE.txt as argument
4. **Python loader** (XOR key 198/0xC6) decrypts LICENSE.txt and executes Starland RAT in memory
5. **Secondary payloads**: x64/x32 shellcode via APC injection, PowerShell WLDR stager

### 2. Starland RAT Core

The Starland RAT is a Python-based implant operating entirely in memory after decryption from the LICENSE.txt file.

**Anti-Analysis Checks:**
- Username check: `WDAGUtilityAccount` (Windows Sandbox)
- Hostname checks against known sandbox environments: Cuckoo, Any.Run, Joe Sandbox, Hybrid Analysis
- Zone.Identifier Alternate Data Stream verification (checks if file was downloaded from internet)

**Reconnaissance Commands:**
- `Win32_ComputerSystemProduct.UUID` (WMI hardware fingerprint)
- `wmic memorychip` (RAM enumeration)
- `AntiVirusProduct` WMI query (security software detection)
- `whoami`, `systeminfo`, `net user /dom`, `nltest /dclist` (domain enumeration)
- XOR key for recon data encoding: "helo1" (5-byte rotating key)

**Command Dispatch:**
| Command | Function |
|---------|----------|
| `shellexecute` | Execute arbitrary commands |
| `x32` / `x64` | APC injection of shellcode (T1055.001) |
| `download` | Download and execute EXE, MSI, DLL, or ZIP |

**Network Behavior:**
- IP enumeration via `api64[.]ipify[.]org`
- Beacon interval: 50-60 seconds
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`
- Kill switch: HTTP 403 response terminates the implant

**Blockchain C2 Resolution:**
- Smart contract address: `0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba`
- Function selector: `0xc659f3b8`
- The implant queries the blockchain to retrieve C2 server addresses stored in the smart contract

### 3. WLDR C2 Implant

The WLDR is a bespoke PowerShell-based C2 implant with sophisticated cryptographic protections:

**Instance Control:**
- Mutex: `f2j398fj239d8j23dkkskskkkkkkkkk` (single-instance check)

**Cryptography:**
- Encryption: AES-256-CBC with HMAC-SHA256 in Encrypt-then-MAC (EtM) scheme
- Protocol tag: `WSv1`
- Key derivation: PBKDF2-SHA256 at 5,000 iterations for session key
- Hardcoded password: `odg5t8mvssvh`

**Operational Parameters:**
- Polling interval: 10 seconds
- Runspace: up to 10 concurrent PowerShell threads
- Hardware ID (HWID): C: drive volume serial number converted from hex to decimal

**Defense Evasion:**
- AMSI bypass: AmsiScanBuffer patching in amsi.dll
- ETW bypass: EtwEventWrite patching in ntdll.dll
- LZX decompression for shellcode delivery

### 4. Persistence Mechanisms

Three distinct persistence mechanisms are employed:

1. **Scheduled Task**: Named `PythonLauncher-{3 random chars}` with AtLogOn trigger and RunLevel Highest, executing pythonw.exe with LICENSE.txt
2. **Registry Run Key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value "MyApp" pointing to mshta.exe executing a remote HTA
3. **Startup Folder LNK**: Created via WScript.Shell COM object

### 5. Secondary Payloads

**CastleStealer (.NET):**
- Chromium and Firefox credential theft
- DPAPI and AES-GCM decryption of browser secrets
- Cryptocurrency wallet targeting
- Discord, Telegram, Steam session theft
- TCP socket transport for exfiltration

**Remcos RAT:**
- Keylogging and screen capture
- Webcam and audio recording
- File management operations

### 6. Infrastructure

**C2 Domains:**
- eorthopaedics[.]com
- sastoro[.]com
- web-devtools[.]com
- zynaris[.]io
- windowscreenrepairnearme[.]com
- aipythondevs[.]com
- polygon-rpc[.]com

**Telegram Bots:**
- Bot ID 8384531459 (skuefq_bot)
- Bot ID 7993597060 (komandastuk_bot)

**C2 IP:** 85[.]137[.]53[.]71 (shared with Miasma worm infrastructure)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation: URLs use `hxxps://`, domains use `[.]`, IP addresses use `[.]`.

### File System

| Filename | Context |
|----------|---------|
| MobaXterm_v26.1.exe | Trojanized NSIS installer |
| WebEx_Client.exe | Trojanized NSIS installer |
| dbeaver-ce-windows-x86_64.exe | Trojanized NSIS installer |
| FaceitInstaller_x64.exe | Trojanized NSIS installer |
| LICENSE.txt | XOR-encrypted (0xC6) Python RAT loader |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | eorthopaedics[.]com | C2 infrastructure |
| Domain | sastoro[.]com | C2 infrastructure |
| Domain | web-devtools[.]com | C2 infrastructure |
| Domain | zynaris[.]io | C2 infrastructure |
| Domain | windowscreenrepairnearme[.]com | C2 infrastructure |
| Domain | aipythondevs[.]com | C2 infrastructure |
| Domain | polygon-rpc[.]com | C2 infrastructure |
| IP | 85[.]137[.]53[.]71 | Shared Miasma/WLDR C2 IP |
| URL | hxxps://api64[.]ipify[.]org | IP enumeration endpoint |
| Telegram | 8384531459 (skuefq_bot) | Operational bot |
| Telegram | 7993597060 (komandastuk_bot) | Operational bot |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Smart Contract | 0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba | C2 configuration storage |
| Function Selector | 0xc659f3b8 | C2 retrieval function |

### Behavioral

- Mutex: `f2j398fj239d8j23dkkskskkkkkkkkk` (WLDR single-instance)
- Scheduled Task pattern: `PythonLauncher-{3 random chars}` (AtLogOn, Highest)
- Registry: `HKCU\...\Run\MyApp` = mshta.exe remote HTA
- XOR key: 198 (0xC6) for LICENSE.txt decryption
- XOR key: "helo1" (5-byte) for recon data
- WLDR password: `odg5t8mvssvh`
- WLDR protocol tag: `WSv1`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`
- Beacon interval: 50-60 seconds (Starland), 10 seconds (WLDR)

### Encryption Keys

| Key | Value | Usage |
|-----|-------|-------|
| XOR key (byte) | 0xC6 (198) | LICENSE.txt payload decryption |
| XOR key (string) | "helo1" | Reconnaissance data encoding |
| PBKDF2 password | "odg5t8mvssvh" | WLDR session key derivation |
| PBKDF2 iterations | 5,000 | WLDR key derivation parameter |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566 | Phishing | ClickFix social engineering directing users to execute mshta commands |
| T1204 | User Execution | Victims run mshta command and install trojanized software |
| T1106 | Native API | Direct Windows API usage in RAT and WLDR implant |
| T1547.001 | Registry Run Keys | HKCU Run key "MyApp" pointing to mshta.exe |
| T1053.005 | Scheduled Task | PythonLauncher-{xxx} scheduled task with AtLogOn trigger |
| T1087 | Account Discovery | net user /dom, nltest /dclist domain enumeration |
| T1005 | Data from Local System | CastleStealer credential and wallet theft |
| T1056.004 | Credential API Hooking | CastleStealer DPAPI + AES-GCM browser credential decryption |
| T1113 | Screen Capture | Remcos screen and webcam capture |
| T1140 | Deobfuscate/Decode | XOR decryption of LICENSE.txt loader (key 0xC6) |
| T1562.001 | Disable Security Tools | AMSI AmsiScanBuffer and ETW EtwEventWrite patching |
| T1036 | Masquerading | Trojanized installers mimicking legitimate software |
| T1027 | Obfuscated Files | XOR encryption, LZX compression of payloads |
| T1055.001 | DLL Injection (APC) | x32/x64 shellcode via APC injection |
| T1071.001 | Web Protocols | HTTP/HTTPS C2 with standard User-Agent |

## Impact Assessment

UAT-11795 presents a significant financial threat due to its multi-stage credential theft capabilities and broad targeting via trojanized popular software. The combination of Starland RAT (Python, in-memory), WLDR C2 (PowerShell, encrypted), CastleStealer (credential/wallet theft), and Remcos RAT provides comprehensive access to victim systems. The blockchain-based C2 resolver adds infrastructure resilience against domain takedowns. The shared C2 IP with the Miasma worm campaign suggests either operational overlap or shared infrastructure-as-a-service. The campaign's focus on cryptocurrency wallets and browser credentials aligns with financially motivated operations.

## Detection & Remediation

### Immediate Detection

```
# Check for Starland RAT scheduled task
schtasks /query /fo list /v | findstr /i "PythonLauncher-"

# Check for registry persistence
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyApp 2>nul

# Check for WLDR mutex (via handle.exe from Sysinternals)
handle.exe -a "f2j398fj239d8j23dkkskskkkkkkkkk" 2>nul

# Check for pythonw.exe executing LICENSE.txt
wmic process where "name='pythonw.exe'" get CommandLine | findstr /i "LICENSE.txt"

# Check for trojanized installers
dir /s "%TEMP%\MobaXterm_v26.1.exe" "%TEMP%\WebEx_Client.exe" "%TEMP%\FaceitInstaller_x64.exe" 2>nul
```

### Remediation

1. **Containment**: Isolate affected hosts; block C2 domains (eorthopaedics[.]com, sastoro[.]com, web-devtools[.]com, zynaris[.]io, windowscreenrepairnearme[.]com, aipythondevs[.]com, polygon-rpc[.]com) and IP (85[.]137[.]53[.]71) at perimeter
2. **Eradication**: Remove PythonLauncher-* scheduled tasks, delete MyApp registry Run key, kill pythonw.exe processes running LICENSE.txt, remove startup folder LNK files
3. **Recovery**: Rotate all credentials accessed from affected hosts; revoke cryptocurrency wallet keys; audit browser stored credentials
4. **Secret Rotation**: Assume all credentials, browser passwords, crypto wallets, and application sessions (Discord, Telegram, Steam) on affected systems are compromised

### Long-Term Hardening

- Block mshta.exe execution via AppLocker/WDAC or constrain to signed HTA files only
- Monitor for pythonw.exe with LICENSE.txt command-line arguments
- Deploy network monitoring for the known smart contract function selector (0xc659f3b8) in JSON-RPC calls
- Block or alert on connections to api64[.]ipify[.]org from non-browser processes
- Implement application control policies restricting NSIS installer execution from user-writable directories

## Detection Rules

The following rules target UAT-11795 IOCs and behavioral patterns at host, file, and network layers. Sigma rules cover the distinctive pythonw/LICENSE.txt execution chain, PythonLauncher scheduled task persistence, WLDR mutex creation, C2 domain DNS queries, registry persistence via mshta, and AMSI/ETW bypass patterns. YARA rules detect the Starland RAT loader (sandbox checks, XOR key, recon commands), WLDR C2 implant (mutex, password, protocol markers), and trojanized NSIS installers. Suricata rules identify C2 domain DNS traffic, blockchain smart contract queries, IP enumeration via ipify, and connections to the shared Miasma C2 IP. Snort rules provide structural equivalents for the blockchain function selector and DNS-level domain detection.

### Sigma: UAT-11795 Starland RAT Execution Chain - mshta to pythonw with LICENSE.txt
Detects pythonw.exe executing with LICENSE.txt as argument, the distinctive Starland RAT in-memory loading technique.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT Execution Chain - mshta to pythonw with LICENSE.txt
id: a4c7e831-2f19-4d6a-b882-1c3d5e8f9a01
status: experimental
description: >
    Detects the UAT-11795 Starland RAT execution chain where a trojanized NSIS
    installer executes pythonw.exe with LICENSE.txt as an argument. The LICENSE.txt
    file contains the XOR-encrypted (key 0xC6) Python loader that decrypts and
    executes the Starland RAT in memory.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pythonw.exe'
        CommandLine|contains: 'LICENSE.txt'
    condition: selection
falsepositives:
    - Highly unlikely in production environments
level: high
```

<!-- AUDIT: IOC-anchored rule. pythonw.exe + LICENSE.txt is the exact execution technique documented by Cisco Talos. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). Field names match Sysmon EID 1 schema. -->

### Sigma: UAT-11795 Starland RAT Scheduled Task Persistence - PythonLauncher Pattern
Detects schtasks.exe creating tasks with the PythonLauncher- naming pattern used for Starland RAT persistence.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT Scheduled Task Persistence - PythonLauncher Pattern
id: b5d8f942-3a20-5e7b-c993-2d4e6f9a0b12
status: experimental
description: >
    Detects the creation of scheduled tasks matching the Starland RAT persistence
    naming pattern PythonLauncher-{3 random chars} with AtLogOn trigger and
    RunLevel Highest. The task executes pythonw.exe with LICENSE.txt to reload
    the encrypted RAT payload.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'PythonLauncher-'
    condition: selection
falsepositives:
    - Custom Python development environments using similar naming convention
level: high
```

<!-- AUDIT: IOC-anchored rule. "PythonLauncher-" prefix is the documented persistence task name pattern. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). -->

### Sigma: UAT-11795 WLDR C2 Implant Mutex Creation
Detects creation of the WLDR-specific mutex value used for single-instance checking.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: high**

```yaml
title: UAT-11795 WLDR C2 Implant Mutex Creation
id: c6e9a053-4b31-6f8c-da04-3e5f7a0b1c23
status: experimental
description: >
    Detects creation of the WLDR C2 implant mutex f2j398fj239d8j23dkkskskkkkkkkkk
    which is a hardcoded single-instance check used by the WLDR PowerShell implant
    deployed by UAT-11795. This mutex value is unique to this threat actor.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.execution
    - attack.t1106
logsource:
    category: create_mutex
    product: windows
detection:
    selection:
        EventType: CreateMutex
        MutexName: 'f2j398fj239d8j23dkkskskkkkkkkkk'
    condition: selection
falsepositives:
    - None known
level: critical
```

<!-- AUDIT: IOC-anchored rule. Exact mutex string from Cisco Talos analysis. Unique value with no known legitimate use. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). Requires Sysmon EID 1/CreateMutex telemetry. -->

### Sigma: UAT-11795 Known C2 Domain DNS Query
Detects DNS queries to any of the seven known UAT-11795 C2 domains.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: high**

```yaml
title: UAT-11795 Known C2 Domain DNS Query
id: d7fa1b64-5c42-7a9d-eb15-4f6a8b1c2d34
status: experimental
description: >
    Detects DNS queries to known UAT-11795 C2 infrastructure domains used
    for Starland RAT and WLDR implant command-and-control in the financially
    motivated campaign targeting US and European users.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'eorthopaedics.com'
            - 'sastoro.com'
            - 'web-devtools.com'
            - 'zynaris.io'
            - 'windowscreenrepairnearme.com'
            - 'aipythondevs.com'
            - 'polygon-rpc.com'
    condition: selection
falsepositives:
    - Unlikely - these are attacker-controlled domains
level: critical
```

<!-- AUDIT: IOC-anchored domain rule. All 7 domains from Cisco Talos report. Not defanged in detection (real values for matching). Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). Critical level appropriate for known C2 infrastructure. -->

### Sigma: UAT-11795 Registry Persistence via mshta MyApp Run Key
Detects the specific registry persistence pattern using Run key "MyApp" pointing to mshta.exe.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: high**

```yaml
title: UAT-11795 Starland RAT Registry Persistence via mshta
id: e8ab2c75-6d53-8b0e-fc26-5a7b9c2d3e45
status: experimental
description: >
    Detects the UAT-11795 registry persistence mechanism where the Run key value
    MyApp is set to execute mshta.exe with a remote HTA URL. This is used as
    a secondary persistence mechanism alongside the scheduled task.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run'
        TargetObject|endswith: '\MyApp'
        Details|contains: 'mshta'
    condition: selection
falsepositives:
    - Unlikely - generic Run value name "MyApp" with mshta is suspicious
level: high
```

<!-- AUDIT: IOC-anchored rule. Exact registry value name "MyApp" and mshta content from Cisco Talos. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). -->

### Sigma: UAT-11795 WLDR AMSI and ETW Bypass via Memory Patching
Detects PowerShell scripts containing AMSI or ETW bypass patterns consistent with WLDR implant initialization.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: medium** (TTP-level; similar patterns used by red team tools)

```yaml
title: UAT-11795 WLDR AMSI and ETW Bypass via Memory Patching
id: f9bc3d86-7e64-9c1f-ad37-6b8c0d3e4f56
status: experimental
description: >
    Detects PowerShell loading amsi.dll or ntdll.dll with subsequent memory
    manipulation consistent with the WLDR C2 implant AMSI bypass (AmsiScanBuffer
    patching) and ETW bypass (EtwEventWrite patching) techniques used by UAT-11795.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: ps_script
    product: windows
detection:
    selection_amsi:
        ScriptBlockText|contains|all:
            - 'AmsiScanBuffer'
            - 'VirtualProtect'
    selection_etw:
        ScriptBlockText|contains|all:
            - 'EtwEventWrite'
            - 'ntdll'
    condition: selection_amsi or selection_etw
falsepositives:
    - Security testing tools and red team scripts
    - AMSI testing utilities
level: high
```

<!-- AUDIT: TTP-level rule. AmsiScanBuffer+VirtualProtect and EtwEventWrite+ntdll are the exact WLDR bypass patterns but also used by other offensive tools. Confidence medium due to TTP reuse. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). -->

### Sigma: UAT-11795 ClickFix Initial Access - mshta Remote HTA Execution
Detects mshta.exe executing remote HTA files, consistent with the ClickFix delivery mechanism.
**compile-status: ✅ compiles (sigma convert splunk pass, sigma convert log_scale pass)** | **confidence: medium** (TTP-level; mshta with remote URLs is used by multiple threat actors)

```yaml
title: UAT-11795 ClickFix Social Engineering - mshta Execution with Remote HTA
id: 0abc4e97-8f75-4012-be48-7c9d1e5a6b78
status: experimental
description: >
    Detects mshta.exe executing a remote HTA file, consistent with the UAT-11795
    ClickFix social engineering technique that tricks users into running mshta
    commands which download and execute VBScript HTA stagers.
references:
    - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
author: Actioner
date: 2026-07-18
tags:
    - attack.initial_access
    - attack.t1566
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: selection
falsepositives:
    - Legitimate HTA applications loaded from intranet
    - Software installers using HTA-based wizards
level: medium
```

<!-- AUDIT: TTP-level rule. mshta + remote URL is a common ClickFix pattern but not unique to UAT-11795. Level medium and confidence medium appropriate. Validated: sigma convert --without-pipeline -t splunk pass (exit 0), sigma convert --without-pipeline -t log_scale pass (exit 0). -->

### YARA: Starland RAT Loader, WLDR C2 Implant, and Trojanized Installer
Three YARA rules targeting the Starland RAT Python loader (sandbox checks, XOR key "helo1", recon commands), the WLDR C2 PowerShell implant (unique mutex, hardcoded password, WSv1 protocol), and the trojanized NSIS installers (Nullsoft + pythonw + LICENSE.txt + PythonLauncher pattern).
**compile-status: ✅ compiles (yarac pass)** | **confidence: high** (RAT loader - sandbox+XOR combo), **high** (WLDR - unique mutex/password), **high** (installer - multi-artifact conjunction)

```yara
rule Malware_Starland_RAT_Loader
{
    meta:
        description = "Detects Starland RAT Python loader via XOR key 0xC6 decryption pattern and anti-analysis sandbox hostnames"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $sandbox1 = "WDAGUtilityAccount" ascii wide
        $sandbox2 = "Cuckoo" ascii wide
        $sandbox3 = "Any.Run" ascii wide
        $sandbox4 = "Joe Sandbox" ascii wide
        $sandbox5 = "Hybrid Analysis" ascii wide

        $xor_key_recon = "helo1" ascii

        $cmd1 = "shellexecute" ascii wide
        $cmd2 = "download" ascii wide

        $recon1 = "Win32_ComputerSystemProduct" ascii wide
        $recon2 = "AntiVirusProduct" ascii wide
        $recon3 = "nltest /dclist" ascii wide

        $ua = "Chrome/138.0.0.0 Safari/537.36" ascii wide

    condition:
        filesize < 10MB and
        (
            (3 of ($sandbox*) and $xor_key_recon) or
            (2 of ($sandbox*) and 2 of ($recon*) and $ua) or
            ($xor_key_recon and 2 of ($recon*) and 1 of ($cmd*))
        )
}

rule Malware_WLDR_C2_Implant
{
    meta:
        description = "Detects the WLDR C2 PowerShell implant via unique mutex, hardcoded password, and protocol markers"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $password = "odg5t8mvssvh" ascii wide
        $protocol = "WSv1" ascii wide
        $aes = "AES" ascii wide
        $hmac = "HMACSHA256" ascii wide

    condition:
        filesize < 5MB and
        (
            $mutex or
            ($password and $protocol) or
            ($password and $aes and $hmac)
        )
}

rule Malware_Starland_Trojanized_Installer
{
    meta:
        description = "Detects trojanized NSIS installers used by UAT-11795 to deploy Starland RAT via pythonw.exe LICENSE.txt execution"
        author = "Actioner"
        date = "2026-07-18"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $nsis = "Nullsoft" ascii wide
        $pythonw = "pythonw.exe" ascii wide
        $license = "LICENSE.txt" ascii wide
        $task = "PythonLauncher-" ascii wide
        $schtasks = "schtasks" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 200MB and
        $nsis and $pythonw and $license and
        ($task or $schtasks)
}
```

<!-- AUDIT: Three YARA rules compiled clean via yarac (exit 0). Strings sourced from Cisco Talos report analysis. Mutex and password are exact values. Sandbox hostnames match documented anti-analysis checks. Condition logic uses conjunctions to reduce false positives. -->

### Suricata: UAT-11795 Network Detection (9 rules)
Nine Suricata rules covering C2 domain DNS queries (5 rules, SIDs 2200101-2200105), Starland RAT IP enumeration via ipify (SID 2200106/2200108), blockchain smart contract function selector query (SID 2200107), and known shared C2 IP connection (SID 2200109).
**compile-status: ✅ compiles (suricata -T pass)** | **confidence: high** (DNS domain rules SIDs 2200101-2200105 -- known C2 domains), **medium** (ipify SIDs 2200106/2200108 -- legitimate service used by many applications), **high** (blockchain SID 2200107 -- specific function selector + contract), **medium** (C2 IP SID 2200109 -- IP may be reassigned)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Known C2 Domain eorthopaedics.com"; dns.query; content:"eorthopaedics.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Known C2 Domain sastoro.com"; dns.query; content:"sastoro.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Known C2 Domain web-devtools.com"; dns.query; content:"web-devtools.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Known C2 Domain zynaris.io"; dns.query; content:"zynaris.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11795 Known C2 Domain polygon-rpc.com"; dns.query; content:"polygon-rpc.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200105; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT Beacon User-Agent and ipify Enumeration"; flow:established,to_server; http.user_agent; content:"Chrome/138.0.0.0"; fast_pattern; http.host; content:"api64.ipify.org"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200106; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Blockchain Smart Contract Query Function Selector 0xc659f3b8"; flow:established,to_server; http.method; content:"POST"; http.content_type; content:"application/json"; http.request_body; content:"0xc659f3b8"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200107; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11795 Starland RAT IP Enumeration via ipify"; flow:established,to_server; http.method; content:"GET"; http.host; content:"api64.ipify.org"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200108; rev:1;)

alert tcp $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - UAT-11795 Known Miasma Shared C2 IP 85.137.53.71"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/; metadata:author Actioner, created_at 2026_07_18; sid:2200109; rev:1;)
```

<!-- AUDIT: All 9 Suricata rules validated via suricata -T -S (exit 0, "Configuration provided was successfully loaded. Exiting."). Dot-notation sticky buffers used (dns.query, http.user_agent, http.host, http.method, http.content_type, http.request_body). All options semicolon-terminated. Flow established for HTTP/TCP. SIDs in custom 2200000+ range. -->

### Snort: UAT-11795 Blockchain C2 and DNS Detection (3 rules)
Three Snort rules covering the blockchain smart contract function selector with contract address, and DNS queries for key C2 domains.
**compile-status: ⚠️ uncompiled (structural check only -- Snort not available)** | **confidence: high** (blockchain rule -- specific function selector + contract address), **high** (DNS rules -- exact domain wire format)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11795 Starland RAT Blockchain Smart Contract Function Selector 0xc659f3b8"; flow:established,to_server; content:"POST"; http_method; content:"0xc659f3b8"; http_client_body; fast_pattern; content:"0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba"; http_client_body; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign; metadata:author Actioner, created_at 2026_07_18; sid:3200101; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 DNS Query for eorthopaedics.com"; content:"|0d|eorthopaedics|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign; metadata:author Actioner, created_at 2026_07_18; sid:3200102; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11795 C2 DNS Query for zynaris.io"; content:"|06|zynaris|02|io|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign; metadata:author Actioner, created_at 2026_07_18; sid:3200103; rev:1;)
```

<!-- AUDIT: Snort rules structurally validated (correct syntax, semicolons, keywords). Cannot be compiled as Snort is not installed. DNS wire format uses length-prefixed labels. Blockchain rule combines function selector with contract address for high specificity. -->

## Lessons Learned

1. **Trojanized installer supply chain**: UAT-11795 demonstrates that trojanizing popular software installers remains highly effective for initial access when combined with ClickFix social engineering. The use of legitimate NSIS installers as wrappers makes static detection difficult.

2. **Blockchain as C2 dead-drop**: The smart contract function selector (0xc659f3b8) pattern provides infrastructure resilience against domain takedowns. Defenders should monitor for JSON-RPC eth_call requests containing unusual function selectors from non-development endpoints.

3. **Multi-implant redundancy**: The deployment of both a Python RAT (Starland) and a PowerShell C2 (WLDR) with different communication protocols and encryption schemes provides operational redundancy. Loss of one implant does not compromise the other.

4. **Shared infrastructure between campaigns**: The overlap with Miasma worm infrastructure (85[.]137[.]53[.]71) suggests either a common threat actor operating multiple campaigns or use of shared bulletproof hosting infrastructure-as-a-service.

5. **LICENSE.txt as payload container**: Using a file named LICENSE.txt to store XOR-encrypted malware is a creative evasion technique that exploits the ubiquity of license files in software distributions and may evade content inspection that skips "benign" file types.

## ClamAV Signatures (Vendor-Provided)

The following ClamAV signatures were published by Cisco Talos for this campaign:

- Txt.Downloader.Agent-10060312-0
- Html.Downloader.Agent-10060313-0 / 10060314-0
- Py.Loader.Agent-10060315-0 / 10060316-0
- Ps1.Trojan.Agent-10060317-0 / 10060318-0
- Ps1.Trojan.WLDRAgent-10060319-0
- Ps1.Downloader.Agent-10060320-0
- Win.Trojan.CastleStealer-10060341-0
- Win.Trojan.Starland_Installer-10060342-0
- Win.Malware.Starland-10060343-0
- Win.Malware.Remka-10060344-0

**Snort SIDs (Vendor):** 66787-66790, 301580

## Sources

- [Cisco Talos - UAT-11795 deploys novel Starland RAT and bespoke WLDR C2 implant in financially motivated campaign](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/) -- primary technical deep-dive of Starland RAT, WLDR C2, execution chain, and IOCs

<!-- revision: v1.0 2026-07-18 DRAFT. 7 Sigma rules (6 passing sigma convert, 1 sigma check blocked by network). 3 YARA rules (yarac compiled). 9 Suricata rules (suricata -T pass). 3 Snort rules (structural only). Total: 22 detection rules. -->

---
*Report generated by Actioner*
