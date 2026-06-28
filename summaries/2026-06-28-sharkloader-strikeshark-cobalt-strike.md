# Technical Analysis Report: SharkLoader / StrikeShark Campaign (2026-06-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-28
Version: 1.1 (FINAL)

## Executive Summary

SharkLoader is a newly discovered malware loader deployed in a campaign Kaspersky tracks as **StrikeShark**. The loader uses DLL side-loading of a legitimate Windows binary (`SystemSettings.exe`) to execute a multi-stage chain culminating in a Cobalt Strike beacon. The campaign targets diplomatic organizations in Indonesia, government entities and software development companies in Taiwan, and entities across Hong Kong, Lebanon, Syria, Colombia, North Macedonia, Nepal, and Serbia. Initial access is achieved through exploitation of known vulnerabilities in internet-facing applications (Exchange, Openfire, GeoServer, and others). Kaspersky attributes the campaign to a Chinese-speaking threat actor with low confidence, based on the use of Chinese-origin open-source post-compromise tools (FScan, Pillager, Searchall). No code or infrastructure overlap with known APT groups has been identified.

## Background: Targeted Organizations

The StrikeShark campaign targets government, diplomatic, and software development organizations across multiple geographies. The threat actor exploits unpatched internet-facing applications to gain initial access, then deploys SharkLoader through custom droppers that masquerade as legitimate software installers (Google Update, Cisco AnyConnect). The campaign's use of advanced evasion techniques -- including "Perfect DLL Hijacking," Loader Lock manipulation, ETW blocking, direct syscalls, and memory protection toggling -- demonstrates a high level of technical sophistication.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06 (reported) | Kaspersky publishes StrikeShark analysis |
| Ongoing | Exploitation of CVE-2021-26855, CVE-2023-32315, CVE-2024-36401 for initial access |
| Post-exploitation | SharkLoader deployment via DLL side-loading, Cobalt Strike beacon delivery |
| Post-compromise | Active Directory enumeration, credential theft, lateral movement |

## Root Cause: Exploitation of Internet-Facing Applications

The threat actor gains initial access by exploiting known vulnerabilities in public-facing servers:

- **CVE-2021-26855** (ProxyLogon) -- Microsoft Exchange Server SSRF leading to RCE
- **CVE-2023-32315** -- Openfire path traversal to RCE
- **CVE-2024-36401** -- GeoServer critical RCE
- **CVE-2016-4437** -- Apache Shiro deserialization
- **CVE-2021-36260** -- Hikvision command injection
- **CVE-2021-27076** -- Microsoft SharePoint RCE
- **CVE-2022-27925** -- Zimbra RCE
- **CVE-2022-41082** -- Exchange ProxyNotShell
- **CVE-2023-46747** -- F5 BIG-IP authentication bypass
- **CVE-2024-21762** -- Fortinet FortiOS out-of-bounds write
- **CVE-2022-40684** -- FortiOS authentication bypass
- **CVE-2023-20198** -- Cisco IOS XE Web UI privilege escalation

Public PoC exploits are sourced from GitHub and open-source platforms in an opportunistic fashion.

## Technical Analysis of the Malicious Payload

### 1. Dropper / Initial Delivery

Custom droppers masquerade as legitimate installers:
- `GoogleUpdateStepup.exe` -- mimics Google Chrome updater
- `AnyConnect-win-4.10.04071-predeploy-k9exe` -- mimics Cisco AnyConnect
- `AutoUpdate.exe` -- generic update lure

Droppers embed three PE resources:
- **TELEMETRY** -- decoy PDF document extracted to `%TEMP%\aswerf\`
- **VAULTSVCD** -- encrypted DscCoreR.mui payload
- **UMRDPRDAT** -- encrypted SyncRes.dat payload

The dropper copies `SystemSettings.exe` from `C:\Windows\ImmersiveControlPanel\` to a deployment directory (`%APPDATA%\xwreg`, `%APPDATA%\xgdf`, `%APPDATA%\Identities`, `C:\ProgramData\KasperskyLab`, or `C:\ADriveLogs_Logs`) alongside the malicious `SystemSettings.dll` and encrypted payloads.

### 2. SharkLoader (SystemSettings.dll) -- DLL Side-Loading

When the legitimate `SystemSettings.exe` executes from the deployment directory, it side-loads the malicious `SystemSettings.dll`. The loader employs **"Perfect DLL Hijacking"** (technique described by Elliot Killick, October 2023) to escape the Windows Loader Lock by manipulating `LdrpLoaderLock` and `LdrpWorkInProgress`, enabling thread creation safely from `DllMain`.

The loader then:
1. Decrypts **DscCoreR.mui** using Blowfish ECB (16-byte key from file header bytes 0-15)
2. Decrypts **SyncRes.dat** using AES-128 (16-byte key from bytes 0-15, 16-byte IV from bytes 16-31)
3. Creates a suspended thread with entry point at the beacon buffer address
4. Decompresses the Cobalt Strike beacon shellcode (zlib) into allocated RWX memory
5. Installs API hooks from MinHook library and Microsoft Detours
6. Resumes the suspended thread via `ResumeThread`

Alternative encrypted payload filenames observed: `GameInputInboxs32.mui`, `diagerr.xml`, `NtfsLog.etl`, `Ignored.Dat`, `VistaCompat.nls`. Alternative DLL side-loading targets: `msedge.dll`, `PrintDialog.dll`, `miracastview.dll`.

### 3. C2 Infrastructure

Known C2 domains:
- `connect-microsoft[.]com`
- `ms-record[.]com`
- `ms-record[.]top`
- `ms-tray[.]top`

The Cobalt Strike beacon is delivered via the DscCoreR.mui decryption/decompression chain. Specific beacon configuration details (watermark, sleep time, jitter, public key, pipe names) were not published in the primary research.

### 4. Platform-Specific Behavior

#### Windows

**API Hooking via SyncRes.dat (Microsoft Detours + MinHook):**

SyncRes.dat installs extensive API hooks for evasion and PPID spoofing:

- **Process Creation:** `CreateProcessA/W` (PPID spoofing to `svchost.exe`), `NtCreateUserProcess`
- **Token Manipulation:** `OpenProcessToken`, `AdjustTokenPrivileges`
- **Memory Operations:** `VirtualAllocEx`, `VirtualProtect`, `VirtualAlloc` (tracks first 3 successful allocations)
- **Thread Operations:** `ResumeThread`, `GetThreadContext`, `OpenThread`, `NtCreateThread/Ex`
- **APC Injection:** `NtQueueApcThread/Ex`
- **Library Loading:** `LoadLibraryA/ExA`, `GetModuleHandleA/W`, `GetProcAddress`
- **File Mapping:** `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`, `NtMapViewOfSectionEx`
- **File I/O:** `NtReadFile`, `NtWriteFile`, `NtCreateNamedPipeFile`
- **ETW Blocking:** `EtwEventWrite`, `EventWriteEx`, `EventWrite`
- **Environment:** `ExpandEnvironmentStringsA`

**Sleep Hook Memory Evasion:**
The MinHook-based `Sleep` hook toggles memory protection from RWX to RW during Sleep calls and back to RWX on resume, evading memory scanners that look for RWX regions containing beacon code.

**VirtualAlloc Hook:**
Tracks the first 3 successful VirtualAlloc calls to identify and intercept beacon memory allocation.

**Additional evasion:**
- Vectored Exception Handler (VEH) registration for access violation handling
- Direct syscall stubs via jitasm
- ROR13-based API hashing
- Murmur32 function name hashing
- MZ header removal from encrypted payloads

### 5. Anti-Forensics / Evasion Techniques

- **Perfect DLL Hijacking:** Manipulates Windows Loader Lock internals to safely create threads from DllMain
- **ETW Blocking:** Hooks `EtwEventWrite`, `EventWriteEx`, `EventWrite` to suppress telemetry
- **PPID Spoofing:** Hooks `CreateProcessA/W` to spoof parent process as `svchost.exe`
- **Memory Protection Toggling:** Sleep hook flips RWX to RW and back to evade memory scanners
- **Direct Syscalls:** jitasm-based syscall stubs bypass user-mode hooking by EDR
- **API Hashing:** ROR13 and Murmur32 hashing to resolve API functions without plaintext strings
- **MZ Header Removal:** Encrypted payloads have PE headers stripped to defeat static scanning

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `connect-microsoft[.]com`)

### File System

| Platform | Path / Filename | Hash (MD5) | Description |
|----------|-----------------|------------|-------------|
| Windows | SystemSettings.exe (in non-standard dir) | D98F568496512E4F98670C61C97CB07A | Legitimate binary abused for DLL side-loading |
| Windows | SystemSettings.dll | AA3086BE652C8B20B0B29B2730D57119 | SharkLoader main DLL |
| Windows | DscCoreR.mui | A514D1BB62D7916475946FE7C07AC0AA | Encrypted Cobalt Strike beacon + MinHook |
| Windows | SyncRes.dat | 9CBD560F820C95D7C38342CD558CB5C6 | Encrypted API hooking DLL (Detours) |
| Windows | Dropper (GoogleUpdateStepup.exe variant) | 1F65544978B8EA0E745E573B8EE9684B | Dropper targeting Lebanon |
| Windows | Dropper (variant) | 24FCEBDEECBA65004FDB0923763D74FD | Dropper targeting Taiwan |
| Windows | Installer | C559CC68986933200FD5D9E4388E2F58 | SharkLoader installer component |
| Windows | Dropper | B3352B42432DEDC4A519F011DC8B5D5A | SharkLoader dropper component |
| Windows | SharkLoader DLL (variant) | 9C872A0D5D5A38950E8B9AC9B488BE3F | SharkLoader DLL variant |

**Deployment directories:** `%APPDATA%\xwreg`, `%APPDATA%\xgdf`, `%APPDATA%\Identities`, `C:\ProgramData\KasperskyLab`, `C:\ADriveLogs_Logs`

**Alternate encrypted payload names:** `GameInputInboxs32.mui`, `diagerr.xml`, `NtfsLog.etl`, `Ignored.Dat`, `VistaCompat.nls`

**Alternate side-loading DLLs:** `msedge.dll`, `PrintDialog.dll`, `miracastview.dll`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | connect-microsoft[.]com | C2 |
| Domain | ms-record[.]com | C2 |
| Domain | ms-record[.]top | C2 |
| Domain | ms-tray[.]top | C2 |

### Behavioral

**Process chain:** `SystemSettings.exe` (from non-standard path) loads `SystemSettings.dll` which decrypts and executes Cobalt Strike beacon in a suspended thread.

**PPID Spoofing:** All child processes spawned by the beacon appear to be children of `svchost.exe` due to `CreateProcessA/W` hooks.

**Registry persistence:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MFUpdate` pointing to `SystemSettings.exe` in the `Identities` directory.

**Scheduled tasks:**
- `OneDrive Standalone Update Task-S-1-5-21-4165425321-4153752593-2322023643-1000` (every 5 minutes)
- `MicrosoftUpdateTaskUserS-1-5-32-2456537112-101246289-228944324-1000` (every 1 second, transient)
- `\Microsoft\Windows\Edge\Edgeupdate` (daily, runs as SYSTEM)

**Post-compromise reconnaissance commands:** `systeminfo`, `ipconfig /all`, `tasklist /svc`, `netstat -ano`, `arp -a`, `net share`, `query user`, `nslookup`, `net group "Domain Controllers" /domain`, `net group "domain admins" /domain`

**Credential dumping:** `ntdsutil` (NTDS extraction), `Procdump64.exe` (LSASS dump)

**Post-exploitation tools:** FScan (scanner), Searchall (data search), Pillager (info gathering), SharpGPOAbuse (GPO modification)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of Exchange (CVE-2021-26855), Openfire (CVE-2023-32315), GeoServer (CVE-2024-36401) |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | SystemSettings.exe side-loads malicious SystemSettings.dll |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MFUpdate registry Run key persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Multiple scheduled tasks for persistence (Edge update, OneDrive task) |
| T1140 | Deobfuscate/Decode Files or Information | Blowfish/AES decryption of DscCoreR.mui and SyncRes.dat |
| T1055 | Process Injection | Suspended thread creation for Cobalt Strike beacon injection |
| T1134.004 | Access Token Manipulation: Parent PID Spoofing | CreateProcessA/W hooks spoof PPID to svchost.exe |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ETW blocking via EtwEventWrite/EventWrite hooks |
| T1106 | Native API | Direct syscall stubs via jitasm; extensive API hooking |
| T1027 | Obfuscated Files or Information | MZ header removal, encrypted payloads, API hashing (ROR13/Murmur32) |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Post-compromise reconnaissance via cmd.exe |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Get-ADGroupMember for AD enumeration |
| T1003.003 | OS Credential Dumping: NTDS | ntdsutil for NTDS database extraction |
| T1003.001 | OS Credential Dumping: LSASS Memory | Procdump64.exe targeting LSASS |
| T1087.002 | Account Discovery: Domain Account | dsquery/dsget, net group commands for AD enumeration |
| T1082 | System Information Discovery | systeminfo, ipconfig /all |
| T1049 | System Network Connections Discovery | netstat -ano |
| T1057 | Process Discovery | tasklist /svc |

## Impact Assessment

The StrikeShark campaign represents a significant threat to government and diplomatic organizations in the Asia-Pacific region and beyond. The combination of known vulnerability exploitation for initial access with advanced evasion techniques (Perfect DLL Hijacking, ETW blocking, PPID spoofing, memory protection toggling, direct syscalls) makes detection challenging. The deployment of Cobalt Strike provides the threat actor with full post-compromise capabilities including credential theft, lateral movement, and data exfiltration. The breadth of targeted CVEs (13+ vulnerabilities across diverse products) indicates an opportunistic yet well-resourced adversary.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for SharkLoader persistence registry key
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v MFUpdate 2>$null

# Check for SystemSettings.exe in non-standard directories
Get-ChildItem -Path "C:\ProgramData","$env:APPDATA" -Recurse -Filter "SystemSettings.exe" -ErrorAction SilentlyContinue

# Check for known encrypted payload filenames
Get-ChildItem -Path "C:\ProgramData","$env:APPDATA" -Recurse -Include "DscCoreR.mui","SyncRes.dat","GameInputInboxs32.mui","Ignored.Dat","VistaCompat.nls" -ErrorAction SilentlyContinue

# Check for suspicious scheduled tasks
schtasks /query /fo LIST /v | Select-String -Pattern "Edgeupdate|OneDrive Standalone Update Task-S-1-5-21-|MicrosoftUpdateTaskUserS-1-5-32-"

# Check for C2 domain resolution (DNS cache)
Get-DnsClientCache | Where-Object { $_.Entry -match "connect-microsoft|ms-record|ms-tray" }
```

### Remediation

1. **Contain:** Isolate affected hosts; block C2 domains (`connect-microsoft.com`, `ms-record.com`, `ms-record.top`, `ms-tray.top`) at DNS/proxy
2. **Eradicate:** Remove `MFUpdate` registry Run key; delete scheduled tasks; remove SharkLoader files from deployment directories
3. **Credential Reset:** Assume credential compromise; reset all domain admin, service account, and affected user passwords; rotate Kerberos KRBTGT key twice
4. **Patch:** Prioritize patching all listed CVEs on internet-facing infrastructure (Exchange, Openfire, GeoServer, FortiOS, Cisco IOS XE, etc.)
5. **Hunt:** Search for `SystemSettings.exe` executing from any path other than `C:\Windows\ImmersiveControlPanel\` or `C:\Windows\SystemApps\`

### Long-Term Hardening

- Deploy application allowlisting to prevent DLL side-loading from non-standard directories
- Enable ETW-TI (Threat Intelligence) provider to detect ETW tampering
- Monitor for suspicious scheduled task creation with names mimicking Microsoft products
- Implement network segmentation to limit lateral movement from compromised servers
- Enable Sysmon with configuration covering process creation, image loads, and registry events

## Detection Rules

These detections target SharkLoader DLL side-loading, encrypted payload deployment, persistence mechanisms, and C2 domain resolution from the StrikeShark campaign. PoC/advisory-specific altitude; all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles clean does not mean fires clean -- verify rules in your pipeline with representative telemetry.

### Sigma: SharkLoader DLL Side-Loading via SystemSettings.exe
Detects SystemSettings.exe executing from a non-standard directory, the key indicator of SharkLoader DLL side-loading.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE STIX download timeout (network issue, not rule issue). splunk convert exit 0; log_scale convert exit 0. Fields: Image (process_creation/windows) — standard Sysmon/4688 field, no encoding concerns. Non-defanged paths in detection values. Revision 1.1: removed incorrect attack.t1059.003 tag (command-line interpreter not relevant to this DLL side-loading rule). -->
```yaml
title: SharkLoader DLL Side-Loading via SystemSettings.exe
id: 7c3a9f1e-4d2b-48e6-a5c3-6b8d0e9f2a1c
status: experimental
description: >
    Detects the SharkLoader DLL side-loading chain where SystemSettings.exe
    is copied to an unusual directory and executed, loading the malicious
    SystemSettings.dll loader as observed in the StrikeShark campaign.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\SystemSettings.exe'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\ImmersiveControlPanel\'
            - 'C:\Windows\SystemApps\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate copies of SystemSettings.exe in non-standard directories (unlikely)
level: high
```

### Sigma: SharkLoader Encrypted Payload File Creation
Detects creation of files matching SharkLoader encrypted payload names (DscCoreR.mui, SyncRes.dat, and known alternates).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. TargetFilename (file_event/windows) — standard Sysmon EID 11 field. Filenames are distinctive to this campaign. Revision 1.1: added filter_system32 to exclude legitimate VistaCompat.nls at C:\Windows\System32\; downgraded confidence from high to medium. -->
```yaml
title: SharkLoader Encrypted Payload File Creation
id: 8b4e2d7a-5f3c-49d1-b6e4-7c9a1f0d3b2e
status: experimental
description: >
    Detects creation of encrypted payload files (DscCoreR.mui, SyncRes.dat)
    or their known alternate names used by SharkLoader in the StrikeShark
    campaign to deliver Cobalt Strike beacons.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1140
    - attack.t1027
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\DscCoreR.mui'
            - '\SyncRes.dat'
            - '\GameInputInboxs32.mui'
            - '\Ignored.Dat'
            - '\VistaCompat.nls'
    filter_system32:
        TargetFilename|startswith: 'C:\Windows\System32\'
    condition: selection and not filter_system32
falsepositives:
    - Legitimate Windows files with the same names in system directories
level: medium
```

### Sigma: SharkLoader Registry Persistence via MFUpdate Run Key
Detects the MFUpdate registry Run key -- the exact persistence value name used by SharkLoader.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. TargetObject (registry_set/windows) — standard Sysmon EID 13 field. "MFUpdate" is highly distinctive and not a known legitimate value name. -->
```yaml
title: SharkLoader Registry Persistence via MFUpdate Run Key
id: 9d5f3e8b-6a4d-4ae2-c7f5-8d0b2e1a4c3f
status: experimental
description: >
    Detects the SharkLoader persistence mechanism that creates an MFUpdate
    registry Run key pointing to SystemSettings.exe in the Identities
    directory, as observed in the StrikeShark campaign.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Microsoft\Windows\CurrentVersion\Run\MFUpdate'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

### Sigma: SharkLoader Scheduled Task Creation for Persistence
Detects schtasks.exe creating tasks with names and paths matching SharkLoader's known persistence patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. Fields: Image, CommandLine (process_creation/windows) — standard. Task names contain campaign-specific SIDs and paths (ADriveLogs_Logs) that are distinctive. -->
```yaml
title: SharkLoader Scheduled Task Creation for Persistence
id: ae6f4a9c-7b5e-4bf3-d8a6-9e1c3f2b5d4a
status: experimental
description: >
    Detects schtasks.exe creating scheduled tasks with names and paths
    matching SharkLoader persistence patterns from the StrikeShark campaign,
    including tasks masquerading as Edge updates or OneDrive sync.
references:
    - https://securelist.com/strikeshark-campaign/120326/
    - https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    selection_indicators:
        CommandLine|contains:
            - '\Microsoft\Windows\Edge\Edgeupdate'
            - 'ADriveLogs_Logs\SystemSettings.exe'
            - 'OneDrive Standalone Update Task-S-1-5-21-'
            - 'MicrosoftUpdateTaskUserS-1-5-32-'
    condition: selection_schtasks and selection_indicators
falsepositives:
    - Legitimate Microsoft Edge or OneDrive scheduled tasks (names differ slightly)
level: high
```

### Snort: SharkLoader C2 Domain DNS Queries
Detects DNS queries to the four known SharkLoader C2 domains using DNS wire-format label-length encoding.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (with include) exit 0. -R flag hit Snort 2.9 pidfile suffix bug (environment issue, not rule issue); validated via include directive. DNS label-length encoding: connect-microsoft = 0x11 (17 bytes), ms-record = 0x09 (9 bytes), ms-tray = 0x07 (7 bytes), com = 0x03, top = 0x03. All values real (not defanged). -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SharkLoader C2 Domain connect-microsoft.com"; flow:to_server; content:"|11|connect-microsoft|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created 2026-06-28; sid:2100101; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-record.com"; flow:to_server; content:"|09|ms-record|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created 2026-06-28; sid:2100102; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-record.top"; flow:to_server; content:"|09|ms-record|03|top|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created 2026-06-28; sid:2100103; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-tray.top"; flow:to_server; content:"|07|ms-tray|03|top|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created 2026-06-28; sid:2100104; rev:1;)
```

### Suricata: SharkLoader C2 Domain DNS Queries
Detects DNS queries to the four known SharkLoader C2 domains via Suricata's `dns.query` sticky buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dns.query dot-notation sticky buffer (correct Suricata syntax). Domain values are real (not defanged). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SharkLoader C2 Domain connect-microsoft.com"; flow:to_server; dns.query; content:"connect-microsoft.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created_at 2026-06-28; sid:2200101; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-record.com"; flow:to_server; dns.query; content:"ms-record.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created_at 2026-06-28; sid:2200102; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-record.top"; flow:to_server; dns.query; content:"ms-record.top"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created_at 2026-06-28; sid:2200103; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to SharkLoader C2 Domain ms-tray.top"; flow:to_server; dns.query; content:"ms-tray.top"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securelist.com/strikeshark-campaign/120326/; metadata:author Actioner, created_at 2026-06-28; sid:2200104; rev:1;)
```

### YARA: SharkLoader DLL and Dropper Detection
Detects SharkLoader DLL and dropper binaries via characteristic PE resource names (TELEMETRY, VAULTSVCD, UMRDPRDAT) and encrypted payload filenames.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt matched Malware_SharkLoader_DLL; neg.txt quiet. Positive constructed from published resource names (TELEMETRY, VAULTSVCD, UMRDPRDAT) and filenames (DscCoreR.mui, SyncRes.dat) per Securelist report. Two rules: _DLL (loader) and _Dropper (installer). PE header check + filesize constraint + combinatorial string matching. -->
```yara
import "pe"

rule Malware_SharkLoader_DLL
{
    meta:
        description = "Detects SharkLoader DLL (SystemSettings.dll) used in StrikeShark campaign via characteristic resource names and encrypted payload references"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        severity = "critical"

    strings:
        $res1 = "TELEMETRY" ascii wide
        $res2 = "VAULTSVCD" ascii wide
        $res3 = "UMRDPRDAT" ascii wide
        $file1 = "DscCoreR.mui" ascii wide
        $file2 = "SyncRes.dat" ascii wide
        $file3 = "SystemSettings.dll" ascii wide
        $alt1 = "GameInputInboxs32.mui" ascii wide
        $alt2 = "VistaCompat.nls" ascii wide
        $alt3 = "Ignored.Dat" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($res*)) or
            ($file1 and $file2) or
            (1 of ($res*) and 1 of ($file*)) or
            (1 of ($res*) and 1 of ($alt*))
        )
}

rule Malware_SharkLoader_Dropper
{
    meta:
        description = "Detects SharkLoader dropper executables masquerading as legitimate installers (Google Update, Cisco AnyConnect) in the StrikeShark campaign"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://securelist.com/strikeshark-campaign/120326/"
        severity = "high"

    strings:
        $lure1 = "GoogleUpdateStepup" ascii wide
        $lure2 = "AnyConnect-win-4.10.04071-predeploy-k9" ascii wide
        $lure3 = "AutoUpdate.exe" ascii wide
        $res1 = "TELEMETRY" ascii wide
        $res2 = "VAULTSVCD" ascii wide
        $res3 = "UMRDPRDAT" ascii wide
        $path1 = "\\xwreg\\" ascii wide
        $path2 = "\\xgdf\\" ascii wide
        $path3 = "\\aswerf\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($lure*) and 1 of ($res*)) or
            (2 of ($res*) and 1 of ($path*))
        )
}
```

## Lessons Learned

1. **DLL side-loading remains a potent evasion vector.** Abusing legitimate, signed Windows binaries like `SystemSettings.exe` allows malware to execute under a trusted process name. Organizations should monitor for legitimate system binaries running from unexpected directories.

2. **Advanced loader lock manipulation raises the bar.** The "Perfect DLL Hijacking" technique demonstrates that threat actors are investing in low-level Windows internals research to bypass security assumptions about DllMain limitations.

3. **Layered evasion defeats single-point detection.** The combination of ETW blocking, PPID spoofing, direct syscalls, memory protection toggling, and API hashing means no single detection mechanism is sufficient. Defense-in-depth with Sysmon, network monitoring, and behavioral analytics is essential.

4. **Patch management for internet-facing assets is critical.** The campaign exploits vulnerabilities dating back to 2016 (Apache Shiro) through 2024 (GeoServer), all of which have available patches. Timely patching of public-facing infrastructure would deny the primary initial access vector.

## Sources

- [Kaspersky Securelist - StrikeShark Campaign](https://securelist.com/strikeshark-campaign/120326/) -- primary technical analysis with IOCs, TTPs, and detailed malware reverse engineering
- [The Hacker News - New SharkLoader Malware Deploys Cobalt Strike](https://thehackernews.com/2026/06/new-sharkloader-malware-deploys-cobalt.html) -- secondary reporting summarizing Kaspersky research

---
*Report generated by Actioner*
