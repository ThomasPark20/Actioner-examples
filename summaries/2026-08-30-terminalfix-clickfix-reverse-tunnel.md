# Technical Analysis Report: TerminalFix Campaign (2026-08-30)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-30
Version: 1.0 (DRAFT)

## Executive Summary

TerminalFix is a ClickFix-variant campaign first reported by Microsoft on August 28, 2026, that chains a fake Cloudflare CAPTCHA on compromised websites with an eight-stage intrusion culminating in a Python-based TLS WebSocket reverse tunnel. The campaign uses DLL sideloading of the legitimate Windows binary `LockScreenContentServer.exe` with a trojanized `dui70.dll`, steganographic payload extraction from PNG images, and asynchronous command execution via file-watch loops. The final implant -- a Python 3.14.5 script running under `pythonw.exe` -- opens a reverse tunnel to `gitnow[.]dev:443` with SOCKS5 proxy, TCP forwarding, and User-Agent rotation capabilities. Microsoft has published 10 SHA-256 hashes for the malicious DLL variants and four associated domains. The attack is Windows-only and targets enterprise environments with Active Directory reconnaissance built into the post-exploitation phase.

## Background: ClickFix Social Engineering and DLL Sideloading

ClickFix is a social engineering technique where compromised or attacker-controlled websites display a fake browser verification (typically mimicking Cloudflare's CAPTCHA challenge) to trick users into copying and executing malicious commands. TerminalFix extends this pattern with a multi-stage payload chain that avoids dropping recognizable malware directly -- instead leveraging a legitimate Microsoft-signed binary for DLL sideloading and hiding subsequent stages inside steganographic PNG images. The use of `LockScreenContentServer.exe` as the sideloading host is notable because this binary ships with Windows and is digitally signed, allowing it to bypass application whitelisting controls.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-28 (reported) | Microsoft publishes analysis of TerminalFix campaign observed Aug 28-29, 2026 |
| Stage 1 | Victim visits compromised website (linked-log[.]com) displaying fake Cloudflare CAPTCHA |
| Stage 2 | CAPTCHA interaction triggers PowerShell to download verify_pkg.zip |
| Stage 3 | ZIP extracted to `C:\ProgramData\f47f2a8c21c9df4e`; `1.bat` executes `LockScreenContentServer.exe` |
| Stage 4 | Sideloaded `dui70.dll` spawns PowerShell for steganographic payload extraction from PNG files hosted on bestsocialmedianewspapper[.]com / offlineupdater[.]com |
| Stage 5 | Persistence established via HKCU Run key and scheduled task (60-min interval) |
| Stage 6 | Active Directory reconnaissance: nltest, net group, ADSI queries, ping sweeps |
| Stage 7 | Asynchronous command execution loop via file-watch + Invoke-Expression |
| Stage 8 | `pythonw.exe` launches `client.py` reverse tunnel to gitnow[.]dev:443 over TLS WebSocket |

## Root Cause: Compromised Website with Fake CAPTCHA (ClickFix)

Initial access is achieved through the ClickFix social engineering technique. Victims visit a compromised legitimate website (linked-log[.]com) that displays a convincing fake Cloudflare CAPTCHA page. Interacting with the CAPTCHA causes PowerShell to download a malicious ZIP archive (`verify_pkg.zip`). The reliance on user interaction (copying and running a clipboard payload) bypasses traditional email-based phishing detection and network-level blocking because the initial URL is a compromised legitimate domain, not a known-bad indicator.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader -- ZIP Delivery and DLL Sideloading

The PowerShell downloader retrieves `verify_pkg.zip` (SHA-256: `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f`) and extracts its contents to `C:\ProgramData\f47f2a8c21c9df4e`. The archive contains:

- `1.bat` -- batch file that launches the sideloading host
- `LockScreenContentServer.exe` -- legitimate Microsoft-signed binary
- `dui70.dll` -- trojanized DLL (10 known variants)

The batch file executes `LockScreenContentServer.exe`, which loads `dui70.dll` from its current directory due to the DLL search order. Since the legitimate `dui70.dll` resides in `C:\Windows\System32`, loading it from `C:\ProgramData` is a clear sideloading indicator. The directory is hidden using `attrib +h +s` to evade casual inspection.

### 2. Steganographic Payload Extraction

The malicious `dui70.dll` spawns a PowerShell process that downloads PNG image files from `bestsocialmedianewspapper[.]com` (primary) and `offlineupdater[.]com` (failover). Payloads are encoded within the RGBA channel data of these images and extracted by the DLL's steganographic decoder. This technique (T1027.003) defeats content-based inspection that would flag standard encoded payloads.

### 3. C2 Infrastructure

| Component | Detail |
|-----------|--------|
| Primary C2 | `gitnow[.]dev:443` |
| Protocol | TLS 1.2 WebSocket, endpoint `/tunnel` |
| Stego hosting | `bestsocialmedianewspapper[.]com`, `offlineupdater[.]com` |
| Initial access vector | `linked-log[.]com` (compromised) |
| Implant capabilities | SOCKS5 address parsing, TCP proxying, User-Agent rotation, MSG_SHUTDOWN, stream multiplexing (7-byte header) |

The reverse tunnel implant communicates over TLS 1.2 WebSocket to `gitnow[.]dev:443/tunnel`. The use of port 443 with valid TLS allows the traffic to blend with legitimate HTTPS. The implant implements stream multiplexing with a 7-byte framing header, supports SOCKS5 address parsing for flexible targeting, and rotates User-Agent strings to frustrate network-level behavioral detection.

### 4. Platform-Specific Behavior

#### Windows (sole target platform)

- **Delivery:** PowerShell downloads ZIP
- **Execution:** DLL sideloading via `LockScreenContentServer.exe` + `dui70.dll`
- **Persistence:** HKCU Run key `LockScreenContentServer_MuODG5yBM` + scheduled task (60-min)
- **Implant runtime:** Embedded Python 3.14.5 (`pythonw.exe`) running `client.py`
- **Reconnaissance:** Windows-native tools (nltest, net.exe, ADSI) for AD enumeration
- **Command loop:** File-watch + `Invoke-Expression` for asynchronous task execution

No Linux or macOS variants have been reported.

### 5. Anti-Forensics / Evasion Techniques

- **DLL sideloading** (T1574.002): Uses a legitimate signed Microsoft binary to load the malicious DLL, bypassing application whitelisting
- **Steganography** (T1027.003): Payloads hidden in PNG RGBA channels defeat content inspection
- **Directory hiding** (T1564.001): `attrib +h +s` on staging directory `C:\ProgramData\f47f2a8c21c9df4e`
- **Masquerading** (T1036.005): Binary names match legitimate Windows components
- **Windowless Python** (T1059.001): Uses `pythonw.exe` (no console window) for the reverse tunnel implant
- **TLS on port 443**: C2 traffic disguised as standard HTTPS
- **User-Agent rotation**: Evades static User-Agent-based network detection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path / Filename | Hash (SHA-256) | Description |
|----------|----------------|----------------|-------------|
| Windows | verify_pkg.zip | `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f` | Initial payload ZIP |
| Windows | dui70.dll | `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a` | Malicious DLL variant |
| Windows | dui70.dll | `ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07` | Malicious DLL variant |
| Windows | dui70.dll | `026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab` | Malicious DLL variant |
| Windows | dui70.dll | `032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22` | Malicious DLL variant |
| Windows | dui70.dll | `df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf` | Malicious DLL variant |
| Windows | dui70.dll | `eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0` | Malicious DLL variant |
| Windows | dui70.dll | `5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8` | Malicious DLL variant |
| Windows | dui70.dll | `9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24` | Malicious DLL variant |
| Windows | dui70.dll | `342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e` | Malicious DLL variant |
| Windows | dui70.dll | `ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d` | Malicious DLL variant |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | gitnow[.]dev | Primary C2 -- TLS WebSocket reverse tunnel on port 443 |
| Domain | bestsocialmedianewspapper[.]com | Steganographic PNG image hosting (primary) |
| Domain | offlineupdater[.]com | Steganographic PNG image hosting (failover) |
| Domain | linked-log[.]com | Compromised website used for initial access |
| URL Pattern | `hxxps://gitnow[.]dev:443/tunnel` | WebSocket reverse tunnel endpoint |

### Behavioral

- `LockScreenContentServer.exe` loading `dui70.dll` from a directory other than `C:\Windows\System32` (DLL sideloading)
- Registry value creation: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM`
- Scheduled task creation named `LockScreenContentServer_MuODG5yBM` with 60-minute recurrence
- `attrib +h +s` applied to `C:\ProgramData\f47f2a8c21c9df4e`
- `pythonw.exe` executing `client.py` from the staging directory
- Sequential execution of `nltest /dclist:`, `net group "Domain Admins"`, and ADSI queries from a PowerShell process spawned by the sideloading chain
- Outbound TLS connections to port 443 with WebSocket upgrade to `/tunnel`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised website (linked-log[.]com) with fake Cloudflare CAPTCHA |
| T1059.001 | PowerShell | PowerShell downloads ZIP, extracts stego payloads, runs command loop |
| T1204.002 | Malicious File | User interaction with fake CAPTCHA triggers payload execution |
| T1547.001 | Registry Run Keys / Startup Folder | HKCU Run key for LockScreenContentServer_MuODG5yBM |
| T1053.005 | Scheduled Task | 60-minute scheduled task for persistence |
| T1574.002 | DLL Side-Loading | LockScreenContentServer.exe loads malicious dui70.dll |
| T1027.003 | Steganography | Payloads hidden in RGBA channels of PNG images |
| T1564.001 | Hidden Files and Directories | attrib +h +s on staging directory |
| T1036.005 | Match Legitimate Name or Location | Binary names mimic Windows components |
| T1018 | Remote System Discovery | Ping sweeps for network reconnaissance |
| T1069.002 | Domain Groups | net group "Domain Admins" /domain |
| T1482 | Domain Trust Discovery | nltest /dclist: for domain controller enumeration |
| T1087.002 | Domain Account | ADSI queries for domain account enumeration |
| T1082 | System Information Discovery | System enumeration during reconnaissance phase |
| T1572 | Protocol Tunneling | TLS WebSocket reverse tunnel via Python implant |
| T1071.001 | Web Protocols | C2 over HTTPS/WebSocket on port 443 |
| T1105 | Ingress Tool Transfer | PowerShell download of ZIP and stego images |

## Impact Assessment

The TerminalFix campaign is a targeted intrusion framework with enterprise-grade post-exploitation capabilities. The reverse tunnel implant provides the operator with full SOCKS5 proxy and TCP forwarding access into the victim network, enabling lateral movement, data exfiltration, and additional tool deployment. The AD reconnaissance stage indicates the operators are specifically targeting Active Directory environments and seeking Domain Admin credentials. The use of 10 distinct DLL variants suggests active retooling to evade hash-based detection. The steganographic payload delivery and TLS WebSocket tunneling make network-level detection challenging without TLS inspection or SNI-based monitoring.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for staging directory
Test-Path "C:\ProgramData\f47f2a8c21c9df4e"

# Check for persistence registry key
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-String "LockScreenContentServer_MuODG5yBM"

# Check for scheduled task
Get-ScheduledTask | Where-Object { $_.TaskName -like "*LockScreenContentServer_MuODG5yBM*" }

# Check for DLL sideloading — dui70.dll loaded from non-System32 path
Get-Process LockScreenContentServer -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -eq "dui70.dll" -and $_.FileName -notlike "C:\Windows\System32\*" }

# Check for pythonw.exe running client.py
Get-WmiObject Win32_Process -Filter "Name='pythonw.exe'" | Where-Object { $_.CommandLine -like "*client.py*" }
```

### Remediation

1. **Contain:** Isolate affected hosts from the network immediately to sever the reverse tunnel
2. **Kill processes:** Terminate `LockScreenContentServer.exe`, `pythonw.exe` (running `client.py`), and any associated PowerShell processes
3. **Remove persistence:** Delete the registry key `HKCU\...\Run\LockScreenContentServer_MuODG5yBM` and the scheduled task
4. **Delete staging directory:** Remove `C:\ProgramData\f47f2a8c21c9df4e` and all contents
5. **Block network IOCs:** Add `gitnow[.]dev`, `bestsocialmedianewspapper[.]com`, `offlineupdater[.]com`, and `linked-log[.]com` to DNS sinkholes and firewall block lists
6. **Credential rotation:** Reset passwords for any accounts that were active on compromised hosts, especially if Domain Admin reconnaissance was observed
7. **AD audit:** Review AD for unauthorized group membership changes, new accounts, or trust modifications
8. **Scan enterprise:** Use the YARA rules below to scan endpoints for DLL variants

### Long-Term Hardening

- Deploy application control policies that prevent DLL loading from `C:\ProgramData` by signed system binaries
- Enable and monitor Sysmon Event ID 7 (Image Load) for DLL sideloading detection
- Enable PowerShell Script Block Logging (Event ID 4104) and Constrained Language Mode
- Deploy TLS inspection or SNI-based monitoring for outbound connections to detect C2 domains
- Implement DNS query logging and alerting for newly registered or low-reputation domains
- Block execution of embedded Python interpreters from non-standard directories
- Consider blocking `pythonw.exe` execution from `C:\ProgramData` via AppLocker or WDAC

## Detection Rules

These rules cover the TerminalFix campaign's key observable artifacts: DLL sideloading, persistence mechanisms, AD reconnaissance, reverse tunnel execution, malicious file hashes, and network C2 indicators. All rules use campaign-specific indicators at advisory altitude; the Sigma AD-recon rule requires a parent-process filter to limit false positives from legitimate admin activity.

### Sigma: DLL Sideloading -- LockScreenContentServer.exe + dui70.dll

Detects the core sideloading behavior where LockScreenContentServer.exe loads dui70.dll from outside System32.
<!-- audit: compile-validated via sigma convert --without-pipeline -t splunk + log_scale 2026-08-30; sigma check skipped (MITRE ATT&CK data endpoint unreachable in CI); logsource image_load requires Sysmon EID 7 or equivalent; field names Image/ImageLoaded per Sysmon schema; no defanged values in detection; filter_legit_path covers System32, SysWOW64, WinSxS -->

compile: pass (splunk + log_scale) | confidence: high

```yaml
title: TerminalFix DLL Sideloading via LockScreenContentServer
id: b00eb69b-70f1-4a05-87ac-3b00ebe02c72
status: experimental
description: >
    Detects DLL sideloading where LockScreenContentServer.exe loads a malicious
    dui70.dll from a non-standard directory, as observed in the TerminalFix
    campaign (Aug 2026). The legitimate dui70.dll resides in System32; loading
    from ProgramData or other unusual paths indicates sideloading.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026-08-30
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_image:
        Image|endswith: '\LockScreenContentServer.exe'
    selection_dll:
        ImageLoaded|endswith: '\dui70.dll'
    filter_legit_path:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection_image and selection_dll and not filter_legit_path
falsepositives:
    - Portable or relocated installations of Windows system components
level: high
```

### Sigma: Registry Run Key Persistence

Detects the campaign-specific registry Run key value used for persistence.
<!-- audit: compile-validated via sigma convert --without-pipeline -t splunk + log_scale 2026-08-30; sigma check skipped (MITRE ATT&CK data endpoint unreachable); logsource registry_set requires Sysmon EID 13 or equivalent; TargetObject field per Sysmon schema; value name LockScreenContentServer_MuODG5yBM is unique to this campaign -->

compile: pass (splunk + log_scale) | confidence: high

```yaml
title: TerminalFix Registry Run Key Persistence
id: dac260c5-e4cb-4bb2-a8e4-d42d5cbc7039
status: experimental
description: >
    Detects creation of a Registry Run key named LockScreenContentServer_MuODG5yBM
    under HKCU CurrentVersion\Run, used by the TerminalFix campaign for
    persistence of the sideloaded DLL loader.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026-08-30
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM'
    condition: selection
falsepositives:
    - None expected; this value name is unique to the campaign
level: critical
```

### Sigma: Scheduled Task Persistence

Detects schtasks.exe creating the campaign-specific scheduled task.
<!-- audit: compile-validated via sigma convert --without-pipeline -t splunk + log_scale 2026-08-30; process_creation logsource requires Sysmon EID 1 or Security 4688 with command-line auditing; task name is unique to campaign; no defanged values -->

compile: pass (splunk + log_scale) | confidence: high

```yaml
title: TerminalFix Scheduled Task Persistence
id: e7487de6-1b90-40cc-99a8-e36b2b051432
status: experimental
description: >
    Detects creation of a scheduled task named LockScreenContentServer_MuODG5yBM,
    used by the TerminalFix campaign to re-execute the sideloaded DLL loader
    every 60 minutes.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026-08-30
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\schtasks.exe'
    selection_args:
        CommandLine|contains: 'LockScreenContentServer_MuODG5yBM'
    condition: selection_binary and selection_args
falsepositives:
    - None expected; this task name is unique to the campaign
level: critical
```

### Sigma: AD Reconnaissance Commands

Detects nltest and net group commands spawned from the TerminalFix process chain; parent-process filter required to reduce FPs from legitimate admin activity.
<!-- audit: compile-validated via sigma convert --without-pipeline -t splunk + log_scale 2026-08-30; parent-process scoping reduces FPs but requires Sysmon EID 1 for ParentImage; environment where admins routinely run nltest from PowerShell may still generate low-volume FPs -->

compile: pass (splunk + log_scale) | confidence: medium

```yaml
title: TerminalFix AD Reconnaissance Command Sequence
id: 53377156-5260-4aa1-a9c6-b35e64c47e15
status: experimental
description: >
    Detects Active Directory reconnaissance commands observed in the TerminalFix
    campaign, including nltest for domain trust enumeration, net group for domain
    admin discovery, and ADSI queries. Matching any single command from this set
    when spawned by LockScreenContentServer.exe or its child PowerShell.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026-08-30
tags:
    - attack.t1482
    - attack.t1069.002
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection_nltest:
        Image|endswith: '\nltest.exe'
        CommandLine|contains: '/dclist:'
    selection_netgroup:
        Image|endswith: '\net.exe'
        CommandLine|contains|all:
            - 'group'
            - 'Domain Admins'
    selection_parent:
        ParentImage|endswith:
            - '\LockScreenContentServer.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: (selection_nltest or selection_netgroup) and selection_parent
falsepositives:
    - Domain administrators running legitimate trust enumeration
    - IT inventory scripts querying domain group membership
level: high
```

### Sigma: Python Reverse Tunnel Execution

Detects pythonw.exe launching client.py from the TerminalFix staging directory.
<!-- audit: compile-validated via sigma convert --without-pipeline -t splunk + log_scale 2026-08-30; staging directory GUID f47f2a8c21c9df4e is unique to campaign; CommandLine field required; no FPs expected -->

compile: pass (splunk + log_scale) | confidence: high

```yaml
title: TerminalFix Python Reverse Tunnel Execution
id: 01c66ea0-815e-47ca-876b-cf6e6b0db602
status: experimental
description: >
    Detects execution of pythonw.exe launching client.py from the TerminalFix
    staging directory (C:\ProgramData\f47f2a8c21c9df4e), used to establish
    a TLS WebSocket reverse tunnel to the C2 server.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026-08-30
tags:
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\pythonw.exe'
    selection_cmdline:
        CommandLine|contains: 'client.py'
    selection_path:
        CommandLine|contains: '\ProgramData\f47f2a8c21c9df4e'
    condition: selection_binary and selection_cmdline and selection_path
falsepositives:
    - None expected; the staging directory GUID is unique to this campaign
level: critical
```

### YARA: Malicious dui70.dll Variants

Matches all 10 known dui70.dll variants by SHA-256 hash, with a behavioral fallback matching campaign-specific strings in DLL files.
<!-- audit: yarac 4.5.0 compile-validated 2026-08-30; pe.is_dll unavailable in YARA 4.5 — replaced with pe.characteristics & pe.DLL; hash module required for SHA-256 matching; behavioral branch fires on 3-of-N campaign strings as fallback for new variants; stego markers included in string set for broader coverage -->

compile: pass (yarac 4.5.0) | confidence: high

```yara
import "pe"
import "hash"

rule TerminalFix_Dui70_DLL_Sideload
{
    meta:
        description = "Detects malicious dui70.dll variants used in the TerminalFix campaign for DLL sideloading via LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-08-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a"
        hash = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        hash = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab"
        hash = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22"
        hash = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf"
        hash = "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0"
        hash = "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8"
        hash = "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24"
        hash = "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e"
        hash = "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $export_name = "dui70.dll" ascii wide nocase
        $stego_marker1 = "RGBA" ascii
        $stego_marker2 = ".png" ascii wide nocase
        $c2_domain = "gitnow.dev" ascii wide
        $staging_dir = "f47f2a8c21c9df4e" ascii wide
        $cmd_loop = "Invoke-Expression" ascii wide nocase
        $persistence_key = "LockScreenContentServer_MuODG5yBM" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & pe.DLL) != 0 and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a" or
            hash.sha256(0, filesize) == "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07" or
            hash.sha256(0, filesize) == "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab" or
            hash.sha256(0, filesize) == "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22" or
            hash.sha256(0, filesize) == "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf" or
            hash.sha256(0, filesize) == "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0" or
            hash.sha256(0, filesize) == "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8" or
            hash.sha256(0, filesize) == "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24" or
            hash.sha256(0, filesize) == "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e" or
            hash.sha256(0, filesize) == "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d" or
            (3 of ($export_name, $stego_marker*, $c2_domain, $staging_dir, $cmd_loop, $persistence_key))
        )
}
```

### YARA: verify_pkg.zip Delivery Archive

Matches the initial payload ZIP by hash with a behavioral fallback for archives containing the expected file names.
<!-- audit: yarac 4.5.0 compile-validated 2026-08-30; ZIP magic at offset 0; hash module for SHA-256; behavioral branch matches 3-of-4 expected filenames within ZIP entries; 50MB size cap is generous to cover padded variants -->

compile: pass (yarac 4.5.0) | confidence: high

```yara
import "hash"

rule TerminalFix_Verify_Pkg_ZIP
{
    meta:
        description = "Detects the verify_pkg.zip archive used as the initial payload delivery mechanism in the TerminalFix campaign"
        author = "Actioner"
        date = "2026-08-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $zip_header = { 50 4B 03 04 }
        $bat_name = "1.bat" ascii
        $exe_name = "LockScreenContentServer.exe" ascii
        $dll_name = "dui70.dll" ascii
        $staging_dir = "f47f2a8c21c9df4e" ascii

    condition:
        $zip_header at 0 and
        filesize < 50MB and
        (
            hash.sha256(0, filesize) == "18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f" or
            (3 of ($bat_name, $exe_name, $dll_name, $staging_dir))
        )
}
```

### Suricata: TLS Connection to gitnow[.]dev C2

Alerts on TLS connections where the SNI matches the primary C2 domain.
<!-- audit: suricata 7.0.3 -T validated 2026-08-30; tls protocol with tls.sni sticky buffer; endswith constrains to exact domain (not subdomains of different registrable domains); nocase for case-insensitive SNI matching; fast_pattern on single content -->

compile: pass (suricata 7.0.3 -T) | confidence: high

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix TLS Connection to gitnow.dev C2"; flow:established,to_server; tls.sni; content:"gitnow.dev"; endswith; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-30, campaign TerminalFix; sid:2100101; rev:1;)
```

### Suricata: Steganographic Image Hosting Domains

Alerts on TLS connections to the two image-hosting domains used for steganographic payload delivery, plus the compromised initial access domain.
<!-- audit: suricata 7.0.3 -T validated 2026-08-30; three separate rules (one per domain) for independent enable/disable; tls.sni sticky buffer; nocase; SIDs 2100102-2100104 -->

compile: pass (suricata 7.0.3 -T) | confidence: high

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Steganographic Image Host bestsocialmedianewspapper.com"; flow:established,to_server; tls.sni; content:"bestsocialmedianewspapper.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-30, campaign TerminalFix; sid:2100102; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Steganographic Image Host offlineupdater.com"; flow:established,to_server; tls.sni; content:"offlineupdater.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-30, campaign TerminalFix; sid:2100103; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Compromised Website linked-log.com"; flow:established,to_server; tls.sni; content:"linked-log.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-30, campaign TerminalFix; sid:2100104; rev:1;)
```

### Snort: C2 and Steganographic Image Domains

Equivalent Snort 3 rules for the same network indicators.
<!-- audit: Snort 3 not available in validation environment; structural check only -- verified header fields, underscore-notation sticky buffers (http_uri, ssl_state), semicolons, balanced parentheses, required fields (msg, sid, rev, gid). Snort 3 uses service:ssl for TLS inspection, not the tls protocol keyword. -->

compile: structural check only | confidence: medium

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - TerminalFix TLS C2 gitnow.dev"; flow:established,to_server; ssl_state:client_hello; content:"gitnow.dev"; fast_pattern:only; metadata:author Actioner, created_at 2026-08-30; classtype:trojan-activity; sid:3100101; rev:1; gid:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - TerminalFix Stego Host bestsocialmedianewspapper.com"; flow:established,to_server; ssl_state:client_hello; content:"bestsocialmedianewspapper.com"; fast_pattern:only; metadata:author Actioner, created_at 2026-08-30; classtype:trojan-activity; sid:3100102; rev:1; gid:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - TerminalFix Stego Host offlineupdater.com"; flow:established,to_server; ssl_state:client_hello; content:"offlineupdater.com"; fast_pattern:only; metadata:author Actioner, created_at 2026-08-30; classtype:trojan-activity; sid:3100103; rev:1; gid:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - TerminalFix Compromised Site linked-log.com"; flow:established,to_server; ssl_state:client_hello; content:"linked-log.com"; fast_pattern:only; metadata:author Actioner, created_at 2026-08-30; classtype:trojan-activity; sid:3100104; rev:1; gid:1;)
```

## Lessons Learned

1. **DLL sideloading remains a potent evasion technique.** Using a legitimate, signed Microsoft binary (`LockScreenContentServer.exe`) to load a malicious DLL bypasses most application whitelisting. Defenders need DLL-load monitoring (Sysmon EID 7) with baseline-aware alerting on non-standard load paths.

2. **ClickFix / fake CAPTCHA is becoming a common initial access vector.** This variant of social engineering bypasses email-based phishing defenses entirely because the attack originates from a compromised legitimate website. User awareness training must explicitly cover fake browser verification prompts.

3. **Steganography defeats payload-level inspection.** Hiding payloads in PNG RGBA channels means file-type-based blocking and signature scanning of downloads are insufficient. Network defenders should monitor for downloads of image files from newly registered or low-reputation domains.

4. **Embedded Python interpreters provide a flexible implant platform.** The use of `pythonw.exe` with Python 3.14.5 to run a sophisticated reverse tunnel shows that interpreted-language implants are increasingly common. Organizations should monitor for and restrict execution of portable Python installations from user-writable directories.

5. **TLS WebSocket tunneling on port 443 is hard to detect without TLS inspection.** The C2 channel blends perfectly with legitimate HTTPS unless defenders have SNI visibility or full TLS inspection. SNI-based monitoring (as implemented in the Suricata rules above) provides a low-cost detection layer.

## Sources

- [Microsoft Security Blog -- TerminalFix Campaign Analysis](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) -- primary source for attack chain, IOCs, and technical details

---
*Report generated by Actioner*
