# Technical Analysis Report: TerminalFix ClickFix Campaign (2026-09-01)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-01
Version: 1.0

## Executive Summary

TerminalFix is a ClickFix variant campaign documented by [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) on August 28, 2026. Unlike earlier ClickFix campaigns that direct victims to the Windows Run dialog, TerminalFix instructs users to open Windows Terminal or PowerShell (via Windows+X then I), paste a command copied to the clipboard by a fake Cloudflare Turnstile CAPTCHA overlay on compromised websites, and execute a multi-line PowerShell script. This shift to Windows Terminal increases the likelihood that complex, multi-stage payloads execute successfully.

The attack chain proceeds through ZIP archive download and extraction to `C:\ProgramData\f47f2a8c21c9df4e`, DLL sideloading via a legitimate signed Windows binary (LockScreenContentServer.exe loading a malicious dui70.dll), steganographic extraction of additional payloads from PNG images downloaded from attacker-controlled domains, and culminates in deployment of a Python 3.14.5 reverse-tunnel implant (client.py) that establishes a WebSocket connection to gitnow[.]dev on port 443. The implant provides the attacker with SOCKS5-style TCP proxy access through the victim's network, enabling lateral movement, privilege escalation, and potential ransomware deployment.

The campaign targets organizations across multiple industries and has no attributed threat actor at this time. Microsoft Defender XDR detects the campaign under multiple signature families including Trojan:Win32/ClickFix, Trojan:Win32/TermFix, Trojan:Win32/Posilod, and Trojan:Python/Indigo.SA.

## Background: ClickFix Social Engineering Evolution

ClickFix is a social engineering technique where fake CAPTCHA or verification overlays instruct victims to execute commands on their systems. The technique gained widespread adoption throughout 2025 and 2026 across multiple threat actors and malware families. According to [Microsoft's earlier ClickFix analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/), the technique traditionally used the Windows Run dialog (Win+R) for command execution.

TerminalFix represents a tactical evolution: directing users to Windows Terminal provides a full PowerShell execution environment capable of handling multi-line scripts, environment variable expansion, and complex download-and-execute chains that would fail in the single-line Run dialog. Microsoft Defender Experts first identified the Windows Terminal variant in February 2026 and tracked its progression to the current multi-stage intrusion documented in the August 2026 report.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| February 2026 | Microsoft Defender Experts identify ClickFix campaigns using Windows Terminal |
| 2026-08-28 | Microsoft Threat Intelligence publishes TerminalFix campaign analysis |
| 2026-08-28 | The Hacker News and other outlets amplify the report |

## Root Cause: Social Engineering via Fake CAPTCHA (User Execution)

Victims visit compromised websites (e.g., linked-log[.]com) that display a fake Cloudflare Turnstile CAPTCHA overlay. The overlay instructs the user to copy a "verification command" to the clipboard, open Windows Terminal (Win+X, I), paste the command, and press Enter. The pasted PowerShell command clears the terminal, displays fake cyan-colored "Starting Cloudflare verification..." status messages to maintain the deception, downloads and extracts a ZIP archive, launches a batch file, and finally prints a green "verification success" message.

## Technical Analysis of the Malicious Payload

### 1. Initial Execution -- PowerShell Download and Extraction

The clipboard-injected PowerShell command performs the following operations:

1. Clears the terminal and prints a fake cyan-colored "Starting Cloudflare verification..." message
2. Downloads verify_pkg.zip (SHA-256: `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f`) using a custom User-Agent header
3. Extracts the archive to `C:\ProgramData\f47f2a8c21c9df4e`
4. Silently executes `1.bat` from the extraction directory
5. Prints a green-text "verification success" confirmation to maintain the CAPTCHA deception

### 2. DLL Sideloading via LockScreenContentServer.exe

The batch file (1.bat) launches LockScreenContentServer.exe, a legitimate signed Windows binary that has a static import dependency on dui70.dll (Windows DirectUI Engine). Because the Windows loader resolves DLLs from the application directory before System32, the malicious dui70.dll planted alongside the executable is loaded instead of the legitimate system DLL. This executes the attacker's code within the context of a trusted, signed process.

Nine distinct SHA-256 hashes for malicious dui70.dll variants were published by Microsoft:

- `ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07`
- `026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab`
- `032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22`
- `df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf`
- `eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0`
- `5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8`
- `9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24`
- `342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e`
- `ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d`

The malicious DLL contains an obfuscated payload in its resource section that is decoded entirely in-memory and executed via `Invoke-Expression`.

### 3. Steganographic Payload Retrieval

The decoded payload launches a PowerShell function called `Extract-RawFileFromImage` that:

1. Downloads PNG images via POST requests from bestsocialmedianewspapper[.]com or offlineupdater[.]com (failover)
2. Reads each pixel's RGBA channels and reconstructs an embedded binary
3. The first 8 bytes encode the payload length as a 64-bit integer; remaining bytes contain the file data
4. Extracts an executable from the first image
5. Extracts two DLL halves from images 2 and 3
6. Concatenates the DLL fragments on disk
7. Deletes source PNG images to reduce forensic artifacts

### 4. Persistence Mechanisms

Two persistence mechanisms are established:

**Registry Run Key:** An entry is added to `HKCU\...\Run` with a randomized service-like name that re-executes LockScreenContentServer.exe on user logon.

**Scheduled Task:** A task named `_LockScreenContentServer_MuODG5yBM` is created to re-execute the malware every 60 minutes.

**Directory Hiding:** The payload directory has `attrib +h +s` applied to hide it from casual directory listing.

### 5. Active Directory Reconnaissance

The campaign performs extensive post-exploitation reconnaissance:

- **System information collection** via `systeminfo` with locale-aware string filters (English, Spanish, German)
- **Domain trust discovery** via `nltest /domain_trusts` and `nltest /dclist`
- **Domain admin enumeration** via `net group "domain admins" /domain`
- **User description harvesting** via ADSI searcher queries
- **Computer enumeration** via ADSI queries targeting Windows Server objects
- **Infrastructure probing** via systematic ping sweeps of named servers (domain controllers, databases, backup systems, gateways, mail systems)

### 6. Asynchronous Command Execution Loop

A persistent PowerShell file-watch loop monitors a text file for changes, executes its contents via `Invoke-Expression`, and writes results to an output file. This creates a primitive but effective filesystem-based C2 channel where the attacker writes commands to the watched file and retrieves outputs from the results file.

### 7. Python Reverse-Tunnel Implant

The final stage downloads an unmodified, signed Python 3.14.5 embeddable runtime from python.org and deploys client.py (SHA-256: `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a`), a custom reverse-tunnel implant.

**Implant characteristics:**

- **Launcher:** pythonw.exe (no visible window)
- **Transport:** TLS WebSocket over port 443 to gitnow[.]dev at the `/tunnel` endpoint
- **Certificate verification:** Disabled (CERT_NONE)
- **User-Agent rotation:** Four randomized browser strings (Chrome, Firefox, Safari variants)
- **Protocol:** 7-byte binary header (message type + stream ID + length) enabling stream multiplexing over a single WebSocket connection
- **Proxy capability:** SOCKS5-style address parsing supporting IPv4, IPv6, and hostname resolution
- **Message types:** Connection setup, data relay, keepalive, and remote termination (MSG_SHUTDOWN)
- **Effect:** The attacker gains the ability to reach any host visible from the victim's network, effectively turning the compromised machine into a network pivot point

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: URLs use `hxxps://` or `hxxp://`, domains use `[.]` replacing dots, IP addresses use `[.]` replacing dots.

### File System

| Artifact | Hash (SHA-256) | Description |
|----------|---------------|-------------|
| verify_pkg.zip | 18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f | Initial ZIP archive |
| client.py | b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a | Python reverse-tunnel implant |
| dui70.dll (variant 1) | ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07 | Malicious sideloading DLL |
| dui70.dll (variant 2) | 026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab | Malicious sideloading DLL |
| dui70.dll (variant 3) | 032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22 | Malicious sideloading DLL |
| dui70.dll (variant 4) | df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf | Malicious sideloading DLL |
| dui70.dll (variant 5) | eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0 | Malicious sideloading DLL |
| dui70.dll (variant 6) | 5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8 | Malicious sideloading DLL |
| dui70.dll (variant 7) | 9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24 | Malicious sideloading DLL |
| dui70.dll (variant 8) | 342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e | Malicious sideloading DLL |
| dui70.dll (variant 9) | ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d | Malicious sideloading DLL |

### File Paths

| Path | Description |
|------|-------------|
| C:\ProgramData\f47f2a8c21c9df4e | Extraction directory |
| C:\ProgramData\f47f2a8c21c9df4e\LockScreenContentServer.exe | Sideloading host (legitimate signed binary) |
| C:\ProgramData\f47f2a8c21c9df4e\dui70.dll | Malicious sideloaded DLL |
| C:\ProgramData\f47f2a8c21c9df4e\1.bat | Batch launcher |
| C:\ProgramData\f47f2a8c21c9df4e\client.py | Python tunnel implant |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | gitnow[.]dev | C2 server for reverse tunnel (port 443, WebSocket at /tunnel) |
| Domain | bestsocialmedianewspapper[.]com | Steganographic image hosting / payload delivery |
| Domain | offlineupdater[.]com | Steganographic image hosting failover |
| URL | hxxps://linked-log[.]com/ | Compromised website (initial access) |

### Behavioral

- LockScreenContentServer.exe loading dui70.dll from outside System32/SysWOW64/WinSxS directories
- Scheduled task named `_LockScreenContentServer_MuODG5yBM` executing every 60 minutes
- Registry Run key with randomized service-like name pointing to LockScreenContentServer.exe in ProgramData
- `attrib +h +s` applied to directories under C:\ProgramData
- pythonw.exe executing client.py with `--server`, `--uuid`, and `cert.pem` arguments
- PowerShell executing `Extract-RawFileFromImage` function processing RGBA pixel channels
- POST requests to external domains retrieving PNG images followed by executable extraction
- WebSocket upgrade requests to `/tunnel` endpoint on port 443
- `nltest /domain_trusts`, `nltest /dclist`, `net group "domain admins" /domain` executed in sequence
- File-watch PowerShell loop with Invoke-Expression executing file contents

### Microsoft Defender XDR Detection Names

| Signature | Description |
|-----------|-------------|
| Trojan:Win32/ClickFix.* | Initial access detection |
| Trojan:Win32/TermFix.* | TerminalFix variant detection |
| Trojan:Win32/Posilod.* | DLL sideloading detection |
| Trojan:Win64/DLLHijack.DAB!MTB | DLL hijacking detection |
| Trojan:Python/Indigo.SA | Python tunnel implant detection |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Fake Cloudflare CAPTCHA overlay on compromised websites |
| T1204.002 | User Execution: Malicious File | Users tricked into pasting and executing PowerShell commands via ClickFix |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Multi-line PowerShell script execution, Invoke-Expression, steganographic extraction |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | LockScreenContentServer.exe loading malicious dui70.dll from application directory |
| T1027.003 | Obfuscated Files or Information: Steganography | Payload extraction from PNG images via RGBA channel reading |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | HKCU Run key with randomized service name for persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | _LockScreenContentServer_MuODG5yBM at 60-minute intervals |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | attrib +h +s applied to payload directory |
| T1036.005 | Masquerading: Match Legitimate Name or Location | dui70.dll masquerading as Windows DirectUI Engine DLL |
| T1082 | System Information Discovery | systeminfo with multilingual locale filters |
| T1482 | Domain Trust Discovery | nltest /domain_trusts and /dclist |
| T1069.002 | Permission Groups Discovery: Domain Groups | net group "domain admins" /domain |
| T1087.002 | Account Discovery: Domain Account | ADSI searcher for user descriptions |
| T1018 | Remote System Discovery | ADSI queries for Windows Servers, systematic ping sweeps |
| T1572 | Protocol Tunneling | WebSocket reverse tunnel implant providing SOCKS5-style proxy |
| T1071.001 | Application Layer Protocol: Web Protocols | TLS WebSocket C2 over port 443 |
| T1105 | Ingress Tool Transfer | Python runtime download from python.org, ZIP archive from attacker infrastructure |

## Impact Assessment

TerminalFix represents a significant escalation over earlier ClickFix campaigns. While prior ClickFix variants typically delivered a single infostealer, TerminalFix deploys a sophisticated multi-stage intrusion chain combining DLL sideloading, steganographic payload extraction, extensive Active Directory reconnaissance, and a custom reverse-tunnel implant. The Python-based tunnel gives attackers persistent SOCKS5-style network access through the victim's machine, enabling lateral movement to any host visible on the victim's network.

Microsoft explicitly notes that organizations should treat affected devices as potential network pivot points and investigate for lateral movement and credential exposure. The campaign's use of a legitimate signed Python runtime and TLS WebSocket tunneling on port 443 makes the C2 channel difficult to distinguish from legitimate HTTPS traffic without deep packet inspection or endpoint telemetry.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for TerminalFix extraction directory
Test-Path "C:\ProgramData\f47f2a8c21c9df4e"

# Check for LockScreenContentServer.exe outside system directories
Get-ChildItem -Path C:\ProgramData -Recurse -Filter "LockScreenContentServer.exe" -ErrorAction SilentlyContinue

# Check for malicious scheduled task
Get-ScheduledTask | Where-Object { $_.TaskName -match "LockScreenContentServer" }

# Check for pythonw.exe running client.py
Get-Process | Where-Object { $_.ProcessName -eq "pythonw" } | ForEach-Object { Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" | Select-Object CommandLine }
```

### Remediation

1. **Containment:** Block gitnow[.]dev, bestsocialmedianewspapper[.]com, offlineupdater[.]com, and linked-log[.]com at the network perimeter. Isolate affected endpoints from the network immediately -- the reverse tunnel provides the attacker with ongoing network access.
2. **Eradication:** Remove the extraction directory `C:\ProgramData\f47f2a8c21c9df4e`. Delete the scheduled task `_LockScreenContentServer_MuODG5yBM`. Remove the HKCU Run key entry pointing to LockScreenContentServer.exe. Kill any pythonw.exe processes running client.py.
3. **Recovery:** Rotate all credentials on compromised systems. Investigate for lateral movement -- the reverse tunnel may have been used to access other internal systems. Review domain admin accounts for unauthorized changes.
4. **Hardening:** Restrict PowerShell and Windows Terminal execution via AppLocker or WDAC policies. Enable PowerShell script block logging (Event ID 4104) to detect obfuscated commands. Monitor for DLL sideloading by alerting on signed executables loading DLLs from non-system directories.

## Detection Rules

These detections target TerminalFix-specific artifacts: DLL sideloading of dui70.dll via LockScreenContentServer.exe, PowerShell execution chains extracting payloads to ProgramData, scheduled task persistence, reverse tunnel implant execution, steganographic extraction functions, AD reconnaissance patterns, and known C2 infrastructure. PoC/advisory-specific altitude; compiles != fires -- verify in your pipeline.

### Sigma: TerminalFix DLL Sideloading via LockScreenContentServer

Detects LockScreenContentServer.exe loading dui70.dll from a non-system directory, the core sideloading mechanism of the TerminalFix campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: removed attack.t1204.002 tag — DLL sideloading is automatic, user did not execute the DLL -->
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert splunk exit 0. LockScreenContentServer.exe loading dui70.dll from ProgramData is a definitive IOC match; no legitimate deployment of this binary outside system directories. -->
```yaml
title: TerminalFix ClickFix DLL Sideloading via LockScreenContentServer
id: a1e4f7b2-3c8d-4e5a-9f6b-7d2e1a0c3b4f
status: experimental
description: >
    Detects LockScreenContentServer.exe loading dui70.dll from a non-system
    directory, indicating DLL sideloading as used by the TerminalFix campaign
    to execute malicious payloads within a trusted signed process.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
    - https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html
author: Actioner
date: 2026/09/01
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\LockScreenContentServer.exe'
        ImageLoaded|endswith: '\dui70.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not filter_system
falsepositives:
    - Legitimate use of LockScreenContentServer.exe outside system directories is not expected
level: high
```

### Sigma: TerminalFix PowerShell Execution to ProgramData

Detects the ClickFix execution chain where PowerShell or cmd.exe spawns processes involving ProgramData extraction and LockScreenContentServer.exe batch launch.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0. CommandLine requiring both ProgramData path and LockScreenContentServer string provides high-specificity IOC matching. -->
```yaml
title: TerminalFix PowerShell Execution to ProgramData with Batch Launch
id: b2f5a8c3-4d9e-5f6b-0a7c-8e3f2b1d4c5a
status: experimental
description: >
    Detects PowerShell or cmd.exe spawning processes involving ProgramData
    extraction and batch file execution of LockScreenContentServer.exe,
    consistent with the TerminalFix ClickFix initial execution chain.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
    - https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html
author: Actioner
date: 2026/09/01
tags:
    - attack.t1059.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
            - '\wt.exe'
        CommandLine|contains|all:
            - '\ProgramData\'
            - 'LockScreenContentServer'
    condition: selection
falsepositives:
    - Unlikely; LockScreenContentServer.exe execution from ProgramData via CLI is not a legitimate workflow
level: high
```

### Sigma: TerminalFix Scheduled Task Persistence

Detects schtasks.exe creating tasks referencing LockScreenContentServer, the persistence mechanism used by TerminalFix with 60-minute intervals.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0. Task name referencing LockScreenContentServer is a direct IOC; no legitimate use case for scheduling this binary via schtasks. -->
```yaml
title: TerminalFix Scheduled Task Persistence for LockScreenContentServer
id: c3a6b9d4-5e0f-6a7c-1b8d-9f4a3c2e5d6b
status: experimental
description: >
    Detects creation of a scheduled task referencing LockScreenContentServer
    for persistence, as used by the TerminalFix campaign with 60-minute
    execution intervals.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/09/01
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'LockScreenContentServer'
    condition: selection
falsepositives:
    - System administrators legitimately creating tasks for this binary (unlikely)
level: high
```

### Sigma: TerminalFix Python Reverse Tunnel Implant Execution

Detects pythonw.exe or python.exe executing client.py with --server and --uuid arguments, matching the reverse tunnel implant command-line pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: added cert.pem to contains|all list to maintain HIGH confidence (quadruple conjunction) -->
<!-- audit: sigma convert splunk exit 0. Quadruple conjunction (client.py + --server + --uuid + cert.pem) provides high specificity; legitimate Python apps matching all four are extremely unlikely. -->
```yaml
title: TerminalFix Python Reverse Tunnel Implant Execution
id: d4b7c0e5-6f1a-7b8d-2c9e-0a5b4d3f6e7c
status: experimental
description: >
    Detects execution of pythonw.exe with command-line arguments matching the
    TerminalFix reverse tunnel implant (client.py with server and UUID
    parameters connecting to gitnow.dev).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/09/01
tags:
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_python:
        Image|endswith:
            - '\pythonw.exe'
            - '\python.exe'
        CommandLine|contains|all:
            - 'client.py'
            - '--server'
            - '--uuid'
            - 'cert.pem'
    condition: selection_python
falsepositives:
    - Legitimate Python applications named client.py using --server and --uuid arguments (review context)
level: high
```

### Sigma: TerminalFix Steganographic Payload Extraction via PowerShell

Detects PowerShell executing the Extract-RawFileFromImage function or processing RGBA pixel channels, consistent with the steganographic extraction stage.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: changed CommandLine|contains (OR) to CommandLine|contains|all (AND) — RGBA alone would fire on benign image-processing scripts -->
<!-- audit: sigma convert splunk exit 0. Extract-RawFileFromImage is a campaign-specific function name; both function name AND RGBA required to fire. -->
```yaml
title: TerminalFix Steganographic Payload Extraction via PowerShell
id: e5c8d1f6-7a2b-8c9e-3d0f-1b6c5e4a7f8d
status: experimental
description: >
    Detects PowerShell executing functions or patterns consistent with
    steganographic extraction from PNG images, specifically the
    Extract-RawFileFromImage pattern used by the TerminalFix campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/09/01
tags:
    - attack.t1027.003
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Extract-RawFileFromImage'
            - 'RGBA'
    condition: selection
falsepositives:
    - Legitimate image processing scripts using RGBA channel manipulation (review script context)
level: high
```

### Sigma: AD Reconnaissance Commands (TerminalFix Context)

Detects Active Directory reconnaissance commands consistent with the TerminalFix post-exploitation reconnaissance phase.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: fixed title to acknowledge generality; fixed description — OR logic, not temporal correlation -->
<!-- audit: sigma convert splunk exit 0. These commands are individually legitimate for domain administrators. Medium confidence because the individual commands are common in AD administration; correlation of both nltest and net group within a short window would increase confidence. -->
```yaml
title: AD Reconnaissance Commands (TerminalFix Context)
id: f6d9e2a7-8b3c-9d0f-4e1a-2c7d6f5b8a9e
status: experimental
description: >
    Detects Active Directory reconnaissance commands (nltest, net group
    domain admins) consistent with the TerminalFix post-exploitation phase.
    Uses OR logic; individual matches are alertworthy but not correlated.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/09/01
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
        CommandLine|contains:
            - '/domain_trusts'
            - '/dclist'
    selection_netgroup:
        Image|endswith: '\net.exe'
        CommandLine|contains|all:
            - 'group'
            - 'domain admins'
    condition: selection_nltest or selection_netgroup
falsepositives:
    - Legitimate domain administration tasks using nltest or net group
level: medium
```

### Suricata: TerminalFix Network Indicators

Detects C2 communication to gitnow[.]dev (both HTTP host and TLS SNI), payload delivery from steganographic image hosts, WebSocket tunnel upgrade requests, and the compromised distribution site.
**Status:** compile ✅ compiles · confidence: high (SIDs 2200201-2200204, 2200206) / medium (SID 2200205)
<!-- revision: downgraded SID 2200205 (WebSocket /tunnel) confidence to medium — any WebSocket upgrade to /tunnel path matches; VPNs, dev tools, etc. -->
<!-- audit: suricata -T -S exit 0. Domain-based rules are high confidence IOC matches. sid:2200205 (WebSocket /tunnel) is behavioral and could match legitimate WebSocket applications (VPNs, dev tools); medium confidence standalone, high when combined with gitnow.dev TLS SNI rule. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix C2 Reverse Tunnel to gitnow.dev"; flow:established,to_server; http.host; content:"gitnow.dev"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200201; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Steganographic Payload Host bestsocialmedianewspapper.com"; flow:established,to_server; http.host; content:"bestsocialmedianewspapper.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Steganographic Payload Host offlineupdater.com"; flow:established,to_server; http.host; content:"offlineupdater.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200203; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix TLS SNI to gitnow.dev Reverse Tunnel"; flow:established,to_server; tls.sni; content:"gitnow.dev"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200204; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix WebSocket Tunnel Upgrade to /tunnel Endpoint"; flow:established,to_server; http.uri; content:"/tunnel"; http.header; content:"Upgrade"; content:"websocket"; nocase; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200205; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Compromised Site linked-log.com"; flow:established,to_server; http.host; content:"linked-log.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-09-01; sid:2200206; rev:1;)
```

### YARA: TerminalFix Malicious DLL and Python Implant Detection

Detects malicious dui70.dll variants by DLL export stubs combined with steganographic extraction or C2 indicators, and the Python reverse-tunnel implant by WebSocket tunnel endpoint, C2 domain, and multiplexing protocol markers. (Steganographic PNG YARA rule cut -- 2-byte MZ marker has near-random match probability in normal PNG files >100KB.)
**Status:** compile ✅ compiles · confidence: high
- Malware_TerminalFix_DUI70_Sideload_DLL: sample: untested (no real sample available; string combinations are campaign-specific IOCs)
- Malware_TerminalFix_Python_Tunnel_Implant: sample: untested (no real sample; string combinations target published C2 and protocol indicators)
<!-- revision: cut Malware_TerminalFix_Stego_PNG_Payload — 2-byte MZ marker {4D 5A} has near-random match probability (~53%+) in normal PNG files >100KB; rule fires on benign PNGs -->
<!-- audit: yarac exit 0. DLL rule uses IOC domains and campaign-specific function names as anchors. Python rule targets unique combination of gitnow.dev + /tunnel + CERT_NONE + stream multiplexing. -->
```yara
rule Malware_TerminalFix_DUI70_Sideload_DLL
{
    meta:
        description = "Detects malicious dui70.dll variants used by the TerminalFix campaign for DLL sideloading via LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash1 = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        hash2 = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab"
        hash3 = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22"
        hash4 = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf"
        hash5 = "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0"
        hash6 = "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8"
        hash7 = "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24"
        hash8 = "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e"
        hash9 = "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d"
        severity = "high"

    strings:
        $dll_name = "dui70.dll" ascii wide
        $export1 = "InitProcessPriv" ascii
        $export2 = "InitThread" ascii
        $export3 = "UnInitThread" ascii
        $export4 = "CreateDUINode" ascii
        $steg1 = "Extract-RawFileFromImage" ascii wide
        $steg2 = "RGBA" ascii wide
        $invoke = "Invoke-Expression" ascii wide nocase
        $c2_1 = "gitnow.dev" ascii wide
        $c2_2 = "bestsocialmedianewspapper.com" ascii wide
        $c2_3 = "offlineupdater.com" ascii wide
        $path = "f47f2a8c21c9df4e" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($dll_name and 2 of ($export*) and ($invoke or 1 of ($steg*))) or
            (2 of ($c2*)) or
            ($path and ($dll_name or $invoke)) or
            ($dll_name and 1 of ($steg*) and 1 of ($c2*))
        )
}

rule Malware_TerminalFix_Python_Tunnel_Implant
{
    meta:
        description = "Detects the Python-based reverse tunnel implant (client.py) used by the TerminalFix campaign for WebSocket C2 tunneling"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a"
        severity = "high"

    strings:
        $tunnel = "/tunnel" ascii
        $c2 = "gitnow.dev" ascii
        $cert = "CERT_NONE" ascii
        $ws1 = "websocket" ascii nocase
        $ws2 = "WebSocket" ascii
        $shutdown = "MSG_SHUTDOWN" ascii
        $keepalive = "keepalive" ascii
        $stream = "stream_id" ascii
        $uuid = "--uuid" ascii
        $server = "--server" ascii
        $pythonw = "pythonw" ascii
        $ua1 = "Chrome" ascii
        $ua2 = "Firefox" ascii
        $ua3 = "Safari" ascii

    condition:
        filesize < 500KB and
        (
            ($c2 and $tunnel and ($cert or 1 of ($ws*))) or
            ($shutdown and $keepalive and $stream) or
            ($c2 and $uuid and $server) or
            ($tunnel and $cert and 2 of ($ua*) and $stream) or
            ($pythonw and $c2 and $tunnel)
        )
}
```

## Lessons Learned

1. **Windows Terminal changes the ClickFix game.** The shift from the Run dialog to Windows Terminal is not cosmetic -- it enables multi-line, multi-stage payloads that could not execute in the single-line Run dialog. Organizations should treat Windows Terminal launches from browser contexts as high-risk events and consider restricting Win+X keyboard shortcuts via Group Policy.

2. **DLL sideloading of system components remains effective.** LockScreenContentServer.exe is a legitimate, signed Windows binary. The Windows loader's application-directory-first DLL resolution order continues to provide a reliable evasion vector. Application whitelisting policies should validate DLL load paths, not just executable signatures.

3. **Steganography adds a forensic gap.** By embedding payloads in PNG pixel data and deleting the source images after extraction, the campaign creates a window where the payload exists only in memory. Network monitoring for POST requests downloading PNG images from unusual domains, combined with PowerShell script block logging, is essential to close this gap.

4. **Reverse tunnels convert endpoints into network pivot points.** The Python implant's SOCKS5-style proxy means compromise of a single endpoint grants the attacker access to the entire network segment. Incident response must extend beyond the compromised host to assess lateral movement across all reachable systems.

## Sources

- [Microsoft Threat Intelligence - TerminalFix campaign deploys a reverse tunnel through multistage intrusion](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) -- primary technical analysis; source of all IOCs, attack chain, and detection guidance
- [The Hacker News - TerminalFix Uses Fake Cloudflare CAPTCHAs to Deploy Reverse-Tunnel Backdoor](https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html) -- secondary reporting with attack chain summary and detection recommendations
- [Microsoft Threat Intelligence - Think before you Click(Fix): Analyzing the ClickFix social engineering technique](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) -- background context on ClickFix technique evolution and detection approaches
- [SigmaHQ - Suspicious ClickFix/FileFix Execution Pattern (PR #5218)](https://github.com/SigmaHQ/sigma/pull/5218) -- community Sigma rules for ClickFix behavioral detection patterns
- [Microsoft Security Intel (@MsftSecIntel) - TerminalFix announcement](https://x.com/MsftSecIntel/status/2085399393302176075) -- initial disclosure and Windows Terminal variant identification

---
*Report generated by Actioner*
