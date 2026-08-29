# Technical Analysis Report: TerminalFix ClickFix Campaign (2026-08-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-29
Version: 1.0

## Executive Summary

Microsoft Threat Intelligence has identified a multi-stage intrusion campaign dubbed "TerminalFix" that leverages the ClickFix social engineering technique to deploy a custom reverse tunnel implant. The campaign compromises legitimate websites to display fake Cloudflare Turnstile CAPTCHA overlays, tricking users into pasting malicious PowerShell commands into Windows Terminal. The attack chain progresses through DLL sideloading via a legitimate Windows binary (`LockScreenContentServer.exe`), steganographic payload extraction from PNG images, extensive Active Directory reconnaissance, and ultimately deploys a Python-based reverse WebSocket tunnel over TLS/443 that provides the attacker with full network-level proxy access to the victim environment.

The campaign targets multiple industries across English, Spanish, and German-speaking regions. No specific threat actor attribution has been provided. The attack features robust persistence through both Registry Run keys and scheduled tasks, and employs multiple evasion techniques including hidden directories, in-memory execution, and certificate verification bypass.

## Background: ClickFix Social Engineering and Reverse Tunneling

ClickFix is a social engineering technique that leverages fake browser-based prompts (typically CAPTCHA verification dialogs) to trick users into copying and executing malicious commands via the clipboard. The TerminalFix variant specifically impersonates Cloudflare Turnstile verification, a widely trusted web protection mechanism. The reverse tunnel component is notable for using an embeddable Python 3.14.5 runtime downloaded from the official `python.org` distribution, allowing the attacker to deploy a full Python environment without pre-existing Python installations on the target.

## Attack Timeline (All Times UTC)

| Phase | Event |
|-------|-------|
| Stage 1 | User visits compromised website (e.g., `linked-log[.]com`) displaying fake Cloudflare Turnstile CAPTCHA |
| Stage 2 | Malicious PowerShell command copied to clipboard; user executes in Windows Terminal |
| Stage 3 | ZIP archive (`verify_pkg.zip`) downloaded, extracted to `C:\ProgramData\f47f2a8c21c9df4e`; batch file `1.bat` launched |
| Stage 4 | `LockScreenContentServer.exe` executed, sideloads malicious `dui70.dll` from working directory |
| Stage 5 | DLL retrieves obfuscated payload from resource section, executes in-memory |
| Stage 6 | PowerShell downloads PNG images via POST; steganographic extraction rebuilds DLL from pixel RGBA channels |
| Stage 7 | Persistence established via Registry Run key and scheduled task (60-minute interval) |
| Stage 8 | AD reconnaissance: domain trusts, admin groups, computer/user enumeration, targeted server pinging |
| Stage 9 | Asynchronous command execution via file-watch loop (Invoke-Expression) |
| Stage 10 | Python 3.14.5 embeddable runtime downloaded from python.org; `pythonw.exe` launches `client.py` reverse tunnel over WebSocket/TLS:443 |

## Root Cause: Drive-by Compromise via Fake CAPTCHA (T1189)

Initial access is achieved through compromised websites that inject a fake Cloudflare Turnstile CAPTCHA overlay. When the user interacts with the overlay, a malicious PowerShell command is silently copied to the clipboard. The overlay instructs the user to open Windows Terminal (or the Run dialog) and paste the command, exploiting user trust in CAPTCHA verification workflows. The fake confirmation messages ("Starting Cloudflare verification..." and "I am not a robot") maintain the illusion of a legitimate process.

## Technical Analysis of the Malicious Payload

### 1. Initial Execution and ZIP Delivery (Stage 1-3)

The pasted PowerShell command downloads a ZIP archive (`verify_pkg.zip`, SHA-256: `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f`) using a custom User-Agent header. The archive is extracted to `C:\ProgramData\f47f2a8c21c9df4e`, after which the batch file `1.bat` is launched. This batch file silently executes `LockScreenContentServer.exe`.

**Process chain:** `powershell.exe` -> `cmd.exe` -> `1.bat` -> `LockScreenContentServer.exe`

### 2. DLL Sideloading (Stage 4-5)

The attack exploits Windows DLL search order hijacking (T1574.002). The legitimate signed binary `LockScreenContentServer.exe` has a static import dependency on `dui70.dll` (Windows DirectUI Engine). Because the Windows loader resolves the application directory before `System32`, the malicious `dui70.dll` planted alongside the executable is loaded instead of the legitimate system DLL. The malicious DLL retrieves an obfuscated payload from its PE resource section and executes it entirely in-memory, avoiding disk-based detection.

Multiple malicious DLL variants have been observed (see IOC hashes below).

### 3. Steganographic Payload Extraction (Stage 6)

PowerShell downloads three PNG images via POST requests to attacker-controlled domains (`bestsocialmedianewspapper[.]com` and `offlineupdater[.]com`). A custom PowerShell function `Extract-RawFileFromImage` reads the RGBA pixel channels of each image. The first 8 bytes encode the payload length as a 64-bit integer; remaining bytes contain the actual file data. The final DLL payload is split across two images and concatenated after extraction. Source images are deleted post-extraction to reduce forensic artifacts.

### 4. Persistence Mechanisms (Stage 7)

Two persistence mechanisms are deployed under the masquerading name `LockScreenContentServer_MuODG5yBM`:

- **Registry Run Key (T1547.001):** An entry with a randomized service-like name is added under `HKCU\...\Run` to ensure execution at user logon.
- **Scheduled Task (T1053.005):** A scheduled task is created to execute every 60 minutes, providing redundant persistence.
- **Hidden Directory (T1564.001):** The payload directory is hidden using `attrib +h +s`, setting both hidden and system attributes.

### 5. Active Directory Reconnaissance (Stage 8)

Extensive domain discovery is performed using native Windows tools:

- `nltest /domain_trusts` -- Domain trust enumeration (T1482)
- `nltest /dclist:` -- Domain controller listing
- `net group "domain admins" /domain` -- Domain admin group enumeration (T1069.002)
- ADSI searcher queries for computer and user enumeration (T1087.002)
- Targeted server pinging of infrastructure roles: domain controllers, databases, backup servers, gateways, mail servers (T1018)
- System information collection with multilingual support (English/Spanish/German) (T1082)

### 6. Asynchronous Command Execution (Stage 9)

A PowerShell file-watch loop monitors a text file for new commands. When changes are detected, the content is executed via `Invoke-Expression` and results are written to a separate output file. This creates an asynchronous command execution channel through the local filesystem, enabling remote command execution without direct network C2 for individual commands.

### 7. C2 Infrastructure -- Reverse WebSocket Tunnel (Stage 10)

The final payload deploys an embeddable Python 3.14.5 runtime downloaded from the official `python.org` distribution. The custom `client.py` tunneling implant (SHA-256: `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a`) is launched via `pythonw.exe` (no visible console window) with arguments: `client.py`, `--server`, `--uuid`, `cert.pem`.

**Tunnel protocol characteristics:**
- Connects to `gitnow[.]dev` on port 443 via TLS 1.2
- WebSocket connection to `/tunnel` endpoint
- 7-byte binary header per message: type (1 byte) + stream ID (2 bytes) + length (4 bytes)
- Eight message types: implant identification, connection setup, data relay, keepalive, remote termination, and others
- SOCKS5-style address parsing enables arbitrary TCP connections through the tunnel
- Certificate verification is **disabled** (`CERT_NONE`), making the connection susceptible to interception but removing cert validation obstacles
- Four randomized realistic browser User-Agent strings rotate per connection

### 8. Anti-Forensics / Evasion Techniques

- In-memory DLL payload execution from PE resource section
- Steganographic concealment in PNG image RGBA channels
- Payload split across multiple images to complicate analysis
- Source images deleted after extraction
- Hidden directory attributes (`attrib +h +s`)
- Use of legitimate signed binaries for DLL sideloading
- `pythonw.exe` for consoleless execution
- TLS 1.2 encryption for C2 communications
- Randomized User-Agent strings
- Masquerading process/task names resembling legitimate Windows services

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | `verify_pkg.zip` | `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f` | Initial ZIP archive |
| Windows | `client.py` | `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a` | Python reverse tunnel implant |
| Windows | `dui70.dll` | `ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07` | Malicious sideloaded DLL |
| Windows | `dui70.dll` | `026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e` | Malicious sideloaded DLL variant |
| Windows | `dui70.dll` | `ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d` | Malicious sideloaded DLL variant |
| Windows | `LockScreenContentServer.exe` | -- | Legitimate sideloading host binary |
| Windows | `1.bat` | -- | Initial batch file launcher |
| Windows | `cert.pem` | -- | Certificate file for tunnel TLS |
| Windows | `C:\ProgramData\f47f2a8c21c9df4e` | -- | Extraction/staging directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `gitnow[.]dev` | Primary C2 server (port 443, TLS/WebSocket) |
| Domain | `bestsocialmedianewspapper[.]com` | Steganographic image hosting / payload delivery |
| Domain | `offlineupdater[.]com` | Failover steganographic image hosting |
| Domain | `linked-log[.]com` | Compromised website used for initial access |
| Protocol | WebSocket over TLS 1.2 | C2 tunnel protocol on port 443 |
| URI | `/tunnel` | WebSocket tunnel endpoint on C2 server |

### Behavioral

- **Process chain:** `powershell.exe` -> `cmd.exe` -> `LockScreenContentServer.exe` -> `dui70.dll` (sideloaded) -> `powershell.exe` (steganography) -> `pythonw.exe` (tunnel)
- **Registry persistence:** `HKCU\...\Run` with randomized service-like name containing `LockScreenContentServer`
- **Scheduled task:** Name `LockScreenContentServer_MuODG5yBM`, 60-minute recurrence
- **Directory hiding:** `attrib +h +s` on `C:\ProgramData\[random]`
- **File-watch command loop:** PowerShell monitors text file, executes via `Invoke-Expression`, writes output to separate file
- **Tunnel binary header:** 7 bytes (type + stream ID + length), 8 message types, SOCKS5 address parsing
- **Python deployment:** Embeddable Python 3.14.5 from `python.org`, launched as `pythonw.exe` (no console)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised websites display fake Cloudflare Turnstile CAPTCHA |
| T1204.002 | User Execution: Malicious File | User pastes and executes clipboard PowerShell command |
| T1059.001 | PowerShell | PowerShell used for initial download, steganography extraction, command execution loop |
| T1059.006 | Python | Python 3.14.5 runtime deployed for reverse tunnel implant |
| T1574.002 | DLL Side-Loading | LockScreenContentServer.exe loads malicious dui70.dll from application directory |
| T1027.003 | Steganography | Payloads extracted from PNG image RGBA pixel channels |
| T1547.001 | Registry Run Keys | Persistence via HKCU Run key with randomized service name |
| T1053.005 | Scheduled Task | 60-minute recurring scheduled task for persistence |
| T1564.001 | Hidden Files and Directories | Staging directory hidden with `attrib +h +s` |
| T1036.005 | Match Legitimate Name or Location | Masquerading as LockScreenContentServer and dui70.dll |
| T1482 | Domain Trust Discovery | `nltest /domain_trusts` enumeration |
| T1069.002 | Domain Groups | `net group "domain admins" /domain` enumeration |
| T1087.002 | Domain Account | ADSI searcher queries for AD user/computer discovery |
| T1018 | Remote System Discovery | Targeted ping sweeps of infrastructure servers |
| T1082 | System Information Discovery | System info collection with multilingual support |
| T1572 | Protocol Tunneling | Custom WebSocket reverse tunnel over TLS/443 |
| T1071.001 | Web Protocols | HTTPS/WebSocket for C2 communications |
| T1105 | Ingress Tool Transfer | Download of ZIP, PNG payloads, Python runtime |

## Impact Assessment

The TerminalFix campaign represents a significant threat due to its full network-level proxy access capability via the reverse tunnel. Once established, the attacker can route arbitrary TCP connections through the victim's network, enabling lateral movement, data exfiltration, and access to internal resources without direct inbound firewall rules. The campaign's multilingual reconnaissance support (English, Spanish, German) suggests targeting across Western European and Latin American organizations. The use of a legitimate signed binary for DLL sideloading and steganographic payload delivery significantly complicates detection by traditional antivirus and network monitoring tools.

## Detection & Remediation

### Immediate Detection

Defenders should check for the following indicators immediately:

- DNS queries or network connections to `gitnow.dev`, `bestsocialmedianewspapper.com`, `offlineupdater.com`
- Presence of `LockScreenContentServer.exe` in `C:\ProgramData\` or any non-System32 location
- Scheduled tasks containing `LockScreenContentServer` in the name
- Registry Run key entries referencing `LockScreenContentServer`
- `pythonw.exe` or `python.exe` processes with `client.py --server --uuid cert.pem` in the command line
- Hidden directories under `C:\ProgramData\` with system+hidden attributes

### Remediation

1. **Containment:** Isolate affected hosts; block `gitnow.dev`, `bestsocialmedianewspapper.com`, `offlineupdater.com` at DNS/proxy
2. **Eradication:** Remove scheduled task `LockScreenContentServer_MuODG5yBM`; delete Registry Run key entries referencing LockScreenContentServer; remove `C:\ProgramData\f47f2a8c21c9df4e` and any hidden ProgramData directories containing campaign artifacts
3. **Recovery:** Rotate all credentials for affected users and service accounts; review domain admin group membership for unauthorized additions
4. **Secret rotation:** Assume all credentials accessible from compromised hosts are compromised; force password reset for domain accounts enumerated during reconnaissance

### Long-Term Hardening

- Deploy AppLocker or Windows Defender Application Control (WDAC) policies to restrict PowerShell and script execution
- Enable PowerShell script block logging and Constrained Language Mode
- Configure Windows Terminal to warn on multi-line paste operations
- Implement attack surface reduction (ASR) rules blocking obfuscated scripts
- Monitor for DLL sideloading from non-standard directories (image_load events)
- Enable network protection and web content filtering in Microsoft Defender
- User security awareness training on fake CAPTCHA social engineering tactics

## Detection Rules

These detections target the TerminalFix ClickFix campaign at PoC/advisory-specific altitude, covering the full attack chain from initial execution through C2 tunnel deployment. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline before production deployment.

### Sigma: TerminalFix ClickFix Initial Execution Chain

Detects PowerShell launching cmd.exe to execute `1.bat` from the `C:\ProgramData` staging directory, matching the campaign's initial access pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Rule is syntactically valid and portable. Keys on specific batch file name + ProgramData path from campaign. -->
```yaml
title: TerminalFix ClickFix Initial PowerShell Execution Chain
id: 7b3c8d4e-1f2a-4b5c-9d6e-0a1b2c3d4e5f
status: experimental
description: >
    Detects the TerminalFix ClickFix campaign initial execution chain where PowerShell
    launches cmd.exe to execute the batch file 1.bat and LockScreenContentServer.exe
    from the C:\ProgramData staging directory.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1204.002
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\powershell.exe'
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_args:
        CommandLine|contains|all:
            - '\ProgramData\'
            - '1.bat'
    condition: selection_parent and selection_cmd and selection_args
falsepositives:
    - Unlikely in legitimate environments
level: high
```

### Sigma: TerminalFix Python Reverse Tunnel Implant Execution

Detects `pythonw.exe` or `python.exe` launched with the campaign's characteristic tunnel arguments (`client.py`, `--server`, `--uuid`, `cert.pem`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Highly distinctive 4-argument combination specific to this implant. -->
```yaml
title: TerminalFix Python Reverse Tunnel Implant Execution
id: 2a4b6c8d-0e1f-4a3b-8c5d-9e7f6a1b2c3d
status: experimental
description: >
    Detects execution of the TerminalFix Python-based reverse tunnel implant via
    pythonw.exe with the characteristic command-line arguments client.py, --server,
    --uuid, and cert.pem.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1572
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\pythonw.exe'
            - '\python.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'client.py'
            - '--server'
            - '--uuid'
            - 'cert.pem'
    condition: selection_process and selection_cmdline
falsepositives:
    - Unlikely; highly specific command-line combination
level: critical
```

### Sigma: TerminalFix DLL Sideloading via LockScreenContentServer

Detects `LockScreenContentServer.exe` loading `dui70.dll` from a non-standard directory (outside System32/WinSxS/Program Files), indicating DLL sideloading.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Requires Sysmon EID 7 (image_load) for telemetry. -->
```yaml
title: TerminalFix DLL Sideloading via LockScreenContentServer
id: 5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a9b
status: experimental
description: >
    Detects loading of malicious dui70.dll by LockScreenContentServer.exe from a
    non-standard directory, indicating DLL sideloading used in the TerminalFix campaign.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\LockScreenContentServer.exe'
        ImageLoaded|endswith: '\dui70.dll'
    filter_legit_paths:
        ImageLoaded|contains:
            - '\Windows\System32'
            - '\Windows\SysWOW64'
            - '\Windows\WinSxS'
            - '\Program Files'
            - '\Program Files (x86)'
    condition: selection and not filter_legit_paths
falsepositives:
    - LockScreenContentServer.exe loading dui70.dll from a non-standard path outside of this campaign
level: high
```

### Sigma: TerminalFix C2 Domain DNS Query

Detects DNS resolution of known TerminalFix C2 and payload-delivery domains (`gitnow.dev`, `bestsocialmedianewspapper.com`, `offlineupdater.com`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. IOC-specific; will need updating if infrastructure rotates. -->
```yaml
title: TerminalFix Campaign C2 Domain DNS Query
id: 8d9e0f1a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
status: experimental
description: >
    Detects DNS queries to known TerminalFix campaign command-and-control and payload
    delivery domains including gitnow.dev, bestsocialmedianewspapper.com, and
    offlineupdater.com.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'gitnow.dev'
            - 'bestsocialmedianewspapper.com'
            - 'offlineupdater.com'
    condition: selection
falsepositives:
    - Unlikely; these domains are campaign-specific infrastructure
level: critical
```

### Sigma: TerminalFix Scheduled Task Persistence

Detects `schtasks.exe /create` with `LockScreenContentServer` in the command line, matching the campaign's persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Specific to campaign persistence pattern. -->
```yaml
title: TerminalFix Scheduled Task Persistence
id: 1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6
status: experimental
description: >
    Detects creation of a scheduled task matching the TerminalFix campaign persistence
    pattern using LockScreenContentServer with randomized suffixes.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - 'LockScreenContentServer'
    condition: selection_schtasks
falsepositives:
    - Legitimate scheduled tasks created for LockScreenContentServer, which is uncommon
level: high
```

### Sigma: TerminalFix Steganographic Payload Extraction

Detects PowerShell script block containing the `Extract-RawFileFromImage` function used to extract payloads from steganographic PNG images.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 from proxy); splunk convert exit 0; log_scale convert exit 0. Requires PowerShell script block logging enabled. Function name is distinctive to this campaign. -->
```yaml
title: TerminalFix Steganographic Payload Extraction via PowerShell
id: 3f4a5b6c-7d8e-9f0a-1b2c-3d4e5f6a7b8c
status: experimental
description: >
    Detects PowerShell script block execution containing the Extract-RawFileFromImage
    function used by the TerminalFix campaign to extract payloads from steganographic
    PNG images.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/29
tags:
    - attack.t1027.003
    - attack.t1059.001
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|contains: 'Extract-RawFileFromImage'
    condition: selection
falsepositives:
    - Legitimate steganography research tools using the same function name
level: high
```

### Snort: TerminalFix DNS Queries to C2 Domains

Detects DNS queries for the three known TerminalFix campaign domains via label-length-encoded content matching.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. DNS label encoding: |06|gitnow|03|dev|00| (6-char label + 3-char label + root), |18|bestsocialmedianewspapper = 24 chars = 0x18, |0e|offlineupdater = 14 chars = 0x0e. Port 53 used (Snort 2 lacks $DNS_PORTS). -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - TerminalFix DNS Query to gitnow.dev C2 Domain"; content:"|06|gitnow|03|dev|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; sid:2100101; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - TerminalFix DNS Query to bestsocialmedianewspapper.com"; content:"|18|bestsocialmedianewspapper|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; sid:2100102; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - TerminalFix DNS Query to offlineupdater.com"; content:"|0e|offlineupdater|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; sid:2100103; rev:1;)
```

### Suricata: TerminalFix DNS and TLS C2 Indicators

Detects DNS queries and TLS connections to TerminalFix campaign infrastructure using Suricata's native `dns.query` and `tls.sni` sticky buffers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Four rules: 3 DNS + 1 TLS SNI. IOC-anchored, will need updating if infrastructure rotates. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - TerminalFix DNS Query to gitnow.dev C2 Domain"; flow:to_server; dns.query; content:"gitnow.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-29; sid:2200101; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - TerminalFix DNS Query to bestsocialmedianewspapper.com"; flow:to_server; dns.query; content:"bestsocialmedianewspapper.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-29; sid:2200102; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - TerminalFix DNS Query to offlineupdater.com"; flow:to_server; dns.query; content:"offlineupdater.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-29; sid:2200103; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix TLS Connection to gitnow.dev C2"; flow:established,to_server; tls.sni; content:"gitnow.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-29; sid:2200104; rev:1;)
```

### YARA: TerminalFix Python Tunnel Implant and Malicious DLL

Detects the TerminalFix Python tunnel implant (`client.py`) and malicious `dui70.dll` via campaign-specific string combinations including C2 domains, steganography function names, and tunnel protocol indicators.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. String-based detection without samples; two rules cover implant script and DLL. Confidence medium because string matches are based on reported indicators, not confirmed sample analysis. -->
```yara
rule TerminalFix_Python_Tunnel_Implant
{
    meta:
        description = "Detects the TerminalFix Python-based reverse tunnel implant (client.py) via characteristic strings"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a"
        severity = "critical"

    strings:
        $s1 = "Extract-RawFileFromImage" ascii wide
        $s2 = "gitnow.dev" ascii wide
        $s3 = "client.py" ascii
        $s4 = "--server" ascii
        $s5 = "--uuid" ascii
        $s6 = "cert.pem" ascii
        $s7 = "/tunnel" ascii
        $s8 = "CERT_NONE" ascii
        $s9 = "bestsocialmedianewspapper.com" ascii wide
        $s10 = "offlineupdater.com" ascii wide

    condition:
        filesize < 500KB and
        (
            (3 of ($s1, $s2, $s7, $s8, $s9, $s10)) or
            ($s3 and $s4 and $s5 and $s6) or
            ($s2 and $s7 and $s8)
        )
}

rule TerminalFix_Malicious_DUI70_DLL
{
    meta:
        description = "Detects the TerminalFix malicious dui70.dll used in DLL sideloading with LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        severity = "critical"

    strings:
        $dll_name = "dui70.dll" ascii wide fullword
        $steg1 = "Extract-RawFileFromImage" ascii wide
        $steg2 = "RGBA" ascii
        $c2_1 = "gitnow.dev" ascii wide
        $c2_2 = "bestsocialmedianewspapper.com" ascii wide
        $c2_3 = "offlineupdater.com" ascii wide
        $persist1 = "LockScreenContentServer" ascii wide
        $bat = "1.bat" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($c2_*)) or
            ($steg1 and 1 of ($c2_*)) or
            ($steg2 and $steg1) or
            ($dll_name and $persist1 and $bat and 1 of ($c2_*))
        )
}
```

## Lessons Learned

1. **ClickFix continues to evolve:** The TerminalFix campaign demonstrates that fake CAPTCHA social engineering remains highly effective, particularly when impersonating trusted mechanisms like Cloudflare Turnstile. User education on not pasting commands from web prompts is critical.

2. **Living-off-the-land via legitimate runtimes:** Downloading an official Python embeddable distribution from `python.org` to deploy a custom tunnel implant is a potent evasion technique -- the Python runtime itself is not malicious, making static detection of the execution environment ineffective. Detection must focus on the implant script and its command-line arguments.

3. **Steganography raises the bar for network detection:** Splitting payloads across multiple PNG images and encoding them in RGBA pixel channels defeats traditional network content inspection. Behavioral detection (monitoring for PowerShell downloading PNG files and then executing extracted code) is more durable than signature-based network detection for this stage.

4. **DLL sideloading of Windows components remains a persistent gap:** The use of `LockScreenContentServer.exe` with `dui70.dll` (the Windows DirectUI Engine DLL) for sideloading highlights the continued risk of legitimate signed binaries being abused. Application allowlisting and image load monitoring are essential compensating controls.

5. **Reverse tunnels bypass perimeter defenses:** A WebSocket tunnel over TLS/443 blends with legitimate HTTPS traffic, bypassing most firewalls and proxies. Detection requires TLS inspection or host-based monitoring of the tunnel establishment process.

## Sources

- [Microsoft Threat Intelligence: TerminalFix Campaign](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) -- Primary technical analysis of the TerminalFix ClickFix campaign with IOCs, attack chain, and detection guidance

---
*Report generated by Actioner*
