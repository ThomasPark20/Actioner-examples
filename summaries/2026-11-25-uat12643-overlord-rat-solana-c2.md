# UAT-12643: Overlord RAT with Solana Blockchain C2 Resolution

> **DRAFT** — Pending critic review.

## Executive Summary

North Korea-aligned threat actor UAT-12643 is conducting an ongoing campaign targeting cryptocurrency and Web3 professionals through fake job offers and social engineering. The campaign deploys a multi-component toolset: **Overlord RAT** (remote access with BSoD-based anti-forensics), a **clipboard hijacker** (cryptocurrency address replacement), and **Good Game Stealer** (browser credential and session theft with gofile[.]io exfiltration). The most notable technical innovation is the use of the **Solana blockchain Memo Program** for C2 address resolution — the actor writes AES-256-encrypted WebSocket URLs as memo transactions, and the RAT reads them via public Solana RPC endpoints, making C2 infrastructure effectively undeletable and censorship-resistant. The campaign has been active since at least early 2025 and continues to evolve with new delivery mechanisms including LNK-based downloaders, `MpCmdRun.exe` abuse, `mshta.exe` with MSXML2, and `msbuild.exe` inline tasks.

## Background

UAT-12643 is tracked by Cisco Talos as a North Korea-aligned actor operating within the broader DPRK cyber ecosystem focused on cryptocurrency theft. The actor's toolset shares no direct code overlap with known Lazarus/APT38 tools but exhibits operational patterns consistent with DPRK-aligned campaigns: targeting of cryptocurrency industry personnel, use of social engineering themed around employment opportunities, and financial theft as a primary objective.

The campaign uses multiple initial access vectors centered on malicious LNK files delivered through social engineering, with subsequent stages hosted on actor-controlled infrastructure at 41[.]216[.]188[.]11. The threat actor operates a Flask-based management interface (port 8000) for campaign administration and deploys WebSocket-based C2 channels across multiple ports (5173, 5656, 5959) for different malware components.

## Attack Timeline

| Date | Event |
|---|---|
| Early 2025 | Earliest observed UAT-12643 activity |
| Mid 2025 | Introduction of Solana blockchain C2 resolution mechanism |
| 2026-11-25 | Cisco Talos publishes comprehensive analysis |

## Root Cause / Initial Access Vector

Initial access is achieved through **social engineering** (T1566.001) using fake job offers targeting cryptocurrency and Web3 professionals. Victims receive malicious LNK files that trigger multi-stage download chains. Three distinct delivery mechanisms have been observed:

1. **MpCmdRun.exe abuse**: LNK executes Windows Defender's `MpCmdRun.exe` with `-DownloadFile` to fetch `RuntimeBroker.exe` from actor infrastructure — a living-off-the-land technique that abuses a signed Microsoft binary.
2. **certutil download**: LNK executes `certutil -urlcache -f` to download payloads directly.
3. **mshta.exe + MSXML2**: LNK executes `mshta.exe` which uses `MSXML2.ServerXMLHTTP` to download and execute a payload dropped to `%TEMP%\s.exe`.

A fourth mechanism uses `msbuild.exe` with an inline task (`CodeTaskFactory`) in `dl.xml` to compile and execute a downloader at runtime.

The LNK files are generated using a builder running on a host identified as `win-8oa3ccqae4d`, with one variant also generating a companion PowerShell script.

## Technical Analysis

### Stage 1: Initial Loader and Download

All delivery chains converge on downloading an executable from 41[.]216[.]188[.]11 port 8000 (Flask server). The downloaded payload spoofs a **Microsoft BITS/7.8** User-Agent header during the download — a fabricated version string not associated with any legitimate BITS release.

Downloaded executables use names designed to blend with legitimate processes: `RuntimeBroker.exe`, `Payload.exe`, `MyApp2.exe`. These loaders perform environment checks before proceeding.

### Stage 2: Sandbox and VM Evasion (T1497.001)

Before deploying payloads, the loader performs extensive environment checks:

**Sandbox DLL detection** — checks for the presence of analysis tool DLLs:
- `sbiedll.dll` (Sandboxie)
- `api_log.dll` (SunBelt SandBox)
- `vmcheck.dll` (Virtual PC)
- `wpespy.dll` (WPE Pro)
- `cmdvrt64.dll` (Comodo)
- `avghookx.dll` (AVG)
- `snxhk.dll` (Avast)
- `guard32.dll` (COMODO Internet Security)

**VM MAC address OUI detection** — checks network adapter MAC prefixes:
- `00:05:69`, `00:0c:29`, `00:50:56` (VMware)
- `08:00:27` (VirtualBox)
- `00:15:5d` (Hyper-V)
- `00:16:3e` (Xen)
- `00:1c:42` (Parallels)

### Stage 3: Overlord RAT — Solana Blockchain C2 Resolution (T1102)

The campaign's most significant technical innovation is the use of the **Solana blockchain Memo Program** for C2 resolution. Rather than hardcoding C2 addresses or using traditional DNS-based DGA, the RAT:

1. Queries a Solana RPC endpoint for recent transactions associated with a specific wallet address using `getSignaturesForAddress`.
2. Retrieves full transaction details via `getTransaction` with `jsonParsed` encoding.
3. Filters for transactions involving the **Memo Program** (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
4. Extracts memo data, filtering for strings matching a **43-character Base58 pattern** (the AES-256-encrypted C2 URL).
5. Decrypts the memo to obtain the WebSocket C2 URL.

This technique makes C2 infrastructure effectively **immutable and censorship-resistant** — blockchain transactions cannot be deleted or seized, and the RAT can recover C2 addresses from any public Solana RPC endpoint.

### Stage 4: Overlord RAT Capabilities

Once connected to C2 (WebSocket on port 5173), Overlord RAT provides:

- **Screen capture** via GDI+ (T1113)
- **Keylogging** via `GetAsyncKeyState` polling (T1056.001)
- **Webcam capture** via `avicap32.dll` / `capCreateCaptureWindow` (T1125)
- **Audio capture** (T1123)
- **Process injection** via `CreateRemoteThread` (T1055.001)
- **BSoD trigger** via `NtRaiseHardError` — forces a blue screen to destroy forensic evidence in memory (T1562.001)
- **Task Manager disabling** via `DisableTaskMgr` registry key (T1562.001)

### Stage 5: Clipboard Hijacker (T1115)

A separate component (`MsgEdgeUpdate.exe`) monitors the clipboard for cryptocurrency wallet addresses and replaces them with actor-controlled addresses:

- Creates mutex `UuuRjinBZPBMIjnc` for single-instance enforcement
- Persists via HKCU Run key `MsgEdgeUpdate`
- Monitors for Bitcoin (bc1/1/3 prefix), Ethereum (0x prefix), Solana, and other cryptocurrency address patterns
- Communicates with C2 on port 5959

### Stage 6: Good Game Stealer (T1555, T1539)

The credential stealer component targets browser data and sessions:

- Steals Chrome, Firefox, and other browser stored credentials, cookies, and session tokens
- Persists via HKCU Run key `Zoipers` (mimicking Zoiper VoIP software)
- Exfiltrates stolen data to **gofile[.]io** via HTTP POST (T1567.002)
- Reports results to actor via **Discord webhooks**
- Communicates with C2 on ports 5656/5959

### Persistence Mechanisms (T1547.001)

Multiple persistence mechanisms are used:

| Mechanism | Component | Details |
|---|---|---|
| Registry Run key `MsgEdgeUpdate` | Clipboard Hijacker | HKCU\...\Run\MsgEdgeUpdate → %APPDATA%\MsgEdgeUpdate.exe |
| Registry Run key `Zoipers` | Good Game Stealer | HKCU\...\Run\Zoipers |
| Startup folder | Various | Payloads copied to Startup directory |
| Recovery OEM directory | Overlord RAT | Components staged in %TARGETOSDRIVE%\Recovery\OEM\ |

## Indicators of Compromise

### Network Indicators

| Type | Indicator | Context |
|---|---|---|
| IP | 41[.]216[.]188[.]11 | Primary C2 / payload server |
| Port | 8000 | Flask management interface |
| Port | 5173 | Overlord RAT WebSocket C2 |
| Port | 5656 | Stealer C2 |
| Port | 5959 | Stealer / Clipper C2 |
| User-Agent | Microsoft BITS/7.8 | Spoofed download User-Agent |
| Domain | gofile[.]io | Exfiltration endpoint |
| URL | discord[.]com/api/webhooks/* | Stealer reporting |

### File System Indicators

| Type | Indicator | Context |
|---|---|---|
| Filename | RuntimeBroker.exe | Masquerading loader |
| Filename | Payload.exe | Loader variant |
| Filename | MyApp2.exe | Loader variant |
| Filename | Ovl.exe | Overlord RAT |
| Filename | Client.exe | Overlord RAT variant |
| Filename | Ova.exe | Overlord RAT variant |
| Filename | microsip-config.exe | Loader masquerading as MicroSIP |
| Filename | microsip-config1.exe | Loader variant |
| Filename | MsgEdgeUpdate.exe | Clipboard Hijacker |
| Filename | dl.xml | MSBuild inline task payload |
| Path | %TEMP%\s.exe | mshta delivery drop path |
| Path | %APPDATA%\MsgEdgeUpdate.exe | Clipper persistence location |
| Path | %TARGETOSDRIVE%\Recovery\OEM\ | Overlord RAT staging directory |
| Mutex | UuuRjinBZPBMIjnc | Clipboard Hijacker single-instance mutex |

### Behavioral Indicators

| Indicator | Context |
|---|---|
| MpCmdRun.exe with -DownloadFile and -url arguments | LOLBin download abuse |
| mshta.exe spawning with MSXML2.ServerXMLHTTP | Script-based download |
| msbuild.exe loading dl.xml with CodeTaskFactory | Inline task compilation |
| Registry key ending in \Run\MsgEdgeUpdate | Clipper persistence |
| Registry key ending in \Run\Zoipers | Stealer persistence |
| DisableTaskMgr set to 1 | Anti-forensics |
| Outbound WebSocket to port 5173 | Overlord RAT C2 |
| HTTP POST to gofile[.]io | Data exfiltration |
| Solana RPC queries for getSignaturesForAddress | Blockchain C2 resolution |

### ClamAV Signatures (Published by Talos)

| Signature | Component |
|---|---|
| Win.Trojan.OverlordRAT-10060615-0 | Overlord RAT |
| Ps1.Trojan.LNKBuilder-10060627-0 | LNK Builder |

### Existing Snort SIDs (Published by Talos)

| SID | Engine |
|---|---|
| 1:67491, 1:67490 | Snort 2 |
| 7:75, 7:74 | Snort 3 |

### LNK Generator Host

| Indicator | Value |
|---|---|
| Hostname | win-8oa3ccqae4d |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Usage |
|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | Malicious LNK files via fake job offers |
| Execution | User Execution: Malicious File | T1204.002 | Victim opens LNK file |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | LNK → cmd.exe chains |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | mshta.exe VBScript execution |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | mshta.exe for payload download |
| Defense Evasion | Trusted Developer Utilities Proxy Execution: MSBuild | T1127.001 | msbuild.exe inline task execution |
| Command and Control | Ingress Tool Transfer | T1105 | Multi-stage payload download |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | MsgEdgeUpdate, Zoipers Run keys |
| Persistence | Boot or Logon Autostart Execution: Active Setup | T1547.014 | Startup folder persistence |
| Defense Evasion | Process Injection: DLL Injection | T1055.001 | CreateRemoteThread injection |
| Collection | Input Capture: Keylogging | T1056.001 | GetAsyncKeyState polling |
| Collection | Screen Capture | T1113 | GDI+ screen capture |
| Collection | Video Capture | T1125 | avicap32.dll webcam access |
| Collection | Audio Capture | T1123 | Microphone recording |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/WebSocket C2 |
| Command and Control | Web Service | T1102 | Solana blockchain C2 resolution |
| Collection | Clipboard Data | T1115 | Crypto address replacement |
| Command and Control | Non-Standard Port | T1571 | C2 on ports 5173, 5656, 5959 |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | DLL and MAC-based VM detection |
| Credential Access | Credentials from Password Stores | T1555 | Browser credential theft |
| Credential Access | Steal Web Session Cookie | T1539 | Browser cookie theft |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | gofile[.]io upload |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | DisableTaskMgr, BSoD trigger |
| Defense Evasion | Obfuscated Files or Information | T1027 | AES-256 encrypted C2 URLs in blockchain |

## Impact Assessment

**Severity: Critical**

This campaign poses a significant threat to cryptocurrency and Web3 organizations:

- **Financial**: Direct cryptocurrency theft via clipboard hijacking and credential/session theft from exchanges and wallets
- **Operational**: Full system compromise via RAT with destructive BSoD capability
- **Strategic**: Censorship-resistant C2 via Solana blockchain makes takedown extremely difficult — the C2 resolution mechanism will continue functioning as long as the Solana network operates
- **Attribution**: North Korea-aligned actor consistent with state-sponsored cryptocurrency theft operations

## Detection & Remediation

### Detection Priorities

1. **High**: Monitor for `MpCmdRun.exe` with `-DownloadFile` parameter — legitimate use is rare and easily baselined
2. **High**: Alert on registry Run key creation for `MsgEdgeUpdate` or `Zoipers` — these are near-unique to this campaign
3. **High**: Network monitoring for connections to 41[.]216[.]188[.]11 on ports 5173/5656/5959/8000
4. **Medium**: Monitor for files written to `\Recovery\OEM\` directory — legitimate writes are extremely rare
5. **Medium**: Hunt for `DisableTaskMgr` registry modifications by non-system processes
6. **Medium**: Monitor for spoofed BITS/7.8 User-Agent in HTTP traffic

### Remediation Steps

1. Block 41[.]216[.]188[.]11 at network perimeter and EDR
2. Search for and remove registry Run keys `MsgEdgeUpdate` and `Zoipers`
3. Search for and remove files in `%TARGETOSDRIVE%\Recovery\OEM\` matching known filenames
4. Scan for mutex `UuuRjinBZPBMIjnc` in running processes
5. Review Solana RPC endpoint access in proxy logs (unusual for most enterprise environments)
6. Deploy the detection rules below across SIEM, IDS, and endpoint platforms
7. Conduct credential rotation for any compromised systems — particularly browser-stored credentials and cryptocurrency wallet access

## Detection Rules

### Sigma Rules

#### 1. MpCmdRun.exe Download Abuse

**Compile status**: validated (Splunk conversion) | **Confidence**: high

Detects MpCmdRun.exe used with -DownloadFile to fetch remote files, a LOLBin technique used by UAT-12643 to deliver Overlord RAT.

```yaml
title: MpCmdRun.exe Abused to Download File - UAT-12643 Overlord RAT Delivery
id: f5687bd2-50ea-44ed-a129-ad31d2e50e98
status: experimental
description: >
    Detects Windows Defender MpCmdRun.exe used with -DownloadFile to fetch
    remote files, a living-off-the-land technique observed in UAT-12643
    campaigns delivering Overlord RAT via RuntimeBroker.exe.
references:
    - https://blog.talosintelligence.com/uat-12643-overlord-rat/
author: Actioner
date: 2026-11-25
tags:
    - attack.t1105
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\MpCmdRun.exe'
        CommandLine|contains|all:
            - '-DownloadFile'
            - '-url'
    condition: selection
falsepositives:
    - Legitimate Windows Defender definition updates using MpCmdRun with -DownloadFile
level: high
```

#### 2. Executable in Recovery OEM Directory

**Compile status**: validated (Splunk conversion) | **Confidence**: high

Detects executables dropped in the Windows Recovery OEM directory, a persistence location used by UAT-12643.

```yaml
title: Executable Dropped in Windows Recovery OEM Directory
id: 59d797df-333e-4a5c-a184-10290de60359
status: experimental
description: >
    Detects creation of executable files in the Windows Recovery OEM directory,
    a rarely inspected persistence location used by UAT-12643 to stage
    Overlord RAT components outside typical forensic search paths.
references:
    - https://blog.talosintelligence.com/uat-12643-overlord-rat/
author: Actioner
date: 2026-11-25
tags:
    - attack.t1036.005
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Recovery\OEM\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.scr'
            - '.bat'
    condition: selection
falsepositives:
    - OEM system recovery software installation or updates
level: high
```

#### 3. MsgEdgeUpdate Registry Persistence

**Compile status**: validated (Splunk conversion) | **Confidence**: high

Detects the unique MsgEdgeUpdate registry Run key used by UAT-12643's clipboard hijacker.

```yaml
title: MsgEdgeUpdate Registry Run Key Persistence - UAT-12643 Clipboard Hijacker
id: bcf8856a-910b-4a7d-893a-9db8e7e9e007
status: experimental
description: >
    Detects creation of a registry Run key named MsgEdgeUpdate, used by
    UAT-12643 clipboard hijacker for persistence while masquerading as
    a Microsoft Edge update component. This is not a legitimate Microsoft
    process or update mechanism.
references:
    - https://blog.talosintelligence.com/uat-12643-overlord-rat/
author: Actioner
date: 2026-11-25
tags:
    - attack.t1547.001
    - attack.t1115
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Run\MsgEdgeUpdate'
    condition: selection
falsepositives:
    - Unlikely - MsgEdgeUpdate is not a legitimate Microsoft Edge update process name
level: high
```

#### 4. Zoipers Registry Persistence

**Compile status**: validated (Splunk conversion) | **Confidence**: medium

Detects the Zoipers registry Run key used by UAT-12643's Good Game Stealer.

```yaml
title: Zoipers Registry Run Key Persistence - UAT-12643 Stealer
id: 2605f79c-43fe-48ca-9c94-3c08878163c7
status: experimental
description: >
    Detects creation of a registry Run key named Zoipers, used by
    UAT-12643 Good Game Stealer for persistence while masquerading as
    the legitimate Zoiper VoIP application. The legitimate software
    uses the name Zoiper, not Zoipers.
references:
    - https://blog.talosintelligence.com/uat-12643-overlord-rat/
author: Actioner
date: 2026-11-25
tags:
    - attack.t1547.001
    - attack.t1555
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Run\Zoipers'
    condition: selection
falsepositives:
    - Legitimate Zoiper VoIP software uses the name Zoiper without the trailing s
level: medium
```

#### 5. DisableTaskMgr Defense Evasion

**Compile status**: validated (Splunk conversion) | **Confidence**: medium

Detects DisableTaskMgr registry modification by non-system processes.

```yaml
title: Task Manager Disabled via Registry - UAT-12643 Defense Evasion
id: df7cd787-1302-44ee-b11d-8d360b5502d5
status: experimental
description: >
    Detects the DisableTaskMgr registry value being set to 1 by a
    non-standard process, a defense evasion technique used by UAT-12643
    Overlord RAT to prevent victims from terminating malicious processes
    via Task Manager.
references:
    - https://blog.talosintelligence.com/uat-12643-overlord-rat/
author: Actioner
date: 2026-11-25
tags:
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Policies\Microsoft\Windows\System\DisableTaskMgr'
    filter_system:
        Image|endswith:
            - '\svchost.exe'
            - '\mmc.exe'
            - '\gpedit.msc'
    condition: selection and not filter_system
falsepositives:
    - Group Policy enforcement of Task Manager restrictions in corporate environments
    - Parental control software disabling Task Manager
level: high
```

### Snort Rules (Snort 2)

#### 6. UAT-12643 C2 to Known Infrastructure

**Compile status**: validated (snort -T) | **Confidence**: high (time-limited — IP may rotate)

```
alert tcp $HOME_NET any -> 41.216.188.11 [5173,5656,5959] (msg:"Actioner - UAT-12643 Overlord RAT C2 to Known Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; sid:2100010; rev:1;)
```

#### 7. Spoofed BITS/7.8 User-Agent

**Compile status**: validated (snort -T) | **Confidence**: high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Spoofed Microsoft BITS/7.8 User-Agent Associated with UAT-12643"; flow:established,to_server; content:"Microsoft BITS/7.8"; http_header; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; sid:2100011; rev:1;)
```

#### 8. UAT-12643 Flask C2 Server

**Compile status**: validated (snort -T) | **Confidence**: high (time-limited — IP may rotate)

```
alert tcp $HOME_NET any -> 41.216.188.11 8000 (msg:"Actioner - UAT-12643 Flask C2 Server Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; sid:2100013; rev:1;)
```

### Suricata Rules

#### 9. UAT-12643 C2 to Known Infrastructure

**Compile status**: validated (suricata -T) | **Confidence**: high (time-limited — IP may rotate)

```
alert tcp $HOME_NET any -> 41.216.188.11 [5173,5656,5959] (msg:"Actioner - UAT-12643 Overlord RAT C2 to Known Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; metadata:author Actioner, created_at 2026-11-25; sid:2100010; rev:1;)
```

#### 10. Spoofed BITS/7.8 User-Agent

**Compile status**: validated (suricata -T) | **Confidence**: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Spoofed Microsoft BITS/7.8 User-Agent Associated with UAT-12643"; flow:established,to_server; http.user_agent; content:"Microsoft BITS/7.8"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; metadata:author Actioner, created_at 2026-11-25; sid:2100011; rev:1;)
```

#### 11. UAT-12643 Flask C2 Server

**Compile status**: validated (suricata -T) | **Confidence**: high (time-limited — IP may rotate)

```
alert tcp $HOME_NET any -> 41.216.188.11 8000 (msg:"Actioner - UAT-12643 Flask C2 Server Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; metadata:author Actioner, created_at 2026-11-25; sid:2100013; rev:1;)
```

#### 12. gofile.io Exfiltration with BITS User-Agent

**Compile status**: validated (suricata -T) | **Confidence**: medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Exfiltration via gofile.io POST with BITS UA - UAT-12643"; flow:established,to_server; http.method; content:"POST"; http.host; content:"gofile.io"; endswith; http.user_agent; content:"BITS"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/uat-12643-overlord-rat/; metadata:author Actioner, created_at 2026-11-25; sid:2100014; rev:1;)
```

### YARA Rules

#### 13. Overlord RAT Core Strings

**Compile status**: compiled (yarac exit 0) | **Confidence**: high

Detects Overlord RAT via BSoD trigger APIs, Solana blockchain C2 resolution strings, and sandbox evasion DLL checks.

```yara
rule Malware_OverlordRAT_Core_Strings
{
    meta:
        description = "Detects Overlord RAT via distinctive string artifacts including BSoD trigger, Solana blockchain C2 resolution, and sandbox evasion checks"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "critical"

    strings:
        $bsod1 = "NtRaiseHardError" ascii fullword
        $bsod2 = "NtSetInformationProcess" ascii fullword

        $sol1 = "getSignaturesForAddress" ascii
        $sol2 = "getTransaction" ascii
        $sol3 = "jsonParsed" ascii
        $sol4 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" ascii

        $cam1 = "avicap32.dll" ascii nocase
        $cam2 = "capCreateCaptureWindow" ascii fullword

        $key1 = "GetAsyncKeyState" ascii fullword
        $key2 = "GetForegroundWindow" ascii fullword

        $sb1 = "sbiedll.dll" ascii nocase
        $sb2 = "api_log.dll" ascii nocase
        $sb3 = "vmcheck.dll" ascii nocase
        $sb4 = "wpespy.dll" ascii nocase
        $sb5 = "cmdvrt64.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($sol*) and 1 of ($bsod*)) or
            (2 of ($sol*) and 1 of ($cam*)) or
            (2 of ($sol*) and 1 of ($key*)) or
            (1 of ($bsod*) and 3 of ($sb*) and (1 of ($cam*) or 1 of ($key*)))
        )
}
```

#### 14. UAT-12643 Clipboard Hijacker

**Compile status**: compiled (yarac exit 0) | **Confidence**: high

Detects the clipboard hijacker via unique mutex and crypto address replacement functionality.

```yara
rule Malware_UAT12643_ClipboardHijacker
{
    meta:
        description = "Detects UAT-12643 clipboard hijacker (MsgEdgeUpdate) via unique mutex and crypto address replacement functionality"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "high"

    strings:
        $mutex = "UuuRjinBZPBMIjnc" ascii wide
        $name1 = "MsgEdgeUpdate" ascii wide
        $clip1 = "GetClipboardData" ascii fullword
        $clip2 = "SetClipboardData" ascii fullword

        $btc = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii
        $eth = "^0x[0-9a-fA-F]{40}$" ascii
        $sol = "^[1-9A-HJ-NP-Za-km-z]{32,44}$" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            $mutex or
            ($name1 and $clip1 and $clip2 and 1 of ($btc, $eth, $sol))
        )
}
```

#### 15. UAT-12643 Good Game Stealer

**Compile status**: compiled (yarac exit 0) | **Confidence**: medium

Detects Good Game Stealer via exfiltration endpoints and browser credential theft indicators.

```yara
rule Malware_UAT12643_GoodGameStealer
{
    meta:
        description = "Detects UAT-12643 Good Game Stealer via gofile.io exfiltration endpoint, Discord webhook reporting, and browser credential theft indicators"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "high"

    strings:
        $exfil1 = "gofile.io" ascii wide
        $exfil2 = "store.gofile.io" ascii wide
        $discord = "discord.com/api/webhooks" ascii wide

        $brw1 = "Login Data" ascii wide
        $brw2 = "Web Data" ascii wide
        $brw3 = "Cookies" ascii wide
        $brw4 = "Local State" ascii wide

        $path1 = "\\AppData\\Local\\Google\\Chrome\\User Data" ascii
        $path2 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" ascii

        $name1 = "Zoipers" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($name1 and 1 of ($exfil*)) or
            (1 of ($exfil*) and $discord and 2 of ($brw*)) or
            ($discord and 3 of ($brw*) and 1 of ($path*))
        )
}
```

## Lessons Learned

1. **Blockchain as C2 infrastructure** represents a significant evolution in resilience — traditional takedown mechanisms (domain seizure, IP blocking) are insufficient when C2 addresses are stored immutably on-chain. Organizations should monitor for unusual blockchain RPC endpoint access patterns.

2. **Living-off-the-land binaries** continue to be effective — `MpCmdRun.exe`, `mshta.exe`, `msbuild.exe`, and `certutil.exe` are all legitimate Windows tools abused in this campaign. Application control policies and command-line monitoring are essential.

3. **Multi-component toolsets** with separate persistence mechanisms increase resilience — even if the RAT is detected and removed, the clipboard hijacker and stealer may continue operating independently.

4. **Cryptocurrency industry targeting** by DPRK-aligned actors remains a persistent threat, with social engineering through fake job offers as a consistently effective initial access vector.

## Sources

- Cisco Talos Intelligence. "UAT-12643: Overlord RAT with Solana Blockchain C2." November 2026. hxxps://blog[.]talosintelligence[.]com/uat-12643-overlord-rat/
