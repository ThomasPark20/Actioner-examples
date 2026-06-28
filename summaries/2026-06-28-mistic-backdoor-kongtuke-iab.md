# Technical Analysis Report: Mistic Backdoor / KongTuke Initial Access Broker (2026-06-28)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-28
Version: 1.0 (DRAFT)

## Executive Summary

Mistic (also tracked as Backdoor.Mistic and MLTBackdoor by Zscaler) is a newly discovered stealthy backdoor linked with low confidence to the financially motivated initial access broker (IAB) known publicly as KongTuke (tracked internally by Symantec/Broadcom as Woodgnat). Active since April 2026, Mistic executes payloads entirely in memory via DLL sideloading through a legitimate Microsoft binary (MpExtMs.exe), communicates over TLS/443 using a spoofed Microsoft-Delivery-Optimization user-agent, and includes a kill switch for self-destruction. Approximately 95% of the backdoor's code consists of junk mathematical operations inserted to confuse automated analysis.

KongTuke has been active since at least May 2024 and has been observed supplying enterprise network access to six major ransomware operations: Qilin, Interlock, Rhysida, Akira, 8Base, and Black Basta. Mistic has been deployed in attacks targeting organizations in the insurance, education, IT, and professional services sectors. A secondary payload, ModeloRAT (a Python-based RAT), has also been deployed in related campaigns including ClickFix, CrashFix, and Microsoft Teams social engineering attacks.

## Background: KongTuke / Woodgnat Initial Access Broker

KongTuke (also tracked as 404 TDS, Chaya_002, LandUpdate808, and TAG-124) is an initial access broker that has been active since at least May 2024. The group specializes in compromising corporate networks and selling persistent footholds to ransomware operators. Their infrastructure leverages a traffic distribution system (TDS) deployed on compromised WordPress sites to redirect victims to ClickFix/CrashFix social engineering pages. KongTuke is assessed by Symantec/Broadcom as "quite highly skilled at development of stealthy remote access tools."

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| May 2024 | KongTuke/Woodgnat initial access broker first observed active |
| 2025 | ClickFix/FileFix delivery campaigns begin |
| January 2026 | ModeloRAT first flagged by Huntress in CrashFix campaign |
| April 2026 | Mistic backdoor deployment begins; Microsoft Teams social engineering vector introduced for ModeloRAT delivery |
| May 2026 | Zscaler documents Mistic (as MLTBackdoor) in ClickFix campaigns |
| June 2026 | Zscaler publishes MLTBackdoor analysis |
| 2026-06-25 | Symantec/Broadcom (Carbon Black) publishes full threat report linking Mistic to Woodgnat/KongTuke |

## Root Cause: Social Engineering via ClickFix / CrashFix / Teams Impersonation

Initial access is achieved through multiple social engineering vectors:

1. **ClickFix/CrashFix Campaigns**: Compromised WordPress sites running a traffic distribution system (TDS) push fake technical alerts that intentionally crash the victim's browser, then display instructions to "fix" the issue by running malicious commands.
2. **Malicious Chrome Extension**: A Chrome extension masquerading as an ad blocker intentionally crashes the browser to push victims toward the ClickFix remediation flow.
3. **Microsoft Teams Social Engineering** (since April/May 2026): Fake IT helpdesk support messages via Microsoft Teams to deliver ModeloRAT.
4. **DNS-based Payload Retrieval**: A secondary variant uses DNS queries for payload staging.

All vectors converge on a multi-stage PowerShell chain that downloads the malware package, which ultimately deploys the Mistic backdoor via DLL sideloading.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader — DLL Sideloading Chain

The infection begins with the deployment of three files to the target system:

- **MpExtMs.exe** — A legitimate Microsoft Defender/endpoint security binary used as the sideloading host
- **version.dll** — The malicious loader DLL (SHA256: `59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712`)
- **EndpointDlp.dll** — The Mistic backdoor payload itself

The loader `version.dll` hooks two critical Windows API functions: `GetModuleFileNameW` and `LoadLibraryW`. These hooks redirect the legitimate binary's DLL loading behavior to ensure the malicious `EndpointDlp.dll` is loaded instead of legitimate Microsoft endpoint security components. The DLL names are chosen to blend with Microsoft endpoint security tooling.

### 2. Mistic Backdoor — In-Memory Execution

Once loaded, Mistic operates entirely in memory. Key capabilities include:

- **File operations**: Upload, download, move, rename, delete files, and create folders
- **In-memory code execution**: Execute code received from C2 directly in memory without writing to disk
- **Beacon Object File (BOF) loading**: Load C language programs directly in memory for expanded capability
- **C2 polling frequency adjustment**: Modify the check-in interval dynamically
- **Credential theft**: Deploy a separate .NET DLL (f.dll) that displays a fake Windows login screen
- **Privilege escalation**: Use a dedicated module (n.dll) for privilege elevation
- **Kill switch**: Self-terminate and delete all deployed files from the target system

Approximately 95% of Mistic's code consists of junk mathematical operations inserted purely to confuse automated analysis tools and sandbox environments.

### 3. C2 Infrastructure

Mistic communicates with its command-and-control infrastructure over TLS on port 443 using a custom binary protocol. Key C2 characteristics:

- **URI pattern**: `/api/v1/telemetry`
- **User-Agent**: `Microsoft-Delivery-Optimization/10.1` — designed to mimic legitimate Windows Update/Delivery Optimization traffic
- **Encryption**: AES-256-GCM session keys derived via ECDH key exchange on NIST P-256
- **Protocol**: Custom binary protocol over HTTPS, each session using its own key exchange

This makes C2 traffic appear as routine Windows telemetry to SIEMs and network monitoring tools — standard HTTPS on port 443 that looks like Windows Update traffic.

### 4. Platform-Specific Behavior

#### Windows

Mistic is a Windows-only threat. The DLL sideloading chain (MpExtMs.exe -> version.dll -> EndpointDlp.dll) is specific to Windows. The backdoor has also been delivered as MSI packages (aeff97fe.msi, 48b47c0.msi).

#### ModeloRAT (Cross-Campaign, Python-Based)

ModeloRAT is a separate Python-based RAT deployed by KongTuke in related campaigns. It is typically delivered as part of a portable WinPython package and executed via a signed `pythonw.exe` interpreter, using RC4-encrypted C2 communications with multiple failover paths.

### 5. Anti-Forensics / Evasion Techniques

- **In-memory execution**: No malicious files written to disk during operation
- **Kill switch / self-destruct**: Terminates and deletes all components (MpExtMs.exe, version.dll, EndpointDlp.dll) from the target
- **DLL sideloading via legitimate Microsoft binary**: Abuses trusted, signed Windows executables to bypass security controls
- **Microsoft endpoint security DLL naming**: EndpointDlp.dll mimics legitimate Microsoft Defender DLP components
- **Spoofed User-Agent**: C2 traffic uses Microsoft-Delivery-Optimization/10.1 to blend with legitimate Windows traffic
- **Code bloat / junk code**: ~95% of binary consists of meaningless mathematical operations to defeat automated analysis
- **ECDH per-session key exchange**: Each C2 session uses unique encryption keys, making traffic decryption and pattern matching difficult

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| MpExtMs.exe | Legitimate (abused) | Microsoft endpoint security binary used as DLL sideloading host |
| version.dll | Malicious loader | Hooks GetModuleFileNameW and LoadLibraryW to redirect DLL loading |
| EndpointDlp.dll | Backdoor.Mistic payload | In-memory backdoor with C2, file ops, BOF loading, and kill switch |
| f.dll | Credential stealer | .NET DLL displaying fake Windows login screen |
| n.dll | Privilege escalation | Privilege escalation component |
| aeff97fe.msi | MSI package | Mistic delivery via Windows Installer package |
| 48b47c0.msi | MSI package | Mistic delivery via Windows Installer package |

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | EndpointDlp.dll | 1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984 | Backdoor.Mistic payload |
| Windows | EndpointDlp.dll | afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c | Backdoor.Mistic payload (variant) |
| Windows | EndpointDlp.dll | db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5 | Backdoor.Mistic payload (variant) |
| Windows | EndpointDlp.dll | fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a | Backdoor.Mistic payload (variant) |
| Windows | version.dll | 59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712 | Mistic loader (hooks API functions) |
| Windows | f.dll | 34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc | Fake login screen credential stealer |
| Windows | n.dll | 8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235 | Privilege escalation module |
| Windows | aeff97fe.msi | 3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be | MSI delivery package |
| Windows | 48b47c0.msi | f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e | MSI delivery package |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 142[.]93[.]242[.]144 | C2 infrastructure |
| IP | 144[.]31[.]53[.]78 | C2 infrastructure |
| IP | 198[.]13[.]159[.]44 | C2 infrastructure |
| IP | 199[.]91[.]221[.]42 | C2 infrastructure |
| Domain | authorized-logins[.]net | C2 domain |
| Domain | b6w9m2z5x8q1v3k[.]top | C2 domain |
| Domain | carrolc[.]com | C2 domain |
| Domain | cj06y9v4xab[.]com | C2 domain |
| Domain | cwrtwright[.]com | C2 domain |
| Domain | defs[.]updater-worelos[.]com | C2 subdomain |
| Domain | ftps[.]upd-domain-goloro[.]com | C2 subdomain |
| Domain | grande-luna[.]top | C2 domain |
| Domain | human-check[.]top | C2 domain |
| Domain | mail[.]authorized-logins[.]net | C2 subdomain |
| Domain | mailes[.]upd-domain-goloro[.]com | C2 subdomain |
| Domain | mails[.]updater-worelos[.]com | C2 subdomain |
| Domain | mueleer[.]com | C2 domain |
| Domain | nano[.]upscale-kolo[.]com | C2 subdomain |
| Domain | oeannon[.]com | C2 domain |
| Domain | php[.]authorized-logins[.]net | C2 subdomain |
| Domain | rotoa-upda-lo[.]com | C2 domain |
| Domain | sql-updater-service[.]com | C2 domain |
| Domain | sss[.]authorized-logins[.]net | C2 subdomain |
| Domain | thomphon[.]com | C2 domain / staging |
| Domain | upd-domain-goloro[.]com | C2 domain |
| Domain | update[.]update-fall[.]com | C2 subdomain |
| Domain | updater-worelos[.]com | C2 domain |
| Domain | upscale-kolo[.]com | C2 domain |
| Domain | w3xasv14culvnqj[.]top | C2 domain |
| URL | hxxp://thomphon[.]com/update[.]msi | MSI payload delivery URL |
| User-Agent | Microsoft-Delivery-Optimization/10.1 | Spoofed UA for C2 traffic |
| URI Pattern | /api/v1/telemetry | C2 beacon check-in endpoint |

### Behavioral

- MpExtMs.exe loading EndpointDlp.dll or version.dll from non-standard directories (outside Windows Defender / Microsoft Security Client paths)
- version.dll hooking GetModuleFileNameW and LoadLibraryW API calls
- Processes communicating on port 443 with Microsoft-Delivery-Optimization user-agent to non-Microsoft IP addresses/domains
- In-memory code execution with no corresponding file writes to disk
- Self-deletion of MpExtMs.exe, version.dll, and EndpointDlp.dll from the same directory
- Run-key persistence entries named after remote-support tools (AnyDesk, Splashtop, Comms) — associated with ModeloRAT
- Startup-folder shortcuts, VBScript launchers, and scheduled tasks for persistence (ModeloRAT)
- WinPython / signed pythonw.exe running unknown scripts (ModeloRAT indicator)
- Use of living-off-the-land binaries: Curl, Reg.exe, Net.exe, PowerShell, Certutil, WMIC for reconnaissance and lateral movement

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised WordPress sites with TDS redirect victims to ClickFix/CrashFix pages |
| T1566.003 | Phishing: Spearphishing via Service | Microsoft Teams fake IT support messages delivering ModeloRAT |
| T1204.002 | User Execution: Malicious File | Victims run malicious commands/files from ClickFix social engineering |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Multi-stage PowerShell chain downloads malware payload |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | MpExtMs.exe sideloads malicious version.dll and EndpointDlp.dll |
| T1055 | Process Injection | In-memory code execution and BOF loading via injected DLL |
| T1620 | Reflective Code Loading | Beacon Object Files (BOFs) loaded directly in memory |
| T1140 | Deobfuscate/Decode Files or Information | Payload deobfuscation during multi-stage loading |
| T1036.005 | Masquerading: Match Legitimate Name or Location | EndpointDlp.dll and version.dll named to match Microsoft components |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over HTTPS/443 with spoofed Microsoft-Delivery-Optimization UA |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encrypted C2 with ECDH key exchange |
| T1056.002 | Input Capture: GUI Input Capture | Fake login screen (f.dll) for credential theft |
| T1070.004 | Indicator Removal: File Deletion | Kill switch self-deletes all backdoor components |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | ModeloRAT persistence via Run keys masquerading as remote-access tools |
| T1053.005 | Scheduled Task/Job: Scheduled Task | ModeloRAT scheduled task persistence |
| T1082 | System Information Discovery | Net.exe and Reg.exe used for network and system reconnaissance |
| T1105 | Ingress Tool Transfer | Certutil and Curl used to download additional payloads |

## Impact Assessment

Mistic represents a significant threat due to the combination of in-memory execution, self-destruct capability, and its link to an IAB supplying access to six major ransomware operations. The use of legitimate Microsoft binaries for DLL sideloading, combined with C2 traffic designed to mimic Windows Update telemetry, makes detection challenging with traditional file-based and network-based controls. Organizations in the insurance, education, IT, and professional services sectors are at elevated risk. The opportunistic targeting approach and ransomware-as-a-service delivery model means any organization could be impacted once initial access is established.

## Detection & Remediation

### Immediate Detection

```
# Check for MpExtMs.exe running from non-standard locations
Get-Process | Where-Object {$_.Path -like "*MpExtMs.exe" -and $_.Path -notlike "C:\Program Files\Windows Defender\*" -and $_.Path -notlike "C:\ProgramData\Microsoft\Windows Defender\*"}

# Check for EndpointDlp.dll or version.dll in unexpected locations
Get-ChildItem -Path C:\ -Recurse -Include EndpointDlp.dll,version.dll -ErrorAction SilentlyContinue | Where-Object {$_.DirectoryName -notlike "*Windows Defender*" -and $_.DirectoryName -notlike "*WinSxS*" -and $_.DirectoryName -notlike "*System32*"}

# Check for known C2 connections
Get-NetTCPConnection -RemotePort 443 | Where-Object {$_.RemoteAddress -in @('142.93.242.144','144.31.53.78','198.13.159.44','199.91.221.42')}

# Check for known malicious hashes
Get-FileHash -Algorithm SHA256 -Path (Get-ChildItem -Path C:\ -Recurse -Include *.dll,*.msi -ErrorAction SilentlyContinue).FullName 2>$null | Where-Object {$_.Hash -in @('1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984','59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712','afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c','db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5','fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a')}

# Check for Run-key persistence masquerading as remote-access tools
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Where-Object {$_.PSObject.Properties.Name -match "AnyDesk|Splashtop|Comms"}
```

### Remediation

1. **Containment**: Isolate affected endpoints immediately. Block the four known C2 IPs and all listed domains at the perimeter firewall and DNS resolver.
2. **Eradication**: Since Mistic operates in memory and self-destructs, focus on memory forensics. Kill any MpExtMs.exe processes running from non-standard paths. Remove any residual files (version.dll, EndpointDlp.dll, f.dll, n.dll) from non-standard directories.
3. **Recovery**: Re-image affected systems if full compromise scope is unclear. Reset all credentials that may have been exposed via the fake login screen (f.dll).
4. **Credential rotation**: Assume any credentials entered on affected endpoints may be compromised. Rotate all domain and local credentials.
5. **Hunt for ModeloRAT**: Check for WinPython installations, pythonw.exe in unexpected locations, and Run-key persistence entries named after AnyDesk/Splashtop/Comms.

### Long-Term Hardening

- Deploy EDR with in-memory scanning capability; traditional file-based AV will not detect Mistic
- Monitor for DLL sideloading via application control policies (e.g., WDAC/AppLocker)
- Block or alert on MpExtMs.exe execution outside of official Windows Defender directories
- Implement network monitoring for Microsoft-Delivery-Optimization user-agent strings from processes/hosts that should not generate them
- Train staff on ClickFix/CrashFix social engineering tactics
- Monitor for anomalous Microsoft Teams IT support messages
- Block execution of unsigned DLLs in user-writable directories

## Detection Rules

These detections target the Mistic backdoor DLL sideloading chain, C2 communication patterns, self-destruct behavior, and known C2 infrastructure. PoC/advisory-specific altitude; all rules compile and convert cleanly. Note: compiles != fires -- verify in your pipeline with representative telemetry before production deployment.

### Sigma: Mistic Backdoor DLL Sideloading via MpExtMs.exe

Detects MpExtMs.exe loading EndpointDlp.dll or version.dll from a non-standard directory, the distinctive sideloading chain used by the Mistic backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (network error fetching MITRE STIX data, not a rule issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma convert -p splunk_windows -t splunk exit 0. All field names standard Sysmon image_load (Image, ImageLoaded). No defanged values in detection. -->
```yaml
title: Mistic Backdoor DLL Sideloading via MpExtMs.exe
id: 7c3a1e8f-4b2d-4f9a-8e6c-1d5a0f3b7e9d
status: experimental
description: >
    Detects the Mistic backdoor DLL sideloading chain where MpExtMs.exe loads
    a malicious version.dll or EndpointDlp.dll from a non-standard directory,
    consistent with Woodgnat/KongTuke initial access broker activity.
references:
    - https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
    - https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1574.002
    - attack.t1036.005
logsource:
    category: image_load
    product: windows
detection:
    selection_parent:
        Image|endswith: '\MpExtMs.exe'
    selection_dll:
        ImageLoaded|endswith:
            - '\EndpointDlp.dll'
            - '\version.dll'
    filter_legitimate_path:
        ImageLoaded|startswith:
            - 'C:\Program Files\Windows Defender\'
            - 'C:\Program Files\Microsoft Security Client\'
            - 'C:\ProgramData\Microsoft\Windows Defender\'
    condition: selection_parent and selection_dll and not filter_legitimate_path
falsepositives:
    - Legitimate Microsoft Defender DLP module loading from standard directories
level: high
```

### Sigma: Mistic Backdoor C2 via MpExtMs.exe Network Connection

Detects MpExtMs.exe initiating outbound connections on port 443 to non-Microsoft hosts, consistent with Mistic's C2 over HTTPS with a spoofed Delivery Optimization user-agent.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0; -p splunk_windows exit 0. Sysmon EID 3 fields (Image, DestinationPort, Initiated, DestinationHostname). Filter excludes known-good Microsoft domains. -->
```yaml
title: Mistic Backdoor C2 Communication with Spoofed Delivery Optimization User-Agent
id: 2f8b5d1a-9c4e-4a7f-b3d6-8e0c2f1a5b9d
status: experimental
description: >
    Detects network connections from MpExtMs.exe to external hosts on port 443,
    consistent with Mistic backdoor C2 using a Microsoft-Delivery-Optimization
    user-agent string to blend with legitimate Windows traffic.
references:
    - https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
    - https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1071.001
    - attack.t1036.005
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\MpExtMs.exe'
        DestinationPort: 443
        Initiated: 'true'
    filter_microsoft:
        DestinationHostname|endswith:
            - '.microsoft.com'
            - '.windowsupdate.com'
            - '.windows.net'
    condition: selection and not filter_microsoft
falsepositives:
    - Legitimate MpExtMs.exe communicating with Microsoft endpoints
level: high
```

### Sigma: Mistic Backdoor Self-Destruct File Deletion

Detects MpExtMs.exe deleting its own DLL components (EndpointDlp.dll, version.dll), consistent with Mistic's kill switch self-destruct behavior.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0; -p splunk_windows exit 0. Sysmon EID 23/26 fields (Image, TargetFilename). High confidence: self-deletion of endpoint security DLLs by the sideloading host is highly anomalous. -->
```yaml
title: Mistic Backdoor Self-Destruct File Deletion
id: a4e9c7b2-3f1d-4e8a-9b5c-6d0a2f7e1c3b
status: experimental
description: >
    Detects MpExtMs.exe or associated loader deleting its own DLL components,
    consistent with Mistic backdoor kill switch / self-destruct behavior.
references:
    - https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
    - https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html
author: Actioner
date: 2026/06/28
tags:
    - attack.t1070.004
logsource:
    category: file_delete
    product: windows
detection:
    selection_process:
        Image|endswith: '\MpExtMs.exe'
    selection_file:
        TargetFilename|endswith:
            - '\EndpointDlp.dll'
            - '\version.dll'
            - '\MpExtMs.exe'
    condition: selection_process and selection_file
falsepositives:
    - Legitimate Microsoft Defender self-update removing old components
level: high
```

### Snort: Mistic Backdoor C2 Spoofed User-Agent and Telemetry URI

Detects outbound HTTP with the campaign's known Microsoft-Delivery-Optimization/10.1 user-agent and /api/v1/telemetry C2 endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R m.rules -T exit 0 (Snort 2.9.20). Two rules: SID 2100010 matches UA alone; SID 2100011 matches URI+UA combination for higher fidelity. UA string is highly distinctive (version-pinned spoofed Microsoft string). -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mistic Backdoor C2 Spoofed Delivery Optimization User-Agent"; flow:established,to_server; content:"Microsoft-Delivery-Optimization/10.1"; http_header; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; sid:2100010; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mistic Backdoor C2 Telemetry URI Pattern"; flow:established,to_server; content:"/api/v1/telemetry"; http_uri; fast_pattern; content:"Microsoft-Delivery-Optimization"; http_header; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; sid:2100011; rev:1;)
```

### Suricata: Mistic C2 User-Agent, Telemetry URI, and Known C2 Domains

Detects Mistic C2 traffic via spoofed Microsoft-Delivery-Optimization user-agent, the /api/v1/telemetry endpoint, and DNS queries to known C2 domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S mistic-c2-suricata.rules -l /tmp/actioner exit 0 (Suricata 7.0.3). Six rules: SID 2200010 UA match, SID 2200011 URI+UA, SIDs 2200012-2200015 known C2 domain DNS queries. Dot-notation buffers verified (http.user_agent, http.uri, dns.query). -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mistic Backdoor C2 Spoofed Delivery Optimization User-Agent"; flow:established,to_server; http.user_agent; content:"Microsoft-Delivery-Optimization/10.1"; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200010; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Mistic Backdoor C2 Telemetry URI with Spoofed UA"; flow:established,to_server; http.uri; content:"/api/v1/telemetry"; fast_pattern; http.user_agent; content:"Microsoft-Delivery-Optimization"; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200011; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Mistic C2 Domain authorized-logins.net"; flow:to_server; dns.query; content:"authorized-logins.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200012; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Mistic C2 Domain updater-worelos.com"; flow:to_server; dns.query; content:"updater-worelos.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200013; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Mistic C2 Domain upd-domain-goloro.com"; flow:to_server; dns.query; content:"upd-domain-goloro.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200014; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Mistic C2 Domain sql-updater-service.com"; flow:to_server; dns.query; content:"sql-updater-service.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.security.com/threat-intelligence/new-mistic-backdoor-modelorat; metadata:author Actioner, created_at 2026-06-28; sid:2200015; rev:1;)
```

### YARA: Mistic Backdoor Loader and Payload

Detects the Mistic loader DLL (version.dll) by API hook targets and sideloading filename references, and the Mistic payload (EndpointDlp.dll) by its C2 user-agent string, telemetry URI, and memory allocation API imports.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac /tmp/actioner/mistic-loader.yar /dev/null exit 0. Two rules: Malware_Mistic_Backdoor_Loader keys on hook targets + sideload filenames; Malware_Mistic_Backdoor_Payload keys on UA + telemetry URI + API imports. No sample available for fired test (PE header gate prevents text-file matching, which is correct). Medium confidence: string-based detection on PE files without a confirmed sample to test against; the published hash provides provenance but we cannot verify in this environment. -->
```yara
import "pe"

rule Malware_Mistic_Backdoor_Loader
{
    meta:
        description = "Detects Mistic backdoor loader (version.dll) that hooks GetModuleFileNameW and LoadLibraryW to sideload EndpointDlp.dll via MpExtMs.exe"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash = "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712"
        severity = "high"

    strings:
        $hook1 = "GetModuleFileNameW" ascii fullword
        $hook2 = "LoadLibraryW" ascii fullword
        $target1 = "EndpointDlp.dll" ascii wide nocase
        $target2 = "MpExtMs" ascii wide nocase
        $target3 = "version.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        pe.is_pe and
        all of ($hook*) and
        2 of ($target*)
}

rule Malware_Mistic_Backdoor_Payload
{
    meta:
        description = "Detects Mistic backdoor payload (EndpointDlp.dll) with in-memory execution and kill switch capabilities"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash = "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984"
        severity = "high"

    strings:
        $name1 = "EndpointDlp" ascii wide
        $ua = "Microsoft-Delivery-Optimization" ascii wide
        $path = "/api/v1/telemetry" ascii wide
        $api1 = "VirtualAlloc" ascii fullword
        $api2 = "VirtualProtect" ascii fullword
        $api3 = "CreateThread" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        pe.is_pe and
        $name1 and
        ($ua or $path) and
        2 of ($api*)
}
```

## Lessons Learned

1. **In-memory execution and self-destruct defeat file-based detection**: Mistic's design specifically targets the gap between file-based AV/EDR and memory-resident threats. Organizations relying solely on file scanning will miss this backdoor entirely.

2. **DLL sideloading via legitimate signed binaries remains highly effective**: Using Microsoft's own endpoint security binaries (MpExtMs.exe) as sideloading hosts is a sophisticated trust-abuse technique that can bypass application whitelisting and code signing requirements.

3. **C2 traffic mimicking legitimate services is increasingly common**: The use of Microsoft-Delivery-Optimization user-agents and telemetry-style URIs over standard HTTPS demonstrates that adversaries are deliberately designing C2 to blend with enterprise traffic. Network monitoring must move beyond domain/IP blocklists to behavioral analysis of traffic patterns.

4. **Initial access brokers are a force multiplier**: KongTuke's business model of establishing persistent footholds and selling them to multiple ransomware crews means a single compromise can result in attacks from any of six major ransomware families. Detecting and disrupting the IAB's access is far more impactful than responding to each ransomware deployment individually.

## Sources

- [Broadcom/Symantec Security Bulletin: Backdoor.Mistic](https://www.broadcom.com/support/security-center/protection-bulletin/backdoor-mistic-new-backdoor-may-be-linked-to-ransomware-access-broker) -- primary advisory announcing Mistic and linking to Woodgnat/KongTuke
- [Symantec/Broadcom Detailed Technical Analysis (SECURITY.COM)](https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat) -- primary source for IOCs (hashes, C2 domains/IPs), DLL sideloading chain, and ModeloRAT details
- [The Hacker News: New Mistic Backdoor Linked to KongTuke](https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html) -- summary of Mistic capabilities, attack timeline, and KongTuke attribution
- [Hackread: Woodgnat Hackers Use Mistic RAT](https://hackread.com/woodgnat-hackers-mistic-rat-access-ransomware-gangs/) -- overview of Woodgnat/KongTuke operations and ransomware connections
- [BleepingComputer: Stealthy Mistic Backdoor Linked to KongTuke](https://www.bleepingcomputer.com/news/security/stealthy-mistic-backdoor-linked-to-ransomware-access-broker-kongtuke/) -- supplementary reporting on capabilities and sector targeting
- [Cryptika Cybersecurity: Mistic Backdoor Blends With Microsoft Endpoint Security Tooling](https://www.cryptika.com/mistic-backdoor-blends-with-microsoft-endpoint-security-tooling-to-evade-detection/) -- DLL sideloading chain details and credential theft component
- [Help Net Security: Stealthy New Backdoor Surfaces](https://www.helpnetsecurity.com/2026/06/25/mistic-backdoor-woodgnat-attacks/) -- supplementary reporting on capabilities
- [CSO Online: Mistic Backdoor Used by Ransomware Broker](https://www.csoonline.com/article/4189132/be-on-the-lookout-for-mistic-a-new-backdoor-used-by-ransomware-broker.html) -- C2 communication details (UA string, URI, encryption)

---
*Report generated by Actioner*
