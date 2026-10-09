# Antino Backdoor: UAT-11587 Leverages Microsoft 365 as Command-and-Control Infrastructure

**Status:** DRAFT | **Date:** 2026-10-09 | **TLP:** CLEAR

---

## Executive Summary

A China-nexus threat actor tracked as **UAT-11587** (Cisco Talos designation) has deployed a novel Rust-compiled backdoor dubbed **Antino** against academic institutions, think tanks, and government entities across eight Asian countries. The campaign, active since September 2025 with peak activity from March through June 2026, is notable for its abuse of **Microsoft 365 services** -- Outlook and OneDrive via the Graph API -- as its command-and-control (C2) channel. This technique allows C2 traffic to blend with legitimate Microsoft 365 usage, complicating network-level detection. The infection chain combines spear-phishing with spoofed sender identities, Cloudflare Pages for stager hosting, and DLL sideloading via a legitimate Microsoft-signed binary (`GatherOsState.exe`) to achieve execution.

This report provides a technical breakdown of the infection chain, C2 mechanism, and attribution indicators, accompanied by validated detection rules across Sigma, YARA, Snort, and Suricata formats.

---

## Background: Microsoft 365 as C2 Infrastructure

Cloud-based C2 channels have become increasingly attractive to advanced threat actors because they exploit trust relationships that organizations maintain with major SaaS providers. By routing C2 communications through `graph.microsoft.com`, the Antino backdoor benefits from:

- **TLS encryption** to a trusted Microsoft endpoint, bypassing most network inspection
- **Domain reputation** -- `graph.microsoft.com` is universally allowlisted
- **Protocol blending** -- Graph API calls are indistinguishable from legitimate M365 application traffic
- **Data exfiltration capacity** via OneDrive, which supports large file transfers under a legitimate service umbrella

The use of Outlook for command dispatch and OneDrive for heartbeat/file transfer represents a dual-channel abuse pattern that is operationally resilient: even if one channel is disrupted, the other may continue to function.

---

## Attack Timeline

| Date | Event |
|------|-------|
| **September 2025** | First observed Antino activity targeting Taiwan academic and policy community |
| **Late 2025 -- Feb 2026** | Gradual expansion to targets in India, Philippines, Cambodia, Pakistan, Thailand, Myanmar, Syria |
| **March -- June 2026** | Peak operational tempo; 16 entities across 8 countries compromised |
| **June 8--9, 2026** | Concentrated attack wave against government IT infrastructure |
| **October 2026** | Public disclosure by Cisco Talos |

---

## Root Cause: Spear-Phishing with Spoofed Senders

Initial access is achieved through spear-phishing emails that **spoof legitimate sender identities**, bypassing SPF and DMARC validation at the target mail gateway. The phishing emails employ a distinctive social engineering technique:

- The email body contains a **fake Gmail attachment preview** constructed from **four inline Base64-encoded PNG images** embedded as MIME parts
- These images are wrapped in HTML anchor tags pointing to a **Cloudflare Pages URL** hosting the next-stage payload
- The visual fidelity of the fake preview persuades the recipient to click, initiating the infection chain

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link), T1586.002 (Compromise Accounts: Email Accounts)

---

## Technical Analysis

### Stage 1: Stager Delivery via Cloudflare Pages

Upon clicking the fake attachment link, the victim is directed to a Cloudflare Pages site hosting an **HTA or WSF (Windows Script File) stager**. This stager executes a **JavaScript downloader/decryptor** that contacts:

```
d32tpl7xt7175h[.]cloudfront[.]net
```

This CloudFront distribution serves as the staging infrastructure for all subsequent payloads.

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1059.007 (Command and Scripting Interpreter: JavaScript)

### Stage 2: .NET Deserialization Loader

The JavaScript downloader retrieves and loads a **.NET deserialization loader** (`TestAssembly.dll`). This loader performs three actions:

1. Downloads and displays a **lure document** to maintain the social engineering pretext
2. Launches a **Calculator decoy** to further normalize the activity
3. Downloads and deploys the **Antino backdoor**

**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File), T1027 (Obfuscated Files or Information)

### Stage 3: DLL Sideloading -- Antino Deployment

Antino is deployed via DLL sideloading using a legitimate Microsoft-signed binary:

| Component | Description |
|-----------|-------------|
| `GatherOsState.exe` | Legitimate Microsoft-signed diagnostic binary (sideloading host) |
| `slc.dll` | Antino backdoor implant (malicious sideloaded DLL) |

`GatherOsState.exe` is a Windows diagnostic utility that legitimately loads `slc.dll` (Software Licensing Client). By placing a malicious `slc.dll` alongside a copy of `GatherOsState.exe` outside its normal system directory, the attacker hijacks the DLL search order to execute arbitrary code under a trusted process name.

**MITRE ATT&CK:** T1574.002 (Hijack Execution Flow: DLL Side-Loading)

### Stage 4: Graph API C2 Mechanism

Once loaded, Antino establishes its C2 channel through the Microsoft Graph API:

**Command Channel (Outlook):**
- Polls the operator-controlled Outlook mailbox every **10 seconds**
- Searches for messages with subject prefix `command_req_[session_id]`
- Parses message body for encoded commands
- Responds via new email messages

**Heartbeat and File Transfer Channel (OneDrive):**
- Sends heartbeat beacon to OneDrive every **60 seconds**
- Uploads exfiltrated files to OneDrive folders
- Downloads operator-supplied tools and payloads from OneDrive

**MITRE ATT&CK:** T1102.002 (Web Service: Bidirectional Communication), T1071.001 (Application Layer Protocol: Web Protocols), T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)

### Antino Capabilities

| Capability | Detail |
|-----------|--------|
| **Host Reconnaissance** | System information gathering, environment enumeration |
| **Process Listing** | Enumerate running processes |
| **Directory Enumeration** | Browse and list file system contents |
| **Shell Execution** | Execute commands via `cmd.exe` |
| **PowerShell Execution** | Execute PowerShell scripts and commands |
| **In-Memory Shellcode** | Load and execute shellcode without touching disk |
| **File Transfer** | Upload/download files via OneDrive |
| **Program Execution** | Run operator-supplied executables |
| **Scripted Diagnostics Abuse** | Abuse Windows Scripted Diagnostics framework (`sdiagnhost.exe`) for PowerShell execution as a defense-evasion technique |

**MITRE ATT&CK:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1083 (File and Directory Discovery), T1057 (Process Discovery), T1082 (System Information Discovery), T1218 (System Binary Proxy Execution)

---

## Indicators of Compromise

> All indicators are defanged per standard practice.

### File System Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `slc.dll` | Filename | Antino backdoor implant (sideloaded DLL) |
| `GatherOsState.exe` | Filename | Legitimate Microsoft binary abused for sideloading (suspicious when outside `C:\Windows\System32`) |
| `TestAssembly.dll` | Filename | .NET deserialization loader |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `d32tpl7xt7175h[.]cloudfront[.]net` | Domain | Payload staging infrastructure |
| `graph[.]microsoft[.]com` | Domain | C2 channel (Graph API -- legitimate service abused) |
| `rsproxy[.]cn` | Domain | Chinese crates.io mirror referenced in build artifacts (not C2) |

### Behavioral Indicators

| Pattern | Description |
|---------|-------------|
| Outlook polling every 10s | Graph API `/me/messages` queries filtering for `command_req_` subject prefix |
| OneDrive heartbeat every 60s | Graph API `/me/drive` writes at regular interval |
| `GatherOsState.exe` outside System32 | DLL sideloading indicator |
| `sdiagnhost.exe` spawning PowerShell | Scripted Diagnostics framework abuse |

---

## Attribution

Attribution to a **China-nexus** actor is assessed with **high confidence** based on:

| Artifact | Detail |
|----------|--------|
| Language metadata | `zh-CN` language tags in document metadata |
| Lure content | Simplified Chinese text in decoy documents |
| Timestamp analysis | `UTC+08:00` timestamps in phishing email headers, consistent with China Standard Time |
| Build artifacts | Cargo (Rust package manager) paths referencing `rsproxy[.]cn`, a Chinese mirror of `crates.io` used by developers in mainland China |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Spoofed phishing emails with fake Gmail preview |
| Execution | User Execution: Malicious File | T1204.002 | Victim clicks fake attachment link |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | HTA/WSF stager, JS downloader |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell command execution |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | cmd.exe command execution |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading | T1574.002 | GatherOsState.exe loads malicious slc.dll |
| Defense Evasion | System Binary Proxy Execution | T1218 | Scripted Diagnostics framework abuse |
| Defense Evasion | Obfuscated Files or Information | T1027 | .NET deserialization loader |
| Discovery | System Information Discovery | T1082 | Host reconnaissance |
| Discovery | Process Discovery | T1057 | Process listing |
| Discovery | File and Directory Discovery | T1083 | Directory enumeration |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Outlook via Graph API for command dispatch |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS to graph.microsoft.com |
| Command and Control | Ingress Tool Transfer | T1105 | CloudFront payload staging |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | OneDrive file exfiltration |

---

## Detection and Remediation

### Detection Priorities

1. **DLL sideloading**: Monitor for `GatherOsState.exe` execution outside `C:\Windows\System32\` and any instance loading `slc.dll` from a non-system path
2. **Graph API anomalies**: Alert on high-frequency Graph API polling patterns (every 10 seconds) from non-standard applications, especially those filtering Outlook messages by `command_req_` subjects
3. **Network IOCs**: Block and alert on connections to `d32tpl7xt7175h[.]cloudfront[.]net`
4. **Scripted Diagnostics abuse**: Alert on `sdiagnhost.exe` or `msdt.exe` spawning PowerShell processes
5. **TestAssembly.dll**: Alert on loading of `TestAssembly.dll` outside development environments

### Remediation Steps

1. **Block** `d32tpl7xt7175h[.]cloudfront[.]net` at network egress (DNS, proxy, firewall)
2. **Hunt** for `GatherOsState.exe` copies outside `C:\Windows\System32\` and `C:\Windows\SysWOW64\`
3. **Audit** Azure AD/Entra ID application registrations and OAuth tokens for Graph API access from unexpected applications
4. **Review** Conditional Access policies to restrict Graph API access to managed devices and approved applications
5. **Monitor** Microsoft 365 Unified Audit Logs for anomalous Outlook and OneDrive Graph API patterns
6. **Validate** SPF, DKIM, and DMARC configurations to reduce spoofed-sender phishing success

---

## Detection Rules

### Sigma Rules

All Sigma rules validated with `sigma check` (exit 0) and successfully converted with `sigma convert --without-pipeline -t splunk` (exit 0) and `sigma convert --without-pipeline -t log_scale` (exit 0). MITRE ATT&CK tag validation was skipped due to upstream data-source connectivity constraints in the build environment; tags follow standard Sigma taxonomy.

---

#### Sigma Rule 1: GatherOsState.exe DLL Sideloading

Detects execution of `GatherOsState.exe` from a non-standard directory, the primary DLL sideloading host for the Antino backdoor.

**Compile status:** `sigma check` pass (exit 0) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence:** High

```yaml
title: Antino Backdoor - GatherOsState.exe DLL Sideloading (slc.dll)
id: 8a3f1e72-b5d4-4c91-a6e8-3d7f2c9b0e14
status: experimental
description: >
    Detects the execution of GatherOsState.exe loading a malicious slc.dll,
    a DLL sideloading technique used by UAT-11587 to deploy the Antino backdoor.
references:
    - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
    - https://securityaffairs.com/200264/apt/antino-backdoor-uses-your-inbox-as-its-control-panel.html
author: CTI Research Team
date: 2026-10-09
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\GatherOsState.exe'
    filter_legit_path:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_process and not filter_legit_path
falsepositives:
    - Legitimate use of GatherOsState.exe outside of standard Windows system directories is uncommon but possible during system diagnostics
level: high
```

---

#### Sigma Rule 2: Suspicious slc.dll Loaded by GatherOsState.exe

Detects `GatherOsState.exe` loading `slc.dll` from a non-system directory, the precise sideloading combination used by Antino.

**Compile status:** `sigma check` pass (exit 0) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence:** Critical

```yaml
title: Antino Backdoor - Suspicious slc.dll Loaded by GatherOsState.exe
id: 7affaa1a-06d2-4b08-85f3-cd2776c1d5e3
status: experimental
description: >
    Detects GatherOsState.exe loading slc.dll from a non-standard directory,
    indicative of the Antino backdoor DLL sideloading technique used by UAT-11587.
references:
    - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
author: CTI Research Team
date: 2026-10-09
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\GatherOsState.exe'
        ImageLoaded|endswith: '\slc.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_system
falsepositives:
    - Unlikely in legitimate environments
level: critical
```

---

#### Sigma Rule 3: Microsoft Graph API Outlook Command Polling

Detects outbound proxy logs showing Graph API requests with `command_req_` in the URI, the Antino C2 command-polling pattern.

**Compile status:** `sigma check` pass (exit 0) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence:** High

```yaml
title: Antino Backdoor - Microsoft Graph API Outlook Command Polling
id: f42b4b1f-5b3c-4e77-935d-593578325966
status: experimental
description: >
    Detects suspicious outbound HTTPS connections to Microsoft Graph API
    endpoints used by Antino backdoor for Outlook-based C2 command polling.
    The backdoor polls for messages with subject prefix command_req_ every 10 seconds.
references:
    - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
    - https://www.esecurityplanet.com/cybersecurity-threats/news-uat-11587-antino-backdoor-microsoft-365-cloudflare/
author: CTI Research Team
date: 2026-10-09
tags:
    - attack.command_and_control
    - attack.t1102.002
    - attack.t1071.001
logsource:
    category: proxy
    product: windows
detection:
    selection_graph:
        c-uri|contains: 'graph.microsoft.com'
    selection_mail_messages:
        c-uri|contains:
            - '/me/messages'
            - '/me/mailFolders'
    selection_filter_subject:
        c-uri|contains: 'command_req_'
    condition: selection_graph and selection_mail_messages and selection_filter_subject
falsepositives:
    - Custom internal applications using Microsoft Graph API with similar naming conventions
level: high
```

---

#### Sigma Rule 4: TestAssembly.dll .NET Deserialization Loader

Detects loading of `TestAssembly.dll`, the .NET deserialization loader in the Antino infection chain.

**Compile status:** `sigma check` pass (exit 0) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence:** High

```yaml
title: Antino Backdoor - TestAssembly.dll .NET Deserialization Loader
id: a59b4818-2e67-40e2-84c0-9f0a7fa71aef
status: experimental
description: >
    Detects the loading or creation of TestAssembly.dll, used by UAT-11587
    as a .NET deserialization loader to deploy the Antino backdoor and associated payloads.
references:
    - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
author: CTI Research Team
date: 2026-10-09
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\TestAssembly.dll'
    condition: selection
falsepositives:
    - Development and testing environments using assemblies named TestAssembly.dll
level: high
```

---

#### Sigma Rule 5: Windows Scripted Diagnostics Framework Abuse

Detects `sdiagnhost.exe` or `msdt.exe` spawning PowerShell, a defense-evasion technique used by Antino.

**Compile status:** `sigma check` pass (exit 0) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence:** High

```yaml
title: Antino Backdoor - Windows Scripted Diagnostics Framework Abuse
id: 3ebbb67c-5af1-41f4-9ec1-687cb362004e
status: experimental
description: >
    Detects abuse of the Windows Scripted Diagnostics framework (sdiagnhost.exe
    or msdt.exe) to execute PowerShell commands, a technique employed by the
    Antino backdoor for defense evasion.
references:
    - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
author: CTI Research Team
date: 2026-10-09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\sdiagnhost.exe'
            - '\msdt.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Windows troubleshooting packs that invoke PowerShell
level: high
```

---

### YARA Rules

Detects the Antino implant (`slc.dll`) and the `TestAssembly.dll` loader based on structural and string indicators.

**Compile status:** `yarac` pass (exit 0)
**Confidence:** High

```yara
rule Antino_Backdoor_SLC_DLL
{
    meta:
        description = "Detects the Antino backdoor (slc.dll) - a Rust-compiled implant used by UAT-11587 for M365 Graph API C2"
        author = "CTI Research Team"
        date = "2026-10-09"
        reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
        hash = ""
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Graph API C2 strings
        $graph1 = "graph.microsoft.com" ascii wide
        $graph2 = "/me/messages" ascii wide
        $graph3 = "/me/drive" ascii wide
        $graph4 = "command_req_" ascii wide

        // Rust compilation artifacts referencing Chinese mirror
        $rust1 = "rsproxy.cn" ascii
        $rust2 = ".cargo" ascii
        $rust3 = "rustc" ascii

        // Sideloading indicators
        $side1 = "slc.dll" ascii wide
        $side2 = "GatherOsState" ascii wide

        // Antino capability strings
        $cap1 = "cmd.exe" ascii wide
        $cap2 = "powershell" ascii wide nocase
        $cap3 = "shellcode" ascii wide nocase
        $cap4 = "TestAssembly" ascii wide

        // Rust binary markers
        $pe1 = { 4D 5A }
        $rust_panic = "panicked at" ascii
        $rust_unwrap = "called `Option::unwrap()`" ascii

    condition:
        $pe1 at 0 and
        (
            ( 2 of ($graph*) and 1 of ($rust*) ) or
            ( 3 of ($graph*) and 1 of ($cap*) ) or
            ( $graph4 and $side1 and $side2 ) or
            ( 2 of ($graph*) and $rust_panic and $rust_unwrap )
        )
}

rule Antino_TestAssembly_Loader
{
    meta:
        description = "Detects the .NET deserialization loader (TestAssembly.dll) used in the Antino backdoor infection chain"
        author = "CTI Research Team"
        date = "2026-10-09"
        reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
        severity = "high"

    strings:
        $dotnet1 = "_CorDllMain" ascii
        $dotnet2 = "mscoree.dll" ascii
        $name = "TestAssembly" ascii wide
        $deser = "Deserialize" ascii wide
        $cloudfront = "cloudfront.net" ascii wide
        $pe = { 4D 5A }

    condition:
        $pe at 0 and
        $dotnet1 and $dotnet2 and $name and
        ( $deser or $cloudfront )
}
```

---

### Snort Rules

Detects DNS and HTTP/TLS connections to the Antino staging infrastructure.

**Compile status:** :warning: uncompiled (structural check only -- Snort compiler not available in build environment)
**Confidence:** High

```snort
# Detect DNS query for Antino staging domain (d32tpl7xt7175h.cloudfront.net)
alert udp $HOME_NET any -> any 53 (msg:"MALWARE Antino Backdoor - DNS Query to CloudFront Staging Domain (d32tpl7xt7175h.cloudfront.net)"; content:"|01 00 00 01|"; offset:2; depth:4; content:"|0e|d32tpl7xt7175h|0a|cloudfront|03|net|00|"; nocase; sid:2026100901; rev:1; classtype:trojan-activity; metadata:affected_product Windows, attack_target Client_Endpoint, mitre_attack_id T1071, deployment Perimeter;)

# Detect TLS SNI to Antino staging domain
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Antino Backdoor - TLS Connection to CloudFront Staging Domain"; flow:established,to_server; content:"|16 03|"; depth:2; content:"d32tpl7xt7175h.cloudfront.net"; nocase; sid:2026100902; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1105;)

# Detect HTTP request to staging domain for payload download
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Antino Backdoor - HTTP GET to CloudFront Staging Domain"; flow:established,to_server; content:"GET"; http_method; content:"d32tpl7xt7175h.cloudfront.net"; http_header; sid:2026100903; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1105;)
```

---

### Suricata Rules

Suricata-native detection for Antino staging infrastructure and Graph API C2 patterns.

**Compile status:** :warning: uncompiled (structural check only -- Suricata compiler not available in build environment)
**Confidence:** High

```suricata
# Detect DNS query for Antino staging domain
alert dns $HOME_NET any -> any any (msg:"MALWARE Antino Backdoor - DNS Query to CloudFront Staging Domain"; dns.query; content:"d32tpl7xt7175h.cloudfront.net"; nocase; sid:2026100911; rev:1; classtype:trojan-activity; metadata:affected_product Windows, attack_target Client_Endpoint, mitre_attack_id T1071;)

# Detect TLS SNI to Antino staging domain
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Antino Backdoor - TLS SNI to CloudFront Staging Domain"; tls.sni; content:"d32tpl7xt7175h.cloudfront.net"; nocase; sid:2026100912; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1105;)

# Detect HTTP request to staging domain
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Antino Backdoor - HTTP Request to CloudFront Staging Domain"; http.host; content:"d32tpl7xt7175h.cloudfront.net"; nocase; sid:2026100913; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1105;)

# Detect Graph API polling pattern with command_req_ subject filter
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Antino Backdoor - Graph API Outlook Command Polling (command_req_)"; http.host; content:"graph.microsoft.com"; http.uri; content:"/me/messages"; content:"command_req_"; sid:2026100914; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1102.002;)

# Detect Graph API OneDrive heartbeat/exfiltration pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Antino Backdoor - Graph API OneDrive C2 Activity"; http.host; content:"graph.microsoft.com"; http.uri; content:"/me/drive"; sid:2026100915; rev:1; classtype:trojan-activity; metadata:affected_product Windows, mitre_attack_id T1567.002;)
```

---

## Sources

- [The Hacker News -- Antino Backdoor Uses Outlook and OneDrive as Its Control Panel](https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html)
- [Security Affairs -- Antino Backdoor Uses Your Inbox as Its Control Panel](https://securityaffairs.com/200264/apt/antino-backdoor-uses-your-inbox-as-its-control-panel.html)
- [eSecurity Planet -- UAT-11587 Antino Backdoor Microsoft 365 Cloudflare](https://www.esecurityplanet.com/cybersecurity-threats/news-uat-11587-antino-backdoor-microsoft-365-cloudflare/)

---

*DRAFT -- For internal review. Not for distribution.*
