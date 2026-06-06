<!-- revision: v1.1 2026-06-06 — DROPPED 3 rules (ASP.NET temp DLL, Potato Suite cmdline, python-requests UA) for excessive FPs or infeasibility with reflective loading. FIXED DNS C2 to match apex domains; removed inbound-only IP 124.156.129.151 from C2 rule; aligned "C2 Infrastructure" title across YAML/prose; downgraded IIS child-process to medium (supporting indicator); tightened YARA ASHX condition (RC4 AND crypto, not OR) and downgraded to high; defanged IOCs in Immediate Detection section; corrected ATT&CK mappings (T1027.010→T1027, T1041 removed). -->
# Technical Analysis Report: OP-512 China-Linked IIS Web Shell Cluster (2026-06-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-06
Version: 1.1 (REVISED)

## Executive Summary

OP-512 is a newly identified China-linked threat cluster conducting espionage operations through custom web shell deployment on Microsoft IIS servers. Discovered by ReliaQuest's agentic AI platform, the cluster deploys a purpose-built framework of three web shells -- an ASPX file manager and two ASHX cryptographic command handlers -- against legacy IIS servers running end-of-life .NET Framework 4.0 on Windows Server 2016. The cluster is assessed with moderate-to-high confidence as a previously undocumented espionage operation distinct from known Chinese threat actors such as CL-STA-0048, DragonRank, and GhostRedirector.

OP-512 demonstrates notable operational sophistication: web shells are polymorphically generated per deployment with randomized variable and method names, cryptographic access controls (RSA signature verification + RC4 encryption), timestomping of deployed files to match surrounding directory timestamps, and a dual-channel C2 notification mechanism (DNS primary with HTTP fallback). Post-exploitation includes privilege escalation to SYSTEM via Potato suite tools loaded reflectively into memory, limiting forensic artifacts on disk.

## Background: Microsoft IIS and Legacy .NET Infrastructure

Microsoft Internet Information Services (IIS) is one of the most widely deployed web server platforms, particularly in enterprise environments running Windows Server. Legacy IIS installations running .NET Framework 4.0 on Windows Server 2016 are approaching or past end-of-life support, making them attractive targets due to reduced patching cadence and older security controls. IIS web shells -- particularly `.aspx` and `.ashx` handlers -- are a well-established persistence mechanism for threat actors targeting Windows web infrastructure, as the IIS worker process (`w3wp.exe`) provides a natural execution context that blends with legitimate web application behavior.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Day -75 (approx.) | Initial compromise of legacy IIS server running .NET Framework 4.0; DNS queries to `ashx[.]lhlsjcb[.]com` observed |
| Day 0 (T+0 seconds) | First `.aspx` file manager web shell deployed to application upload directory |
| Day 0 (T+seconds) | Self-reporting notification transmitted via DNS (primary) and HTTP (fallback) to attacker C2 |
| Day 0 (T+seconds) | Two `.ashx` cryptographic command handler web shells deployed |
| Day 0 (T+minutes) | EDR behavioral detection fires on reflective .NET assembly loading via `w3wp.exe` |
| Day 0 (T+minutes) | Endpoint prevention terminates malicious process; IIS auto-restarts worker process, bypassing containment |
| Day 0 (T+hours) | Potato suite privilege escalation tools loaded reflectively into memory; `whoami /priv` commands issued |
| Day 0 (T+19 hours) | Compiled DLL artifacts in ASP.NET temporary directory detected and quarantined |

## Root Cause: Exploitation of Legacy Internet-Facing IIS Server

Initial access was achieved through exploitation of a legacy internet-facing IIS server running Windows Server 2016 with end-of-life .NET Framework 4.0. The exact initial exploitation vector has not been confirmed, but the presence of DNS queries to attacker infrastructure approximately 75 days before the main web shell deployment suggests a prolonged reconnaissance or staging phase. The target's outdated software stack -- a common finding in enterprise environments with technical debt -- provided a lower-resistance attack surface.

## Technical Analysis of the Malicious Payload

### 1. Web Shell Framework Architecture

OP-512 deploys a coordinated three-component web shell framework, distinguished from commodity web shells by per-deployment polymorphic generation and cryptographic access controls.

**Component 1: ASPX File Manager**
The primary `.aspx` web shell provides a full file management interface with directory listing, file read/write, upload, download, delete, and rename operations. Critically, it includes a built-in timestomping function that scans the surrounding directory, calculates the median last-modified timestamp of adjacent files, and applies that timestamp to the web shell files -- making them appear to have existed since the directory was originally populated. The file manager also implements an automatic C2 notification mechanism: upon each page access (with a 5-minute cooldown to reduce noise), it transmits the web shell's URL location to attacker infrastructure via DNS query (primary) or HTTP request (fallback).

**Components 2-3: ASHX Command Handlers**
Two `.ashx` generic HTTP handlers serve as cryptographic command execution endpoints. Each handler embeds a unique RSA public key, enabling the operator to address commands to a specific handler. The command processing pipeline is:

```
HTTP POST --> Base64 Decode --> RC4 Decrypt --> RSA Signature Verify --> Execute Command
```

This multi-layer authentication ensures that even if the web shell endpoint is discovered, commands cannot be issued without possession of the corresponding RSA private key. Both handlers implement identical functionality but with completely different variable names, method names, and injected dead code (junk variables, comments), indicating automated polymorphic code generation at the framework level.

### 2. Defense Evasion Techniques

**Timestomping (T1070.006):** The ASPX file manager explicitly manipulates `CreationTime`, `LastWriteTime`, and `LastAccessTime` attributes of deployed web shell files. Rather than using a hardcoded date, it algorithmically calculates the median modification timestamp of files in the same directory, making the web shells temporally indistinguishable from legitimate application files.

**Polymorphic Code Generation (T1027):** Each deployment generates web shells with randomized identifier names. Example junk variable names observed: `_nkkspqwc`, `_nbgrzrak`, `rmluimqjmidu`. This defeats signature-based detection keyed on specific variable or function names.

**Reflective Assembly Loading:** Potato suite privilege escalation tools were loaded directly into memory via reflective .NET assembly loading through `w3wp.exe`, avoiding disk-based artifact creation and bypassing traditional file-based detection.

### 3. C2 Infrastructure

**DNS Tunneling (Primary Channel):** OP-512 uses hex-encoded DNS subdomain queries for C2 communication. The subdomain pattern follows the structure `a.<hex-encoded-data>.c.<domain>`, where the hex segment encodes URL segments and command data. Two C2 domains were identified:
- `ashx[.]lhlsjcb[.]com` (earlier reconnaissance phase)
- `hcgos[.]com` (primary incident, subdomain pattern: `a.<hex>.c.hcgos[.]com`)

**HTTP Fallback Channel:** When DNS queries fail, the web shell falls back to HTTP-based notification. The User-Agent string `python-requests/2.33.0` was observed in fallback communications.

**Meterpreter C2:** A Meterpreter reverse shell connection was established to `43[.]160[.]202[.]246:8053` (non-standard port). Additional outbound connections were observed to `140[.]206[.]161[.]227:443` and inbound web shell interaction from `124[.]156[.]129[.]151`.

### 4. Privilege Escalation

Post-initial web shell deployment, OP-512 loaded Potato suite tools -- specifically BadPotato, SweetPotato, and EfsPotato -- to escalate from the IIS application pool identity to SYSTEM. These tools exploit Windows token impersonation vulnerabilities. The tools were loaded reflectively into memory rather than written to disk. Privilege verification commands (`whoami /priv`) were issued with Base64-encoded command arguments, with encoding patterns character-identical to those observed in a Flax Typhoon campaign targeting ArcGIS servers.

### 5. Anti-Forensics / Evasion Techniques

- **Timestomping:** Median-based timestamp manipulation of all deployed web shell files
- **Polymorphic generation:** Per-deployment unique code with randomized identifiers and dead code injection
- **Memory-only tools:** Privilege escalation tooling loaded via reflective assembly loading, no disk artifacts
- **IIS containment bypass:** After EDR terminated the malicious `w3wp.exe` process, IIS automatically restarted the worker process, re-establishing the execution environment
- **Cryptographic access control:** RSA signature verification prevents unauthorized command execution even if web shells are discovered
- **DLL compilation artifacts:** Web shells trigger automatic DLL compilation in ASP.NET temporary directories, creating additional forensic artifacts in non-obvious locations

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | lhlsjcb[.]com | DNS C2 domain (reconnaissance phase, ~75 days prior) |
| Domain | ashx[.]lhlsjcb[.]com | DNS C2 subdomain for web shell notification |
| Domain | hcgos[.]com | DNS C2 domain (primary incident) |
| IP | 43[.]160[.]202[.]246:8053 | Meterpreter C2 server (non-standard port) |
| IP | 140[.]206[.]161[.]227:443 | Outbound C2 connection |
| IP | 124[.]156[.]129[.]151 | Web shell interaction source IP |
| User-Agent | `python-requests/2.33.0` | HTTP fallback C2 User-Agent string |
| DNS Pattern | `a.<hex>.c.hcgos[.]com` | Hex-encoded DNS tunneling subdomain structure |

### File System

| Platform | Path / Indicator | Description |
|----------|------------------|-------------|
| Windows/IIS | Application upload directory (path varies) | Web shell deployment location |
| Windows/IIS | `\Temporary ASP.NET Files\` subdirectories | Auto-compiled DLL artifacts from web shell access |
| Windows/IIS | `.aspx` file with timestomping + file management code | ASPX file manager web shell |
| Windows/IIS | `.ashx` files with RSA + RC4 cryptographic handlers | ASHX command handler web shells |

### Behavioral

- `w3wp.exe` spawning `cmd.exe`, `powershell.exe`, or `whoami.exe`
- `w3wp.exe` initiating outbound DNS queries with abnormally long hex-segmented subdomains
- New DLL compilation in ASP.NET temporary directories outside normal deployment windows
- ASP.NET processes loading cryptographic components via reflective assembly loading
- Base64-encoded `whoami /priv` commands executed through IIS worker process
- Files in web application directories with modification timestamps matching the median of surrounding files (timestomping indicator)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of legacy IIS server running .NET Framework 4.0 for initial access |
| T1505.003 | Server Software Component: Web Shell | Deployment of three-component web shell framework (ASPX file manager + 2 ASHX handlers) |
| T1070.006 | Indicator Removal: Timestomping | Median-based timestamp manipulation of web shell files to match surrounding directory contents |
| T1027 | Obfuscated Files or Information | Polymorphic code generation with randomized identifiers and dead code injection per deployment |
| T1140 | Deobfuscate/Decode Files or Information | Base64 encoding of commands; hex-encoding of URL segments in DNS C2 queries |
| T1134.003 | Access Token Manipulation: Make and Impersonate Token | BadPotato/SweetPotato/EfsPotato token impersonation for SYSTEM escalation |
| T1071.004 | Application Layer Protocol: DNS | Hex-encoded DNS subdomain tunneling for C2 notification and communication |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP fallback C2 channel with python-requests User-Agent; web shell self-reporting notification |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | RC4 encryption of command payloads in ASHX handlers |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA signature verification gating command execution |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Command execution via cmd.exe spawned from w3wp.exe |

## Impact Assessment

OP-512 represents a targeted espionage operation rather than a broad opportunistic campaign. The cluster's use of purpose-built tooling with per-deployment cryptographic uniqueness, combined with the effort invested in anti-forensic timestomping and polymorphic code generation, indicates a well-resourced threat actor with specific intelligence collection objectives. The targeting of legacy IIS infrastructure is notable because these systems often serve internal enterprise applications with access to sensitive data while receiving reduced security monitoring compared to modern cloud workloads.

The IIS containment bypass -- where the web server automatically restarts terminated worker processes -- represents a systemic challenge for endpoint detection and response in IIS environments, as it can negate kill-chain disruption at the process termination stage.

## Detection & Remediation

### Immediate Detection

1. Search DNS logs for queries to `lhlsjcb[.]com` or `hcgos[.]com` (any subdomain)
2. Search network logs for connections to `43[.]160[.]202[.]246:8053` or `140[.]206[.]161[.]227:443`
3. Search IIS logs for requests to unexpected `.aspx` or `.ashx` files in upload directories
4. Audit ASP.NET temporary compilation directories for recently created DLL files
5. Search process creation logs for `w3wp.exe` spawning `cmd.exe`, `powershell.exe`, or `whoami.exe`
6. Search for User-Agent string `python-requests/2.33.0` in HTTP proxy/firewall logs originating from IIS servers

### Remediation

1. **Containment:** Isolate affected IIS servers from the network; note that simply killing `w3wp.exe` is insufficient as IIS will restart the process
2. **Stop the application pool** in IIS Manager to prevent automatic worker process restart
3. **Forensic collection:** Preserve web shell files, ASP.NET temporary compilation DLLs, IIS logs, DNS query logs, and Sysmon/EDR telemetry
4. **Eradication:** Remove all web shell files from application directories; clear ASP.NET temporary compilation caches
5. **Credential rotation:** Rotate all credentials accessible from the compromised server, including service accounts and any stored database connection strings
6. **Patch/upgrade:** Migrate from .NET Framework 4.0 and Windows Server 2016 to supported versions

### Long-Term Hardening

- Retire legacy .NET Framework 4.0 applications or migrate to .NET 6+/8+
- Implement application allowlisting on IIS servers to prevent unauthorized `.aspx`/`.ashx` file execution
- Deploy file integrity monitoring on web application directories
- Monitor ASP.NET temporary compilation directories for unexpected DLL creation
- Restrict outbound DNS from IIS servers to authorized resolvers; alert on direct DNS queries from `w3wp.exe`
- Implement network segmentation limiting IIS server outbound connectivity

## Detection Rules

The following 10 rules (4 Sigma, 3 YARA, 3 Suricata) target OP-512's distinctive indicators across host, file, and network telemetry. Three rules from the initial draft were dropped during review (noted inline). IOC-based rules (specific domains, IPs) are high confidence but have a limited shelf life as the actor rotates infrastructure. Behavioral rules (IIS child process spawning, DNS tunneling patterns) provide broader coverage but require tuning for legitimate application activity.

### Sigma: IIS Worker Process Spawning Suspicious Child Process

Detects `w3wp.exe` spawning command interpreters or reconnaissance utilities consistent with web shell command execution. This is a generic web shell indicator that duplicates community Sigma rules; it serves as a supporting signal, not a standalone OP-512 detection.

**Status:** ✅ compiles | Confidence: medium (behavioral TTP rule, not OP-512-specific)

<!-- audit: sigma check exit 0, sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0. Behavioral pattern — w3wp.exe spawning cmd/whoami is common in web shell activity broadly, not unique to OP-512. FP risk from legitimate IIS management scripts. Downgraded to medium per review: generic pattern, supporting indicator only. -->

```yaml
title: OP-512 - IIS Worker Process Spawning Suspicious Child Process
id: 40afe81b-e7c4-452a-8b7d-b1ac3893f4c3
status: experimental
description: >
    Detects IIS worker process (w3wp.exe) spawning command interpreters or
    reconnaissance tools, consistent with web shell command execution observed
    in OP-512 activity targeting IIS servers.
references:
    - https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512
    - https://thehackernews.com/2026/06/new-threat-cluster-op-512-targets.html
author: Actioner
date: 2026-06-06
tags:
    - attack.t1505.003
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\w3wp.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\whoami.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\ipconfig.exe'
            - '\systeminfo.exe'
            - '\nltest.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate IIS management scripts or health checks spawning command-line tools
    - Application pools that intentionally invoke command-line utilities
level: medium
```

### Sigma: DNS Query to Known OP-512 C2 Domains

Detects DNS resolution attempts for the two known OP-512 C2 domains (both apex and any subdomain) used for web shell self-reporting and command-and-control.

**Status:** ✅ compiles | Confidence: high (IOC-specific)

<!-- audit: sigma check exit 0, sigma convert --without-pipeline -t splunk exit 0. IOC-based — high confidence but limited shelf life. Now matches both bare apex domains (lhlsjcb.com, hcgos.com) and any subdomain. -->

```yaml
title: OP-512 - DNS Query to Known C2 Domains
id: 728f8cbd-2566-48d9-9030-7cd227a85543
status: experimental
description: >
    Detects DNS queries to known OP-512 C2 domains used for web shell
    self-reporting and command-and-control communication.
references:
    - https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512
author: Actioner
date: 2026-06-06
tags:
    - attack.t1071.004
logsource:
    category: dns_query
detection:
    selection_subdomain:
        QueryName|endswith:
            - '.lhlsjcb.com'
            - '.hcgos.com'
    selection_apex:
        QueryName:
            - 'lhlsjcb.com'
            - 'hcgos.com'
    condition: 1 of selection_*
falsepositives:
    - Unlikely - these are attacker-controlled domains
level: critical
```

### Sigma: IIS Worker Process DNS Query with Hex-Encoded Subdomain

Detects `w3wp.exe` performing DNS queries with the OP-512 hex-segmented subdomain pattern (`a.<hex>.c.<domain>`) used for DNS tunneling C2.

**Status:** ✅ compiles | Confidence: medium (behavioral TTP pattern)

<!-- audit: sigma check exit 0, sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0. Regex-based detection of DNS tunneling subdomain structure. Requires Sysmon EID 22 with process context. FP possible from CDN hex subdomains but scoped to w3wp.exe reduces noise significantly. -->

```yaml
title: OP-512 - IIS Worker Process DNS Query with Hex-Encoded Subdomain
id: 283444e6-8c7e-4983-9bc7-856bdf6b4a46
status: experimental
description: >
    Detects w3wp.exe performing DNS queries with long hex-encoded subdomain
    patterns consistent with OP-512 DNS tunneling C2 communication, where
    subdomains follow the pattern a.<hex>.c.<domain>.
references:
    - https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512
author: Actioner
date: 2026-06-06
tags:
    - attack.t1071.004
logsource:
    category: dns_query
detection:
    selection_process:
        Image|endswith: '\w3wp.exe'
    selection_query:
        QueryName|re: '^a\.[0-9a-f]{8,}\.c\..+$'
    condition: selection_process and selection_query
falsepositives:
    - CDN or cloud service subdomains with hex-encoded segments initiated by web applications
level: high
```

### ~~Sigma: Suspicious DLL Creation in ASP.NET Temporary Compilation Directory~~ (DROPPED)

Dropped: fires on every legitimate ASP.NET page compilation, app pool recycle, and deployment. No OP-512-specific content.

### Sigma: Network Connection to Known OP-512 C2 Infrastructure

Detects outbound network connections to the two confirmed OP-512 outbound C2 infrastructure IP addresses. IP `124[.]156[.]129[.]151` was removed as it is an inbound source IP (web shell interaction), not an outbound destination.

**Status:** ✅ compiles | Confidence: high (IOC-specific)

<!-- audit: sigma check exit 0, sigma convert --without-pipeline -t splunk exit 0. IOC-based — high confidence, limited shelf life. Removed 124.156.129.151 (inbound source, not outbound destination). Title aligned to "C2 Infrastructure" across YAML and prose. -->

```yaml
title: OP-512 - Network Connection to Known C2 Infrastructure
id: 594c964f-6b68-4ce0-ab03-6b12aadbb5de
status: experimental
description: >
    Detects outbound network connections to known OP-512 C2 infrastructure IPs,
    including the Meterpreter C2 server on non-standard port 8053.
references:
    - https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512
author: Actioner
date: 2026-06-06
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        Initiated: 'true'
        DestinationIp:
            - '43.160.202.246'
            - '140.206.161.227'
    condition: selection
falsepositives:
    - Unlikely - these are known attacker infrastructure IPs
level: critical
```

### ~~Sigma: Potato Suite Privilege Escalation via IIS Worker Process~~ (DROPPED)

Dropped: OP-512 uses reflective assembly loading for Potato tools; command-line strings will not be present, making this rule ineffective for this threat.

### YARA: OP-512 Web Shell File Detection

Three YARA rules targeting the web shell framework's file-level indicators: the ASPX file manager (timestomping + file operations + C2 notification), the ASHX command handler (RSA + RC4 + command execution pipeline), and a generic combined indicator rule.

**Status:** ✅ compiles (yarac exit 0) | Confidence: medium (string-based detection; polymorphic code may evade variable name matching, but structural patterns like crypto APIs and C2 domains are stable)

<!-- audit: yarac exit 0. OP512_ASHX_Command_Handler condition tightened: RC4 AND crypto strings now required together (was OR). Severity downgraded from critical to high. Rules key on .NET cryptographic API names which are framework strings not subject to polymorphic renaming, plus known C2 domains. -->

```yara
rule OP512_ASPX_WebShell_FileManager
{
    meta:
        description = "Detects OP-512 ASPX web shell file manager with timestomping capability, dual C2 notification channels (DNS/HTTP), and file management operations"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $aspx_header = "<%@ Page" ascii nocase
        $timestomp1 = "SetCreationTime" ascii wide
        $timestomp2 = "SetLastWriteTime" ascii wide
        $timestomp3 = "SetLastAccessTime" ascii wide
        $fileop1 = "Directory.GetFiles" ascii wide
        $fileop2 = "File.Delete" ascii wide
        $fileop3 = "File.Move" ascii wide
        $fileop4 = "File.WriteAllBytes" ascii wide
        $dns1 = "DnsGetRecord" ascii wide
        $dns2 = "nslookup" ascii wide nocase
        $http_fallback = "python-requests" ascii wide
        $c2_pattern = "hcgos.com" ascii wide nocase
        $c2_pattern2 = "lhlsjcb.com" ascii wide nocase

    condition:
        filesize < 500KB and
        $aspx_header and
        (2 of ($timestomp*)) and
        (2 of ($fileop*)) and
        (1 of ($dns*) or $http_fallback or 1 of ($c2_pattern*))
}

rule OP512_ASHX_Command_Handler
{
    meta:
        description = "Detects OP-512 ASHX command handler web shell with RSA signature verification and RC4 decryption pipeline"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "high"

    strings:
        $ashx_header = "<%@ WebHandler" ascii nocase
        $rsa1 = "RSACryptoServiceProvider" ascii wide
        $rsa2 = "RSAParameters" ascii wide
        $rsa3 = "VerifyData" ascii wide
        $rc4_1 = "RC4" ascii wide nocase
        $crypto1 = "FromBase64String" ascii wide
        $crypto2 = "Convert.FromBase64String" ascii wide
        $exec1 = "Process.Start" ascii wide
        $exec2 = "ProcessStartInfo" ascii wide
        $handler = "IHttpHandler" ascii wide
        $context = "HttpContext" ascii wide

    condition:
        filesize < 200KB and
        $ashx_header and
        (1 of ($rsa*)) and
        (1 of ($rc4_*) and 1 of ($crypto*)) and
        (1 of ($exec*)) and
        ($handler or $context)
}

rule OP512_WebShell_Generic_Indicators
{
    meta:
        description = "Detects generic indicators of OP-512 web shell framework including polymorphic code patterns and cryptographic command processing pipeline"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pipe1 = "FromBase64String" ascii wide
        $pipe2 = "RSACryptoServiceProvider" ascii wide
        $pipe3 = "ProcessStartInfo" ascii wide
        $aspx = "<%@" ascii
        $ashx = "<%@ WebHandler" ascii nocase
        $c2_dom1 = "hcgos.com" ascii wide nocase
        $c2_dom2 = "lhlsjcb.com" ascii wide nocase

    condition:
        filesize < 500KB and
        ($aspx or $ashx) and
        all of ($pipe*) and
        1 of ($c2_dom*)
}
```

### Suricata: OP-512 Network C2 Detection

Three Suricata rules covering DNS queries to both known C2 domains and TCP connections to the Meterpreter C2 server on port 8053. The `python-requests/2.33.0` User-Agent rule (sid:2100503) was dropped as `python-requests` is the default UA for any Python HTTP client, producing unacceptable false-positive volume with no process-scoping possible in Suricata.

**Status:** ✅ compiles (suricata -T exit 0) | Confidence: high (IOC-specific rules)

<!-- audit: suricata -T exit 0 with "Configuration provided was successfully loaded." SIDs 2100501, 2100502, 2100504. sid:2100503 (python-requests UA) dropped — default UA for the Python requests library, fires on any Python client with no scoping possible. sid:2100504 title aligned to "C2 Infrastructure". -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - OP-512 DNS Query to Known C2 Domain hcgos.com"; flow:to_server; dns.query; content:"hcgos.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512; metadata:author Actioner, created_at 2026-06-06, tlp WHITE; sid:2100501; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OP-512 DNS Query to Known C2 Domain lhlsjcb.com"; flow:to_server; dns.query; content:"lhlsjcb.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512; metadata:author Actioner, created_at 2026-06-06, tlp WHITE; sid:2100502; rev:1;)

alert tcp $HOME_NET any -> 43.160.202.246 8053 (msg:"Actioner - OP-512 Outbound Connection to Known C2 Infrastructure"; flow:established,to_server; classtype:trojan-activity; reference:url,reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512; metadata:author Actioner, created_at 2026-06-06, tlp WHITE; sid:2100504; rev:1;)
```

## Lessons Learned

1. **Legacy infrastructure is a persistent liability.** OP-512 specifically targeted end-of-life .NET Framework 4.0 on Windows Server 2016, exploiting the security gap created by deferred migrations. Organizations must inventory and prioritize retirement of internet-facing legacy systems.

2. **IIS worker process restart behavior undermines containment.** EDR tools that terminate malicious `w3wp.exe` processes face a systemic challenge: IIS automatically restarts worker processes, re-establishing the attacker's execution context. Detection strategies must account for this by targeting the web shell files and application pool configuration, not just the process.

3. **Polymorphic web shells defeat signature-based detection.** OP-512's per-deployment code randomization renders traditional web shell signatures ineffective. Detection must focus on behavioral patterns (IIS child process spawning, DNS tunneling) and structural indicators (.NET cryptographic API usage patterns) rather than specific variable names or code strings.

4. **Timestomping remains an effective anti-forensic technique.** OP-512's algorithmic approach -- calculating the median timestamp of surrounding files rather than using a hardcoded date -- is more sophisticated than typical timestomping. File integrity monitoring that captures creation events (not just modification timestamps) is essential.

5. **Cryptographic access controls in web shells represent an escalation in tradecraft.** The RSA signature verification layer means that discovery of the web shell endpoint alone does not enable security researchers or incident responders to interact with it, complicating analysis and attribution.

## Sources

- [ReliaQuest Threat Spotlight: OP-512](https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512) -- primary technical analysis; source of all IOCs, TTPs, and web shell framework details
- [The Hacker News: New Threat Cluster OP-512 Targets Microsoft IIS Servers](https://thehackernews.com/2026/06/new-threat-cluster-op-512-targets.html) -- initial reporting with attribution context and related cluster comparisons

---
*Report generated by Actioner*
