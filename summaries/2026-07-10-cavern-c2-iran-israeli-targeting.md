# Technical Analysis Report: Cavern Manticore C2 Framework (2026-07-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-10
Version: 1.0-DRAFT

## Executive Summary

Check Point Research has disclosed a previously undocumented modular command-and-control framework dubbed **Cavern** (also known as **Cav3rn**) attributed to **Cavern Manticore**, an Iran-nexus threat cluster linked to Iran's Ministry of Intelligence and Security (MOIS). The framework shares tactical overlaps with MuddyWater and Lyceum (an assessed OilRig subgroup) and has been used to target Israeli IT service providers and government-sector organizations, with secondary operations observed against aviation, energy, and government entities in Egypt and the UAE.

The framework employs a sophisticated multi-format .NET compilation strategy across its components (.NET Framework 4.7.2, Mixed-Mode C++/CLI, and NativeAOT .NET 8) to force analysts into multiple reverse-engineering toolchains simultaneously. The attack chain leverages DLL side-loading via a legitimate WinDirStat.exe binary to load a trojanized uxtheme.dll containing the Cavern backdoor agent, which communicates over HTTPS and WebSocket channels to the C2 domain hospitalinstallation[.]com registered through Fars Data, an Iranian hosting provider. The modular architecture includes dedicated components for file operations, SQL database access, Active Directory reconnaissance, network scanning, SMB brute-forcing, and SOCKS5 proxy tunneling.

## Background: Targeted IT Service Providers and Government Sectors

Cavern Manticore specifically targets IT managed service providers (MSPs) and Remote Monitoring and Management (RMM) platforms as a supply-chain entry point. By compromising trusted service providers, the actor gains access to downstream client environments -- including Israeli government organizations -- through legitimate administrative channels. The actor has been observed abusing SysAid's legitimate software update feature (not a vulnerability) to deploy the Cavern agent, and leveraging browser-based remote desktop and remote printing capabilities for lateral movement and data exfiltration. This supply-chain approach significantly amplifies the blast radius of each compromise.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-2026 (est.) | Older Cav3rn builds observed with webshell + steganography transport (cac.aspx, .CvnC.png/.CvnA.png/.CvnR.png) communicating to adserviceupdate[.]com and hygienehistory[.]com |
| 2025-2026 | Exploitation of CVE-2025-52691 (SmarterMail), CVE-2025-68613 (n8n), CVE-2025-9316 (N-Central), CVE-2025-34291 (Langflow), CVE-2025-54068 (Laravel Livewire) in related campaigns |
| 2026 (est.) | Modernized Cavern framework deployed: refactored modular architecture with three compilation formats, new communication module n-HTCommp.dll replacing webshell transport |
| 2026-07-07 | Check Point Research publishes "Cavern Manticore: Exposing Iran-Linked Modular C2 Framework" |

## Root Cause: Supply Chain Compromise via IT Service Provider Abuse

Initial access is achieved through compromise of IT managed service providers and RMM platforms. The actor gains footholds through OWA brute-force attacks and exploitation of internet-facing vulnerabilities in common enterprise software (SmarterMail, n8n, N-Central, Langflow, Laravel Livewire). Once inside an MSP environment, the actor abuses the trusted service-provider relationship -- using legitimate RMM features such as SysAid's software update deployment -- to propagate to downstream target organizations. Multi-hop chains have been observed: compromise IT provider A, use provider A's access to reach IT provider B, then pivot to the final high-value government target.

## Technical Analysis of the Malicious Payload

### 1. DLL Side-Loading Chain (Initial Execution)

The actor deploys a legitimate 64-bit WinDirStat.exe binary to `C:\ProgramData\WinDir\WinDirStat.exe` alongside a trojanized `uxtheme.dll`. When WinDirStat.exe executes, standard DLL search order causes it to load the attacker's uxtheme.dll instead of the legitimate system copy. The trojanized DLL is compiled as a Mixed-Mode C++/CLI assembly (.NET Framework 4.7.2) containing 83 exported functions -- 82 are empty stubs; the real backdoor logic resides behind export ordinal #20 (`EnableThemeDialogTexture`). This design ensures automated analysis tools invoking default exports observe only benign behavior.

### 2. Cavern Agent (uxtheme.dll -- Orchestrator)

Upon activation via the EnableThemeDialogTexture export, the agent:

1. Creates a mutex (`MYMUTEX123HELLP02` or `MYMUTEX123HELLP04`, depending on build) to enforce single-instance execution
2. Reads `config.txt` containing JSON configuration with keys: `i` (agent ID), `xd` (XOR key/variant data), `int` (beacon interval)
3. Loads the native communication module `n-HTCommp.dll` via `LoadLibraryA`
4. Enters a beacon loop, polling the C2 for commands
5. On first startup of newer builds, enumerates the working directory and deletes all files except n-HTCommp.dll, config.txt, and log files, reporting "cleared" to C2

Module loading follows a naming convention: DLLs prefixed with `n-` are loaded as native DLLs via `LoadLibraryA`; others are loaded as managed .NET assemblies via AppDomain isolation using a `DotNetProxy` class (inheriting `MarshalByRefObject`). Each module runs in a dedicated AppDomain that is unloaded after execution, preventing assembly artifacts from persisting in default domain memory.

Module versioning uses numeric suffixes (`modulename0.dll`, `modulename1.dll`); the agent automatically loads the highest-numbered variant.

### 3. C2 Infrastructure

**Primary C2 Domain:** hospitalinstallation[.]com (registered via Fars Data, an Iranian hosting provider)

**Active C2 Subdomains:**
- `auth[.]hospitalinstallation[.]com` (older agent builds)
- `google[.]com[.]hospitalinstallation[.]com` (newer builds -- visual obfuscation mimicking Google)

**Legacy C2 Domains:**
- `adserviceupdate[.]com` (older Cav3rn webshell transport)
- `hygienehistory[.]com` (older Cav3rn webshell transport)

**Communication Protocol (n-HTCommp.dll -- NativeAOT .NET 8):**

The communication module uses a fixed User-Agent string:
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0`

**HTTP Transport Verbs:**

| Verb | Method | Endpoint | XOR (0x48) | Base64 | Custom Header |
|------|--------|----------|------------|--------|---------------|
| get | GET | `<host>/profile` | Yes | Yes | X-User-token: `<AgentID>00` |
| send | POST | `<host>/gallery` | Yes | Yes | X-User-token: `<AgentID>00` |
| cget | GET | `<url>` | No | No | User-Agent only |
| cpost | POST | `<url>` | No | No | User-Agent only |
| upload | POST multipart | `<url>` | No | No | form field `file` |

**WebSocket Transport:**
- Endpoints: `wss://<host>/socket` or `ws://<host>/socket`
- Initial frame XOR-encrypted with key 0x48

**Command Delimiters:** `_;;_` (field separator), `_,_` (argument separator)

**Agent Self-Commands (000-series):**
- 001: Update polling interval
- 002: GZip+Base64 module update (self-update capable)
- 003: Toggle debug logging
- 004: Activate WebSocket mode
- 005: Close WebSocket
- 006: Reconnect WebSocket

**Legacy Transport (cac.aspx -- Older Cav3rn):**

The older webshell-style ASP.NET handler uses:
- Request format: `s=<unix_timestamp>&id=<agent_id>&q=<xor_base32_payload>`
- Response: body starts with a JPEG magic header (21-byte prefix); `Content-Disposition` filename encrypted with agent ID as XOR key
- Certificate validation bypass: `ServerCertificateValidationCallback` hardcoded to return `true`

### 4. Platform-Specific Behavior

#### Windows

All observed activity is Windows-only. The framework targets Windows environments running .NET Framework 4.7.2+ and .NET 8.0 runtime.

**Post-Exploitation Modules:**

| Module | File | Compilation | Command IDs | Capabilities |
|--------|------|-------------|-------------|--------------|
| File Manager | mhm.dll | .NET Framework 4.7.2 | 101-104, 301-314, 801-806 | File enumeration, recursive search, archiving (GZip/ZIP), bidirectional transfer, DPAPI decrypt (`ProtectedData.Unprotect`, `DataProtectionScope.CurrentUser`), token/time info |
| SQL | db.dll | .NET Framework 4.7.2 | 201, 901 | SQL query execution, database enumeration/browsing/export/manipulation |
| LDAP/AD | ode.dll | .NET Framework 4.7.2 | 401-407 | LDAP bind test, AD user/group enumeration, LDAP brute-force (semicolon-delimited credentials, `<path` prefix for file-based input) |
| Network Recon | n-ten.dll | NativeAOT .NET 8 | 1101-1701 | DNS lookup, interface/IP config, ping, netstat, mapped drives, SMB brute-force (`WNetAddConnection2`), user/group enumeration, ARP table, domain info, share/computer enumeration (`NetShareEnum`, `NetServerEnum`), TCP port scanning |
| Tunnel | n-sws.dll | NativeAOT .NET 8 | - | SOCKS5 proxy and WebSocket tunneling |

### 5. Anti-Forensics / Evasion Techniques

**Compilation-Based Evasion:**
- **Pure .NET Framework (IL-only):** Full symbol metadata but requires .NET decompiler (ILSpy, dnSpyEx)
- **Mixed-Mode C++/CLI (uxtheme.dll):** Combines managed .NET + native C++; requires both a decompiler and a disassembler
- **NativeAOT .NET 8 (n-HTCommp.dll, n-ten.dll, n-sws.dll):** Statically compiled runtime yielding ~5.5MB binaries with thousands of stripped framework functions; requires specialized tooling (ida-nativeaot IDA Pro plugin)

**String Obfuscation (NativeAOT Modules):**
- Frozen strings stored in a "hydrated" BSS-like section, materialized only at runtime
- Verb constants packed as character integers in CMP instructions (e.g., "get" encoded as `0x650067`, `0x740065` in UTF-16 char packing)
- `strings` utility returns almost no usable output against NativeAOT binaries

**Delayed P/Invoke Resolution (n-ten.dll):**
- APIs resolved at runtime via descriptor tables
- Not present in PE import table, hiding module capabilities from static analysis
- 21 dynamically-loaded API descriptors recovered (including `WNetAddConnection2`, `NetShareEnum`, `NetLocalGroupGetMembers`, `NetServerEnum`)

**AppDomain Isolation:**
- Each module loaded in a dedicated AppDomain via `DotNetProxy` (`MarshalByRefObject`)
- AppDomains unloaded post-execution, preventing assembly artifacts in default domain memory
- Enables sequential loading of multiple versions of the same module

**Empty Export Stubs:**
- uxtheme.dll exports 83 functions; 82 are benign stubs
- Real payload only behind ordinal #20 (`EnableThemeDialogTexture`)

**Self-Cleanup:**
- Newer agent builds delete all working-directory files except n-HTCommp.dll, config.txt, and logs on first startup

**Certificate Validation Bypass (Legacy):**
- Hardcoded `ServerCertificateValidationCallback` returning `true` to accept self-signed C2 certificates

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | uxtheme.dll | 37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066 | Cavern Agent (build 02) |
| Windows | uxtheme.dll | 92cae0ad7f98f51a14bcc0ee05e372ebdc29ea96ea7bd161bd3f55198767603b | Cavern Agent (build 04) |
| Windows | uxtheme.dll | 5dc08bda6919a57a85e5f38b857985fa71529ca39c8299868d5a49a987e19b18 | Cavern Agent (oldest build) |
| Windows | n-HTCommp.dll | a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41 | Communication module (variant 1) |
| Windows | n-HTCommp.dll | b630c96d3763182533d4fb9b614134382bd644cb02c6c1c3ade848b6ecc31e86 | Communication module (variant 2) |
| Windows | mhm.dll | 8e9425c0b46eeb516610ae913d13f2b3f44a023043cb099277031d4ec38a6134 | File manager module |
| Windows | mhm.dll | 0a3663648a46771a5a5423ad01e91a4e7ba825595e99fa934cb35cbb4848adc8 | File manager (older Cav3rn) |
| Windows | db.dll | 5394d3b220de4695f731647e3a70545f951a8912ceb0c6585efab8d6842e8b42 | SQL module |
| Windows | ode.dll | 30cb4679c4b8599eeb3d63a551716475c6332bdc4d4b4e3de0964aadb3092a10 | LDAP/AD reconnaissance module |
| Windows | n-ten.dll | 2cb1ad3b22db8e3666ea138fee88034a87a87cf43db3d3265a675ebf221379b0 | Network reconnaissance module |
| Windows | n-sws.dll | 7d586fb7f94182a8e2a0e53c7e4deb898066da029da5cd9972a94a59ca6d255a | SOCKS5/WebSocket tunnel module |
| Windows | (older agent) | 541b1f417b9e42078c3355693a8a492b6a76048850f6549a429e0be99e6819cb | Older Cav3rn agent |
| Windows | (older agent) | cbc9485db715e1b8cc384fe94b4cceadca4006cda8a5e28adc8848529cfafc93 | Older Cav3rn agent |
| Windows | (older HTTP module) | ccf218189c3aadb1c761da14bfda3bae686769031e1e1b10007648bd72e34748 | Older Cav3rn HTTP module |
| Windows | C:\ProgramData\WinDir\WinDirStat.exe | - | Legitimate sideload host binary |
| Windows | C:\ProgramData\WinDir\uxtheme.dll | - | Trojanized agent DLL |
| Windows | config.txt | - | Agent configuration (JSON: i, xd, int) |
| Windows | Cvn.cfg.A / Cvn.cfg.U | - | Legacy alive-time configuration files |
| Windows | cac.aspx | - | Older Cav3rn ASP.NET C2 handler |
| Windows | .CvnC.png / .CvnA.png / .CvnR.png | - | Steganographic transport files (older builds) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | hospitalinstallation[.]com | Primary C2 root domain (registered via Fars Data, Iran) |
| Domain | auth[.]hospitalinstallation[.]com | C2 subdomain (older agent builds) |
| Domain | google[.]com[.]hospitalinstallation[.]com | C2 subdomain (newer builds, visual obfuscation) |
| Domain | adserviceupdate[.]com | Legacy Cav3rn C2 domain |
| Domain | hygienehistory[.]com | Legacy Cav3rn C2 domain |
| URL Pattern | hxxps://\<C2\>/profile | Beacon check-in endpoint (GET, XOR+Base64) |
| URL Pattern | hxxps://\<C2\>/gallery | Data exfiltration/command result upload (POST, XOR+Base64) |
| URL Pattern | wss://\<C2\>/socket | WebSocket C2 channel |
| HTTP Header | X-User-token: \<AgentID\>00 | Custom header in C2 beacon requests |
| User-Agent | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0 | Fixed C2 User-Agent string |

### Behavioral

- **Mutex creation:** `MYMUTEX123HELLP`, `MYMUTEX123HELLP02`, `MYMUTEX123HELLP04` -- unique mutex names used for single-instance enforcement
- **DLL side-loading chain:** WinDirStat.exe from `C:\ProgramData\WinDir\` loading uxtheme.dll (abnormal -- legitimate WinDirStat never resides in ProgramData)
- **XOR encryption:** All C2 traffic on the primary HTTP channel encrypted with single-byte XOR key `0x48`, followed by Base64 encoding
- **Command delimiter strings:** `_;;_` (field separator) and `_,_` (argument separator) in C2 protocol
- **AppDomain lifecycle:** Rapid creation and teardown of .NET AppDomains for module execution/unloading
- **Self-cleanup on first execution:** Agent deletes all non-essential files in working directory
- **P/Invoke descriptor resolution:** Runtime API resolution via descriptor tables (21 descriptors in n-ten.dll) rather than import table entries
- **PDB path artifact:** `C:\Users\rick\Desktop\Modules\cavern\` present in debug symbols

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Abuse of IT managed service providers and RMM software (SysAid) update features to deploy malware to downstream victims |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | WinDirStat.exe loads trojanized uxtheme.dll from C:\ProgramData\WinDir\ |
| T1027 | Obfuscated Files or Information | Three distinct .NET compilation formats (IL-only, Mixed-Mode C++/CLI, NativeAOT) force multi-toolchain analysis; XOR 0x48 + Base64 on C2 traffic |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS GET/POST to /profile and /gallery endpoints; WebSocket to /socket |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | XOR encryption (key 0x48) applied to all primary C2 HTTP/WebSocket payloads |
| T1041 | Exfiltration Over C2 Channel | POST verb sends XOR+Base64-encoded command results/data to /gallery |
| T1046 | Network Service Discovery | n-ten.dll TCP port scanning (command 1701), NetServerEnum for computer discovery |
| T1087.002 | Account Discovery: Domain Account | ode.dll LDAP user/group enumeration (commands 402-406) |
| T1110 | Brute Force | LDAP brute-force (command 407) and SMB brute-force via WNetAddConnection2 (command 1204) |
| T1083 | File and Directory Discovery | mhm.dll file enumeration and recursive search (commands 301-314) |
| T1106 | Native API | P/Invoke to WNetAddConnection2, NetShareEnum, NetLocalGroupGetMembers via runtime descriptor resolution |
| T1105 | Ingress Tool Transfer | On-the-fly module download from C2 via self-command 002 (GZip+Base64) |
| T1129 | Shared Modules | DLL versioning scheme with automatic highest-version loading; module dispatch via naming convention |
| T1059 | Command and Scripting Interpreter | SQL query execution via db.dll module |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | WebSocket tunneling and SOCKS5 proxy via n-sws.dll |
| T1018 | Remote System Discovery | NetServerEnum via n-ten.dll for domain computer enumeration |
| T1555 | Credentials from Password Stores | DPAPI decryption via ProtectedData.Unprotect (mhm.dll command 102) |

## Impact Assessment

The Cavern framework represents a mature, operationally deployed toolset with clear indicators of sustained development. The multi-hop supply-chain approach through IT service providers significantly amplifies impact -- a single MSP compromise can cascade to dozens of downstream organizations. The primary targets are Israeli government and IT sectors, though secondary targeting of Egyptian and UAE entities in aviation, energy, and government has been observed. The majority of observed malware samples score zero or very low detection rates on VirusTotal, indicating the multi-compilation-format evasion strategy is effective against current endpoint detection solutions.

## Detection & Remediation

### Immediate Detection

**File-based checks:**
```
# Check for WinDirStat in ProgramData
dir /s /b "C:\ProgramData\WinDir\WinDirStat.exe"
dir /s /b "C:\ProgramData\WinDir\uxtheme.dll"

# Check for Cavern module DLLs
dir /s /b "C:\*n-HTCommp.dll"
dir /s /b "C:\*n-sws.dll"
dir /s /b "C:\*n-ten.dll"

# Check for config artifacts
dir /s /b "C:\*Cvn.cfg.A"
dir /s /b "C:\*Cvn.cfg.U"
```

**Network-based checks:**
```
# DNS query logs for C2 domains
grep -iE "(hospitalinstallation|adserviceupdate|hygienehistory)\." /var/log/dns*

# HTTP proxy logs for C2 URI patterns
grep -E "/(profile|gallery|socket)" /var/log/proxy* | grep -i "X-User-token"
```

**Hash-based IOC sweep (SHA256):**
```
37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066
92cae0ad7f98f51a14bcc0ee05e372ebdc29ea96ea7bd161bd3f55198767603b
5dc08bda6919a57a85e5f38b857985fa71529ca39c8299868d5a49a987e19b18
a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41
b630c96d3763182533d4fb9b614134382bd644cb02c6c1c3ade848b6ecc31e86
8e9425c0b46eeb516610ae913d13f2b3f44a023043cb099277031d4ec38a6134
5394d3b220de4695f731647e3a70545f951a8912ceb0c6585efab8d6842e8b42
30cb4679c4b8599eeb3d63a551716475c6332bdc4d4b4e3de0964aadb3092a10
2cb1ad3b22db8e3666ea138fee88034a87a87cf43db3d3265a675ebf221379b0
7d586fb7f94182a8e2a0e53c7e4deb898066da029da5cd9972a94a59ca6d255a
```

### Remediation

1. **Containment:** Immediately isolate any hosts with confirmed IOC matches from the network; revoke RMM/SysAid service account credentials
2. **Eradication:** Remove `C:\ProgramData\WinDir\` directory entirely; sweep for Cavern module DLLs across all managed endpoints; check IIS servers for cac.aspx webshell
3. **Recovery:** Rebuild compromised hosts from known-good images; rotate all credentials accessible from compromised systems, especially service accounts and DPAPI-protected secrets
4. **Secret rotation:** Force password reset for all domain accounts enumerated via LDAP; invalidate Kerberos tickets; rotate SQL database credentials
5. **RMM audit:** Review SysAid and other RMM software deployment logs for unauthorized package installations; verify RMM agent integrity

### Long-Term Hardening

- Implement application whitelisting to prevent DLL side-loading from non-standard paths (C:\ProgramData should not contain executable applications)
- Enable and monitor Sysmon Event ID 7 (Image Loaded) for DLL side-loading detection in security-critical environments
- Segment RMM/MSP network access using zero-trust principles; require MFA for all administrative RMM operations
- Monitor for .NET AppDomain creation/teardown anomalies via ETW (Event Tracing for Windows)
- Block or alert on DNS queries to newly registered domains with Iranian hosting providers
- Deploy TLS inspection to identify XOR-encoded payloads within HTTPS traffic where feasible

## Detection Rules

Four Sigma rules, two YARA rules, five Suricata rules, and two Snort rules target the Cavern Manticore framework. The Sigma and Suricata rules key on specific artifacts (C2 domains, DLL side-loading paths, module file names); the YARA rules detect malware samples via published mutex names, PDB paths, and C2 protocol strings. Snort is not installed in this environment; those rules received structural validation only.

### Sigma: Cavern DLL Side-Loading via WinDirStat from ProgramData

Detects WinDirStat.exe execution from the non-standard `C:\ProgramData\WinDir\` path used by Cavern Manticore for DLL side-loading.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy); sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Fields: Image (endswith + contains) on process_creation/windows — standard Sysmon EID 1 / Win 4688 fields. Path C:\ProgramData\WinDir\ is highly distinctive and not used by legitimate WinDirStat installations. No defanged values in rule. -->
```yaml
title: Cavern Manticore DLL Side-Loading via WinDirStat from ProgramData
id: 7a2b3c4d-5e6f-4a8b-9c1d-2e3f4a5b6c7d
status: experimental
description: >
    Detects execution of WinDirStat.exe from the non-standard path
    C:\ProgramData\WinDir\, used by Cavern Manticore for DLL side-loading
    of the trojanized uxtheme.dll agent.
references:
    - https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
    - https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html
author: Actioner
date: 2026/07/10
tags:
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\WinDirStat.exe'
        Image|contains: '\ProgramData\WinDir\'
    condition: selection
falsepositives:
    - Legitimate WinDirStat installation in non-standard ProgramData path (unlikely)
level: high
```

### Sigma: Cavern Agent DLL Loaded by WinDirStat from ProgramData

Detects the specific image-load event of uxtheme.dll from `C:\ProgramData\WinDir\` by WinDirStat.exe, the exact DLL side-loading chain used by Cavern Manticore.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Fields: Image (endswith), ImageLoaded (endswith + contains) on image_load/windows — Sysmon EID 7. Requires Sysmon with image_load logging enabled. Three-field AND is highly specific. -->
```yaml
title: Cavern Agent DLL Loaded by WinDirStat from ProgramData
id: 8b3c4d5e-6f7a-4b9c-ad1e-3f4a5b6c7d8e
status: experimental
description: >
    Detects WinDirStat.exe loading uxtheme.dll from C:\ProgramData\WinDir\,
    consistent with Cavern Manticore DLL side-loading chain where the
    trojanized uxtheme.dll contains the Cavern backdoor agent.
references:
    - https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
    - https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html
author: Actioner
date: 2026/07/10
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\WinDirStat.exe'
        ImageLoaded|endswith: '\uxtheme.dll'
        ImageLoaded|contains: '\ProgramData\WinDir\'
    condition: selection
falsepositives:
    - None expected in this specific path combination
level: critical
```

### Sigma: DNS Query to Cavern Manticore C2 Domains

Detects DNS resolution requests to known Cavern Manticore C2 infrastructure domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Field: QueryName (endswith) on dns_query — Sysmon EID 22. Three known C2 domains (hospitalinstallation.com, adserviceupdate.com, hygienehistory.com); endswith handles subdomain variants. Real (non-defanged) domain values in rule. -->
```yaml
title: DNS Query to Cavern Manticore C2 Domains
id: 9c4d5e6f-7a8b-4cad-be2f-4a5b6c7d8e9f
status: experimental
description: >
    Detects DNS queries to known Cavern Manticore C2 domains including
    hospitalinstallation.com and its subdomains, as well as legacy
    Cav3rn infrastructure domains adserviceupdate.com and hygienehistory.com.
references:
    - https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
    - https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html
author: Actioner
date: 2026/07/10
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'hospitalinstallation.com'
            - 'adserviceupdate.com'
            - 'hygienehistory.com'
    condition: selection
falsepositives:
    - None expected for these specific domains
level: critical
```

### Sigma: Cavern Manticore Module File Creation

Detects creation of known Cavern Manticore post-exploitation module DLLs with distinctive `n-` prefixed names (n-HTCommp.dll, n-ten.dll, n-sws.dll). Generic module names (db.dll, ode.dll, mhm.dll) were removed to avoid false positives from unrelated software.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: removed generic filenames \db.dll, \ode.dll, \mhm.dll per critic — too generic, will fire on unrelated software; kept only the three n-prefixed modules which are genuinely distinctive -->
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Field: TargetFilename (endswith) on file_event/windows — Sysmon EID 11. The n-prefixed modules are distinctive. -->
```yaml
title: Cavern Manticore Module File Creation
id: ad5e6f7a-8b9c-4dbe-cf3a-5b6c7d8e9f0a
status: experimental
description: >
    Detects creation of known Cavern Manticore post-exploitation module DLLs
    (n-HTCommp.dll, n-ten.dll, n-sws.dll) which use a distinctive n- prefix
    naming convention exclusive to this framework.
references:
    - https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
    - https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html
author: Actioner
date: 2026/07/10
tags:
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\n-HTCommp.dll'
            - '\n-ten.dll'
            - '\n-sws.dll'
    condition: selection
falsepositives:
    - Legitimate software using identically named DLLs with n- prefix (very unlikely)
level: medium
```

### Snort: Cavern Manticore C2 Beacon to /profile with X-User-token

Detects HTTP GET to /profile with the custom X-User-token header characteristic of Cavern Manticore C2 beacon check-ins.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- revision: capped confidence from high to medium — Snort not installed, cannot verify compilation -->
<!-- audit: Snort is NOT installed in this environment; structural validation only. Rule uses http service, http_method + http_uri + http_header sticky buffers. content:"/profile" at offset 0 depth 8 is tight. X-User-token is a non-standard HTTP header highly distinctive to this framework. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Cavern Manticore C2 Beacon to /profile with X-User-token"; flow:established, to_server; http_method; content:"GET"; http_uri; content:"/profile", fast_pattern, offset 0, depth 8; http_header; content:"X-User-token"; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created 2026-07-10; sid:2100001; rev:1;)
```

### Snort: Cavern Manticore C2 Exfil to /gallery with X-User-token

Detects HTTP POST to /gallery with the custom X-User-token header used by Cavern Manticore for data exfiltration and command result upload.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- revision: capped confidence from high to medium — Snort not installed, cannot verify compilation -->
<!-- audit: Snort is NOT installed in this environment; structural validation only. Same pattern as /profile rule but POST method + /gallery endpoint. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Cavern Manticore C2 Exfil to /gallery with X-User-token"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/gallery", fast_pattern, offset 0, depth 8; http_header; content:"X-User-token"; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created 2026-07-10; sid:2100002; rev:1;)
```

### Suricata: Cavern Manticore C2 Beacon to /profile Endpoint

Detects HTTP GET requests to the /profile endpoint with the custom X-User-token header, matching the Cavern Manticore primary C2 beacon pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses http protocol with dot-notation buffers (http.method, http.uri, http.request_header). X-User-token is a non-standard header highly specific to this framework. startswith on /profile constrains URI matching. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Cavern Manticore C2 Beacon to /profile Endpoint"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/profile"; startswith; fast_pattern; http.request_header; content:"X-User-token"; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created_at 2026-07-10; sid:2200001; rev:1;)
```

### Suricata: Cavern Manticore C2 Data Exfil to /gallery Endpoint

Detects HTTP POST requests to the /gallery endpoint with the custom X-User-token header, matching the Cavern Manticore data exfiltration pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Same buffer pattern as /profile rule. POST + /gallery + X-User-token is the exfil/result-upload verb in the Cavern protocol. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Cavern Manticore C2 Data Exfil to /gallery Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/gallery"; startswith; fast_pattern; http.request_header; content:"X-User-token"; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created_at 2026-07-10; sid:2200002; rev:1;)
```

### Suricata: DNS Query to Cavern Manticore C2 Domain hospitalinstallation.com

Detects DNS queries to the primary Cavern Manticore C2 domain hospitalinstallation.com (covers all subdomains).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dns protocol with dns.query buffer. nocase handles case variations. endswith not used because Suricata dns.query matches the full query name; substring match covers subdomains. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Cavern Manticore C2 Domain hospitalinstallation.com"; flow:to_server; dns.query; content:"hospitalinstallation.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created_at 2026-07-10; sid:2200003; rev:1;)
```

### Suricata: DNS Query to Cavern Manticore Legacy C2 Domain adserviceupdate.com

Detects DNS queries to the legacy Cav3rn C2 domain adserviceupdate.com used in earlier operations.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Same pattern as hospitalinstallation rule. Legacy domain but still valid for historical compromise detection. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Cavern Manticore Legacy C2 Domain adserviceupdate.com"; flow:to_server; dns.query; content:"adserviceupdate.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created_at 2026-07-10; sid:2200004; rev:1;)
```

### Suricata: DNS Query to Cavern Manticore Legacy C2 Domain hygienehistory.com

Detects DNS queries to the legacy Cav3rn C2 domain hygienehistory.com used in earlier operations.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Same pattern. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Cavern Manticore Legacy C2 Domain hygienehistory.com"; flow:to_server; dns.query; content:"hygienehistory.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/; metadata:author Actioner, created_at 2026-07-10; sid:2200005; rev:1;)
```

### YARA: Cavern Manticore Agent Detection

Detects the Cavern Manticore backdoor agent (uxtheme.dll) via distinctive mutex names (MYMUTEX123HELLP*), PDB path referencing developer username "rick", and developer frustration strings embedded in the binary.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. yara fired on constructed positive (MYMUTEX123HELLP02 + n-HTCommp.dll + config.txt + EnableThemeDialogTexture + delimiters from published CPR report); quiet on negative. Mutex strings are unique and not used by any known legitimate software. PDB path C:\Users\rick\Desktop\Modules\cavern\ is highly specific. Error strings are verbatim from CPR analysis. Condition: PE + filesize <10MB + (any mutex OR pdb OR error OR 2-of module/delim/export). -->
```yara
import "pe"

rule APT_Cavern_Manticore_Agent : cavern iran
{
    meta:
        description = "Detects Cavern Manticore backdoor agent (uxtheme.dll) via mutex names, developer artifacts, and module-loading strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        hash = "37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $mutex1 = "MYMUTEX123HELLP" ascii wide
        $mutex2 = "MYMUTEX123HELLP02" ascii wide
        $mutex3 = "MYMUTEX123HELLP04" ascii wide
        $pdb = "\\Users\\rick\\Desktop\\Modules\\cavern\\" ascii
        $err1 = "where is get_version" ascii wide
        $err2 = "DLL not found...Maybe you didn't upload it" ascii wide
        $mod1 = "n-HTCommp.dll" ascii wide
        $mod2 = "config.txt" ascii wide
        $delim1 = "_;;_" ascii wide
        $delim2 = "_,_" ascii wide
        $export = "EnableThemeDialogTexture" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($mutex*) or
            $pdb or
            (1 of ($err*)) or
            (2 of ($mod*, $delim*, $export))
        )
}
```

### YARA: Cavern Manticore Communication Module Detection

Detects the Cavern Manticore communication module (n-HTCommp.dll) via C2 endpoint URI patterns, the custom X-User-token header, fixed User-Agent string, and developer typos embedded in the NativeAOT binary.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. No sample test for this rule (CommModule rule did not fire on Agent-focused positive; would need a separate n-HTCommp.dll sample). The User-Agent string (Chrome/146+Edg/146) is distinctive but may appear in legitimate Edge browser traffic — the combination with X-User-token + /profile + /gallery is what makes the rule specific. The CAV3RN namespace string and typos ("receivecd", "handeling") are published verbatim by CPR and are highly unlikely in benign software. Condition: PE + filesize <10MB + (header+uri OR ua OR typo OR cfg+uri OR namespace). -->
```yara
import "pe"

rule APT_Cavern_Manticore_CommModule : cavern iran
{
    meta:
        description = "Detects Cavern Manticore communication module (n-HTCommp.dll) via C2 endpoint patterns and transport verb strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        hash = "a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41"
        tlp = "WHITE"
        severity = "high"

    strings:
        $uri1 = "/profile" ascii wide
        $uri2 = "/gallery" ascii wide
        $uri3 = "/socket" ascii wide
        $hdr = "X-User-token" ascii wide
        $ua = "Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0" ascii wide
        $typo1 = "tunnel message receivecd" ascii wide
        $typo2 = "handeling connect ms" ascii wide
        $cfg1 = "Cvn.cfg.A" ascii wide
        $cfg2 = "Cvn.cfg.U" ascii wide
        $ns = "CAV3RN" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($hdr and 1 of ($uri*)) or
            $ua or
            any of ($typo*) or
            (1 of ($cfg*) and 1 of ($uri*)) or
            $ns
        )
}
```

## Lessons Learned

1. **Multi-compilation-format evasion is effective.** Cavern Manticore's use of three distinct .NET compilation targets (IL-only, Mixed-Mode C++/CLI, NativeAOT) across components within a single framework is a novel approach that successfully defeats current AV/EDR solutions, as evidenced by near-zero VirusTotal detection rates. Detection teams should invest in tooling that can analyze NativeAOT binaries (e.g., ida-nativeaot) and should not rely solely on static signature-based detection for .NET malware.

2. **Supply-chain compromise through IT service providers remains a high-impact vector.** The multi-hop MSP-to-MSP-to-target pattern maximizes blast radius while minimizing the attacker's exposure. Organizations should audit RMM software deployment logs, enforce strict application whitelisting on RMM-managed endpoints, and implement zero-trust segmentation between MSP administrative access and production environments.

3. **DLL side-loading continues to evade detection.** The use of a legitimate, signed binary (WinDirStat.exe) deployed to a non-standard path bypasses application whitelisting that checks binary signatures but not deployment locations. Defenders should monitor for known-good binaries executing from unusual paths (especially `C:\ProgramData\`) and enable Sysmon Event ID 7 (Image Loaded) logging to detect suspicious DLL loads.

## Sources

- [Check Point Research: Cavern Manticore: Exposing Iran-Linked Modular C2 Framework](https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/) -- primary technical analysis with complete IOC list, module analysis, C2 protocol details, and MITRE ATT&CK mapping
- [The Hacker News: Iran-Linked Hackers Use New Cavern C2 Framework to Target Israeli Organizations](https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html) -- secondary reporting summarizing Check Point Research findings with additional context on related vulnerability exploitation
- [Infosecurity Magazine: New Iran-Nexus Hacking Group Targets Israel Government and IT Sectors](https://www.infosecurity-magazine.com/news/new-iran-hacking-group-targets/) -- supplementary coverage with attribution context and evasion technique details
- [GBHackers: Cavern Manticore Malware Uses Low-Detection .NET Modules for Reconnaissance and Lateral Movement](https://gbhackers.com/cavern-manticore-malware/) -- additional technical coverage of module capabilities and detection evasion

---
*Report generated by Actioner*
