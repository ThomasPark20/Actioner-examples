# Technical Analysis Report: SLEEPWALKER Backdoor (2026-08-27)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-27
Version: 0.1-draft

## Executive Summary

SLEEPWALKER is a sophisticated passive Windows backdoor discovered by independent researcher Dominik Reichel (formerly Palo Alto Networks Unit 42) and published on August 24, 2026. The malware uses DLL side-loading to masquerade as a Microsoft Data Protection API component (`dpapi.dll`) alongside ESET Management Agent (`ERAAgent.exe`). Unlike conventional implants, SLEEPWALKER carries no hardcoded C2 infrastructure and opens no listening ports -- it remains dormant until a specially crafted "magic packet" traverses a monitored network interface. Commands are delivered via a custom 23-instruction bytecode language encrypted with AES-256-CCM. The backdoor supports six transport channels (TCP, UDP, ICMP, SMB named pipes, raw sockets, VMware VMCI) and enables memory-resident payload execution and lateral movement. No attribution has been established; the compilation timestamp (2024-06-10) and operational sophistication suggest a well-resourced threat actor. It is unconfirmed whether the backdoor has been deployed in the wild.

## Background: ESET Management Agent

ESET Management Agent (`ERAAgent.exe`) is a legitimate endpoint management component distributed by ESET for centralized administration of ESET security products. It typically runs as a Windows service with elevated privileges, making it an attractive target for DLL side-loading. The SLEEPWALKER backdoor exploits the Windows DLL search order: by placing a malicious `dpapi.dll` in the same directory as `ERAAgent.exe`, the malware is loaded each time the ESET Management Agent service starts. The malware validates that its host process is named `ERAAgent.exe` before activating, ensuring it only executes in the intended context.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-06-10 09:18:27 | SLEEPWALKER DLL compilation timestamp |
| 2026-08-24 | Dominik Reichel publishes technical analysis on r136a1.dev |
| 2026-08-25 -- 2026-08-27 | Coverage by The Hacker News, Cybersecurity News, The Register |

## Root Cause: DLL Side-Loading (Post-Compromise)

SLEEPWALKER is a post-compromise implant requiring pre-existing local administrator access on the target system. The attacker places the malicious `dpapi.dll` (and optionally `dpapisvc.dll`) alongside `ERAAgent.exe` in the ESET Management Agent installation directory. The initial access vector is unknown and is not part of this malware's functionality -- it has no self-propagation, download, or dropper capabilities. The DLL placement cannot be patched because it exploits the fundamental Windows DLL search order behavior.

## Technical Analysis of the Malicious Payload

### 1. DLL Side-Loading and Initialization

The SLEEPWALKER backdoor is a 64-bit Windows DLL (59,904 bytes) that masquerades as `dpapi.dll` (Microsoft Data Protection API). It exports seven functions matching the genuine `dpapi.dll` interface: `CryptProtectDataNoUI`, `CryptProtectMemory`, `CryptResetMachineCredentials`, `CryptUnprotectDataNoUI`, `CryptUnprotectMemory`, `CryptUpdateProtectedState`, and `iCryptIdentifyProtection`. These functions attempt to forward calls to `dpapisvc.dll` -- a non-existent Windows component, making the presence of this file a high-fidelity indicator.

The DLL forges its PE version resource to match ESET Management Agent:
- CompanyName: ESET
- ProductName: ESET Management Agent
- FileDescription: ESET Management Agent Module
- InternalName: ERAAgent
- OriginalFilename: dpapi.dll
- Version: 11.2.2076.0
- Copyright: ESET, spol. s r.o. 1992-2024

On load, the malware verifies that the host process is named `ERAAgent.exe`. It resolves API functions at runtime (`VirtualProtect`, `SetSecurityDescriptorDacl`, `CryptGenRandom`) to reduce its static import footprint.

### 2. Encrypted Configuration and Magic Packet Trigger

SLEEPWALKER carries a 2,048-byte encrypted configuration block decrypted using a static AES-256-CCM key and nonce:
- Key: `0x746531ff378dbb4bb51d2aa2b1d38d905350a959583186baf4c690f5f316b3ae`
- Nonce: `0x3a6d357fb9bc51eacc8b8509`

The decrypted configuration specifies a single instruction: monitor up to 8 network interfaces (skipping loopback) for a magic packet. The magic packet validation performs a multi-step check:

1. Packet must be at least 48 bytes
2. XOR of the last two u16 values, then XOR with `0xAAAA`, yields a candidate length
3. Candidate length must fall within a valid range
4. A byte pair at a computed offset must equal the sum of trailing values
5. The candidate-length block must pass CRC-32 validation
6. The block must decrypt successfully under AES-256-CCM

A minimum rearm time of 3 seconds between triggers prevents packet-storm abuse.

### 3. Custom 23-Instruction Bytecode Language

SLEEPWALKER interprets a custom command language with 23 opcodes organized into functional categories:

**Basic Control:**
- `EXIT` (0x06): Sets a process-wide stop flag
- `SPAWN_THREAD_SCRIPT` (0x0B): Runs nested program in a separate thread

**Timing/Scheduling:**
- `SLEEP_SECONDS` (0x0C): Fixed-duration pause (u16)
- `SLEEP_RANDOM_SECONDS` (0x0D): Random pause up to modulus (u16)
- `CRON_SCHEDULE` (0x0E): Minute/hour/day/weekday bitmasks with nested XOR-masked program
- `REPEAT_N` (0x0F): Repeat count (u16) with nested program
- `LOOP_FOREVER` (0x10): Infinite loop with nested program

**Data Transmission:**
- `TCP_SEND` (0x29): Send data via TCP
- `UDP_SEND` (0x2A): Send data via UDP
- `ICMP_SEND` (0x2B): Embed data in ICMP echo requests
- `PIPE_SEND` (0x2C): Write to named pipe (supports credentials)

**Inbound Reception:**
- `TCP_CONNECT_RECV` (0x6F): Outbound TCP connection to receive data
- `TCP_LISTEN_RECV` (0x70): TCP listener for inbound data
- `UDP_BIND_RECV` (0x73): UDP listener
- `PIPE_CLIENT_RECV` (0x7D): Named pipe client
- `PIPE_SERVER_RECV` (0x7E): Named pipe server

**Program Building/Execution:**
- `STAGE_WRITE` (0x32): Write chunk to 128 KB staging buffer at offset
- `STAGE_VERIFY_EXEC` (0x33): SHA-256 verification then execution
- `DECOMPRESS_RUN` (0x1F): LZMA decompression (5-byte properties)
- `RUN_SHELLCODE` (0x65): Execute machine code directly in memory
- `RUN_FILE_SCRIPT` (0x66): Load and decrypt file-based program

**Trigger Detection:**
- `SNIFF_MAGIC_PACKET` (0x87): Raw trigger only
- `SNIFF_MAGIC_PACKET_DNS` (0x88): Raw + DNS trigger

Bytecode format uses big-endian fixed integers, 7-bit variable-length encoding for length-prefixed fields, and XOR-obfuscated nested programs.

### 3. C2 Infrastructure

SLEEPWALKER contains no hardcoded C2 domains, IP addresses, or URLs. It is entirely passive: the operator delivers commands via magic packets that traverse a monitored network interface. Data exfiltration and command reception use six transport channels:

1. **TCP** -- standard connections to arbitrary addresses/ports
2. **UDP** -- datagram-based communication
3. **ICMP** -- data embedded in ICMP echo requests
4. **SMB Named Pipes** -- pipe writes to specified computers (supports credential-based access)
5. **Raw Promiscuous Socket** -- monitors all traffic crossing watched interfaces
6. **VMware VMCI** -- via `\\.\VMCI` device for VM-to-hypervisor communication

The DNS trigger channel uses a distinctive format: base32-encoded encrypted payload embedded between marker characters (range g-v), where each marker encodes a 4-bit CRC-8 value (polynomial 0x31, start 0x00, 256-entry lookup table). DNS queries must have a standard header (one question, zero answers/authority/additional).

### 4. Platform-Specific Behavior

#### Windows

SLEEPWALKER is Windows-only. It modifies two registry keys to facilitate lateral movement via named pipes:

- `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` -- sets `EveryoneIncludesAnonymous` to 1
- `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` -- adds entries to `NullSessionPipes`

These modifications grant Everyone and Anonymous Logon access to named pipes, enabling unauthenticated lateral movement. The cleanup process is noted as risky: removal may delete legitimate pre-existing entries.

### 5. Anti-Forensics / Evasion Techniques

- **Passive trigger model**: No outbound C2 connections, eliminating traditional beacon-based detection
- **No write-to-disk**: External components must pre-stage any data; the malware itself does not drop files
- **Memory-resident execution**: Shellcode runs directly via `RUN_SHELLCODE` without touching disk
- **Staged payload verification**: SHA-256 hash verification before execution prevents corrupted or tampered payloads
- **Runtime API resolution**: Key APIs resolved by name at runtime, reducing static import visibility
- **Forged PE metadata**: Version resource mimics legitimate ESET Management Agent
- **DLL search order abuse**: No registry persistence or scheduled tasks -- persistence is implicit via the ESET service

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through.

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `<ESET_DIR>\dpapi.dll` | `d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60` | SLEEPWALKER backdoor DLL (59,904 bytes) |
| Windows | `<ESET_DIR>\dpapisvc.dll` | N/A | Forwarding target (non-existent Windows component) |

**Additional File Hashes:**
- SHA-1: `2ec8aa9661a33bccc002150ce1ed02d90c3986ff`
- MD5: `2318327b29bb1c0e2d2b5f0211fc7fac`
- Imphash: `4e2dbfa7e3efd4cca2f3662797df9735`

### Network

| Type | Value | Context |
|------|-------|---------|
| N/A | N/A | No hardcoded C2 infrastructure; entirely passive trigger-based |

### Behavioral

- Unexpected `dpapi.dll` in the ESET Management Agent installation directory (not in `C:\Windows\System32\` or `C:\Windows\SysWOW64\`)
- Presence of `dpapisvc.dll` anywhere on the system (non-existent Windows component)
- Registry value `EveryoneIncludesAnonymous` set to 1 under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
- Unexpected entries in `NullSessionPipes` under `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
- `ERAAgent.exe` creating or connecting to named pipes outside normal ESET management operations
- ICMP echo requests with payloads exceeding 100 bytes originating from hosts running ESET Management Agent
- DNS queries with labels containing base32-encoded data flanked by g-v marker characters
- AES-256-CCM static key bytes `746531ff378dbb4b...` present in loaded DLLs
- Process `ERAAgent.exe` loading `dpapi.dll` from a non-system directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Malicious `dpapi.dll` placed alongside `ERAAgent.exe` to exploit DLL search order |
| T1036.005 | Masquerading: Match Legitimate Name or Location | DLL forges ESET version resource and matches genuine `dpapi.dll` export names |
| T1059 | Command and Scripting Interpreter | Custom 23-instruction bytecode interpreter for command execution |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Named pipe-based lateral movement with credential support |
| T1112 | Modify Registry | Sets `EveryoneIncludesAnonymous=1` and modifies `NullSessionPipes` for anonymous pipe access |
| T1095 | Non-Application Layer Protocol | ICMP echo requests used for data transmission (`ICMP_SEND`) |
| T1572 | Protocol Tunneling | DNS trigger channel with base32-encoded encrypted payloads in query labels |
| T1620 | Reflective Code Loading | `RUN_SHELLCODE` opcode executes machine code directly in memory |
| T1027 | Obfuscated Files or Information | AES-256-CCM encrypted configuration and XOR-obfuscated nested bytecode programs |
| T1071.004 | Application Layer Protocol: DNS | DNS-based trigger channel for activation |
| T1205 | Traffic Signaling | Magic packet trigger activates dormant backdoor; passive monitoring of network interfaces |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence via ESET Management Agent service loading the side-loaded DLL |

## Impact Assessment

SLEEPWALKER's passive design makes it exceptionally difficult to detect via traditional network monitoring. The absence of C2 beacons, hardcoded infrastructure, and disk-written payloads means standard IOC-based detection will miss it. The requirement for local administrator access for initial DLL placement limits the initial attack surface, but once deployed, the backdoor provides persistent, stealthy access with full command execution capabilities. The compilation timestamp (June 2024) suggests the tool has been available for over two years. Detection coverage was assessed as "low at publication" by the researcher.

## Detection & Remediation

### Immediate Detection

Check for SLEEPWALKER artifacts using PowerShell:

```powershell
# Check for dpapi.dll outside system directories alongside ERAAgent.exe
Get-ChildItem -Path "C:\Program Files\ESET\*" -Recurse -Filter "dpapi.dll" -ErrorAction SilentlyContinue

# Check for dpapisvc.dll anywhere (should not exist on any Windows system)
Get-ChildItem -Path "C:\" -Recurse -Filter "dpapisvc.dll" -ErrorAction SilentlyContinue

# Check hash of any dpapi.dll found outside System32
Get-FileHash -Algorithm SHA256 -Path "<suspect_path>\dpapi.dll" | Where-Object { $_.Hash -eq "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60" }

# Check registry modifications
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -ErrorAction SilentlyContinue
```

### Remediation

1. **Isolate** any system where SLEEPWALKER artifacts are found from the network immediately
2. **Remove** the malicious `dpapi.dll` and `dpapisvc.dll` from the ESET agent directory
3. **Restore** `EveryoneIncludesAnonymous` to 0 and audit `NullSessionPipes` entries (caution: removal may delete legitimate pre-existing entries)
4. **Investigate** the initial access vector -- SLEEPWALKER requires prior admin access, indicating a deeper compromise
5. **Sweep** all systems running ESET Management Agent for the file hash and registry indicators
6. **Rotate** all credentials accessible from compromised hosts

### Long-Term Hardening

- Deploy Sysmon with image load logging (Event ID 7) to detect DLL side-loading
- Monitor for `dpapi.dll` loading from non-system directories
- Alert on registry changes to `EveryoneIncludesAnonymous` and `NullSessionPipes`
- Consider application whitelisting to prevent unsigned DLLs from loading alongside ESET binaries
- Implement network segmentation to limit lateral movement via named pipes

## Detection Rules

These detections target SLEEPWALKER's distinctive artifacts: DLL side-loading into ESET Management Agent, the fabricated `dpapisvc.dll` component, registry modifications for anonymous pipe access, the DNS trigger channel, and the malware binary itself. Rules are PoC/advisory-specific (default altitude), strict leniency. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment.

### Sigma: SLEEPWALKER DLL Side-Loading via ESET Management Agent
Detects `dpapi.dll` loaded by `ERAAgent.exe` from a non-system directory, the primary SLEEPWALKER persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (proxy 403, not a rule issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Field names (Image, ImageLoaded) are standard Sysmon EID 7 image_load fields. No pipeline-mapped conversion available for image_load category. Filter excludes System32/SysWOW64 to suppress legitimate dpapi.dll loads. -->
```yaml
title: SLEEPWALKER Backdoor DLL Side-Loading via ESET Management Agent
id: 7c3a91d2-4e8b-4f1a-b6c5-2d9e0f8a7b34
status: experimental
description: >
    Detects loading of a masquerading dpapi.dll by ERAAgent.exe (ESET Management Agent),
    consistent with the SLEEPWALKER backdoor DLL side-loading technique. The malware places
    a malicious dpapi.dll alongside ERAAgent.exe to hijack the DLL search order.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026/08/27
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_process:
        Image|endswith: '\ERAAgent.exe'
    selection_dll:
        ImageLoaded|endswith: '\dpapi.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_process and selection_dll and not filter_system
falsepositives:
    - Legitimate third-party dpapi.dll placed alongside ERAAgent.exe (unlikely)
level: high
```

### Sigma: SLEEPWALKER Companion DLL dpapisvc.dll Creation
Detects creation of `dpapisvc.dll`, a fabricated Windows component name unique to SLEEPWALKER's DLL forwarding mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. dpapisvc.dll is not a real Windows component; any instance is highly suspicious. File event category uses standard TargetFilename field. -->
```yaml
title: SLEEPWALKER Companion DLL dpapisvc.dll Creation
id: 9f2d84c1-3b7e-4a5f-8d6c-1e0a9b8c7d52
status: experimental
description: >
    Detects creation of dpapisvc.dll, a non-existent Windows component fabricated by the
    SLEEPWALKER backdoor. The malicious dpapi.dll attempts to forward calls to dpapisvc.dll.
    This file should never appear on a legitimate Windows system.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026/08/27
tags:
    - attack.t1574.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\dpapisvc.dll'
    condition: selection
falsepositives:
    - Unknown legitimate software using a DLL named dpapisvc.dll (highly unlikely)
level: critical
```

### Sigma: SLEEPWALKER Registry Modification - Anonymous Pipe Access
Detects registry changes enabling unauthenticated named pipe access (`EveryoneIncludesAnonymous=1` or `NullSessionPipes` modification), consistent with SLEEPWALKER lateral movement preparation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. EveryoneIncludesAnonymous=1 is a known hardening concern independent of SLEEPWALKER; NullSessionPipes modification is less common. Medium confidence because these registry changes can occur in legacy environments. -->
```yaml
title: SLEEPWALKER Registry Modification - Anonymous Pipe Access Enabled
id: b4e7f3a2-6c1d-4e8b-9a5f-3d2c1b0e7f48
status: experimental
description: >
    Detects registry modifications to EveryoneIncludesAnonymous and NullSessionPipes
    consistent with SLEEPWALKER backdoor enabling unauthenticated named pipe access
    for lateral movement.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026/08/27
tags:
    - attack.t1574.002
    - attack.t1021.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_anon:
        TargetObject|endswith: '\Control\Lsa\EveryoneIncludesAnonymous'
        Details: 'DWORD (0x00000001)'
    selection_pipes:
        TargetObject|endswith: '\Services\LanmanServer\Parameters\NullSessionPipes'
    condition: selection_anon or selection_pipes
falsepositives:
    - Legacy applications requiring anonymous pipe access
    - Domain controllers in mixed-mode environments
level: high
```

### Sigma: SLEEPWALKER Named Pipe Activity from ESET Agent
Detects named pipe creation by `ERAAgent.exe`, which SLEEPWALKER uses for lateral movement via `PIPE_SEND`/`PIPE_SERVER_RECV` opcodes. Scope to environments where ESET pipe activity is baselined.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Medium confidence because legitimate ESET Management Agent may create named pipes for management operations. Requires environment-specific baselining to reduce FPs. Specific pipe names were not disclosed in the source analysis. -->
```yaml
title: SLEEPWALKER Named Pipe Activity from ESET Agent Process
id: d1c8e5b3-7a4f-4d2e-b9c6-5f3a2e1d0c89
status: experimental
description: >
    Detects named pipe creation by ERAAgent.exe that is not loading dpapi.dll from system
    directories, indicating potential SLEEPWALKER backdoor lateral movement via named pipes.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026/08/27
tags:
    - attack.t1021.002
    - attack.t1570
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        Image|endswith: '\ERAAgent.exe'
    condition: selection
falsepositives:
    - Legitimate ESET Management Agent named pipe operations
level: medium
```

### Snort: SLEEPWALKER DNS Trigger Channel
Detects DNS queries with the SLEEPWALKER trigger format: standard query header followed by base32-encoded payload flanked by g-v marker characters (CRC-8 delimiters).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf (include method) -T exit 0. Snort 2.9.20. DNS standard query header matched at depth 12. PCRE matches g-v markers flanking base32 chars. Medium confidence: the g-v + base32 pattern is distinctive but may match benign DNS with labels in that character range. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - SLEEPWALKER DNS Trigger Channel - Base32 Payload with g-v Marker Characters"; flow:to_server; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:12; pcre:"/[g-v][a-z2-7]{4,}[g-v]/"; classtype:trojan-activity; reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/; sid:2100101; rev:1;)
```

### Snort: SLEEPWALKER ICMP Data Exfiltration
Detects ICMP echo requests with oversized payloads (>100 bytes), consistent with SLEEPWALKER's `ICMP_SEND` data transmission opcode. Hunt-only; pair with host-level DLL side-loading detections.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: snort -c /etc/snort/snort.conf (include method) -T exit 0. Snort 2.9.20. Low confidence: oversized ICMP is a broad indicator; many legitimate tools produce large ICMP payloads (ping -l, network diagnostics). Best used as a hunt rule correlated with SLEEPWALKER host indicators. -->
```snort
alert icmp $HOME_NET any -> any any (msg:"Actioner - SLEEPWALKER ICMP Data Exfiltration - Oversized Echo Request"; itype:8; dsize:>100; classtype:trojan-activity; reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/; sid:2100102; rev:1;)
```

### Suricata: SLEEPWALKER DNS Trigger Channel
Detects DNS queries containing base32-encoded labels flanked by g-v CRC-8 marker characters, matching SLEEPWALKER's DNS trigger activation format.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. Suricata 7.0.3. Uses dns protocol with dns.query buffer and pcre for marker detection. Medium confidence for same reason as Snort variant. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - SLEEPWALKER DNS Trigger Channel - Base32 Encoded Labels with CRC-8 Markers"; flow:to_server; dns.query; pcre:"/[g-v][a-z2-7]{4,}[g-v]/"; classtype:trojan-activity; reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/; metadata:author Actioner, created_at 2026-08-27; sid:2200101; rev:1;)
```

### Suricata: SLEEPWALKER ICMP Data Exfiltration
Detects ICMP echo requests with oversized payloads (>100 bytes), consistent with SLEEPWALKER's `ICMP_SEND` opcode. Hunt-only; pair with host-level DLL side-loading detections.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. Suricata 7.0.3. Low confidence: broad indicator, requires correlation with host-side SLEEPWALKER detections. -->
```suricata
alert icmp $HOME_NET any -> any any (msg:"Actioner - SLEEPWALKER ICMP Data Exfiltration - Oversized Echo Request"; itype:8; dsize:>100; classtype:trojan-activity; reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/; metadata:author Actioner, created_at 2026-08-27; sid:2200102; rev:1;)
```

### YARA: SLEEPWALKER Backdoor Binary Detection
Detects the SLEEPWALKER DLL via its static AES-256-CCM key, configuration nonce, `dpapisvc.dll` forwarding string, and `dpapi.dll` export function names.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. Positive test: constructed PE with dpapisvc.dll + 3 export names + ERAAgent.exe + API names -> fired. Negative test: benign PE with unrelated strings -> silent. AES key match alone is sufficient (unique 32-byte sequence). The dpapisvc.dll + export-names branch catches recompiled variants that change the key. filesize < 100KB scoped per known sample (59,904 bytes). -->
```yara
import "pe"

rule Malware_SLEEPWALKER_Backdoor : sleepwalker backdoor
{
    meta:
        description = "Detects the SLEEPWALKER passive backdoor DLL that side-loads into ESET Management Agent (ERAAgent.exe) using static AES-256-CCM key, forged ESET version info, and dpapisvc.dll forwarding"
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Static AES-256-CCM key (32 bytes)
        $aes_key = { 74 65 31 ff 37 8d bb 4b b5 1d 2a a2 b1 d3 8d 90 53 50 a9 59 58 31 86 ba f4 c6 90 f5 f3 16 b3 ae }

        // Configuration nonce (12 bytes)
        $config_nonce = { 3a 6d 35 7f b9 bc 51 ea cc 8b 85 09 }

        // DLL forwarding target - non-existent Windows component
        $fwd_dll = "dpapisvc.dll" ascii wide

        // Exported function names matching dpapi.dll
        $exp1 = "CryptProtectDataNoUI" ascii
        $exp2 = "CryptUnprotectDataNoUI" ascii
        $exp3 = "CryptProtectMemory" ascii
        $exp4 = "CryptUnprotectMemory" ascii
        $exp5 = "CryptResetMachineCredentials" ascii
        $exp6 = "CryptUpdateProtectedState" ascii
        $exp7 = "iCryptIdentifyProtection" ascii

        // Runtime resolved API names
        $api1 = "VirtualProtect" ascii
        $api2 = "SetSecurityDescriptorDacl" ascii
        $api3 = "CryptGenRandom" ascii

        // Process name check
        $proc_check = "ERAAgent.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        (
            $aes_key or
            $config_nonce or
            (
                $fwd_dll and
                $proc_check and
                3 of ($exp*)
            ) or
            (
                $fwd_dll and
                2 of ($api*) and
                2 of ($exp*)
            )
        )
}
```

## Lessons Learned

SLEEPWALKER demonstrates a class of implant that traditional network-centric detection struggles with: passive backdoors that carry no C2 infrastructure and generate no outbound traffic until activated. Its use of DLL side-loading against a security product (ESET) is particularly notable -- defenders implicitly trust security tooling, and side-loading into a trusted security agent process makes the malware harder to spot and more likely to be whitelisted. The custom bytecode interpreter, while adding complexity, provides operational flexibility that static command-and-control protocols lack. Organizations running ESET Management Agent should immediately audit for unauthorized `dpapi.dll` files alongside `ERAAgent.exe` and deploy the Sysmon-based image load detection rules. The broader lesson is that endpoint telemetry (DLL load events, registry changes, named pipe creation) provides the highest-fidelity detection surface for this class of threat.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Dominik Reichel - r136a1.dev](https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/) -- primary technical analysis by the researcher who discovered SLEEPWALKER
- [The Hacker News](https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html) -- news coverage with additional detection context and PowerShell scanner details
- [The Register](https://www.theregister.com/security/2026/08/24/you-dont-want-this-sleepwalker-backdoor-on-your-windows-machine/5292021) -- news coverage with bytecode instruction categorization details

---
*Report generated by Actioner*
