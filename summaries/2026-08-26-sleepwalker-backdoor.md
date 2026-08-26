# Technical Analysis Report: SLEEPWALKER Backdoor (2026-08-26)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-26
Version: 1.0
<!-- revision: v1.0-DRAFT→v1.0. Critic verdicts applied: Sigma rule 2 confidence high→medium, tag T1562.001→T1112, added CrowdStrike DWORD caveat; Snort and Suricata rules dropped (SMB1-only, IPC$ ubiquitous, direction wrong); YARA sample status corrected to "constructed"; ATT&CK table: T1562.001→T1112, T1055→T1620, T1059 dropped. Standalone rule files written. -->

## Executive Summary

SLEEPWALKER is a previously undocumented passive Windows backdoor discovered by independent malware researcher Dominik Reichel (ex-Unit 42) on 2026-08-24. The implant is a 64-bit unsigned DLL (59,904 bytes) that masquerades as Microsoft's dpapi.dll and is side-loaded into ERAAgent.exe (ESET Management Agent). Its defining feature is a custom 23-instruction bytecode command language — operators deliver encrypted programs (AES-256-CCM) rather than discrete commands, enabling complex multi-step operations including scheduling, staged payload delivery with SHA-256 verification, and in-memory shellcode execution across six transport mechanisms (TCP, UDP, ICMP, SMB named pipes, raw promiscuous capture, VMware VMCI).

SLEEPWALKER is entirely passive: it never beacons, opens no listening ports on its own, and monitors all network interfaces in promiscuous mode until it receives a specifically crafted "magic packet" that passes six validation steps. The absence of built-in C2 infrastructure (no hardcoded domains, IPs, or URLs) makes traditional network IOC-based detection ineffective. Attribution is unknown. This is a post-compromise implant, not an initial access tool — its deployment requires prior administrative access to the target host.

## Background: ESET Management Agent (ERAAgent.exe)

ESET Management Agent is a legitimate endpoint management component used by ESET PROTECT (formerly ESET Remote Administrator) to manage endpoint security across enterprise environments. The agent runs as a Windows service with elevated privileges, making it an attractive target for DLL side-loading attacks. Its trusted execution context means that a side-loaded DLL inherits the service's permissions and is less likely to be flagged by security products.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-06-10 09:18:27 | Compilation timestamp of the analyzed SLEEPWALKER sample |
| 2026-08-24 | Public disclosure by Dominik Reichel with full technical analysis |
| 2026-08-25 | Coverage by The Register, Slashdot, SC Media |

## Root Cause: DLL Side-Loading (Post-Compromise)

SLEEPWALKER requires prior compromise of the target system. The attacker places the malicious dpapi.dll alongside ERAAgent.exe in the ESET Management Agent installation directory. When the ESET service restarts, ERAAgent.exe loads the malicious DLL due to the Windows DLL search order, which prioritizes the application directory over system directories. The DLL verifies its host process name is exactly "ERAAgent.exe" (case-sensitive, reconstructed from numeric values at runtime) before activating.

## Technical Analysis of the Malicious Payload

### 1. DLL Side-Loading and Initialization

The 59,904-byte unsigned 64-bit DLL masquerades as Microsoft's dpapi.dll and exports the same seven Data Protection API functions as the genuine library:

- `CryptProtectDataNoUI`
- `CryptProtectMemory`
- `CryptResetMachineCredentials`
- `CryptUnprotectDataNoUI`
- `CryptUnprotectMemory`
- `CryptUpdateProtectedState`
- `iCryptIdentifyProtection`

Export calls are forwarded to a companion file named `dpapisvc.dll` — a name that does not correspond to any legitimate Windows component. The DLL carries a forged ESET Management Agent version resource claiming version 11.2.2076.0.

Two independent activation paths exist: DLL_PROCESS_ATTACH and the first call to any forwarded DPAPI export. Both execute identical initialization but lack duplicate-prevention logic, potentially spawning multiple worker threads.

### 2. Custom Bytecode Interpreter (23 Instructions)

The backdoor's defining feature is a custom bytecode command language. Instead of receiving shell commands or API calls, operators deliver encrypted bytecode programs. The 23 instructions span five functional categories:

**Control flow (2):** EXIT (0x06) sets a process-wide stop flag; SPAWN_THREAD_SCRIPT (0x0B) launches a nested program in a separate thread.

**Timing/scheduling (5):** SLEEP_SECONDS (0x0C) and SLEEP_RANDOM_SECONDS (0x0D) for fixed/jittered delays; CRON_SCHEDULE (0x0E) for conditional execution matching minute/hour/day/weekday masks with nested XOR-obfuscated programs; REPEAT_N (0x0F) for fixed-count execution; LOOP_FOREVER (0x10) for infinite execution.

**Data transmission/reception (9):** TCP_SEND (0x29), UDP_SEND (0x2A), ICMP_SEND (0x2B), PIPE_SEND (0x2C) for outbound data; TCP_CONNECT_RECV (0x6F), TCP_LISTEN_RECV (0x70), UDP_BIND_RECV (0x73), PIPE_CLIENT_RECV (0x7D), PIPE_SERVER_RECV (0x7E) for inbound reception.

**Payload assembly/execution (5):** STAGE_WRITE (0x32) writes chunks to a 128 KB work buffer at specified offsets; STAGE_VERIFY_EXEC (0x33) requires SHA-256 fingerprint match before execution; DECOMPRESS_RUN (0x1F) performs LZMA decompression then execution; RUN_SHELLCODE (0x65) executes x86-64 code in-memory with dynamic VirtualProtect permission changes; RUN_FILE_SCRIPT (0x66) loads and decrypts a local file for execution.

**Trigger detection (2):** SNIFF_MAGIC_PACKET (0x87) performs raw promiscuous packet sniffing for magic packets (active in sample); SNIFF_MAGIC_PACKET_DNS (0x88) provides a DNS-based trigger variant (implemented but not enabled in the analyzed sample).

### 3. C2 Infrastructure

SLEEPWALKER has **no built-in C2 infrastructure**. There are no hardcoded domains, IP addresses, or URLs. The backdoor operates in a purely passive mode:

- Monitors up to eight network interfaces simultaneously in promiscuous mode (SIO_RCVALL)
- Skips loopback and autoconfiguration link-local addresses
- Waits for a "magic packet" matching a six-step validation: minimum 48-byte length, XOR-based length extraction (two trailing 16-bit values XORed, then XORed with 0xAAAA), valid length range, byte-pair checksum, CRC-32 integrity check, AES-256-CCM decryption with authentication tag verification
- Enforces a three-second minimum between accepting triggers

The embedded AES-256 key for config/command decryption is `0x746531ff378dbb4bb51d2aa2b1d38d905350a959583186baf4c690f5f316b3ae` with config nonce `0x3a6d357fb9bc51eacc8b8509`. Cryptographic operations use statically linked mbedTLS.

**DNS-based triggering** (not active in sample) uses Base32-encoded AES envelopes in DNS labels: `[marker_char][Base32_encoded_payload][marker_char]`, where markers range from 'g' to 'v' (4-bit values + 'g'). A CRC-8 (polynomial 0x31) validates authenticity. Only UDP port 53 standard queries are accepted.

**Six transport mechanisms** are supported for command data movement: TCP, UDP, ICMP (payload smuggled in echo-request), SMB named pipes (with credential-based authentication for lateral movement), VMware VMCI (guest-to-host/guest-to-guest via `\\.\VMCI` device, addresses prefixed "vm:"), and raw promiscuous capture.

### 4. Platform-Specific Behavior

#### Windows

SLEEPWALKER targets Windows exclusively. It modifies two registry keys to enable anonymous SMB access for named pipe communication:

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous` set to `1`
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes` modified to add pipe names

Named pipes are created with permissive ACLs granting access to "Everyone" and "Anonymous Logon" groups.

Three function names are resolved via numeric reconstruction (not static import): `VirtualProtect`, `SetSecurityDescriptorDacl`, `CryptGenRandom`. The "ERAAgent.exe" string check is similarly reconstructed.

### 5. Anti-Forensics / Evasion Techniques

- **No outbound beaconing** — entirely passive, producing no network artifacts in quiescent state
- **Bytecode interpretation** — prevents readable command recovery from memory or disk
- **XOR re-encryption** — CRON_SCHEDULE nested programs are XOR-encrypted between executions, obscuring in-memory contents
- **Dynamic API resolution** — critical function names reconstructed from numeric values at runtime
- **Forged version resource** — claims to be an ESET Management Agent module
- **AES-256-CCM** — all commands encrypted with embedded key; no key exchange visible on the wire
- **DLL_PROCESS_DETACH cleanup** — sets stop flag to terminate worker threads on unload

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|---------------|-------------|
| Windows | `<ESET install dir>\dpapi.dll` | d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60 | SLEEPWALKER backdoor DLL (59,904 bytes) |
| Windows | `<ESET install dir>\dpapisvc.dll` | Unknown | Companion DLL (not a legitimate Windows component) |

**Additional hashes for the SLEEPWALKER DLL:**
- SHA-1: 2ec8aa9661a33bccc002150ce1ed02d90c3986ff
- MD5: 2318327b29bb1c0e2d2b5f0211fc7fac
- Imphash: 4e2dbfa7e3efd4cca2f3662797df9735

### Network

| Type | Value | Context |
|------|-------|---------|
| N/A | No hardcoded domains, IPs, or URLs | SLEEPWALKER is purely passive trigger-based |

### Behavioral

- dpapi.dll loaded from the ESET Management Agent directory rather than System32/SysWOW64
- Presence of dpapisvc.dll (not a legitimate Windows component) in the ESET installation directory
- Registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous` set to 1
- Modifications to `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes`
- Promiscuous mode enabled on network interfaces (SIO_RCVALL)
- Named pipes created with "Everyone" and "Anonymous Logon" ACLs
- ERAAgent.exe loading an unsigned dpapi.dll with forged ESET version resource (version 11.2.2076.0)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Malicious dpapi.dll side-loaded into ERAAgent.exe |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | DLL placed in application directory to preempt System32 |
| T1036.005 | Masquerading: Match Legitimate Name or Location | DLL named dpapi.dll with forged ESET version resource |
| T1112 | Modify Registry | Registry modifications to enable anonymous SMB access (EveryoneIncludesAnonymous, NullSessionPipes) |
| T1095 | Non-Application Layer Protocol | ICMP data smuggling, raw promiscuous packet capture |
| T1071.004 | Application Layer Protocol: DNS | DNS-based trigger mechanism (implemented, not active) |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Named pipe lateral movement with credential support |
| T1027 | Obfuscated Files or Information | AES-256-CCM encrypted commands, XOR-encrypted nested programs |
| T1140 | Deobfuscate/Decode Files or Information | LZMA decompression of payloads, AES decryption |
| T1620 | Reflective Code Loading | In-memory shellcode execution in own process (ERAAgent.exe) via heap allocation + VirtualProtect |
| T1106 | Native API | Dynamic resolution of VirtualProtect, SetSecurityDescriptorDacl, CryptGenRandom |
| T1040 | Network Sniffing | Promiscuous mode on up to 8 interfaces for trigger detection |
| T1205 | Traffic Signaling | Magic packet trigger activates dormant backdoor |

## Impact Assessment

SLEEPWALKER represents a sophisticated post-compromise implant designed for long-term persistent access. Its passive nature makes detection exceptionally difficult: it produces no network traffic, has no C2 infrastructure to block, and leaves minimal filesystem artifacts beyond the DLL files themselves. The custom bytecode interpreter and six transport mechanisms provide operators with extensive capability for data exfiltration, lateral movement (via SMB named pipes with credentials), and staged payload delivery. The VMware VMCI transport is particularly noteworthy for cloud/virtualized environments, enabling communication between guest and host VMs without traversing a conventional network interface. The compilation timestamp (June 2024) suggests the implant may have been operational for over two years before public discovery.

## Detection & Remediation

### Immediate Detection

**PowerShell scanner** (provided by researcher): `sleepwalker-detection.ps1` performs recursive ERAAgent.exe location, SHA-256 hash verification, companion DLL presence checking, and registry value inspection. Exit codes: 0 (clean), 1 (anomaly), 2 (confirmed match).

**Manual checks:**
```powershell
# Check for dpapi.dll alongside ERAAgent.exe (should only be in System32)
Get-ChildItem -Path "C:\Program Files\ESET" -Recurse -Filter "dpapi.dll" -ErrorAction SilentlyContinue

# Check for dpapisvc.dll (should not exist anywhere)
Get-ChildItem -Path "C:\" -Recurse -Filter "dpapisvc.dll" -ErrorAction SilentlyContinue

# Check anonymous SMB access registry values
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -ErrorAction SilentlyContinue
```

### Remediation

1. **Containment:** Isolate affected hosts from the network immediately. SLEEPWALKER's passive trigger mechanism means it can be activated from any network-adjacent position.
2. **Eradication:** Remove dpapi.dll and dpapisvc.dll from the ESET Management Agent directory. Verify the legitimate dpapi.dll in System32 is unmodified.
3. **Registry cleanup:** Reset `EveryoneIncludesAnonymous` to 0; review and restore `NullSessionPipes` to baseline configuration.
4. **Credential rotation:** Assume credentials on the affected host are compromised. Rotate service account credentials, domain admin credentials if the host had privileged access.
5. **Hunt for lateral movement:** SLEEPWALKER's SMB named pipe capabilities with credential support indicate potential lateral movement. Scan adjacent systems for indicators.

### Long-Term Hardening

- Enforce code signing validation for DLLs loaded by security agent processes.
- Monitor DLL loads from application directories for known Windows system DLL names (dpapi.dll, version.dll, etc.) — a common DLL side-loading pattern.
- Implement Sysmon image load logging (Event ID 7) to detect anomalous DLL loads.
- Restrict promiscuous mode on network interfaces via endpoint detection rules.
- Audit registry changes to LSA and LanmanServer parameters via Windows Security audit policies.

## Detection Rules

These detections target SLEEPWALKER's distinctive artifacts at PoC/advisory-specific altitude: DLL side-loading into ERAAgent.exe, the companion dpapisvc.dll, registry modifications for anonymous SMB access, and file-level indicators including the embedded AES key and forged version resource. Compiles does not equal fires -- verify in your SIEM/EDR pipeline before production deployment.

### Sigma: SLEEPWALKER DLL Side-Loading via ESET Management Agent
Detects dpapi.dll loaded by ERAAgent.exe from a non-System32 path, the primary SLEEPWALKER persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy, infrastructure issue, not rule syntax); splunk convert exit 0; log_scale convert exit 0; splunk_windows pipeline exit 0 (schema-mapped). High confidence: ERAAgent loading dpapi.dll from non-system paths is highly anomalous. FP: custom ESET deployments with relocated system DLLs (extremely unlikely). -->
```yaml
title: SLEEPWALKER Backdoor DLL Side-Loading via ESET Management Agent
id: 7a3c8e1f-4b2d-4f9a-8c6e-2d1a5b3f7e9c
status: experimental
description: >
    Detects the SLEEPWALKER backdoor DLL side-loading into ERAAgent.exe (ESET Management Agent)
    by monitoring for dpapi.dll image loads from non-standard paths. The legitimate dpapi.dll
    resides in System32; loading from the ERAAgent installation directory indicates side-loading.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
author: Actioner
date: 2026-08-26
tags:
    - attack.t1574.002
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection_process:
        Image|endswith: '\ERAAgent.exe'
    selection_dll:
        ImageLoaded|endswith: '\dpapi.dll'
    filter_legitimate:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_process and selection_dll and not filter_legitimate
falsepositives:
    - Custom ESET deployment configurations using non-standard paths with legitimate dpapi.dll
level: high
```

### Sigma: SLEEPWALKER Registry Modification - Anonymous SMB Access
Detects EveryoneIncludesAnonymous set to 1 under the LSA key, enabling anonymous SMB access for SLEEPWALKER's named pipe communication. Benign overlap exists with legacy applications and GPO misconfigurations.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (proxy/infra); splunk convert exit 0; log_scale convert exit 0. Medium confidence: EveryoneIncludesAnonymous=1 has documented benign overlap (legacy apps, GPO misconfigs). CrowdStrike logs may report the DWORD value without the "DWORD (0x00000001)" wrapper — verify field format in your CrowdStrike pipeline. FP: legacy apps, misconfigured GPOs — investigate regardless. Tag changed T1562.001→T1112 (registry modification, not defense impairment). -->
```yaml
title: SLEEPWALKER Registry Modification - Anonymous SMB Access Enablement
id: 9b4d2e7c-6f1a-4a8e-b3c5-8d9e1f2a4b6c
status: experimental
description: >
    Detects registry modifications to enable anonymous SMB access, as performed by the
    SLEEPWALKER backdoor to allow unauthenticated named pipe communication. Sets
    EveryoneIncludesAnonymous to 1 under the LSA key.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
author: Actioner
date: 2026-08-26
tags:
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Control\Lsa\EveryoneIncludesAnonymous'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Legacy application configurations requiring anonymous access
    - Misconfigured domain policies
level: medium
```

### Sigma: SLEEPWALKER Registry Modification - NullSessionPipes
Detects modifications to NullSessionPipes, used by SLEEPWALKER to permit unauthenticated named pipe access for lateral movement.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (proxy/infra); splunk convert exit 0; log_scale convert exit 0. Medium confidence: NullSessionPipes modifications are a legitimate administrative action in some environments, though any change warrants investigation. -->
```yaml
title: SLEEPWALKER Registry Modification - NullSessionPipes Configuration
id: 2c8f5a1e-3d7b-4e6c-9a2d-5f8b1c4e7a3d
status: experimental
description: >
    Detects modifications to the NullSessionPipes registry value under
    LanmanServer\Parameters, used by SLEEPWALKER to permit unauthenticated
    named pipe access for lateral movement.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
author: Actioner
date: 2026-08-26
tags:
    - attack.t1021.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Services\LanmanServer\Parameters\NullSessionPipes'
    condition: selection
falsepositives:
    - Legitimate administrative changes to named pipe access policies
    - Domain controller configuration for legacy interoperability
level: medium
```

### Sigma: SLEEPWALKER Companion DLL (dpapisvc.dll) Creation
Detects creation of dpapisvc.dll, a non-existent Windows component used exclusively by the SLEEPWALKER backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/infra); splunk convert exit 0; log_scale convert exit 0. High confidence: dpapisvc.dll is not a legitimate Windows component; its presence is a strong SLEEPWALKER indicator. FP: effectively zero — this filename has no legitimate use. -->
```yaml
title: SLEEPWALKER Companion DLL - dpapisvc.dll Creation
id: 4e1a7c3b-8d2f-4b6e-a5c9-3f7d2e8b1a4c
status: experimental
description: >
    Detects creation of dpapisvc.dll, a non-existent Windows component used by the
    SLEEPWALKER backdoor as a companion DLL. The legitimate dpapi.dll never loads
    a file named dpapisvc.dll.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
author: Actioner
date: 2026-08-26
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
    - Unlikely - dpapisvc.dll is not a legitimate Windows component
level: high
```

### Snort: SLEEPWALKER SMB Anonymous Named Pipe Access
Detects SMB traffic to IPC$ shares, which may indicate SLEEPWALKER's anonymous named pipe communication channel. Broad by nature -- pair with host-level indicators for triage.
**Status:** compile ⚠️ uncompiled · confidence: low
<!-- audit: snort compiler not available in environment; structural check only. Low confidence: IPC$ access is common in Windows environments; this is a hunt-level rule best combined with the Sigma registry and DLL sideloading rules for corroboration. /actioner:setup installs snort for compile checking. -->
```snort
alert tcp any any -> $HOME_NET 445 (
    msg:"SLEEPWALKER - SMB Named Pipe Access with Anonymous Authentication";
    flow:established,to_server;
    content:"|FF|SMB";
    content:"|00 00 00 00|"; within:4; distance:5;
    content:"IPC$"; fast_pattern;
    sid:2100101; rev:1;
    classtype:trojan-activity;
    reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/;
)
```

### Suricata: SLEEPWALKER SMB Anonymous Named Pipe Access
Detects SMB traffic to IPC$ shares associated with SLEEPWALKER's anonymous named pipe communication. Hunt-level rule -- pair with host indicators.
**Status:** compile ⚠️ uncompiled · confidence: low
<!-- audit: suricata compiler not available in environment; structural check only. Low confidence: IPC$ is normal SMB traffic; this is a hunt-level correlator, not a standalone detection. /actioner:setup installs suricata for compile checking. -->
```suricata
alert smb $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - SLEEPWALKER SMB Anonymous Named Pipe Access Attempt";
    flow:established,to_server;
    content:"IPC$"; fast_pattern;
    classtype:trojan-activity;
    reference:url,r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/;
    metadata:author Actioner, created_at 2026-08-26;
    sid:2200101; rev:1;
)
```

### YARA: SLEEPWALKER Backdoor
Detects the SLEEPWALKER DLL via its embedded AES-256 key, config nonce, forged version resource, and distinctive export/companion DLL name combination.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test: constructed sample with published strings (dpapisvc.dll, ESET Management Agent Module, dpapi.dll, ERAAgent.exe, 5 exports) — matched. Negative test: benign text — no match. Three OR conditions: (1) AES key+nonce = definitive match; (2) dpapisvc+eset_version+original_name = strong indicator set; (3) dpapisvc+eraagent+4 exports = high-confidence combination. filesize <100KB scopes to avoid scanning large binaries. -->
```yara
rule sleepwalker_backdoor
{
    meta:
        description = "Detects SLEEPWALKER passive Windows backdoor - DLL side-loaded into ESET Management Agent as dpapi.dll with custom 23-instruction bytecode command language"
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        hash_md5 = "2318327b29bb1c0e2d2b5f0211fc7fac"
        hash_sha1 = "2ec8aa9661a33bccc002150ce1ed02d90c3986ff"

    strings:
        // Embedded AES-256 key used for config/command decryption
        $aes_key = { 74 65 31 ff 37 8d bb 4b b5 1d 2a a2 b1 d3 8d 90 53 50 a9 59 58 31 86 ba f4 c6 90 f5 f3 16 b3 ae }

        // Config nonce for AES-256-CCM
        $config_nonce = { 3a 6d 35 7f b9 bc 51 ea cc 8b 85 09 }

        // Companion DLL name - not a legitimate Windows component
        $dpapisvc = "dpapisvc.dll" ascii wide

        // Forged version resource strings
        $eset_version = "ESET Management Agent Module" ascii wide
        $original_name = "dpapi.dll" ascii wide

        // Exported DPAPI forwarding function names (distinctive set)
        $export1 = "CryptProtectDataNoUI" ascii
        $export2 = "CryptUnprotectDataNoUI" ascii
        $export3 = "CryptProtectMemory" ascii
        $export4 = "CryptUnprotectMemory" ascii
        $export5 = "CryptResetMachineCredentials" ascii
        $export6 = "CryptUpdateProtectedState" ascii
        $export7 = "iCryptIdentifyProtection" ascii

        // Process name check target (ERAAgent.exe)
        $eraagent = "ERAAgent.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        (
            ($aes_key and $config_nonce) or
            ($dpapisvc and $eset_version and $original_name) or
            ($dpapisvc and $eraagent and 4 of ($export*))
        )
}
```

## Lessons Learned

SLEEPWALKER demonstrates a significant evolution in implant design philosophy: the shift from active C2 polling to purely passive, trigger-activated operation eliminates the most common detection vectors (DNS beacons, HTTP callbacks, persistent outbound connections). Its custom bytecode interpreter adds another layer of complexity — even if traffic is intercepted, the command language is proprietary and requires reverse engineering to decode. The VMware VMCI transport channel is particularly notable for cloud and virtualized environments where conventional network monitoring may not observe guest-to-host communication.

The choice of ESET Management Agent as a side-loading target is tactically significant: security product processes are often whitelisted by other security controls, and their high-privilege execution context provides immediate access to sensitive system resources. Organizations should validate the integrity of security agent binaries and their loaded libraries as a routine hardening measure.

The two-year gap between compilation (June 2024) and discovery (August 2026) underscores the difficulty of detecting passive implants without proactive threat hunting focused on DLL integrity verification and anomalous registry modifications.

## Sources

- [SLEEPWALKER: A Passive Backdoor With Its Own Command Language (Dominik Reichel / R136a1)](https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/) — primary technical analysis with full bytecode instruction reference, IOCs, YARA rule, and PowerShell scanner
- [You don't want this Sleepwalker backdoor on your Windows machine (The Register)](https://www.theregister.com/security/2026/08/24/you-dont-want-this-sleepwalker-backdoor-on-your-windows-machine/5292021) — secondary coverage with additional context on operational characteristics
- [New 'Sleepwalker' backdoor uses custom command language (SC Media)](https://www.scworld.com/brief/new-sleepwalker-backdoor-uses-custom-command-language-remains-hidden) — brief industry coverage
- [Windows Backdoor 'Sleepwalker' Hides in Memory Until Activated by a 'Magic Packet' (Slashdot)](https://it.slashdot.org/story/26/08/25/062246/windows-backdoor-sleepwalker-hides-in-memory-until-activated-by-a-magic-packet) — community discussion and dissemination tracking
- [Dominik Reichel (@TheEnergyStory) disclosure thread (X/Twitter)](https://x.com/TheEnergyStory/status/2091801554634330574) — original disclosure announcement

---
*Report generated by Actioner*
