# Technical Analysis Report: SLEEPWALKER Backdoor (2026-08-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-28
Version: 1.0 (DRAFT)

## Executive Summary

SLEEPWALKER is a previously undocumented, passive Windows backdoor that side-loads into the ESET Management Agent (ERAAgent.exe) by masquerading as Microsoft's dpapi.dll. Once loaded, it decrypts an embedded AES-256-CCM bootstrap configuration and enters an indefinite passive monitoring state, sniffing all network interfaces using raw promiscuous sockets (SIO_RCVALL) without opening any listening ports or initiating outbound connections. Activation requires a specifically crafted "magic packet" that passes a multi-step cryptographic validation chain. Upon activation, it executes commands encoded in a custom 23-instruction bytecode language capable of scheduling, staged payload delivery with SHA-256 integrity verification, direct in-memory shellcode execution, and communication over six transport channels (TCP, UDP, ICMP, SMB named pipes, raw capture, and VMware VMCI).

The backdoor was discovered by independent researcher Dominik Reichel (formerly Palo Alto Networks Unit 42) and published on August 24, 2026. No attribution to a known threat actor has been established. The approach -- a passive listener with encrypted triggers, no disk-writing instructions, and an in-memory bytecode interpreter -- is consistent with a targeted, well-resourced espionage operation rather than opportunistic activity. No victim, industry, or country has been identified, and it remains unclear whether the sample was ever operationally deployed.

## Background: ESET Management Agent Side-Loading

The ESET Management Agent (ERAAgent.exe) is a legitimate endpoint management component widely deployed in enterprise environments. SLEEPWALKER exploits the Windows DLL search order -- not any vulnerability in ESET's software -- by placing a malicious dpapi.dll in the same directory as ERAAgent.exe. When the agent service starts, Windows loads the attacker's DLL before the legitimate System32 copy. The malicious DLL exports all seven genuine DPAPI functions (forwarding them to a non-existent "dpapisvc.dll") and carries forged ESET version information to blend in. Local administrator rights are required to write the DLL to the ESET installation directory, making this a post-compromise persistence implant rather than an initial access vector.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-06-10 09:18:27 | PE compilation timestamp of the analyzed SLEEPWALKER sample |
| 2026-08-11 | YARA detection rule authored by Dominik Reichel |
| 2026-08-24 | Public disclosure of technical analysis at r136a1[.]dev |
| 2026-08-26 | The Hacker News coverage; ESET had issued no public advisory as of this date |

## Root Cause: DLL Search-Order Hijacking

The attacker places a malicious dpapi.dll alongside the legitimate ERAAgent.exe binary. When the ESET Management Agent Windows service starts (or restarts), the operating system's DLL search order loads the local dpapi.dll before the legitimate copy in System32. No exploit or vulnerability in ESET software is required -- only the ability to write a file to the ESET installation directory, which requires local administrator privileges. The malware validates it is running inside `ERAAgent.exe` by reconstructing the process name from numerical constants (not stored as a readable string) before activating.

## Technical Analysis of the Malicious Payload

### 1. DLL Side-Loading and Initialization

The malicious dpapi.dll is an unsigned 64-bit Windows DLL (59,904 bytes) with forged version information claiming to be "ESET Management Agent Module" version 11.2.2076.0. It exports seven genuine DPAPI functions that forward to `dpapisvc.dll` (a non-existent Windows component):

- `CryptProtectDataNoUI`
- `CryptProtectMemory`
- `CryptResetMachineCredentials`
- `CryptUnprotectDataNoUI`
- `CryptUnprotectMemory`
- `CryptUpdateProtectedState`
- `iCryptIdentifyProtection`

The initialization sequence: (1) check if host process name matches "ERAAgent.exe" (string rebuilt from numeric constants); (2) spawn a background thread; (3) allocate a 128 KB staging buffer; (4) decrypt the embedded bootstrap instruction using AES-256-CCM; (5) execute the bootstrap via the bytecode interpreter. Dual activation paths exist (DllMain and first exported function call) with no duplicate-detection logic.

### 2. Custom Bytecode Interpreter (23 Instructions)

The backdoor's defining feature is a compact bytecode interpreter with 23 instructions organized into seven functional categories:

**Control (2):** EXIT (0x06) sets a process-wide stop flag; SPAWN_THREAD_SCRIPT (0x0B) runs a nested program in a separate thread.

**Scheduling (5):** SLEEP_SECONDS (0x0C), SLEEP_RANDOM_SECONDS (0x0D, jittered), CRON_SCHEDULE (0x0E, cron-style with minute/hour/day/weekday masks), REPEAT_N (0x0F), LOOP_FOREVER (0x10). Scheduled programs use XOR re-encryption between executions.

**Data Transmission (4):** TCP_SEND (0x29), UDP_SEND (0x2A), ICMP_SEND (0x2B, data embedded in echo-request payloads), PIPE_SEND (0x2C, SMB named pipe with optional credentials). TCP and UDP support VMware VMCI targets via `vm:contextID` syntax.

**Inbound Reception (5):** TCP_CONNECT_RECV (0x6F), TCP_LISTEN_RECV (0x70), UDP_BIND_RECV (0x73), PIPE_CLIENT_RECV (0x7D), PIPE_SERVER_RECV (0x7E). All support deadlines and VMCI where applicable.

**Program Building/Execution (5):** STAGE_WRITE (0x32, writes to 128 KB buffer at offset), STAGE_VERIFY_EXEC (0x33, SHA-256 verification before execution), DECOMPRESS_RUN (0x1F, LZMA decompression then execution), RUN_SHELLCODE (0x65, direct x86-64 code execution via VirtualProtect), RUN_FILE_SCRIPT (0x66, reads encrypted file from disk).

**Trigger Detection (2):** SNIFF_MAGIC_PACKET (0x87, raw packets only), SNIFF_MAGIC_PACKET_DNS (0x88, raw packets plus DNS-based triggers).

Critically, no instruction in the language writes to disk -- all filesystem data must be pre-placed by companion components.

### 3. C2 Infrastructure

SLEEPWALKER has no embedded C2 domains, IP addresses, or URLs. It initiates no outbound connections independently. Communication is entirely passive until triggered:

**Magic Packet Trigger:** A six-step validation process -- (1) packet >= 48 bytes; (2) XOR trailing 16-bit values to compute candidate length; (3) validate length range; (4) byte-pair verification; (5) CRC-32 checksum of encrypted block; (6) AES-256-CCM decryption with authentication tag. Minimum 3-second interval between accepted triggers.

**DNS-Based Trigger (inactive in analyzed sample):** Commands encoded in DNS labels using Base32 (lowercase) with CRC-8 checksum (polynomial 0x31). Marker characters `g` through `v` delimit the payload. Example: `mqfoceywmw4etcjdp2nptitil[.]example[.]com` encodes a 14-byte encrypted instruction.

**Six Transport Channels:** TCP, UDP, ICMP (data in echo-request payloads), SMB named pipes (with credential-based lateral movement), raw promiscuous capture (SIO_RCVALL across up to 8 interfaces), and VMware VMCI (guest-to-host/guest-to-guest, never touches physical NIC).

**Encryption:** All task envelopes use AES-256-CCM (12-byte nonce, 16-byte authentication tag). DNS triggers use a shorter format (7-byte nonce, 4-byte tag). mbedTLS is statically linked. CryptGenRandom provides randomness.

### 4. Platform-Specific Behavior

#### Windows (Only Observed Platform)

- **Delivery:** DLL side-loading via ERAAgent.exe search-order hijacking
- **Persistence:** Automatic execution when ESET Management Agent service starts
- **Registry modifications:** Sets `EveryoneIncludesAnonymous = 1` (LSA key) and adds entries to `NullSessionPipes` (LanmanServer) to enable anonymous access to named pipes
- **Privilege requirement:** Local administrator to write DLL to ESET directory
- **Runtime API resolution:** VirtualProtect, SetSecurityDescriptorDacl, CryptGenRandom resolved by name at runtime

### 5. Anti-Forensics / Evasion Techniques

- **No disk writes by bytecode:** The instruction set cannot write files to disk; all payloads execute in memory
- **Process name obfuscation:** "ERAAgent.exe" is reconstructed from numerical constants, never stored as a readable string
- **Passive operation:** No outbound beaconing, no listening ports, no DNS resolution -- invisible to network monitoring until triggered
- **Promiscuous capture:** Can intercept triggers not even addressed to the host machine (useful on gateways, VPN concentrators, bridged hosts)
- **Forged version information:** DLL claims to be a legitimate ESET component with matching version, description, and copyright
- **Cryptographic validation:** Only the operator with the correct AES key can trigger the backdoor; failed packets are silently dropped
- **VMCI channel:** Guest-to-host communication that bypasses all network-level monitoring

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| dpapi.dll (masqueraded) | 11.2.2076.0 (forged ESET version) | Malicious DLL side-loaded by ERAAgent.exe; exports seven DPAPI functions |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `<ESET_INSTALL_DIR>\dpapi.dll` | `d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60` | SLEEPWALKER backdoor DLL (59,904 bytes) |
| Windows | `<ESET_INSTALL_DIR>\dpapisvc.dll` | Unknown | Non-existent forwarding target; presence indicates compromise |

Additional hashes:
- **SHA-1:** `2ec8aa9661a33bccc002150ce1ed02d90c3986ff`
- **MD5:** `2318327b29bb1c0e2d2b5f0211fc7fac`
- **Imphash:** `4e2dbfa7e3efd4cca2f3662797df9735`

### Network

| Type | Value | Context |
|------|-------|---------|
| N/A | No embedded network IOCs | SLEEPWALKER contains no hardcoded domains, IPs, or URLs; entirely passive until triggered |

### Behavioral

- Unexpected `dpapi.dll` (unsigned, 59,904 bytes) present alongside `ERAAgent.exe` in the ESET Management Agent directory
- Unexpected `dpapisvc.dll` in the same directory
- `EveryoneIncludesAnonymous` set to `1` under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- Unexpected entries added to `NullSessionPipes` under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
- ERAAgent.exe process exhibiting raw/promiscuous socket behavior (SIO_RCVALL)
- ERAAgent.exe loading dpapi.dll from its own directory rather than System32

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1574.001 | DLL Search Order Hijacking | Malicious dpapi.dll placed alongside ERAAgent.exe exploiting Windows DLL search order |
| T1036.005 | Match Legitimate Name or Location | DLL named dpapi.dll with forged ESET version information and legitimate DPAPI exports |
| T1040 | Network Sniffing | Raw promiscuous sockets (SIO_RCVALL) on up to 8 interfaces to capture trigger packets |
| T1059 | Command and Scripting Interpreter | Custom 23-instruction bytecode interpreter for command execution |
| T1055 | Process Injection | In-memory shellcode execution via RUN_SHELLCODE instruction with VirtualProtect |
| T1562.001 | Disable or Modify Tools | Registry modifications to enable anonymous access (EveryoneIncludesAnonymous, NullSessionPipes) |
| T1095 | Non-Application Layer Protocol | C2 over raw TCP, UDP, ICMP echo-request payloads, and VMware VMCI |
| T1021.002 | SMB/Windows Admin Shares | Named pipe communication with credential-based authentication for lateral movement |
| T1140 | Deobfuscate/Decode Files or Information | AES-256-CCM decryption of configuration and task payloads; LZMA decompression of programs |
| T1027 | Obfuscated Files or Information | Process name reconstructed from numeric constants; runtime API resolution by name |

## Impact Assessment

The impact of SLEEPWALKER is difficult to quantify: no victims, industries, or countries have been identified, and it remains unknown whether the sample was ever deployed operationally. However, the sophistication of the implant -- a custom bytecode language, six transport channels including VMCI, cryptographic trigger validation, and entirely in-memory execution -- indicates a well-resourced threat actor capable of sustained, targeted intrusion operations. Organizations running ESET Management Agent should perform immediate checks for the specific file hash and directory anomalies, regardless of the absence of confirmed victims.

## Detection & Remediation

### Immediate Detection

Check for the SLEEPWALKER DLL in ESET Management Agent directories:

```powershell
# Quick check: look for dpapi.dll or dpapisvc.dll next to ERAAgent.exe
Get-ChildItem -Path "C:\Program Files\ESET\RemoteAdministrator\Agent" -Filter "dpapi*.dll" -ErrorAction SilentlyContinue
Get-ChildItem -Path "${env:ProgramFiles}\ESET\RemoteAdministrator\Agent" -Filter "dpapi*.dll" -ErrorAction SilentlyContinue

# Hash check against known IOC
Get-FileHash -Path "C:\Program Files\ESET\RemoteAdministrator\Agent\dpapi.dll" -Algorithm SHA256 -ErrorAction SilentlyContinue | Where-Object { $_.Hash -eq 'd347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60' }

# Registry checks
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionPipes' -ErrorAction SilentlyContinue
```

The original researcher also published a comprehensive PowerShell scanner with JSON output, exit codes, and Authenticode verification at the primary source.

### Remediation

1. **Containment:** Isolate affected hosts immediately; SLEEPWALKER can intercept triggers on gateway/bridged hosts meant for other machines
2. **Eradication:** Remove the malicious `dpapi.dll` and `dpapisvc.dll` from the ESET agent directory; restore the legitimate DPAPI DLL from a known-good source
3. **Registry restoration:** Reset `EveryoneIncludesAnonymous` to `0` and audit/restore `NullSessionPipes` to its legitimate value
4. **Credential rotation:** Rotate all credentials accessible from compromised hosts; SLEEPWALKER's PIPE_SEND instruction supports authentication with supplied credentials
5. **Service restart validation:** After cleanup, restart the ESET Management Agent and verify dpapi.dll loads from System32 via Sysmon Event ID 7 (ImageLoad)
6. **Memory forensics:** Given the in-memory execution model, capture memory dumps before remediation for forensic analysis of any staged payloads

### Long-Term Hardening

- Deploy Sysmon with DLL load logging (Event ID 7) to detect side-loading attempts across all managed endpoints
- Monitor for unsigned DLLs loaded by signed executables in protected directories
- Implement application whitelisting / DLL allow-listing for sensitive service directories
- Audit registry changes to LSA and LanmanServer keys via Windows Security Event Log (Event IDs 4657, 4663)
- Consider restricting raw socket capabilities (SIO_RCVALL) via Windows Firewall or endpoint protection policies
- Monitor for VMware VMCI device access from unexpected processes in virtualized environments

## Detection Rules

These detections target the specific artifacts of the SLEEPWALKER backdoor at PoC/advisory-specific altitude. The Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale; the YARA rule compiles against the published sample. Snort and Suricata rules are not applicable because SLEEPWALKER uses encrypted, cryptographically validated trigger packets with no fixed cleartext signatures and embeds no network IOCs (domains, IPs, URLs).

### Sigma: SLEEPWALKER DLL Side-Loading via ESET Management Agent

Detects creation of dpapi.dll or dpapisvc.dll in the ESET Management Agent directory, the primary delivery mechanism for the SLEEPWALKER backdoor.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Rule keys on specific path + filename combination unique to this threat. FP risk minimal: legitimate ESET agent never ships dpapi.dll in its own directory. -->
```yaml
title: SLEEPWALKER Backdoor DLL Side-Loading via ESET Management Agent
id: 8a3c7e1f-b5d2-4f89-a6e1-c9d4f2b08e3a
status: experimental
description: >
    Detects creation of a suspicious dpapi.dll or dpapisvc.dll in the ESET
    Management Agent directory, consistent with the SLEEPWALKER backdoor
    DLL side-loading technique.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1574.001
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains: '\ESET\RemoteAdministrator\Agent\'
    selection_filename:
        TargetFilename|endswith:
            - '\dpapi.dll'
            - '\dpapisvc.dll'
    condition: selection_path and selection_filename
falsepositives:
    - Legitimate ESET Management Agent updates that include dpapi.dll (unlikely)
level: critical
```

### Sigma: SLEEPWALKER DLL Load Hijacking Detection

Detects ERAAgent.exe loading dpapi.dll from outside System32, the hallmark of SLEEPWALKER's search-order hijacking.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Requires Sysmon Event ID 7 (ImageLoad). Filter excludes legitimate System32/SysWOW64 paths. -->
```yaml
title: SLEEPWALKER Backdoor Loaded by ESET Management Agent
id: 4b1e8c5d-a9f3-42d7-b6e0-f7c2d1a34e89
status: experimental
description: >
    Detects ERAAgent.exe loading a dpapi.dll from its own directory rather than
    the legitimate System32 location, indicating DLL search-order hijacking
    consistent with the SLEEPWALKER backdoor.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection_process:
        Image|endswith: '\ERAAgent.exe'
    selection_dll:
        ImageLoaded|endswith: '\dpapi.dll'
    filter_system32:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_process and selection_dll and not filter_system32
falsepositives:
    - Custom ESET deployment with a legitimately placed dpapi.dll (highly unlikely)
level: critical
```

### Sigma: SLEEPWALKER Registry Modification - Anonymous Access Enablement

Detects EveryoneIncludesAnonymous being set to 1, a registry change made by SLEEPWALKER to enable anonymous named pipe access.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. This registry value can be set by other malware families or legacy configurations, hence medium confidence rather than high. -->
```yaml
title: SLEEPWALKER Registry Modification - Anonymous Access Enablement
id: 2f7d9a3b-e4c6-41a8-b5f0-d8e1c3a97b2f
status: experimental
description: >
    Detects modification of the EveryoneIncludesAnonymous registry value to 1
    under the LSA key, a technique used by the SLEEPWALKER backdoor to enable
    anonymous access to named pipes for unauthenticated lateral movement.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Control\Lsa\EveryoneIncludesAnonymous'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Legacy applications requiring anonymous access to network shares
    - Misconfigured Group Policy applying this setting intentionally
level: high
```

### Sigma: SLEEPWALKER Registry Modification - NullSessionPipes

Detects modification of NullSessionPipes, used by SLEEPWALKER to allow unauthenticated named pipe access for C2 communication.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. NullSessionPipes is a broader indicator; some legacy environments legitimately configure this. Medium confidence due to benign overlap. -->
```yaml
title: SLEEPWALKER Registry Modification - NullSessionPipes Enablement
id: 9e6f3b2a-d1c8-47e5-a0f4-b3c7e5d29a81
status: experimental
description: >
    Detects addition of entries to the NullSessionPipes registry value under
    LanmanServer parameters, used by the SLEEPWALKER backdoor to allow
    unauthenticated access to named pipes for C2 communication.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Services\LanmanServer\Parameters\NullSessionPipes'
    condition: selection
falsepositives:
    - Legitimate administrative configuration of NullSessionPipes for legacy applications
    - Group Policy applying NullSessionPipes settings
level: medium
```

### Sigma: SLEEPWALKER Inbound Connection to ESET Agent

Detects non-initiated (inbound) network connections to ERAAgent.exe, which may indicate SLEEPWALKER's raw promiscuous socket activity. Hunt-only; pair with the file-event and image-load rules above.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Sysmon Event ID 3 with Initiated=false. Legitimate ESET agent may receive management connections, hence low confidence. Best used as a hunting rule in conjunction with other SLEEPWALKER indicators. -->
```yaml
title: SLEEPWALKER Promiscuous Socket Activity by ESET Management Agent
id: c3a5d8e7-f1b4-4926-9d0e-a2b6c4f81e57
status: experimental
description: >
    Detects ERAAgent.exe initiating a network connection with promiscuous-mode
    characteristics. SLEEPWALKER uses SIO_RCVALL raw sockets to sniff all
    traffic on up to eight interfaces while waiting for a magic trigger packet.
    This rule fires on any network connection from ERAAgent.exe, which
    legitimately communicates with the ESET management server but should not
    exhibit raw-socket or broad-listener behavior.
references:
    - https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
    - https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1040
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\ERAAgent.exe'
        Initiated: 'false'
    condition: selection
falsepositives:
    - Legitimate ESET Management Agent receiving inbound management connections
level: medium
```

### Snort: N/A

SLEEPWALKER's trigger packets are encrypted with AES-256-CCM and validated via a multi-step cryptographic chain (CRC-32 + authenticated decryption). No fixed cleartext content signatures exist in the trigger format, and no C2 domains or IPs are embedded. Snort content-match rules cannot detect the cryptographically validated trigger without the operator's AES key.

### Suricata: N/A

Same rationale as Snort. The backdoor embeds no network-level IOCs (domains, IPs, URLs, JA3 hashes, TLS certificates). All six transport channels (TCP, UDP, ICMP, SMB, raw capture, VMCI) use encrypted payloads with no distinguishing cleartext patterns. Suricata's application-layer inspection cannot match the encrypted trigger format.

### YARA: SLEEPWALKER Backdoor Detection

Detects the SLEEPWALKER backdoor DLL via embedded AES-256 key bytes, config nonce, magic-packet validation algorithm, and the distinctive combination of DPAPI exports with forged ESET version metadata.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Rule adapted from Dominik Reichel's original (r136a1.dev). Three independent detection paths: (1) AES key or nonce or packet-validation algorithm byte sequence, (2) DPAPI masquerade with ESET metadata + all seven exports. Path 1 is sample-specific (crypto material); path 2 catches variants that reuse the masquerade technique with different keys. The magic_packet_algo pattern is compiler-dependent and may break on recompilation with different optimization settings. -->
```yara
import "pe"

rule Malware_SLEEPWALKER_Backdoor
{
    meta:
        description = "Detects the SLEEPWALKER passive backdoor DLL via embedded AES key, config nonce, magic packet validation logic, and DPAPI masquerade exports."
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Static AES-256 key for task envelope decryption
        $aes_key = { 74 65 31 FF 37 8D BB 4B B5 1D 2A A2 B1 D3 8D 90
                      53 50 A9 59 58 31 86 BA F4 C6 90 F5 F3 16 B3 AE }

        // 12-byte nonce for bootstrap config envelope
        $config_nonce = { 3A 6D 35 7F B9 BC 51 EA CC 8B 85 09 }

        // Trigger-packet validation: XOR with 0xAAAA, compare against 0x1C minimum
        $magic_packet_algo = {
            49 83 FC 30
            0F 82 ?? ?? ?? ??
            47 0F B7 44 25 FC
            47 0F B7 4C 25 FE
            B8 AA AA 00 00
            41 0F B7 C8
            66 41 33 C9
            66 33 C8
            66 83 F9 1C
        }

        // Non-existent forwarding DLL
        $dpapi_svc = "dpapisvc.dll" wide

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (
            any of ($aes_key, $config_nonce, $magic_packet_algo)
            or (
                pe.version_info["OriginalFilename"] contains "dpapi.dll" and
                (
                    pe.version_info["FileDescription"] contains "ESET Management Agent Module" or
                    $dpapi_svc
                ) and
                pe.exports("CryptProtectDataNoUI") and
                pe.exports("CryptProtectMemory") and
                pe.exports("CryptResetMachineCredentials") and
                pe.exports("CryptUnprotectDataNoUI") and
                pe.exports("CryptUnprotectMemory") and
                pe.exports("CryptUpdateProtectedState") and
                pe.exports("iCryptIdentifyProtection")
            )
        )
}
```

## Lessons Learned

SLEEPWALKER demonstrates that passive, trigger-activated implants -- previously seen primarily on Linux (e.g., BPFDoor) -- are viable and dangerous on Windows. The absence of outbound C2 beaconing, listening ports, and disk-writing instructions makes this class of implant nearly invisible to traditional network monitoring and many endpoint detection approaches. Key takeaways:

1. **DLL side-loading remains a persistent threat:** Legitimate, signed executables from security vendors can be abused as hosts. Organizations should monitor for unsigned DLLs loaded from application directories rather than System32.
2. **Custom bytecode interpreters evade signature-based detection:** The 23-instruction language creates a self-contained execution environment that leaves minimal forensic artifacts. Memory forensics becomes essential.
3. **Passive implants require proactive hunting:** Without outbound beaconing, network-based detection is ineffective. Host-based indicators (file events, image loads, registry changes) and periodic integrity scanning of service directories are the primary detection surface.
4. **VMware VMCI is an undermonitored channel:** Guest-to-host/guest-to-guest communication via VMCI bypasses all network monitoring and is rarely audited in enterprise environments.

## Sources

- [SLEEPWALKER: A Passive Backdoor With Its Own Command Language (r136a1.dev)](https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/) -- primary technical analysis by Dominik Reichel; includes YARA rule, PowerShell scanner, full bytecode ISA, and cryptographic details
- [New SLEEPWALKER Backdoor Waits for One Crafted Packet, Then Runs Its Own Bytecode (The Hacker News)](https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html) -- news coverage with summary of key findings and industry context
- [SLEEPWALKER Backdoor Uses Magic Packet, DLL Side-Loading and In-Memory Shellcode Execution (GBHackers)](https://gbhackers.com/sleepwalker-backdoor/) -- supplementary coverage of transport channels and deployment mechanism
- [You don't want this Sleepwalker backdoor on your Windows machine (The Register)](https://www.theregister.com/security/2026/08/24/you-dont-want-this-sleepwalker-backdoor-on-your-windows-machine/5292021) -- additional reporting on operational implications

---
*Report generated by Actioner*
