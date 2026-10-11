# Technical Analysis Report: AnyDesk Linux Pre-Authentication RCE (AnyPwn) (2026-10-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-11
Version: 1.0

## Executive Summary

A pre-authentication remote code execution vulnerability in AnyDesk for Linux 8.0.2 has been publicly exploited via a tool called "AnyPwn," published on October 8, 2026 by Rick de Jager of the V12 security team. The flaw is a heap buffer overflow in the session protocol's mode-5 stream packet handler, caused by unchecked 32-bit integer arithmetic when computing buffer allocation sizes. An attacker sending a crafted packet with a declared payload length of 0xFFFFFFF0 over a direct TCP connection to port 7070 can trigger a zero-length allocation, overflow the heap, corrupt adjacent objects, and achieve arbitrary command execution as root via a ROP chain. No authentication or user interaction is required.

AnyDesk silently patched the issue in version 8.0.3 (released June 2026), describing it only as "fixed a bug that could lead to a crash." No CVE has been assigned and no formal security advisory has been published. The vulnerability affects only AnyDesk for Linux running in service mode; Windows and macOS builds are reportedly not affected. While the researchers demonstrated the same vulnerable code path is reachable through AnyDesk relay connections (validated via Frida instrumentation), the published exploit targets only direct TCP connections. The exploit is probabilistic: incorrect heap layout causes a service crash rather than code execution.

## Background: AnyDesk for Linux

AnyDesk is a widely deployed proprietary remote desktop application. On Linux, it typically runs as a systemd service (`anydesk --service`) under root, listening on TCP port 7070 for direct peer-to-peer connections. The service is also reachable via AnyDesk's relay infrastructure, which brokers connections between peers that cannot establish direct links. AnyDesk's large deployment base across enterprise, managed service provider, and remote-support environments makes this vulnerability significant -- any internet-exposed AnyDesk Linux instance running version 8.0.2 or earlier is a potential target for unauthenticated root compromise.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-22 | V12 security team publicly announces the vulnerability discovery |
| 2026-06 (exact date unknown) | AnyDesk releases version 8.0.3 with the fix, described as "fixed a bug that could lead to a crash" |
| 2026-10-08 | V12 security team publishes the AnyPwn PoC exploit on GitHub |
| 2026-10-09 | Multiple media outlets report on the published exploit |
| As of 2026-10-11 | No CVE assigned; no formal security advisory from AnyDesk |

## Root Cause: Heap Buffer Overflow via 32-Bit Integer Overflow

The vulnerability resides in the handler for mode-5 stream packets in the AnyDesk session protocol. When a remote peer sends a mode-5 packet, the handler reads a varint-encoded payload length from the packet, adds a 16-byte object header to it using 32-bit unsigned arithmetic, and allocates a buffer of the resulting size. The addition is performed without an overflow check: a declared payload length of 0xFFFFFFF0 plus 16 wraps to 0x00000000, causing a zero-length (or near-zero) allocation. The object internally records the original large length, so subsequent writes using that length overflow far past the tiny allocated buffer.

This code path is reachable before any authentication exchange, making it a pre-authentication attack surface.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (Mode-5 Stream Packet)

The attacker connects to TCP port 7070 and sends a crafted mode-5 stream packet with the following structure:

| Field | Size | Value |
|-------|------|-------|
| `frame_len` | u16 big-endian | Packet frame length |
| `assigned_stream_id` | u16 big-endian | Target stream identifier |
| `stream_mode_prefix` | u8 | `0x00` (mode-5 indicator) |
| `mode5_declared_len` | varint (LEB128) | `0xFFFFFFF0` (encodes as `F0 FF FF FF 0F`) |
| `mode5_body` | u8[] | Overflow payload bytes |

Values in the range 0xFFFFFFF0 through 0xFFFFFFFF all trigger the integer wrap, producing allocations of 0 to 15 bytes while recording the original large length.

### 2. Heap Grooming and Exploitation

The exploit performs deterministic heap grooming before triggering the overflow:

- **Groom phase:** Sends 100 persistent mode-5 objects at each size from `0x1` to `0x17F1` in `0x10`-byte increments, filling the heap to create predictable layout.
- **Victim placement:** Opens 10 additional client connections to place candidate victim objects adjacent to the overflow target.
- **Spray phase:** Allocates 20 objects of `0xF000` bytes each, containing a `ret` sled followed by a ROP chain.
- **Trigger:** Sends the overflow packet. Even one byte of attacker-controlled data writes past the tiny allocation, corrupting dispatch-related fields (including a vtable pointer and stack-pivot gadget) in an adjacent victim object.
- **Execution:** The corrupted vtable redirects execution into the ROP chain, which writes the attacker-supplied command string into fixed scratch memory and calls the target build's `system()` PLT entry.

The exploit is probabilistic -- it depends on the heap layout placing a suitable victim object immediately after the overflowed buffer. Failed layout causes a crash (denial of service).

### 3. Post-Exploitation

Since AnyDesk runs as root, successful exploitation grants immediate root-level command execution. The PoC demonstrates this with `id>/tmp/anypwn`, writing proof of code execution. A real attacker could execute arbitrary commands: reverse shells, credential harvesting, persistence installation, lateral movement tools.

### 4. Platform-Specific Behavior

#### Linux (Affected)
- **Service mode:** `anydesk --service` runs as root via systemd.
- **Direct connection port:** TCP/7070.
- **Tested environment:** Linux Mint 22.3 (Zena), kernel 6.14.0-37-generic, x86_64.
- **Build-specific:** ROP gadget offsets are tied to the specific AnyDesk binary build. The published exploit targets version 8.0.2.

#### Windows / macOS (Not Affected)
- The researchers report that Windows and macOS builds do not share the vulnerable code path.

### 5. Relay Connection Vector

The researchers confirmed via Frida instrumentation that the same vulnerable code path is reachable through AnyDesk relay connections (the default connection method when direct connections are not available). However, the full exploitation chain (heap grooming + ROP) has not been demonstrated over relays. AnyDesk has stated the issue affects only direct connections. This discrepancy means relay-based exploitation cannot be ruled out but is unconfirmed.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| AnyDesk for Linux | 8.0.2 (and possibly earlier 8.x) | Contains the heap buffer overflow in mode-5 stream handler |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | AnyDesk 8.0.2 binary | `62ee04ad48dc039dd9c927f998e56143c87a9c5e12d28654f78c7f6340394f5a` | Vulnerable AnyDesk binary targeted by the exploit |
| Linux | `/tmp/anypwn` | N/A | PoC artifact -- proof of code execution output (attacker-configurable) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Port | TCP/7070 | AnyDesk direct connection listener; exploit delivery channel |
| Byte pattern | `00 F0 FF FF FF 0F` in TCP/7070 stream | Mode-5 prefix (0x00) + varint-encoded 0xFFFFFFF0 overflow length |

### Behavioral

- **AnyDesk service crashes:** Repeated crashes of the `anydesk` process (running as root) may indicate exploitation attempts, since failed heap layouts cause crashes rather than successful exploitation.
- **Unusual inbound connections to TCP/7070:** Multiple rapid TCP connections to port 7070 from a single source, particularly with the heap grooming pattern of 10+ simultaneous connections.
- **Post-exploitation indicators:** Unexpected child processes spawned by the `anydesk` service process (e.g., `/bin/sh`, reverse shell binaries, download utilities) indicate successful exploitation.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Pre-auth exploitation of AnyDesk service on TCP/7070 via crafted mode-5 stream packet |
| T1059.004 | Unix Shell | ROP chain calls `system()` to execute attacker-supplied shell commands |
| T1059.006 | Python | AnyPwn exploit tool executed as a Python script |

## Impact Assessment

- **Breadth:** Any internet-exposed AnyDesk for Linux installation running version 8.0.2 or earlier is potentially vulnerable. AnyDesk is widely used in enterprise remote support, managed service providers, and individual remote access deployments.
- **Depth:** Pre-authentication root-level RCE -- maximum severity. No credentials, no user interaction, no prior access required.
- **Stealth:** The exploit is noisy in failure (crashes the service) but successful exploitation may leave minimal traces beyond the executed command's artifacts. The service may restart automatically via systemd, masking crash evidence.
- **Confirmed in-the-wild exploitation:** None reported as of 2026-10-11, though the public PoC availability makes exploitation imminent.

## Detection & Remediation

### Immediate Detection

Check for vulnerable AnyDesk version:
```bash
# Check installed AnyDesk version
anydesk --version

# Check running AnyDesk service
systemctl status anydesk
ps aux | grep anydesk

# Verify the binary hash against the known vulnerable build
sha256sum $(which anydesk)
# Vulnerable: 62ee04ad48dc039dd9c927f998e56143c87a9c5e12d28654f78c7f6340394f5a

# Check for PoC artifacts (default output path)
ls -la /tmp/anypwn

# Check for recent AnyDesk service crashes
journalctl -u anydesk --since "7 days ago" | grep -i "crash\|signal\|segfault\|core dump"
```

### Remediation

1. **Update immediately:** Upgrade AnyDesk for Linux to version 8.0.3 or later (8.1.0 is current as of this writing).
2. **Restrict network access:** If updating is not immediately possible, block inbound TCP/7070 from untrusted networks. AnyDesk relay connections may still function without direct port exposure.
3. **Review service logs:** Check `journalctl -u anydesk` for segfaults or unexpected restarts that may indicate exploitation attempts.
4. **Audit for compromise:** On systems that were exposed, check for unauthorized user accounts, SSH keys, cron jobs, and running processes that may indicate post-exploitation persistence.

### Long-Term Hardening

- Do not expose AnyDesk's direct connection port (TCP/7070) to the internet; use the relay infrastructure or a VPN.
- Monitor AnyDesk changelog releases and treat "crash fix" entries as potential security patches requiring immediate evaluation.
- Implement network monitoring for anomalous traffic patterns on TCP/7070.
- Consider running AnyDesk with reduced privileges where possible (non-root service accounts), though this may limit functionality.

## Detection Rules

Four detection rules target the AnyPwn exploit at the PoC/advisory-specific altitude. The Snort and Suricata rules key on the distinctive byte pattern of the integer-overflowing varint (0xFFFFFFF0 encoded as LEB128) in TCP/7070 traffic; the Sigma rule detects execution of the AnyPwn tool itself; the YARA rule identifies the AnyPwn exploit script on disk or in memory by its characteristic string combinations. Note: the Snort and Suricata rules match only the varint encoding of 0xFFFFFFF0 (`F0 FF FF FF 0F`); values 0xFFFFFFF1 through 0xFFFFFFFF (15 additional values) also trigger the integer overflow but encode to different byte sequences and are not matched. This is acceptable at the PoC-specific altitude since the published exploit uses only 0xFFFFFFF0, but operators should be aware of this coverage gap. Compiles does not equal fires -- verify each rule against your traffic and telemetry before promoting to production.

### Sigma: AnyPwn Exploit Tool Execution

Detects execution of the AnyPwn exploit tool via process creation events matching the tool's distinctive command-line arguments.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to environment constraint (MITRE ATT&CK data fetch blocked by proxy), not rule syntax. sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 (log_scale target = CrowdStrike LogScale / Falcon LogScale). Splunk output: CommandLine="*anypwn*" CommandLine="*--host*". LogScale output: CommandLine=/anypwn/i CommandLine=/--host/i. Rule keys on tool-specific CLI args; FP only from authorized pentest use of the same tool name + flags. -->
```yaml
title: AnyPwn Exploit Tool Execution Against AnyDesk Linux
id: b42fc99b-18d9-4b2d-86bf-115f6ca5d9a5
status: experimental
description: >
    Detects execution of the AnyPwn exploit tool (anypwn.py) targeting the
    pre-authentication heap buffer overflow in AnyDesk for Linux 8.0.2.
    The tool connects to TCP/7070 and sends crafted mode-5 stream packets
    with an integer-overflowing payload length to achieve RCE as root.
references:
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
author: Actioner
date: 2026/10/11
tags:
    - attack.t1190
    - attack.t1059.006
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'anypwn'
            - '--host'
    condition: selection
falsepositives:
    - Authorized penetration testing using the AnyPwn tool
level: high
```

### Snort: AnyDesk Mode-5 Integer Overflow Packet

Detects the distinctive byte pattern of a mode-5 stream packet carrying the integer-overflowing payload length (varint-encoded 0xFFFFFFF0) on TCP port 7070. Note: this rule matches only the varint encoding of 0xFFFFFFF0; the 15 other overflow-triggering values (0xFFFFFFF1--0xFFFFFFFF) have different encodings and are not matched.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: snort compiler not available in this environment. Structural check: protocol tcp, flow established/to_server, single content match with hex bytes and fast_pattern, all options semicolon-terminated, parentheses balanced, sid in 2100000+ range. The byte pattern |00 F0 FF FF FF 0F| is the mode-5 prefix (0x00) followed by the LEB128 varint encoding of 0xFFFFFFF0. Confidence downgraded from high to medium: rule is uncompiled and matches only one of the 16 overflow-triggering varint values. FP risk: low -- this exact 6-byte sequence in a TCP/7070 stream is highly specific to the exploit; benign AnyDesk traffic would not produce a varint this large. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Linux Heap Overflow Exploit (AnyPwn) Mode-5 Integer Overflow"; flow:established,to_server; content:"|00 F0 FF FF FF 0F|"; fast_pattern; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created 2026-10-11; sid:2100001; rev:1;)
```

### Suricata: AnyDesk Mode-5 Integer Overflow Packet

Detects the same mode-5 integer overflow byte pattern on TCP/7070 using Suricata syntax. Same single-value limitation as the Snort rule above: only 0xFFFFFFF0 is matched.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: suricata compiler not available in this environment. Structural check: protocol tcp, flow established/to_server, content with pipe-delimited hex bytes, fast_pattern, all options semicolon-terminated, parentheses balanced, msg prefixed "Actioner - ", metadata with created_at, sid in 2200000+ range. Confidence downgraded from high to medium: rule is uncompiled and matches only one of the 16 overflow-triggering varint values. Same byte pattern rationale as Snort rule above. -->
```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Linux Heap Overflow Exploit (AnyPwn) Mode-5 Integer Overflow"; flow:established,to_server; content:"|00 F0 FF FF FF 0F|"; fast_pattern; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created_at 2026-10-11; sid:2200001; rev:1;)
```

### YARA: AnyPwn Exploit Script Detection

Detects the AnyPwn exploit script by its characteristic strings including the tool name, overflow value, heap grooming parameters, and CLI arguments.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. Sample test: constructed positive file with tool-characteristic strings (anypwn, fffffff0, 7070, --host, --command, 0xf000, 0x17f1) fired rule; negative file with benign anydesk references did not fire. Strings derived from published PoC repository description: tool name, overflow constant, target port, CLI flags, heap spray size, groom boundary. Condition requires $tool AND $overflow_val AND 3 of all strings -- anchors on the two most distinctive indicators. FP risk: very low -- requires co-occurrence of exploit-specific identifiers. -->
```yara
rule Exploit_AnyPwn_AnyDesk_Linux_RCE
{
    meta:
        description = "Detects the AnyPwn exploit script targeting AnyDesk Linux pre-auth heap buffer overflow (mode-5 stream integer overflow to RCE)"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        severity = "critical"

    strings:
        $tool = "anypwn" ascii nocase
        $overflow_val = "fffffff0" ascii nocase
        $port = "7070" ascii
        $arg_host = "--host" ascii
        $arg_cmd = "--command" ascii
        $heap_size = "0xf000" ascii nocase
        $groom_end = "0x17f1" ascii nocase

    condition:
        filesize < 1MB and
        $tool and $overflow_val and
        3 of them
}
```

## Lessons Learned

1. **Silent patching obscures risk.** AnyDesk's decision to describe a pre-authentication root RCE as a "crash fix" in the changelog -- without assigning a CVE or publishing a security advisory -- left defenders unable to assess risk or prioritize patching. Organizations relying on AnyDesk's changelog for patch prioritization would have treated this as a low-priority stability fix. Vendors should assign CVEs and publish security advisories for all remotely exploitable vulnerabilities.

2. **Remote desktop tools are high-value targets.** AnyDesk runs as root with network exposure, making it an ideal initial access vector. The 2024 AnyDesk infrastructure breach and this 2026 pre-auth RCE demonstrate that remote desktop tools require the same security scrutiny as VPN appliances and edge devices. Organizations should treat remote access tools as critical infrastructure: minimize internet exposure, enforce updates aggressively, and monitor for anomalous behavior.

3. **Heap overflow exploitation on Linux is practical.** While the exploit is probabilistic and build-specific, the researchers demonstrated reliable exploitation on a common Linux distribution. The gap between "crash fix" and "root RCE" illustrates that heap corruption vulnerabilities should not be dismissed as denial-of-service.

## Sources

- [The Hacker News - Researchers Publish Working Exploit for Pre-Auth AnyDesk Linux Flaw](https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html) -- primary news coverage with technical summary
- [V12 Security PoC Repository (AnyPwn)](https://github.com/v12-security/pocs/tree/main/anydesk) -- original exploit code and technical writeup
- [V12 Security Team](https://v12.sh/) -- researcher organization homepage
- [V12 Security Announcement on X](https://x.com/v12sec/status/2069178874118668364) -- original public disclosure announcement
- [Aviatrix Threat Research - AnyDesk Linux Pre-Auth RCE Analysis](https://aviatrix.ai/threat-research-center/anydesk-linux-pre-auth-rce-anypwn-exploit-2026/) -- secondary analysis with MITRE ATT&CK mapping
- [CyberSecurityNews - AnyDesk Linux Flaw Remote Root RCE](https://cybersecuritynews.com/anydesk-linux-vulnerability/) -- additional media coverage
- [AnyDesk Linux Changelog](https://anydesk.com/en/changelog/linux) -- vendor changelog with the silent crash fix entry
- [CVE-2025-27918 (Tenable)](https://www.tenable.com/cve/CVE-2025-27918) -- prior AnyDesk heap overflow vulnerability for historical context

---
*Report generated by Actioner*
