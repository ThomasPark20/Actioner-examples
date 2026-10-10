# Technical Analysis Report: AnyDesk Linux Pre-Authentication Remote Code Execution — AnyPwn (2026-10-10)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-10
Version: 1.1 (REVISED)
<!-- revision: v1.1 — (1) Sigma "Repeated Crashes" renamed to "AnyDesk Service Crash" with single-event semantics; (2) Suricata Rule 1 and Snort Rule 1 now include content match for varint-encoded overflow value |F0 FF FF FF 0F|; (3) Suricata Rule 3 dropped — shell output from system() goes to local stdout, not back over AnyDesk port 7070; (4) T1068 removed from ATT&CK mapping (AnyDesk runs as root — no privilege escalation); (5) T1210 qualified for lateral movement only; (6) Suricata status note clarified re SYN-only rule direction. -->

## Executive Summary

AnyPwn is a **pre-authentication, zero-click remote code execution** vulnerability in AnyDesk for Linux, caused by a **heap buffer overflow** triggered by a 32-bit integer wraparound in the session protocol's mode-5 stream packet handler. No CVE has been assigned as of October 10, 2026. An unauthenticated attacker with network access to TCP port 7070 (AnyDesk's direct connection port) can achieve **root-level command execution** before any user approves a connection. AnyDesk patched the flaw in version **8.0.3** (June 23, 2026) with the vague changelog entry "fixed a bug that could lead to a crash" and issued no security advisory.

The full working exploit ("AnyPwn") was published on [GitHub](https://github.com/v12-security/pocs/tree/main/anydesk) on October 8, 2026, by **Rick de Jager** of the **V12 security team**. The exploit targets **AnyDesk Linux 8.0.2 on x86_64** running in service mode. It is probabilistic (heap-layout-dependent) and crashes the service on failed attempts. The researchers confirmed the vulnerable code path is also reachable through AnyDesk relay servers via Frida instrumentation, though full exploitation over relays has not been demonstrated. AnyDesk maintains that only direct connections on Linux are affected, and that Windows and macOS are not vulnerable.

Given the public PoC with specific exploitation patterns (heap spray connections, mode-5 overflow packets, post-exploitation shell spawning), this analysis passes the **viability gate for production-ready detections**. Detection rules target the network-level attack pattern (rapid connections for heap grooming, oversized packets to port 7070) and host-level post-exploitation indicators (AnyDesk service spawning shells, service crash patterns).

## Background: AnyDesk and Its Linux Service

[AnyDesk](https://anydesk.com/) is a widely deployed remote desktop application used across enterprises for remote support, administration, and access. On Linux, AnyDesk can run as a system service (`anydesk --service`) under root, listening on **TCP port 7070** for direct peer-to-peer connections. This service mode is common in enterprise deployments where unattended access is required. AnyDesk also supports relay-based connections through its cloud infrastructure, where clients connect through AnyDesk servers rather than directly.

The AnyDesk session protocol uses a custom binary format with various stream modes. **Mode-5 stream packets** are part of the session establishment and data-transfer machinery. The handler for these packets allocates memory based on a declared payload length field sent by the remote peer.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-01 (approx.) | AnyDesk tells researchers the flaw affects only direct Linux connections, not relays; Windows/macOS not affected |
| 2026-06-22 | V12 security team publicly announces the vulnerability |
| 2026-06-23 | AnyDesk acknowledges the flaw, releases version 8.0.3 with the fix |
| 2026-06-23 | AnyDesk changelog describes the fix as "fixed a bug that could lead to a crash" |
| Post-June 2026 | AnyDesk removes 8.0.2 binary from download page (changelog reference remains) |
| 2026-10-08 | Full working PoC exploit ("AnyPwn") published on [GitHub](https://github.com/v12-security/pocs/tree/main/anydesk) |
| 2026-10-09 | [The Hacker News](https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html) and other outlets report on the public exploit |
| 2026-10-10 | No CVE or formal security advisory issued by AnyDesk |

## Root Cause: Integer Wraparound in Mode-5 Stream Allocation

The vulnerability resides in AnyDesk's session protocol handler for **mode-5 stream packets**. The handler processes incoming packets from the remote peer before any authentication or connection approval.

### Vulnerable Code Path

1. **Packet parsing**: The handler reads the incoming mode-5 packet, which contains an attacker-controlled `mode5_declared_len` field (a varint encoding a 32-bit value).
2. **Allocation size calculation**: The handler computes the allocation size by adding a **16-byte object header (0x10)** to the declared payload length, using **32-bit unsigned arithmetic** with no overflow check.
3. **Integer wraparound**: The attacker declares a payload length of **0xFFFFFFF0**. The calculation `0xFFFFFFF0 + 0x10 = 0x100000000` wraps to **0x00000000** under 32-bit arithmetic. The allocator receives a request for zero (or near-zero) bytes.
4. **Metadata mismatch**: The allocated object's metadata retains the original large length (0xFFFFFFF0), while its data pointer is set to `allocation_base + 0x10`.
5. **Heap overflow**: When even one byte of attacker-controlled body data is copied into the undersized allocation, it writes past the allocation boundary into adjacent heap objects.

### Packet Structure (Mode-5 Stream on an Assigned Stream)

| Field | Size/Type | Notes |
|-------|-----------|-------|
| frame_len | u16be | Outer frame length |
| assigned_stream_id | u16be | Stream identifier |
| stream_mode_prefix | u8 | Value 0x00 |
| mode5_declared_len | varint | Unvalidated 32-bit value; set to 0xFFFFFFF0 in the exploit |
| mode5_body | u8[] | Attacker-controlled overflow data |

### Validation Gap

The vulnerable path does not check that the declared mode-5 length matches the bytes actually present in the frame. This means the attacker does not need to send gigabytes of data -- the varint length field triggers the wrap, and only the body bytes needed for the overflow and corruption are sent.

## Technical Analysis of the Exploit Chain

### 1. Heap Grooming / Size-Graded Spray

The exploit opens **multiple persistent connections** to TCP/7070 and sends mode-5 objects across a range of sizes to populate allocator size classes. This creates a predictable heap layout where target objects will be allocated in known regions.

### 2. Victim Object Placement

Several additional client connections are established so the service allocates **client objects** (containing vtable pointers and function pointers) near the groomed region. These client objects are the corruption targets.

### 3. Trigger Packet

The malicious mode-5 packet with `mode5_declared_len = 0xFFFFFFF0` is sent. The allocation wraps to near-zero bytes, but the object retains the large logical length. The attacker's body data overflows into the adjacent victim object, overwriting its **vtable pointer** and a **stack-pivot gadget address**.

### 4. ROP Spray

Many copies of a **return-gadget sled followed by a ROP chain** are sprayed across heap memory so the stack pivot has multiple potential landing points, increasing reliability.

### 5. Command Execution

When the service processes the corrupted object, control flow is hijacked through the overwritten vtable pointer, pivoting into the ROP chain. The chain writes the attacker's command string into a fixed memory location and calls the target build's **`system()` PLT entry**, executing the command as root.

### 6. Reliability and Failure Mode

The exploit is **probabilistic**. Success requires the target victim object to be adjacent to the overflowed buffer in the heap. If the layout is unfavorable, the service **crashes (segfault/SIGSEGV)** instead of executing the command. The attacker may need **multiple attempts**, and each failed attempt restarts the service (if configured for automatic restart). The published offsets are specific to **AnyDesk Linux 8.0.2 on x86_64**; other versions or architectures require recalculated offsets.

### Test Environment (from PoC)

- Linux Mint 22.3 (Zena), kernel 6.14.0-37-generic, x86_64

## Indicators of Compromise (IOCs)

> **Defanging Convention:** IOCs are defanged (`hxxps://`, `[.]`). No resolvable C2 indicators exist for this vulnerability -- it is an exploit technique, not a malware campaign.

### Software / Vulnerability Level

| Component | Vulnerable Version | Fixed Version | Description |
|-----------|-------------------|---------------|-------------|
| AnyDesk Linux | <= 8.0.2 | 8.0.3+ (latest: 8.1.0) | Pre-auth heap buffer overflow in mode-5 stream handler |

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Port | TCP/7070 | AnyDesk direct connection port; the exploit requires direct TCP access to this port |
| Traffic pattern | Burst of 10+ TCP connections from single source to port 7070 in < 60 seconds | Heap grooming phase: multiple connections for size-graded spray and victim placement |
| Traffic pattern | Short-lived TCP connections to port 7070 that do not complete AnyDesk handshake | Failed exploitation attempts or connection teardown after spray |
| Protocol anomaly | Mode-5 stream packet with declared length near 0xFFFFFFFF (e.g., 0xFFFFFFF0) | The overflow trigger; varint-encoded in the packet body |

### Host / Behavioral Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Process creation | AnyDesk service (`/usr/bin/anydesk`) spawning `/bin/sh`, `/bin/bash`, `python`, `perl`, `curl`, `wget`, or similar | Post-exploitation command execution via `system()` |
| Service crash | AnyDesk service crash (segfault/SIGSEGV) followed by restart | Failed exploitation attempt (unfavorable heap layout) |
| Service crash | Repeated AnyDesk crash-restart cycles correlated with inbound connections to TCP/7070 | Multiple exploitation attempts |
| Process tree | Root-owned processes spawned by AnyDesk that are not part of normal remote-desktop operation | Arbitrary commands executed via the ROP chain |

### File System Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Core dump | Core dump files from AnyDesk process in `/var/crash/` or systemd journal | Crashed service from failed exploit attempts |
| Exploit tool | Files named `anypwn` or containing "AnyPwn" in script content | Presence of the public exploit tool |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Pre-auth exploitation of AnyDesk service listening on TCP/7070, reachable without credentials |
| T1059 | Command and Scripting Interpreter | Post-exploitation command execution via `system()` call from ROP chain |
| T1059.004 | Unix Shell | The exploit uses `system()` to spawn a shell or run arbitrary commands as root |
| T1210 | Exploitation of Remote Services | Remote service (AnyDesk) exploited (applicable when used for lateral movement; initial access is covered by T1190) |
| T1499.004 | Application or System Exploitation (DoS) | Failed exploitation attempts crash the AnyDesk service |

## Impact Assessment

**Severity: Critical.** This is a pre-authentication, zero-click, remote code execution vulnerability that yields root access on any reachable AnyDesk Linux installation running version 8.0.2 or earlier with direct connections enabled (TCP/7070 exposed). AnyDesk is widely deployed in enterprise environments for remote support, meaning the attack surface may be significant.

**Scope:** AnyDesk Linux <= 8.0.2 on x86_64. Windows and macOS are not affected per both AnyDesk and the researchers. The relay-connection attack path is unresolved -- the vulnerable code is reachable over relays (confirmed via instrumentation), but full exploitation has not been demonstrated.

**Blast radius:** Root-level command execution allows full host compromise, persistence installation, lateral movement, data exfiltration, and use of the compromised host as a pivot point into internal networks.

**Stealth:** Failed attempts crash the service and are noisy. Successful exploitation is quiet -- the command runs as root and the service continues operating. Without specific monitoring for AnyDesk child processes, successful exploitation may go undetected.

## Detection & Remediation

### Immediate Detection

1. Deploy the Suricata/Snort rules below to detect the mode-5 overflow trigger packet and heap-grooming connection bursts to TCP/7070.
2. Deploy the Sigma rules to detect AnyDesk service spawning suspicious child processes and crash/restart patterns.
3. Hunt for AnyDesk Linux installations running version <= 8.0.2 (`anydesk --version` or package manager queries).
4. Review firewall logs for external connections to TCP/7070 on Linux hosts.
5. Check for AnyDesk core dumps and crash logs on potentially exposed hosts.

### Remediation

1. **Patch immediately:** Upgrade all AnyDesk Linux installations to **8.0.3 or later** (latest is 8.1.0). This is the only complete fix.
2. **Restrict TCP/7070:** Block or restrict inbound access to TCP/7070 using host firewalls (iptables/nftables), network ACLs, and cloud security groups.
3. **Use relay-only mode:** Where feasible, configure AnyDesk to operate only through relay connections (disable direct connections). Note: the researchers showed the code path is reachable over relays, so this is risk reduction, not elimination.
4. **Investigate exposed hosts:** Any host that ran AnyDesk Linux 8.0.2 with TCP/7070 reachable from untrusted networks should be treated as potentially compromised. Review logs, check for unauthorized processes, new user accounts, SSH keys, and persistence mechanisms.
5. **Remove stale installations:** Find and remove any AnyDesk Linux installations that are no longer needed or actively managed.

### Long-Term Hardening

- Segment AnyDesk Linux hosts from sensitive internal networks; require VPN or bastion access for remote support connections.
- Monitor AnyDesk version compliance as part of vulnerability management.
- Subscribe to AnyDesk security communications (note: AnyDesk's track record on security transparency is poor -- no CVE, no advisory, vague changelog entry).
- Deploy endpoint monitoring (EDR/Sysmon for Linux) that captures process creation events with parent process context.

## Detection Rules

### Sigma: AnyDesk Service Suspicious Child Process - Possible AnyPwn RCE Exploitation

Detects the AnyDesk Linux service spawning suspicious child processes (shells, interpreters, download utilities). The AnyPwn exploit uses `system()` to execute arbitrary commands as root. Legitimate AnyDesk service operation does not spawn these processes without user-initiated remote sessions.

**Status:** compile `sigma check` blocked by proxy (MITRE ATT&CK data download) -- structural check only via `sigma convert` | `sigma convert -t splunk` ✅ | `sigma convert -t log_scale` ✅ · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk -> valid SPL output. sigma convert --without-pipeline -t log_scale -> valid LogScale output. sigma check fails on MITRE ATT&CK data download (HTTP 403 from proxy), not a rule syntax issue. Rule structure is valid YAML, correct logsource/detection schema. -->
```yaml
title: AnyDesk Service Suspicious Child Process - Possible AnyPwn RCE Exploitation
id: a1d2e3f4-5678-4abc-9def-0123456789ab
status: experimental
description: >
    Detects the AnyDesk Linux service spawning suspicious child processes such as
    shells, scripting interpreters, or download utilities. The AnyPwn exploit
    (pre-auth heap buffer overflow in AnyDesk Linux <= 8.0.2) uses system() to
    execute arbitrary commands as root. Legitimate AnyDesk service operation does
    not spawn these processes without user-initiated remote sessions.
references:
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thecybersecguru.com/exploits/anydesk-linux-anypwn-pre-auth-root-rce/
author: Actioner
date: 2026-10-10
tags:
    - attack.t1059
    - attack.t1190
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith: '/anydesk'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
            - '/python'
            - '/python3'
            - '/perl'
            - '/ruby'
            - '/curl'
            - '/wget'
            - '/nc'
            - '/ncat'
            - '/socat'
            - '/chmod'
            - '/chown'
            - '/useradd'
            - '/adduser'
    condition: selection_parent and selection_child
falsepositives:
    - AnyDesk legitimate remote support sessions where a user intentionally runs
      shell commands through AnyDesk terminal features
    - Custom AnyDesk automation scripts that spawn child processes
level: high
```

### Sigma: AnyDesk Service Crash - Possible AnyPwn Exploitation Attempt

Detects a single AnyDesk service crash (segfault/SIGSEGV/core dump) in syslog, which may indicate a failed AnyPwn exploitation attempt. Correlate with inbound connections to TCP/7070 and AnyDesk version.

**Status:** compile `sigma check` blocked by proxy (MITRE ATT&CK data download) -- structural check only via `sigma convert` | `sigma convert -t splunk` ✅ | `sigma convert -t log_scale` ✅ · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk -> valid SPL output. sigma convert --without-pipeline -t log_scale -> valid LogScale output. sigma check fails on MITRE ATT&CK data download (HTTP 403 from proxy), not a rule syntax issue. Revised v1.1: renamed from "Repeated Crashes" — rule fires on a single crash event (no aggregation/count), so title and description now reflect single-event semantics. Crash signals are not CVE-specific but are highly relevant when correlated with AnyDesk version and network activity. -->
```yaml
title: AnyDesk Service Crash - Possible AnyPwn Exploitation Attempt
id: b2c3d4e5-6789-4bcd-aef0-1234567890bc
status: experimental
description: >
    Detects the AnyDesk service crashing (segfault, SIGSEGV, or core dump),
    which may indicate a failed AnyPwn exploitation attempt. The exploit is
    probabilistic and crashes the service when heap layout is unfavorable.
    Correlate with inbound connections to TCP/7070 and check AnyDesk version
    (vulnerable: 8.0.2 or earlier). Multiple crashes in a short period are
    especially suspicious.
references:
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thecybersecguru.com/exploits/anydesk-linux-anypwn-pre-auth-root-rce/
author: Actioner
date: 2026-10-10
tags:
    - attack.t1190
    - attack.t1499.004
logsource:
    product: linux
    service: syslog
detection:
    selection:
        - SyslogMessage|contains|all:
            - 'anydesk'
            - 'segfault'
        - SyslogMessage|contains|all:
            - 'anydesk'
            - 'SIGSEGV'
        - SyslogMessage|contains|all:
            - 'anydesk'
            - 'core dumped'
    condition: selection
falsepositives:
    - Legitimate AnyDesk crashes unrelated to exploitation
    - System instability or resource exhaustion causing service crashes
level: medium
```

### Sigma: Inbound Connection to AnyDesk Direct Port - Possible AnyPwn Attack Surface

Detects inbound TCP connections to port 7070 from external (non-RFC1918) sources. Any external connection to this port on a host running a vulnerable AnyDesk version warrants investigation.

**Status:** compile `sigma check` blocked by proxy (MITRE ATT&CK data download) -- structural check only via `sigma convert` | `sigma convert -t splunk` ✅ | `sigma convert -t log_scale` ✅ · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk -> valid SPL output. sigma convert --without-pipeline -t log_scale -> valid LogScale output. This is a broad indicator that needs tuning for environments where external AnyDesk direct connections are expected. -->
```yaml
title: Inbound Connection to AnyDesk Direct Port - Possible AnyPwn Attack Surface
id: c3d4e5f6-7890-4cde-bf01-2345678901cd
status: experimental
description: >
    Detects inbound TCP connections to port 7070 (AnyDesk direct connection port)
    from external sources. The AnyPwn exploit targets AnyDesk Linux via direct TCP
    connections to this port. While a single connection is not conclusive, any
    external-origin connection to this port on a host running a vulnerable AnyDesk
    version (8.0.2 or earlier) warrants investigation, especially if the host
    should not be accepting direct AnyDesk connections.
references:
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thecybersecguru.com/exploits/anydesk-linux-anypwn-pre-auth-root-rce/
author: Actioner
date: 2026-10-10
tags:
    - attack.t1190
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationPort: 7070
        Initiated: 'false'
    filter_internal:
        SourceIp|startswith:
            - '10.'
            - '172.16.'
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - '192.168.'
            - '127.'
    condition: selection and not filter_internal
falsepositives:
    - Legitimate external AnyDesk direct connections from authorized support staff
    - AnyDesk relay infrastructure IP ranges
level: medium
```

### Suricata: AnyPwn AnyDesk Pre-Auth Heap Overflow Detection Suite

Two Suricata rules targeting the AnyPwn exploitation pattern on TCP/7070: the mode-5 overflow trigger packet (keyed on the varint-encoded 0xFFFFFFF0 value) and heap-grooming SYN bursts.
<!-- revision: dropped Rule 3 (post-exploitation shell response) — shell output does not traverse AnyDesk port 7070; system() output goes to local stdout -->

**Status:** compile ✅ suricata -T: "Configuration provided was successfully loaded" (1 warning: SYN-only rule 2 auto-disabled for toclient direction -- this is expected since the rule uses `flags:S` without `flow`, and it functions correctly for the to_server direction that matters) · confidence: medium
<!-- audit: suricata (-T -S anydesk-anypwn.rules -l /tmp/actioner) -> "Configuration provided was successfully loaded. Exiting." exit 0. Warning on rule 2 (SYN flags + no direction) is informational: the rule fires for to_server SYN packets as intended; auto-disable applies only to the toclient direction which is irrelevant for this detection. Rule 1 revised v1.1: added content match for varint-encoded 0xFFFFFFF0 (bytes F0 FF FF FF 0F) as the distinctive exploit artifact, replacing the generic |00| + dsize match. Rule 3 dropped v1.1: system() output goes to local stdout/stderr, not back over the AnyDesk protocol on port 7070. -->
```suricata
# Rule 1: Detect AnyPwn overflow trigger — varint-encoded 0xFFFFFFF0 in mode-5 stream packet
# The exploit sends a mode-5 stream packet declaring payload length 0xFFFFFFF0.
# The varint encoding of 0xFFFFFFF0 is the byte sequence F0 FF FF FF 0F, which is
# the distinctive artifact of the integer-wraparound trigger.
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyPwn AnyDesk Pre-Auth Heap Overflow - Mode-5 Varint Overflow Trigger"; flow:established,to_server; content:"|F0 FF FF FF 0F|"; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created_at 2026-10-10, affected_product AnyDesk_Linux, attack_target Server; sid:2026100101; rev:2;)

# Rule 2: Detect rapid connection pattern consistent with AnyPwn heap grooming
# The exploit opens many TCP connections to port 7070 for heap spray/grooming.
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyPwn AnyDesk Heap Grooming - Rapid TCP Connection Burst to Port 7070"; flags:S; threshold:type both, track by_src, count 15, seconds 30; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created_at 2026-10-10, affected_product AnyDesk_Linux, attack_target Server; sid:2026100102; rev:1;)
```

### Snort: AnyPwn AnyDesk Pre-Auth Heap Overflow Detection

Two Snort rules targeting the AnyPwn exploitation pattern: the mode-5 overflow trigger packet (varint-encoded 0xFFFFFFF0) and heap-grooming SYN bursts on TCP/7070.

**Status:** ⚠️ uncompiled (structural check only -- Snort not installed) · confidence: medium
<!-- audit: Snort is not installed in this environment. Rules follow Snort 2.9/3.x syntax conventions, mirroring the validated Suricata rules. Structural review: correct semicolon-delimited options, valid content modifiers, threshold syntax, metadata and reference fields. Rule 1 revised v1.1: added content match for varint-encoded 0xFFFFFFF0 (bytes F0 FF FF FF 0F), replacing generic |00| + dsize match, to match the distinctive exploit artifact. -->
```snort
# Rule 1: Detect AnyPwn overflow trigger — varint-encoded 0xFFFFFFF0 in mode-5 stream packet
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyPwn AnyDesk Pre-Auth Heap Overflow - Mode-5 Varint Overflow Trigger"; flow:established,to_server; content:"|F0 FF FF FF 0F|"; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner; sid:3026100101; rev:2;)

# Rule 2: Detect rapid SYN connections to AnyDesk port consistent with heap grooming
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyPwn AnyDesk Heap Grooming - Rapid TCP SYN Burst to Port 7070"; flags:S; threshold:type both, track by_src, count 15, seconds 30; classtype:attempted-admin; reference:url,github.com/v12-security/pocs/tree/main/anydesk; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner; sid:3026100102; rev:1;)
```

### YARA: AnyPwn Exploit Script Detection

Detects the AnyPwn exploit tool or variants by matching on tool name, combination of exploit-related strings (heap spray, ROP chain, system() PLT, target version), or the overflow trigger value (0xFFFFFFF0) alongside AnyDesk references.

**Status:** compile ✅ `yarac` exit 0 · confidence: medium
<!-- audit: yarac /tmp/actioner/anydesk-anypwn.yar /dev/null -> exit 0, no errors. Rule uses string-based and byte-pattern matching. False positive risk is low for the $anypwn_name match (unique tool name), moderate for the combination conditions (3-of-N threshold may match unrelated security tooling). -->
```yara
rule AnyPwn_Exploit_Script
{
    meta:
        description = "Detects the AnyPwn exploit tool or variants targeting AnyDesk Linux pre-auth heap buffer overflow"
        author = "Actioner"
        date = "2026-10-10"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        reference2 = "https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html"
        severity = "critical"

    strings:
        $anypwn_name = "AnyPwn" ascii nocase
        $anydesk_target = "anydesk" ascii nocase
        $port_7070 = "7070" ascii
        $heap_spray = "spray" ascii nocase
        $mode5 = "mode-5" ascii nocase
        $mode5_alt = "mode_5" ascii nocase
        $overflow_val1 = { F0 FF FF FF }
        $overflow_val2 = { FF FF FF F0 }
        $rop_chain = "ROP" ascii nocase
        $system_call = "system(" ascii
        $system_plt = "system@plt" ascii
        $vuln_version = "8.0.2" ascii

    condition:
        ($anypwn_name) or
        (3 of ($anydesk_target, $port_7070, $heap_spray, $mode5, $mode5_alt, $rop_chain, $system_call, $system_plt, $vuln_version)) or
        (($overflow_val1 or $overflow_val2) and $anydesk_target)
}
```

## Lessons Learned

The AnyPwn case illustrates several recurring patterns in vulnerability disclosure and enterprise risk:

1. **Silent patching is a disservice to defenders.** AnyDesk patched a critical pre-auth RCE as "fixed a bug that could lead to a crash" with no CVE, no advisory, and no severity indication. Enterprises that deprioritize "crash bug" patches were left vulnerable for months. The four-month gap between the silent patch (June) and the public exploit (October) is the direct cost of this opacity.

2. **Service-mode remote access tools are high-value targets.** AnyDesk running as root with a listening port that accepts unauthenticated connections is a textbook pre-auth RCE surface. Organizations should treat remote-access tool services as crown-jewel attack surface and restrict their network exposure accordingly.

3. **Probabilistic exploits are still dangerous.** The heap-layout dependency means the exploit crashes the service on most attempts, but crashes are cheap and automatic restarts enable retries. A "probabilistic" exploit with unlimited retries against an auto-restarting service is effectively deterministic given time.

4. **Prior AnyDesk security incidents compound the risk.** AnyDesk's 2024 production breach (code-signing certificate revocation, forced password resets) and the separate CVE-2025-27918 heap overflow establish a pattern. Organizations should evaluate whether AnyDesk's security posture meets their risk tolerance.

## Sources

- [The Hacker News -- Researchers Publish Working Exploit for Pre-Auth AnyDesk Linux Flaw That Gives Root Access](https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html) -- primary news coverage, timeline, technical overview
- [V12 Security -- AnyPwn PoC on GitHub](https://github.com/v12-security/pocs/tree/main/anydesk) -- public exploit repository with README, offsets, and exploit code
- [The CyberSec Guru -- AnyDesk Linux AnyPwn Exploit: Pre-Auth Root RCE](https://thecybersecguru.com/exploits/anydesk-linux-anypwn-pre-auth-root-rce/) -- detailed technical analysis including packet structure, exploitation chain, and reliability assessment
- [Cyber Security News -- AnyDesk Linux Flaw Lets Remote Attackers Execute Code as Root Without Authentication](https://cybersecuritynews.com/anydesk-linux-vulnerability/) -- additional coverage and context
- [Mallory.ai -- AnyPwn Exploit Enables Pre-Auth Root Code Execution in AnyDesk Linux](https://mallory.ai/stories/01a120d6-b8b8-7293-afc6-4c568f61e318) -- news summary with timeline details
- [V12 Security (X/Twitter) -- Original Announcement](https://x.com/v12sec/status/2069178874118668364) -- researchers' initial public disclosure
- [V12 Security -- Homepage](https://v12.sh/) -- researcher team information
- [AnyDesk Linux Changelog](https://anydesk.com/en/changelog/linux) -- vendor changelog (returned HTTP 403 at fetch time)
- [Hunter Strategy Blog -- AnyDesk Root Exploit, SonicWall SMA1000 Attacks, and a Critical NetScaler Flaw](https://blog.hunterstrategy.net/anydesk-root-exploit-sonicwall-sma1000-attacks-and-a-critical-netscaler-flaw/) -- aggregated security news coverage
- [NVD -- CVE-2025-27918](https://nvd.nist.gov/vuln/detail/CVE-2025-27918) -- prior AnyDesk heap overflow (different vulnerability, all platforms, fixed in 7.0.0)

---
*Report generated by Actioner*
