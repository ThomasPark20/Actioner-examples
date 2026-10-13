# Technical Analysis Report: AnyDesk Linux Pre-Authentication RCE (CVE-2026-109390 / AnyPwn)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-13
Version: 1.0-DRAFT

## Executive Summary

A pre-authentication heap buffer overflow in AnyDesk for Linux (CVE-2026-109390, CVSS 9.8) allows unauthenticated remote attackers to execute arbitrary commands as root over TCP port 7070, without requiring the victim to approve a desktop-control session. The vulnerability exists in the session protocol's mode-5 stream packet handler, where a 32-bit integer overflow in payload buffer size calculation leads to a near-zero allocation that is subsequently overflowed with attacker-controlled data. Exploitation uses a ROP chain to achieve arbitrary command execution.

The flaw affects AnyDesk Linux versions 8.0.0 through 8.0.2 and was silently patched in version 8.0.3 (released June 2026) with changelog wording describing only a crash fix. No vendor security advisory was published. CVE-2026-109390 was assigned on October 12, 2026 (CNA status: Received, NVD analysis pending). A full working exploit (named "AnyPwn") was published on GitHub by Rick de Jager of the V12 security team on October 8, 2026. The exploit is probabilistic -- failed attempts crash the service rather than achieving code execution, producing a distinctive crash-restart pattern.

Windows and macOS builds are not affected. The demonstrated exploit works only over direct TCP connections; reachability through AnyDesk relay servers was partially validated by the researchers using Frida instrumentation but a full relay exploit chain was not demonstrated.

## Background: AnyDesk on Linux

AnyDesk is a widely deployed remote desktop application. On Linux, the AnyDesk service runs as root and listens on TCP port 7070 for incoming connections. The service typically runs as a systemd unit and automatically restarts after crashes. The AnyDesk protocol is proprietary and binary, using a custom session protocol with multiple stream modes for different data types (display, input, file transfer, etc.).

AnyDesk has experienced security incidents previously, including a corporate breach in early 2024 that led to certificate revocation and password resets. A separate heap overflow (CVE-2025-27918) in the AnyDesk client was fixed in version 7.0.0 in April 2025, affecting all platforms. The current vulnerability (CVE-2026-109390) is distinct and affects only the Linux build.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-06-22 | V12 Security (Rick de Jager) publicly announces the vulnerability |
| 2026-06-23 | AnyDesk acknowledges the report |
| 2026-06 (exact date unknown) | AnyDesk releases version 8.0.3 with fix described as crash bug resolution |
| 2026-10-08 | V12 Security publishes full working exploit ("AnyPwn") on GitHub |
| 2026-10-09 | The Hacker News and multiple outlets publish coverage |
| 2026-10-12 | CVE-2026-109390 published (CNA advisory, NVD analysis pending) |
| Post-2026-10-08 | AnyDesk removes 8.0.2 build from download page (changelog still references it) |

## Root Cause: Integer Overflow in Mode-5 Stream Packet Handler

The vulnerability resides in the handler for mode-5 stream packets in AnyDesk's session protocol. When processing an incoming stream packet, the handler computes the allocation size for the packet buffer by adding a 16-byte (0x10) header to the declared payload length. This addition uses 32-bit unsigned arithmetic with no overflow check.

An attacker declares a payload length of 0xFFFFFFF0. The addition of 0x10 wraps the 32-bit result to 0x00000000, causing a near-zero-size heap allocation. The AnyDesk session object retains the original large length value (0xFFFFFFF0), so even a single byte of attacker-supplied data writes past the actual allocation boundary.

**CWE**: CWE-130 (Improper Handling of Length Parameter Inconsistency)

The heap overflow corrupts fields in adjacent heap objects. The published exploit leverages this corruption to build a ROP chain that executes an arbitrary shell command. Because the AnyDesk service runs as root on Linux, successful exploitation yields root-level command execution.

**Reliability**: The exploit is probabilistic. The target heap object must be allocated adjacent to the overflowed buffer for corruption to achieve code execution. When the layout condition is not met, the service crashes instead. Because systemd typically restarts the service, an attacker can retry, producing a distinctive burst of crash-restart cycles.

**Attack Surface**: The demonstrated exploit works over direct TCP connections to port 7070. The researchers validated that the same code path is reachable through AnyDesk relay servers using Frida instrumentation, but did not demonstrate a complete relay exploit chain. Whether relay-path exploitation is fully achievable remains unresolved.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| TCP port 7070 | Port | AnyDesk service listening port; exploit target |
| hxxps://github[.]com/v12-security/pocs/tree/main/anydesk | URL | Published exploit repository |

### Process-Based Indicators

| Parent Process | Child Process | Context |
|----------------|---------------|---------|
| `anydesk` (running as root) | `/bin/sh` | Post-exploitation shell execution |
| `anydesk` (running as root) | `/bin/bash` | Post-exploitation shell execution |
| `anydesk` (running as root) | `python` / `python3` | Post-exploitation scripting |
| `anydesk` (running as root) | `curl` / `wget` | Post-exploitation tool download |
| `anydesk` (running as root) | `perl` | Post-exploitation scripting |

### Behavioral Indicators

- AnyDesk service crashes followed by automatic systemd restarts, especially after connections from unfamiliar IP addresses (indicates probabilistic exploit attempts)
- Bursts of TCP connections to port 7070 from a single source IP that terminate before the session handshake completes
- Root-owned AnyDesk process spawning shell interpreters, scripting languages, or download utilities
- Unexpected child processes of the anydesk daemon that are not part of normal remote desktop operations
- Core dump files from the anydesk process (segfault in heap-related operations)

### Log-Based Indicators

| Log Entry | Source | Significance |
|-----------|--------|-------------|
| `anydesk` + `segfault` | syslog/journal | Service crash from heap corruption |
| `anydesk` + `dumping core` | systemd journal | Core dump generation after exploit attempt |
| Repeated `anydesk.service: Main process exited` | systemd journal | Crash-restart cycle indicating brute-force exploitation |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Remote exploitation of AnyDesk Linux service via TCP port 7070 using crafted mode-5 stream packets with integer-overflowed payload length |
| T1059.004 | Unix Shell | Post-exploitation execution of /bin/sh or /bin/bash as root from the compromised AnyDesk process |

## Impact Assessment

- **Breadth**: AnyDesk is widely deployed across enterprises, MSPs, and individual users. Linux installations running versions 8.0.0-8.0.2 are vulnerable. The silent patching (no CVE, no advisory, crash-fix changelog wording) means many organizations may not have prioritized the 8.0.3 update.
- **Depth**: Full root-level RCE without authentication. The service runs as root, so exploitation immediately grants the highest privilege level. No user interaction or desktop-control approval is required.
- **Stealth**: Failed exploitation crashes the service, which is noisy. However, successful exploitation leaves the attacker with root access and the ability to clear evidence. The crash-restart behavior may be dismissed as instability rather than attack activity.
- **Exploit availability**: Full working exploit is publicly available on GitHub since October 8, 2026, lowering the barrier to exploitation.

## Detection & Remediation

### Immediate Detection

Administrators should check for compromise indicators on all Linux hosts running AnyDesk:

```bash
# Check installed AnyDesk version
anydesk --version 2>/dev/null || dpkg -l anydesk 2>/dev/null || rpm -q anydesk 2>/dev/null

# Check for recent AnyDesk crash dumps
journalctl -u anydesk --since "7 days ago" | grep -iE "segfault|core dump|dumping core|signal 11"

# Check for unexpected child processes of anydesk
ps -eo pid,ppid,user,comm | awk '$4=="anydesk" {print $1}' | while read pid; do
    ps --ppid "$pid" -o pid,user,comm 2>/dev/null
done

# Review incoming connections to port 7070
ss -tnp sport = :7070 2>/dev/null
journalctl -u anydesk --since "7 days ago" | grep -i "connection from"

# Check for core dumps
find /var/lib/systemd/coredump/ -name "*anydesk*" -mtime -7 2>/dev/null
coredumpctl list anydesk 2>/dev/null
```

### Remediation

1. **Immediate**: Update AnyDesk Linux to version 8.0.3 or later (current latest: 8.1.0). This is the only complete fix.
2. **If update not immediately possible**: Restrict inbound access to TCP port 7070 using firewall rules (iptables/nftables/cloud security groups) to allow only trusted source IPs.
3. **If compromised**: Isolate the host, preserve crash dumps and logs for forensic analysis, and rebuild from clean backups. A root-level compromise requires full system rebuild.
4. **Network segmentation**: Do not expose AnyDesk service ports directly to the internet. Use VPN or zero-trust network access for remote administration.
5. **Monitoring**: Deploy process creation monitoring (auditd, Sysmon for Linux, or EDR) on all AnyDesk hosts, with alerts on shell interpreter spawning by the anydesk process.

## Detection Rules

7 detection rules (2 Sigma, 2 Suricata, 2 Snort, 1 YARA) target the exploitation behavior and vulnerable installations for CVE-2026-109390. The exploit is a binary protocol heap overflow, limiting network-level detection to heuristic byte-pattern matching; process-level behavioral detection on Linux endpoints is the highest-fidelity approach.

### Sigma Rule 1: AnyDesk Linux Service Spawning Shell or Interpreter

Detects the root-owned AnyDesk process spawning shells or download utilities, the primary post-exploitation indicator.

**Compile**: sigma check pass (attacktag validator excluded due to proxy blocking MITRE ATT&CK data fetch), sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: high

```yaml
title: AnyDesk Linux Service Spawning Shell or Interpreter (CVE-2026-109390 Post-Exploitation)
id: a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects the AnyDesk Linux service (which runs as root) spawning shell
    interpreters or download utilities. This is the expected post-exploitation
    behavior following successful heap buffer overflow exploitation of the
    mode-5 stream handler in AnyDesk Linux 8.0.0-8.0.2 (CVE-2026-109390).
references:
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
author: Actioner
date: 2026-10-13
tags:
    - attack.t1059.004
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
            - '/curl'
            - '/wget'
    condition: selection_parent and selection_child
falsepositives:
    - AnyDesk custom client scripts that intentionally invoke shell commands (rare on Linux daemon installations)
level: critical
```

<!-- Audit: sigma check 0 errors 0 issues (attacktag validator excluded due to proxy blocking MITRE ATT&CK data fetch); sigma convert --without-pipeline -t splunk produces valid SPL: ParentImage="*/anydesk" Image IN ("*/sh", "*/bash", ...); sigma convert --without-pipeline -t log_scale produces valid LogScale query. Process list covers common shells (sh, bash, dash, zsh), scripting interpreters (python, python3, perl), and download tools (curl, wget) -- all cited by cybersecguru.com as expected post-exploitation behavior. ParentImage|endswith '/anydesk' matches the standard Linux binary name. Requires Sysmon for Linux or auditd with process_creation logging. -->

### Sigma Rule 2: AnyDesk Linux Service Crash Indicating Exploitation Attempt

Detects AnyDesk crash or segfault entries in syslog, which occur when the probabilistic heap overflow exploit fails to achieve the required heap layout.

**Compile**: sigma check pass (attacktag validator excluded), sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: medium

```yaml
title: AnyDesk Linux Service Repeated Crashes Indicating Exploitation Attempts (CVE-2026-109390)
id: b2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects AnyDesk service crash or core dump entries in syslog. The
    CVE-2026-109390 heap overflow exploit is probabilistic and crashes the
    service when heap layout conditions are not met. Multiple crash entries
    from the anydesk service suggest active exploitation attempts.
references:
    - https://github.com/v12-security/pocs/tree/main/anydesk
    - https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html
author: Actioner
date: 2026-10-13
tags:
    - attack.t1190
logsource:
    product: linux
    service: syslog
detection:
    selection_crash:
        SyslogIdentifier: 'systemd'
        Message|contains|all:
            - 'anydesk'
            - 'dumping core'
    selection_segfault:
        Message|contains|all:
            - 'anydesk'
            - 'segfault'
    condition: selection_crash or selection_segfault
falsepositives:
    - Legitimate AnyDesk crashes due to software bugs or resource exhaustion (should be investigated regardless)
level: high
```

<!-- Audit: sigma check 0 errors 0 issues (attacktag validator excluded). sigma convert --without-pipeline -t splunk produces: (SyslogIdentifier="systemd" Message="*anydesk*" Message="*dumping core*") OR (Message="*anydesk*" Message="*segfault*"). Medium confidence because individual crashes can have benign causes; correlation with connection bursts to port 7070 raises confidence. This rule produces individual match events -- SOC should correlate multiple hits within a short window (e.g., 3+ in 10 minutes) to distinguish exploitation attempts from isolated crashes. The deprecated pipe/count syntax was avoided in favor of simple OR conditions. -->

### Suricata Rules: AnyDesk Exploit Network Detection

Two Suricata rules detecting potential exploitation traffic: one for the specific integer-overflow payload length value (0xFFFFFFF0 in little-endian) in TCP traffic to port 7070, and one for rapid SYN bursts indicating brute-force heap layout attempts.

**Caveat**: AnyDesk uses a proprietary binary protocol. The byte pattern 0xF0FFFFFF may appear at any offset in the TCP stream; this rule is heuristic and requires tuning against baseline AnyDesk traffic.

**Compile**: suricata -T pass ("Configuration provided was successfully loaded") | **Confidence**: medium

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Possible Heap Overflow Exploit Payload Length 0xFFFFFFF0 (CVE-2026-109390)"; flow:established,to_server; content:"|F0 FF FF FF|"; fast_pattern; threshold:type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:cve,2026-109390; reference:url,github.com/v12-security/pocs/tree/main/anydesk; metadata:author Actioner, created_at 2026-10-13; sid:2100300; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Rapid Reconnection Burst Possible Exploit Brute-Force (CVE-2026-109390)"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 10, seconds 30; classtype:attempted-admin; reference:cve,2026-109390; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created_at 2026-10-13; sid:2100301; rev:1;)
```

<!-- Audit: suricata -T -S suricata_anydesk_exploit.rules -l /tmp/actioner exit 0. Rule 1 uses content match for the little-endian representation of 0xFFFFFFF0 (the integer-overflowed payload length) in established TCP streams to port 7070. fast_pattern on this content; threshold limits alerts to 1 per source IP per 60 seconds to reduce noise. Without protocol-level dissection, this is a best-effort heuristic -- 4 bytes of 0xF0FFFFFF could appear in legitimate binary protocol traffic, though this is unlikely given the specific port restriction. Rule 2 detects SYN flood patterns (10+ SYNs in 30 seconds) to port 7070 from a single source, which matches the brute-force heap layout behavior described by researchers. False positives possible from rapid legitimate reconnection scenarios. -->

### Snort Rules: AnyDesk Exploit Network Detection

Two equivalent Snort 3 rules for the same network patterns.

**Compile**: not available (snort not installed) | **Confidence**: medium

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Possible Heap Overflow Exploit Payload Length 0xFFFFFFF0 (CVE-2026-109390)"; flow:established, to_server; content:"|F0 FF FF FF|", fast_pattern; threshold:type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:cve,2026-109390; reference:url,github.com/v12-security/pocs/tree/main/anydesk; metadata:author Actioner, created 2026-10-13; sid:2100400; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 7070 (msg:"Actioner - AnyDesk Rapid Reconnection Burst Possible Exploit Brute-Force (CVE-2026-109390)"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 10, seconds 30; classtype:attempted-admin; reference:cve,2026-109390; reference:url,thehackernews.com/2026/10/researchers-publish-working-exploit-for.html; metadata:author Actioner, created 2026-10-13; sid:2100401; rev:1;)
```

<!-- Audit: snort not available for compilation. Rules use Snort 3 syntax with comma-delimited content modifiers (fast_pattern). Structural review confirms balanced parentheses, all required fields (msg, sid, rev), semicolon termination, and flow keywords present. SID range 2100400-2100401 chosen to avoid collision with Suricata SIDs. -->

### YARA Rule: Vulnerable AnyDesk Linux Binary Detection

Detects AnyDesk Linux ELF binaries in the vulnerable version range (8.0.0-8.0.2), enabling asset inventory scanning to identify unpatched installations.

**Compile**: yarac pass (exit 0) | **Confidence**: medium

```yara
rule Vuln_AnyDesk_Linux_CVE_2026_109390 : vulnerability
{
    meta:
        description = "Detects AnyDesk Linux binaries in the version range affected by CVE-2026-109390 (pre-auth heap buffer overflow, 8.0.0-8.0.2). The mode-5 stream handler integer overflow is present in these builds."
        author = "Actioner"
        date = "2026-10-13"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        severity = "critical"

    strings:
        $anydesk_str = "AnyDesk" ascii wide
        $linux_elf = { 7F 45 4C 46 }

        $vuln_v800 = "8.0.0" ascii
        $vuln_v801 = "8.0.1" ascii
        $vuln_v802 = "8.0.2" ascii

        $anynet = "anynet" ascii
        $ad_proto = "ad.session" ascii
        $ad_stream = "ad.stream" ascii

    condition:
        $linux_elf at 0 and
        $anydesk_str and
        1 of ($vuln_v8*) and
        1 of ($anynet, $ad_proto, $ad_stream)
}
```

<!-- Audit: yarac yara_anydesk_vuln.yar /dev/null exit 0, rule compiles cleanly. Medium confidence: version string matching in binaries can produce false positives if short version strings like "8.0.0" appear in unrelated context. The additional constraints ($anydesk_str + ELF magic at offset 0 + at least one AnyDesk protocol-specific string) reduce false positives. The protocol strings ($anynet, $ad_proto, $ad_stream) are inferred from AnyDesk's known internal naming; if the actual binary uses different strings, the rule requires adjustment. This rule is designed for asset inventory, not exploit detection. -->

## Lessons Learned

1. **Silent patching of critical vulnerabilities delays defensive response**: AnyDesk patched a CVSS 9.8 pre-auth RCE as a crash fix with no CVE or advisory. Organizations relying on CVE feeds or vendor advisories for patch prioritization would have treated this as a routine update. The 4-month gap between patch and exploit publication was the only protection for environments that did not update.

2. **Integer overflow in size calculations remains a persistent vulnerability class**: The root cause -- unchecked 32-bit addition of a header size to a user-supplied length -- is a well-documented anti-pattern (CWE-190/CWE-130). Static analysis and fuzzing tooling should flag any arithmetic on untrusted length values that feeds into allocation functions.

3. **Linux remote access services as root expand blast radius**: AnyDesk running as root means exploitation immediately grants the highest privilege level without requiring a separate privilege escalation step. Organizations should evaluate whether remote access services can run with reduced privileges or in sandboxed contexts.

4. **Probabilistic exploits generate distinctive detection opportunities**: The crash-restart pattern produced by failed heap exploitation attempts is a high-signal behavioral indicator. Monitoring systemd service restart frequency for critical services can detect exploitation attempts even when the exploit fails to achieve code execution.

## Sources

- [The Hacker News - Researchers Publish Working Exploit for Pre-Auth AnyDesk Linux Flaw That Gives Root Access](https://thehackernews.com/2026/10/researchers-publish-working-exploit-for.html) -- primary reporting with technical details on the integer overflow, mode-5 stream handler, and exploit mechanism
- [V12 Security PoC Repository](https://github.com/v12-security/pocs/tree/main/anydesk) -- published exploit code and vulnerability documentation
- [V12 Security](https://v12.sh/) -- researcher organization (Rick de Jager)
- [V12 Security Announcement (X/Twitter)](https://x.com/v12sec/status/2069178874118668364) -- original June 22, 2026 disclosure announcement
- [CVE-2026-109390 (Strix.ai)](https://www.strix.ai/cve/CVE-2026-109390) -- CVE entry with CVSS 9.8, CWE-130, affected versions 8.0.0-8.0.2
- [CVE-2026-109390 Intel (cve.imfht.com)](https://cve.imfht.com/intel/841733) -- CVE aggregation with PoC reference
- [AnyDesk Linux Changelog](https://anydesk.com/en/changelog/linux) -- version history (8.0.3 fix described as crash resolution)
- [SC World - AnyDesk Linux exploit grants root access before connection approval](https://www.scworld.com/brief/anydesk-linux-exploit-grants-root-access-before-connection-approval) -- coverage of relay-path partial validation
- [CyberSecurity News - AnyDesk Linux Flaw Lets Remote Attackers Execute Code as Root](https://cybersecuritynews.com/anydesk-linux-vulnerability/) -- additional technical coverage
- [The CyberSec Guru - AnyDesk Linux AnyPwn Exploit](https://thecybersecguru.com/exploits/anydesk-linux-anypwn-pre-auth-root-rce/) -- detection guidance: shell spawning, crash-restart patterns, connection bursts
- [Aviatrix Threat Research - AnyDesk Linux Pre-Auth RCE](https://aviatrix.ai/threat-research-center/anydesk-linux-pre-auth-rce-anypwn-exploit-2026/) -- MITRE ATT&CK mapping and defensive guidance
- [Hunter Strategy - AnyDesk Root Exploit](https://blog.hunterstrategy.net/anydesk-root-exploit-sonicwall-sma1000-attacks-and-a-critical-netscaler-flaw/) -- CVE assignment timeline context
- [Cryptika - AnyDesk Linux Flaw](https://www.cryptika.com/anydesk-linux-flaw-lets-remote-attackers-execute-code-as-root-without-authentication/) -- timeline and remediation details
- [First Hackers News - Critical AnyDesk Linux Flaw](https://firsthackersnews.com/anydesk-linux-vulnerability-root-code-execution/) -- additional reporting
- [Tenable - CVE-2025-27918](https://www.tenable.com/cve/CVE-2025-27918) -- prior AnyDesk heap overflow (separate vulnerability, all platforms)

---
*Report generated by Actioner (DRAFT)*
