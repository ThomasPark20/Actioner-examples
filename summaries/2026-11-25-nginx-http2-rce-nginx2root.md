# Technical Analysis Report: NGINX HTTP/2 RCE "nginx2root" (2026-11-25)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-25
Version: 1.0

## Executive Summary

Two critical vulnerabilities in NGINX's HTTP/2 implementation — CVE-2026-123007 (integer underflow, CVSS 9.2) and CVE-2026-123633 (use-after-free) — allow unauthenticated remote code execution against NGINX servers with HTTP/2 enabled. Dubbed "nginx2root," the exploit chain targets NGINX versions 1.9.5 through 1.30.6 (stable) and 1.31.0 through 1.31.8 (mainline). A fully weaponized public proof-of-concept exists (sfewer-r7/CVE-2026-123007) demonstrating reliable exploitation in approximately 2.5 minutes using ~128 GB of HTTP/2 traffic.

Both vulnerabilities were patched in NGINX 1.30.7 (stable) and 1.31.9 (mainline) released by F5/NGINX on 2026-11-18. Given the ubiquity of NGINX as a reverse proxy and web server, the unauthenticated nature of the attack, and the availability of a public PoC, immediate patching is critical. Network-level detection (Snort/Suricata) is not viable because the attack traverses encrypted HTTP/2 over TLS; detection must rely on host-based log analysis and process monitoring.

## Background: NGINX HTTP/2 Stack

NGINX is the world's most widely deployed web server and reverse proxy, serving an estimated 34% of all websites. HTTP/2 support was introduced in NGINX 1.9.5 (September 2015), making the vulnerable code path over 10 years old. The HTTP/2 implementation handles stream multiplexing, header compression (HPACK), and flow control within NGINX worker processes, which run as unprivileged users (typically `www-data` or `nginx`) but have full access to served content, TLS private keys, and upstream application traffic.

The affected component is the HTTP/2 connection and stream management subsystem, specifically the handling of worker connection slot exhaustion and the subsequent "draining" codepath that reclaims connections. Under normal operation, when free worker_connections slots drop below 1/16th of the configured value, NGINX enters a draining mode that reuses idle connections. The vulnerabilities corrupt memory during this transition.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2015-09-22 | NGINX 1.9.5 released with HTTP/2 support, introducing the vulnerable code path |
| 2026-11-11 | CVE-2026-123007 and CVE-2026-123633 assigned |
| 2026-11-18 | F5/NGINX releases patches in 1.30.7 (stable) and 1.31.9 (mainline) |
| 2026-11-19 | Unit 42 publishes detailed technical analysis of CVE-2026-123633 |
| 2026-11-20 | sfewer-r7 releases full PoC exploit for CVE-2026-123007 on GitHub |
| 2026-11-21 | The Hacker News reports on the vulnerability with exploitation details |

## Root Cause: HTTP/2 Connection Draining Memory Corruption

**CVE-2026-123007 (Integer Underflow):** When an NGINX worker process enters the connection draining state (triggered when free worker_connections drop below 1/16th of the configured value), an integer underflow in the HTTP/2 stream counter allows an attacker to manipulate internal bookkeeping. By sending carefully crafted HTTP/2 frames during the draining transition, the attacker causes the stream count to wrap, leading to a controlled out-of-bounds write in the worker's heap. The PoC leverages this to overwrite function pointers and redirect execution.

**CVE-2026-123633 (Use-After-Free):** A related vulnerability in the same draining codepath occurs when NGINX is configured with `proxy_pass` using a variable-based hostname (e.g., `proxy_pass https://$host`). During connection reuse in the draining state, a freed HTTP/2 stream structure is referenced after deallocation. The dangling pointer can be reclaimed with attacker-controlled data via heap spraying through additional HTTP/2 streams.

Both vulnerabilities require the target to have HTTP/2 enabled (the default in modern NGINX configurations) and for the attacker to exhaust worker connections to trigger the draining codepath. The PoC achieves this by opening many concurrent HTTP/2 streams.

## Technical Analysis of the Malicious Payload

### 1. Connection Exhaustion Phase

The exploit begins by establishing numerous HTTP/2 connections to the target NGINX server, each multiplexing many streams. The goal is to exhaust worker_connections slots below the 1/16th threshold, forcing NGINX into the draining codepath. The public PoC requires approximately 128 GB of HTTP/2 traffic sent over ~2.5 minutes to achieve this condition reliably.

**Prerequisites:**
- Target NGINX must have HTTP/2 enabled (default in most modern configs)
- For CVE-2026-123633 specifically: `proxy_pass` with a variable hostname and `worker_connections` set to a relatively low value
- The attacker's system must support AVX-512F and AVX-512VL CPU instructions (used by the PoC for heap manipulation)

### 2. Memory Corruption and Code Execution

Once the draining state is triggered:

- **CVE-2026-123007 path:** The integer underflow corrupts the HTTP/2 stream management structures, allowing controlled heap writes. The PoC overwrites a function pointer in the event handler chain to redirect execution to attacker-supplied shellcode.
- **CVE-2026-123633 path:** The use-after-free on the stream structure is exploited by spraying the heap with crafted HTTP/2 HEADERS frames, reclaiming the freed memory with attacker-controlled data that includes a fake vtable pointer.

Both paths achieve code execution within the NGINX worker process context.

### 3. Post-Exploitation

The PoC demonstrates spawning an interactive shell (`/bin/sh`) from the compromised NGINX worker process. Since NGINX workers typically run as an unprivileged user, the initial shell has the permissions of that user. However, the worker process has access to:
- TLS private keys loaded in memory
- All upstream application traffic passing through the proxy
- Configuration files readable by the NGINX user
- Potential for lateral movement to backend services

No C2 infrastructure is associated with the public PoC; it demonstrates a simple reverse shell. Real-world exploitation would likely deploy more sophisticated post-exploitation tooling.

### 4. Platform-Specific Behavior

#### Linux
The primary target platform. NGINX on Linux with HTTP/2 enabled is vulnerable. The PoC specifically targets Linux x86_64 with AVX-512 support. Worker processes crash with SIGSEGV (signal 11) on failed exploitation attempts; successful exploitation spawns a child shell process.

### 5. Anti-Forensics / Evasion Techniques

The attack occurs entirely over encrypted HTTP/2 (TLS), making network-level packet inspection ineffective. The malicious HTTP/2 frames are indistinguishable from legitimate traffic at the network layer. The only observable artifacts are:
- NGINX error log messages about connection draining (`worker_connections are not enough, reusing connections`)
- Worker process crash signals (SIGSEGV, SIGABRT, SIGBUS) on failed attempts
- Anomalous child processes (shells) spawned by the NGINX master/worker process tree

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through.

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|---------------------|-------------|
| NGINX (stable) | 1.9.5 – 1.30.6 | HTTP/2 integer underflow (CVE-2026-123007) |
| NGINX (mainline) | 1.19.7 – 1.31.8 | HTTP/2 use-after-free with proxy_pass variable hostname (CVE-2026-123633) |

### File System

No file-system IOCs are associated with these vulnerabilities. The exploit operates entirely in memory through HTTP/2 protocol manipulation.

### Network

Network-layer IOCs are not applicable. The attack occurs over standard HTTPS/HTTP2 connections and is indistinguishable from legitimate traffic at the packet level due to TLS encryption.

### Behavioral

- **Connection draining trigger:** NGINX error log entries containing `worker_connections are not enough, reusing connections` — indicates the prerequisite condition for exploitation has been reached
- **Worker process crashes:** NGINX error log entries showing worker process termination by signal 11 (SIGSEGV), signal 6 (SIGABRT), or signal 7 (SIGBUS) — indicates possible failed exploitation attempts
- **Anomalous child processes:** Shell interpreters (`/bin/sh`, `/bin/bash`, `/bin/dash`, etc.) spawned as child processes of an NGINX worker — a strong indicator of successful exploitation, as NGINX workers should never spawn interactive shells
- **High-volume HTTP/2 connections:** Sustained ~128 GB of HTTP/2 traffic over ~2.5 minutes from a single source (characteristic of the public PoC)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated RCE via HTTP/2 protocol manipulation against internet-facing NGINX servers |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation spawns `/bin/sh` or other Unix shells from the NGINX worker process |

## Impact Assessment

**Breadth:** NGINX serves approximately 34% of all websites and is the most common reverse proxy for cloud-native architectures. Any NGINX instance with HTTP/2 enabled (the default) running versions 1.9.5 through 1.30.6 (stable) or 1.19.7 through 1.31.8 (mainline) is potentially vulnerable. This represents millions of internet-facing servers.

**Depth:** Successful exploitation yields code execution as the NGINX worker user, granting access to TLS private keys, proxied traffic, backend service credentials, and a foothold for lateral movement. The unauthenticated, remote nature and public PoC availability make this a high-severity threat.

**Stealth:** The attack is difficult to detect at the network layer due to TLS encryption. Failed attempts produce worker crashes that may be dismissed as normal instability. Successful exploitation leaves minimal forensic artifacts beyond anomalous process trees.

## Detection & Remediation

### Immediate Detection

Check NGINX version:
```bash
nginx -v 2>&1
```

Check for signs of exploitation in NGINX error logs:
```bash
grep -E "worker_connections are not enough|exited on signal (11|6|7)|SIGSEGV|SIGABRT|SIGBUS|core dumped" /var/log/nginx/error.log
```

Check for suspicious child processes of NGINX:
```bash
ps -eo pid,ppid,user,comm --forest | grep -A5 nginx
```

Check if HTTP/2 is enabled:
```bash
grep -r "http2" /etc/nginx/ 2>/dev/null
```

### Remediation

1. **Patch immediately:** Upgrade to NGINX 1.30.7 (stable) or 1.31.9 (mainline)
2. **If patching is not immediately possible:** Disable HTTP/2 by removing `http2` from `listen` directives as a temporary mitigation
3. **For CVE-2026-123633 specifically:** Avoid using variable hostnames in `proxy_pass` directives (e.g., change `proxy_pass https://$host` to a static upstream)
4. **Increase `worker_connections`:** Raising the value makes the draining threshold harder to reach, though this is a mitigation, not a fix
5. **Rotate TLS certificates:** If exploitation is suspected, assume TLS private keys were compromised
6. **Audit process trees:** Investigate any shell processes that have ever been children of NGINX workers

### Long-Term Hardening

- Enable process monitoring/EDR to alert on unexpected child processes from web server workers
- Deploy NGINX with minimal privileges and mandatory access controls (AppArmor/SELinux profiles that prevent shell execution)
- Monitor NGINX error logs for connection draining warnings as an early indicator of connection exhaustion attacks
- Implement rate limiting on HTTP/2 connection and stream creation at the load balancer level
- Consider deploying a WAF or proxy upstream of NGINX that can limit HTTP/2 stream concurrency

## Detection Rules

Three Sigma rules cover the observable phases of nginx2root exploitation: the prerequisite connection draining condition, worker process crashes from failed attempts, and post-exploitation shell spawning. Network-level detection (Snort/Suricata) is not viable because the attack occurs over encrypted HTTP/2; YARA rules are not applicable as there are no file-level indicators.

### Sigma: NGINX Connection Drain Warning (CVE-2026-123007 Prerequisite)

compile: pass | confidence: medium

```yaml
title: NGINX Connection Drain Warning Indicating CVE-2026-123007 Prerequisite
id: 7c8e4a2f-1b39-4d6e-a5f7-9e3c2d8b1a04
status: experimental
description: >
    Detects the NGINX error log message indicating worker connection exhaustion
    and connection draining. This condition is a prerequisite for CVE-2026-123007
    and CVE-2026-123633 exploitation, where free worker_connections slots drop
    below one sixteenth of the configured value.
references:
    - https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/
    - https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html
author: Actioner
date: 2026/11/25
tags:
    - attack.t1190
logsource:
    product: linux
    service: syslog
detection:
    selection:
        SyslogMessage|contains|all:
            - 'worker_connections are not enough'
            - 'reusing connections'
    condition: selection
falsepositives:
    - Legitimately overloaded NGINX instances under heavy organic traffic
    - Misconfigured worker_connections setting with low values
level: medium
```

<!--
VALIDATION AUDIT
- sigma convert --without-pipeline -t splunk: exit 0
- sigma convert --without-pipeline -t loki: exit 0 (CrowdStrike LogScale backend)
- Logsource: product linux / service syslog — matches NGINX error log forwarded via syslog
- SyslogMessage field with |contains|all ensures both substrings present in same message
- Tags: attack.t1190 (Exploit Public-Facing Application) — correct per MITRE mapping
- UUID: generated, unique
- No defanged values in detection (none needed — matching log text)
- False positive rate: medium — legitimate overload can trigger the same log message
-->

### Sigma: NGINX Worker Process Crash Detection

compile: pass | confidence: medium

```yaml
title: NGINX Worker Process Crash Detected via Signal
id: e5d2f8a1-6b4c-49e3-8a7d-c1f03e9b2d75
status: experimental
description: >
    Detects NGINX error log messages indicating worker process termination by
    signal (SIGSEGV, SIGABRT, SIGBUS), which may indicate failed exploitation
    attempts of CVE-2026-123007 or CVE-2026-123633 use-after-free vulnerabilities.
references:
    - https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/
    - https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html
author: Actioner
date: 2026/11/25
tags:
    - attack.t1190
logsource:
    product: linux
    service: syslog
detection:
    selection_process:
        SyslogMessage|contains: 'nginx'
    selection_signal:
        SyslogMessage|contains:
            - 'worker process'
            - 'exited on signal'
    selection_crash_signal:
        SyslogMessage|contains:
            - 'signal 11'
            - 'signal 6'
            - 'signal 7'
            - 'SIGSEGV'
            - 'SIGABRT'
            - 'SIGBUS'
            - 'core dumped'
    condition: selection_process and selection_signal and selection_crash_signal
falsepositives:
    - NGINX crashes due to legitimate bugs or memory issues
    - Third-party module crashes in NGINX workers
level: medium
```

<!--
VALIDATION AUDIT
- sigma convert --without-pipeline -t splunk: exit 0
- sigma convert --without-pipeline -t loki: exit 0
- Logsource: product linux / service syslog — matches NGINX error log forwarded via syslog
- selection_signal uses OR list (contains any of 'worker process' or 'exited on signal') — intentional, both phrases appear in crash messages but matching either plus crash signal is sufficient
- Crash signals: 11=SIGSEGV, 6=SIGABRT, 7=SIGBUS — correct numeric and symbolic forms
- Tags: attack.t1190 — correct
- UUID: generated, unique
- False positive rate: medium — legitimate NGINX bugs produce identical log messages
-->

### Sigma: Suspicious Shell Spawned by NGINX Worker

compile: pass | confidence: high

```yaml
title: Suspicious Shell Process Spawned by NGINX Worker
id: 3a1f5e9d-8c72-4b6a-d3e1-f7a2c9b04e56
status: experimental
description: >
    Detects shell or command interpreter processes spawned by an NGINX worker
    process, which may indicate post-exploitation of CVE-2026-123007 (nginx2root)
    or CVE-2026-123633. NGINX workers should never spawn interactive shells.
references:
    - https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/
    - https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html
author: Actioner
date: 2026/11/25
tags:
    - attack.t1059.004
    - attack.t1190
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith: '/nginx'
    selection_shell:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
            - '/ksh'
            - '/csh'
    condition: selection_parent and selection_shell
falsepositives:
    - Custom NGINX modules that intentionally execute shell commands
    - NGINX health check scripts executed via exec directives
level: high
```

<!--
VALIDATION AUDIT
- sigma convert --without-pipeline -t splunk: exit 0
- sigma convert --without-pipeline -t loki: exit 0
- Logsource: category process_creation / product linux — matches Sysmon for Linux, auditd process tracking, or EDR telemetry
- ParentImage|endswith '/nginx' — matches any nginx binary path
- Image|endswith covers all major Unix shell interpreters
- Tags: attack.t1059.004 (Unix Shell) + attack.t1190 (Exploit Public-Facing Application) — both correct
- UUID: generated, unique
- Confidence high: NGINX workers spawning shells is inherently suspicious with very few legitimate scenarios
-->

### Snort / Suricata

Not applicable. The attack occurs over encrypted HTTP/2 (TLS), making payload inspection at the network layer infeasible without TLS termination upstream of the IDS.

### YARA

Not applicable. No file-level artifacts (dropped binaries, scripts, or distinctive file content) are associated with these vulnerabilities. The exploit operates entirely in memory via HTTP/2 protocol manipulation.

## Lessons Learned

The nginx2root vulnerabilities highlight the risk of decade-old code in widely deployed infrastructure components. The vulnerable HTTP/2 codepath existed since 2015 — over 10 years — before discovery. This underscores the need for ongoing security auditing of protocol implementations in critical infrastructure software, even when they have been stable for years.

The encrypted nature of HTTP/2 over TLS makes network-level detection infeasible, reinforcing the importance of host-based detection: process monitoring, error log analysis, and endpoint detection capabilities. Organizations relying solely on network IDS/IPS for web server protection have a blind spot for this class of attack.

The ~128 GB traffic requirement and AVX-512 CPU prerequisite of the current PoC provide some practical barrier, but these constraints are likely to be relaxed as exploit development matures. Organizations should treat the patch timeline as urgent regardless of these current limitations.

## Sources

- [Unit 42: CVE-2026-123633 NGINX HTTP/2 Vulnerability Analysis](https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/) — primary technical analysis of the use-after-free vulnerability, exploitation mechanism, and connection draining prerequisite
- [The Hacker News: 10-Year-Old NGINX HTTP/2 Flaw Lets Attackers Execute Remote Code](https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html) — reporting on both CVEs with PoC details, affected versions, and patch availability

---
*Report generated by Actioner*
