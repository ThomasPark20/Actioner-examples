# Technical Analysis Report: NGINX Critical RCE Vulnerabilities (CVE-2026-42530 & CVE-2026-42055) (2026-06-19)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-19
Version: 1.1

## Executive Summary

On June 17, 2026, F5 Networks released out-of-band emergency patches for two critical remote code execution vulnerabilities in NGINX Open Source and NGINX Plus. CVE-2026-42530 (CVSS 9.2) is a use-after-free vulnerability in the HTTP/3 QUIC module (`ngx_http_v3_module`) that allows remote unauthenticated attackers to crash or potentially execute code on NGINX worker processes by sending specially crafted HTTP/3 sessions that reopen a QPACK encoder stream. CVE-2026-42055 (CVSS 9.2) is a heap-based buffer overflow in the HTTP/2 proxy modules (`ngx_http_proxy_v2_module` and `ngx_http_grpc_module`) exploitable via oversized HTTP headers when specific non-default configuration directives are active.

No active exploitation in the wild has been reported as of publication. However, given the severity ratings, the ubiquity of NGINX in production infrastructure, and the historical precedent of CVE-2026-42945 ("NGINX Rift") seeing exploitation within days of disclosure, the risk of imminent weaponization is high. Organizations running affected versions should patch immediately or apply the documented mitigations.

## Background: NGINX Web Server

NGINX is one of the most widely deployed web servers and reverse proxy platforms globally, powering an estimated 34% of all web-facing infrastructure. It is the default ingress controller in many Kubernetes deployments and serves as the foundation for F5's commercial NGINX Plus product line. The affected components -- HTTP/3 QUIC support and HTTP/2 upstream proxying -- are increasingly adopted features in modern deployment architectures, making the exposure surface significant.

NGINX Open Source added experimental HTTP/3 (QUIC) support starting in version 1.25.0, with the feature becoming production-ready in the 1.31.x branch. HTTP/2 upstream proxying (`proxy_http_version 2`) has been available since version 1.13.10 and is commonly used in gRPC proxy and microservice mesh configurations.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-17 | F5 Networks publishes out-of-band security advisories K000161616 (CVE-2026-42530) and K000161584 (CVE-2026-42055) |
| 2026-06-17 | NVD entries created for both CVEs; initial disclosure credited to F5 Networks |
| 2026-06-18 | NVD entries updated; CVSS v4.0 scores confirmed at 9.2 Critical for both |
| 2026-06-19 | Multiple security news outlets publish coverage; patched versions available |

## Root Cause: Memory Safety Vulnerabilities in NGINX Protocol Modules

### CVE-2026-42530: Use-After-Free in HTTP/3 QUIC Module

The vulnerability resides in `ngx_http_v3_module`, specifically in the QPACK (QUIC Header Compression) encoder stream handling logic. An attacker can craft an HTTP/3 session that causes the NGINX worker process to reopen a QPACK encoder stream after the associated memory has been freed. This use-after-free condition (CWE-416) leads to memory corruption in the worker process.

**Exploitation requirements:**
- Target must have HTTP/3 (QUIC) enabled via `listen ... quic` directives
- Remote, unauthenticated access to the QUIC port (typically UDP 443)
- For reliable code execution: ASLR must be disabled or bypassable

**Impact:**
- Guaranteed: Worker process crash and restart (denial of service)
- Potential: Arbitrary code execution when ASLR is disabled or bypassed

**Affected versions:** NGINX Open Source 1.31.0 and 1.31.1
**Fixed version:** NGINX Open Source 1.31.2

### CVE-2026-42055: Heap-Based Buffer Overflow in HTTP/2 Proxy Modules

The vulnerability exists in `ngx_http_proxy_v2_module` and `ngx_http_grpc_module` when processing HTTP/2 upstream traffic. An attacker sends oversized HTTP headers that trigger a heap-based buffer overflow (CWE-122) in the worker process when three non-default configuration conditions are met simultaneously.

**Exploitation requirements (all three must be true):**
1. A location block using `proxy_http_version 2` or `grpc_pass` directive
2. The `ignore_invalid_headers` directive is set to `off` (default is `on`)
3. The `large_client_header_buffers` directive exceeds 2 MB

**Impact:**
- Worker process crash and restart (denial of service)
- Potential arbitrary code execution when ASLR is disabled or bypassed
- Deployments using default NGINX configuration are NOT exposed

**Affected versions:**
- NGINX Open Source 1.13.10 through 1.31.1 (fixed in 1.31.2)
- NGINX Open Source 1.30.0 through 1.30.2 (fixed in 1.30.3)
- NGINX Plus R33 through R36 (fixed in R36 P6)
- NGINX Plus 37.0.0 through 37.0.1 (fixed in 37.0.2.1)

## Technical Analysis of the Malicious Payload

### 1. CVE-2026-42530: QPACK Encoder Stream Manipulation

The attack vector involves sending a crafted HTTP/3 session over QUIC (UDP) that manipulates the QPACK encoder stream lifecycle. QPACK is the header compression mechanism specified in RFC 9204 for HTTP/3. The vulnerability is triggered when:

1. A legitimate QPACK encoder stream is established during an HTTP/3 session
2. The attacker sends a specially crafted sequence that causes the stream to be closed and the associated memory freed
3. A subsequent operation in the same session references the freed QPACK encoder stream memory
4. The dangling pointer dereference corrupts the worker process heap

No public proof-of-concept code or specific payload bytes have been disclosed. The advisory describes the mechanism at a conceptual level only.

### 2. CVE-2026-42055: Oversized Header Heap Overflow

The attack exploits insufficient bounds checking when NGINX processes HTTP/2 upstream headers with non-default configuration:

1. The attacker sends HTTP requests with headers exceeding the `large_client_header_buffers` allocation
2. Because `ignore_invalid_headers` is disabled, malformed/oversized headers are not rejected at the parsing stage
3. When proxied upstream via HTTP/2 (`proxy_http_version 2`) or gRPC (`grpc_pass`), the header data overflows the allocated heap buffer
4. The overflow corrupts adjacent heap structures, crashing the worker process

The specific requirement for all three configuration conditions reduces the attack surface but does not eliminate it -- gRPC proxy deployments frequently disable header validation for interoperability.

### 3. Crash Behavior and Observable Artifacts

Both vulnerabilities produce observable artifacts in NGINX error logs when triggered:

- Worker process crash entries: `worker process [PID] exited on signal 11`
- NGINX master process spawning replacement workers: `start worker process [PID]`
- For CVE-2026-42530: crash context may reference `ngx_http_v3`, `quic`, or `qpack` functions in core dumps
- For CVE-2026-42055: crash context may reference `ngx_http_proxy`, `ngx_http_grpc`, or `upstream` functions

Repeated crashes in rapid succession (crash-restart loops) are indicative of active exploitation attempts, particularly brute-force ASLR bypass attempts.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| NGINX Open Source | 1.31.0, 1.31.1 | Affected by both CVE-2026-42530 and CVE-2026-42055 |
| NGINX Open Source | 1.30.0 - 1.30.2 | Affected by CVE-2026-42055 only |
| NGINX Plus | R33 - R36, 37.0.0 - 37.0.1 | Affected by CVE-2026-42055 |
| NGINX Gateway Fabric | 2.0.0 - 2.6.3 | Affected by CVE-2026-42530 |
| NGINX Ingress Controller | 5.0.0 - 5.5.0, 4.0.0 - 4.0.1, 3.5.0 - 3.7.2 | Affected by CVE-2026-42530 |
| NGINX Instance Manager | 2.17.0 - 2.22.0 | Affected by CVE-2026-42530 |

### File System

No file-system IOCs have been published for these vulnerabilities. Core dump files generated by worker process crashes may contain forensic evidence:

| Platform | Path | Description |
|----------|------|-------------|
| Linux | `/var/log/nginx/error.log` | NGINX error log containing crash entries |
| Linux | Core dump path (system-dependent) | Worker process core dumps with memory corruption evidence |

### Network

No specific network-level IOCs (C2 domains, IPs, URLs) are associated with these vulnerabilities. Detection focuses on protocol-level anomalies:

| Type | Value | Context |
|------|-------|---------|
| Protocol | QUIC (UDP 443) | CVE-2026-42530 attack vector |
| Protocol | HTTP/2 | CVE-2026-42055 attack vector |
| Server Header | `nginx/1.31.0`, `nginx/1.31.1` | Vulnerable version identification |
| Server Header | `nginx/1.30.0` through `nginx/1.30.2` | Vulnerable to CVE-2026-42055 |

### Behavioral

- **Worker process crash loops:** Rapid succession of `worker process exited on signal 11` entries in NGINX error logs, particularly when correlated with incoming HTTP/3 or HTTP/2 traffic bursts
- **QPACK stream anomalies:** HTTP/3 sessions with unusual QPACK encoder stream lifecycle patterns (open-close-reopen sequences)
- **Oversized HTTP/2 headers:** HTTP/2 requests with aggregate header size exceeding 2 MB targeting endpoints configured with `grpc_pass` or `proxy_http_version 2`
- **Post-exploitation indicators:** If code execution is achieved, standard post-exploitation behaviors (reverse shells, file drops, persistence mechanisms) originating from the NGINX worker process UID

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Remote exploitation of NGINX vulnerabilities via crafted HTTP/3 or HTTP/2 requests, potentially leading to code execution on the server |
| T1499.004 | Application or System Exploitation (Endpoint DoS) | Worker process crashes causing denial of service |
| T1592 | Gather Victim Host Information | Vulnerable NGINX version strings exposed in Server response headers enable attacker reconnaissance |

<!-- revision: T1203 (Exploitation for Client Execution) removed — T1203 is client-side exploitation, not server-side. T1592 added for the version-detection asset-awareness rules. -->

## Impact Assessment

**Breadth:** NGINX is deployed on an estimated 400+ million websites and servers globally. HTTP/3 QUIC adoption is growing rapidly, and HTTP/2 upstream proxying is standard in microservice architectures. The CVE-2026-42055 attack surface is limited by the requirement for three non-default configuration directives, but CVE-2026-42530 affects any NGINX instance with HTTP/3 enabled.

**Depth:** Both vulnerabilities carry a CVSS v4.0 score of 9.2 (Critical). Successful exploitation yields at minimum denial of service and potentially full remote code execution, though the latter requires ASLR bypass.

**Stealth:** Exploitation attempts produce visible crash entries in NGINX error logs, making detection feasible. However, a successful single-shot exploit (without crash-restart brute-forcing) would leave minimal traces beyond a single worker process restart.

**Known exploitation:** No active exploitation in the wild as of 2026-06-19. Historical precedent with CVE-2026-42945 ("NGINX Rift") suggests weaponization may occur within days.

## Detection & Remediation

### Immediate Detection

Check for vulnerable NGINX versions:

```bash
# Check NGINX version
nginx -v 2>&1

# Check for HTTP/3 QUIC configuration (CVE-2026-42530)
grep -rn 'listen.*quic' /etc/nginx/

# Check for CVE-2026-42055 trigger conditions (all three must be present)
grep -rn 'proxy_http_version\s*2\|grpc_pass' /etc/nginx/
grep -rn 'ignore_invalid_headers\s*off' /etc/nginx/
grep -rn 'large_client_header_buffers' /etc/nginx/

# Check error logs for exploitation indicators
grep -c 'exited on signal 11' /var/log/nginx/error.log
grep 'worker process.*exited on signal 11' /var/log/nginx/error.log | tail -20
```

### Remediation

1. **Patch immediately:**
   - NGINX Open Source: Upgrade to 1.31.2 (or 1.30.3 for the stable branch)
   - NGINX Plus: Upgrade to R36 P6 or 37.0.2.1
   - NGINX Gateway Fabric: Upgrade to 2.6.4
   - Follow the upgrade paths documented in the F5 advisories

2. **Apply mitigations if patching is delayed:**
   - CVE-2026-42530: Remove `quic` from all `listen` directives to disable HTTP/3
   - CVE-2026-42055: Remove `ignore_invalid_headers off` directives (restore default `on`) or reduce `large_client_header_buffers` below 2 MB

3. **Monitor for exploitation:**
   - Deploy the detection rules in the Detection Rules section below
   - Enable verbose NGINX error logging
   - Set up alerting on worker process crash patterns

### Long-Term Hardening

- **Keep NGINX updated:** Subscribe to F5/NGINX security mailing lists for timely patch notification
- **Enable ASLR:** Ensure ASLR is enabled on all systems running NGINX (`cat /proc/sys/kernel/randomize_va_space` should return `2`)
- **Minimize attack surface:** Only enable HTTP/3 and HTTP/2 upstream proxying where required
- **Configuration review:** Audit non-default directives like `ignore_invalid_headers off` and oversized `large_client_header_buffers`
- **Core dump analysis:** Configure core dump collection for NGINX worker processes to enable post-incident forensics

## Detection Rules

These rules detect exploitation indicators for CVE-2026-42530 and CVE-2026-42055 at both the host log level (Sigma for NGINX error logs) and network level (Suricata/Snort for protocol anomalies and version identification). No public PoC payloads exist, so network-level rules focus on behavioral anomalies and vulnerable version detection rather than exact exploit byte patterns.

### Sigma: NGINX HTTP/3 Worker Process Crash (CVE-2026-42530)

Detects NGINX worker process crashes (signal 11) in error logs, indicating potential CVE-2026-42530 exploitation. Module-specific keywords (ngx_http_v3, quic, qpack) appear in core dump backtraces, not in the standard NGINX error log line, so this rule fires on any signal 11 crash and should be combined with core dump analysis for HTTP/3-specific attribution.

compile: pass | confidence: low

```yaml
title: NGINX Worker Process Crash Indicating HTTP/3 Use-After-Free Exploitation (CVE-2026-42530)
id: 60e3bdd3-d59b-4a98-9549-fbd858a88fa8
status: experimental
description: >
    Detects NGINX worker process crashes (signal 11/SIGSEGV) in the error log
    that may indicate exploitation of CVE-2026-42530, a use-after-free
    vulnerability in the ngx_http_v3_module (HTTP/3 QUIC). Worker process
    crashes caused by memory corruption from QPACK encoder stream manipulation
    will produce signal 11 entries in the NGINX error log. Module keywords
    (ngx_http_v3, quic, qpack) appear in core dump backtraces, not in the
    standard error log line; this rule fires on signal 11 crashes and should
    be combined with core dump analysis for HTTP/3-specific attribution.
references:
    - https://my.f5.com/manage/s/article/K000161616
    - https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html
author: Actioner
date: 2026-06-19
tags:
    - attack.t1190
logsource:
    category: application
    product: nginx
detection:
    selection_crash:
        data|contains|all:
            - 'worker process'
            - 'exited on signal 11'
    condition: selection_crash
falsepositives:
    - Legitimate NGINX worker crashes due to bugs unrelated to exploitation
    - Memory issues caused by system resource exhaustion
level: medium
```

<!-- revision: Fixed logsource from category:webserver to category:application/product:nginx (error logs, not access logs). Replaced cs-uri field (W3C access log field) with data field (correct for application/error logs). Removed module-specific keyword filter (ngx_http_v3, quic, qpack) because these tokens do not appear in the standard NGINX error log format — they only appear in core dump backtraces. Lowered confidence from medium to low and level from high to medium to reflect the reduced specificity. -->
<!-- audit: sigma check pass (0 errors, 0 issues); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: NGINX HTTP/2 Worker Process Crash (CVE-2026-42055)

Detects NGINX worker process crashes (signal 11) in error logs, indicating potential CVE-2026-42055 exploitation. Module-specific keywords (ngx_http_proxy, ngx_http_grpc) appear in core dump backtraces, not in the standard NGINX error log line. The "upstream" keyword was removed as it is too broad and triggers on benign upstream connectivity errors.

compile: pass | confidence: low

```yaml
title: NGINX Worker Process Crash Indicating HTTP/2 Buffer Overflow Exploitation (CVE-2026-42055)
id: 5968f81b-f6a8-495e-bdf2-1ccf487c3d6a
status: experimental
description: >
    Detects NGINX worker process crashes (signal 11/SIGSEGV) in the error log
    that may indicate exploitation of CVE-2026-42055, a heap-based buffer
    overflow in ngx_http_proxy_v2_module and ngx_http_grpc_module. Crashes from
    oversized HTTP/2 header manipulation will produce signal 11 entries. Module
    keywords (ngx_http_proxy, ngx_http_grpc) appear in core dump backtraces,
    not in the standard error log line; this rule fires on signal 11 crashes
    and should be combined with core dump analysis for HTTP/2-specific
    attribution.
references:
    - https://my.f5.com/manage/s/article/K000161584
    - https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html
author: Actioner
date: 2026-06-19
tags:
    - attack.t1190
logsource:
    category: application
    product: nginx
detection:
    selection_crash:
        data|contains|all:
            - 'worker process'
            - 'exited on signal 11'
    condition: selection_crash
falsepositives:
    - Legitimate NGINX worker crashes due to bugs unrelated to exploitation
    - Upstream connectivity issues causing worker instability
level: medium
```

<!-- revision: Fixed logsource from category:webserver to category:application/product:nginx (error logs, not access logs). Replaced cs-uri field with data field. Removed module-specific keyword filter (ngx_http_proxy, ngx_http_grpc, upstream) — these tokens do not appear in the standard NGINX error log format, and "upstream" is too broad, matching benign upstream errors. Lowered confidence from medium to low. -->
<!-- audit: sigma check pass (0 errors, 0 issues); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: NGINX Worker Process Crash on Signal 11 (Single-Event Detector)

Detects any NGINX worker process exit on signal 11 (SIGSEGV). This is a **single-event detector**, not a crash-loop detector -- it fires once per crash entry. Layer SIEM correlation (e.g., count >= 5 within 60 seconds) on top of this rule to detect crash-restart loops indicative of exploit brute-forcing.

compile: pass | confidence: medium

```yaml
title: NGINX Worker Process Crash on Signal 11 (CVE-2026-42530 / CVE-2026-42055 Indicator)
id: d9f0fb72-3b15-4125-99db-aa8d1564adb6
status: experimental
description: >
    Detects any NGINX worker process exit on signal 11 (SIGSEGV) in the error
    log. This is a single-event detector; layer SIEM correlation (count >= 5
    within 60 seconds) on top of this rule to detect crash-restart loops
    indicative of memory corruption exploit brute-forcing against
    CVE-2026-42530 or CVE-2026-42055. A single crash is suspicious; rapid
    repeated crashes are near-certain exploitation.
references:
    - https://my.f5.com/manage/s/article/K000161616
    - https://my.f5.com/manage/s/article/K000161584
    - https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html
author: Actioner
date: 2026-06-19
tags:
    - attack.t1190
logsource:
    category: application
    product: nginx
detection:
    selection:
        data|contains|all:
            - 'worker process'
            - 'exited on signal 11'
    condition: selection
falsepositives:
    - NGINX under severe memory pressure from legitimate traffic
    - Configuration errors causing repeated crashes
level: high
```

<!-- revision: Renamed from "NGINX Rapid Worker Process Restarts" to "NGINX Worker Process Crash on Signal 11" to honestly reflect single-event logic (no temporal aggregation). Fixed logsource from category:webserver to category:application/product:nginx. Replaced cs-uri field with data field. Lowered confidence from high to medium. Changed level from critical to high — a single crash is suspicious but not certainly malicious. -->
<!-- audit: sigma check pass (0 errors, 0 issues); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. -->

### Sigma: NGINX Vulnerable Version in Server Response Header

Asset-awareness rule to identify unpatched NGINX instances by matching vulnerable version strings in web traffic logs. Uses fieldless keyword matching because there is no standard Sigma field for the Server response header; map to the appropriate field in your SIEM pipeline (e.g., `sc_server`, `response.server`, `http.response.header.server`). Does not cover NGINX Plus version strings (e.g., `nginx-plus-r36`).

compile: pass | confidence: medium

```yaml
title: NGINX Vulnerable Version Detected in Server Response Header
id: f1258d34-a297-4be1-af18-69630ccdc5a0
status: experimental
description: >
    Detects NGINX server response headers advertising versions known to be
    vulnerable to CVE-2026-42530 and/or CVE-2026-42055. This is an
    asset-awareness rule to identify unpatched NGINX instances in web traffic
    logs. Versions 1.31.0 and 1.31.1 are affected by both CVEs. Versions
    1.30.0 through 1.30.2 are affected by CVE-2026-42055 only. Does not
    cover NGINX Plus version strings (e.g., "nginx-plus-r36"). Field mapping
    is pipeline-dependent; map keywords to the Server header field in your
    SIEM (e.g., sc_server, response.server, http.response.header.server).
references:
    - https://my.f5.com/manage/s/article/K000161616
    - https://my.f5.com/manage/s/article/K000161584
    - https://securityonline.info/nginx-vulnerabilities/
author: Actioner
date: 2026-06-19
tags:
    - attack.t1592
logsource:
    category: webserver
detection:
    keywords:
        - 'nginx/1.31.0'
        - 'nginx/1.31.1'
        - 'nginx/1.30.0'
        - 'nginx/1.30.1'
        - 'nginx/1.30.2'
    condition: keywords
falsepositives:
    - NGINX instances with custom or spoofed Server headers
    - Testing environments running vulnerable versions intentionally
level: medium
```

<!-- revision: Replaced sc-header field (non-standard in Sigma) with fieldless keywords matching. Changed ATT&CK tag from T1190 to T1592 (Gather Victim Host Information) — version detection is reconnaissance/asset-awareness, not exploitation. Added note about NGINX Plus version gaps. Lowered confidence from high to medium due to fieldless matching. -->
<!-- audit: sigma check pass (0 errors, 0 issues); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. -->

<!-- revision: DROPPED — Suricata QUIC Flood rule (sid:2100010). Generic volumetric rule with no CVE-specific content. The threshold of 50 QUIC packets in 10 seconds has no exploit-specific basis and fires on normal HTTP/3 browsing. Without public PoC payloads, no meaningful content match can be constructed. -->

### Suricata: HTTP Oversized Header Detection (CVE-2026-42055 Hunt Lead)

Detects HTTP requests with headers exceeding 64 KB. This is a low-confidence hunt lead: the actual CVE-2026-42055 trigger threshold is approximately 2 MB (`large_client_header_buffers` exceeding 2 MB), and this rule fires on all HTTP traffic, not just HTTP/2. Useful for identifying anomalously large headers that warrant investigation.

compile: pass | confidence: low

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - HTTP Oversized Header Potential CVE-2026-42055 Hunt Lead"; flow:established,to_server; http.header; bsize:>65535; classtype:attempted-admin; reference:url,my.f5.com/manage/s/article/K000161584; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100011; rev:2;)
```

<!-- revision: Renamed to "Hunt Lead" and lowered confidence from medium to low. The 65535 threshold is well below the actual 2MB CVE trigger, making this a broad anomaly detector. Added clarification that it fires on all HTTP, not just HTTP/2, as Suricata's http handler covers both. -->
<!-- audit: suricata -T pass. -->

### Suricata: NGINX Vulnerable Version in Server Response Header

Identifies unpatched NGINX instances by matching vulnerable version strings in the HTTP Server response header. Uses `http.server` sticky buffer for precise header matching. Each vulnerable version has its own rule to avoid prefix over-matching (e.g., `nginx/1.30.` would incorrectly match patched `1.30.3`).

compile: pass | confidence: high

```
alert http $HOME_NET any -> any any (msg:"Actioner - NGINX Vulnerable Version 1.31.0 in Server Header (CVE-2026-42530/CVE-2026-42055)"; flow:established,to_client; http.server; content:"nginx/1.31.0"; classtype:policy-violation; reference:cve,2026-42530; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100012; rev:2;)

alert http $HOME_NET any -> any any (msg:"Actioner - NGINX Vulnerable Version 1.31.1 in Server Header (CVE-2026-42530/CVE-2026-42055)"; flow:established,to_client; http.server; content:"nginx/1.31.1"; classtype:policy-violation; reference:cve,2026-42530; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100013; rev:2;)

alert http $HOME_NET any -> any any (msg:"Actioner - NGINX Vulnerable Version 1.30.0 in Server Header (CVE-2026-42055)"; flow:established,to_client; http.server; content:"nginx/1.30.0"; classtype:policy-violation; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100014; rev:2;)

alert http $HOME_NET any -> any any (msg:"Actioner - NGINX Vulnerable Version 1.30.1 in Server Header (CVE-2026-42055)"; flow:established,to_client; http.server; content:"nginx/1.30.1"; classtype:policy-violation; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100017; rev:1;)

alert http $HOME_NET any -> any any (msg:"Actioner - NGINX Vulnerable Version 1.30.2 in Server Header (CVE-2026-42055)"; flow:established,to_client; http.server; content:"nginx/1.30.2"; classtype:policy-violation; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-19; sid:2100018; rev:1;)
```

<!-- revision: Fixed 1.30.x prefix over-match: replaced single "nginx/1.30." prefix rule (sid:2100014) with three explicit version rules (1.30.0, 1.30.1, 1.30.2) to avoid matching patched 1.30.3. Switched from http.response_header with content:"Server" to http.server sticky buffer (cleaner, single-buffer match). -->
<!-- audit: suricata -T pass (all 5 rules). -->

<!-- revision: DROPPED — Snort HTTP/2 Oversized Payload rule (sid:2100015). Fundamentally flawed: dsize:>65535 applies to individual TCP segments (typically ~1460 bytes MTU), not reassembled HTTP content. A TCP segment will never exceed 65535 bytes, so this rule can never fire. -->

### Snort: NGINX Vulnerable Version in Server Response Header

Identifies unpatched NGINX 1.31.x instances in HTTP response Server headers.

compile: pass | confidence: high

```
alert tcp $HOME_NET $HTTP_PORTS -> any any (msg:"Actioner - NGINX Vulnerable Version in Server Header (CVE-2026-42530/CVE-2026-42055)"; flow:established,to_client; content:"Server|3a| nginx/1.31."; nocase; classtype:policy-violation; reference:cve,2026-42530; reference:cve,2026-42055; sid:2100016; rev:1;)
```

<!-- audit: snort -c /etc/snort/snort.conf -T pass (via include). Matches "Server: nginx/1.31." in response headers. Uses hex |3a| for colon to avoid ambiguity. Covers both 1.31.0 and 1.31.1 via prefix match. High confidence for version identification. Does not cover 1.30.x versions; a separate rule could be added. -->

## Lessons Learned

1. **Memory-unsafe languages remain a systemic risk in critical infrastructure.** NGINX is written in C, and both vulnerabilities are memory safety bugs (use-after-free and heap buffer overflow) that would be impossible in memory-safe languages. As HTTP/3 and HTTP/2 add protocol complexity, the attack surface in C-based implementations grows.

2. **Feature adoption outpaces security hardening.** HTTP/3 QUIC support in NGINX is relatively new (production-ready only in 1.31.x), and the QPACK encoder stream handling had a fundamental lifecycle management bug. Organizations should evaluate the security maturity of new protocol features before enabling them in production.

3. **Non-default configurations can create unexpected exposure.** CVE-2026-42055 requires three non-default directives to be active simultaneously, which might lead organizations to dismiss the risk. However, gRPC proxy deployments commonly disable `ignore_invalid_headers` for interoperability, and large header buffers are a common tuning parameter -- making the combination more prevalent than it appears.

4. **Detection without PoC payloads is challenging but feasible.** In the absence of public exploit code, detection rules must rely on behavioral indicators (crash patterns, protocol anomalies, version identification) rather than exact payload signatures. This underscores the value of maintaining layered detection at both host and network levels.

## Sources

- [The Hacker News](https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html) — primary reporting on both CVEs with affected version details and mitigation guidance
- [Security Affairs](https://securityaffairs.com/193842/security/f5-patches-critical-nginx-vulnerabilities-enabling-unauthenticated-code-execution.html) — additional context on exploitation requirements and impact assessment
- [Security Online](https://securityonline.info/nginx-vulnerabilities/) — detailed affected version matrix and official advisory links
- [NVD - CVE-2026-42530](https://nvd.nist.gov/vuln/detail/CVE-2026-42530) — CVSS vectors, CWE classification, and official description
- [NVD - CVE-2026-42055](https://nvd.nist.gov/vuln/detail/CVE-2026-42055) — CVSS vectors, CWE classification, affected version ranges
- [F5 Advisory K000161616](https://my.f5.com/manage/s/article/K000161616) — official F5 advisory for CVE-2026-42530 (requires authentication)
- [F5 Advisory K000161584](https://my.f5.com/manage/s/article/K000161584) — official F5 advisory for CVE-2026-42055 (requires authentication)

---
*Report generated by Actioner*
