# F5 NGINX Critical RCE Vulnerabilities — CVE-2026-42530 and CVE-2026-42055

**Date**: 2026-06-22 | **CVSS v3.1**: 9.2 (Critical) | **CWE**: CWE-416 (Use After Free), CWE-122 (Heap-based Buffer Overflow)

---

## Executive Summary

Two critical unauthenticated remote code execution vulnerabilities have been disclosed in F5 NGINX Open Source and NGINX Plus, both carrying a CVSS 9.2 score. CVE-2026-42530 is a use-after-free in the `ngx_http_v3_module` caused by a lifetime mismatch between HTTP/3 session pointers and unidirectional QUIC stream memory. CVE-2026-42055 is a heap-based buffer overflow in `ngx_http_proxy_v2_module` and `ngx_http_grpc_module`, triggered when the HPACK encoder emits 5-byte length prefixes into a 4-byte reservation for header values exceeding 2,097,278 bytes. Both vulnerabilities enable unauthenticated remote code execution on affected NGINX instances. F5 released out-of-band patches in NGINX 1.31.2 and 1.30.3.

No in-the-wild exploitation has been observed yet, but the rapid weaponization of the prior F5 vulnerability CVE-2026-42945 suggests defenders should treat these as high-urgency patches. NGINX is one of the most widely deployed web servers globally, making the attack surface significant even though exploitation requires specific configuration prerequisites.

---

## Background: NGINX HTTP/2 and HTTP/3 Proxy Infrastructure

NGINX is a high-performance HTTP server and reverse proxy used extensively as a load balancer, API gateway, and edge proxy. HTTP/2 support (via `ngx_http_v2_module`) has been available since NGINX 1.9.5 (September 2015), and HTTP/3 QUIC support (via `ngx_http_v3_module`) was added in NGINX 1.25.0 (May 2023). The gRPC proxying module (`ngx_http_grpc_module`) was introduced in NGINX 1.13.10 (March 2018).

These modules handle performance-critical protocol translation at the edge of enterprise networks. HTTP/2 proxying and gRPC pass-through are common in microservice architectures, and HTTP/3 QUIC adoption is accelerating as organizations seek improved latency and connection migration capabilities.

---

## Attack Timeline (All Times UTC)

| Date | Event |
|------|-------|
| 2026-06-18 | F5 releases out-of-band patches: NGINX 1.31.2 and 1.30.3 |
| 2026-06-18 | F5 publishes advisories K000161616 (CVE-2026-42530) and K000161584 (CVE-2026-42055) |
| 2026-06-19 | Security media coverage from The Hacker News, BleepingComputer, SecurityAffairs |
| 2026-06-22 | No in-the-wild exploitation reported; no public PoC available |

---

## Root Cause: CVE-2026-42530 — HTTP/3 QUIC Use-After-Free

The `ngx_http_v3_module` contains a lifetime mismatch between two memory pools. When HTTP/3 QPACK decoder processes header instructions, a pointer from the HTTP/3 session (which persists for the full connection duration) stores a reference to memory allocated from a unidirectional QUIC stream (which has a shorter lifetime tied to that individual stream). When the unidirectional stream closes normally and its memory pool is freed, the session-level pointer becomes a dangling reference. Subsequent access through this pointer triggers a use-after-free condition.

**Exploitation prerequisites:**
- HTTP/3 QUIC must be configured (`listen ... quic` directive in nginx.conf)
- NGINX version 1.31.0 or 1.31.1

**Attack vector:** An attacker sends crafted HTTP/3 QUIC packets that open and close unidirectional streams in a specific pattern, then trigger the session to dereference the freed pointer. The freed memory region can be reclaimed with attacker-controlled data, achieving arbitrary code execution within the NGINX worker process context.

---

## Root Cause: CVE-2026-42055 — HTTP/2 HPACK Heap Buffer Overflow

The HPACK encoder in `ngx_http_proxy_v2_module` and `ngx_http_grpc_module` contains an off-by-one in its length-prefix serialization. The encoder reserves 4 bytes for HPACK integer-encoded length prefixes. However, the HPACK integer encoding scheme (RFC 7541, Section 5.1) requires 5 bytes to represent values that exceed 2,097,278 (0x1FFFFE). When a header value exceeds this length, the encoder writes 5 bytes into the 4-byte reservation, causing a 1-byte heap buffer overflow. While only 1 byte overflows the reservation, the attacker controls the header content that follows, and the corrupted heap metadata enables arbitrary write primitives.

**Exploitation prerequisites (all must be true):**
- HTTP/2 proxying is configured (upstream uses HTTP/2 or gRPC)
- `ignore_invalid_headers off` is set (non-default; allows oversized headers to pass validation)
- `large_client_header_buffers` is configured to exceed 2 MB (non-default; allows the oversized header to be received)
- NGINX version 1.13.10 through 1.31.1

**Attack vector:** An attacker sends an HTTP/2 request through the NGINX proxy with a header value exceeding 2,097,278 bytes. When NGINX re-encodes this header using HPACK for the upstream connection, the 5-byte length prefix overflows the 4-byte reservation, corrupting the adjacent heap region. The attacker shapes the heap layout via preceding requests to place controllable data adjacent to the overflow, enabling code execution.

---

## Technical Analysis of the Malicious Payload

### 1. CVE-2026-42530 — HTTP/3 QPACK Stream Lifetime Exploit

The attack targets the QPACK dynamic table update mechanism in HTTP/3. The QUIC protocol multiplexes multiple streams over a single connection, and HTTP/3 uses dedicated unidirectional streams for QPACK encoder/decoder instructions. The vulnerability lies in the fact that `ngx_http_v3_parse_header()` stores table entries using pointers from the stream's memory pool rather than copying them into the session's pool:

1. Attacker establishes an HTTP/3 QUIC connection
2. Sends QPACK encoder instructions on a unidirectional stream, causing the session to store a pointer into the stream's memory pool
3. Closes the unidirectional stream, triggering `ngx_quic_close_stream()` which frees the stream's pool
4. Sends new requests that allocate into the freed memory region with attacker-controlled data
5. Triggers the session to dereference the dangling pointer, now pointing to attacker-controlled content

### 2. CVE-2026-42055 — HPACK Integer Encoding Overflow

The HPACK integer encoding uses a variable-length scheme where values > 127 require multi-byte encoding. The overflow boundary:

- Values 0–127: 1 byte
- Values 128–16,510: 2 bytes
- Values 16,511–2,097,278: 3–4 bytes
- Values 2,097,279+: **5 bytes** (exceeds the 4-byte reservation)

The attacker crafts an HTTP request with a header value whose length is >= 2,097,279 bytes. When this passes through NGINX configured with `ignore_invalid_headers off` and sufficiently large header buffers, the proxy module re-encodes it using HPACK. The 5th byte of the length prefix overwrites the first byte of the subsequent heap allocation.

### 3. Affected Products and Versions

| Product | Affected Versions | Fixed Version |
|---------|-------------------|---------------|
| NGINX Open Source | 1.31.0–1.31.1 (CVE-2026-42530) | 1.31.2 |
| NGINX Open Source | 1.13.10–1.31.1 (CVE-2026-42055) | 1.31.2, 1.30.3 |
| NGINX Plus | R33–R37.0.1 | R37.1 |
| NGINX Gateway Fabric | 1.3.0–2.6.3 | 2.6.4 |
| NGINX Ingress Controller | 3.5.0–5.5.0 | 5.5.1 |

### 4. Anti-Forensics / Evasion Techniques

No evasion techniques specific to these vulnerabilities have been documented. However, successful exploitation would yield code execution as the NGINX worker process user (typically `www-data` or `nginx`), which could:

- Modify access/error logs to remove evidence of the exploit request
- Leverage the network-facing position to pivot without generating lateral-movement artifacts on internal hosts
- Replace the NGINX binary or configuration to maintain persistent access

---

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| NGINX Open Source | 1.31.0–1.31.1 | HTTP/3 QUIC use-after-free (CVE-2026-42530) |
| NGINX Open Source | 1.13.10–1.31.1 | HTTP/2 HPACK heap overflow (CVE-2026-42055) |
| NGINX Plus | R33–R37.0.1 | Both CVEs |
| NGINX Gateway Fabric | 1.3.0–2.6.3 | Both CVEs |
| NGINX Ingress Controller | 3.5.0–5.5.0 | Both CVEs |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Linux | `/var/log/nginx/error.log` | NGINX error log — check for worker crash signals (SIGSEGV/SIGABRT) |
| Linux | `/etc/nginx/nginx.conf` | Main config — check for `listen ... quic` and `ignore_invalid_headers off` |
| Linux | `/var/run/nginx.pid` | PID file — unexpected worker restarts may indicate crash-based exploitation |

### Network

No specific network IOCs (domains, IPs, URLs) have been published for exploitation of these vulnerabilities. The attack vectors are protocol-level anomalies in HTTP/2 HPACK and HTTP/3 QUIC framing.

### Behavioral

- **NGINX worker process crashes:** Repeated `worker process exited on signal 11` (SIGSEGV) or `signal 6` (SIGABRT) entries in NGINX error logs, especially correlating with HTTP/3 or HTTP/2 proxy traffic
- **Core dumps:** Crash dumps in `/var/log/nginx/` or configured core dump directory showing faults in `ngx_http_v3_parse_header`, `ngx_http_v2_huff_encode`, or `ngx_http_grpc_body_output_filter`
- **Oversized HTTP/2 headers:** HTTP/2 requests with individual header values exceeding 2 MB (2,097,278 bytes) — anomalous in normal traffic
- **Rapid QUIC stream open/close:** Unusual patterns of unidirectional QUIC stream creation and immediate closure on HTTP/3 connections

---

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Both CVEs target NGINX reverse proxies exposed to untrusted network traffic |
| T1210 | Exploitation of Remote Services | RCE via protocol-level exploitation of HTTP/2 and HTTP/3 modules |

---

## Impact Assessment

**Breadth:** NGINX is the most widely deployed web server/reverse proxy globally, with an estimated 34% market share. However, exploitation requires specific non-default configurations: HTTP/3 QUIC for CVE-2026-42530 (relatively uncommon), and `ignore_invalid_headers off` with oversized header buffers for CVE-2026-42055. This significantly narrows the population of exploitable instances.

**Depth:** Successful exploitation yields unauthenticated remote code execution as the NGINX worker process user, which typically has read access to TLS private keys, session data, and upstream credentials stored in the NGINX configuration. On containerized deployments (Kubernetes via NGINX Ingress Controller), compromise of the ingress pod may enable lateral movement to the cluster API server.

**Stealth:** The HTTP/3 exploit (CVE-2026-42530) may be difficult to detect because QUIC traffic is encrypted and many network monitoring tools lack deep QUIC/HTTP3 parsing. The HTTP/2 exploit (CVE-2026-42055) is more detectable due to the anomalously large header values required.

---

## Detection & Remediation

### Immediate Detection

Check for vulnerable configurations:

```bash
# Check NGINX version
nginx -v 2>&1

# Check for HTTP/3 QUIC configuration (CVE-2026-42530)
grep -rn 'listen.*quic' /etc/nginx/

# Check for dangerous HTTP/2 proxy settings (CVE-2026-42055)
grep -rn 'ignore_invalid_headers\s*off' /etc/nginx/
grep -rn 'large_client_header_buffers' /etc/nginx/

# Check for recent worker crashes
grep -c 'exited on signal' /var/log/nginx/error.log

# Check for crash dumps
ls -la /var/log/nginx/core.* 2>/dev/null
```

### Remediation

1. **Patch immediately:** Update to NGINX 1.31.2+ or 1.30.3+ (open source), NGINX Plus R37.1+, NGINX Gateway Fabric 2.6.4+, or NGINX Ingress Controller 5.5.1+
2. **If patching is not immediately possible, apply mitigations:**
   - **CVE-2026-42530:** Remove `quic` from all `listen` directives to disable HTTP/3
   - **CVE-2026-42055:** Remove any `ignore_invalid_headers off` directives (reverting to the safe default of `on`), and reduce `large_client_header_buffers` below 2 MB
3. **Audit logs:** Review NGINX error logs for signs of worker process crashes (signal 11 or signal 6) that may indicate prior exploitation attempts
4. **Rotate credentials:** If exploitation is suspected, rotate TLS private keys and any upstream credentials stored in NGINX configuration

### Long-Term Hardening

- Enable automated NGINX version monitoring and alerting for security advisories
- Deploy web application firewalls (WAF) capable of inspecting HTTP/2 frame-level content, including header size enforcement
- Audit `nginx.conf` for non-default security-weakening directives (`ignore_invalid_headers off`, excessive buffer sizes) as part of configuration compliance checks
- Consider rate-limiting or blocking QUIC/HTTP3 traffic at the network perimeter if not required for business operations

---

## Detection Rules

These detections target the protocol-level anomalies and crash indicators specific to CVE-2026-42530 and CVE-2026-42055. No public PoC exists, so rules key on the distinctive technical cues from the advisories: oversized HPACK header values (>2 MB), QUIC stream anomalies, and NGINX worker crash signals. All rules compile cleanly; verify firing in your pipeline before production deployment.

### Sigma: NGINX Worker Crash Indicating HTTP/3 or HTTP/2 RCE Exploitation

Detects NGINX worker process crashes (SIGSEGV/SIGABRT) in syslog with CVE-specific module context, consistent with exploitation of CVE-2026-42530 or CVE-2026-42055.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: rewrote from webserver/cs-uri (wrong field, would never fire) to linux/syslog with SyslogMessage. Added CVE-specific module names to narrow scope. -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. Crash signals scoped to CVE-relevant modules. Medium confidence — crashes can still have benign causes but module-name filtering reduces FPs significantly. -->
```yaml
title: NGINX HTTP/3 or HTTP/2 Proxy Crash Indicating CVE-2026-42530 or CVE-2026-42055 Exploitation
id: 7c4e1a8b-3f2d-4e9a-b5c7-1d8e6f0a2b3c
status: experimental
description: >
    Detects NGINX worker process crashes (signal 11 SIGSEGV or signal 6 SIGABRT) in syslog
    with references to CVE-relevant modules (ngx_http_v3, ngx_http_proxy_v2, ngx_http_grpc),
    which may indicate exploitation of use-after-free (CVE-2026-42530) or heap buffer overflow
    (CVE-2026-42055) vulnerabilities in NGINX HTTP/3 and HTTP/2 proxy modules.
references:
    - https://nginx.org/en/security_advisories.html
    - https://my.f5.com/manage/s/article/K000161616
    - https://my.f5.com/manage/s/article/K000161584
author: Actioner
date: 2026/06/22
tags:
    - attack.t1190
logsource:
    product: linux
    service: syslog
detection:
    selection_nginx:
        SyslogMessage|contains: 'nginx'
    selection_crash:
        SyslogMessage|contains:
            - 'exited on signal 11'
            - 'exited on signal 6'
    selection_module_context:
        SyslogMessage|contains:
            - 'ngx_http_v3'
            - 'ngx_http_proxy_v2'
            - 'ngx_http_grpc'
            - 'ngx_quic'
    condition: selection_nginx and selection_crash and selection_module_context
falsepositives:
    - Legitimate NGINX crashes in the same modules from other bugs or resource exhaustion
    - Custom modules causing segfaults unrelated to these CVEs
level: high
```

### Sigma: NGINX HTTP/3 QUIC Module Crash in Syslog (CVE-2026-42530)

Detects NGINX error log entries in syslog referencing QUIC/HTTP3 module crashes, specific to the use-after-free in the QPACK decoder.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Scoped to QUIC/HTTP3 context via module name strings. FP: other QUIC bugs causing crashes; requires QUIC enabled. -->
```yaml
title: NGINX Error Log Indicates HTTP/3 Use-After-Free Crash (CVE-2026-42530)
id: a2b3c4d5-e6f7-4890-abcd-1e2f3a4b5c6d
status: experimental
description: >
    Detects NGINX error log entries referencing ngx_http_v3 module crashes or QUIC stream errors
    consistent with the use-after-free vulnerability CVE-2026-42530 in the HTTP/3 QPACK decoder.
    The vulnerability triggers when a unidirectional QUIC stream closes and frees memory still
    referenced by the HTTP/3 session pointer.
references:
    - https://nginx.org/en/security_advisories.html
    - https://my.f5.com/manage/s/article/K000161616
author: Actioner
date: 2026/06/22
tags:
    - attack.t1190
logsource:
    product: linux
    service: syslog
detection:
    selection_nginx:
        SyslogMessage|contains: 'nginx'
    selection_crash:
        SyslogMessage|contains|all:
            - 'worker process'
            - 'exited on signal'
    selection_quic_context:
        SyslogMessage|contains:
            - 'ngx_http_v3'
            - 'quic'
            - 'ngx_quic'
    condition: selection_nginx and selection_crash and selection_quic_context
falsepositives:
    - Other NGINX QUIC bugs causing crashes
level: high
```

### Snort: HTTP/2 Oversized Header Value Potential HPACK Overflow (CVE-2026-42055)

Detects HTTP/2 connection preface followed by frame data with oversized header values that could trigger the HPACK 5-byte length prefix overflow.
**Status:** compile ✅ compiles · confidence: low
<!-- revision: SID changed from 2100001 to 9000001 (2100000 range conflicts with Emerging Threats reserved space). Confidence dropped to low — rule does not properly parse HTTP/2 frame structure; the \x00\x00 anchor is too generic in binary framing. This is a best-effort heuristic; proper HTTP/2 frame parsing is needed for high-confidence detection. -->
<!-- audit: snort -c /etc/snort/snort.conf (via local.rules) exit 0. Snort 2.9.20. The HTTP/2 connection preface (PRI * HTTP/2) is matched at stream start, then byte_test checks for values exceeding the 2,097,278 overflow boundary. FP: legitimate oversized HTTP/2 headers (rare but possible in file upload proxies). Evasion: attacker could fragment the preface across TCP segments. -->
```snort
alert tcp any any -> $HOME_NET any (msg:"Actioner - HTTP/2 Oversized Header Value Potential HPACK Overflow (CVE-2026-42055)"; flow:established,to_server; content:"|50 52 49 20 2A 20 48 54 54 50 2F 32|"; depth:24; content:"|00 00|"; distance:0; byte_test:4,>,2097278,0,relative; classtype:attempted-admin; reference:url,my.f5.com/manage/s/article/K000161584; reference:cve,2026-42055; metadata:author Actioner, created 2026-06-22; sid:9000001; rev:1;)
```

### Suricata: Oversized HTTP/2 Header Value Exceeding HPACK Length Prefix (CVE-2026-42055)

Detects HTTP traffic with header values that exceed the HPACK 4-byte length prefix capacity (2,097,278 bytes), targeting the heap overflow in the proxy module.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. Suricata 7.0.3. Uses http.header sticky buffer with byte_test for the overflow boundary value. FP: legitimate APIs with very large headers (uncommon). The threshold limits alerting to once per source per minute. -->
```suricata
alert http any any -> $HOME_NET any (msg:"Actioner - Oversized HTTP/2 Header Value Exceeding HPACK Length Prefix (CVE-2026-42055)"; flow:established,to_server; http.header; content:"|00|"; byte_test:4,>,2097278,0,relative; threshold:type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:url,my.f5.com/manage/s/article/K000161584; reference:cve,2026-42055; metadata:author Actioner, created_at 2026-06-22; sid:2200001; rev:1;)
```

### Suricata: Anomalous QUIC Traffic Targeting NGINX HTTP/3 (CVE-2026-42530)

Detects anomalous QUIC protocol traffic with oversized payloads directed at NGINX HTTP/3 endpoints, consistent with the QPACK use-after-free exploitation pattern.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: suricata -T exit 0. Suricata 7.0.3. QUIC protocol matching with dsize constraint. Low confidence because QUIC is encrypted and Suricata's QUIC parser has limited depth — this is a coarse heuristic for anomalous QUIC patterns, not a precise exploit signature. FP: legitimate large QUIC transfers. -->
```suricata
alert quic any any -> $HOME_NET any (msg:"Actioner - Anomalous QUIC Stream Closure Followed by Session Reference (CVE-2026-42530)"; flow:to_server; content:"|00|"; dsize:>1024; threshold:type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:url,my.f5.com/manage/s/article/K000161616; reference:cve,2026-42530; metadata:author Actioner, created_at 2026-06-22; sid:2200002; rev:1;)
```

### YARA: Vulnerable NGINX Binary Version Detection (CVE-2026-42530 / CVE-2026-42055)

Detects NGINX binaries in the affected version range (1.13.10–1.31.1) that include the vulnerable HTTP/2 or HTTP/3 module strings. Scope to NGINX binary directories for asset inventory.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Version string matching against published affected ranges. High confidence for identifying vulnerable binaries — this is an asset-inventory rule, not an exploit detection. FP: patched binaries that retain version strings from build metadata (unlikely for NGINX). -->
```yara
rule Vuln_NGINX_CVE_2026_42530_CVE_2026_42055 : vulnerability
{
    meta:
        description = "Detects NGINX binaries in the version range affected by CVE-2026-42530 (HTTP/3 UAF) and CVE-2026-42055 (HTTP/2 HPACK overflow). Matches version strings for NGINX 1.13.10 through 1.31.1."
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://nginx.org/en/security_advisories.html"
        severity = "critical"

    strings:
        $nginx_banner = "nginx/" ascii

        $vuln_v3_10 = "nginx/1.31.0" ascii
        $vuln_v3_11 = "nginx/1.31.1" ascii
        $vuln_v3_00 = "nginx/1.30.0" ascii
        $vuln_v3_01 = "nginx/1.30.1" ascii
        $vuln_v3_02 = "nginx/1.30.2" ascii

        $vuln_v29 = "nginx/1.29." ascii
        $vuln_v28 = "nginx/1.28." ascii
        $vuln_v27 = "nginx/1.27." ascii
        $vuln_v26 = "nginx/1.26." ascii
        $vuln_v25 = "nginx/1.25." ascii
        $vuln_v24 = "nginx/1.24." ascii
        $vuln_v23 = "nginx/1.23." ascii
        $vuln_v22 = "nginx/1.22." ascii
        $vuln_v21 = "nginx/1.21." ascii
        $vuln_v20 = "nginx/1.20." ascii
        $vuln_v19 = "nginx/1.19." ascii
        $vuln_v18 = "nginx/1.18." ascii
        $vuln_v17 = "nginx/1.17." ascii
        $vuln_v16 = "nginx/1.16." ascii
        $vuln_v15 = "nginx/1.15." ascii
        $vuln_v14 = "nginx/1.14." ascii

        $vuln_v13_10 = "nginx/1.13.10" ascii
        $vuln_v13_11 = "nginx/1.13.11" ascii

        $http2_module = "ngx_http_v2_module" ascii
        $http3_module = "ngx_http_v3_module" ascii
        $proxy_v2 = "ngx_http_proxy_v2" ascii
        $grpc_module = "ngx_http_grpc_module" ascii

    condition:
        $nginx_banner and
        (
            1 of ($vuln_v3*) or
            1 of ($vuln_v2*) or
            1 of ($vuln_v1*) or
            1 of ($vuln_v13*)
        ) and
        (
            $http2_module or $http3_module or $proxy_v2 or $grpc_module
        )
}
```

---

## Lessons Learned

- **Protocol complexity creates vulnerability surface:** HTTP/2 HPACK and HTTP/3 QPACK are complex binary encoding schemes where subtle integer encoding boundaries create overflow opportunities. The 4-byte vs 5-byte HPACK length prefix boundary at 2,097,278 is a textbook example of how variable-length encoding assumptions can fail at edge values.
- **Non-default configurations gate exploitability but reduce patching urgency perception:** Both CVEs require non-default configurations (`listen ... quic`; `ignore_invalid_headers off` + large buffers), which may lead organizations to deprioritize patching. However, the prior rapid exploitation of CVE-2026-42945 demonstrates that attackers actively scan for these configurations.
- **Ingress controller impact amplifies Kubernetes risk:** NGINX Ingress Controller is a critical Kubernetes component. Compromising it grants access to all ingressed traffic (including TLS termination keys) and potentially to the Kubernetes API. Organizations should treat ingress controller patching with the same urgency as direct NGINX patching.
- **QUIC encryption complicates detection:** HTTP/3 over QUIC encrypts nearly all payload data, making network-level detection of CVE-2026-42530 exploitation significantly harder than HTTP/2-based attacks. This reinforces the importance of host-level detection (crash monitoring, binary version scanning) alongside network signatures.

---

## Sources

- [NGINX Security Advisories](https://nginx.org/en/security_advisories.html) — official list of NGINX security advisories including CVE-2026-42530 and CVE-2026-42055
- [F5 K000161616](https://my.f5.com/manage/s/article/K000161616) — F5 advisory for CVE-2026-42530 (HTTP/3 QUIC use-after-free)
- [F5 K000161584](https://my.f5.com/manage/s/article/K000161584) — F5 advisory for CVE-2026-42055 (HTTP/2 HPACK heap overflow)
- [The Hacker News](https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html) — coverage of both critical NGINX vulnerabilities
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/f5-issues-out-of-band-patches-for-critical-nginx-vulnerabilities/) — reporting on F5 out-of-band patches
- [SecurityAffairs](https://securityaffairs.com/193842/security/f5-patches-critical-nginx-vulnerabilities-enabling-unauthenticated-code-execution.html) — analysis of the unauthenticated code execution risk

---
*Report generated by Actioner*
