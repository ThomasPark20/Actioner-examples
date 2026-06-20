# Technical Analysis Report: F5 NGINX Critical RCE Vulnerabilities CVE-2026-42530 & CVE-2026-42055 (2026-06-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-20
Version: 1.0 (DRAFT)

## Executive Summary

F5 released out-of-band security patches on June 17, 2026 for two critical vulnerabilities in NGINX Open Source and NGINX Plus that can enable remote code execution under specific conditions. CVE-2026-42530 (CVSS v4 9.2) is a use-after-free in the HTTP/3 QUIC module (`ngx_http_v3_module`) triggered by reopening a QPACK encoder stream via a crafted HTTP/3 session. CVE-2026-42055 (CVSS v4 9.2) is a heap-based buffer overflow in the HTTP/2 proxy and gRPC modules (`ngx_http_proxy_v2_module`, `ngx_http_grpc_module`) exploitable when non-default configuration options are present.

Both vulnerabilities require ASLR to be disabled or bypassed for reliable code execution; without that, exploitation causes denial of service through worker process crashes. Neither vulnerability has a public proof-of-concept, and no in-the-wild exploitation has been reported. The attack surface is limited: CVE-2026-42530 requires HTTP/3 QUIC to be explicitly enabled, and CVE-2026-42055 requires three non-default configuration directives (`proxy_http_version 2` or `grpc_pass`, `ignore_invalid_headers off`, and `large_client_header_buffers` exceeding 2 MB).

Two additional high-severity authenticated configuration injection flaws (CVE-2026-11311 and CVE-2026-50107) in NGINX Gateway Fabric were disclosed alongside these critical CVEs.

## Background: NGINX and the Affected Modules

NGINX is the world's most widely deployed reverse proxy and web server, powering an estimated one-third of internet-facing web infrastructure. F5 Networks acquired NGINX Inc. in 2019 and maintains both the open-source and commercial NGINX Plus products.

**ngx_http_v3_module** provides HTTP/3 support via the QUIC transport protocol. HTTP/3 uses QPACK for header compression (the successor to HPACK used in HTTP/2). QPACK operates over dedicated unidirectional QUIC streams -- an encoder stream and a decoder stream -- to synchronize the dynamic header table between client and server. The vulnerability lies in the handling of encoder stream lifecycle events.

**ngx_http_proxy_v2_module** and **ngx_http_grpc_module** handle upstream HTTP/2 proxying and gRPC pass-through respectively. When NGINX acts as a reverse proxy to HTTP/2 backends, these modules parse upstream HTTP/2 frames, including HEADERS frames containing HPACK-compressed headers. The `ignore_invalid_headers` directive (default: `on`) controls whether NGINX rejects headers with invalid characters; setting it to `off` allows malformed headers to pass through the parsing pipeline, expanding the buffer overflow attack surface.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-17 | F5 releases out-of-band security advisory and patches for NGINX Open Source 1.31.2 and 1.30.3, NGINX Plus R36 P6 and 37.0.2.1, and NGINX Gateway Fabric 2.6.4 |
| 2026-06-17 | F5 security advisories K000161616 (CVE-2026-42530) and K000161584 (CVE-2026-42055) published |
| 2026-06-18 | Public reporting by The Hacker News, SecurityWeek, BleepingComputer, and Security Affairs |
| 2026-06-20 | No public PoC or in-the-wild exploitation reported as of this date |

## Root Cause: CVE-2026-42530 -- Use-After-Free in QPACK Encoder Stream Handling

**CWE-416 (Use After Free)**

When an HTTP/3 client sends a specially crafted QUIC session that reopens (re-initiates) a QPACK encoder stream, the NGINX worker process continues to reference memory associated with the original stream after it has been freed. The reopened stream triggers the use-after-free condition, corrupting heap metadata.

**Prerequisites:**
- NGINX configured with HTTP/3 QUIC support (`listen ... quic;` and/or `http3 on;`)
- Remote, unauthenticated access to the QUIC endpoint (UDP port, typically 443)
- For RCE: ASLR disabled or bypassed (without this, the result is a worker process crash/restart -- DoS only)

**Affected versions:** NGINX Open Source 1.31.0 and 1.31.1

## Root Cause: CVE-2026-42055 -- Heap Buffer Overflow in HTTP/2 Proxy Header Parsing

**CWE-122 (Heap-Based Buffer Overflow)**

When NGINX proxies traffic to an HTTP/2 upstream backend using `proxy_http_version 2` or `grpc_pass`, and the configuration includes `ignore_invalid_headers off` with `large_client_header_buffers` set to a size exceeding 2 MB, an attacker can send crafted HTTP headers that overflow a heap buffer in the proxy or gRPC module's header parsing logic.

**Prerequisites (ALL must be present):**
1. A `location` block using `proxy_http_version 2` or `grpc_pass`
2. `ignore_invalid_headers` set to `off` (default is `on`)
3. `large_client_header_buffers` configured with a buffer size exceeding 2 MB (default is 8 KB)
4. For RCE: ASLR disabled or bypassed

**Affected versions:** NGINX Open Source 1.13.10 through 1.31.1 (very broad range -- the HTTP/2 proxy module was introduced in 1.13.10); NGINX Plus R33 through R36, 37.0.0 through 37.0.1

## Technical Analysis of the Vulnerability Mechanisms

### 1. CVE-2026-42530: QPACK Encoder Stream Reopening

In the QUIC/HTTP/3 protocol, QPACK uses unidirectional streams for encoder and decoder communication. RFC 9204 (QPACK) specifies that each endpoint opens exactly one encoder stream and one decoder stream. If a client opens a second encoder stream (i.e., "reopens" it), this violates the protocol specification. NGINX's `ngx_http_v3_module` did not properly handle this edge case -- instead of rejecting the duplicate stream, it freed the resources associated with the original encoder stream context while retaining dangling pointers. Subsequent processing of QPACK instructions on either stream dereferences the freed memory.

The attack is delivered entirely over QUIC (UDP), which is encrypted by design using TLS 1.3. This means:
- Network-level IDS/IPS cannot inspect the QUIC payload to detect the malicious QPACK framing
- The exploit is contained within the encrypted QUIC connection
- Only the NGINX process itself can observe the malformed protocol behavior

### 2. CVE-2026-42055: Oversized Header Buffer Overflow

When `ignore_invalid_headers` is `off`, NGINX's header parser does not reject headers containing characters that would normally be considered invalid (e.g., whitespace in header names, control characters). Combined with `large_client_header_buffers` exceeding 2 MB, this creates an unusually large header buffer that the attacker can overflow with specially crafted HTTP/2 HEADERS frames. The overflow corrupts adjacent heap metadata, enabling controlled memory corruption.

This vulnerability requires the attacker to either:
- Control an upstream HTTP/2 server that NGINX proxies to, or
- Be able to inject crafted headers into HTTP/2 traffic destined for an upstream

### 3. Post-Exploitation Considerations

Both vulnerabilities target the NGINX **worker process**, not the master process. Worker process crashes cause the master process to spawn a new worker, producing:
- Error log entries such as `worker process XXXX exited on signal 11` (SIGSEGV)
- Potential brief service interruption during worker restart
- If RCE is achieved, the attacker operates with the privileges of the NGINX worker user (typically `nginx` or `www-data`)

There are no C2 infrastructure indicators, no file-level IOCs, and no known post-exploitation tooling specific to these vulnerabilities.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation where applicable.

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| NGINX Open Source | 1.31.0 -- 1.31.1 | Affected by CVE-2026-42530 (HTTP/3 UaF) |
| NGINX Open Source | 1.13.10 -- 1.31.1 | Affected by CVE-2026-42055 (HTTP/2 buffer overflow) |
| NGINX Open Source | 1.30.0 -- 1.30.2 | Affected by CVE-2026-42055 |
| NGINX Plus | R33 -- R36, 37.0.0 -- 37.0.1 | Affected by CVE-2026-42055 |
| NGINX Gateway Fabric | 1.3.0 -- 1.6.2, 2.0.0 -- 2.6.3 | Affected by both CVEs |
| NGINX Ingress Controller | 3.5.0 -- 3.7.2, 4.0.0 -- 4.0.1, 5.0.0 -- 5.5.0 | Affected by both CVEs |
| NGINX Instance Manager | 2.17.0 -- 2.22.0 | Affected by both CVEs |
| F5 WAF for NGINX | 5.9.0 -- 5.13.1 | Affected by CVE-2026-42055 |
| NGINX App Protect WAF | 4.10.0 -- 4.16.0, 5.2.0 -- 5.8.0 | Affected by CVE-2026-42055 |

### Network

No network-level IOCs are available. CVE-2026-42530 exploits occur within encrypted QUIC sessions and are not observable at the network layer without TLS termination. CVE-2026-42055 exploits occur in upstream HTTP/2 connections, typically also encrypted.

### Behavioral

- **NGINX worker process crash/restart** (`worker process XXXX exited on signal 11`) -- this is a generic indicator of memory corruption but is not specific to these CVEs; many bugs and conditions can cause SIGSEGV
- **Repeated worker restarts in rapid succession** may indicate active exploitation attempts causing DoS

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Remote unauthenticated exploitation of NGINX HTTP/3 or HTTP/2 proxy endpoints |
| T1499.004 | Endpoint Denial of Service: Application or System Exploitation | Worker process crash/restart via memory corruption |

## Impact Assessment

**Breadth:** NGINX Open Source is one of the most deployed web servers globally. However, exposure is significantly constrained:
- CVE-2026-42530 only affects the two most recent versions (1.31.0-1.31.1) with HTTP/3 QUIC explicitly enabled -- a feature not yet in widespread production use
- CVE-2026-42055 requires three non-default configuration directives simultaneously, substantially reducing the exposed population

**Depth:** If ASLR is disabled or bypassed, full remote code execution is possible with the privileges of the NGINX worker process. On most modern Linux distributions, ASLR is enabled by default, limiting practical impact to denial of service.

**Stealth:** Exploitation produces visible artifacts (worker process crashes) that are logged by default. However, a skilled attacker who achieves RCE could suppress subsequent crash logging.

**Active exploitation:** No in-the-wild exploitation reported as of 2026-06-20. However, F5 NGINX products have been targeted rapidly after prior CVE disclosures (e.g., CVE-2026-42945, the "NGINX Rift" rewrite module flaw, saw exploitation within days of disclosure in May 2026).

## Detection & Remediation

### Immediate Detection

**Configuration audit (exposure assessment):**

```bash
# Check NGINX version
nginx -v 2>&1

# Check for HTTP/3 QUIC configuration (CVE-2026-42530 exposure)
grep -rn 'quic\|http3' /etc/nginx/ /usr/local/nginx/conf/ 2>/dev/null

# Check for CVE-2026-42055 exposure (all three must be present)
grep -rn 'proxy_http_version\s*2\|grpc_pass' /etc/nginx/ /usr/local/nginx/conf/ 2>/dev/null
grep -rn 'ignore_invalid_headers\s*off' /etc/nginx/ /usr/local/nginx/conf/ 2>/dev/null
grep -rn 'large_client_header_buffers' /etc/nginx/ /usr/local/nginx/conf/ 2>/dev/null
```

**Worker crash monitoring (post-exploitation indicator):**

```bash
# Check NGINX error logs for recent worker crashes
grep -i 'exited on signal 11\|exited on signal 6\|abort\|segfault' /var/log/nginx/error.log
```

### Remediation

1. **Patch immediately** -- update to NGINX Open Source 1.31.2 (or 1.30.3 for the stable branch), NGINX Plus R36 P6 or 37.0.2.1, NGINX Gateway Fabric 2.6.4
2. **If patching is not immediately possible:**
   - **CVE-2026-42530:** Disable HTTP/3 by removing `quic` from all `listen` directives and removing `http3 on;`
   - **CVE-2026-42055:** Ensure `ignore_invalid_headers` is set to `on` (default) or remove the `off` override; reduce `large_client_header_buffers` below 2 MB
3. **Verify ASLR is enabled** on all NGINX hosts: `cat /proc/sys/kernel/randomize_va_space` should return `2`

### Long-Term Hardening

- Keep NGINX on the latest stable or mainline release with a defined patch cadence
- Avoid disabling security-relevant defaults (`ignore_invalid_headers off` should be treated as a high-risk configuration change)
- Enable HTTP/3 only when required and with awareness of the expanded protocol attack surface
- Monitor NGINX error logs for worker process crashes as a canary for memory corruption exploits
- Ensure ASLR is enforced system-wide and not disabled for debugging in production

## Detection Rules

No production-ready detection rules are generated for these vulnerabilities. The viability assessment follows:

**CVE-2026-42530 (HTTP/3 QPACK Use-After-Free):** The exploit occurs entirely within an encrypted QUIC session. QUIC traffic is encrypted using TLS 1.3 from the initial handshake onward, making the malicious QPACK encoder stream reopening invisible to network-level inspection (Snort/Suricata). No specific file hashes, domains, IPs, or process-level artifacts have been disclosed. No public PoC exists that would provide distinctive byte patterns for YARA rules. The only observable indicator -- worker process crashes -- is a generic symptom of any memory corruption bug in NGINX and would produce unacceptable false positive rates as a production detection rule.

**CVE-2026-42055 (HTTP/2 Heap Buffer Overflow):** The exploit targets upstream HTTP/2 proxy connections, which are also typically TLS-encrypted. The trigger requires non-default configuration, and the malicious payload consists of oversized HTTP/2 HEADERS frames without any distinctive content signature. No PoC, specific byte sequences, or IOCs have been published.

**Conclusion:** Both CVEs are memory corruption vulnerabilities in encrypted protocol handlers with no public PoCs, no file-level IOCs, no network signatures extractable from encrypted traffic, and no distinctive behavioral artifacts beyond generic worker crashes. Writing detection rules would require either inventing broad, high-false-positive signatures or detecting encrypted protocol anomalies that IDS engines cannot inspect. The correct defensive action is to **patch or apply configuration mitigations** as described above.

## Lessons Learned

1. **Encrypted protocol modules expand the unmonitorable attack surface.** HTTP/3 QUIC and HTTP/2 with TLS create protocol processing that occurs entirely within encrypted channels, making traditional IDS/IPS detection impossible without TLS termination. Organizations adopting HTTP/3 should treat the QUIC stack as a high-risk component requiring rapid patching.

2. **Non-default configurations create hidden exposure.** CVE-2026-42055 is exploitable only when three non-default directives are combined. Configuration drift auditing tools should flag `ignore_invalid_headers off` and oversized `large_client_header_buffers` as security-relevant deviations.

3. **ASLR remains a critical last-resort defense.** Both vulnerabilities are constrained from RCE to DoS by ASLR. Organizations should verify ASLR is enforced across all production infrastructure and never disabled for convenience.

4. **F5/NGINX products are high-value targets.** The reference to CVE-2026-42945 ("NGINX Rift") being exploited within days of disclosure in May 2026 underscores that threat actors actively monitor NGINX CVE disclosures. Patching speed is the primary defense.

## Sources

- [The Hacker News -- F5 Patches Two Critical NGINX Open Source Flaws Enabling Remote Code Execution](https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html) -- primary source with CVE details, affected versions, and vulnerability descriptions
- [Security Affairs -- F5 Patches Critical NGINX Vulnerabilities Enabling Unauthenticated Code Execution](https://securityaffairs.com/193842/security/f5-patches-critical-nginx-vulnerabilities-enabling-unauthenticated-code-execution.html) -- additional source with CWE classifications and configuration requirements
- [SecurityOnline -- F5 Patches Two Critical NGINX Flaws in HTTP/3 and HTTP/2 Modules](https://securityonline.info/nginx-vulnerabilities/) -- technical details on QPACK encoder stream reopening and buffer overflow trigger conditions
- [NGINX Security Advisories](https://nginx.org/en/security_advisories.html) -- official NGINX security advisory page listing CVE-2026-42530 and CVE-2026-42055
- [F5 Security Advisory K000161616](https://my.f5.com/manage/s/article/K000161616) -- official F5 advisory for CVE-2026-42530
- [F5 Security Advisory K000161584](https://my.f5.com/manage/s/article/K000161584) -- official F5 advisory for CVE-2026-42055
- [SecurityWeek -- F5 Patches Critical, High-Severity NGINX Vulnerabilities](https://www.securityweek.com/f5-patches-critical-high-severity-nginx-vulnerabilities/) -- reporting on out-of-band patch release
- [BleepingComputer -- F5 Issues Out-of-Band Patches for Critical NGINX Vulnerabilities](https://www.bleepingcomputer.com/news/security/f5-issues-out-of-band-patches-for-critical-nginx-vulnerabilities/) -- additional reporting confirming no active exploitation
- [SOCPrime -- CVE-2026-42530: Critical NGINX HTTP/3 Flaw](https://socprime.com/blog/cve-2026-42530-critical-nginx-http-3-flaw-can-trigger-dos-and-possible-rce/) -- detection strategy analysis confirming no concrete detection artifacts available

---
*Report generated by Actioner*
