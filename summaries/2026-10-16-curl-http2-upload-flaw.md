# Technical Analysis Report: curl HTTP/2 Upload Use-After-Free CVE-2026-92392 (2026-10-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-16
Version: 1.0 (DRAFT)

## Executive Summary

CVE-2026-92392 is a high-severity use-after-free vulnerability in curl and libcurl's HTTP/2 upload handling, present in versions 8.12.0 through 8.22.0. A malicious server can trigger the flaw by sending an HTTP/2 `RST_STREAM` frame with reason `HTTP_1_1_REQUIRED` or `REFUSED_STREAM` during an active upload, causing curl to retain a dangling pointer to a freed `struct Curl_easy` object. The reporter demonstrated code execution under strict laboratory conditions, though the curl project assesses a crash as the most likely real-world outcome.

The vulnerability was reported on September 15, 2026, by Luna Tong of Anthropic using AI-assisted vulnerability research (OSS Scanner with Claude). It was fixed on October 14, 2026, in curl 8.23.0, with backports to 8.20.2, 8.16.2, and 8.14.3. The fix is a six-line reorder in `lib/multi.c` by Stefan Eissing that ensures connection filters release references to the easy handle before the handle is detached and the connection returned to the pool.

No in-the-wild exploitation has been reported. The PoC (HackerOne report #4030333) became public alongside the advisory on October 14.

## Background: curl and HTTP/2 Uploads

curl is the most widely deployed command-line HTTP client and transfer library. libcurl is embedded in thousands of applications, operating systems, containers, and IoT devices. Since version 7.33.0 (2013), curl supports HTTP/2 via the nghttp2 library, and since 7.47.0 (2016), libcurl negotiates HTTP/2 by default for HTTPS URLs when the server offers it via ALPN.

HTTP/2 multiplexes multiple logical streams over a single TCP connection. Each stream can be independently reset by either peer using `RST_STREAM` frames. The `HTTP_1_1_REQUIRED` (0x0d) and `REFUSED_STREAM` (0x07) error codes are standard mechanisms a server uses to request protocol downgrade or reject a stream, respectively. curl treats these resets as retryable errors and may attempt the transfer again on a new connection.

The vulnerable code path was introduced in commit `cd9107e0128191b7b5396b` shipped with curl 8.12.0 (February 2025).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-02 | Vulnerable code introduced in curl 8.12.0 |
| 2026-09-15 | Luna Tong (Anthropic) reports vulnerability via HackerOne |
| 2026-09-15 | curl security team confirms the flaw within hours |
| 2026-10-07 | Pre-announcement of upcoming security release |
| 2026-10-14 | curl 8.23.0 released with fix; advisory and HackerOne report published |
| 2026-10-14 | Debian DSA-6558-1 issued for Debian 13 (8.14.1-2+deb13u7) |

## Root Cause: Ordering Error in multi_done() Handle Cleanup

The vulnerability exists in the `multi_done()` function in `lib/multi.c`. When an HTTP/2 upload is interrupted by a server-sent `RST_STREAM` (with reason `HTTP_1_1_REQUIRED` or `REFUSED_STREAM`), curl enters a cleanup path where the order of operations is critical:

### Vulnerable Code Path (Before Fix)

1. `Curl_conn_ev_data_done(data, premature)` is called **outside** the `if(conn)` block, notifying connection filters that the transfer is done.
2. `multi_schedule_pending(data->multi)` is called **before** the connection is returned to the pool.
3. Inside `if(conn)`, the handle is detached and the connection returned to the pool.

This ordering allows the HTTP/2 connection filter (nghttp2) to retain a reference to the `data` handle after the handle has been freed. The stale pointer is later dereferenced when the connection processes pending data.

### Fixed Code Path (After Fix)

```c
if(conn) {
    struct multi_done_ctx mdctx;
    /* Inform connection filters that this transfer is done and they
     * need to give up any references to `data`. */
    Curl_conn_ev_data_done(data, premature);
    Curl_detach_connection(data);
    Curl_dnscache_prune(data, pnow);
    memset(&mdctx, 0, sizeof(mdctx));
    mdctx.premature = premature;
    Curl_cpool_return(data, conn, multi_done_locked, &mdctx, pnow);
    if(data->multi)
        multi_schedule_pending(data->multi);
}
```

The fix moves `Curl_conn_ev_data_done()` inside the `if(conn)` block so it executes **before** `Curl_detach_connection()`, and moves `multi_schedule_pending()` to **after** the connection is returned to the pool, guarded by `if(data->multi)`.

### Exploitation Chain

Per the advisory and Daniel Stenberg's blog post, the full exploitation chain operates as follows:

1. **Window stall:** The malicious server sets the HTTP/2 flow-control window to zero, pausing the client's upload mid-stream.
2. **Partial response + stream reset:** The server returns part of the HTTP response, then sends `RST_STREAM` with `HTTP_1_1_REQUIRED` or `REFUSED_STREAM`, while keeping the underlying TCP connection open.
3. **Retry trigger:** curl interprets the reset as a retryable error and prepares to retry the upload on a new connection.
4. **Dangling data on old connection:** During cleanup, leftover upload bytes on the still-open HTTP/2 connection are sent with no transfer registered. These bytes are parsed as a new request, and a new stream stores a pointer to the already-freed easy handle.
5. **Handle freed:** The retry completes on a new HTTP/1.1 connection, and the application calls `curl_easy_cleanup()`, freeing the easy handle.
6. **Use-after-free:** The old HTTP/2 connection later uses the dangling pointer to the freed easy handle.
7. **ASLR leak + RCE:** The reporter's exploit leaks heap addresses to defeat ASLR and overwrites a function pointer in the freed memory region, which curl subsequently calls.

### Exploitation Prerequisites

The advisory lists demanding conditions for achieving code execution:

- The server's TLS certificate must pass the client's validation (CA-signed or pinned)
- The client must upload approximately 135 KB over HTTP/2
- The attacker must know the exact curl version, target architecture, and build configuration
- The attacker must know the libc allocator behavior and heap layout
- Specific nghttp2 and OpenSSL TLS 1.3 behavior must be present
- Two parallel transfers with precise timing are required
- Calibrated libc offsets are needed for the RCE payload
- The command payload must fit in approximately 23 bytes

## Technical Analysis of the Attack

### 1. Attack Vector

This is a **server-to-client** attack. The malicious entity is the HTTP server, and the victim is any curl or libcurl client that uploads data over HTTP/2 to the attacker-controlled server. The client must initiate the connection and upload; the server cannot trigger the vulnerability against clients that only download.

### 2. Protocol-Level Trigger

The attack uses standard HTTP/2 frame types and error codes:

- **WINDOW_UPDATE** frame with increment 0 (or simply not sending updates) to stall the upload
- **HEADERS** frame with partial response headers
- **RST_STREAM** frame with error code `0x0d` (`HTTP_1_1_REQUIRED`) or `0x07` (`REFUSED_STREAM`)

These are all legitimate HTTP/2 mechanisms. The malicious aspect is their specific combination and timing during an active upload, not any malformed or non-standard frames.

### 3. Platform-Specific Behavior

#### Linux
Primary target. glibc's malloc allocator is exploitable with heap grooming in release builds. The PoC targets Linux with specific glibc versions and architecture (likely x86_64).

#### macOS / Windows
Affected if using curl/libcurl 8.12.0-8.22.0 built with HTTP/2 support. Different allocators (macOS libmalloc, Windows NT heap) change exploitation feasibility but not vulnerability.

#### Containers / Alpine
Alpine uses musl libc with a different allocator, affecting exploitation reliability. However, the use-after-free and resulting crash remain.

### 4. Anti-Forensics / Evasion

No special evasion techniques are required. The attack uses standard, encrypted HTTP/2 over TLS. The malicious server behavior (window stalling, RST_STREAM) is indistinguishable from legitimate server behavior without deep protocol analysis. TLS encryption prevents network-level inspection of HTTP/2 frame contents in most deployments.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation where applicable.

### Package / Software Level

| Package / Component | Vulnerable Versions | Fixed Versions | Description |
|---------------------|---------------------|----------------|-------------|
| curl (CLI) | 8.12.0 - 8.22.0 | 8.23.0 | HTTP/2 upload use-after-free |
| libcurl | 8.12.0 - 8.22.0 | 8.23.0 | HTTP/2 upload use-after-free |
| libcurl (8.20.x branch) | 8.20.0 - 8.20.1 | 8.20.2 | Backported fix |
| libcurl (8.16.x branch) | 8.16.0 - 8.16.1 | 8.16.2 | Backported fix |
| libcurl (8.14.x branch) | 8.14.0 - 8.14.2 | 8.14.3 | Backported fix |
| Debian 13 (trixie) | curl < 8.14.1-2+deb13u7 | 8.14.1-2+deb13u7 | DSA-6558-1 |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Linux | `/usr/bin/curl` | curl CLI binary |
| Linux | `/usr/lib/libcurl.so.*`, `/usr/lib/x86_64-linux-gnu/libcurl.so.*` | libcurl shared library |
| macOS | `/usr/bin/curl`, Homebrew paths | curl CLI binary |
| Container | Various (Alpine, Debian-based images) | curl/libcurl in container images |

### Network

No network-level IOCs (IPs, domains, URLs) are available. The attack requires the victim to connect to an attacker-controlled server, so the malicious server's identity is context-dependent. No C2 infrastructure or post-exploitation network indicators are known.

### Behavioral

- **curl/libcurl process crashes:** Segmentation faults (SIGSEGV) or abort signals (SIGABRT) in curl or applications linked against libcurl during or shortly after HTTP/2 uploads. The crash occurs in heap memory operations related to the freed `struct Curl_easy`.
- **HTTP/2 to HTTP/1.1 downgrade retry:** An upload that starts over HTTP/2, receives a stream reset, and is retried over HTTP/1.1 to the same server. This is the expected retry behavior that creates the race condition.
- **Core dumps:** Crash dumps showing use-after-free in `multi_done()` or related functions (`Curl_conn_ev_data_done`, `Curl_detach_connection`, `Curl_cpool_return`).

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1203 | Exploitation for Client Execution | Malicious server exploits curl client during HTTP/2 upload to achieve code execution via use-after-free |
| T1071.001 | Application Layer Protocol: Web Protocols | Attack operates over standard HTTPS/HTTP/2, using legitimate protocol mechanisms (RST_STREAM, WINDOW_UPDATE) |

## Impact Assessment

**Breadth:** Very wide. curl and libcurl are among the most deployed software components globally, present on virtually every Linux system, in most container images, and embedded in countless applications. However, exploitation requires the victim to upload data to an attacker-controlled server over HTTP/2, narrowing the practical attack surface to scenarios where curl clients upload to untrusted or compromised servers.

**Depth:** High. Successful exploitation yields code execution with the privileges of the curl process or the application embedding libcurl. In practice, crash (denial of service) is the far more likely outcome than code execution.

**Stealth:** High. The attack uses standard, encrypted HTTP/2 protocol mechanisms. The malicious server behavior is indistinguishable from legitimate server behavior at the network level without TLS decryption and deep HTTP/2 frame analysis.

**Exploitation probability:** Low for RCE, moderate for DoS. The extensive prerequisites for code execution (exact build knowledge, heap layout, timing of parallel transfers, 23-byte payload constraint) make weaponized exploitation unlikely outside targeted attacks. Crash-based denial of service is more achievable but still requires the victim to upload to the attacker's server.

## Detection & Remediation

### Immediate Detection

**Check curl version:**
```bash
curl --version | head -1
# Vulnerable: curl 8.12.0 through 8.22.0
# Fixed: 8.23.0 or later
```

**Check libcurl version for running processes:**
```bash
for pid in $(pgrep -f 'curl'); do
    echo "PID $pid: $(readlink /proc/$pid/exe)"
    ldd /proc/$pid/exe 2>/dev/null | grep -i curl
done
```

**Check container images:**
```bash
# Scan container images for vulnerable curl versions
docker run --rm <image> curl --version 2>/dev/null | head -1
```

**Check for crash indicators:**
```bash
# Check for recent curl-related crashes
journalctl --since "30 days ago" | grep -iE "(curl.*SIGSEGV|curl.*SIGABRT|curl.*segfault)"
dmesg | grep -i "curl.*segfault"
# Check for core dumps
find /var/crash /var/lib/systemd/coredump -name "*curl*" -newer /tmp -type f 2>/dev/null
```

### Remediation

1. **Patch immediately:** Upgrade curl/libcurl to the fixed version for your branch:
   - Any 8.12.0-8.22.0 -> **8.23.0**
   - 8.20.x -> **8.20.2** (backport)
   - 8.16.x -> **8.16.2** (backport)
   - 8.14.x -> **8.14.3** (backport)
   - Debian 13 -> **8.14.1-2+deb13u7** (DSA-6558-1)
2. **Restart all applications** linked against libcurl after upgrading
3. **Rebuild container images** that bundle curl/libcurl
4. **If patching is delayed:** Force HTTP/1.1 as a workaround:
   - CLI: `curl --http1.1 ...`
   - Library: `curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1)`
   - Note: existing HTTP/2 connections may still be reused despite this setting

### Long-Term Hardening

- **Minimize uploads to untrusted servers:** Review workflows where curl/libcurl uploads data to external or third-party servers, as these are the attack surface
- **Pin HTTP/1.1 where HTTP/2 is not needed:** Many upload workflows do not benefit from HTTP/2 multiplexing
- **Monitor for curl/libcurl crashes:** Instrument crash reporting for processes using libcurl, particularly those performing uploads
- **Track curl security advisories:** Subscribe to the curl-security mailing list or monitor [curl.se/docs/security.html](https://curl.se/docs/security.html)

## Viability Gate Assessment

**Can production-ready detection rules be generated for this vulnerability?**

**Partially. Host-level version inventory and crash detection are viable. Network-level exploit detection is not production-ready.**

Rationale:

1. **No distinctive network artifacts:** The attack uses standard HTTP/2 frame types (`RST_STREAM`, `WINDOW_UPDATE`) with legitimate error codes (`HTTP_1_1_REQUIRED`, `REFUSED_STREAM`). These are common in normal HTTP/2 traffic. Any Suricata/Snort rule matching these patterns would generate an unacceptable false-positive rate.

2. **TLS encryption blocks inspection:** HTTP/2 is negotiated via ALPN during TLS handshake and the frame-level traffic is encrypted. Network IDS cannot inspect HTTP/2 frame contents without TLS termination, which is not deployed in most environments for outbound client traffic.

3. **No malformed protocol elements:** Unlike many protocol exploits, this attack does not use malformed frames, invalid headers, or anomalous byte patterns. The exploit relies on timing and ordering of legitimate protocol operations.

4. **Host-level detection is viable but limited:**
   - Version inventory (Sigma) can identify vulnerable installations
   - Crash pattern detection (Sigma) can identify exploitation attempts that result in crashes (the most likely outcome)
   - Neither detects successful silent exploitation

**Conclusion:** Two Sigma rules are provided below for host-level detection. Network-level Suricata/Snort rules are assessed as **not production-ready** for this vulnerability due to the reasons above.

## Detection Rules

These detections target host-level indicators of CVE-2026-92392: vulnerable curl versions and crash patterns from libcurl processes during HTTP/2 uploads. Network-level rules (Suricata/Snort) are not included because the attack uses standard encrypted HTTP/2 frame sequences that cannot be distinguished from legitimate traffic without TLS decryption and would produce unacceptable false-positive rates.

### Sigma: Vulnerable curl Version Detected via Process Execution

Detects execution of curl binaries with version strings matching the vulnerable range (8.12.0 through 8.22.0). Useful for asset inventory and patch verification, not exploit detection. Note: this fires on `curl --version` output or process command-line metadata that includes version strings; it requires a log source that captures command-line arguments or process metadata.
**Status:** compile ✅ compiles (sigma convert -t splunk --without-pipeline) · confidence: low
<!-- audit: sigma convert exit 0 (pySigma 1.5.1, splunk backend). Rule targets process_creation with curl version strings in CommandLine. FP risk: moderate — version-check scripts, CI/CD pipelines, and configuration management tools routinely run curl --version. Use as inventory/hunt query, not alert. sigma check could not validate tags due to proxy blocking MITRE ATT&CK data fetch. -->
```yaml
title: Vulnerable curl Version Detected via Process Execution (CVE-2026-92392)
id: a1f7c3e9-8d42-4b6a-9e15-3c7d0f8a2b64
status: experimental
description: >
    Detects execution of curl binaries with version strings matching
    curl 8.12.0 through 8.22.0, which are vulnerable to CVE-2026-92392
    (HTTP/2 upload use-after-free). Use as an inventory and patch-verification
    hunt query. Does not detect exploitation.
references:
    - https://curl.se/docs/CVE-2026-92392.html
    - https://daniel.haxx.se/blog/2026/10/14/a-uaf-turned-rce/
    - https://thehackernews.com/2026/10/curl-patches-http2-upload-flaw-after.html
author: Actioner
date: 2026/10/16
tags:
    - attack.t1518.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_curl_binary:
        Image|endswith: '/curl'
    selection_vulnerable_version:
        CommandLine|contains:
            - 'curl 8.12.'
            - 'curl 8.13.'
            - 'curl 8.14.0'
            - 'curl 8.14.1'
            - 'curl 8.14.2'
            - 'curl 8.15.'
            - 'curl 8.16.0'
            - 'curl 8.16.1'
            - 'curl 8.17.'
            - 'curl 8.18.'
            - 'curl 8.19.'
            - 'curl 8.20.0'
            - 'curl 8.20.1'
            - 'curl 8.21.'
            - 'curl 8.22.'
    condition: selection_curl_binary and selection_vulnerable_version
falsepositives:
    - Legitimate version checking scripts during patching operations
    - Configuration management and inventory tools auditing curl versions
    - CI/CD pipelines that log curl version output
    - Backport builds may report a vulnerable version string despite containing the fix
level: low
```

### Sigma: curl or libcurl Process Crash During HTTP/2 Upload (CVE-2026-92392)

Detects segmentation faults or abort signals from curl or processes linked against libcurl, which may indicate exploitation of CVE-2026-92392. The most likely outcome of triggering this vulnerability is a crash. This rule monitors syslog and kernel log sources for crash indicators. Requires syslog or journald logging of kernel segfault messages.
**Status:** compile ✅ compiles (sigma convert -t splunk --without-pipeline) · confidence: medium
<!-- audit: sigma convert exit 0 (pySigma 1.5.1, splunk backend). Rule targets linux syslog for segfault/SIGABRT patterns from curl-related processes. FP risk: moderate — any curl crash (not just CVE-2026-92392) will fire this rule, including memory exhaustion, other bugs, or corrupt downloads. Best used in correlation with HTTP/2 upload activity and triage of crash dumps. The rule detects the SYMPTOM (crash) not the CAUSE (specific exploit). sigma check could not validate tags due to proxy blocking MITRE ATT&CK data fetch. -->
```yaml
title: curl or libcurl Process Crash Indicating Possible CVE-2026-92392 Exploitation
id: b4e2d6f1-9a53-4c8e-b072-5d1f3e6a9c87
status: experimental
description: >
    Detects segmentation faults or abort signals from curl or processes linked
    against libcurl, reported via kernel log or syslog. The most common outcome
    of triggering CVE-2026-92392 is a use-after-free crash. This rule detects
    the symptom (crash) rather than the specific exploit, so triage should
    correlate with HTTP/2 upload activity and examine crash dumps for
    use-after-free in multi_done() or related functions.
references:
    - https://curl.se/docs/CVE-2026-92392.html
    - https://daniel.haxx.se/blog/2026/10/14/a-uaf-turned-rce/
    - https://github.com/curl/curl/commit/8b0744af5b1b631da5b938ca31c3f9895ad5a321
author: Actioner
date: 2026/10/16
tags:
    - attack.t1203
logsource:
    product: linux
    service: syslog
detection:
    selection_segfault_curl:
        - Message|contains|all:
            - 'segfault'
            - 'curl'
        - Message|contains|all:
            - 'segfault'
            - 'libcurl'
    selection_sigabrt_curl:
        - Message|contains|all:
            - 'SIGABRT'
            - 'curl'
        - Message|contains|all:
            - 'SIGABRT'
            - 'libcurl'
    selection_traps:
        - Message|contains|all:
            - 'traps:'
            - 'curl'
            - 'trap'
    condition: selection_segfault_curl or selection_sigabrt_curl or selection_traps
falsepositives:
    - curl crashes unrelated to CVE-2026-92392 (other bugs, memory exhaustion, corrupt data)
    - Applications with 'curl' in their name that are unrelated to libcurl
    - Development and testing environments running curl under fuzzing or stress testing
level: medium
```

### Network Detection: Not Production-Ready

**No Suricata or Snort rules are provided for this vulnerability.**

The attack uses standard HTTP/2 `RST_STREAM` frames with legitimate error codes (`HTTP_1_1_REQUIRED` / `REFUSED_STREAM`) over TLS-encrypted connections. Specific reasons network rules are not viable:

1. **TLS encryption:** HTTP/2 frames are encrypted within TLS. Without TLS termination on the inspection path, frame contents are invisible to network IDS.
2. **Legitimate protocol behavior:** `RST_STREAM` with `REFUSED_STREAM` (0x07) or `HTTP_1_1_REQUIRED` (0x0d) are standard error codes that appear in normal HTTP/2 traffic (server overload, protocol negotiation, load balancing).
3. **Timing-dependent exploit:** The vulnerability depends on the ordering and timing of frames across multiple streams, which cannot be expressed in stateless IDS signature syntax.
4. **No anomalous byte patterns:** Unlike buffer overflows with characteristic payload signatures, this exploit uses well-formed protocol messages.

For environments with TLS-terminating proxies that log HTTP/2 frame details, a hunting query could look for the pattern: outbound HTTP/2 upload > server RST_STREAM with HTTP_1_1_REQUIRED/REFUSED_STREAM > immediate retry over HTTP/1.1 to the same host. This is a hunting hypothesis, not a detection rule.

## References

- [curl Advisory: CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html)
- [Daniel Stenberg: "A UAF turned RCE"](https://daniel.haxx.se/blog/2026/10/14/a-uaf-turned-rce/)
- [curl 8.23.0 Release Post](https://daniel.haxx.se/blog/2026/10/14/curl-8-23-0/)
- [The Hacker News: curl Patches HTTP/2 Upload Flaw After PoC Demonstrates Client-Side Code Execution](https://thehackernews.com/2026/10/curl-patches-http2-upload-flaw-after.html)
- [Threat Landscape Blog: curl 8.23.0 Fixes High-Severity CVE-2026-92392 HTTP/2 Flaw](https://threatlandscape.io/blog/curl-8-23-0-http2-upload-use-after-free-cve-2026-92392)
- [Fix Commit: 8b0744af5b1b631da5b938ca31c3f9895ad5a321](https://github.com/curl/curl/commit/8b0744af5b1b631da5b938ca31c3f9895ad5a321)
- [Introducing Commit: cd9107e0128191b7b5396b](https://github.com/curl/curl/commit/cd9107e0128191b7b5396b)
- [HackerOne Report #4030333](https://hackerone.com/reports/4030333)
- [Debian Security Advisory DSA-6558-1](https://linuxsecurity.com/advisories/debian/debian-dsa-6558-1-curl)
- [Debian Security Tracker: CVE-2026-92392](https://security-tracker.debian.org/tracker/CVE-2026-92392)
- [oss-security Mailing List Post](https://openwall.com/lists/oss-security/2026/10/14/3)
- [CVE-2026-92392 Advisory JSON](https://curl.se/docs/CVE-2026-92392.json)
