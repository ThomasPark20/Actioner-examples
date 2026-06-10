# Technical Analysis Report: OpenSSL PKCS#7 Use-After-Free RCE CVE-2026-45447 (2026-06-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-10
Version: 1.0 (DRAFT)

## Executive Summary

CVE-2026-45447 is a critical (CVSS 9.8) use-after-free vulnerability in OpenSSL's `PKCS7_verify()` function, discovered through AI-assisted vulnerability research by Alex Gaynor (Anthropic) using Claude. The flaw is triggered when processing a crafted PKCS#7 or S/MIME signed message where the `SignedData.digestAlgorithms` field is an empty ASN.1 SET. Under this condition, OpenSSL incorrectly frees a caller-owned BIO object during verification; subsequent application use of that BIO produces heap corruption, crashes, or potentially remote code execution.

The vulnerability affects all major OpenSSL branches: 4.0.0, 3.6.0-3.6.2, 3.5.0-3.5.6, 3.4.0-3.4.5, 3.0.0-3.0.20, 1.1.1 through 1.1.1zg, and 1.0.2 through 1.0.2zp. Patches are available in versions 4.0.1, 3.6.3, 3.5.7, 3.4.6, 3.0.21, 1.1.1zh (premium support), and 1.0.2zq (premium support). Applications using the CMS API or FIPS modules (3.0-4.0) are not affected; only applications calling the PKCS#7 API directly for S/MIME or PKCS#7 signature verification are vulnerable.

CISA-ADP assigned a CVSS 3.1 score of 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), reflecting the network-reachable, unauthenticated, no-interaction attack surface. Exploitation depends on allocator behavior and the calling application's BIO usage pattern, making reliable RCE application-specific.

## Background: OpenSSL PKCS#7 and S/MIME

OpenSSL is the most widely deployed open-source cryptographic library, providing TLS/SSL, certificate management, and cryptographic message syntax (PKCS#7/CMS) functionality. PKCS#7 (Public-Key Cryptography Standard #7) defines the format for signed and encrypted data, and is the underlying standard for S/MIME email signatures and many enterprise document-signing workflows.

The `PKCS7_verify()` function is the primary API for verifying PKCS#7 signatures. It accepts a `PKCS7` structure and a BIO containing the signed data, performs signature verification against the provided certificates, and returns a verification result. Applications processing S/MIME email, signed software packages, or other PKCS#7-wrapped content commonly call this function.

The CMS (Cryptographic Message Syntax) API is a newer, separate implementation that handles the same use cases but is not affected by this vulnerability. The FIPS provider modules in OpenSSL 3.0-4.0 are also unaffected.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-05 | Alex Gaynor (Anthropic) discovers the vulnerability using Claude AI during systematic fuzzing/code analysis of OpenSSL's PKCS#7 implementation |
| 2026-06-09 | OpenSSL publishes security advisory for CVE-2026-45447; patches released for all supported branches |
| 2026-06-09 | NVD entry published; CISA-ADP assigns CVSS 9.8 |
| 2026-06-10 | Security Online and SecurityWeek publish detailed coverage |

## Root Cause: Incorrect BIO Ownership in PKCS7_verify() with Empty digestAlgorithms

The vulnerability exists in `PKCS7_verify()`. When the `SignedData.digestAlgorithms` field is present as an empty ASN.1 SET (DER encoding: `31 00`), OpenSSL enters a code path that incorrectly calls `BIO_free()` on the caller-owned data BIO. The BIO is owned by the calling application, which expects to continue using it (or free it itself) after `PKCS7_verify()` returns. When the application subsequently accesses or frees the already-freed BIO, a use-after-free condition occurs.

A legitimate `digestAlgorithms` field always contains at least one `AlgorithmIdentifier` (e.g., SHA-256). An empty SET is structurally valid ASN.1 but semantically invalid for PKCS#7 SignedData, making it an unambiguous indicator of an exploit attempt or malformed message.

## Technical Analysis of the Malicious Payload

### 1. Exploit Trigger: Crafted PKCS#7 SignedData with Empty digestAlgorithms

The exploit payload is a PKCS#7 SignedData structure with the following key characteristics:

- **Content type OID:** `1.2.840.113549.1.7.2` (PKCS#7 SignedData), DER: `06 09 2A 86 48 86 F7 0D 01 07 02`
- **digestAlgorithms:** Empty SET, DER: `31 00`
- The remainder of the SignedData structure can be minimal or arbitrary

When this payload is passed to `PKCS7_verify()`, OpenSSL processes the empty digestAlgorithms SET, incorrectly frees the caller's BIO, and returns. The caller's subsequent BIO operation (typically `BIO_free()` in cleanup) dereferences freed memory.

### 2. Exploitation Path

The use-after-free occurs in the heap. Depending on the allocator (glibc malloc, jemalloc, etc.) and the application's heap state:

- **Crash (DoS):** The freed BIO memory is overwritten before the double-free, causing a segfault — the most likely outcome
- **Heap corruption:** Controlled overwrite of freed memory could corrupt adjacent heap metadata or objects
- **RCE:** If an attacker can influence heap layout (e.g., through concurrent requests), they may be able to place controlled data in the freed BIO slot and hijack execution when the application uses the dangling pointer

### 3. Delivery Vectors

The crafted PKCS#7 payload can reach vulnerable applications through:

- **S/MIME email:** Email clients or gateways that verify S/MIME signatures using OpenSSL's PKCS#7 API
- **Web applications:** Services that accept and verify signed documents or data in PKCS#7 format
- **Certificate chains:** Systems processing PKCS#7 certificate bags
- **File transfer:** Any system that processes uploaded PKCS#7-signed files

### 4. Platform-Specific Behavior

#### Linux
The primary target environment. Most OpenSSL-linked server applications (mail gateways, web servers, signing services) run on Linux. glibc's malloc allocator may detect double-free in debug builds but is exploitable in release builds with heap grooming.

#### Windows
Windows applications using OpenSSL (rather than SChannel/CNG) are vulnerable. The Windows heap allocator's behavior differs from glibc, affecting exploitation reliability.

#### macOS
macOS ships LibreSSL by default, which is not affected. Applications explicitly linking OpenSSL (e.g., via Homebrew or bundled) are vulnerable.

### 5. Anti-Forensics / Evasion Techniques

No anti-forensics techniques are applicable — the vulnerability is triggered by a malformed data structure in an otherwise normal cryptographic message. The exploit payload is a single PKCS#7 blob that could be embedded in a standard S/MIME email or file upload.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|---------------------|-------------|
| OpenSSL | 4.0.0 | Use-after-free in PKCS7_verify() |
| OpenSSL | 3.6.0 - 3.6.2 | Use-after-free in PKCS7_verify() |
| OpenSSL | 3.5.0 - 3.5.6 | Use-after-free in PKCS7_verify() |
| OpenSSL | 3.4.0 - 3.4.5 | Use-after-free in PKCS7_verify() |
| OpenSSL | 3.0.0 - 3.0.20 | Use-after-free in PKCS7_verify() |
| OpenSSL | 1.1.1 - 1.1.1zg | Use-after-free in PKCS7_verify() (premium support) |
| OpenSSL | 1.0.2 - 1.0.2zp | Use-after-free in PKCS7_verify() (premium support) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `/usr/lib/libssl.so.*`, `/usr/lib/libcrypto.so.*` | N/A (version-dependent) | Vulnerable OpenSSL shared libraries |
| Linux | `/usr/bin/openssl` | N/A (version-dependent) | Vulnerable OpenSSL binary |

### Network

No network-level IOCs (IPs, domains, URLs) are available for this vulnerability. The exploit payload is embedded in standard PKCS#7/S/MIME data structures and does not require C2 communication.

### Behavioral

- **ASN.1 structural anomaly:** A PKCS#7 SignedData message with an empty `digestAlgorithms` SET (`31 00`) is semantically invalid and should never appear in legitimate traffic. Legitimate PKCS#7 signed messages always include at least one digest algorithm (e.g., SHA-256, SHA-384).
- **Application crash patterns:** Segfaults or heap corruption crashes in applications calling `PKCS7_verify()` — particularly double-free errors detected by allocator guards (glibc `MALLOC_CHECK_`, AddressSanitizer).
- **S/MIME processing failures:** Mail gateway or email client crashes when processing specific signed emails.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Crafted PKCS#7 payload sent to application using OpenSSL's PKCS7_verify() |
| T1203 | Exploitation for Client Execution | S/MIME email with malicious PKCS#7 signature triggers use-after-free in email client |

## Impact Assessment

**Breadth:** Extremely wide. OpenSSL is deployed on virtually every Linux server and is used by countless applications for cryptographic operations. However, only applications that directly call the PKCS#7 API (not CMS) for signature verification are vulnerable. This narrows the attack surface to S/MIME email processors, document signing verification services, and similar PKCS#7-specific workflows.

**Depth:** Critical. Successful exploitation yields code execution with the privileges of the vulnerable application. For mail gateways, this typically means service-account-level access to the mail processing infrastructure.

**Stealth:** Moderate. The exploit payload is a structurally anomalous but syntactically valid PKCS#7 message. Without specific detection rules targeting the empty digestAlgorithms SET, it would pass through as a normal signed message.

**Exploitation probability:** Moderate. While the use-after-free is reliable, achieving RCE (rather than a crash) requires heap grooming tailored to the specific application and allocator, reducing the likelihood of opportunistic exploitation. DoS via crash is trivially achievable.

## Detection & Remediation

### Immediate Detection

**Check OpenSSL version:**
```bash
openssl version
# Vulnerable: anything before 4.0.1, 3.6.3, 3.5.7, 3.4.6, 3.0.21
```

**Check linked OpenSSL version for running processes:**
```bash
for pid in $(pgrep -f 'openssl\|nginx\|apache\|postfix\|dovecot\|sendmail'); do
    echo "PID $pid: $(readlink /proc/$pid/exe)"
    ldd /proc/$pid/exe 2>/dev/null | grep -i ssl
done
```

**Check for crash indicators:**
```bash
# Check for recent PKCS7/S/MIME-related crashes
journalctl --since "7 days ago" | grep -i -E "(pkcs7|smime|SIGSE?GV|double free|heap|use.after.free)"
dmesg | grep -i segfault
```

### Remediation

1. **Patch immediately:** Upgrade OpenSSL to the fixed version for your branch:
   - 4.0.0 -> **4.0.1**
   - 3.6.x -> **3.6.3**
   - 3.5.x -> **3.5.7**
   - 3.4.x -> **3.4.6**
   - 3.0.x -> **3.0.21**
   - 1.1.1x -> **1.1.1zh** (premium support)
   - 1.0.2x -> **1.0.2zq** (premium support)
2. **Restart all services** linked against OpenSSL after upgrading
3. **If patching is delayed:** Disable PKCS#7 signature verification in exposed applications where possible; switch to CMS APIs if the application supports both
4. **Review S/MIME processing infrastructure** — mail gateways (Postfix with OpenSSL-based S/MIME verification, custom mail filters) are the primary attack surface

### Long-Term Hardening

- **Migrate from PKCS#7 to CMS APIs:** OpenSSL's CMS implementation is the successor to the PKCS#7 API and was not affected by this vulnerability. Where possible, update applications to use `CMS_verify()` instead of `PKCS7_verify()`.
- **Enable allocator hardening:** Use `MALLOC_CHECK_=3` or AddressSanitizer in development/staging to catch use-after-free bugs early.
- **Implement ASN.1 input validation:** Applications processing PKCS#7 data should validate the `digestAlgorithms` field is non-empty before passing to `PKCS7_verify()`.
- **Monitor for AI-discovered vulnerabilities:** This vulnerability was found using AI-assisted code analysis (Claude), signaling a trend toward AI-augmented vulnerability research that will accelerate disclosure velocity.

## Detection Rules

These detections target the specific ASN.1 structural anomaly (empty `digestAlgorithms` SET in PKCS#7 SignedData) that triggers CVE-2026-45447, plus a version-inventory Sigma rule. Compiles does not equal fires -- verify against your pipeline and telemetry before production deployment.

### Sigma: Vulnerable OpenSSL Version Detected via Process Execution

Detects `openssl version` execution revealing a vulnerable OpenSSL version string; useful for asset inventory and patch verification, not exploit detection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Version-enumeration rule — detects openssl binary invocations with version output matching vulnerable ranges. Broad match on 3.0.x/1.1.1/1.0.2 since enumerating every point release is impractical; will match patched 3.0.21 as well (FP). Best used as hunt/inventory query, not alert. No pipeline conversion tested (linux process_creation has no standard Sigma pipeline). -->
```yaml
title: Vulnerable OpenSSL Version Detected via Process Execution (CVE-2026-45447)
id: 7c3e8a1d-4b2f-4e9c-a5d6-1f0e2b3c4d5a
status: experimental
description: >
    Detects execution of applications linked against OpenSSL versions vulnerable to
    CVE-2026-45447 (PKCS#7 use-after-free in PKCS7_verify). Vulnerable versions include
    OpenSSL 4.0.0, 3.6.0-3.6.2, 3.5.0-3.5.6, 3.4.0-3.4.5, 3.0.0-3.0.20, 1.1.1-1.1.1zg,
    and 1.0.2-1.0.2zp. Version strings may appear in process command-line output or
    library loading events.
references:
    - https://securityonline.info/openssl-security-patches-rce/
    - https://www.securityweek.com/openssl-patches-high-severity-vulnerability-found-with-ai/
author: Actioner
date: 2026/06/10
tags:
    - attack.t1190
logsource:
    category: process_creation
    product: linux
detection:
    selection_openssl_binary:
        Image|endswith: '/openssl'
        CommandLine|contains: 'version'
    selection_vulnerable_version:
        CommandLine|contains:
            - 'OpenSSL 4.0.0 '
            - 'OpenSSL 3.6.0 '
            - 'OpenSSL 3.6.1 '
            - 'OpenSSL 3.6.2 '
            - 'OpenSSL 3.5.0 '
            - 'OpenSSL 3.5.1 '
            - 'OpenSSL 3.5.2 '
            - 'OpenSSL 3.5.3 '
            - 'OpenSSL 3.5.4 '
            - 'OpenSSL 3.5.5 '
            - 'OpenSSL 3.5.6 '
            - 'OpenSSL 3.4.0 '
            - 'OpenSSL 3.4.1 '
            - 'OpenSSL 3.4.2 '
            - 'OpenSSL 3.4.3 '
            - 'OpenSSL 3.4.4 '
            - 'OpenSSL 3.4.5 '
            - 'OpenSSL 3.0.'
            - 'OpenSSL 1.1.1'
            - 'OpenSSL 1.0.2'
    condition: selection_openssl_binary and selection_vulnerable_version
falsepositives:
    - Legitimate version checking scripts during patching operations
    - Configuration management tools auditing OpenSSL versions
level: medium
```

### Snort: PKCS#7 SignedData with Empty DigestAlgorithms SET

Detects PKCS#7 SignedData content bearing an empty `digestAlgorithms` SET (`31 00`) immediately following the SignedData OID, the exact trigger for CVE-2026-45447.
**Status:** compile ⚠️ uncompiled (Snort not installed)
<!-- audit: snort binary not available in environment; structural check only. Rule uses raw tcp with content hex matches for PKCS#7 SignedData OID + empty SET within 256 bytes. distance:0 anchors the empty SET search after the OID match. FP risk: minimal — empty digestAlgorithms SET in PKCS#7 is semantically invalid and should not appear in legitimate traffic. Evasion: fragmentation across the OID/SET boundary could evade; flow:established mitigates reassembly-based evasion in most deployments. -->
```snort
alert tcp any any -> $HOME_NET any (msg:"Actioner - PKCS7 SignedData with Empty DigestAlgorithms SET (CVE-2026-45447)"; flow:established,to_server; content:"|06 09 2A 86 48 86 F7 0D 01 07 02|"; fast_pattern; content:"|31 00|"; distance:0; within:256; classtype:attempted-admin; reference:cve,2026-45447; reference:url,securityonline.info/openssl-security-patches-rce/; metadata:author Actioner, created 2026-06-10; sid:2100001; rev:1;)
```

### Suricata: PKCS#7 SignedData with Empty DigestAlgorithms SET

Detects PKCS#7 SignedData content bearing an empty `digestAlgorithms` SET (`31 00`) following the SignedData OID in TCP traffic, the trigger for CVE-2026-45447.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Rule uses raw tcp (not app-layer) because PKCS#7 payloads can arrive over any TCP-based protocol (SMTP, HTTP uploads, custom protocols). content hex matches PKCS#7 SignedData OID (1.2.840.113549.1.7.2) then empty SET (31 00) within 256 bytes. FP risk: low — legitimate PKCS#7 never has empty digestAlgorithms. Evasion: TCP segmentation across OID/SET boundary is handled by Suricata's stream reassembly. Does not cover UDP or non-TCP transports (unlikely for PKCS#7). -->
```suricata
alert tcp any any -> $HOME_NET any (msg:"Actioner - PKCS7 SignedData with Empty DigestAlgorithms SET (CVE-2026-45447)"; flow:established,to_server; content:"|06 09 2A 86 48 86 F7 0D 01 07 02|"; fast_pattern; content:"|31 00|"; distance:0; within:256; classtype:attempted-admin; reference:cve,2026-45447; reference:url,securityonline.info/openssl-security-patches-rce/; metadata:author Actioner, created_at 2026-06-10; sid:2200001; rev:1;)
```

### YARA: PKCS#7 SignedData with Empty DigestAlgorithms SET

Detects files containing a PKCS#7 SignedData structure with an empty `digestAlgorithms` SET, the trigger for CVE-2026-45447; scan S/MIME attachments, uploaded PKCS#7 blobs, and mail spool directories.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0 (warning: $empty_set may slow scanning — expected for short hex pattern, acceptable for targeted scans). yara fired on constructed positive (PKCS#7 OID + 31 00), quiet on negative (PKCS#7 OID + 31 0f with SHA-256 AlgorithmIdentifier). Positive constructed from the advisory's published trigger condition (empty digestAlgorithms SET), not invented. FP: a file containing both the PKCS#7 OID and an unrelated 31 00 byte pair could false-positive; the position constraint (empty_set after OID) and filesize cap reduce this. For high-volume scanning, consider adding depth constraints or content-type pre-filtering. -->
```yara
rule Exploit_CVE_2026_45447_PKCS7_Empty_DigestAlgorithms
{
    meta:
        description = "Detects PKCS#7 SignedData with empty digestAlgorithms SET, the trigger for CVE-2026-45447 use-after-free in PKCS7_verify()"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://securityonline.info/openssl-security-patches-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // PKCS#7 SignedData OID: 1.2.840.113549.1.7.2
        $pkcs7_signed_data_oid = { 06 09 2A 86 48 86 F7 0D 01 07 02 }

        // Empty SET (digestAlgorithms = SET OF with zero elements)
        // In DER: SET tag (0x31) + length 0 (0x00)
        $empty_set = { 31 00 }

    condition:
        $pkcs7_signed_data_oid and
        $empty_set and
        // Empty SET must appear after the OID (within the SignedData structure)
        for any i in (1..#empty_set) : (
            @empty_set[i] > @pkcs7_signed_data_oid
        ) and
        filesize < 10MB
}
```

## Lessons Learned

1. **AI-assisted vulnerability discovery is here.** CVE-2026-45447 was found through collaboration between a security researcher and Claude AI, underscoring that AI tools are becoming practical force-multipliers for code auditing. Defenders should expect accelerating vulnerability disclosure rates, particularly in complex C codebases with subtle memory management bugs.

2. **PKCS#7 is a legacy attack surface hiding in plain sight.** While the industry has largely moved to CMS for new implementations, PKCS#7 APIs remain in widespread use for S/MIME processing and legacy interoperability. The empty `digestAlgorithms` SET is a trivial malformation that should have been rejected at the parser level — a class of bug (missing input validation on ASN.1 structures) that affects many cryptographic libraries.

3. **Memory-safety bugs in cryptographic libraries remain critical.** Despite decades of attention, OpenSSL continues to produce use-after-free and similar memory-safety vulnerabilities. Organizations should evaluate their exposure to PKCS#7 processing paths and consider migrating to memory-safe alternatives (Rust-based TLS libraries) or at minimum to the CMS API where OpenSSL must be used.

## Sources

- [Security Online](https://securityonline.info/openssl-security-patches-rce/) — primary coverage of the OpenSSL security patches including CVE-2026-45447 technical details
- [SecurityWeek](https://www.securityweek.com/openssl-patches-high-severity-vulnerability-found-with-ai/) — coverage of AI-assisted discovery by Alex Gaynor/Anthropic and vulnerability details
- [OpenSSL Vulnerabilities Page](https://openssl-library.org/news/vulnerabilities) — official OpenSSL security advisory with affected/patched version matrix
- [NVD CVE-2026-45447](https://nvd.nist.gov/vuln/detail/CVE-2026-45447) — CISA-ADP CVSS 9.8 scoring and CWE-416 classification

---
*Report generated by Actioner*
