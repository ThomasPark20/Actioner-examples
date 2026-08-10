# Technical Analysis Report: CVE-2026-66066 — KindaRails2Shell (2026-08-02)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-02
Version: FINAL

## Executive Summary

CVE-2026-66066 (dubbed "KindaRails2Shell") is a critical pre-authentication arbitrary file read and remote code execution vulnerability in Ruby on Rails Active Storage, scored CVSS v4 9.5. The flaw allows unauthenticated attackers to upload a crafted MATLAB/HDF5 file via Active Storage's direct-upload endpoint and trigger variant processing through libvips, which reads arbitrary server files (including `/proc/1/environ`) and returns their contents as image pixel data. Recovered secrets such as `secret_key_base`, Rails master key, database credentials, and cloud storage tokens enable escalation to full remote code execution via forged ImageProcessing variation payloads. Public PoCs appeared within days of the July 29, 2026 advisory, prompting early disclosure of full technical details and forensic tools by the Rails team.

Applications running Rails 7.0+ defaults with Active Storage and libvips (the default variant processor since Rails 7.0) that accept untrusted image uploads are affected. Patched versions are Active Storage 7.2.3.2, 8.0.5.1, and 8.1.3.1, with a hard requirement on libvips >= 8.13 and ruby-vips >= 2.2.1.

## Background: Rails Active Storage and libvips

Ruby on Rails Active Storage provides a framework for uploading files to cloud storage services (Amazon S3, Google Cloud Storage, Azure Storage) or local disk, and attaching them to Active Record objects. Since Rails 7.0, the default image variant processor is libvips (via the `ruby-vips` gem), replacing ImageMagick. libvips reads and writes file formats through "operations" (loaders/savers), many backed by third-party libraries. Some operations are marked as "unfuzzed" (unsafe for untrusted content) by libvips, meaning they have not been hardened against malicious input. Active Storage did not disable these unfuzzed operations before processing user uploads, creating the attack surface for CVE-2026-66066.

Active Storage also exposes a direct-upload endpoint (`/rails/active_storage/direct_uploads`) that is enabled by default even if the application UI does not use it, broadening the attack surface to applications that may not be aware they accept direct uploads.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-29 | Rails security advisory published (GHSA-xr9x-r78c-5hrm) with patches |
| 2026-07-29 | Patched Active Storage versions 7.2.3.2, 8.0.5.1, 8.1.3.1 released |
| 2026-07-30 | Rapid7 publishes initial analysis; no evidence of exploitation in the wild |
| 2026-07-31 | Public PoCs appear; Rails team releases full technical details and forensic tools early |
| 2026-07-31 | Rails publishes `rails-forensics-CVE-2026-66066` repository with detection tooling |

## Root Cause: Insecure Default Initialization (CWE-1188)

Active Storage hands untrusted uploads to libvips without disabling "unfuzzed" image loaders. libvips operations backed by third-party libraries (specifically the MATLAB/matload loader backed by libmatio, which in turn invokes HDF5) are marked unsafe for untrusted content, but Active Storage did not block them. The configuration option `config.active_storage.variant_processor = :vips` (default in `load_defaults 7.0`) activates the vulnerable code path. The direct-upload route is enabled by default, providing unauthenticated access to the upload mechanism.

## Technical Analysis of the Malicious Payload

### 1. Multi-Stage Exploit Chain

The documented exploitation chain involves 5-6 stages:

**Stage 1 -- CSRF Token Acquisition:** The attacker sends `GET /` to retrieve the CSRF token from `<meta name="csrf-token">`.

**Stage 2 -- Legitimate Upload (Anchor):** `POST /uploads` with a legitimate PNG image to establish a valid representation URL pattern containing the variant key structure at `/rails/active_storage/representations/`.

**Stage 3 -- Malicious Blob Registration:** `POST /rails/active_storage/direct_uploads` with JSON blob metadata (filename, byte_size, checksum, content_type). The content_type is declared as `image/bmp` despite the file being a crafted MATLAB/HDF5 container. Rails permits clients to set a blob's `content_type` without validation.

**Stage 4 -- Artifact Upload:** `PUT` to the signed direct-upload URL with the crafted binary payload. The payload structure:
- MATLAB 5.0 header (128 bytes) -- the first 10 bytes declare "MATLAB 5.0"
- HDF5 signature (`\x89HDF\r\n\x1a\n`) at offset 512
- HDF5 dataset with External File List referencing the target path (e.g., `/proc/1/environ`)
- 512-byte user block between MATLAB header and HDF5 data
- PoC-specific marker: `RAILS_GHSA_OAST_PAYLOAD_V1\x00`
- JSON manifest + Ruby Marshal 4.8 serialized object + SHA256 digest

**Stage 5 -- Variant Processing Trigger:** `GET /rails/active_storage/representations/redirect/[token]` triggers libvips to process the uploaded file. The type-confusion cascade:
1. Rails identifies the file content_type as set by client (no re-validation)
2. libvips identifies actual file type via magic bytes -- first 10 bytes claim "MATLAB 5.0"
3. libvips routes to the MATLAB loader (matload)
4. libmatio dispatches on a different byte range and finds MAT 7.3 format (HDF5)
5. HDF5's External File List feature reads the attacker-specified path (`/proc/1/environ`)
6. File contents are returned as image pixel data in the variant response

### 2. Secret Recovery and RCE Escalation

The pixel data from the rendered variant encodes the contents of `/proc/1/environ`, which contains environment variables including:
- `SECRET_KEY_BASE` -- Rails application signing secret
- Rails master key and encrypted credentials
- Database passwords
- Cloud storage credentials (S3, GCS, Azure)
- Third-party API tokens

The PoC extracts `SECRET_KEY_BASE` from the pixel data and uses it to derive a verifier key. The RCE chain then:
1. Constructs a Ruby Marshal 4.8 serialized object graph
2. Uses `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` as a gadget
3. Wraps `MiniMagick::Tool` targeting `/usr/bin/curl` for out-of-band callback
4. Signs the payload using the recovered verifier key: `base64url(marshal_data)--hmac_sha1(verifier_key)`
5. Submits the signed variation URL, which Rails deserializes and executes

The RCE does not require Marshal deserialization in all cases -- the Rapid7 analysis notes the path "does not require Marshal deserialization" for ImageProcessing 1.x variation forging.

### 3. C2 Infrastructure

No persistent C2 infrastructure is associated with this vulnerability. The PoC uses an OAST (Out-of-band Application Security Testing) callback pattern: `[callback_base]?rails_ghsa_xr9x=[16-byte-hex-nonce]` to confirm code execution via blind HTTP callback.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)
The primary exploitation target is Linux-based Rails deployments where `/proc/1/environ` is readable by the Rails process. This provides direct access to all environment variables.

#### Containerized Deployments
Docker/container deployments are particularly exposed since environment variables are the standard mechanism for passing secrets to containerized applications, making `/proc/1/environ` especially rich.

### 5. Anti-Forensics / Evasion Techniques

The Rails forensic tooling notes that scheduled blob cleanup may remove evidence of exploitation attempts. The attack leaves three artifacts of increasing strength:
1. The uploaded blob record in the Active Storage database
2. The crafted file in the object store
3. The rendered variant (strongest evidence) -- contains the stolen bytes as pixel values in the application's own object store

The crafted file uses a MATLAB 5.0 header combined with HDF5 magic bytes. Note: MATLAB itself produces MAT v7.3 files with an identical byte-level structure, so this pattern alone is not proof of exploitation -- forensic detection via the `crafted_mat_file.rb` detector should be correlated with Active Storage upload context.
<!-- revision: corrected false claim that "legitimate software never produces" this header combination; MATLAB v7.3 files share the same structure. -->

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation. URLs: `hxxps://`, domains: `[.]`, IPs: `[.]`, emails: `[at]`.

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|-------------------|-------------|
| activestorage (Rails) | < 7.2.3.2, 8.0.0-8.0.5.0, 8.1.0-8.1.3.0 | Active Storage variant processing with insecure default |
| libvips | < 8.13 | Does not block unfuzzed operations by default |
| ruby-vips | < 2.2.1 | Missing `block_untrusted` API support |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Linux | /proc/1/environ | Primary target for secret extraction via HDF5 external dataset |
| Linux | /proc/self/environ | Alternate target for environment variable extraction |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | /rails/active_storage/direct_uploads | Direct upload endpoint (POST) -- initial upload stage |
| URL Pattern | /rails/active_storage/representations/redirect/ | Variant processing trigger (GET) -- file read stage |
| URL Pattern | /rails/active_storage/disk/ | Disk service upload endpoint (PUT) -- artifact delivery |

### Behavioral

- HTTP POST to `/rails/active_storage/direct_uploads` with JSON metadata declaring `content_type` as `image/bmp` or other image type, followed by upload of a file with MATLAB 5.0 magic bytes
- HTTP GET to `/rails/active_storage/representations/` triggering variant generation from a recently uploaded blob
- Uploaded files with MATLAB 5.0 header (first 10 bytes) combined with HDF5 signature (`\x89HDF\r\n\x1a\n`) at offset 512 -- note: MATLAB v7.3 (MAT-file 7.3) produces files with this same structure, so context (upload to Active Storage) is required to distinguish exploit payloads from legitimate files
- PoC payload marker string: `RAILS_GHSA_OAST_PAYLOAD_V1`
- Outbound HTTP requests from the Rails process to unexpected external endpoints (OAST callback) following variant processing
- Ruby Marshal 4.8 deserialization with `MiniMagick::Tool` gadget chain executing `/usr/bin/curl`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of Rails Active Storage direct-upload and variant processing endpoints |
| T1005 | Data from Local System | Arbitrary file read via HDF5 External File List reads `/proc/1/environ` and other server files |
| T1552.001 | Unsecured Credentials: Credentials In Files | Extraction of SECRET_KEY_BASE, database passwords, API tokens from process environment |
| T1059 | Command and Scripting Interpreter | RCE via Ruby Marshal deserialization executing system commands through MiniMagick gadget |
<!-- revision: removed T1203 (Exploitation for Client Execution) — client-side technique, not applicable to server-side CVE-2026-66066. Server-side exploitation already covered by T1190. -->

## Impact Assessment

**Breadth:** Any Rails application using Active Storage with libvips (default since Rails 7.0) that accepts image uploads from untrusted users is vulnerable. Rails powers a significant portion of web applications globally, including major platforms like GitHub, Shopify, Basecamp, and numerous SaaS products.

**Depth:** Critical -- unauthenticated pre-auth arbitrary file read escalates to full RCE, credential theft, and potential lateral movement to connected systems (databases, cloud services, third-party APIs).

**Stealth:** Moderate -- exploitation uses standard Active Storage endpoints and produces artifacts (uploaded blobs, rendered variants) that persist in the application's object store, enabling forensic detection. However, scheduled blob cleanup can remove evidence.

**Exploitation Status:** As of July 30, 2026, Rapid7 reported no evidence of active exploitation in the wild. Public PoCs became available by July 31, 2026, making exploitation highly likely going forward.

## Detection & Remediation

### Immediate Detection

**Check if your application is vulnerable:**
```ruby
# In Rails console
Rails.application.config.active_storage.variant_processor
# If :vips → vulnerable (unless already patched)
```

```bash
# Check Active Storage version
bundle show activestorage
# Check libvips version
vips --version
```

**Scan Active Storage blobs for exploitation artifacts:**
Use the official forensic tool: `rails/rails-forensics-CVE-2026-66066` on GitHub. The `bin/kr2s_scan_active_storage_blobs.rb` script reads two header fields from blob byte ranges to identify the MATLAB/HDF5 header combination used in the exploit payload. Note: MATLAB v7.3 files share this byte structure, so the scanner's context (files in Active Storage) provides the distinguishing signal.

**Web server log review:**
```bash
# Search for direct upload requests
grep -E "POST.*/rails/active_storage/direct_uploads" access.log
# Search for representation/variant requests
grep -E "GET.*/rails/active_storage/representations/" access.log
# Correlate: direct upload followed shortly by representation access from same IP
```

### Remediation

1. **Upgrade Active Storage** to 7.2.3.2, 8.0.5.1, or 8.1.3.1
2. **Upgrade libvips** to version 8.13 or later (critical -- patching Rails alone is insufficient with older libvips)
3. **Upgrade ruby-vips** to 2.2.1 or later (when installed)
4. **Rotate all secrets immediately:**
   - `secret_key_base`
   - Rails master key (`config/master.key`)
   - All encrypted credentials (`rails credentials:edit`)
   - Database passwords
   - Cloud storage credentials (S3, GCS, Azure)
   - Third-party API tokens
5. **Run forensic scan** with `rails-forensics-CVE-2026-66066` before blob cleanup removes evidence

**Interim workarounds (if patching is delayed):**
- Set `VIPS_BLOCK_UNTRUSTED` environment variable (requires libvips >= 8.13)
- Add `Vips.block_untrusted(true)` to a Rails initializer (requires ruby-vips >= 2.2.1)
- Note: These workarounds require updated library versions; if upgrading libvips is not immediately possible, consider temporarily switching to ImageMagick: `config.active_storage.variant_processor = :mini_magick`

### Long-Term Hardening

- Run image processing in sandboxed/isolated processes with restricted file system access (Landlock, seccomp profiles)
- Scrub environment variables from image processing worker processes
- Validate uploaded file content types server-side rather than trusting client-provided values
- Monitor and restrict Active Storage direct-upload endpoint access via authentication or network controls
- Implement Content-Type validation that verifies actual file magic bytes match declared types

## Detection Rules

These detections target CVE-2026-66066 exploitation at the web server log level (Sigma), on the network (Snort/Suricata), and at the file level (YARA). PoC/advisory-specific altitude; compiles does not equal fires -- verify in your pipeline.

### Sigma: CVE-2026-66066 Active Storage Direct Upload Activity

Detects HTTP POST requests to the Rails Active Storage direct_uploads endpoint. Hunt-only -- fires on any direct upload, not exploit-specific; pair with variant representation access and payload-level rules for higher fidelity.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0 (with --exclude attacktag due to MITRE API 403 in env; tags are valid technique-only per spec). splunk 0, log_scale 0. webserver logsource is generic; cs-uri-stem and cs-method are standard proxy/web fields. FP risk: legitimate direct uploads from authorized users will match; pair with representation access correlation or anomalous upload volume. -->
<!-- revision: renamed from "Exploitation Attempt" — rule matches ANY direct upload with no exploit-specific condition. Downgraded medium->low, labeled hunt-only. Fixed description that incorrectly claimed temporal correlation was implemented. -->
```yaml
title: CVE-2026-66066 Active Storage Direct Upload Activity
id: 8c4e1a3b-7f2d-4e6a-9b1c-5d3e8f0a2c7b
status: experimental
description: >
    Detects HTTP POST requests to the Rails Active Storage direct_uploads endpoint.
    Hunt-only: fires on any direct upload, not exploit-specific. Pair with variant
    representation access (Sigma rule 2a9f5b1c) and payload-level detections
    (YARA/Snort/Suricata) for CVE-2026-66066 triage.
references:
    - https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm
    - https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails/
    - https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432
author: Actioner
date: 2026/08/02
tags:
    - attack.t1190
    - attack.t1005
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/rails/active_storage/direct_uploads'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Legitimate Active Storage direct uploads from authorized application users
level: low
```

### Sigma: CVE-2026-66066 Active Storage Variant Representation Access

Detects HTTP GET requests to Rails Active Storage representation endpoints which trigger variant processing via libvips. Hunt-only; pair with the direct upload rule above for higher fidelity.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0 (with --exclude attacktag). splunk 0, log_scale 0. This endpoint is hit by any user viewing resized images -- high FP as standalone. Value is in correlation with the direct_uploads rule (same source IP within short window). -->
```yaml
title: CVE-2026-66066 Active Storage Variant Representation Access
id: 2a9f5b1c-3d4e-4f8a-b6c7-1e2d3f4a5b6c
status: experimental
description: >
    Detects HTTP GET requests to Rails Active Storage representation endpoints
    which trigger variant processing via libvips. In CVE-2026-66066 exploitation,
    the attacker requests a representation URL to trigger processing of a crafted
    MATLAB/HDF5 file that reads arbitrary server files.
references:
    - https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm
    - https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails/
author: Actioner
date: 2026/08/02
tags:
    - attack.t1190
    - attack.t1005
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/rails/active_storage/representations/'
        cs-method: 'GET'
    condition: selection
falsepositives:
    - Legitimate image variant requests from application users viewing resized images
level: low
```

### Snort: CVE-2026-66066 Rails Active Storage Direct Upload Request

Detects HTTP POST to the Active Storage direct_uploads endpoint on the wire. Generic endpoint match -- pair with payload-level rules for triage.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: snort -T exit 0 (Snort 2.9.20 with /etc/snort/snort.conf). content match on URI path is case-insensitive via nocase. fast_pattern on the distinctive URI segment. FP: legitimate direct uploads. -->
<!-- revision: reversed traffic direction $HOME_NET->$EXTERNAL_NET to $EXTERNAL_NET->$HOME_NET (inbound attack). Downgraded medium->low (generic endpoint match). -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - CVE-2026-66066 Rails Active Storage Direct Upload Request"; flow:established,to_server; content:"POST"; depth:4; content:"/rails/active_storage/direct_uploads"; fast_pattern; nocase; sid:2100010; rev:2; classtype:web-application-attack; reference:cve,2026-66066; reference:url,github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm;)
```

### Snort: CVE-2026-66066 MATLAB HDF5 Payload Upload

Detects the distinctive MATLAB 5.0 header followed by HDF5 magic bytes in HTTP traffic, consistent with the crafted exploit payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. MATLAB header + HDF5 magic is the file-level signature the Rails forensic tooling uses. Note: MATLAB v7.3 (MAT-file 7.3) legitimately produces files with this same byte structure, so FPs are possible if MAT files are uploaded to the same endpoint. distance:0 within:1024 ensures both patterns are proximate. -->
<!-- revision: reversed traffic direction $HOME_NET->$EXTERNAL_NET to $EXTERNAL_NET->$HOME_NET (inbound attack). Corrected false "legitimate software never produces this" claim — MATLAB v7.3 has identical structure. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - CVE-2026-66066 MATLAB HDF5 Payload Upload to Rails"; flow:established,to_server; content:"MATLAB 5.0"; content:"|89 48 44 46 0D 0A 1A 0A|"; distance:0; within:1024; sid:2100011; rev:2; classtype:web-application-attack; reference:cve,2026-66066; reference:url,github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm;)
```

### Suricata: CVE-2026-66066 Rails Active Storage Direct Upload Request

Detects HTTP POST to the Active Storage direct_uploads endpoint using Suricata HTTP inspection. Generic endpoint match -- pair with payload-level rules for triage.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). http.method + http.uri dot-notation buffers. FP: legitimate direct uploads from authorized users. -->
<!-- revision: reversed traffic direction $HOME_NET->$EXTERNAL_NET to $EXTERNAL_NET->$HOME_NET (inbound attack). Downgraded medium->low (generic endpoint match). -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-66066 Rails Active Storage Direct Upload Request"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/rails/active_storage/direct_uploads"; fast_pattern; classtype:web-application-attack; reference:cve,2026-66066; reference:url,github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm; metadata:author Actioner, created_at 2026-08-02; sid:2200010; rev:2;)
```

### Suricata: CVE-2026-66066 MATLAB HDF5 Payload in HTTP Upload

Detects the crafted MATLAB 5.0 + HDF5 byte pattern in HTTP request bodies, the definitive exploit payload signature.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. http.request_body inspects the upload payload for MATLAB header + HDF5 magic. This is the same combination the Rails forensic detector uses. Note: MATLAB v7.3 (MAT-file 7.3) legitimately produces files with this same byte structure, so FPs are possible if MAT files are uploaded to the application. -->
<!-- revision: reversed traffic direction $HOME_NET->$EXTERNAL_NET to $EXTERNAL_NET->$HOME_NET (inbound attack). Corrected false "legitimate software never produces it" claim — MATLAB v7.3 has identical structure. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-66066 MATLAB HDF5 Payload in HTTP Upload to Rails"; flow:established,to_server; http.request_body; content:"MATLAB 5.0"; fast_pattern; content:"|89 48 44 46 0D 0A 1A 0A|"; distance:0; within:1024; classtype:web-application-attack; reference:cve,2026-66066; reference:url,github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm; metadata:author Actioner, created_at 2026-08-02; sid:2200011; rev:2;)
```

### YARA: Crafted MATLAB/HDF5 Exploit File (CVE-2026-66066)

Detects files with MATLAB 5.0 header at offset 0 combined with HDF5 magic bytes in the first kilobyte -- the same byte pattern used in CVE-2026-66066 exploit payloads. Note: standard MATLAB v7.3 (MAT-file 7.3) files share this structure; context (e.g., presence in Active Storage, or HDF5 External File List referencing /proc/) is needed to confirm exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. MATLAB header at offset 0 + HDF5 magic in range 128-1024 is the combination the Rails forensic detector (crafted_mat_file.rb) uses. MATLAB v7.3 files legitimately share this byte structure, so this rule will match both exploit payloads and legitimate MAT v7.3 files. Use in Active Storage context or pair with additional indicators. -->
<!-- revision: downgraded high->medium — standard MAT v7.3 files have identical byte structure. Corrected false "legitimate software never produces" claims. -->
```yara
rule Exploit_CVE_2026_66066_Crafted_MAT_HDF5
{
    meta:
        description = "Detects MATLAB 5.0 / HDF5 files matching the byte pattern used in CVE-2026-66066 exploitation against Rails Active Storage. Note: legitimate MATLAB v7.3 files share this structure; pair with upload context for triage."
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm"
        severity = "high"

    strings:
        $matlab_header = "MATLAB 5.0" ascii
        $hdf5_magic = { 89 48 44 46 0D 0A 1A 0A }

    condition:
        $matlab_header at 0 and
        $hdf5_magic in (128..1024) and
        filesize < 1MB
}
```

### YARA: CVE-2026-66066 PoC Payload Marker

Detects the specific PoC marker string `RAILS_GHSA_OAST_PAYLOAD_V1` embedded in CVE-2026-66066 exploit tools.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. yara matched on a constructed test file (pos-marker.txt containing the PoC string), quiet on negative. String is from the published Zer0SumGam3/CVE-2026-66066-POC exploit tool -- unique, never appears in legitimate files. Tested against fabricated text file, not a real PoC artifact. -->
<!-- revision: changed "sample: fired" to "sample: constructed" — tested against fabricated text file, not real PoC artifact. -->
```yara
rule Exploit_CVE_2026_66066_POC_Marker
{
    meta:
        description = "Detects the specific PoC payload marker string used in CVE-2026-66066 exploit tools targeting Rails Active Storage"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://github.com/Zer0SumGam3/CVE-2026-66066-POC"
        severity = "critical"

    strings:
        $marker = "RAILS_GHSA_OAST_PAYLOAD_V1" ascii

    condition:
        $marker and filesize < 1MB
}
```

## Lessons Learned

1. **Default configurations must be secure.** The root cause (CWE-1188) is that Active Storage used libvips' full operation set without disabling those marked unsafe for untrusted input. Framework defaults should operate in the most restrictive mode when handling user-provided data.

2. **Content-type trust boundaries matter.** Rails trusting client-provided content types without server-side validation of actual file magic bytes enabled the type-confusion chain. Server-side content-type validation should be mandatory for uploaded files.

3. **Image processing libraries need sandboxing.** Running image processing in the same process and with the same permissions as the web application means a vulnerability in the image pipeline grants access to all application secrets. Isolated processing with restricted file system access (Landlock, seccomp) would contain the impact.

4. **Secret management via environment variables creates concentration risk.** The ability to read `/proc/1/environ` yielded every secret the application possessed. Secrets management solutions that provide secrets on-demand rather than storing them in the process environment would limit exposure from file-read vulnerabilities.

5. **Rapid PoC development accelerates risk.** Public PoCs appeared within 48 hours of the advisory, forcing the Rails team to publish full technical details ahead of their planned August 28 disclosure. Organizations need to patch within hours, not weeks, for critical pre-auth vulnerabilities with known PoCs.

## Sources

- [Rails Security Advisory GHSA-xr9x-r78c-5hrm](https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm) -- official GitHub security advisory with affected versions, CVSS, and patches
- [Rapid7 KindaRails2Shell Analysis](https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails/) -- detailed technical analysis of the exploit chain, timeline, and detection guidance
- [Rails Discussion Forum Advisory](https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432) -- official Rails security announcement with workarounds
- [Rails Discussion Forum Attack Details](https://discuss.rubyonrails.org/t/cve-2026-66066-attack-details-and-tools-to-perform-a-forensic-investigation/91441) -- full attack details and forensic investigation tools
- [Rails Forensics Repository](https://github.com/rails/rails-forensics-CVE-2026-66066) -- official forensic scanner and investigation tooling
- [CVE-2026-66066 PoC](https://github.com/Zer0SumGam3/CVE-2026-66066-POC) -- public proof-of-concept exploit demonstrating the full chain
- [SecurityWeek Coverage](https://www.securityweek.com/ruby-on-rails-patches-critical-vulnerability/) -- initial news coverage
- [HeroDevs Analysis](https://www.herodevs.com/blog-posts/cve-2026-66066-rails-active-storage-arbitrary-file-read-and-rce) -- additional technical context on affected versions and remediation
- [Ethiack Research](https://ethiack.com/info-hub/research/kindarails2shell-rails-rce-cve-2026-66066) -- original researcher analysis (Ethiack team credited as reporters)

---
*Report generated by Actioner*
