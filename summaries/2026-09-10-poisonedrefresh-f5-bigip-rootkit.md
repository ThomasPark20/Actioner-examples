# Technical Analysis Report: PoisonedRefresh Fileless Linux Rootkit (2026-09-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-10
Version: 1.0

## Executive Summary

PoisonedRefresh (tracked by Sophos as Linux/Agnt-IC) is a fileless Linux rootkit targeting F5 BIG-IP Access Policy Manager (APM) systems via CVE-2025-53521, an unauthenticated remote code execution vulnerability. The implant hijacks Apache's module-loading mechanism to inject PHP web shells directly into server memory without writing to disk, making traditional file-based detection ineffective. A UNIX domain socket at `/run/bigtlog.pipe` provides local backdoor access via interactive bash shells. At disclosure, the Shadowserver Foundation identified 795 exposed vulnerable endpoints. The rootkit's use of RC4-encrypted strings, `mmap()` interception, and legitimate CSS response mimicry represent a sophisticated evasion toolkit purpose-built for long-term persistence on network edge appliances.

## Background: F5 BIG-IP APM

F5 BIG-IP Access Policy Manager is a widely deployed enterprise access gateway that provides SSL VPN, identity-aware proxy, and application access policy enforcement. BIG-IP APM runs on a customized Linux distribution with Apache and the PHP module (`libphp`) serving webtop portal interfaces. These webtop components -- including `apm_css.php3`, `full_wt.php3`, and `webtop_popup_css.php3` -- are the specific injection targets. As internet-facing infrastructure handling authentication and remote access, compromised BIG-IP devices provide attackers with privileged network positioning and credential access.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-2026-09-08 | CVE-2025-53521 initially disclosed and misclassified as denial-of-service |
| Pre-2026-09-08 | F5 confirms RCE capability; Shadowserver identifies 795 exposed endpoints |
| Pre-2026-09-08 | Threat actor deploys first-stage payload via modified `/usr/sbin/httpd` binary |
| 2026-09-08 | SophosLabs publishes detailed technical analysis of PoisonedRefresh rootkit |
| 2026-09-10 | Security Affairs reports on PoisonedRefresh; F5 tracks activity as cluster c05d5254 |

## Root Cause: CVE-2025-53521 (Unauthenticated RCE in F5 BIG-IP APM)

CVE-2025-53521 is an unauthenticated remote code execution vulnerability in F5 BIG-IP APM that is exploitable when access policies are configured on virtual servers. The vulnerability was initially misclassified as a denial-of-service issue before F5 confirmed its RCE capability. The attacker leverages this vulnerability to deploy a modified `/usr/sbin/httpd` binary containing a malicious prefix of `0x5430` bytes that bootstraps the PoisonedRefresh implant before normal Apache initialization begins.

## Technical Analysis of the Malicious Payload

### 1. First-Stage Payload: Modified httpd Binary

The attack begins with infection of `/usr/sbin/httpd`, the Apache HTTP server binary. A malicious `0x5430`-byte prefix is embedded into the binary, implementing a custom ELF loader that bypasses the standard dynamic linker. This loader intercepts `__libc_start_main` to execute before Apache's initialization and any security tool activation. The first stage also:

- Modifies SELinux configuration to weaken security controls
- Embeds persistence in BIG-IP upgrade images at `/mnt/tm_install`, ensuring survival across system upgrades

### 2. PoisonedRefresh: In-Memory Web Shell Injection (Linux/Agnt-IC)

PoisonedRefresh is a standalone Linux ELF binary with a custom loader that performs fileless web shell injection through a sophisticated multi-step process:

**Apache Module Loading Interception:**
- Hooks `apr_dso_load` (Apache Portable Runtime module loader function)
- Waits for the PHP module (`libphp`) to load
- Reads `/proc/self/maps` to locate the `libphp` memory region
- Temporarily changes memory permissions via `mprotect()` to read-write-execute
- Redirects file function calls: `open`, `close`, `mmap`, `__fxstat`
- Restores original memory protections after patching

**PHP Web Shell Delivery via mmap() Interception:**
When PHP opens any of these three legitimate BIG-IP APM webtop scripts, the hooked `mmap()` returns a modified memory view containing the original script content preceded by an embedded PHP web shell:

- `apm_css.php3`
- `full_wt.php3`
- `webtop_popup_css.php3`

On-disk files remain completely unmodified -- the web shell exists only in Apache worker process memory.

**Web Shell Command & Control Protocol:**
- **Trigger**: Requests must contain the magic prefix `BSOHAzPB` in raw data from `php://input`
- **Encryption**: Stream cipher using key `wSLjN1beuR`
- **Execution**: Decrypted payload executed via PHP `eval()`
- **Response Obfuscation**: HTTP 201 status with `Content-Type: text/css; charset=utf-8` header, mimicking legitimate CSS responses

### 3. Local Backdoor: UNIX Domain Socket

PoisonedRefresh creates a UNIX domain socket at `/run/bigtlog.pipe` for local privilege access:

- **Authentication**: Requires token `Kzwd6jM5`
- **Behavior**: Redirects shell stdin/stdout/stderr to the socket, launches `/bin/bash`
- **Evasion**: Uses AF_UNIX (avoiding TCP port exposure and network monitoring); on 32-bit systems uses `socketcall` multiplexing
- **Timing**: Delayed trigger using `apr_time_now()` waits for full Apache startup before activating

### 4. Anti-Forensics / Evasion Techniques

**String Obfuscation:**
- All operational strings are RC4-encrypted with the hardcoded 16-byte key `TrswBWIl90Z5e38n`
- Strings are decrypted only at runtime when needed
- Static analysis reveals minimal actionable content beyond function names

**Fileless Architecture:**
- No web shell artifacts written to disk
- Memory-only payload delivery via `mmap()` interception
- Original file integrity checksums remain valid
- Custom ELF loader avoids standard dynamic linker detection
- Relocation table patching targets shared libraries directly in memory

**Threading:**
- Uses `pthread_create` and `pthread_detach` for socket listener threads
- Socket handler runs asynchronously within Apache worker processes

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains/IPs: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `/usr/sbin/httpd` (modified) | `26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9` | Infected Apache binary with 0x5430-byte malicious prefix |
| Linux | `/run/bigtlog.pipe` | N/A (socket) | UNIX domain socket for local backdoor access |
| Linux | `/mnt/tm_install` | N/A (directory) | BIG-IP upgrade image persistence location |

### Behavioral

| Indicator | Description |
|-----------|-------------|
| Apache httpd reading `/proc/self/maps` | PoisonedRefresh locating libphp memory region |
| Temporary RWX permissions on libphp memory | Memory permission changes for function hooking |
| UNIX socket at `/run/bigtlog.pipe` | Local backdoor channel |
| Apache httpd spawning `/bin/bash` | Interactive shell via socket backdoor |
| HTTP 201 responses from `.php3` endpoints with `Content-Type: text/css` | Web shell C2 communication |
| SELinux configuration modifications | First-stage payload weakening security controls |
| Modified BIG-IP upgrade images | Persistence mechanism |

### Cryptographic Material (Hardcoded)

| Artifact | Value | Purpose |
|----------|-------|---------|
| RC4 key | `TrswBWIl90Z5e38n` | String obfuscation/decryption |
| Web shell magic prefix | `BSOHAzPB` | C2 request trigger |
| Stream cipher key | `wSLjN1beuR` | Web shell payload encryption |
| Socket auth token | `Kzwd6jM5` | UNIX socket authentication |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2025-53521 for initial access to BIG-IP APM |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | Hooking `apr_dso_load` to intercept Apache module loading |
| T1055.009 | Process Injection: Proc Memory | In-memory modification of libphp via mmap()/mprotect() interception |
| T1505.003 | Server Software Component: Web Shell | Fileless PHP web shell injected into Apache worker memory |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Interactive /bin/bash via UNIX socket backdoor |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication disguised as CSS responses (HTTP 201 + text/css) |
| T1027 | Obfuscated Files or Information | RC4 encryption of operational strings with hardcoded key |
| T1601.001 | Modify System Image: Patch System Image | Persistence embedded in BIG-IP upgrade images (/mnt/tm_install) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | SELinux configuration modification |
| T1082 | System Information Discovery | Reading /proc/self/maps to enumerate memory layout |

## Impact Assessment

PoisonedRefresh represents a high-impact threat to organizations running F5 BIG-IP APM with exposed management or access policy interfaces. With 795 vulnerable endpoints identified by Shadowserver at disclosure, the potential victim pool is substantial. The fileless nature of the implant means that standard endpoint detection, file integrity monitoring, and forensic disk imaging will miss the active web shell entirely. The rootkit's persistence through BIG-IP upgrade images means that even organizations that patch and upgrade may remain compromised. The combination of an in-memory web shell (for remote access) and a UNIX socket backdoor (for lateral movement from adjacent compromised hosts) gives attackers a resilient, multi-channel persistence framework on a critical network edge device.

## Detection & Remediation

### Immediate Detection

Check for the UNIX socket backdoor:
```bash
ls -la /run/bigtlog.pipe
```

Check for modified httpd binary (compare against known-good hash from F5):
```bash
sha256sum /usr/sbin/httpd
```

Check for anomalous HTTP 201 responses from webtop php3 endpoints in Apache access logs:
```bash
grep -E '(apm_css|full_wt|webtop_popup_css)\.php3.*201' /var/log/httpd/access_log
```

Check for unexpected SELinux modifications:
```bash
sestatus
getenforce
```

Scan process memory for web shell artifacts:
```bash
grep -r "BSOHAzPB" /proc/*/maps 2>/dev/null
strings /proc/$(pgrep -o httpd)/mem 2>/dev/null | grep -E "(BSOHAzPB|wSLjN1beuR|Kzwd6jM5)"
```

### Remediation

1. **Isolate** the affected BIG-IP device from the network immediately
2. **Capture volatile evidence**: dump Apache process memory before restarting services
3. **Apply F5 patches** for CVE-2025-53521
4. **Rebuild** the httpd binary from a known-good F5 image (do not trust in-place repair)
5. **Inspect upgrade images** at `/mnt/tm_install` for embedded persistence
6. **Restore SELinux** configuration to enforcing mode
7. **Rotate all credentials** that traversed the BIG-IP APM (VPN users, SSO tokens, LDAP binds)
8. **Monitor** for re-compromise using the detection rules below

### Long-Term Hardening

- Restrict management interface access to trusted administrative networks only
- Enable ptrace restrictions: `echo 1 > /proc/sys/kernel/yama/ptrace_scope`
- Block `.php3` execution if not required: `<FilesMatch "\.php3$"> Require all denied </FilesMatch>`
- Implement file integrity monitoring on `/usr/sbin/httpd` and BIG-IP upgrade image directories
- Deploy memory forensics capabilities (e.g., Volatility) for periodic Apache process inspection
- Monitor for UNIX socket creation in `/run/` via auditd rules

## Detection Rules

Eight detection rules targeting PoisonedRefresh's distinctive artifacts across host, file, and network telemetry. The YARA rules key on the implant's unique hardcoded cryptographic material and socket path; the Sigma rules detect host-level behavioral indicators via auditd and process/webserver logs; the Suricata rules catch the web shell's distinctive C2 protocol on the wire. Caveat: the behavioral Sigma rules (httpd-spawns-bash, proc/self/maps access) may fire on legitimate CGI or monitoring tools and require environment-specific tuning.

### Sigma: PoisonedRefresh UNIX Socket Creation at bigtlog.pipe

Detects creation of the `/run/bigtlog.pipe` UNIX socket via auditd SOCKADDR records, a unique artifact of the PoisonedRefresh backdoor channel.
<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; saddr value is hex-encoded ASCII of "/run/bigtlog.pipe" per logsource-encoding guidance for auditd hex blobs. -->

**Compile:** Sigma convert Splunk/LogScale: pass | **Confidence:** high

```yaml
title: PoisonedRefresh UNIX Socket Creation at bigtlog.pipe
id: 7a3e2c91-4b8d-4f6e-a1d5-9c0b3e7f2a84
status: experimental
description: >
    Detects creation of the UNIX domain socket /run/bigtlog.pipe, used by the
    PoisonedRefresh rootkit (Linux/Agnt-IC) as a local backdoor channel on
    compromised F5 BIG-IP APM systems (CVE-2025-53521).
references:
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1559
    - attack.t1059.004
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SOCKADDR
        saddr|contains: '2f72756e2f626967746c6f672e70697065'
    condition: selection
falsepositives:
    - Legitimate F5 BIG-IP logging infrastructure using a similarly named socket (unlikely)
level: critical
```

### Sigma: Apache httpd Process Spawning Bash Shell

Detects Apache httpd spawning `/bin/bash`, consistent with the PoisonedRefresh UNIX socket backdoor delivering interactive shell access. Caveat: this is a hunt/triage signal, not an alerting rule -- CGI scripts and ops automation tools can legitimately trigger httpd-to-bash chains.
<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; process_creation logsource with linux product. ParentImage/Image endswith matching is pipeline-dependent. -->
<!-- revision: level capped at medium (behavioral pattern); added hunt/triage caveat per critic. -->

**Compile:** Sigma convert Splunk/LogScale: pass | **Confidence:** medium

```yaml
title: Apache httpd Process Spawning Bash Shell
id: 8b4f3d02-5c9e-4a7f-b2e6-0d1c4f8a3b95
status: experimental
description: >
    Detects Apache httpd spawning an interactive bash shell, a behavior
    consistent with the PoisonedRefresh rootkit backdoor which redirects
    shell I/O through a UNIX socket after exploitation of CVE-2025-53521.
references:
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1059.004
    - attack.t1505.003
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/httpd'
        Image|endswith: '/bash'
    condition: selection
falsepositives:
    - CGI scripts or legitimate server-side applications that invoke bash from Apache
    - Operations automation or monitoring tools executed from Apache context
level: medium
```

### Sigma: Apache httpd Reading /proc/self/maps

Detects Apache httpd accessing `/proc/self/maps`, used by PoisonedRefresh to locate the libphp shared library in memory before injection. Caveat: requires a pre-joined auditd event model for cross-record correlation (SYSCALL + PATH are separate audit records); APM agents and memory profilers routinely read `/proc/self/maps`.
<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; uses auditd SYSCALL+PATH correlation; field names are auditd-native. -->
<!-- revision: level capped at medium; added auditd cross-record correlation caveat and APM/profiler FP note per critic. -->

**Compile:** Sigma convert Splunk/LogScale: pass | **Confidence:** medium

```yaml
title: Apache httpd Reading proc self maps for Memory Mapping
id: 9c5a4e13-6d0f-4b8a-c3f7-1e2d5a9b4c06
status: experimental
description: >
    Detects Apache httpd process accessing /proc/self/maps, which PoisonedRefresh
    uses to locate the libphp shared library in memory before injecting a fileless
    PHP web shell via mmap() interception.
references:
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1055.009
    - attack.t1082
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        exe|endswith: '/httpd'
    selection_path:
        type: PATH
        name: '/proc/self/maps'
    condition: selection and selection_path
falsepositives:
    - Application performance monitoring (APM) agents or memory profilers reading memory maps from httpd context
level: medium
```

### Sigma: HTTP 201 Response from PHP3 Endpoint

Detects the distinctive PoisonedRefresh C2 response pattern: HTTP 201 status codes returned from BIG-IP APM webtop `.php3` endpoints, which should not produce 201 responses under normal operation.
<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; webserver logsource uses W3C/IIS field naming (sc-status, cs-uri-stem); Apache environments may need field mapping. -->
<!-- revision: title corrected -- detection block has no content_type field; removed CSS claim from title and description. -->

**Compile:** Sigma convert Splunk/LogScale: pass | **Confidence:** high

```yaml
title: HTTP 201 Response from PHP3 Endpoint
id: 1d6b5f24-7e1a-4c9b-d4a8-2f3e6b0c5d17
status: experimental
description: >
    Detects HTTP 201 responses from .php3 endpoints, a distinctive behavioral
    signature of the PoisonedRefresh web shell C2 communication pattern on
    compromised F5 BIG-IP APM systems.
references:
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/
author: Actioner
date: 2026-09-10
tags:
    - attack.t1505.003
    - attack.t1071.001
logsource:
    category: webserver
detection:
    selection:
        sc-status: 201
        cs-uri-stem|endswith:
            - 'apm_css.php3'
            - 'full_wt.php3'
            - 'webtop_popup_css.php3'
    condition: selection
falsepositives:
    - Legitimate F5 BIG-IP APM webtop scripts should not return HTTP 201
level: critical
```

### YARA: Rootkit_PoisonedRefresh_LinuxAgntIC

Detects the PoisonedRefresh ELF binary via its unique combination of hardcoded RC4 key, web shell magic prefix, stream cipher key, socket authentication token, and target PHP filenames.
<!-- audit: yarac poisonedrefresh.yar /dev/null EXIT:0 on attempt 3 (attempts 1-2 fixed unreferenced strings $proc_maps, $proc_exe, $libphp). ELF magic check + filesize < 5MB + combination logic requires multiple distinct operational strings. -->

**Compile:** yarac: pass | **Confidence:** high

```yara
rule Rootkit_PoisonedRefresh_LinuxAgntIC
{
    meta:
        description = "Detects the PoisonedRefresh fileless Linux rootkit (Linux/Agnt-IC) targeting F5 BIG-IP APM via CVE-2025-53521, based on embedded operational strings"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $rc4_key = "TrswBWIl90Z5e38n" ascii
        $magic = "BSOHAzPB" ascii
        $ws_key = "wSLjN1beuR" ascii
        $auth_token = "Kzwd6jM5" ascii
        $socket_path = "/run/bigtlog.pipe" ascii
        $php1 = "apm_css.php3" ascii
        $php2 = "full_wt.php3" ascii
        $php3 = "webtop_popup_css.php3" ascii
        $apr_hook = "apr_dso_load" ascii
        $libphp = "libphp" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($rc4_key and 1 of ($magic, $ws_key, $auth_token)) or
            ($socket_path and 2 of ($php1, $php2, $php3)) or
            (4 of ($rc4_key, $magic, $ws_key, $auth_token, $socket_path, $apr_hook, $libphp))
        )
}
```

### YARA: Rootkit_PoisonedRefresh_WebShellStrings

Broader hunt rule for PoisonedRefresh artifacts in ELF binaries or memory dumps, matching any 3 of the 5 unique operational strings. Caveat: designed for threat hunting on memory dumps where the ELF header check is inappropriate.
<!-- audit: yarac poisonedrefresh.yar /dev/null EXIT:0. No file-type gate (intentional for memory forensics). Requires 3-of-5 unique strings to minimize false positives. -->

**Compile:** yarac: pass | **Confidence:** medium (no file-type constraint)

```yara
rule Rootkit_PoisonedRefresh_WebShellStrings
{
    meta:
        description = "Detects PoisonedRefresh web shell trigger strings and encryption keys in ELF binaries or memory dumps"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        tlp = "WHITE"
        severity = "high"

    strings:
        $magic = "BSOHAzPB" ascii
        $ws_key = "wSLjN1beuR" ascii
        $auth = "Kzwd6jM5" ascii
        $rc4 = "TrswBWIl90Z5e38n" ascii
        $socket = "/run/bigtlog.pipe" ascii

    condition:
        3 of them
}
```

### Suricata: PoisonedRefresh Web Shell C2 Request

Detects inbound HTTP requests to `.php3` endpoints containing the `BSOHAzPB` magic prefix in the request body, the trigger mechanism for the PoisonedRefresh web shell.
<!-- audit: suricata -T -S poisonedrefresh_suricata.rules -l /tmp/actioner EXIT:0. Uses http.uri endswith + http.request_body startswith for the magic prefix. fast_pattern on BSOHAzPB. -->

**Compile:** Suricata -T: pass | **Confidence:** high

```
alert http any any -> $HOME_NET any (msg:"Actioner - PoisonedRefresh Web Shell C2 Request to BIG-IP php3 Endpoint"; flow:established,to_server; http.uri; content:".php3"; endswith; http.request_body; content:"BSOHAzPB"; startswith; fast_pattern; classtype:web-application-attack; reference:url,www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/; metadata:author Actioner, created_at 2026-09-10, cve CVE-2025-53521; sid:2100101; rev:1;)
```

### Suricata: PoisonedRefresh Web Shell HTTP 201 CSS Response

Detects outbound HTTP 201 responses with `text/css` content type, the distinctive response pattern used by PoisonedRefresh to camouflage web shell output as legitimate CSS content.
<!-- audit: suricata -T -S poisonedrefresh_suricata.rules -l /tmp/actioner EXIT:0 after rev:2 fix removing http.uri from to_client rule (direction conflict). Response-only buffers: http.stat_code + http.content_type. -->

**Compile:** Suricata -T: pass | **Confidence:** medium (HTTP 201 + text/css alone may match non-malicious APIs; best deployed on BIG-IP-facing segments)

```
alert http $HOME_NET any -> any any (msg:"Actioner - PoisonedRefresh Web Shell HTTP 201 CSS Response from php3 Endpoint"; flow:established,to_client; http.stat_code; content:"201"; http.content_type; content:"text/css"; classtype:web-application-attack; reference:url,www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/; metadata:author Actioner, created_at 2026-09-10, cve CVE-2025-53521; sid:2100102; rev:2;)
```

### Snort: PoisonedRefresh Web Shell C2 Request

Detects inbound HTTP requests containing the `BSOHAzPB` magic prefix in POST body data sent to `.php3` endpoints.

**Compile:** Snort is not installed -- structural check only | **Confidence:** high

```
alert http any any -> $HOME_NET any (msg:"Actioner - PoisonedRefresh Web Shell C2 Request Magic Prefix BSOHAzPB"; flow:established, to_server; http_uri; content:".php3"; http_client_body; content:"BSOHAzPB", offset 0, depth 8, fast_pattern; classtype:web-application-attack; reference:url,www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/; metadata:author Actioner, created 2026-09-10, cve CVE-2025-53521; sid:2100201; rev:1;)
```

### Snort: PoisonedRefresh Web Shell HTTP 201 CSS Response

Detects outbound HTTP 201 responses with `text/css` content type from BIG-IP APM `.php3` endpoints.

**Compile:** Snort is not installed -- structural check only | **Confidence:** medium

```
alert http $HOME_NET any -> any any (msg:"Actioner - PoisonedRefresh Web Shell HTTP 201 CSS Response"; flow:established, to_client; http_stat_code; content:"201"; http_header; content:"text/css"; http_uri; content:".php3"; classtype:web-application-attack; reference:url,www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/; metadata:author Actioner, created 2026-09-10, cve CVE-2025-53521; sid:2100202; rev:1;)
```

## Lessons Learned

PoisonedRefresh demonstrates the continued evolution of network appliance-targeted malware toward fully fileless architectures. The rootkit's technique of hijacking Apache's runtime module loader to intercept `mmap()` calls -- delivering web shells purely through memory views of legitimate files -- is a significant escalation in evasion sophistication. Defenders relying solely on file integrity monitoring or traditional antivirus scanning on edge appliances will miss this class of threat entirely. This incident reinforces three structural defensive needs: (1) runtime memory integrity monitoring on critical infrastructure, (2) network-level detection of anomalous HTTP response patterns from edge devices, and (3) treating network appliance firmware/upgrade images as part of the trusted computing base that requires cryptographic verification before and after installation.

## Sources

- [Security Affairs - PoisonedRefresh](https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html) -- initial public reporting on PoisonedRefresh with CVE-2025-53521 context and Shadowserver exposure data
- [SophosLabs - Dissecting a PHP Web Server Rootkit](https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit/) -- primary technical analysis with full attack chain decomposition, IOCs, and memory injection mechanics

---
*Report generated by Actioner*
