# Technical Analysis Report: PoisonedRefresh Fileless Linux Rootkit Targeting F5 BIG-IP APM (2026-09-11)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-11
Version: 1.1

## Executive Summary

PoisonedRefresh is a fileless Linux rootkit that exploits CVE-2025-53521 (CVSS 9.8) to inject PHP web shells directly into Apache memory on F5 BIG-IP Access Policy Manager (APM) servers. Discovered independently by SophosLabs and ESET in September 2026, the rootkit intercepts Apache Portable Runtime (APR) function calls to monitor module loading, locates `libphp` in process memory via `/proc/self/maps`, and injects malicious PHP code into the in-memory representation of three legitimate BIG-IP APM webtop scripts. On-disk files remain unmodified, defeating conventional file-integrity monitoring. The rootkit also creates a UNIX domain socket at `/run/bigtlog.pipe` for interactive shell access without opening network ports. An installer component propagates the malware by infecting BIG-IP upgrade images, enabling persistence across system updates. The Shadowserver Foundation reported 795 vulnerable BIG-IP APM endpoints exposed to the internet as of September 7, 2026.

## Background: F5 BIG-IP Access Policy Manager

F5 BIG-IP APM is a widely deployed network appliance providing secure remote access, SSL VPN, and application access management for enterprise environments. BIG-IP APM runs Apache with PHP (`libphp`) to serve its webtop interface -- a web-based portal through which authenticated users access internal applications. The platform uses CentOS-based Linux with SELinux enforcement. BIG-IP APM webtop scripts include PHP3-format files (e.g., `apm_css.php3`, `full_wt.php3`, `webtop_popup_css.php3`) that are legitimate components of the access policy interface. BIG-IP systems are high-value targets due to their perimeter position and the sensitive traffic they mediate.

CVE-2025-53521 was initially disclosed on October 15, 2025 as a denial-of-service vulnerability, but F5 reclassified it as an unauthenticated remote code execution flaw on March 27, 2026. CISA added it to the Known Exploited Vulnerabilities (KEV) catalog the same day. The vulnerability affects BIG-IP APM versions 15.1.0--15.1.10, 16.1.0--16.1.6, 17.1.0--17.1.2, and 17.5.0--17.5.1.

## Technical Analysis

### Stage 1: Initial Access and Installation

The PoisonedRefresh rootkit is deployed as a second-stage payload following exploitation of CVE-2025-53521 against the `apmd` daemon. The installer component, found embedded within a modified `/usr/bin/umount` binary, operates with root privileges and performs the following:

1. **SELinux Disablement**: Turns off SELinux enforcement to remove mandatory access control barriers.
2. **httpd Infection**: Prepends 0x5430 bytes of malicious code to the legitimate `/usr/sbin/httpd` binary, creating a composite executable that loads the rootkit before Apache initialization.
3. **Install Media Infection**: Infects `umount`, `httpd`, and `rc.local` inside BIG-IP install images located at `/mnt/tm_install`, enabling propagation to other systems via installation media.

### Stage 2: Custom ELF Loading and Startup Hijacking

When the infected `httpd` binary executes:

1. **Custom ELF Loader**: The malicious prefix reopens its own image via `/proc/self/exe`, seeks to the offset where the preserved original Apache executable begins, and manually loads the embedded ELF into memory using custom relocation patching rather than the standard Linux dynamic loader.
2. **`__libc_start_main` Interception**: The rootkit wraps `__libc_start_main` to execute its initialization code before Apache's `main()` function runs, ensuring the implant is active before logging systems initialize.

### Stage 3: APR Function Hooking and Memory Injection

1. **`apr_dso_load` Hook**: The rootkit hooks the Apache Portable Runtime's module loading function (`apr_dso_load`) and monitors for `libphp` being loaded.
2. **Memory Inspection**: Upon detecting `libphp`, the rootkit parses `/proc/self/maps` to locate the module's memory address range.
3. **Relocation Patching**: The rootkit walks the relocation data associated with `libphp` and adjusts PC-relative call targets for four functions: `open`, `close`, `mmap`, and `__fxstat`. Memory pages are temporarily set to RWX (`mprotect`), patched, then restored to RX.
4. **mmap Interception**: When PHP opens one of the three target files (`apm_css.php3`, `full_wt.php3`, `webtop_popup_css.php3`), the rootkit records the file descriptor. When that file is subsequently memory-mapped, the rootkit creates a modified in-memory view that prepends the embedded PHP web shell to the mapped content, leaving the on-disk file unchanged.

### Stage 4: Web Shell Operation

The injected PHP web shell operates as follows:

- **Request Processing**: Reads raw request bytes from `php://input`, checks for the magic prefix `BSOHAzPB`, decrypts the remainder using a stream cipher with key `wSLjN1beuR`, and executes the decrypted content via `eval()`.
- **Response Camouflage**: Returns HTTP status 201 with `Content-Type: text/css; charset=utf-8`, making web shell traffic appear as stylesheet requests in access logs and network monitoring.
- **String Protection**: Operational strings are encrypted with RC4 using the hardcoded key `TrswBWIl90Z5e38n` and decrypted at runtime, evading static string searches.

### Stage 5: UNIX Socket Backdoor

The rootkit provides a second access channel independent of the web shell:

1. **Delayed Activation**: Hooks `apr_time_now` as a trigger mechanism, waiting until Apache has fully started before launching a background worker thread.
2. **Socket Binding**: Creates a UNIX domain socket at `/run/bigtlog.pipe`, disguised as a BIG-IP logging pipe.
3. **Authentication**: Accepts connections and verifies a fixed token (`Kzwd6jM5`) before granting access.
4. **Shell Spawning**: Redirects standard input, output, and error streams to the socket and executes `/bin/bash`, providing interactive shell access. The listener remains active and accepts additional connections.

### Evasion Techniques

| Technique | Description |
|-----------|-------------|
| Fileless web shell | PHP web shell exists only in memory; on-disk files remain benign |
| Pre-logging execution | Initialization occurs via `__libc_start_main` before Apache logging starts |
| RC4 string encryption | Operational strings encrypted with key `TrswBWIl90Z5e38n` |
| CSS response mimicry | Web shell responses use HTTP 201 with `text/css` content type |
| No network listener | UNIX socket avoids TCP port exposure detectable by port scans |
| Install media persistence | Survives BIG-IP upgrades by infecting installation images |
| Relocation patching | Hooks functions via relocation data manipulation rather than LD_PRELOAD or ptrace |

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in report prose use defanged notation. Detection rules use real (non-defanged) values.

### File System

| Path | Type | Description |
|------|------|-------------|
| `/usr/sbin/httpd` | Infected Binary | Apache httpd with 0x5430-byte malicious prefix |
| `/usr/bin/umount` | Installer | Modified umount containing rootkit payload |
| `/run/bigtlog.pipe` | UNIX Socket | Backdoor interactive shell socket |
| `/run/bigstart.ltm` | Persistence | Persistence indicator file |
| `apm_css.php3` | Target Script | BIG-IP APM webtop PHP script (memory-injected) |
| `full_wt.php3` | Target Script | BIG-IP APM webtop PHP script (memory-injected) |
| `webtop_popup_css.php3` | Target Script | BIG-IP APM webtop PHP script (memory-injected) |
| `/mnt/tm_install` | Install Media | BIG-IP upgrade image directory (infected for propagation) |
| `rc.local` | Persistence | Modified in BIG-IP install images |

### Hashes

| Algorithm | Value | Description |
|-----------|-------|-------------|
| SHA-256 | `26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9` | PoisonedRefresh rootkit sample |

### Operational Strings

| String | Purpose |
|--------|---------|
| `TrswBWIl90Z5e38n` | RC4 encryption key for operational strings |
| `BSOHAzPB` | Web shell magic prefix in HTTP request body |
| `wSLjN1beuR` | Stream cipher key for web shell payload decryption |
| `Kzwd6jM5` | UNIX socket authentication token |

### Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| Apache worker reading `/proc/self/maps` | Memory inspection for libphp location |
| Temporary RWX permissions on libphp memory | Relocation patching activity |
| HTTP 201 responses with `text/css` from `.php3` endpoints | Web shell response camouflage |
| `/bin/bash` spawned as child of `/usr/sbin/httpd` | UNIX socket shell activation |
| UNIX socket creation at `/run/bigtlog.pipe` | Backdoor channel establishment |
| SELinux disabled on BIG-IP appliance | Installer preparation step |

### Vulnerability

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2025-53521 | 9.8 (v3.1) | Unauthenticated RCE in F5 BIG-IP APM `apmd` process |

### Affected Versions

| Branch | Vulnerable Range |
|--------|-----------------|
| 17.5.x | 17.5.0 -- 17.5.1 |
| 17.1.x | 17.1.0 -- 17.1.2 |
| 16.1.x | 16.1.0 -- 16.1.6 |
| 15.1.x | 15.1.0 -- 15.1.10 |

### AV Designations

| Vendor | Name |
|--------|------|
| Sophos | Linux/Agnt-IC |
| ESET | PoisonedRefresh |
| F5 | Cluster identifier c05d5254 |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | PoisonedRefresh Usage |
|-------------|----------------|----------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2025-53521 against BIG-IP APM |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Interactive `/bin/bash` via UNIX socket backdoor |
| T1055 | Process Injection | In-memory PHP web shell injection via mmap hooking |
| T1505.003 | Server Software Component: Web Shell | PHP web shell injected into Apache memory space |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | APR function hooking (`apr_dso_load`, `apr_time_now`) |
| T1140 | Deobfuscate/Decode Files or Information | RC4 decryption of operational strings at runtime |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Socket named `bigtlog.pipe` mimicking BIG-IP logging; HTTP 201/CSS response |
| T1562.001 | Impair Defenses: Disable or Modify Tools | SELinux disablement during installation |
| T1542.003 | Pre-OS Boot: Bootkit | Persistence via infected BIG-IP install images and rc.local |
| T1070.004 | Indicator Removal: File Deletion | Fileless operation -- web shell never written to disk |
| T1106 | Native API | Custom ELF loading, relocation patching, `mprotect` syscalls |
| T1071 | Application Layer Protocol | Web shell communication disguised as CSS requests |

## Impact Assessment

**Severity: Critical**

- **Scope**: Any F5 BIG-IP APM deployment running affected versions with an APM access policy configured on a virtual server is vulnerable to initial exploitation via CVE-2025-53521.
- **Exposure**: 795 vulnerable endpoints documented by Shadowserver Foundation as of September 7, 2026.
- **Stealth**: Fileless web shell defeats file-integrity monitoring; process memory analysis required for detection.
- **Persistence**: Install media infection enables survival across BIG-IP upgrades and redeployments.
- **Access**: Dual access channels (HTTP web shell + UNIX socket) provide redundant entry points.
- **Blast Radius**: BIG-IP APM mediates authentication for internal applications; compromise enables lateral movement, credential harvesting, and traffic interception.

## Detection and Remediation

### Detection Priorities

1. **Process Memory Analysis**: Capture and inspect Apache worker process memory for injected PHP code; on-disk file comparison alone is insufficient.
2. **Behavioral Monitoring**: Alert on Apache workers reading `/proc/self/maps`, temporary RWX memory permissions on `libphp`, and `/bin/bash` spawned from `httpd`.
3. **Network Telemetry**: Monitor for HTTP 201 responses with `text/css` content type from `.php3` endpoints, and POST requests to `apm_css.php3`, `full_wt.php3`, or `webtop_popup_css.php3`.
4. **File System Inspection**: Check for unexpected UNIX socket at `/run/bigtlog.pipe` and verify integrity of `/usr/sbin/httpd` and `/usr/bin/umount` against known-good hashes.
5. **SELinux Status**: Alert on SELinux being disabled or set to permissive mode.

### Remediation Steps

1. **Patch Immediately**: Apply F5-released patches for CVE-2025-53521 (advisory K000156741).
2. **Volatile Evidence First**: Capture process memory before any service restart -- restarting Apache destroys the in-memory web shell evidence.
3. **Assume Dual Access**: Both web shell and UNIX socket channels must be addressed; closing one leaves the other active.
4. **Validate Install Media**: Check BIG-IP upgrade images for infection; reimage from known-clean media.
5. **Binary Integrity**: Compare `/usr/sbin/httpd` and `/usr/bin/umount` sizes and hashes against F5-provided baselines.
6. **Restrict Attack Surface**: Disable `.php3` execution if not required; restrict `/proc/self/maps` access; enforce SELinux.

### Hardening Recommendations

- Restrict `.php3` execution in Apache configuration:
  ```apache
  <FilesMatch "\.php3$">
      Require all denied
  </FilesMatch>
  ```
- Restrict ptrace scope: `echo 1 > /proc/sys/kernel/yama/ptrace_scope`
- Monitor for UNIX socket binding under `/run/` by non-standard processes

## Detection Rules

### Sigma Rules

#### Rule 1: Apache Worker Reading /proc/self/maps

Detects Apache httpd workers reading `/proc/self/maps` to locate libphp memory ranges -- a key step in the PoisonedRefresh memory injection chain.

**Status**: compiled (Splunk, LogScale) | confidence: medium

```yaml
title: PoisonedRefresh - Apache Worker Reading /proc/self/maps
id: 8a3c7e1d-4f2b-4d9a-b6e8-1c5a0f3d7e2b
status: experimental
description: Detects Apache httpd worker processes reading /proc/self/maps, a behavior observed in PoisonedRefresh rootkit memory injection targeting F5 BIG-IP APM servers. The rootkit parses this file to locate libphp memory ranges before patching relocations.
references:
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
author: Actioner
date: 2026/09/11
tags:
    - attack.t1055
    - attack.t1106
logsource:
    product: linux
    category: file_access
detection:
    selection:
        Image|endswith: '/httpd'
        FileName: '/proc/self/maps'
    condition: selection
falsepositives:
    - Legitimate Apache debugging or performance monitoring tools
    - Custom Apache modules that inspect process memory maps
level: high
```

> Requires Linux file-access audit logging (e.g., auditd with file-access rules or Sysmon for Linux).

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0, output: Image="*/httpd" FileName="/proc/self/maps". sigma convert --without-pipeline -t log_scale: exit 0. sigma check: blocked by proxy (MITRE ATT&CK data fetch 403). yamlload: valid. -->

---

#### Rule 2: Suspicious UNIX Socket at /run/bigtlog.pipe

Detects creation of the PoisonedRefresh backdoor UNIX socket at its hardcoded path.

**Status**: compiled (Splunk, LogScale) | confidence: critical

```yaml
title: PoisonedRefresh - Suspicious UNIX Socket Creation at /run/bigtlog.pipe
id: 2f9b4a6c-8d1e-4c3f-a7b5-9e0d2f6a1b8c
status: experimental
description: Detects creation of a UNIX domain socket at /run/bigtlog.pipe, the hardcoded backdoor socket path used by the PoisonedRefresh rootkit on compromised F5 BIG-IP APM servers for interactive shell access.
references:
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
author: Actioner
date: 2026/09/11
tags:
    - attack.t1071
    - attack.t1059.004
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename: '/run/bigtlog.pipe'
    condition: selection
falsepositives:
    - Unlikely in legitimate environments as this is a hardcoded rootkit artifact
level: critical
```

> Very low false-positive rate due to hardcoded artifact path.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0, output: TargetFilename="/run/bigtlog.pipe". sigma convert --without-pipeline -t log_scale: exit 0. sigma check: blocked by proxy. -->

---

#### Rule 3: Bash Shell Spawned from Apache httpd

Detects `/bin/bash` executed as a child of Apache httpd, the behavior observed when PoisonedRefresh's UNIX socket backdoor is accessed.

**Status**: compiled (Splunk, LogScale) | confidence: high

```yaml
title: PoisonedRefresh - Bash Shell Spawned from Apache httpd
id: 5d8f2c1a-3e7b-4a6d-9c0e-4b7f1d2a8e3c
status: experimental
description: Detects /bin/bash being executed as a child process of Apache httpd, which occurs when the PoisonedRefresh rootkit UNIX socket backdoor is accessed. The rootkit redirects stdio to the socket and executes /bin/bash for interactive access.
references:
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
author: Actioner
date: 2026/09/11
tags:
    - attack.t1059.004
    - attack.t1505.003
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '/httpd'
        Image: '/bin/bash'
    condition: selection
falsepositives:
    - CGI scripts legitimately invoking bash from Apache
    - Apache maintenance scripts
level: high
```

> On BIG-IP APM, bash from httpd is unexpected; may need tuning in general Apache environments with CGI.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0, output: ParentImage="*/httpd" Image="/bin/bash". sigma convert --without-pipeline -t log_scale: exit 0. sigma check: blocked by proxy. -->

---

#### Rule 4: SELinux Disabled on BIG-IP

Detects SELinux disablement, a preparatory step in the PoisonedRefresh installation process.

**Status**: compiled (Splunk, LogScale) | confidence: medium

```yaml
title: PoisonedRefresh - SELinux Disabled on F5 BIG-IP
id: 7e4b1d9a-6c3f-4e2a-8d5b-0a9c3e7f2d1b
status: experimental
description: Detects attempts to disable SELinux enforcement, a step performed by the PoisonedRefresh installer to allow rootkit operations on F5 BIG-IP APM servers.
references:
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
author: Actioner
date: 2026/09/11
tags:
    - attack.t1562.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_setenforce:
        Image|endswith: '/setenforce'
        CommandLine|contains: '0'
    selection_selinux_config:
        Image|endswith:
            - '/sed'
            - '/echo'
        CommandLine|contains:
            - 'SELINUX=disabled'
            - 'SELINUX=permissive'
    condition: 1 of selection_*
falsepositives:
    - Legitimate SELinux administration
    - System provisioning scripts
level: medium
```

> Generic rule -- gains value when correlated with other PoisonedRefresh indicators on BIG-IP systems.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0, output valid. sigma convert --without-pipeline -t log_scale: exit 0. sigma check: blocked by proxy. -->

---

#### Rule 5: HTTP 201 CSS Response from PHP3 Endpoint

Detects the distinctive PoisonedRefresh web shell response pattern: HTTP 201 with CSS content type from BIG-IP APM `.php3` endpoints.

**Status**: compiled (Splunk, LogScale) | confidence: critical

```yaml
title: PoisonedRefresh - HTTP 201 Response with CSS Content-Type from PHP Endpoint
id: 3a6d9e2f-1b7c-4e8a-9f0d-5c4b2a1e7d3f
status: experimental
description: Detects HTTP 201 responses with text/css content-type from .php3 endpoints, a distinctive web shell response pattern used by PoisonedRefresh to camouflage command output as stylesheet requests.
references:
    - https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit
    - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
author: Actioner
date: 2026/09/11
tags:
    - attack.t1505.003
    - attack.t1036.005
logsource:
    category: webserver
    product: apache
detection:
    selection:
        sc-status: 201
        cs-uri|endswith:
            - 'apm_css.php3'
            - 'full_wt.php3'
            - 'webtop_popup_css.php3'
    condition: selection
falsepositives:
    - Legitimate BIG-IP APM webtop operations returning 201 status codes are not expected for these endpoints
level: critical
```

> Requires Apache access log ingestion with status code and URI fields.

<!-- audit: sigma convert --without-pipeline -t splunk: exit 0, output: "sc-status"=201 "cs-uri" IN ("*apm_css.php3", "*full_wt.php3", "*webtop_popup_css.php3"). sigma convert --without-pipeline -t log_scale: exit 0. sigma check: blocked by proxy. -->

---

### YARA Rules

#### Rule 6: PoisonedRefresh Rootkit Strings

Detects PoisonedRefresh ELF binary based on combinations of hardcoded operational strings including encryption keys, socket paths, and web shell markers.

**Status**: compiled (yarac exit 0) + positive/negative test pass | confidence: critical

```yara
rule PoisonedRefresh_Rootkit_Strings
{
    meta:
        description = "Detects PoisonedRefresh fileless Linux rootkit targeting F5 BIG-IP APM based on hardcoded operational strings"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        hash = "26bd5b0722d1dbab5db749a063c49bc8638653ac2addfead7a9cb3d6d57bccc9"
        severity = "critical"

    strings:
        $rc4_key = "TrswBWIl90Z5e38n"
        $socket_path = "/run/bigtlog.pipe"
        $auth_token = "Kzwd6jM5"
        $webshell_prefix = "BSOHAzPB"
        $webshell_key = "wSLjN1beuR"
        $php_target1 = "apm_css.php3"
        $php_target2 = "full_wt.php3"
        $php_target3 = "webtop_popup_css.php3"
        $proc_maps = "/proc/self/maps"
        $proc_exe = "/proc/self/exe"
        $apr_hook = "apr_dso_load"
        $apr_time = "apr_time_now"
        $libc_hook = "__libc_start_main"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($rc4_key and $socket_path) or
            ($auth_token and $webshell_prefix) or
            ($webshell_key and any of ($php_target*)) or
            (3 of ($rc4_key, $socket_path, $auth_token, $webshell_prefix, $webshell_key)) or
            (all of ($apr_*) and $proc_maps and any of ($php_target*)) or
            ($proc_exe and $libc_hook and any of ($apr_*))
        )
}
```

> ELF-only rule. Strings may be RC4-encrypted in the binary; consider scanning process memory dumps where strings are decrypted.

<!-- audit: yarac poisonedrefresh.yar /dev/null: exit 0. yara poisonedrefresh.yar test_positive.bin: matched PoisonedRefresh_Rootkit_Strings. yara poisonedrefresh.yar test_negative.bin: no match. -->

---

#### Rule 7: PoisonedRefresh PHP Web Shell Payload

Detects the injected PHP web shell payload based on the magic prefix and cipher key combination, applicable to memory dumps where the web shell is decrypted.

**Status**: compiled (yarac exit 0) | confidence: high

```yara
rule PoisonedRefresh_PHP_Webshell
{
    meta:
        description = "Detects PoisonedRefresh PHP web shell payload injected into BIG-IP APM PHP scripts in memory"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        severity = "critical"

    strings:
        $magic = "BSOHAzPB"
        $cipher_key = "wSLjN1beuR"
        $php_input = "php://input"
        $eval = "eval("
        $css_type = "text/css; charset=utf-8"
        $status_201 = "201"

    condition:
        $magic and $cipher_key and
        (
            $php_input or
            ($eval and $css_type) or
            ($status_201 and $css_type)
        )
}
```

> Best applied to Apache process memory dumps; the web shell never exists on disk.

<!-- audit: yarac poisonedrefresh.yar /dev/null: exit 0. -->

---

#### Rule 8: PoisonedRefresh Installer Component

Detects the installer component that infects httpd and BIG-IP install media.

**Status**: compiled (yarac exit 0) | confidence: high

```yara
rule PoisonedRefresh_Installer
{
    meta:
        description = "Detects PoisonedRefresh installer component that infects httpd and install media on F5 BIG-IP APM"
        author = "Actioner"
        date = "2026-09-11"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        severity = "critical"

    strings:
        $target_httpd = "/usr/sbin/httpd"
        $install_path = "/mnt/tm_install"
        $socket_path = "/run/bigtlog.pipe"
        $rc_local = "rc.local"
        $selinux = "SELINUX"
        $bigstart = "bigstart"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        $target_httpd and $install_path and
        2 of ($socket_path, $rc_local, $selinux, $bigstart)
}
```

> Targets the installer/propagation ELF binary, not the injected web shell.

<!-- audit: yarac poisonedrefresh.yar /dev/null: exit 0. -->

---

### Suricata Rules

#### Rule 9: POST to BIG-IP APM php3 Web Shell Endpoint

Detects POST requests to the three PHP3 endpoints targeted by PoisonedRefresh for web shell command delivery.

**Status**: compiled (suricata -T exit 0) | confidence: high

```
alert http any any -> any any (msg:"MALWARE PoisonedRefresh POST to BIG-IP APM php3 webshell endpoint"; flow:to_server,established; http.method; content:"POST"; http.uri; content:".php3"; pcre:"/\/(apm_css|full_wt|webtop_popup_css)\.php3/"; classtype:web-application-attack; sid:2026091101; rev:1; metadata:created_at 2026_09_11, updated_at 2026_09_11;)
```

> Legitimate GETs to these endpoints occur during normal BIG-IP APM webtop use; rule targets POST specifically.

<!-- audit: suricata -T -S poisonedrefresh.rules -l /tmp/actioner/: exit 0, "Configuration provided was successfully loaded." -->

---

#### Rule 10: HTTP 201 CSS Response with Web Shell Signature

Detects HTTP 201 responses containing the PoisonedRefresh web shell magic prefix bytes in the response body with CSS content type.

**Status**: compiled (suricata -T exit 0) | confidence: critical

```
alert http any any -> any any (msg:"MALWARE PoisonedRefresh HTTP 201 CSS response from php3 endpoint (web shell camouflage)"; flow:to_client,established; http.stat_code; content:"201"; http.content_type; content:"text/css"; http.response_body; content:"|42 53 4f 48 41 7a 50 42|"; classtype:web-application-attack; sid:2026091102; rev:1; metadata:created_at 2026_09_11, updated_at 2026_09_11;)
```

> Hex content `|42 53 4f 48 41 7a 50 42|` is ASCII for "BSOHAzPB"; requires response body inspection enabled.

<!-- audit: suricata -T -S poisonedrefresh.rules -l /tmp/actioner/: exit 0. -->

---

#### Rule 11: Web Shell Magic Prefix in Request Body

Detects the PoisonedRefresh web shell magic prefix (`BSOHAzPB`) in the first 16 bytes of an HTTP POST request body.

**Status**: compiled (suricata -T exit 0) | confidence: critical

```
alert http any any -> any any (msg:"MALWARE PoisonedRefresh web shell magic prefix in HTTP request body"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"BSOHAzPB"; depth:16; classtype:web-application-attack; sid:2026091103; rev:1; metadata:created_at 2026_09_11, updated_at 2026_09_11;)
```

> Highly specific -- the 8-byte magic prefix at the start of request bodies is distinctive to PoisonedRefresh.

<!-- audit: suricata -T -S poisonedrefresh.rules -l /tmp/actioner/: exit 0. -->

## Sources

- [SophosLabs - Dissecting a PHP Web Server Rootkit](https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit) -- Primary technical analysis (September 7-8, 2026)
- [Security Affairs - PoisonedRefresh Fileless Linux Rootkit](https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html) -- Secondary reporting (September 9, 2026)
- [The Hacker News - F5 BIG-IP APM Malware Injects PHP Web Shells](https://thehackernews.com/2026/09/f5-big-ip-apm-malware-injects-php-web.html) -- Secondary reporting (September 2026)
- [BleepingComputer - Hackers Breach F5 BIG-IP APM Devices](https://www.bleepingcomputer.com/news/security/hackers-breach-f5-big-ip-apm-devices-to-deploy-linux-rootkit/) -- Additional coverage
- [F5 - K000156741: BIG-IP APM Vulnerability CVE-2025-53521](https://my.f5.com/manage/s/article/K000156741) -- Vendor advisory
- [CISA KEV - CVE-2025-53521](https://thehackernews.com/2026/03/cisa-adds-cve-2025-53521-to-kev-after.html) -- CISA Known Exploited Vulnerabilities addition (March 27, 2026)
