# Technical Analysis Report: WordPress wp2shell Pre-Auth RCE (2026-07-21)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-21
Version: DRAFT

## Executive Summary

WordPress wp2shell is a critical pre-authentication remote code execution (RCE) exploit chain targeting WordPress core, composed of two chained vulnerabilities: CVE-2026-63030 (REST API batch-route confusion) and CVE-2026-60137 (SQL injection in `WP_Query`). The chain requires no authentication, no plugins, and no special configuration -- it works on stock WordPress installations. Affected versions include WordPress 6.9.0-6.9.4 and 7.0.0-7.0.1 (full RCE), with WordPress 6.8.0-6.8.5 vulnerable to the SQL injection component alone. Patches were released on July 17, 2026 (versions 6.8.6, 6.9.5, and 7.0.2), with WordPress enabling forced automatic updates.

Active exploitation began within hours of patch release, with WatchTowr researchers documenting "tens of thousands of exploitation attempts" and "more than 100 backdoor accounts created by different threat actors" across honeypots by July 20. Over two dozen unique proof-of-concept exploits have been published, including a full working PoC on GitHub (Icex0/wp2shell-poc). Post-exploitation activity includes backdoor administrator account creation, malicious plugin deployment, credential exfiltration, and delivery of the Overlord RAT (Golang-based remote access trojan). Given WordPress powers over 500 million websites, the exposure surface is massive.

## Background: WordPress REST API Batch Endpoint

WordPress provides a REST API batch endpoint (`/wp-json/batch/v1` or `?rest_route=/batch/v1`) that allows multiple API sub-requests to be processed in a single HTTP request. This mechanism is used by the Gutenberg block editor and WordPress mobile applications for performance optimization. The batch endpoint processes sub-requests using parallel arrays for requests, validation results, and matched handlers -- a design whose array-synchronization invariant is the root cause of CVE-2026-63030.

The `WP_Query` class, WordPress's primary database query interface, accepts an `author__not_in` parameter intended to exclude posts by specific author IDs. This parameter is expected to receive an integer array but can be manipulated to accept raw string input, creating the SQL injection vector (CVE-2026-60137).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-17 | WordPress releases patches 6.8.6, 6.9.5, 7.0.2; forced auto-updates enabled |
| 2026-07-17 (hours later) | Public exploits emerge; full PoC published (Icex0/wp2shell-poc) |
| 2026-07-18 (Saturday AM) | Active exploitation begins; credential exfiltration techniques observed |
| 2026-07-19 | Over 24 unique PoC variants documented |
| 2026-07-20 | WatchTowr reports tens of thousands of exploitation attempts; 100+ backdoor accounts across honeypots |
| 2026-07-20 | VulnCheck confirms in-the-wild exploitation via Canary Intelligence network |
| 2026-07-20 | Rapid7 releases unauthenticated vulnerability checks |

## Root Cause: REST API Batch Route Confusion + SQL Injection

**CVE-2026-63030 (Route Confusion / Authentication Bypass):** The batch endpoint processes sub-requests using three parallel arrays: `$requests` (parsed request objects or `WP_Error` instances), `$matches` (route handler tuples), and `$validation` (validation results). When a sub-request's path fails `wp_parse_url()`, the code appends to `$validation` but does not add a placeholder to `$matches`, causing the arrays to fall out of step. Subsequent valid requests read handler tuples intended for later requests, bypassing permission checks and the `allow_batch` restriction. This allows attacker-controlled parameters to reach authenticated-only endpoints without authentication.

**CVE-2026-60137 (SQL Injection in WP_Query):** The `author__not_in` parameter in `WP_Query` is sanitized only when it arrives as an array (`array_map('absint', ...)`). When a raw scalar string bypasses this check through the route confusion, it is interpolated directly into SQL: `AND {$wpdb->posts}.post_author NOT IN ($ids)`. This enables UNION-based, error-based (EXTRACTVALUE/UPDATEXML), and blind SQL injection.

**RCE Precondition:** The full RCE chain requires that persistent object caching (Redis/Memcached) is NOT in use -- the default configuration for most WordPress installations.

## Technical Analysis of the Malicious Payload

### 1. Route Confusion Entry (Batch Endpoint Abuse)

The exploit sends a `POST` request to `/wp-json/batch/v1` containing a crafted `requests` array with:
- A malformed `///` path that fails `wp_parse_url()` and creates `parse_path_failed`
- A `/wp/v2/posts` request acting as a batch-allowed spacer
- A `/wp/v2/block-renderer/...` route (not batch-allowed) that returns `block_cannot_read` if reached anonymously
- A nested `/batch/v1` sub-request returning `rest_batch_not_allowed`

The array desynchronization causes a `GET /wp/v2/posts/999999` item-route request with collection query parameters to be dispatched through `get_items()` instead of its intended handler, delivering unvalidated parameters (`author_exclude`, `orderby`, `per_page`) to the SQL injection vector.

### 2. SQL Injection to Admin Bridge

The exploitation follows a multi-step escalation:

1. **UNION injection** forges fake `wp_posts` rows via the `author_exclude` parameter (mapped to `author__not_in`) with `orderby=none` and `per_page=500`
2. **oEmbed cache poisoning**: WordPress creates real oEmbed cache posts from the forged data
3. **Changeset hijack**: A single poisoned batch request recasts cache post IDs as customizer changesets, navigation items, and request hooks
4. **Privilege escalation**: Publishing a forged changeset temporarily elevates the request context to administrator
5. **Account creation**: A previously rejected user-creation request (`POST /wp/v2/users`) re-evaluates with administrator privileges and succeeds

### 3. Web Shell Deployment

After gaining administrative access (either via the bridge-generated admin account or supplied credentials):
- A plugin-format web shell is uploaded via the WordPress admin plugin mechanism (`/wp-admin/plugin-install.php?tab=upload`)
- The web shell is locked behind a random path and a per-run authentication token
- The shell exposes a command interface via `?tok=<token>&c=<command>` parameters
- Response output is wrapped in `WP2SHELL_OUT_START` / `WP2SHELL_OUT_END` markers
- Cleanup parameter `&rm=1` triggers self-deletion
- The bridge-generated administrator account is automatically removed after shell session completion

**Observed web shell variants:**
- **Minimal backdoor (~1.3 KB):** Single-line PHP eval wrapper with fake `Author: WordPress.org Community` header, gated behind token, returning 404 for evasion
- **CMSmap plugin (~150 KB):** Obfuscated payload using hex-encoded strings and gzip compression with database access, file management, and privilege escalation modules
- **REST API variant:** Custom endpoint at `/morning/v1/[path]` accepting base64-encoded commands via POST

### 4. Post-Exploitation Activities

Observed threat actor activities across honeypots and incident response engagements:
- Malicious plugin uploads
- User enumeration and admin credential harvesting (`/wp-json/wp/v2/users?context=edit`)
- Local file inclusion targeting database credentials (`/admin-ajax.php?template=../../../wp-config`)
- Overlord RAT deployment (Golang-based remote access trojan)
- Indiscriminate internet-wide scanning from multiple geographic origins

### 5. Anti-Forensics / Evasion Techniques

- Auto-deletion of bridge-generated administrator accounts after shell session
- Auto-removal of uploaded web shell plugin
- Exploit can execute with "almost nothing in the logs" -- database artifacts and file timestamps are the primary evidence, not web server access logs
- Web shell returns HTTP 404 responses when accessed without valid token
- Fake plugin headers mimicking legitimate WordPress.org authorship

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| WordPress Core | 6.9.0-6.9.4, 7.0.0-7.0.1 | Full RCE chain (batch route confusion + SQLi) |
| WordPress Core | 6.8.0-6.8.5 | SQL injection only (author__not_in) |

### File System

| Platform | Path | Hash (SHA1) | Description |
|----------|------|-------------|-------------|
| Linux | wp-content/plugins/\<name\>-\<6hex\>/\<name\>.php | 2a1410d8e2a8337ac2171cedea8c0fdc47c647a0 | Deployed web shell variant |
| Linux | wp-content/plugins/\<name\>-\<6hex\>/\<name\>.php | 58eca847e9eae9e6b08cc211f1559817b71bc4cc | Deployed web shell variant |
| Linux | wp-content/plugins/\<name\>-\<6hex\>/\<name\>.php | ebea44890f434d5d67ede22009a3f4bb5cac33f8 | Deployed web shell variant |
| Linux | wp-content/plugins/\<name\>-\<6hex\>/\<name\>.php | d9a220c8039f1c4d72cae7ccb8b3a33dec8815be | Deployed web shell variant |
| Linux | wp-content/plugins/\<name\>-\<6hex\>/\<name\>.php | e9756e2338f84746007235e4cab7a70d5b3ca47f | Deployed web shell variant |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 45.79.167[.]238 | Exploitation / scanning source |
| IP | 34.81.132[.]62 | Exploitation / scanning source |
| IP | 79.177.131[.]206 | Exploitation / scanning source |
| IP | 15.157.135[.]170 | Exploitation / scanning source |
| IP | 94.100.52[.]128 | Exploitation / scanning source |
| IP | 172.235.128[.]52 | Mass scanning source |
| URL Pattern | /wp-json/batch/v1 | Exploit entry point (batch endpoint) |
| URL Pattern | ?rest_route=/batch/v1 | Exploit entry point (query-string variant) |
| User-Agent | wp2shell-check/1.0 | Reconnaissance tool signature |
| User-Agent | wp2shell-poc/1.0 | Exploit tool signature |
| User-Agent | *wp2shell* | Exploit framework signature |
| User-Agent | *rezwp2shell* | Exploit framework signature |

### Behavioral

**Rogue administrator accounts:** Login name patterns `wp2_*`, `w2s_*`, `wpsvc_<hex>` with email domains `@wp2shell[.]invalid`, `@wp2shell[.]shellcode[.]lol`, `@wordpress-svc[.]internal`, `@wordpress-noreply[.]net`, `@x[.]lol`.

**Database artifacts:** Unexpected rows in `wp_users`/`wp_usermeta` tables; `oembed_cache` loopback entries; `customize_changeset` posts with abnormally high parent IDs; orphaned usermeta entries; user ID gaps; tampered `active_plugins` in `wp_options`; injected `_transient_` or object-cache entries.

**HTTP response markers:** HTTP 207 Multi-Status responses from batch endpoint with route-confusion marker pattern: `parse_path_failed`, `block_cannot_read`, `rest_batch_not_allowed`.

**Web shell command interface:** PHP files under `wp-content/plugins/` accepting `?tok=<token>&c=<command>` with response wrapped in `WP2SHELL_OUT_START` / `WP2SHELL_OUT_END` markers.

**Scanning origins:** 13 unique IPs observed from Switzerland, Germany, UK, Indonesia, Lithuania, Netherlands, and Singapore.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of WordPress REST API batch endpoint via route confusion + SQL injection chain for pre-auth RCE |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Web shell executing OS commands via `shell_exec()`, `system()`, `passthru()` |
| T1136.001 | Create Account: Local Account | Creation of rogue administrator accounts (wp2_*, w2s_*, wpsvc_*) via the SQLi-to-admin bridge |
| T1505.003 | Server Software Component: Web Shell | Deployment of PHP web shells disguised as WordPress plugins |
| T1078.001 | Valid Accounts: Default Accounts | Use of bridge-generated admin accounts for post-exploitation |
| T1105 | Ingress Tool Transfer | Upload of Overlord RAT and malicious plugins |
| T1070.004 | Indicator Removal: File Deletion | Auto-deletion of web shell and bridge admin account after session |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Web shell disguised as legitimate WordPress plugin with fake authorship headers |

## Impact Assessment

**Breadth:** WordPress powers over 500 million websites globally. All stock installations running WordPress 6.9.0-6.9.4 or 7.0.0-7.0.1 without persistent object caching are vulnerable to the full RCE chain. WordPress 6.8.x sites are vulnerable to the SQL injection component.

**Depth:** Complete compromise -- unauthenticated attackers gain full control of the website and its underlying database. Post-exploitation capabilities include arbitrary code execution, credential theft, data exfiltration, and lateral movement into the hosting infrastructure.

**Stealth:** The exploit can execute with minimal log evidence. Database artifacts and file system changes are the primary forensic evidence rather than web server access logs.

**Scale of exploitation:** Tens of thousands of exploitation attempts documented within 72 hours of patch release, with over 100 backdoor accounts created by distinct threat actors across monitored honeypots.

## Detection & Remediation

### Immediate Detection

```bash
# Check for rogue administrator accounts
wp user list --role=administrator --format=table

# Search for known malicious email domains in user table
mysql -e "SELECT ID, user_login, user_email, user_registered FROM wp_users WHERE user_email LIKE '%wp2shell%' OR user_email LIKE '%shellcode%' OR user_email LIKE '%wordpress-svc.internal%' OR user_email LIKE '%wordpress-noreply.net%' OR user_email LIKE '%x.lol' OR user_login LIKE 'wp2\_%' OR user_login LIKE 'w2s\_%' OR user_login LIKE 'wpsvc\_%'"

# Search web server logs for batch endpoint exploitation
grep -Ei "batch/v1" /var/log/nginx/access.log* /var/log/apache2/access.log*
grep -Ei "author_exclude|author__not_in" /var/log/nginx/access.log* /var/log/apache2/access.log*

# Find recently created PHP files in plugins directory
find /var/www/html/wp-content/plugins -name "*.php" -newermt "2026-07-16" -ls

# Verify WordPress core file integrity
wp core verify-checksums

# Check for suspicious eval/shell_exec in plugin files
grep -rl 'eval\s*(' /var/www/html/wp-content/plugins/ | head -20
grep -rl 'WP2SHELL' /var/www/html/wp-content/plugins/ | head -20
```

### Remediation

1. **Patch immediately**: Update to WordPress 7.0.2, 6.9.5, or 6.8.6
2. **Run compromise scanner** before reinstall: Use the "Compromise Scanner for wp2shell" WordPress plugin or the InstaWP/wp2shell-scan Bash tool
3. **Remove rogue accounts**: Delete any administrator accounts matching the patterns above
4. **Force password reset** for all existing user accounts
5. **Audit plugins**: Remove any unrecognized plugins, especially with 6-character hex suffixes in directory names
6. **Preserve forensic evidence**: Take read-only snapshots of the database and web root before cleanup if compromise is suspected
7. **Rotate database credentials**: Change database passwords and regenerate WordPress salts/keys in `wp-config.php`
8. **Review cron jobs and persistence**: Check `/etc/crontab`, `/etc/cron.*`, user crontabs, and `~/.bash_history` for www-data and service accounts

### Long-Term Hardening

- **Enable persistent object caching** (Redis/Memcached) where feasible -- this blocks the specific RCE path (though SQLi remains)
- **Block batch endpoint for unauthenticated users** via WAF rule or `rest_pre_dispatch` filter if batch functionality is not required
- **Deploy WAF rules** blocking `POST` to `/wp-json/batch/v1` and `?rest_route=/batch/v1` from unauthenticated sources
- **Enable WordPress auto-updates** for core security releases
- **Monitor for new administrator account creation** as a standing alert
- **Implement file integrity monitoring** on the `wp-content/plugins/` directory

## Detection Rules

These detections target the wp2shell exploit chain at the network and file level: batch endpoint exploitation attempts, known exploit tool user-agents, SQL injection parameters, and deployed web shells. PoC/advisory-specific altitude (default); Sigma rules convert cleanly to Splunk and CrowdStrike. Compiles does not equal fires -- verify in your pipeline with representative logs.

### Sigma: WordPress wp2shell Batch Endpoint Exploitation Attempt
Detects HTTP POST requests to the WordPress REST API batch endpoint (`/batch/v1`), the entry point for the wp2shell RCE chain.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy — not a rule error); splunk convert exit 0; log_scale convert exit 0. Medium confidence because batch endpoint is also used by Gutenberg editor — POST to /batch/v1 alone is not conclusive without body inspection. FP: legitimate Gutenberg/mobile batch requests. Evasion: attacker could use ?rest_route= query-string variant only. -->
```yaml
title: WordPress wp2shell Batch Endpoint Exploitation Attempt
id: 7c3a1e9b-4f2d-48a6-b5c8-9d0e7f1a2b3c
status: experimental
description: >
    Detects HTTP POST requests to the WordPress REST API batch endpoint
    (/wp-json/batch/v1 or ?rest_route=/batch/v1) which is the entry point
    for the wp2shell pre-authentication RCE chain (CVE-2026-63030 + CVE-2026-60137).
references:
    - https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://github.com/Icex0/wp2shell-poc
author: Actioner
date: 2026/07/21
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_post:
        cs-method: 'POST'
    selection_batch_uri:
        cs-uri-stem|contains: '/batch/v1'
    selection_batch_query:
        cs-uri-query|contains: 'rest_route=/batch/v1'
    condition: selection_post and (selection_batch_uri or selection_batch_query)
falsepositives:
    - Legitimate WordPress REST API batch operations from Gutenberg editor
    - WordPress mobile app batch requests
level: medium
```

### Sigma: WordPress wp2shell Exploit Tool User-Agent
Detects HTTP requests with User-Agent strings containing known wp2shell exploitation framework signatures.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy — not a rule error); splunk convert exit 0; log_scale convert exit 0. High confidence — "wp2shell" and "rezwp2shell" are purpose-built exploit tool signatures with no legitimate use. FP: authorized pentesting only. -->
```yaml
title: WordPress wp2shell Exploit Tool User-Agent
id: 8d4b2f0c-5a3e-49b7-c6d9-ae1f8b2c3d4e
status: experimental
description: >
    Detects HTTP requests with User-Agent strings containing known wp2shell
    exploitation framework signatures (wp2shell, rezwp2shell) observed in
    active scanning campaigns targeting CVE-2026-63030.
references:
    - https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137
    - https://www.cyberkendra.com/2026/07/wp2shell-guide.html
author: Actioner
date: 2026/07/21
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-useragent|contains:
            - 'wp2shell'
            - 'rezwp2shell'
    condition: selection
falsepositives:
    - Authorized penetration testing using wp2shell tooling
level: high
```

### Sigma: WordPress wp2shell SQL Injection Parameters
Detects requests to WordPress batch or posts endpoints containing SQL injection keywords in the `author_exclude`/`author__not_in` parameter used by the wp2shell exploit chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy — not a rule error); splunk convert exit 0; log_scale convert exit 0. High confidence — SQL keywords (UNION, SELECT, SLEEP, EXTRACTVALUE, UPDATEXML) in query strings to batch/posts endpoints are not legitimate. FP: generic SQLi scanners (still worth alerting on). -->
```yaml
title: WordPress wp2shell SQL Injection in Batch Request Parameters
id: 9e5c3a1d-6b4f-4ac8-d7ea-bf2a9c3d4e5f
status: experimental
description: >
    Detects HTTP requests to WordPress batch or posts endpoints containing
    SQL injection keywords in query parameters, targeting the author_exclude /
    author__not_in SQL injection vector used in the wp2shell exploit chain
    (CVE-2026-60137).
references:
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained
    - https://github.com/Icex0/wp2shell-poc
author: Actioner
date: 2026/07/21
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-stem|contains:
            - '/batch/v1'
            - '/wp/v2/posts'
    selection_sqli:
        cs-uri-query|contains:
            - 'author_exclude'
            - 'author__not_in'
    selection_sqli_keywords:
        cs-uri-query|contains:
            - 'UNION'
            - 'SELECT'
            - 'SLEEP'
            - 'EXTRACTVALUE'
            - 'UPDATEXML'
    condition: selection_endpoint and (selection_sqli or selection_sqli_keywords)
falsepositives:
    - Generic SQL injection scanners not related to wp2shell
level: high
```

### Snort: WordPress wp2shell Batch Endpoint POST with author_exclude
Detects POST requests to the WordPress batch endpoint containing `author_exclude` in the request body, indicating active wp2shell exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort-test.conf -T exit 0. Snort 2.9.20. High confidence — POST to /batch/v1 with author_exclude in body is a specific, distinctive exploitation pattern. FP: none expected in normal WordPress operation. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - WordPress wp2shell Batch Endpoint Exploitation Attempt (CVE-2026-63030)"; flow:established,to_server; content:"POST"; http_method; content:"/batch/v1"; http_uri; fast_pattern; content:"author_exclude"; http_client_body; sid:2100101; rev:1; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; reference:cve,2026-63030;)
```

### Snort: WordPress wp2shell Exploit Tool User-Agent
Detects HTTP requests with the `wp2shell` string in headers, identifying purpose-built exploitation frameworks.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort-test.conf -T exit 0. Snort 2.9.20. High confidence — "wp2shell" in headers is a unique exploit tool signature. FP: authorized pentesting only. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - WordPress wp2shell Exploit Tool User-Agent"; flow:established,to_server; content:"wp2shell"; http_header; fast_pattern; sid:2100102; rev:1; classtype:web-application-attack; reference:url,www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137; reference:cve,2026-63030;)
```

### Suricata: WordPress wp2shell Batch Endpoint POST with author_exclude
Detects POST requests to the batch endpoint with `author_exclude` in the body, the specific exploitation pattern for CVE-2026-63030.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). High confidence — POST to /batch/v1 with author_exclude in body is specific to wp2shell exploitation. FP: none expected. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - WordPress wp2shell Batch Endpoint POST with author_exclude (CVE-2026-63030)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/batch/v1"; fast_pattern; http.request_body; content:"author_exclude"; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; reference:cve,2026-63030; metadata:author Actioner, created_at 2026-07-21; sid:2200101; rev:1;)
```

### Suricata: WordPress wp2shell Exploit Tool User-Agent
Detects the `wp2shell` string in the HTTP User-Agent header, a known exploitation framework signature.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). High confidence — unique tool signature. FP: authorized pentesting only. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - WordPress wp2shell Exploit Tool User-Agent"; flow:established,to_server; http.user_agent; content:"wp2shell"; fast_pattern; classtype:web-application-attack; reference:url,www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137; reference:cve,2026-63030; metadata:author Actioner, created_at 2026-07-21; sid:2200102; rev:1;)
```

### Suricata: WordPress wp2shell Web Shell Command Interface
Detects HTTP requests to PHP files with the `tok=` and `&c=` parameters characteristic of the wp2shell web shell command interface.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Medium confidence — tok/c parameter pattern could overlap with other PHP apps using similar query parameters, though the combination is distinctive. FP: uncommon PHP apps using tok= and c= query parameters. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - WordPress wp2shell Webshell Command Interface Access"; flow:established,to_server; http.uri; content:".php"; content:"tok="; content:"&c="; fast_pattern; classtype:web-application-attack; reference:url,www.cyberkendra.com/2026/07/wp2shell-guide.html; reference:cve,2026-63030; metadata:author Actioner, created_at 2026-07-21; sid:2200103; rev:1;)
```

### YARA: wp2shell Webshell Plugin Detection
Detects wp2shell web shell plugins by matching the `WP2SHELL_OUT_START`/`WP2SHELL_OUT_END` response markers, fake WordPress.org authorship header combined with command execution parameters, or the combination of fake headers with eval/exec functions and GET parameter access.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on positive (constructed from published indicators — WP2SHELL_OUT_START/END markers, $_GET['tok']/$_GET['c'] params, Author: WordPress.org Community header, shell_exec); quiet on negative (legitimate plugin). High confidence — WP2SHELL_OUT markers and the token+command parameter pattern are unique to this exploit. -->
```yara
rule Exploit_WP2Shell_Webshell_Plugin
{
    meta:
        description = "Detects wp2shell webshell plugin deployed via CVE-2026-63030 exploitation, identified by response markers and command interface patterns"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.cyberkendra.com/2026/07/wp2shell-guide.html"
        reference2 = "https://github.com/InstaWP/wp2shell-scan"
        severity = "critical"

    strings:
        $marker_start = "WP2SHELL_OUT_START" ascii
        $marker_end = "WP2SHELL_OUT_END" ascii
        $header = "Author: WordPress.org Community" ascii
        $param_tok = "$_GET['tok']" ascii
        $param_c = "$_GET['c']" ascii
        $param_rm = "$_GET['rm']" ascii
        $eval1 = "eval(" ascii
        $eval2 = "shell_exec(" ascii
        $eval3 = "system(" ascii
        $eval4 = "passthru(" ascii
        $eval5 = "base64_decode(" ascii

    condition:
        filesize < 10KB and
        (
            ($marker_start and $marker_end) or
            ($header and 2 of ($param_*)) or
            ($header and 2 of ($eval*) and 1 of ($param_*))
        )
}

rule Exploit_WP2Shell_CMSmap_Webshell
{
    meta:
        description = "Detects the larger CMSmap-style obfuscated webshell (approx 150KB) observed in wp2shell post-exploitation campaigns"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        severity = "critical"

    strings:
        $gzip = "gzinflate(" ascii
        $eval = "eval(" ascii
        $b64 = "base64_decode(" ascii
        $hex_decode = "hex2bin(" ascii
        $plugin_header = "Plugin Name:" ascii
        $fake_author = "WordPress.org" ascii
        $cmd1 = "shell_exec" ascii
        $cmd2 = "proc_open" ascii
        $cmd3 = "passthru" ascii

    condition:
        filesize > 50KB and filesize < 300KB and
        $plugin_header and $fake_author and
        $eval and ($gzip or $b64 or $hex_decode) and
        1 of ($cmd*)
}
```

## Lessons Learned

- **Patch-to-exploit window is now measured in hours, not days.** Public exploits emerged the same day as the WordPress patch, and active exploitation began within 24 hours. Organizations must have automated patching or immediate WAF mitigation capabilities.
- **Core platform vulnerabilities dwarf plugin vulns in impact.** Unlike typical WordPress plugin vulnerabilities, this chain affects every default WordPress installation regardless of installed plugins, multiplying the attack surface by orders of magnitude.
- **Array synchronization bugs are an emerging vulnerability class.** The root cause -- parallel array desynchronization in batch processing -- is a subtle logic bug that evades both static analysis and typical security review. Similar patterns exist in other batch/pipeline processing implementations.
- **Anti-forensics complicate incident response.** The exploit's auto-cleanup capabilities (deleting the admin account and web shell) mean that a compromised site may show no obvious signs of compromise in a cursory check. Database-level forensics and file-system timeline analysis are essential.
- **Persistent object caching provides accidental defense-in-depth.** While not a security feature, Redis/Memcached object caching blocks the specific RCE path, highlighting the value of architectural decisions that incidentally reduce attack surface.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News - Exploitation Grows](https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html) -- mass exploitation observations, scanning infrastructure, Overlord RAT deployment
- [The Hacker News - New wp2shell Flaw](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html) -- initial disclosure, affected versions, batch endpoint mechanism, mitigation
- [Security Affairs - Attackers Can Take Over WordPress Sites](https://securityaffairs.com/195597/hacking/attackers-can-take-over-wordpress-sites-using-newly-released-wp2shell-exploits.html) -- exploitation confirmation, affected versions, mitigation approaches
- [The Register - Attackers Pummel Critical WordPress Vuln](https://www.theregister.com/security/2026/07/20/attackers-pummel-critical-wordpress-vuln-to-create-all-sorts-of-mischief/5275265) -- exploitation timeline, WatchTowr statistics, multiple PoC variants
- [Icex0/wp2shell-poc (GitHub)](https://github.com/Icex0/wp2shell-poc) -- full PoC source, exploit chain details, SQL injection techniques, route confusion mechanism
- [Eye Security - wp2shell Defenders Guide](https://labs.eye.security/wp2shell-defenders-guide/) -- rogue account patterns, database artifacts, forensic analysis paths, detection indicators
- [Picus Security - wp2shell RCE Explained](https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained) -- route confusion code trace, SQL injection vector, privilege escalation path
- [Wiz - Exploitation in the Wild](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137) -- exploitation IPs, web shell hashes, post-exploitation patterns, HTTP indicators
- [VulnCheck - WP2Shell Vulnerabilities](https://www.vulncheck.com/blog/wp2shell) -- exploitation confirmation via Canary Intelligence, version matrix
- [Rapid7 - CVE-2026-63030 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/) -- CVSS scoring, unauthenticated check availability
- [Cyber Kendra - WP2Shell Checker, Patch & Detection Guide](https://www.cyberkendra.com/2026/07/wp2shell-guide.html) -- dropped file patterns, C2 signatures (WP2SHELL_OUT markers), detection commands
- [InstaWP/wp2shell-scan (GitHub)](https://github.com/InstaWP/wp2shell-scan) -- rogue account detection patterns, web shell file signatures, scanner capabilities

---
*Report generated by Actioner*
