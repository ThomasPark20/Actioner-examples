# Technical Analysis Report: WordPress wp2shell Core RCE — CVE-2026-63030 + CVE-2026-60137 (2026-07-18)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-18
Version: 1.1 (REVISED)

## Executive Summary

Two chained vulnerabilities in WordPress core — CVE-2026-63030 (REST API batch-route confusion) and CVE-2026-60137 (SQL injection via `author__not_in` parameter) — enable unauthenticated remote code execution on default WordPress installations with zero plugins required. The chain, dubbed "wp2shell," affects WordPress 6.9.0-6.9.4 and 7.0.0-7.0.1 (full RCE), with the SQL injection component alone affecting 6.8.0-6.8.5. Given WordPress powers over 500 million sites and versions 6.9+ have been available since December 2, 2025, the exposed attack surface is massive. Patches were released on July 17-18, 2026 (WordPress 6.8.6, 6.9.5, 7.0.2), and a public PoC appeared on GitHub within one day of the patch. Sites using persistent object caching (Redis/Memcached) may avoid the RCE path but remain vulnerable to SQL injection.

## Background: WordPress REST API Batch Processing + WP_Query

WordPress exposes a REST API batch endpoint at `/wp-json/batch/v1` that processes multiple sub-requests in a single HTTP call. The batch endpoint accepts parallel arrays of requests that are processed sequentially. `WP_Query` is WordPress's core database query class, and its `author__not_in` parameter is designed to accept an array of author IDs to exclude from query results. The vulnerability arises because passing a string instead of the expected array bypasses the validation that normally sanitizes these values before they reach the SQL query builder.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-17/18 | WordPress releases 6.8.6, 6.9.5, 7.0.2 security patches |
| 2026-07-18 | Exploitation mechanism publicly documented; public PoC on GitHub |
| 2026-07-18 | The Hacker News publishes advisory article |

## Root Cause: Batch Array Misalignment + Unsanitized author__not_in String Injection

### CVE-2026-63030: REST API Batch-Route Confusion

The `/wp-json/batch/v1` endpoint processes multiple sub-requests using parallel arrays. When one sub-request deliberately triggers an error, the resulting exception handling misaligns the arrays by one position. This causes subsequent requests to execute under different endpoint handlers than intended, effectively bypassing endpoint allowlists and authentication checks.

### CVE-2026-60137: SQL Injection in WP_Query author__not_in

The `author__not_in` parameter in `WP_Query` expects an array of integer author IDs. When a string is passed instead of an array, the type-checking validation is bypassed, and the raw string value is interpolated directly into the SQL query. Combined with the batch-route confusion to bypass authentication, this allows an unauthenticated attacker to inject arbitrary SQL and achieve code execution.

## Technical Analysis of the Exploitation Chain

### 1. Initial Access — Batch Endpoint Request

The attacker sends a POST request to the batch endpoint:
```
POST /wp-json/batch/v1 HTTP/1.1
Host: <target>
Content-Type: application/json

{
  "requests": [
    {"path": "/wp/v2/invalid-endpoint-to-trigger-error", ...},
    {"path": "/wp/v2/posts", "body": {"author__not_in": "<SQL_PAYLOAD>"}}
  ]
}
```

The first sub-request is deliberately malformed to trigger the array misalignment (CVE-2026-63030). The second sub-request carries the SQL injection payload in `author__not_in` as a string rather than an array (CVE-2026-60137).

### 2. SQL Injection Payload Characteristics

The `author__not_in` parameter receives a string containing SQL that escapes the integer context:
- Closes the current `NOT IN (...)` clause
- Appends arbitrary SQL (UNION SELECT, stacked queries)
- Leverages MySQL's `INTO OUTFILE` or similar to achieve RCE from SQLi

### 3. Alternative Delivery — Query String Variant

The batch endpoint is also reachable via the query-string REST API route:
```
POST /?rest_route=/batch/v1 HTTP/1.1
```
This variant bypasses `.htaccess` or reverse proxy rules that only block the `/wp-json/` path prefix.

### 4. Platform-Specific Behavior

- Sites with persistent object caching (Redis/Memcached) may avoid the RCE execution path because cached query results prevent the injected SQL from being executed in a context that allows file writes
- The SQL injection itself still works regardless of caching layer
- Default installations without any caching are fully exploitable

### 5. Anti-Forensics / Evasion Techniques

- Query-string variant (`rest_route=/batch/v1`) evades path-based WAF rules targeting `/wp-json/`
- JSON body encoding obscures the SQL payload from URL-based log inspection
- Batch processing creates a single log entry for multiple operations
- The error-triggering sub-request may be logged as a benign 404

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`, domains `[.]`, IPs `[.]`, emails `[at]`.

### Package / Software Level

| Package / Component | Affected Version | Description |
|---------------------|------------------|-------------|
| WordPress core (REST API batch + WP_Query) | 6.8.0-6.8.5 | SQL injection only (author__not_in); fixed in 6.8.6 |
| WordPress core (REST API batch + WP_Query) | 6.9.0-6.9.4 | Full RCE chain; fixed in 6.9.5 |
| WordPress core (REST API batch + WP_Query) | 7.0.0-7.0.1 | Full RCE chain; fixed in 7.0.2 |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/wp-json/batch/v1` | Primary batch endpoint (POST) |
| URL Pattern | `/?rest_route=/batch/v1` | Query-string variant of batch endpoint |
| Request Body Artifact | `author__not_in` as string (not array) in JSON body | SQLi injection point |
| Request Body Artifact | Multiple sub-requests with deliberately invalid first request | Array misalignment trigger |

### Behavioral

POST requests to `/wp-json/batch/v1` or `?rest_route=/batch/v1` containing JSON bodies with multiple sub-requests where one is deliberately malformed and another contains `author__not_in` as a string value (not an array). The string value in `author__not_in` will typically contain SQL syntax: parentheses, UNION, SELECT, INTO OUTFILE, or comment sequences (--). Successful exploitation may be followed by requests to a newly created web shell file.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated RCE against internet-facing WordPress REST API |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation command execution via injected web shell |
| T1505.003 | Server Software Component: Web Shell | RCE chain writes PHP web shell to filesystem via SQL INTO OUTFILE |

## Impact Assessment

**Breadth:** Massive — WordPress powers 500M+ installations; versions 6.9+ (available since Dec 2, 2025) expose the full RCE chain on default configurations. **Depth:** Critical — unauthenticated, zero-interaction RCE on bare installs with no plugins. **Stealth:** Moderate — the batch endpoint and JSON body make the attack less visible in URL-only logging, but distinctive artifacts (batch/v1 + author__not_in string) are detectable. **Urgency:** Extreme — public PoC available within one day of patch; mass exploitation expected.

## Detection & Remediation

### Immediate Detection

Search web/access logs and application logs for batch endpoint exploitation:
```
# Access logs — batch endpoint hits (unusual for most sites)
grep -E '(wp-json/batch/v1|rest_route=/batch/v1|rest_route=%2Fbatch%2Fv1)' access.log

# Application logs / POST body logs — SQLi indicator
grep -F 'author__not_in' /var/log/wordpress/*.log

# Look for web shells created after exploitation
find /var/www/ -name "*.php" -newer /var/www/wp-includes/version.php -mtime -7
```

### Remediation

1. **Update immediately** to WordPress 6.8.6, 6.9.5, or 7.0.2. This is the only definitive fix.
2. **WAF mitigation** (interim): Block POST requests to `/wp-json/batch/v1` and `rest_route=/batch/v1` at the WAF/reverse proxy level. Note: this may break legitimate plugins that use the batch API.
3. **Disable unauthenticated REST API access** if your site does not require public API access.
4. **Post-incident**: Search for newly created PHP files, check for unauthorized admin accounts, rotate all secrets (database credentials, salts, API keys), and review `wp_options` for injected content.

### Long-Term Hardening

- Enable persistent object caching (Redis/Memcached) to mitigate the RCE path (though SQLi remains)
- Restrict REST API access to authenticated users where possible
- Deploy WAF rules with JSON body inspection capability
- Monitor batch endpoint usage — most WordPress sites never use `/wp-json/batch/v1` legitimately

## Detection Rules

These detections target the WordPress wp2shell exploitation chain at the network and log level. They key on the distinctive combination of the `/wp-json/batch/v1` (or `rest_route=/batch/v1`) endpoint with `author__not_in` manipulation — artifacts specific to CVE-2026-63030 + CVE-2026-60137 rather than generic SQLi patterns. The batch endpoint is rarely used by legitimate clients on most WordPress installations, making the endpoint alone a useful signal; combined with the `author__not_in` string injection indicator, confidence is high. Verify field mappings (cs-uri-stem, cs-uri-query, cs-body) against your log schema before deploying.

### Sigma Rule 1: WordPress wp2shell Batch Endpoint RCE Exploitation (CVE-2026-63030 + CVE-2026-60137)
Detects requests to the WordPress batch endpoint combined with author__not_in parameter presence in the request body — the core exploitation signal.
**Status:** compile PASS (sigma check 0 issues; convert splunk PASS; convert log_scale PASS) | confidence: high
<!-- audit: sigma check 0 errors/0 issues (excluding attacktag/cvetag/d3_fendtag due to offline MITRE data). sigma convert --without-pipeline -t splunk: OK. sigma convert --without-pipeline -t log_scale: OK. cs-uri-stem|contains for /wp-json/batch/v1 path variant; cs-uri-query|contains for rest_route= query-string variant. author__not_in is in the JSON POST body so uses cs-body|contains. FP: legitimate batch API calls with author__not_in are uncommon. The endpoint alone is a signal on most sites. -->
```yaml
title: WordPress wp2shell Batch Endpoint RCE Exploitation (CVE-2026-63030 + CVE-2026-60137)
id: 8a3c7e1f-4d6b-4f92-b5e8-1c9a3d7f2e06
status: experimental
description: >
    Detects exploitation of the WordPress wp2shell RCE chain targeting
    /wp-json/batch/v1 (or rest_route=/batch/v1). The attack chains
    CVE-2026-63030 (batch-route confusion) with CVE-2026-60137 (SQL injection
    via author__not_in string injection in WP_Query). Keys on the distinctive
    batch endpoint combined with author__not_in manipulation indicators.
references:
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://wordpress.org/news/2026/07/wordpress-6-9-5-security-release/
author: Actioner
date: 2026-07-18
tags:
    - attack.t1190
    - attack.initial_access
    - cve.2026-63030
    - cve.2026-60137
logsource:
    category: webserver
detection:
    selection_batch_path:
        cs-uri-stem|contains:
            - '/wp-json/batch/v1'
    selection_batch_query:
        cs-uri-query|contains:
            - 'rest_route=/batch/v1'
            - 'rest_route=%2Fbatch%2Fv1'
    selection_sqli_indicator:
        cs-body|contains:
            - 'author__not_in'
            - 'author%5F%5Fnot%5Fin'
    condition: (selection_batch_path or selection_batch_query) and selection_sqli_indicator
falsepositives:
    - Legitimate batch API requests that reference author__not_in in the POST body are uncommon but possible in custom REST clients
level: high
```

### Sigma Rule 2: WordPress wp2shell Batch POST with SQLi Indicators (CVE-2026-60137)
Detects POST requests to the batch endpoint with author__not_in and SQL injection keywords in the request body — higher confidence, requires body logging.
**Status:** compile PASS (sigma check 0 issues; convert splunk PASS; convert log_scale PASS) | confidence: high
<!-- audit: sigma check 0 errors/0 issues. Requires cs-body field (body logging enabled). cs-uri-stem|contains for /wp-json/batch/v1 path variant; cs-uri-query|contains for rest_route= query-string variant. More specific than Rule 1 — fires only on POST with SQL keyword indicators in body alongside author__not_in. The combination is highly specific to exploitation; FP near zero. Evasion: comment obfuscation or case tricks in body may evade keyword list. '--' and '/*' are marginal but acceptable given full conjunction with method+endpoint+author__not_in. -->
```yaml
title: WordPress wp2shell Batch POST with SQLi Indicators (CVE-2026-60137)
id: 2b4d8f3a-7e1c-4a59-9d6f-3c8b5e2a1f07
status: experimental
description: >
    Detects HTTP POST requests to the WordPress batch/v1 endpoint where the
    request body contains author__not_in with SQL injection indicators. The
    wp2shell chain uses a deliberately malformed batch request to misalign
    sub-request arrays (CVE-2026-63030) and then injects SQL via author__not_in
    passed as a string rather than an array (CVE-2026-60137).
references:
    - https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html
    - https://wordpress.org/news/2026/07/wordpress-6-9-5-security-release/
author: Actioner
date: 2026-07-18
tags:
    - attack.t1190
    - attack.initial_access
    - cve.2026-63030
    - cve.2026-60137
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_batch_path:
        cs-uri-stem|contains:
            - '/wp-json/batch/v1'
    selection_batch_query:
        cs-uri-query|contains:
            - 'rest_route=/batch/v1'
            - 'rest_route=%2Fbatch%2Fv1'
    selection_sqli_body:
        cs-body|contains:
            - 'author__not_in'
    selection_sqli_patterns:
        cs-body|contains:
            - 'UNION SELECT'
            - 'UNION%20SELECT'
            - "' OR "
            - "' AND "
            - 'ORDER BY'
            - 'SLEEP('
            - 'BENCHMARK('
            - 'EXTRACTVALUE('
            - 'UPDATEXML('
            - '--'
            - '/*'
    condition: selection_method and (selection_batch_path or selection_batch_query) and selection_sqli_body and selection_sqli_patterns
falsepositives:
    - Very unlikely; the combination of batch endpoint + author__not_in + SQL keywords in POST body is highly specific
level: critical
```

### Suricata: WordPress wp2shell Batch Endpoint RCE (CVE-2026-63030 + CVE-2026-60137)
Detects HTTP requests to the batch endpoint with author__not_in in the request body — network-level detection via Suricata 7.x dotted sticky buffers.
**Status:** compile PASS (suricata -T exit 0, Suricata 7.0.3) | confidence: high
<!-- audit: suricata -T exit 0. Uses http.uri sticky buffer for endpoint matching, http.request_body for SQLi parameter. fast_pattern on /wp-json/batch/v1. Two rules: one for direct path, one for rest_route= query-string variant. Fires on any POST carrying author__not_in in body to the batch endpoint. -->
```suricata
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"Actioner - WordPress wp2shell Batch Endpoint RCE Attempt (CVE-2026-63030 + CVE-2026-60137)"; flow:established,to_server; http.uri; content:"/wp-json/batch/v1"; fast_pattern; http.request_body; content:"author__not_in"; nocase; classtype:web-application-attack; reference:cve,2026-63030; reference:cve,2026-60137; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; metadata:author Actioner, created_at 2026_07_18, updated_at 2026_07_18; sid:2200950; rev:1;)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"Actioner - WordPress wp2shell Batch Endpoint Query String Variant (CVE-2026-63030)"; flow:established,to_server; http.uri; content:"rest_route="; content:"/batch/v1"; distance:0; fast_pattern; http.request_body; content:"author__not_in"; nocase; classtype:web-application-attack; reference:cve,2026-63030; reference:cve,2026-60137; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; metadata:author Actioner, created_at 2026_07_18, updated_at 2026_07_18; sid:2200951; rev:1;)
```

### Snort: WordPress wp2shell Batch Endpoint RCE (CVE-2026-63030 + CVE-2026-60137)
Detects the same pattern via Snort 2.9 syntax (tcp + non-dotted buffers).
**Status:** structural check only (snort binary not available) | confidence: high
<!-- audit: snort not installed; structural check only. Uses http_uri for endpoint, http_client_body for author__not_in. Mirrors Suricata logic in Snort 2.9 dialect. -->
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Actioner - WordPress wp2shell Batch Endpoint RCE Attempt CVE-2026-63030 + CVE-2026-60137"; flow:established,to_server; content:"/wp-json/batch/v1"; http_uri; fast_pattern; content:"author__not_in"; nocase; http_client_body; classtype:web-application-attack; reference:cve,2026-63030; reference:cve,2026-60137; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; sid:2100950; rev:1;)

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Actioner - WordPress wp2shell Batch Endpoint Query String Variant CVE-2026-63030"; flow:established,to_server; content:"rest_route="; http_uri; content:"/batch/v1"; http_uri; distance:0; fast_pattern; content:"author__not_in"; nocase; http_client_body; classtype:web-application-attack; reference:cve,2026-63030; reference:cve,2026-60137; reference:url,thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html; sid:2100951; rev:1;)
```

### YARA: N/A
No file-level malware sample or static artifact grounds a file signature — the vulnerability is exploited over HTTP via JSON API requests. Post-exploitation web shells are generic PHP and better detected by existing PHP web shell YARA rules.

## Lessons Learned

The wp2shell chain demonstrates that even WordPress core — with its massive security review surface — can harbor exploitable logic flaws in overlooked API surfaces. The batch endpoint's parallel array processing is a non-obvious attack surface, and the type confusion in `author__not_in` (string vs. array) bypasses validation that was designed for the expected type. The one-day gap between patch release and public PoC means defenders have effectively zero grace period — WAF mitigations blocking the batch endpoint should be staged before or simultaneously with patching. The query-string variant (`rest_route=/batch/v1`) is a reminder that path-based blocking alone is insufficient when WordPress exposes alternative routing mechanisms.

## Sources

- [The Hacker News — New wp2shell WordPress Core Flaw](hxxps://thehackernews[.]com/2026/07/new-wp2shell-wordpress-core-flaw-lets[.]html) — primary reporting; CVE identifiers, affected versions, exploitation mechanism summary, timeline
- [WordPress 6.9.5 Security Release](hxxps://wordpress[.]org/news/2026/07/wordpress-6-9-5-security-release/) — vendor advisory; patched versions, acknowledgments
- [WordPress 7.0.2 Security Release](hxxps://wordpress[.]org/news/2026/07/wordpress-7-0-2-security-release/) — vendor advisory for 7.x branch

<!-- revision: v1.1 2026-07-18 — Sigma Rule 1: split endpoint detection into cs-uri-stem|contains (path variant) and cs-uri-query|contains (rest_route= variant); moved author__not_in from cs-uri-query to cs-body|contains; updated audit comment. Sigma Rule 2: same path/query split; confidence label corrected from "critical" to "high" in status line; audit comment updated re: marginal patterns acceptable given conjunction. Suricata/Snort: unchanged (KEEP). Re-validated: sigma check 0 errors/0 issues; sigma convert splunk PASS; sigma convert log_scale PASS. -->

---
*Report generated by Actioner*
