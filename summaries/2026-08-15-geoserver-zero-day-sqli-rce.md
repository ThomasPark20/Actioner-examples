# Technical Analysis Report: GeoServer jsonArrayContains SQL Injection Zero-Day (2026-08-15)

Prepared by: Actioner
Classification: FINAL
<!-- revision: critic READY, minor version notation fix applied -->
Date: 2026-08-15
Version: 1.0

## Executive Summary

A critical SQL injection vulnerability (CVSS 9.8) in the GeoTools `jsonArrayContains` filter function is under active exploitation against GeoServer instances backed by PostGIS 12+. The flaw, tracked as GHSA-mqjf-5f49-2fjh and a regression of CVE-2023-25158, allows unauthenticated attackers to execute arbitrary SQL against the backing database by injecting payloads through the `value` parameter of the `jsonArrayContains(column, pointer, value)` CQL filter function, which is written into generated SQL without escaping. Under configurations where the database account has elevated privileges, this escalates to full remote code execution via PostgreSQL's `COPY ... FROM PROGRAM` or similar facilities.

Security researcher q1uf3ng publicly disclosed the vulnerability on August 12, 2026. WatchTowr reported observing hundreds of exploitation attempts from a small number of source IPs within hours of disclosure. GeoServer released patched versions (2.27.6, 2.28.5, 3.0.1) on August 14, 2026, incorporating GeoTools fixes (33.6, 34.5, 35.1).

## Background: GeoServer and GeoTools

GeoServer is a widely deployed open-source Java server for sharing and processing geospatial data via OGC (Open Geospatial Consortium) standards including WFS (Web Feature Service), WMS (Web Mapping Service), and WCS (Web Coverage Service). It is used across government, agriculture, telecommunications, and transit sectors. GeoServer relies on the GeoTools library for data store operations, including SQL generation for database-backed layers.

The `jsonArrayContains` function was introduced in GeoServer 2.22.0 / GeoTools to support querying JSON array fields in PostGIS and Oracle JDBC data stores. It accepts three parameters: a column name, a JSON pointer path, and a value to search for. When used with PostGIS 12+, GeoTools delegates this function to PostgreSQL's `jsonb_path_exists()`, constructing a jsonpath expression that includes the user-supplied value argument.

GeoServer has a history of OGC filter injection vulnerabilities. The 2023 OGC Filter Injection advisory (CVE-2023-25158) addressed SQL injection in several filter functions including `jsonArrayContains`. The current vulnerability is a regression: the prior mitigation (enabling `preparedStatements` and disabling `encode functions`) is ineffective for this specific function's code path.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-12 | Security researcher q1uf3ng discloses vulnerability on X/Twitter |
| 2026-08-12 (hours later) | WatchTowr begins observing exploitation attempts; hundreds recorded from small number of source IPs |
| 2026-08-14 | GeoTools publishes advisory GHSA-mqjf-5f49-2fjh and fix PR #5829 (GEOT-7958) |
| 2026-08-14 | GeoServer releases patched versions: 2.27.6 (GeoTools 33.6), 2.28.5 (GeoTools 34.5), 3.0.1 (GeoTools 35.1) |
| 2026-08-14 | SecurityWeek and SecurityAffairs publish coverage |

## Root Cause: Unsanitized Value Interpolation in jsonArrayContains SQL Generation

The vulnerability resides in `FilterToSqlHelper.java` within the GeoTools PostGIS JDBC module (`org.geotools:gt-jdbc-postgis`). When translating a `jsonArrayContains` CQL filter into SQL for PostGIS 12+, the function constructs a jsonpath expression string. The third parameter (the search value) is interpolated directly into this string without escaping:

```java
// VULNERABLE CODE (pre-fix)
return "(@.%s == \"%s\")".formatted(jsonPath[lastIndex], value);
```

An attacker-supplied value containing double-quote or single-quote characters can escape the string context, injecting arbitrary SQL expressions. The fix (PR #5829) introduces an `escapeJsonLiteral()` function that sanitizes the value before interpolation:

```java
// FIXED CODE
String literal = escapeJsonLiteral(String.valueOf(value));
return "(@.%s == \"%s\")".formatted(jsonPath[lastIndex], literal);
```

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery via OGC Filter Parameters

The attack is delivered through HTTP requests to GeoServer's OGC service endpoints. The vulnerable `jsonArrayContains` function is invoked through CQL (Common Query Language) filter parameters in GET requests or XML filter bodies in POST requests.

**Vulnerable endpoints:**
- `/geoserver/ows` (generic OGC service endpoint)
- `/geoserver/wfs` (Web Feature Service)
- `/geoserver/wms` (Web Mapping Service)
- `/geoserver/wcs` (Web Coverage Service)

**Attack parameter:** `CQL_FILTER` (GET query parameter)

**Example exploitation request pattern:**
```
GET /geoserver/ows?service=WFS&version=1.0.0&request=GetFeature
    &typeName=<layer>
    &CQL_FILTER=jsonArrayContains(json_col,%27/path%27,%27INJECTED_VALUE%27)
```

Where `INJECTED_VALUE` contains SQL injection payload characters such as `"'` followed by arbitrary SQL.

### 2. SQL Injection to Database Compromise

The injected value reaches PostgreSQL's `jsonb_path_exists()` function within a jsonpath expression. By escaping the string context with carefully crafted quote characters, the attacker can execute arbitrary SQL expressions.

**Reconnaissance phase (observed in the wild):** Attackers are scanning broadly, triggering errors, comparing responses, and building lists of vulnerable systems. This corresponds to time-based blind SQL injection techniques using `pg_sleep()` to infer database responses.

**Escalation paths:**
- **Data exfiltration:** `UNION SELECT` or error-based extraction of database contents
- **Remote code execution:** PostgreSQL's `COPY ... FROM PROGRAM` executes operating system commands when the database user has sufficient privileges

### 3. C2 Infrastructure

No specific C2 infrastructure has been publicly attributed to the observed exploitation attempts. WatchTowr noted that scanning originates from "a small number of source IP addresses" but these have not been published.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)
GeoServer is predominantly deployed on Linux. PostgreSQL backends typically run on the same host or within the same network segment. The `COPY ... FROM PROGRAM` RCE vector executes commands as the PostgreSQL service user (typically `postgres`).

#### Windows
GeoServer deployments on Windows with PostgreSQL backends are equally vulnerable. The `COPY ... FROM PROGRAM` vector executes commands as the PostgreSQL Windows service account.

### 5. Anti-Forensics / Evasion Techniques

Exploitation occurs through standard HTTP requests to legitimate GeoServer endpoints, making traffic blending straightforward. Attackers may use URL encoding to obscure payloads in the `CQL_FILTER` parameter. No novel evasion techniques have been reported beyond standard SQL injection obfuscation.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| org.geotools:gt-jdbc-postgis | >= 33.1 & < 33.6, >= 34.0 & < 34.5, 35.0 | GeoTools PostGIS JDBC module with unsanitized jsonArrayContains value interpolation |
| GeoServer | < 2.27.6, < 2.28.5, < 3.0.1 | All versions using vulnerable GeoTools PostGIS module |

### File System

No file system IOCs have been published for this vulnerability.

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/geoserver/ows?*CQL_FILTER=*jsonArrayContains(*` | Exploitation via OGC service endpoint with CQL filter |
| URL Pattern | `/geoserver/wfs?*CQL_FILTER=*jsonArrayContains(*` | Exploitation via WFS endpoint |
| URL Pattern | `/geoserver/wms?*CQL_FILTER=*jsonArrayContains(*` | Exploitation via WMS endpoint |

No specific attacker IP addresses or domains have been published. WatchTowr noted exploitation from "a small number of source IP addresses" without disclosing them.

### Behavioral

- HTTP requests to GeoServer OGC endpoints containing `jsonArrayContains` in the `CQL_FILTER` query parameter, particularly with SQL injection indicators (unescaped quotes, SQL keywords like `UNION`, `SELECT`, `pg_sleep`, `COPY`, `FROM PROGRAM`)
- Elevated error rates or unusual response times from GeoServer (indicative of time-based blind SQL injection probing with `pg_sleep`)
- PostgreSQL log entries showing syntax errors in `jsonb_path_exists()` calls or unexpected SQL execution patterns

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | SQL injection via unauthenticated HTTP requests to GeoServer OGC endpoints using crafted jsonArrayContains CQL filters |
| T1059 | Command and Scripting Interpreter | Potential RCE via PostgreSQL `COPY ... FROM PROGRAM` when database privileges allow |

## Impact Assessment

**Breadth:** GeoServer is widely deployed in government, academic, and infrastructure organizations worldwide. Any instance backed by PostGIS 12+ with String or JSON fields is vulnerable. The attack requires no authentication and no user interaction.

**Depth:** CVSS 9.8 (Critical). Successful exploitation yields arbitrary SQL execution against the backing database. Under common configurations where the PostgreSQL user has file or superuser privileges, this escalates to operating system command execution.

**Stealth:** Exploitation uses standard HTTP requests to legitimate endpoints, making detection challenging without specific content inspection of CQL filter parameters.

**Exposure window:** The vulnerability was publicly disclosed on August 12 with no patch available. Patches were released August 14, creating a minimum 48-hour window of zero-day exposure. Organizations that have not yet updated remain vulnerable.

## Detection & Remediation

### Immediate Detection

**Web server access logs (Apache/Nginx/IIS):**
```bash
# Search for jsonArrayContains in GeoServer access logs
grep -i "jsonArrayContains" /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log 2>/dev/null

# Search for jsonArrayContains with SQL injection indicators
grep -iP "jsonArrayContains.*(%27|%22|UNION|SELECT|pg_sleep|COPY)" /var/log/nginx/access.log 2>/dev/null
```

**PostgreSQL logs:**
```sql
-- Check for suspicious jsonb_path_exists errors
SELECT * FROM pg_stat_activity WHERE query LIKE '%jsonb_path_exists%' AND state = 'active';
```

**GeoServer version check:**
```bash
# Check GeoServer version via REST API (if exposed)
curl -s http://localhost:8080/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage | grep -i version
```

### Remediation

1. **Update immediately** to GeoServer 2.27.6, 2.28.5, or 3.0.1 (released 2026-08-14)
2. **Restrict public access** to GeoServer OGC endpoints via VPN, reverse proxy with IP allowlisting, or WAF rules blocking `jsonArrayContains` in query strings
3. **Audit PostgreSQL privileges** — ensure the GeoServer database user has minimal privileges; revoke `SUPERUSER`, `CREATEROLE`, and file-access privileges
4. **Review access logs** for exploitation attempts using the detection queries above
5. **Monitor PostgreSQL logs** for anomalous query patterns or errors in `jsonb_path_exists`

### Long-Term Hardening

- Enable `preparedStatements` in GeoServer PostGIS data store configuration (mitigates many SQL injection classes, though not this specific regression)
- Disable `encode functions` in PostGIS data store configuration
- Deploy a WAF with SQL injection detection rules in front of GeoServer
- Restrict GeoServer OGC endpoint exposure — avoid direct internet-facing deployment without access controls
- Subscribe to GeoServer security advisories for timely patching

## Detection Rules

These detections target the GeoServer jsonArrayContains SQL injection exploitation pattern (GHSA-mqjf-5f49-2fjh) at advisory-specific altitude. They key on the `jsonArrayContains` function name combined with PostgreSQL SQL injection indicators in HTTP requests. Compiles does not equal fires — verify each rule in your pipeline with representative telemetry.

### Sigma: GeoServer jsonArrayContains SQL Injection Attempt
Detects HTTP requests containing the `jsonArrayContains` CQL filter function with PostgreSQL-specific SQL injection payloads in web server access logs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. No pipeline for webserver category — syntactically valid, not schema-mapped. Values are URL-encoded representations matching raw query strings in access logs. No defanged values in rule. -->
```yaml
title: GeoServer jsonArrayContains SQL Injection Attempt
id: d8977c16-3cb5-4336-bc5a-3acfd5918e68
status: experimental
description: >
    Detects HTTP requests exploiting the GeoTools jsonArrayContains CQL filter
    function SQL injection vulnerability (GHSA-mqjf-5f49-2fjh). The function
    writes user-supplied values directly into SQL without escaping, enabling
    unauthenticated SQL injection against PostGIS 12+ backends. Active
    exploitation observed within hours of public disclosure on 2026-08-12.
references:
    - https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh
    - https://securityaffairs.com/197216/hacking/geoserver-zero-day-is-already-being-probed-thats-the-problem.html
    - https://www.securityweek.com/hackers-exploiting-unpatched-geoserver-zero-day/
author: Actioner
date: 2026/08/15
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_function:
        cs-uri-query|contains: 'jsonArrayContains'
    selection_sqli:
        cs-uri-query|contains:
            - 'pg_sleep'
            - 'UNION%20SELECT'
            - 'COPY%20'
            - 'version()'
            - 'chr('
            - 'FROM%20PROGRAM'
            - '%22%27'
            - '%27%20OR%20'
            - '%27%20AND%20'
            - '%27--%20'
    condition: selection_function and selection_sqli
falsepositives:
    - Legitimate GeoServer CQL queries using jsonArrayContains whose values coincidentally contain PostgreSQL function names
level: high
```

### Snort: GeoServer jsonArrayContains SQLi via pg_sleep
Detects time-based blind SQL injection probing through the jsonArrayContains function using PostgreSQL's `pg_sleep` — the most common reconnaissance technique observed.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (Snort 2.9.20). http_uri buffer is URL-decoded by Snort, so content matches the literal pg_sleep string regardless of URL encoding. fast_pattern on jsonArrayContains for efficient pre-filter. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - GeoServer jsonArrayContains SQL Injection via pg_sleep"; flow:established,to_server; content:"jsonArrayContains"; http_uri; nocase; fast_pattern; content:"pg_sleep"; http_uri; nocase; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; sid:2100001; rev:1;)
```

### Snort: GeoServer jsonArrayContains SQLi via UNION SELECT
Detects data-exfiltration SQL injection attempts through the jsonArrayContains function using `UNION SELECT` syntax.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (Snort 2.9.20). Two content matches (UNION + SELECT) in http_uri after jsonArrayContains anchor reduce FP vs single keyword. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - GeoServer jsonArrayContains SQL Injection via UNION SELECT"; flow:established,to_server; content:"jsonArrayContains"; http_uri; nocase; fast_pattern; content:"UNION"; http_uri; nocase; content:"SELECT"; http_uri; nocase; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; sid:2100002; rev:1;)
```

### Suricata: GeoServer jsonArrayContains SQLi via pg_sleep
Detects time-based blind SQL injection probing via `pg_sleep` in GeoServer `jsonArrayContains` CQL filter requests.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S <file> -l /tmp/actioner exit 0 (Suricata 7.0.3). Dot-notation http.uri sticky buffer; both content matches in same buffer. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - GeoServer jsonArrayContains SQL Injection via pg_sleep"; flow:established,to_server; http.uri; content:"jsonArrayContains"; nocase; fast_pattern; content:"pg_sleep"; nocase; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; metadata:author Actioner, created_at 2026-08-15; sid:2200001; rev:1;)
```

### Suricata: GeoServer jsonArrayContains SQLi via UNION SELECT
Detects data-exfiltration SQL injection attempts via `UNION SELECT` in GeoServer `jsonArrayContains` CQL filter requests.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S <file> -l /tmp/actioner exit 0 (Suricata 7.0.3). Three chained content matches in http.uri buffer for high specificity. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - GeoServer jsonArrayContains SQL Injection via UNION SELECT"; flow:established,to_server; http.uri; content:"jsonArrayContains"; nocase; fast_pattern; content:"UNION"; nocase; content:"SELECT"; nocase; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; metadata:author Actioner, created_at 2026-08-15; sid:2200002; rev:1;)
```

### YARA: N/A
No file-level indicators suitable for YARA detection in this vulnerability.

## Lessons Learned

This incident reinforces several recurring themes:

1. **Regression vulnerabilities are real.** The current flaw is a regression of CVE-2023-25158, fixed in 2023. The `jsonArrayContains` code path was not fully covered by the original mitigation (prepared statements / encode-functions toggle), demonstrating that security fixes must be validated against all affected code paths, not just the ones reported.

2. **Zero-day disclosure-to-exploitation is collapsing.** WatchTowr recorded hundreds of exploitation attempts within hours of public disclosure, before any vendor patch was available. Organizations need pre-positioned detection capabilities and rapid response procedures.

3. **CQL filter injection is a persistent GeoServer attack surface.** The OGC filter evaluation mechanism has been the source of multiple critical vulnerabilities (CVE-2023-25158, CVE-2024-36401, and now this regression). Organizations running GeoServer should treat the CQL filter parameter surface as high-risk and apply defense-in-depth (WAF rules, minimal database privileges, network segmentation).

4. **Database privilege minimization is a critical RCE barrier.** The escalation from SQL injection to RCE depends on the PostgreSQL user's privileges. Restricting the GeoServer database user to the minimum required permissions blocks the `COPY ... FROM PROGRAM` escalation path.

## Sources

- [GeoTools Security Advisory GHSA-mqjf-5f49-2fjh](https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh) — primary advisory documenting the SQL injection in jsonArrayContains, CVSS 9.8, CWE-89, affected/patched versions
- [GeoTools PR #5829 (GEOT-7958)](https://github.com/geotools/geotools/pull/5829) — fix commit introducing escapeJsonLiteral() for value sanitization with test cases demonstrating injection payloads
- [SecurityAffairs: GeoServer zero-day is already being probed](https://securityaffairs.com/197216/hacking/geoserver-zero-day-is-already-being-probed-thats-the-problem.html) — reporting on active exploitation, WatchTowr observations, and timeline
- [SecurityWeek: Hackers Exploiting Unpatched GeoServer Zero-Day](https://www.securityweek.com/hackers-exploiting-unpatched-geoserver-zero-day/) — technical context on PostGIS/Oracle JDBC exposure, WatchTowr statement, and affected sectors
- [GeoServer 2.28.5 Release Notes](https://geoserver.org/announcements/vulnerability/2026/08/14/geoserver-2-28-5-released.html) — patch release incorporating GeoTools 34.5 fix
- [GeoServer OGC Filter Injection Advisory (CVE-2023-25158)](https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html) — prior advisory documenting the original jsonArrayContains SQL injection, now regressed
- [GeoServer CVE-2024-36401 Advisory (GHSA-6jj6-gm7p-fcvv)](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv) — related prior RCE via property name expressions in OGC filters (CVSS 9.8)

---
*Report generated by Actioner*
