# Technical Analysis Report: GeoServer jsonArrayContains SQL Injection Zero-Day (2026-08-16)

Prepared by: Actioner
Classification: FINAL
Date: 2026-08-16
Version: 1.1

## Executive Summary

An unauthenticated SQL injection vulnerability in GeoServer's `jsonArrayContains` filter function (advisory [GHSA-mqjf-5f49-2fjh](https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh), CVSS 9.8) enables arbitrary SQL execution against PostGIS-backed layers. The flaw is a regression of CVE-2023-25158 in the GeoTools library (`org.geotools:gt-jdbc-postgis`): the `jsonArrayContains(<column>, <pointer>, <value>)` function writes the `<value>` parameter into generated SQL without escaping, allowing single-quote breakout. Under configurations where the database account holds elevated privileges (e.g., PostgreSQL superuser), this escalates to remote code execution via `COPY TO PROGRAM` or equivalent.

The vulnerability was publicly disclosed on 2026-08-12 at 10:46 UTC by security researcher @q1uf3ng on X. Within hours, [watchTowr](https://www.securityweek.com/hackers-exploiting-unpatched-geoserver-zero-day/) reported hundreds of probing attempts from a small pool of source IP addresses. A Python proof-of-concept exploit targeting PostgreSQL RCE was published on GitHub. GeoServer subsequently released patched versions 3.0.1, 2.28.5, and 2.27.6 on 2026-08-14. Organizations running unpatched, internet-facing GeoServer instances with PostGIS 12+ backends are at critical risk.

## Background: GeoServer

[GeoServer](https://geoserver.org/) is an open-source Java server implementing OGC (Open Geospatial Consortium) standards including WFS (Web Feature Service), WMS (Web Map Service), and WCS (Web Coverage Service). It enables sharing, editing, and publishing of geospatial data. GeoServer is widely deployed across government agencies (including U.S. federal), defense organizations, scientific institutions, utilities, transportation systems, and environmental monitoring platforms. Its OGC-compliant endpoints accept filter expressions --- including CQL (Common Query Language) filters --- that are translated into SQL queries against the backing data store. This architecture means that filter-to-SQL translation bugs can expose the database engine directly to unauthenticated external input.

GeoServer has prior history of critical SQL injection vulnerabilities in its filter pipeline. CVE-2023-25157 and CVE-2023-25158 addressed multiple OGC filter injection paths in February 2023. CVE-2024-36401 --- an XPath expression evaluation vulnerability --- was actively exploited at scale, with compromised instances being recruited into DDoS botnets and cryptomining networks.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-12 10:46 | Security researcher @q1uf3ng discloses the vulnerability publicly on X |
| 2026-08-12 (hours later) | watchTowr begins observing exploitation probes; hundreds of attempts from a small IP pool |
| 2026-08-13 | Field Effect, SecurityWeek, The Hacker News, Security Affairs publish advisories; no confirmed compromises reported |
| 2026-08-14 | GeoServer releases patched versions 3.0.1, 2.28.5, 2.27.6; GitHub advisory GHSA-mqjf-5f49-2fjh published |
| 2026-08-14 | Python PoC exploit (jsonArrayContains SQLi to PostgreSQL RCE) published on GitHub |

## Root Cause: Unescaped Value in jsonArrayContains Filter-to-SQL Translation

The root cause resides in GeoTools' `FilterToSqlHelper.constructEquality` method within the `org.geotools:gt-jdbc-postgis` package. When processing a `jsonArrayContains(<column>, <pointer>, <value>)` OGC filter expression against PostGIS 12+ data stores with String or JSON fields, the `<value>` parameter is written directly into the generated SQL statement without proper escaping or parameterization. This enables a classic single-quote breakout: an attacker supplies a value like `x')` followed by arbitrary SQL, terminated with `--` to comment out the remainder of the original query.

The previous mitigations for CVE-2023-25158 --- enabling `preparedStatements` and disabling `encode` functions --- are **not effective** against this regression. The `jsonArrayContains` function bypasses those controls.

**Prerequisites for exploitation:**
- GeoServer with PostGIS 12+ data store (or Oracle JDBC data store)
- At least one layer with a String or JSON field accessible via OGC filter endpoints
- Network access to the GeoServer OWS/WFS/WMS endpoint (typically `/geoserver/ows`)

**Prerequisites for RCE escalation:**
- Database account with superuser or elevated privileges (e.g., PostgreSQL `sa` role)
- `COPY TO PROGRAM` or equivalent command execution capability

## Technical Analysis of the Malicious Payload

### 1. OGC Filter Injection via CQL_FILTER

The attack is delivered as an HTTP GET request to a GeoServer OGC endpoint. The vulnerable parameter is `CQL_FILTER`, which accepts CQL filter expressions including `jsonArrayContains`.

**Target endpoint pattern:**
```
/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=<layer>&CQL_FILTER=jsonArrayContains("<column>",'/a','<PAYLOAD>') = true
```

The `<PAYLOAD>` position breaks out of the SQL string context using a single quote and closing parenthesis: `x')`, then appends arbitrary SQL, followed by `--` to comment out the trailing query.

### 2. SQL Injection Payload Variants

Three primary exploitation modes were documented in the published PoC:

**Stacked query verification (time-based):**
```sql
x') ; SELECT pg_sleep(4) --
```
Confirms SQL injection by inducing a measurable delay in the HTTP response.

**Remote command execution (requires superuser):**
```sql
x') ; COPY (SELECT 1) TO PROGRAM '<command>' --
```
Executes arbitrary operating system commands via PostgreSQL's `COPY TO PROGRAM` facility.

**Blind time-based data extraction:**
```sql
x') AND (SELECT * FROM (SELECT pg_sleep(CASE WHEN <condition> THEN 4 ELSE 0 END)) a) IS NOT NULL --
```
Extracts data character-by-character using binary search on ASCII values: `ascii(substr(<expr>, <pos>, 1)) > <mid>`.

### 3. C2 Infrastructure

No specific C2 infrastructure has been documented in association with this vulnerability as of the report date. The observed activity has been limited to scanning and probing (reconnaissance), not post-compromise operations.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

GeoServer is predominantly deployed on Linux servers. The PostgreSQL `COPY TO PROGRAM` RCE vector executes commands as the PostgreSQL service user (typically `postgres`). Post-exploitation could include reverse shell establishment, persistence via cron, or lateral movement.

#### Windows

GeoServer deployments on Windows with PostgreSQL would face similar RCE risk via `COPY TO PROGRAM`. The CSO Online report also notes potential escalation via Microsoft SQL Server's `xp_cmdshell` when MSSQL is the backing store with administrator-level database accounts.

### 5. Anti-Forensics / Evasion Techniques

The SQL injection can be URL-encoded to evade basic WAF rules. Key evasion patterns include:
- URL-encoding the single-quote breakout: `%27%29` for `')`
- Encoding spaces: `%20` for space characters in SQL keywords
- Using comment syntax (`--`) to neutralize trailing SQL
- Time-based blind extraction avoids generating error messages in logs

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| org.geotools:gt-jdbc-postgis | 35.0, >=34.0, >=33.1 | jsonArrayContains writes value into SQL without escaping |
| GeoServer | Pre-3.0.1, Pre-2.28.5, Pre-2.27.6 | Exposes vulnerable GeoTools filter function via OGC endpoints |

### File System

No file-system IOCs have been documented for this vulnerability at this time. Post-exploitation artifacts would depend on the attacker's secondary payload.

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/geoserver/ows?service=wfs&...&CQL_FILTER=jsonArrayContains(...)` | Exploitation endpoint; any request with `jsonArrayContains` in `CQL_FILTER` to OWS/WFS/WMS |
| URL Pattern | `/geoserver/wfs?...&CQL_FILTER=jsonArrayContains(...)` | Alternate exploitation endpoint |
| URL Pattern | `/geoserver/wms?...&CQL_FILTER=jsonArrayContains(...)` | Alternate exploitation endpoint |

**Note:** Specific attacker IP addresses were not disclosed in public reporting. watchTowr reported "hundreds of attempts originating from a small number of source IP addresses" but did not publish the IPs.

### Behavioral

- HTTP GET requests to GeoServer OGC endpoints (`/geoserver/ows`, `/geoserver/wfs`, `/geoserver/wms`) containing `jsonArrayContains` in the `CQL_FILTER` query parameter
- Requests containing SQL injection markers in the `CQL_FILTER` value: single-quote breakout (`')`), `pg_sleep`, `COPY`, `TO PROGRAM`, SQL comment terminator (`--`)
- URL-encoded variants of injection markers: `%27%29` (URL-encoded `')`), `%20` (spaces in SQL keywords)
- GeoServer returning HTTP 500 errors in response to probing attempts (attackers "triggering server errors as they attempt to refine their payloads")
- Unexpected child processes spawning from the PostgreSQL database service (indicator of successful `COPY TO PROGRAM` exploitation)
- Database logs showing unusual SQL queries containing `pg_sleep`, `COPY TO PROGRAM`, or stacked queries originating from GeoServer connections

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | SQL injection via unauthenticated OGC filter endpoint on internet-facing GeoServer |
| T1059 | Command and Scripting Interpreter | OS command execution via PostgreSQL `COPY TO PROGRAM` after SQL injection |
| T1059.004 | Unix Shell | Linux command execution through PostgreSQL service user context |
<!-- revision: T1046→T1595.002 per critic — mass internet probing is Reconnaissance/Active Scanning, not post-access Discovery -->
| T1595.002 | Active Scanning: Vulnerability Scanning | Mass probing of internet-exposed GeoServer instances to identify vulnerable systems |
<!-- revision: T1589→T1005 per critic — blind SQL data extraction is Collection, not pre-targeting identity research -->
| T1005 | Data from Local System | Time-based blind SQL extraction of database contents character-by-character |

## Impact Assessment

**Breadth:** GeoServer is deployed across government, defense, scientific research, environmental monitoring, utilities, and transportation sectors globally. Shodan and similar platforms reveal thousands of internet-facing instances. The unauthenticated nature of the vulnerability means every exposed instance with a PostGIS 12+ backend is potentially exploitable.

**Depth:** The vulnerability enables full SQL injection (read/write/execute against the database) and, under common deployment configurations with elevated database privileges, remote code execution on the underlying server. This represents complete system compromise.

**Stealth:** Time-based blind exploitation generates minimal log artifacts beyond HTTP access logs. Successful `COPY TO PROGRAM` execution leaves standard PostgreSQL audit log entries but no GeoServer-level artifacts.

**Historical precedent:** CVE-2024-36401 (a prior GeoServer vulnerability) was exploited at scale to build DDoS botnets and cryptomining networks, demonstrating that threat actors actively target GeoServer infrastructure for mass exploitation.

## Detection & Remediation

### Immediate Detection

**Web server access logs --- search for jsonArrayContains in query strings:**
```bash
grep -i "jsonArrayContains" /var/log/geoserver/access.log /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null
```

**PostgreSQL logs --- search for anomalous queries:**
```bash
grep -iE "pg_sleep|COPY.*TO.*PROGRAM|jsonArrayContains" /var/log/postgresql/*.log 2>/dev/null
```

**Check GeoServer version:**
```bash
curl -s http://localhost:8080/geoserver/web/ | grep -i "version"
```

### Remediation

1. **Patch immediately:** Update to GeoServer 3.0.1, 2.28.5, or 2.27.6 (released 2026-08-14)
2. **Restrict access:** If patching is not immediately possible, restrict public access to GeoServer via VPN, reverse proxy with authentication, or IP allowlisting
3. **Reduce database privileges:** Ensure the GeoServer database account does not hold superuser privileges; revoke `COPY TO PROGRAM` capability
4. **Audit logs:** Review web server access logs and PostgreSQL logs for exploitation indicators described above
5. **Network segmentation:** Isolate GeoServer instances from sensitive internal networks

### Long-Term Hardening

- Deploy a web application firewall (WAF) in front of GeoServer instances with rules to detect SQL injection in OGC filter parameters
- Implement the principle of least privilege for all database service accounts
- Subscribe to the GeoServer security mailing list for future advisories
- Conduct periodic external attack surface assessments for GeoServer and other geospatial infrastructure
- Note that the CVE-2023-25158 mitigations (enabling `preparedStatements`, disabling `encode` functions) are **not effective** against this specific regression --- do not rely on them

## Detection Rules

These detections target the GeoServer jsonArrayContains SQL injection attack vector (GHSA-mqjf-5f49-2fjh). PoC/advisory-specific altitude; Sigma rules convert to Splunk and CrowdStrike LogScale. `sigma check` could not validate ATT&CK tags (MITRE data endpoint blocked by proxy); portability proven via `sigma convert` to both backends.

### Sigma: GeoServer jsonArrayContains SQL Injection Attempt

<!-- revision: replaced bare '--' with ')--' in selection_injection_markers to avoid matching innocuous double-hyphens -->
Detects HTTP requests to GeoServer OGC endpoints with `jsonArrayContains` in `CQL_FILTER` combined with SQL injection markers (quote breakout, stacked queries, `pg_sleep`, `COPY TO PROGRAM`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — proxy/env issue, not rule issue); sigma convert splunk exit 0; sigma convert log_scale exit 0. Values are real (not defanged). FP risk: extremely low — legitimate jsonArrayContains values do not contain SQL breakout sequences. Evasion: double-URL-encoding or case variation of SQL keywords could bypass; add additional encoded variants if observed. -->
```yaml
title: GeoServer jsonArrayContains SQL Injection Attempt via OWS/WFS
id: c4a7e1b3-9f2d-4d6a-8e5c-3b1a0f7d9c2e
status: experimental
description: >
    Detects HTTP requests to GeoServer OWS/WFS endpoints containing the
    jsonArrayContains function within CQL_FILTER parameters combined with
    SQL injection patterns (quote breakout, stacked queries, pg_sleep,
    COPY TO PROGRAM). This targets the GHSA-mqjf-5f49-2fjh zero-day
    regression of CVE-2023-25158 in gt-jdbc-postgis.
references:
    - https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh
    - https://thehackernews.com/2026/08/unpatched-geoserver-zero-day-targeted.html
    - https://www.securityweek.com/hackers-exploiting-unpatched-geoserver-zero-day/
author: Actioner
date: 2026-08-16
tags:
    - attack.t1190
    - attack.t1059
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-stem|contains:
            - '/geoserver/ows'
            - '/geoserver/wfs'
            - '/geoserver/wms'
    selection_sqli:
        cs-uri-query|contains|all:
            - 'jsonArrayContains'
            - 'CQL_FILTER'
    selection_injection_markers:
        cs-uri-query|contains:
            - "x')"
            - 'pg_sleep'
            - 'COPY%20'
            - 'TO%20PROGRAM'
            - "')--"
            - '%27%29'
    condition: selection_endpoint and selection_sqli and selection_injection_markers
falsepositives:
    - Legitimate use of jsonArrayContains with values containing SQL-like syntax is extremely unlikely
level: high
```

### Sigma: GeoServer jsonArrayContains Probe in OGC Filter Request

Detects any request to GeoServer OGC endpoints with `jsonArrayContains` in the query string --- the vulnerable function itself, regardless of injection markers. Broader than the SQLi rule; useful for hunting during the active-exploitation window.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — env issue); sigma convert splunk exit 0; sigma convert log_scale exit 0. FP: legitimate jsonArrayContains use against PostGIS JSON fields will trigger — tune per environment. This is a hunt rule for the zero-day window. -->
```yaml
title: GeoServer jsonArrayContains Probe in OGC Filter Request
id: 8b2f4d6e-1a3c-5e7f-9d0b-4c8a2e6f1b3d
status: experimental
description: >
    Detects any HTTP request to GeoServer endpoints where the query string
    includes jsonArrayContains within a CQL_FILTER or OGC filter parameter.
    This function is the injection vector for GHSA-mqjf-5f49-2fjh and its
    presence in external requests warrants investigation, even without
    obvious injection markers.
references:
    - https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh
    - https://thehackernews.com/2026/08/unpatched-geoserver-zero-day-targeted.html
author: Actioner
date: 2026-08-16
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-stem|contains:
            - '/geoserver/ows'
            - '/geoserver/wfs'
            - '/geoserver/wms'
    selection_function:
        cs-uri-query|contains: 'jsonArrayContains'
    condition: selection_endpoint and selection_function
falsepositives:
    - Legitimate GeoServer applications using jsonArrayContains for normal JSON array queries against PostGIS layers
level: medium
```

### Snort: GeoServer jsonArrayContains SQLi Attempt

Detects inbound HTTP traffic to GeoServer containing `jsonArrayContains` combined with URL-encoded single-quote breakout (`%27%29`), the PoC injection pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 (Snort 2.9.20, minimal config with classification.config). Content matches: /geoserver/ (nocase), jsonArrayContains (nocase, fast_pattern), CQL_FILTER (nocase), %27%29 (URL-encoded breakout). FP: near-zero — the combination of all four content strings is highly specific. Evasion: double-encoding, chunked transfer encoding. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - GeoServer jsonArrayContains SQLi Attempt (GHSA-mqjf-5f49-2fjh)"; flow:established,to_server; content:"/geoserver/"; nocase; content:"jsonArrayContains"; nocase; fast_pattern; content:"CQL_FILTER"; nocase; content:"%27%29"; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; sid:2100010; rev:1;)
```

### Suricata: GeoServer jsonArrayContains SQLi Attempt

Detects inbound HTTP traffic to GeoServer containing `jsonArrayContains` combined with URL-encoded single-quote breakout in the URI, using Suricata's `http.uri.raw` sticky buffer for raw (non-decoded) matching.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: switched http.uri → http.uri.raw so percent-encoded %27%29 matches against the raw URI; http.uri decodes to ') via libhtp, causing the %27%29 content match to never fire -->
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Dot-notation http.uri.raw buffer used. Content matches: /geoserver/, jsonArrayContains (nocase, fast_pattern), CQL_FILTER (nocase), %27%29. FP: near-zero. Evasion: double-encoding, HTTP/2 multiplexing. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - GeoServer jsonArrayContains SQLi Attempt (GHSA-mqjf-5f49-2fjh)"; flow:established,to_server; http.uri.raw; content:"/geoserver/"; content:"jsonArrayContains"; nocase; fast_pattern; content:"CQL_FILTER"; nocase; content:"%27%29"; classtype:web-application-attack; reference:url,github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh; metadata:author Actioner, created_at 2026-08-16; sid:2200010; rev:2;)
```

### YARA: N/A

No file-level indicators suitable for YARA detection in this topic. The vulnerability is exploited entirely via network requests with no malware binary or file-system artifact documented.

## Lessons Learned

1. **Filter-to-SQL translation remains a persistent attack surface in GeoServer.** This is the third critical SQL injection in GeoServer's OGC filter pipeline since 2023 (following CVE-2023-25157, CVE-2023-25158), and the current flaw is explicitly a regression of CVE-2023-25158 --- the same vulnerable function that was previously patched re-introduced the same class of bug. This pattern suggests systemic issues in the filter translation code's security review process.

2. **Speed of exploitation continues to compress.** Exploitation probes were observed within hours of public disclosure --- consistent with trends across the industry where the window between disclosure and active exploitation is now measured in hours, not days.

3. **Uncoordinated disclosure amplifies risk.** The OSGeo project noted that the coordinated vulnerability disclosure process was not followed for this flaw. Public disclosure before a patch was available gave attackers a head start over defenders.

4. **Database privilege reduction is a critical defense-in-depth measure.** The RCE escalation path requires elevated database privileges. Organizations that follow least-privilege principles for database service accounts would face SQL injection (data exposure) but not full system compromise.

5. **Geospatial infrastructure is a high-value target.** GeoServer's deployment in government, defense, and critical infrastructure sectors makes it attractive to both opportunistic and targeted threat actors, as demonstrated by the rapid mass-scanning activity.

## Sources

- [GeoTools Security Advisory GHSA-mqjf-5f49-2fjh](https://github.com/geotools/geotools/security/advisories/GHSA-mqjf-5f49-2fjh) --- primary advisory; affected versions, CVSS 9.8, root cause description
- [The Hacker News: Unpatched GeoServer Zero-Day Targeted](https://thehackernews.com/2026/08/unpatched-geoserver-zero-day-targeted.html) --- technical summary, timeline, watchTowr observations
- [SecurityWeek: Hackers Exploiting Unpatched GeoServer Zero-Day](https://www.securityweek.com/hackers-exploiting-unpatched-geoserver-zero-day/) --- exploitation activity, industry impact, researcher attribution
- [Security Affairs: GeoServer Zero-Day Is Already Being Probed](https://securityaffairs.com/197216/hacking/geoserver-zero-day-is-already-being-probed-thats-the-problem.html) --- CVE-2024-36401 historical context, watchTowr quote, critical infrastructure exposure
- [Field Effect: Early Exploitation Attempts Observed](https://fieldeffect.com/blog/early-exploitation-attempts-observed-geoserver-zero-day) --- exploitation timeline, H2 database risk, detection guidance
- [CSO Online: Attackers Target Zero-Day in GeoServer](https://www.csoonline.com/article/4209388/attackers-target-zero-day-vulnerability-in-geospatial-data-platform-geoserver.html) --- watchTowr researcher Jake Knott quote, MSSQL RCE context
- [GeoServer Release Announcement (3.0.1 / 2.28.5 / 2.27.6)](https://discourse.osgeo.org/t/geoserver-3-0-1-geoserver-2-28-5-geoserver-2-27-6-released/154874) --- patch release details, advisory links
- [PoC: GeoServer jsonArrayContains SQLi to PostgreSQL RCE](https://gist.github.com/portbuster1337/70d75ec246b85e3199037ce212ff1a06) --- PoC exploit details, payload structure, exploitation modes
- [GeoServer OGC Filter Injection Vulnerability Statement (2023)](https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html) --- historical context on CVE-2023-25157/CVE-2023-25158 and prior jsonArrayContains issue
- [CyberUpdates365: Critical Unpatched GeoServer Zero-Day](https://cyberupdates365.com/unpatched-geoserver-zero-day-sqli-rce/) --- attack stage descriptions, reconnaissance patterns

---
*Report generated by Actioner*
