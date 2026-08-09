# Technical Analysis Report: Metabase Zero-Day SQL Injection (2026-08-09)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-09
Version: DRAFT 1.0

## Executive Summary

A maximum-severity (CVSS 10.0) unauthenticated SQL injection vulnerability in Metabase (advisory [GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf)) was exploited as a zero-day against Metabase Cloud instances before discovery. The flaw resides in the `/api/session/reset_password` endpoint and allows a remote, unauthenticated attacker to inject arbitrary SQL into the Metabase application database, escalate to administrator privileges, steal stored database credentials, and exfiltrate any data accessible through connected database connections. No CVE has been assigned.

Confirmed victims include **Framework** (PC manufacturer -- customer PII including names, emails, login IPs, billing/shipping addresses, and phone numbers were stolen), **Tally** (form builder -- email addresses and password hashes exposed), and **LexisNexis** (Metabase API impacted; systems disconnected for investigation). Metabase discovered the attack on August 3, 2026, blocked the malicious endpoint, and released patches across all affected version branches (v58 through v63) by August 6-7. Self-hosted instances that have not patched remain vulnerable.

## Background: Metabase

Metabase is a widely used open-source business intelligence and analytics platform that connects to organizational databases (PostgreSQL, MySQL, BigQuery, Snowflake, etc.) to provide dashboards, queries, and reporting. It stores connection credentials for all connected databases in its own application database, making it a high-value target -- compromise of a single Metabase instance can cascade into access to every connected data warehouse and production database. Metabase is available as a hosted cloud service (Metabase Cloud) and as a self-hosted deployment. Versions 1.58.0 through 1.63.4 (both Cloud and self-hosted) are affected; versions prior to 1.58 are unaffected.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-03 | Attack on Metabase Cloud detected; zero-day exploitation of `/api/session/reset_password` endpoint confirmed |
| 2026-08-03 (est.) | Metabase immediately blocks the malicious endpoint on Cloud instances |
| 2026-08-06 | Metabase notifies affected customers; patches released (v58.24, v59.21, v60.17, v61.11, v62.9, v63.5) |
| 2026-08-06 | Security advisory [GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) published |
| 2026-08-07 | Public disclosure; Framework, Tally, and LexisNexis confirm data breaches |
| 2026-08-07 | Framework publishes customer notification detailing stolen data categories |

## Root Cause: Unauthenticated SQL Injection in Password Reset Endpoint

The vulnerability is an unauthenticated SQL injection flaw in the `POST /api/session/reset_password` API endpoint. This endpoint, designed for password reset functionality, failed to properly sanitize user-supplied input before incorporating it into SQL queries against the Metabase application database. Because the endpoint requires no authentication, any network-reachable attacker could exploit it without credentials.

Successful exploitation grants the attacker the ability to execute arbitrary SQL against the Metabase application database, which stores user accounts, session tokens, API keys, and -- critically -- the connection credentials (hostnames, ports, usernames, passwords) for all connected databases. The attacker can escalate to full administrator access on the Metabase instance.

CVSS v3.1 vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (Score: 10.0)

## Technical Analysis of the Malicious Payload

### 1. Initial Access -- SQL Injection via Password Reset API

The attack targets the `POST /api/session/reset_password` endpoint. The attacker sends a crafted POST request containing SQL injection payloads in the request parameters. The advisory-specified indicator of exploitation is:

- A `POST /api/session/reset_password` request returning a **400 status code**, followed by
- A successful `GET /api/user/current` request returning a **200 status code**

The 400 response on the reset endpoint indicates the injected SQL was processed (the request is malformed from the application's perspective but the SQL injection succeeds as a side effect). The subsequent 200 on `/api/user/current` confirms the attacker has obtained an authenticated session.

### 2. Privilege Escalation -- Administrator Access

Once SQL injection succeeds, the attacker can manipulate the application database to grant themselves administrator privileges. This includes modifying user roles, creating new admin accounts, or directly manipulating session tokens. With admin access, the attacker gains full control over the Metabase instance configuration.

### 3. Credential Theft and Data Exfiltration

With administrator access, the attacker can:
- **Steal stored database credentials**: Metabase stores connection strings (including passwords) for all connected databases in its application database. Admin API endpoints expose these credentials.
- **Read connected database data**: Using the Metabase query interface or API, the attacker can execute arbitrary queries against all connected databases.
- **Export data**: Metabase's data export functionality enables bulk exfiltration.
- **Modify configuration**: The attacker can alter application settings to maintain access or cover tracks.

### 4. Platform-Specific Behavior

#### Metabase Cloud
Cloud instances were the primary target. Metabase applied patches and blocked the vulnerable endpoint on the server side. Cloud customers' data may have been accessed before the block was applied.

#### Self-Hosted Metabase
Self-hosted instances remain vulnerable until manually patched. The endpoint is reachable from any network position that can reach the Metabase web interface. No automatic patching mechanism exists for self-hosted deployments.

### 5. Anti-Forensics / Evasion Techniques

No specific anti-forensics or evasion techniques have been reported for this attack. The SQL injection itself leaves minimal traces beyond web server access logs and Metabase activity logs. Post-exploitation activity (credential access, data queries) would appear as legitimate admin actions in application logs.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Metabase (Cloud & Self-Hosted) | v1.58.0 through v1.58.23 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |
| Metabase (Cloud & Self-Hosted) | v1.59.0 through v1.59.20 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |
| Metabase (Cloud & Self-Hosted) | v1.60.0 through v1.60.16 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |
| Metabase (Cloud & Self-Hosted) | v1.61.0 through v1.61.10 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |
| Metabase (Cloud & Self-Hosted) | v1.62.0 through v1.62.8 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |
| Metabase (Cloud & Self-Hosted) | v1.63.0 through v1.63.4 | Vulnerable to unauthenticated SQLi via `/api/session/reset_password` |

### File System

No file system indicators were reported for this attack.

### Network

| Type | Value | Context |
|------|-------|---------|
| URI Pattern | `/api/session/reset_password` | Vulnerable endpoint; POST requests with 400 status indicate exploitation |
| URI Pattern | `/api/user/current` | GET requests with 200 status following the above indicate successful session hijack |

No attacker IP addresses, domains, or C2 infrastructure were disclosed in any source.

### Behavioral

- **Exploitation signature**: A `POST /api/session/reset_password` returning HTTP 400, followed by a `GET /api/user/current` returning HTTP 200, indicates successful exploitation and session hijack.
- **Post-exploitation**: Newly created admin accounts, unauthorized API key generation, queries against connected databases from unrecognized sessions, and bulk data exports should be investigated.
- **Session anomaly**: Entries in the `core_session` table that do not correspond to legitimate user logins.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated SQL injection against the Metabase `/api/session/reset_password` endpoint to gain initial access |
| T1505 | Server Software Component | Exploitation of the Metabase web application server component to achieve code execution via SQL injection |
| T1078 | Valid Accounts | Attacker uses SQL injection to create or hijack administrator accounts, gaining legitimate-appearing access |
| T1552.001 | Unsecured Credentials: Credentials In Files | Metabase stores database connection credentials in its application database; attacker extracts these after gaining admin access |
| T1530 | Data from Cloud Storage Object | Attacker uses stolen database credentials to access and exfiltrate data from connected databases and data warehouses |

## Impact Assessment

**Breadth**: All Metabase installations running versions 1.58 through 1.63 (both Cloud and self-hosted) are affected. Metabase is used by thousands of organizations worldwide for business intelligence. Three confirmed victims (Framework, Tally, LexisNexis) have been publicly identified, but the actual number is likely higher.

**Depth**: The vulnerability is maximally severe (CVSS 10.0). Exploitation grants unauthenticated remote attackers full administrator access, enabling theft of all connected database credentials and any data accessible through those connections. The cascading impact -- from a single Metabase instance to all connected databases -- makes this especially dangerous.

**Stealth**: The attack uses a legitimate API endpoint and, once admin access is obtained, post-exploitation actions resemble normal admin activity. Without specific log monitoring for the exploitation signature (POST 400 + GET 200 pattern), the attack may go undetected.

**Known victim impact**:
- **Framework**: Customer PII stolen (names, emails, login IPs, billing/shipping addresses, phone numbers). No payment or order data compromised.
- **Tally**: Email addresses and one-way password hashes exposed.
- **LexisNexis**: Metabase API impacted; systems disconnected pending investigation.

## Detection & Remediation

### Immediate Detection

Check web server / reverse proxy access logs for the exploitation signature:

```bash
# Search for POST to reset_password with 400 status (adjust log format as needed)
grep -E 'POST /api/session/reset_password.*" 400' /var/log/nginx/access.log
grep -E 'POST /api/session/reset_password.*" 400' /var/log/apache2/access.log

# Search Metabase activity logs for unauthorized admin actions
# Check the core_session table for sessions not associated with known user logins
```

Check for unauthorized admin accounts or API keys in the Metabase admin interface.

### Remediation

1. **Patch immediately**: Upgrade to the fixed version for your branch:
   - v1.58.24, v1.59.21, v1.60.17, v1.61.11, v1.62.9, or v1.63.5
2. **Block the endpoint** (if patching is not immediately possible): Block `POST /api/session/reset_password` at the reverse proxy / WAF level
3. **Clear all sessions**: Delete all rows from the `core_session` table in the Metabase application database
4. **Review API keys**: Audit and revoke any unrecognized API keys
5. **Audit admin accounts**: Check for unauthorized administrator accounts or privilege changes
6. **Rotate all database credentials**: Change passwords/credentials for every database connected to Metabase
7. **Review query logs**: Examine Metabase activity logs and connected database query logs for suspicious data access or exports

### Long-Term Hardening

- Place Metabase behind a reverse proxy with WAF capabilities to filter SQL injection payloads
- Restrict network access to Metabase admin endpoints to trusted IP ranges
- Enable and monitor Metabase audit logging
- Implement database credential rotation on a regular schedule
- Use database accounts with least-privilege permissions for Metabase connections
- Subscribe to Metabase security advisories for timely patching

## Detection Rules

These detections target the advisory-specified exploitation indicator: HTTP POST requests to the Metabase `/api/session/reset_password` endpoint. Rules are PoC/advisory-specific altitude, strict leniency. Compiles does not equal fires -- verify in your log pipeline before production deployment.

### Sigma: Metabase SQL Injection via Password Reset Endpoint

Detects POST requests to `/api/session/reset_password` returning 400 status in web server logs, the advisory-specified exploitation indicator.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check exit 0 (attacktag validator excluded — network-blocked from fetching MITRE ATT&CK data, not a rule issue). sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. No fitting product pipeline for webserver category — schema mapping skipped (no overclaim). Confidence medium (not high) because legitimate failed password reset attempts may also return 400; the distinctive signal is the 400+subsequent 200 on /api/user/current correlation, which is a two-event sequence not expressible in a single Sigma rule without aggregation. -->
```yaml
title: Metabase SQL Injection via Password Reset Endpoint
id: 8f2a1b3c-d4e5-4f6a-9b7c-1e2d3f4a5b6c
status: experimental
description: >
    Detects HTTP POST requests to the Metabase /api/session/reset_password
    endpoint returning a 400 status code, which is the advisory-specified
    indicator of SQL injection exploitation (GHSA-vwf4-m7j8-wcjf, CVSS 10.0).
references:
    - https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf
    - https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/
    - https://thehackernews.com/2026/08/metabase-zero-day-exploited-in-wild.html
author: Actioner
date: 2026/08/09
tags:
    - attack.t1190
    - attack.t1505
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/api/session/reset_password'
        sc-status: 400
    condition: selection
falsepositives:
    - Legitimate failed password reset attempts on Metabase instances
level: high
```

### Snort: Metabase SQLi Exploit POST to reset_password Endpoint

Detects HTTP POST requests to the Metabase `/api/session/reset_password` endpoint on the wire.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf -T -i lo exit 0 ("Snort successfully validated the configuration!"). Rule appended to local.rules for validation, then removed. Snort 2.9.20. Confidence medium: matches all POST requests to the endpoint (legitimate and malicious); cannot distinguish SQL injection payloads from normal reset requests at this altitude without payload-specific content matches (no PoC payload published). -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Metabase SQLi Exploit POST to reset_password Endpoint (GHSA-vwf4-m7j8-wcjf)"; flow:established,to_server; content:"POST"; http_method; content:"/api/session/reset_password"; http_uri; fast_pattern; classtype:web-application-attack; reference:url,github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf; sid:2100001; rev:1;)
```

### Suricata: Metabase SQLi Exploit POST to reset_password Endpoint

Detects HTTP POST requests to the Metabase `/api/session/reset_password` endpoint on the wire.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S /tmp/actioner/metabase-sqli-suricata.rules -l /tmp/actioner exit 0 ("Configuration provided was successfully loaded. Exiting."). Suricata 7.0.3. Uses dot-notation sticky buffers (http.method, http.uri). Confidence medium: same reasoning as Snort rule — matches all POSTs to the endpoint. For environments where the endpoint should be fully blocked (per mitigation guidance), confidence is effectively high since any POST is suspect. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Metabase SQLi Exploit POST to reset_password Endpoint (GHSA-vwf4-m7j8-wcjf)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/session/reset_password"; fast_pattern; classtype:web-application-attack; reference:url,github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf; metadata:author Actioner, created_at 2026-08-09; sid:2200001; rev:1;)
```

### YARA: N/A

No file-level indicators suitable for YARA detection in this topic. The vulnerability is a web application SQL injection with no malware binary, dropped file, or distinctive file artifact reported.

## Lessons Learned

1. **Credential storage is a cascading risk**: Metabase's design -- storing plaintext-equivalent credentials for all connected databases -- means a single application-layer vulnerability cascades into organization-wide database compromise. BI tools that aggregate database access are high-value targets and should be treated with the same security rigor as database servers themselves.

2. **Unauthenticated endpoints are attack surface**: The vulnerability existed in an endpoint that required no authentication. Password reset, account creation, and similar "public" API endpoints deserve heightened input validation scrutiny, especially when they interact with the application database.

3. **Zero-day response speed matters**: Metabase's timeline -- discovery on August 3, patches by August 6, disclosure on August 7 -- is relatively fast, but the window between exploitation and patch availability is where damage occurs. Organizations running self-hosted instances had no protection during this window unless they independently blocked the endpoint.

4. **Post-compromise hygiene is extensive**: Patching alone is insufficient. The advisory's remediation guidance (session clearing, API key audit, credential rotation, query log review) reflects the depth of access the attacker gains. Organizations must assume full compromise of all connected databases if exploitation is confirmed.

## Sources

- [Metabase Security Advisory GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) -- primary advisory with vulnerability details, affected versions, patched versions, and remediation guidance
- [BleepingComputer: Framework, Tally disclose Metabase data-theft attacks](https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/) -- victim impact details for Framework, Tally, and LexisNexis; attack timeline; exploitation indicators
- [The Hacker News: Metabase Zero-Day Exploited in Wild Allows Admin Access Without Authentication](https://thehackernews.com/2026/08/metabase-zero-day-exploited-in-wild.html) -- affected version ranges, exploitation details, Framework impact
- [Security Affairs: Metabase Zero-Day Exploited in the Wild, Exposing Admin Access and Sensitive Data](https://securityaffairs.com/196874/hacking/metabase-zero-day-exploited-in-the-wild-exposing-admin-access-and-sensitive-data.html) -- remediation steps, technical exploitation details, version impact

---
*Report generated by Actioner*
