# Technical Analysis Report: Metabase Unauthenticated SQL Injection Zero-Day (2026-08-08)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-08
Version: 1.0

## Executive Summary

A critical (CVSS 10.0) unauthenticated SQL injection vulnerability in Metabase versions 0.58+ (OSS) / 1.58+ (Enterprise) has been actively exploited as a zero-day to steal customer data from multiple organizations. The flaw resides in the `/api/session/reset_password` endpoint and allows a remote, unauthenticated attacker to inject arbitrary SQL into the Metabase application database, gaining administrator access. From there, the attacker can modify application configuration, steal stored database credentials for connected data warehouses, read any accessible data, and export it. Metabase Cloud SaaS and self-hosted installations are both affected.

Framework (modular laptop manufacturer) disclosed that all customers' names, emails, IP addresses, billing/shipping addresses, phone numbers, and company names were stolen. Tally (form-building platform) disclosed that customer email addresses and cryptographic password hashes were exposed. LexisNexis also reported compromise of its Metabase-connected services (Diligence, Metabase API, Newsdesk) through a third-party vendor. Active exploitation was confirmed on August 3, 2026, with Metabase issuing patches and notifications on August 6, 2026. No CVE identifier has been assigned; the vulnerability is tracked as GHSA-vwf4-m7j8-wcjf.

## Background: Metabase

Metabase is a widely used open-source business intelligence and analytics platform that connects to an organization's databases and data warehouses, enabling users to build dashboards, run queries, and visualize data without writing SQL. It is available as a self-hosted application (OSS and Enterprise editions) and as Metabase Cloud (SaaS). Metabase's application database stores user accounts, credentials for connected databases, saved queries, and configuration -- making it a high-value target. The platform is used by thousands of organizations across industries, from startups to enterprises.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-03 | Active exploitation of zero-day; attacker accesses Framework and Tally Metabase Cloud instances |
| 2026-08-06 | Metabase identifies and patches the vulnerability; notifies affected customers including Framework and Tally |
| 2026-08-07 | Framework sends breach notification email to all customers; Metabase publishes security blog post; BleepingComputer publishes coverage |
| 2026-08-07 | Tally sends breach notification email to affected customers |
| 2026-08-08 | The Hacker News publishes coverage; GitHub Security Advisory GHSA-vwf4-m7j8-wcjf published |

## Root Cause: Unauthenticated SQL Injection in Password Reset Endpoint

The vulnerability exists in the `/api/session/reset_password` endpoint, which is unauthenticated by design (it handles password reset requests). Insufficient input sanitization allows an attacker to inject arbitrary SQL statements into the Metabase application database. The SQL injection grants the attacker the ability to escalate to administrator privileges on the Metabase instance without any prior authentication. The CVSS 3.1 vector is `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` -- network-accessible, low complexity, no privileges required, no user interaction, changed scope, with high impact to confidentiality, integrity, and availability.

## Technical Analysis of the Malicious Payload

### 1. Initial Access — SQL Injection via Password Reset

The attacker sends a crafted `POST` request to `/api/session/reset_password` containing SQL injection payloads. The endpoint processes the input without adequate parameterization, allowing the injected SQL to execute against the Metabase application database. The POST request returns an HTTP 400 status code (indicating the password reset itself "fails"), but the injected SQL executes successfully as a side effect, granting the attacker administrator-level access.

### 2. Privilege Escalation — Administrator Access

Following the SQL injection, the attacker issues a `GET /api/user/current` request, which returns HTTP 200, confirming they have gained authenticated administrator access to the Metabase instance. This two-step pattern (POST 400 followed by GET 200) is the primary indicator of compromise in application logs.

### 3. Post-Exploitation — Data Exfiltration

With administrator access, the attacker can:
- **Modify application configuration** to expand access or disable security controls
- **Steal stored database credentials** for all connected data warehouses and databases
- **Query and export data** from any connected database through Metabase's query interface
- **Create or modify administrator accounts** for persistent access
- **Generate API keys** for continued programmatic access

### 4. Platform-Specific Behavior

#### Metabase Cloud (SaaS)
Confirmed exploited. Metabase Cloud instances were directly targeted. The attacker gained access to tenant data through the shared platform. Metabase has patched all Cloud instances.

#### Self-Hosted Instances
Equally vulnerable if the `/api/session/reset_password` endpoint is publicly accessible. Self-hosted operators must upgrade manually.

### 5. Anti-Forensics / Evasion Techniques

No specific anti-forensics techniques have been disclosed in the available reporting. The attack leverages a legitimate API endpoint with standard HTTP methods, making it difficult to distinguish from normal password reset traffic without inspecting the request body for SQL injection payloads.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Vulnerable Versions (OSS 0.x / Enterprise 1.x) | Description |
|---------------------|--------------------------------------------------|-------------|
| Metabase OSS / Enterprise | >= 0.58.0 / 1.58.0, < 0.58.24 / 1.58.24 | Unauthenticated SQLi in `/api/session/reset_password` |
| Metabase OSS / Enterprise | >= 0.59.0 / 1.59.0, < 0.59.21 / 1.59.21 | Same vulnerability |
| Metabase OSS / Enterprise | >= 0.60.0 / 1.60.0, < 0.60.17 / 1.60.17 | Same vulnerability |
| Metabase OSS / Enterprise | >= 0.61.0 / 1.61.0, < 0.61.11 / 1.61.11 | Same vulnerability |
| Metabase OSS / Enterprise | >= 0.62.0 / 1.62.0, < 0.62.9 / 1.62.9 | Same vulnerability |
| Metabase OSS / Enterprise | >= 0.63.0 / 1.63.0, < 0.63.5 / 1.63.5 | Same vulnerability |

### File System

No file-level indicators have been published for this vulnerability. The attack is entirely API/network-based.

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `POST /api/session/reset_password` (HTTP 400) | Exploitation endpoint; SQL injection entry point |
| URL Pattern | `GET /api/user/current` (HTTP 200) | Post-exploitation validation; confirms admin access gained |

### Behavioral

The primary behavioral indicator is a sequential pair of HTTP requests in web server or reverse proxy access logs:

1. `POST /api/session/reset_password` returning HTTP status **400**
2. Followed by `GET /api/user/current` returning HTTP status **200**

This sequence — a "failed" password reset immediately followed by successful authentication as the current user — is anomalous and strongly indicative of successful exploitation. In normal operation, a password reset returning 400 would not be followed by an authenticated session.

Additional post-exploitation behaviors to monitor:
- Unexpected administrator account creation or modification
- Unusual database credential access or rotation through Metabase
- Bulk data export operations from connected databases
- New or unrecognized API key generation
- Modifications to application configuration (especially security settings)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated SQL injection against Metabase `/api/session/reset_password` endpoint |
| T1078 | Valid Accounts | Attacker gains legitimate administrator access through SQLi privilege escalation |
| T1555 | Credentials from Password Stores | Stored database connection credentials retrieved from Metabase's application database (which stores DB creds for all connected sources) |
| T1213 | Data from Information Repositories | Customer data accessed and exported via Metabase's query interface into connected databases/data warehouses |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration over HTTP, the same protocol used for the initial exploitation |

## Impact Assessment

**Breadth:** All Metabase Cloud and self-hosted instances running versions 0.58+ (OSS) / 1.58+ (Enterprise) are vulnerable. Metabase is used by thousands of organizations. At least three victims are publicly confirmed: Framework (all customers affected -- estimated hundreds of thousands), Tally (email addresses and password hashes), and LexisNexis (Diligence, API, and Newsdesk services).

**Depth:** CVSS 10.0 -- maximum severity. The vulnerability requires no authentication, no user interaction, has low attack complexity, and impacts confidentiality, integrity, and availability with changed scope. Successful exploitation grants full administrator access to the Metabase instance and, by extension, to all connected databases.

**Stealth:** The attack uses a legitimate API endpoint with standard HTTP methods. Without specific log monitoring for the POST-400/GET-200 pattern, exploitation would be difficult to distinguish from normal traffic.

## Detection & Remediation

### Immediate Detection

Search web server access logs (nginx, Apache, load balancer, WAF) and Metabase application logs for the exploitation pattern:

```bash
# Search for exploitation pattern in access logs
grep "POST /api/session/reset_password" /var/log/nginx/access.log | grep " 400 "

# Cross-reference with successful /api/user/current requests from same source
grep "GET /api/user/current" /var/log/nginx/access.log | grep " 200 "
```

Additionally, check the Metabase application database directly:

```sql
-- Check for unexpected sessions (post-exploitation persistence)
SELECT * FROM core_session ORDER BY created_at DESC LIMIT 50;

-- Check for unexpected admin users
SELECT * FROM core_user WHERE is_superuser = true;

-- Review API keys
SELECT * FROM api_key ORDER BY created_at DESC;
```

### Remediation

1. **Upgrade immediately** to the minimum safe release for your major version:
   - OSS: 0.58.24, 0.59.21, 0.60.17, 0.61.11, 0.62.9, or 0.63.5
   - Enterprise: 1.58.24, 1.59.21, 1.60.17, 1.61.11, 1.62.9, or 1.63.5
2. **If unable to upgrade immediately**, block access to `/api/session/reset_password` at the reverse proxy or WAF level as a temporary mitigation (this will disable password reset functionality)
3. **Revoke all active sessions**: `DELETE FROM core_session;` or `TRUNCATE TABLE core_session;`
4. **Review and revoke unrecognized API keys**
5. **Audit administrator accounts** for unexpected creations or modifications
6. **Rotate credentials** for all connected databases and data warehouses
7. **Review data warehouse logs** for unauthorized queries or data exports during the exposure window
8. **Examine Metabase activity and query history** for suspicious operations

### Long-Term Hardening

- Restrict network access to Metabase admin API endpoints using a WAF or reverse proxy
- Implement monitoring for the detection patterns described above
- Enable audit logging on all connected databases to detect unauthorized access
- Consider network segmentation to limit blast radius if the BI platform is compromised
- Review the principle of least privilege for database credentials stored in Metabase

## Detection Rules

These detections target the Metabase SQL injection exploitation pattern via the `/api/session/reset_password` endpoint. They cover web server logs (Sigma) and network traffic (Snort, Suricata) at PoC/advisory-specific altitude. Note: compiles does not equal fires -- verify against your log pipeline before production deployment.

### Sigma: Metabase SQLi Exploitation via Password Reset Endpoint

Detects HTTP POST requests to the Metabase `/api/session/reset_password` endpoint returning HTTP 400, which is the primary indicator of the GHSA-vwf4-m7j8-wcjf SQL injection exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (ATT&CK data download 403); splunk convert 0; log_scale convert 0. Keys on the exact exploit endpoint + anomalous 400 response. The 400 status is distinctive — legitimate reset_password calls return 200/204 on success or 404/422 on invalid input, not 400 with SQL error side effects. FP: a misconfigured client repeatedly sending malformed reset requests could trigger; filter by volume. No pipeline mapping available for webserver logsource. -->
```yaml
title: Metabase SQLi Exploitation via Password Reset Endpoint
id: c8e2f1a4-9b3d-4e7f-a5c6-1d0e8f2b3a4c
status: experimental
description: >
    Detects POST requests to the Metabase /api/session/reset_password endpoint
    returning HTTP 400, indicating potential exploitation of the unauthenticated
    SQL injection vulnerability (GHSA-vwf4-m7j8-wcjf, CVSS 10.0).
references:
    - https://www.metabase.com/blog/security-update
    - https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf
    - https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/
author: Actioner
date: 2026-08-08
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|endswith: '/api/session/reset_password'
        sc-status: 400
    condition: selection
falsepositives:
    - Misconfigured clients sending malformed password reset requests
    - Security scanners probing the endpoint
level: high
```

<!-- revision: Dropped "Sigma: Metabase Post-Exploitation Admin Access Validation" — GET /api/user/current returning 200 fires on every authenticated page load (normal session validation); pure noise without SIEM-specific cross-event correlation that Sigma cannot express. -->

### Snort: Metabase SQLi POST to reset_password Endpoint

Detects HTTP POST requests targeting the Metabase `/api/session/reset_password` endpoint over the network, indicating potential exploitation of the unauthenticated SQL injection.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -c /etc/snort/snort.conf -T exit 0 (validated via local.rules include). Snort 2 syntax — uses tcp + http_method/http_uri sticky buffers. Keys on POST method + exact URI path. fast_pattern on the URI string. FP risk low — this exact endpoint path is Metabase-specific. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Metabase SQLi POST to reset_password Endpoint (GHSA-vwf4-m7j8-wcjf)"; flow:established,to_server; content:"POST"; http_method; content:"/api/session/reset_password"; http_uri; fast_pattern; classtype:web-application-attack; reference:url,github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf; reference:url,www.metabase.com/blog/security-update; sid:2100101; rev:1;)
```

### Suricata: Metabase SQLi POST to reset_password Endpoint

Detects HTTP POST requests to the Metabase `/api/session/reset_password` endpoint, the attack vector for the unauthenticated SQL injection vulnerability GHSA-vwf4-m7j8-wcjf.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S ... -l /tmp/actioner exit 0. Uses dot-notation sticky buffers (http.method, http.uri). fast_pattern on the URI path. Direction is EXTERNAL_NET -> HOME_NET to match inbound exploitation attempts. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Metabase SQLi POST to reset_password Endpoint (GHSA-vwf4-m7j8-wcjf)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/session/reset_password"; fast_pattern; classtype:web-application-attack; reference:url,github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf; reference:url,www.metabase.com/blog/security-update; metadata:author Actioner, created_at 2026-08-08; sid:2200101; rev:1;)
```

### YARA: N/A

No file-level indicators (malware samples, dropped files, byte patterns) have been published for this vulnerability. The attack is entirely API/network-based.

## Lessons Learned

This incident underscores several critical themes:

1. **SaaS supply-chain risk is real.** Framework, Tally, and LexisNexis were all compromised not through their own code, but through a third-party analytics platform. Organizations must treat SaaS integrations as extensions of their own attack surface and apply the same rigor to vendor security assessments and monitoring.

2. **Unauthenticated endpoints on internal tools are high-value targets.** The vulnerable endpoint was unauthenticated by design (password reset). Any unauthenticated endpoint that touches the application database is a critical attack surface that demands rigorous input validation and parameterized queries.

3. **Credential storage in BI platforms is a force multiplier.** Metabase stores database connection credentials for all connected data sources. Compromising the BI platform gives an attacker a pivot point into every connected database, dramatically amplifying the impact of a single vulnerability.

4. **Zero-day patching speed matters.** The window between active exploitation (Aug 3) and patch availability (Aug 6) was three days. Self-hosted operators who cannot apply patches quickly should implement compensating controls (endpoint blocking, WAF rules) for critical admin/auth endpoints.

## Sources

- [Metabase Security Update Blog](https://www.metabase.com/blog/security-update) — Primary vendor advisory with affected versions, remediation steps, and detection patterns
- [GitHub Security Advisory GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) — Formal advisory with CVSS vector, affected version ranges, and patched releases
- [BleepingComputer: Framework, Tally disclose Metabase data theft attacks](https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/) — Reporting on Framework, Tally, and LexisNexis breaches with victim impact details
- [The Hacker News: Metabase Zero-Day Exploited in Wild](https://thehackernews.com/2026/08/metabase-zero-day-exploited-in-wild.html) — Coverage of active exploitation and technical exploitation pattern
- [TechCrunch: Framework notifies all customers of data breach](https://techcrunch.com/2026/08/07/computer-maker-framework-notifies-all-customers-of-a-data-breach/) — Framework's breach disclosure affecting all customers
- [MyEmailTools: Tally data breach update](https://myemailtools.com/tally-data-breach-update/) — Tally's disclosure with details on exposed email addresses and password hashes

---
*Report generated by Actioner*
