# Technical Analysis Report: Metabase Zero-Day SQL Injection — GHSA-vwf4-m7j8-wcjf (2026-08-10)

<!-- revision: v1.0 DRAFT -> v1.1 FINAL. Dropped 4 rules (Sigma 2/3, Suricata SID 2026081002/2026081003) — all fire on normal authenticated traffic, pure noise without correlation. Fixed ATT&CK mapping: removed T1552.001 (credentials are in DB not files, kept T1552 parent), replaced T1005 with T1213 (data from remote repositories not local system), removed T1530 (Snowflake/BigQuery are SQL warehouses not storage buckets). Added dual-versioning note for 0.x/1.x. Added reverse-proxy caveat to remediation. Updated detection rule count from 6 to 2. -->

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-10
Version: 1.1 (FINAL)

## Executive Summary

A critical (CVSS 10.0) unauthenticated SQL injection zero-day in Metabase (GHSA-vwf4-m7j8-wcjf) is being actively exploited in the wild. The vulnerability affects all Metabase versions 1.58 and above and allows a remote, unauthenticated attacker to inject arbitrary SQL into the Metabase application database through the `/api/session/reset_password` endpoint. Successful exploitation grants full administrator access, enabling attackers to modify application configuration, steal stored database credentials, and exfiltrate data from all connected data sources.

Confirmed victims include Framework (laptop manufacturer), Tally (form builder), and LexisNexis (via a third-party vendor). Framework confirmed exposure of customer PII including full names, email addresses, login IPs, billing/shipping addresses, phone numbers, company names, and tax identifiers. Tally confirmed exposure of email addresses and cryptographic password hashes. Metabase discovered the flaw when attackers exploited it against Metabase Cloud infrastructure itself. Patches were released on August 7, 2026 across six release branches. Organizations running self-hosted Metabase should patch immediately or block the vulnerable endpoint at the network perimeter.

## Background: Metabase

Metabase is an open-source business intelligence and analytics platform that allows organizations to query, visualize, and share data from connected databases. It is widely deployed as both a cloud-hosted (Metabase Cloud) and self-hosted application, with thousands of internet-facing instances. Metabase connects to backend databases (PostgreSQL, MySQL, Snowflake, BigQuery, etc.) using stored credentials, making it a high-value target — compromising Metabase can cascade into compromise of every connected data warehouse.

The application exposes a REST API under `/api/` for all operations including authentication, user management, database configuration, and query execution. The `/api/session/reset_password` endpoint, intended for password reset workflows, became the attack vector for this zero-day.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-03 | Earliest confirmed attacker access to vulnerable Metabase instances |
| 2026-08-06 | Metabase notifies Framework of the vulnerability after detecting exploitation on Metabase Cloud |
| 2026-08-06 | Metabase publishes security update blog post; Cloud instances auto-patched |
| 2026-08-07 | Patches released for self-hosted: 0.58.24, 0.59.21, 0.60.17, 0.61.11, 0.62.9, 0.63.5 |
| 2026-08-08 | Public disclosure via security media; Framework and Tally disclose customer data breaches |

## Root Cause: Unauthenticated SQL Injection in Application Database

The vulnerability is an unauthenticated SQL injection in the Metabase application database (the internal database Metabase uses to store its own configuration, users, sessions, and connected database credentials). The attack vector is the `/api/session/reset_password` endpoint, which accepts POST requests without requiring prior authentication.

By injecting arbitrary SQL through this endpoint, an attacker can:
1. Create or hijack administrator accounts in the Metabase application
2. Bypass all authentication and authorization controls
3. Gain full administrative access to the Metabase instance

The specific SQL injection payload mechanics have not been publicly disclosed by Metabase, though the advisory confirms the injection targets the application database itself, not the connected data warehouses. The application database stores credentials for all connected databases in its configuration tables.

## Technical Analysis of the Malicious Payload

### 1. Initial Exploitation — SQL Injection via Reset Password Endpoint

The attack begins with an unauthenticated HTTP POST request to `/api/session/reset_password`. The specific parameter(s) carrying the SQL injection payload have not been publicly detailed, but the documented detection signature is:

```
POST /api/session/reset_password HTTP/1.1
```

A successful injection attempt returns HTTP 400 (the endpoint's normal error response), but the SQL has already been executed against the application database, granting the attacker admin privileges.

### 2. Post-Exploitation — Admin Verification and Credential Theft

Immediately following exploitation, attackers issue:

```
GET /api/user/current HTTP/1.1
```

A 200 response confirms the attacker has gained an authenticated session with administrator privileges. From this point, the attacker can:

- Access `/api/database` to enumerate all connected database configurations including stored credentials
- Modify application settings
- Create API keys for persistent access
- Execute queries against connected data sources
- Export data through the Metabase query interface

### 3. Data Exfiltration

With admin access and database credentials, attackers accessed connected data warehouses and exfiltrated:
- **Framework:** Customer PII (names, emails, login IPs, addresses, phone numbers, company names, VAT/EIN)
- **Tally:** User email addresses and password hashes
- **LexisNexis:** Scope unclear; Metabase API confirmed compromised via third-party vendor

### 4. Platform-Specific Behavior

The vulnerability affects Metabase regardless of deployment platform (Docker, JAR, cloud). Both Metabase Cloud and self-hosted instances running vulnerable versions are affected. Metabase uses dual version numbering: 0.x releases are the open-source (Community) edition and 1.x releases are the Enterprise/Pro edition, but both share the same codebase and are affected by this vulnerability. The patched versions listed in this report use the 0.x numbering convention; the corresponding Enterprise versions are 1.58.24, 1.59.21, 1.60.17, 1.61.11, 1.62.9, and 1.63.5. The application database backend (H2, PostgreSQL, MySQL) may influence exploitation specifics, but all are confirmed affected.

### 5. Anti-Forensics / Evasion Techniques

No specific anti-forensic techniques have been documented. The attack is notable for its simplicity — a single unauthenticated HTTP request achieves admin access, requiring no malware, persistence mechanisms, or lateral movement tools.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|---------------------|-------------|
| Metabase (all editions) | >= 0.58.0 / 1.58.0, < 0.58.24 / 1.58.24 | Unauthenticated SQLi in application database via `/api/session/reset_password` |
| Metabase (all editions) | >= 0.59.0 / 1.59.0, < 0.59.21 / 1.59.21 | Same vulnerability |
| Metabase (all editions) | >= 0.60.0 / 1.60.0, < 0.60.17 / 1.60.17 | Same vulnerability |
| Metabase (all editions) | >= 0.61.0 / 1.61.0, < 0.61.11 / 1.61.11 | Same vulnerability |
| Metabase (all editions) | >= 0.62.0 / 1.62.0, < 0.62.9 / 1.62.9 | Same vulnerability |
| Metabase (all editions) | >= 0.63.0 / 1.63.0, < 0.63.5 / 1.63.5 | Same vulnerability |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/api/session/reset_password` | Exploitation endpoint (POST) |
| URL Pattern | `/api/user/current` | Post-exploitation admin verification (GET, 200 response) |
| URL Pattern | `/api/database` | Post-exploitation credential theft (GET) |

### Behavioral

The documented attack signature in web server / reverse proxy access logs:

1. `POST /api/session/reset_password` with HTTP 400 status code
2. Followed by `GET /api/user/current` with HTTP 200 status code (from the same source IP, within a short time window)

Additional post-exploitation indicators:
- Unexpected entries in the `core_session` table
- Unrecognized API keys
- New or modified administrator accounts
- Unusual queries against connected databases in Metabase query logs

**Note:** No IP addresses, domains, file hashes, or threat actor attribution have been published for this campaign. The source articles and vendor advisory contain no network-level IOCs beyond the URL patterns above.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated SQLi against the Metabase `/api/session/reset_password` endpoint to gain admin access |
| T1078 | Valid Accounts | Attacker gains legitimate admin session after SQLi exploitation; subsequent API calls use valid session tokens |
| T1552 | Unsecured Credentials | Database connection credentials stored in Metabase application database are extracted post-exploitation |
| T1213 | Data from Information Repositories | Attacker exports data from connected data warehouses (Snowflake, BigQuery, PostgreSQL) using stolen credentials and Metabase query capabilities |

## Impact Assessment

**Breadth:** All Metabase deployments running versions 0.58+ / 1.58+ are affected. Metabase has millions of downloads and is widely used across enterprises, startups, and SaaS platforms. Internet-facing self-hosted instances are directly exploitable without authentication.

**Depth:** CVSS 10.0 — the maximum severity score. The vulnerability requires no authentication, no user interaction, and grants complete administrative control. The cascading impact through stored database credentials can expose entire data infrastructure.

**Confirmed Victims:**
- **Framework:** Customer PII exposed (names, emails, IPs, addresses, phone numbers, tax IDs)
- **Tally:** User emails and password hashes exposed
- **LexisNexis:** Confirmed compromise via third-party vendor hosting Metabase

**Stealth:** The attack generates minimal forensic evidence — a single POST request achieving admin access. Standard access logging captures the request, but without specific monitoring for this endpoint, exploitation may go undetected.

## Detection & Remediation

### Immediate Detection

**Check web server / reverse proxy logs for the exploitation pattern:**

```bash
# Nginx/Apache access logs - look for the exploit endpoint
grep -E "POST.*/api/session/reset_password" /var/log/nginx/access.log /var/log/httpd/access_log

# Correlate with successful admin access
grep -E "GET.*/api/user/current.*200" /var/log/nginx/access.log /var/log/httpd/access_log
```

**Check Metabase application database for unauthorized access:**

```sql
-- Look for unexpected sessions (connect to Metabase app DB)
SELECT * FROM core_session ORDER BY created_at DESC LIMIT 50;

-- Check for unauthorized admin accounts
SELECT id, email, is_superuser, date_joined, last_login FROM core_user WHERE is_superuser = true;

-- Check for unauthorized API keys
SELECT * FROM api_key ORDER BY created_at DESC;
```

### Remediation

1. **Patch immediately** to one of the fixed versions: 0.58.24, 0.59.21, 0.60.17, 0.61.11, 0.62.9, or 0.63.5 (Enterprise: 1.58.24, 1.59.21, 1.60.17, 1.61.11, 1.62.9, or 1.63.5)
2. **If patching is not immediately possible**, block access to `/api/session/reset_password` at the reverse proxy / WAF / load balancer level. Note: this assumes a reverse proxy or WAF is deployed in front of Metabase; if the application is exposed directly, use host-based firewall rules or iptables with string matching, or take the instance offline until patching is complete.
3. **Revoke all active sessions** — delete all rows from the `core_session` table in the Metabase application database
4. **Audit API keys** — review and delete any unrecognized API keys
5. **Audit admin accounts** — verify all superuser accounts are legitimate; remove unauthorized ones
6. **Rotate all connected database credentials** — assume all credentials stored in Metabase are compromised
7. **Review data warehouse access logs** — check connected database audit logs for unauthorized queries during the exposure window
8. **Review Metabase query logs** — audit the query history for unauthorized data exports

### Long-Term Hardening

- **Never expose Metabase directly to the internet** — place it behind a VPN or zero-trust network access solution
- **Enable web application firewall (WAF)** rules in front of Metabase instances
- **Implement network segmentation** — restrict Metabase's access to only required database endpoints
- **Monitor the `/api/session/reset_password` endpoint** — alert on any POST requests to this endpoint
- **Subscribe to Metabase security advisories** at [metabase.com/blog](https://www.metabase.com/blog)
- **Regularly rotate database credentials** stored in Metabase

## Detection Rules

One Sigma rule and one Suricata rule target the initial exploitation vector: POST requests to the `/api/session/reset_password` endpoint. No file-level indicators exist, so YARA rules are not applicable.

> **Note:** Four additional rules covering post-exploitation endpoints (`/api/user/current` and `/api/database`) were evaluated and dropped during review — both endpoints are called routinely during normal authenticated Metabase usage, making standalone rules against them high-false-positive noise without temporal correlation to the initial exploit request.

### Sigma Rule: Metabase SQLi Exploitation via Reset Password Endpoint

Detects POST requests to the vulnerable `/api/session/reset_password` endpoint, the documented attack vector for GHSA-vwf4-m7j8-wcjf.
**Compile: compiles (Splunk + LogScale) | Confidence: high**

<!-- audit: sigma check exit 0 (excluding attacktag — MITRE data unreachable from sandbox). sigma convert --without-pipeline -t splunk exit 0 -> "cs-method"="POST" "cs-uri-stem"="*/api/session/reset_password*". sigma convert --without-pipeline -t log_scale exit 0. No defanged values. Field names match webserver logsource conventions (cs-method, cs-uri-stem). FP: legitimate password resets exist but are uncommon and worth investigating during an active campaign. -->

```yaml
title: Metabase SQLi Exploitation via Reset Password Endpoint
id: 5b178f50-db2d-41e8-ba14-9dabfdac3710
status: experimental
description: >
    Detects HTTP POST requests to the Metabase /api/session/reset_password endpoint, the attack vector for the critical unauthenticated SQL injection (GHSA-vwf4-m7j8-wcjf, CVSS 10.0).
references:
    - https://www.metabase.com/blog/security-update
    - https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/
    - https://thehackernews.com/2026/08/metabase-zero-day-exploited-in-wild.html
author: Actioner
date: 2026-08-10
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/api/session/reset_password'
    condition: selection
falsepositives:
    - Legitimate password reset requests by authenticated Metabase users
level: high
```

**Splunk conversion:**
```
"cs-method"="POST" "cs-uri-stem"="*/api/session/reset_password*"
```

**CrowdStrike LogScale conversion:**
```
"cs-method"=/^POST$/i "cs-uri-stem"=/\/api\/session\/reset_password/i
```

### Suricata Rule

One Suricata rule targeting the initial exploitation endpoint. This rule uses Suricata's `http.method` and `http.uri` sticky buffers for efficient matching.
**Compile: uncompiled (structural check only) | Confidence: high**

<!-- audit: suricata/snort not installed in sandbox; rule validated by manual structural review only. Uses standard Suricata 7.x syntax: flow:established,to_server, http.method/http.uri sticky buffers. SID 2026081001. -->

```
# Metabase SQLi Zero-Day (GHSA-vwf4-m7j8-wcjf) - Suricata Rule
# Reference: https://www.metabase.com/blog/security-update

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"METABASE SQLi - POST to /api/session/reset_password (GHSA-vwf4-m7j8-wcjf)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/session/reset_password"; classtype:web-application-attack; sid:2026081001; rev:1; metadata:created_at 2026_08_10, updated_at 2026_08_10;)
```

### YARA Rules

No production-ready YARA detection. This vulnerability is exploited entirely via HTTP requests with no file-level artifacts (no malware, no dropped files, no modified binaries).

## Lessons Learned

1. **Stored credentials are a cascading risk.** Metabase's design of storing database credentials in its own application database means that a single SQLi in Metabase can cascade into full compromise of every connected data source. Organizations should evaluate whether BI tools need direct credential access or whether delegated authentication (OAuth, IAM roles) is feasible.

2. **Zero-day exploitation windows are shrinking — but so is response time.** The attacker exploited this vulnerability before Metabase knew it existed. The vendor discovered the flaw through active exploitation on its own infrastructure, highlighting that even well-resourced vendors can be caught off guard. The 3-4 day window between first exploitation (Aug 3) and patch availability (Aug 7) was enough for confirmed breaches at multiple organizations.

3. **Internet-facing analytics tools are high-value targets.** BI platforms like Metabase aggregate access to multiple data sources behind a single authentication boundary. Placing them behind VPNs or zero-trust access controls significantly reduces the attack surface for unauthenticated vulnerabilities like this one.

4. **Behavioral log patterns matter when IOCs are sparse.** This campaign produced no IP addresses, domains, or file hashes for blocklisting. The only detection available is the behavioral pattern in web server logs (POST to reset_password followed by GET to user/current). Organizations not logging Metabase API access have no forensic visibility.

## Sources

- [Metabase Security Update Blog Post](https://www.metabase.com/blog/security-update) — primary vendor advisory with affected versions, detection patterns, and remediation guidance
- [BleepingComputer: Framework, Tally Disclose Metabase Data Theft Attacks](https://www.bleepingcomputer.com/news/security/framework-tally-disclose-metabase-data-theft-attacks/) — breach disclosures from Framework and Tally with victim impact details
- [The Hacker News: Metabase Zero-Day Exploited in Wild](https://thehackernews.com/2026/08/metabase-zero-day-exploited-in-wild.html) — technical coverage with affected version ranges and remediation steps
- [Security Affairs: Metabase Zero-Day Exploited in the Wild](https://securityaffairs.com/196874/hacking/metabase-zero-day-exploited-in-the-wild-exposing-admin-access-and-sensitive-data.html) — additional reporting on exploitation scope and post-exploitation actions
- [GitHub Security Advisory GHSA-vwf4-m7j8-wcjf](https://github.com/advisories/GHSA-vwf4-m7j8-wcjf) — formal advisory identifier (not publicly accessible at time of report)

---
*Report generated by Actioner*
