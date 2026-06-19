# Klue OAuth Token Abuse Supply Chain Attack (Icarus Threat Actors)

**Date:** 2026-06-19
**TLP:** CLEAR
**Status:** FINAL
**Sector:** SaaS / CRM / Cybersecurity

---

## Executive Summary

In June 2026, threat actor group Icarus compromised Klue's backend infrastructure by exploiting a long-disused but still active credential originally created for abandoned third-party integration prototyping. The attackers deployed code to harvest OAuth tokens that Klue customers use to connect their CRM and collaboration platforms (Salesforce, HubSpot, SharePoint, Zoom, Gong, Chorus, Clari, Google Drive, Slack). Using stolen OAuth tokens, the attackers directly queried customer Salesforce REST API endpoints, exfiltrating CRM data including business contacts, price quotes, sales communications, and competitive intelligence. The attack impacted multiple organizations including cybersecurity firms Huntress and Recorded Future. Salesforce disabled the Klue Battlecards app integration on June 17, 2026. Stolen data was uploaded to gofile[.]io and used for extortion. This is a third-party SaaS integration supply chain attack that highlights the risk of non-human identity (NHI) credential management in cloud integration ecosystems.

---

## Background: Klue and Salesforce Integration

[Klue](https://klue.com) is a competitive intelligence platform that integrates with CRM systems (Salesforce, HubSpot), collaboration tools (Slack, Google Drive, SharePoint), and sales intelligence platforms (Gong, Chorus, Clari) via OAuth-based API connections. The Klue Battlecards app is a Salesforce AppExchange integration that provides sales teams with competitive intelligence directly within their CRM workflow. These integrations require persistent OAuth tokens with broad data access scopes, creating non-human identities (NHIs) that typically receive less monitoring than employee accounts.

Salesforce is the world's largest CRM platform. Its Event Monitoring and EventLogFile features provide audit logging of API access, including REST API queries, user agents, and source IPs -- which proved critical for forensic analysis of this attack.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-28 | Icarus threat actor group first observed active, with two earlier victims documented |
| Pre-June 11 | Attacker gains access to Klue backend infrastructure via a long-disused, still-active credential created for abandoned integration prototyping |
| 2026-06-11 | Anomalous behavior detected in Klue system connecting to customer integrations; attack initiated targeting integration infrastructure |
| 2026-06-12 | Klue identifies unauthorized activity; threat actor posts "get ready; big corps getting listed"; Klue begins deactivating OAuth tokens |
| 2026-06-13 | Klue issues general customer alert (no specific victim identification) |
| 2026-06-16 | Icarus publishes stolen data to leak site; extortion emails begin reaching Huntress staff with subject "top secret email" |
| 2026-06-17 | Salesforce disables the Klue Battlecards app integration platform-wide |
| 2026-06-18 | Huntress publishes detailed incident investigation blog post |
| 2026-06-19 | Public disclosure by SecurityWeek, The Hacker News; Recorded Future confirms impact |

---

## Root Cause: Dormant Integration Credential

The attacker exploited "a long-disused but still active credential" originally created by Klue for prototyping an abandoned third-party integration. This credential provided access to Klue's backend infrastructure, from which the attacker:

1. Connected to Klue's backend servers
2. Executed unauthorized commands
3. Pushed code updates that harvested OAuth tokens for customer integrations
4. Used those OAuth tokens to directly query customer CRM platforms

This is a textbook non-human identity (NHI) security failure: a credential created for development/prototyping purposes was never rotated or revoked after the integration was abandoned, leaving persistent infrastructure access.

---

## Technical Analysis

### 1. Initial Access: Dormant Credential Exploitation

The attacker leveraged a stale credential to access Klue's backend infrastructure. The exact mechanism of credential compromise is not publicly disclosed, but the credential had been inactive long enough that its continued existence represented a governance failure rather than an active monitoring target.

### 2. Token Harvesting: OAuth Credential Collection

Once inside Klue's infrastructure, the attacker deployed code that systematically collected OAuth tokens used by Klue customers to connect their platforms. These tokens provided direct API access to customer SaaS instances without requiring customer credentials. Affected integrations included Salesforce, HubSpot, SharePoint, Zoom, Gong, Chorus, Clari, Google Drive, and Slack.

### 3. Data Exfiltration: Salesforce REST API Abuse

Using harvested OAuth tokens, the attackers queried customer Salesforce instances directly through the REST API. Based on Huntress's forensic analysis of Salesforce Event Monitoring logs:

**API Endpoint Targeted:**
- Nearly all malicious requests targeted `/services/data/v59.0/query/<STRING>`
- Attackers used QueryMore cursor pagination for large result sets
- Initial reconnaissance queries hit `/services/data/v59.0/sobjects` (object enumeration)

**Query Volume and Patterns:**
- Approximately 1,000 queries in 15 minutes during peak activity
- Sustained extraction windows lasting over 6 hours
- 24-hour automated query loops
- Queries originated from "trusted" integration accounts, evading standard detection

**User-Agent Strings:**
- `5238` or blank (empty string) -- most common, used for the majority of queries
- `Python-urllib/3.12` -- 811 queries observed
- `Python-urllib/3.14` -- 58 queries observed

### 4. Exfiltration Staging: gofile.io

Stolen data was uploaded to gofile[.]io, a file-sharing service with 10-day default data retention. Premium accounts offer extended storage. The attackers used this as their primary data leak platform.

### 5. Extortion Campaign

Beginning June 16, 2026, Icarus sent extortion emails to victims. For Huntress, emails with subject line "top secret email" were sent to employee email addresses. The emails contained Session Messenger IDs for communication. Extortion emails were sent through compromised mail infrastructure belonging to three Australian retail company domains, with valid SPF and DMARC authentication.

### 6. Anti-Forensics / Evasion

- OAuth token-based access bypassed standard authentication monitoring (queries appeared as legitimate integration traffic)
- Use of Klue's own trusted integration identity avoided third-party app monitoring alerts
- Attacker infrastructure spread across multiple countries (Netherlands, France, Ukraine)
- Extortion emails sent via compromised legitimate mail servers with valid SPF/DMARC to bypass email security

---

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `user[at]domain[.]com`)

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 138[.]226[.]246[.]94 | Attacker infrastructure (ISP: Netherlands); linked to March 2026 spam campaigns |
| IP | 212[.]86[.]125[.]24 | Attacker infrastructure (ISP: France) |
| IP | 213[.]111[.]148[.]90 | Attacker infrastructure (ISP: France) |
| IP | 94[.]154[.]32[.]160 | Attacker infrastructure (ISP: Ukraine) |
| Domain | gofile[.]io | Data exfiltration / leak hosting platform |
| Domain | house[.]com[.]au | Compromised mail infrastructure (extortion emails) |
| Domain | robinskitchen[.]com[.]au | Compromised mail infrastructure (extortion emails) |
| Domain | baccarat[.]com[.]au | Compromised mail infrastructure (extortion emails) |

### Behavioral

**Salesforce API Access Patterns:**
- Bulk queries to `/services/data/v59.0/query/` endpoint via OAuth integration tokens
- User-Agent strings: `Python-urllib/3.12`, `Python-urllib/3.14`, `5238`, or blank
- High-volume query patterns: ~1,000 queries in 15-minute windows
- Sustained 6+ hour extraction sessions with automated pagination (QueryMore)
- Reconnaissance via `/services/data/v59.0/sobjects` endpoint

**Extortion Communication:**
- Session Messenger used for threat actor communication
- Self-identifies as "mr bean" / "mb"
- Signature patterns: "xoxo", "wrong session lol"
- Email subject: "top secret email"

---

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1528 | Steal Application Access Token | Harvested OAuth tokens from Klue's infrastructure for customer integrations (Salesforce, HubSpot, etc.) |
| T1199 | Trusted Relationship | Exploited Klue's trusted third-party integration relationship with customer Salesforce instances |
| T1078.004 | Valid Accounts: Cloud Accounts | Used legitimate OAuth integration credentials to access customer CRM data |
| T1580 | Cloud Infrastructure Discovery | Enumerated Salesforce objects via `/services/data/v59.0/sobjects` endpoint to map available data resources |
| T1530 | Data from Cloud Storage Object | Queried and extracted CRM data (contacts, quotes, sales communications) from Salesforce |
| T1106 | Native API | Used Salesforce REST API directly for data access and exfiltration |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based API communication with Salesforce REST endpoints |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Uploaded stolen data to gofile[.]io file sharing service |
<!-- revision: T1657 (Financial Theft) row removed. T1657 covers direct financial theft (e.g., unauthorized transfers), not extortion/ransom demands. No single ATT&CK technique cleanly maps to data extortion; the exfiltration itself is covered by T1567.002 above. -->

---

## Impact Assessment

**Scope:** Multiple Klue customers across Salesforce, HubSpot, and other integrated platforms. At least two cybersecurity firms (Huntress and Recorded Future) publicly confirmed impact. The total number of affected organizations is undisclosed.

**Data Compromised (Huntress):** Business contacts, price quotes, sales-related data and messaging with customers and partners, product pricing data, and competitive market reports. No compromise of threat intelligence data, customer/partner credentials, employee credentials, payment/PCI information, product source code, or endpoint telemetry.

**Data Compromised (Recorded Future):** Client contact names, email addresses, and potentially business contract information from Salesforce.

**Stealth Factor:** High. The attack leveraged trusted OAuth integration identities, causing queries to appear as legitimate Klue integration traffic. Organizations without Salesforce Event Monitoring (a premium feature) would have minimal visibility into the unauthorized access.

---

## Detection & Remediation

### Immediate Detection

1. **Review Salesforce Event Monitoring logs** for the following indicators:
   - API access from IPs: `138[.]226[.]246[.]94`, `212[.]86[.]125[.]24`, `213[.]111[.]148[.]90`, `94[.]154[.]32[.]160`
   - User-Agent values: `Python-urllib/3.12`, `Python-urllib/3.14`, `5238`, or blank
   - High-volume queries to `/services/data/v59.0/query/` endpoints
   - Unusual query volume from Klue Connected App tokens (if historically used)

2. **Check proxy/firewall logs** for outbound POST requests to `gofile.io`

3. **Audit email inboxes and spam folders** for extortion communications with subject "top secret email" or referencing Session Messenger contact methods

4. **Request access/API logs from Klue** and cross-reference with IOCs provided

### Remediation

1. **Revoke all Klue-associated OAuth tokens** from Salesforce, HubSpot, and all other integrated platforms immediately
2. **Revoke all active sessions** for affected services to invalidate potentially compromised sessions
3. **Audit all third-party Connected Apps** in Salesforce for excessive permissions or dormant integrations
4. **Enable Salesforce Event Monitoring** (Shield) if not already active for API access auditing
5. **Review Klue-connected data** to assess what information was accessible through the integration
6. **Engage cyber insurance providers** if applicable for investigation support
7. **Monitor for secondary attacks** using exfiltrated contact/business intelligence data

### Long-Term Hardening

1. **Implement NHI lifecycle management:** Enforce credential rotation policies for all third-party integration tokens; automatically revoke unused credentials after a defined inactivity period
2. **Apply least-privilege scoping** to OAuth integrations: audit and restrict API scopes granted to third-party Connected Apps to only required objects and fields
3. **Deploy anomaly detection** on non-human identity API access patterns: baseline normal integration behavior and alert on volume, timing, or endpoint deviations
4. **Require Salesforce Event Monitoring** for all production instances: treat API audit logs as a security baseline, not a premium feature
5. **Establish vendor security assessment cadence** that specifically evaluates OAuth token management, credential hygiene, and integration security practices

---

## Detection Rules

Three proxy-log Sigma rules target the concrete artifacts observed in this attack: attacker User-Agent strings (Python-urllib and the anomalous numeric value "5238"), and known Icarus IPs querying Salesforce. All rules use the `proxy` logsource category for web proxy / CASB / SASE log sources. Note: organizations without web proxy visibility into Salesforce API traffic should focus on Salesforce Event Monitoring (EventLogFile) native queries instead, which are not covered by Sigma's standard logsource taxonomy.

### Sigma Rule 1: Suspicious Salesforce API Access with Python-urllib User-Agent

Detects Salesforce REST API access using Python-urllib User-Agent strings observed during the Klue attack. Compile: PASS (0 errors, 0 issues; converts to Splunk and LogScale). Confidence: medium -- Python-urllib is used by legitimate automation, so the rule requires the Salesforce destination anchor to reduce false positives.

```yaml
title: Suspicious Salesforce API Access with Python-urllib User-Agent
id: f7a2c3d1-8e4b-5f6a-9b1d-2c7e8f3a4b5d
status: experimental
description: >
    Detects Salesforce REST API access using Python-urllib User-Agent strings,
    which were observed during the Klue OAuth token abuse supply chain attack
    (June 2026). Threat actor Icarus used Python-urllib/3.12 and Python-urllib/3.14
    to issue bulk queries against Salesforce REST API endpoints using stolen OAuth tokens.
references:
    - https://www.huntress.com/blog/klue-breach-investigation
    - https://www.securityweek.com/cybersecurity-firms-impacted-by-klue-supply-chain-attack/
    - https://thehackernews.com/2026/06/salesforce-disables-klue-app.html
author: Actioner
date: 2026-06-19
tags:
    - attack.t1528
    - attack.t1106
logsource:
    category: proxy
detection:
    selection_useragent:
        c-useragent|startswith: 'Python-urllib'
    selection_sfdc_target:
        r-dns|endswith:
            - '.salesforce.com'
            - '.force.com'
    selection_api_path:
        cs-uri-stem|contains: '/services/data/'
    condition: selection_useragent and selection_sfdc_target and selection_api_path
falsepositives:
    - Legitimate internal automation scripts using Python requests/urllib to interact with Salesforce APIs
    - CI/CD pipelines with Salesforce integration tests
level: medium
```

<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. Field names follow W3C Extended Log Format (proxy category). Python-urllib is a known-legitimate UA but combined with SFDC API path provides a useful hunt query. No defanged values in detection fields. -->

### Sigma Rule 2: Salesforce REST API Query Access with Anomalous User-Agent

Detects access to the Salesforce REST API query endpoint with the distinctive User-Agent value "5238" used by Icarus. Compile: PASS (0 errors; 1 LOW issue -- NumberAsStringIssue for "5238", intentional since User-Agent is a string field; converts to Splunk and LogScale). Confidence: medium -- "5238" is a single 4-character string that may appear in other contexts; empty-string UA matching was removed because it is unreliable across proxy log sources (some omit the field entirely rather than logging a blank); the version-pinned path `/services/data/v59.0/` limits longevity as Salesforce API versions increment.

```yaml
title: Salesforce REST API Query Endpoint Access with Anomalous Numeric User-Agent
id: e8b3d4f2-9a5c-6e7b-0c2d-3d8f9e4a5b6c
status: experimental
description: >
    Detects access to the Salesforce REST API query endpoint with the suspicious User-Agent
    value "5238". During the Klue OAuth supply chain attack (June 2026), the Icarus threat
    actor used this anomalous numeric User-Agent string for the majority of malicious API
    queries against Salesforce REST API query endpoints.
references:
    - https://www.huntress.com/blog/klue-breach-investigation
    - https://www.securityweek.com/cybersecurity-firms-impacted-by-klue-supply-chain-attack/
author: Actioner
date: 2026-06-19
tags:
    - attack.t1528
    - attack.t1106
logsource:
    category: proxy
detection:
    selection_sfdc_query:
        cs-uri-stem|contains: '/services/data/'
        r-dns|endswith:
            - '.salesforce.com'
            - '.force.com'
    selection_suspicious_ua:
        c-useragent: '5238'
    selection_api_path:
        cs-uri-stem|contains: '/query'
    condition: selection_sfdc_query and selection_suspicious_ua and selection_api_path
falsepositives:
    - Misconfigured legitimate API clients sending numeric User-Agent strings
level: medium
```

<!-- audit: sigma check 0 errors 1 LOW issue (NumberAsStringIssue for "5238" -- intentional, UA is string field); sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. No defanged values in detection. Empty-string UA match removed (unreliable across log sources). Version-pinned path broadened from v59.0 to /services/data/ + /query for longevity. -->

### Sigma Rule 3: Salesforce API Access from Known Icarus Infrastructure

Detects network connections to Salesforce from four IP addresses attributed to the Icarus threat actor. Compile: PASS (0 errors, 0 issues; converts to Splunk and LogScale). Confidence: high -- IOC-specific, but IPs may be rotated or reassigned over time. Level downgraded from critical to high because IOC-based IP rules age out as infrastructure rotates.

```yaml
title: Salesforce API Access from Known Icarus Threat Actor Infrastructure
id: d9c4e5a3-0b6d-7f8c-1d3e-4e9f0a5b6c7d
status: experimental
description: >
    Detects network connections to Salesforce from IP addresses attributed to the Icarus
    threat actor group, which compromised Klue OAuth tokens to exfiltrate CRM data from
    Salesforce instances in June 2026. These IPs were observed performing bulk API queries
    using stolen OAuth tokens.
references:
    - https://www.huntress.com/blog/klue-breach-investigation
    - https://www.securityweek.com/cybersecurity-firms-impacted-by-klue-supply-chain-attack/
author: Actioner
date: 2026-06-19
tags:
    - attack.t1528
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_src_ip:
        c-ip:
            - '138.226.246.94'
            - '212.86.125.24'
            - '213.111.148.90'
            - '94.154.32.160'
    selection_sfdc:
        r-dns|endswith:
            - '.salesforce.com'
            - '.force.com'
    condition: selection_src_ip and selection_sfdc
falsepositives:
    - Unlikely given the specificity of the IP addresses and Salesforce destination; however IPs may be reassigned over time
level: high
```

<!-- audit: sigma check 0 errors 0 issues; sigma convert --without-pipeline -t splunk OK; sigma convert --without-pipeline -t log_scale OK. IPs are real (not defanged) per logsource-encoding.md. IPs will age out as infrastructure rotates; useful for retroactive hunting and near-term detection. -->

<!-- revision: Sigma Rule 4 (Data Upload to gofile.io, id c0d5f6b4-1c7e-8a9d-2e4f-5f0a1b6c7d8e) DROPPED during review. Rationale: gofile.io is a legitimate file-sharing service; the rule had no campaign-specific anchor (no source IP filter, no Salesforce context, no time window). Detection of uploads to gofile.io belongs in a URL category blocklist or web proxy policy, not a campaign-specific detection pack. -->

---

## Lessons Learned

1. **Non-human identities are the new attack surface.** This attack succeeded because a dormant integration credential was never revoked. Organizations must implement NHI lifecycle management with automatic expiration, rotation, and least-privilege scoping for all OAuth tokens and API credentials granted to third-party integrations.

2. **Third-party integration supply chains create transitive trust.** When a customer grants an OAuth token to a SaaS vendor like Klue, they implicitly trust that vendor's entire security posture. A single compromised vendor can cascade access across hundreds of customer environments through legitimate integration channels. Defenders need to monitor integration account behavior with the same rigor applied to human accounts.

3. **Salesforce Event Monitoring is a security necessity, not a premium add-on.** The forensic analysis that identified User-Agent strings, query volumes, and IP addresses was only possible because Huntress had Salesforce Event Monitoring (Shield) enabled. Organizations without this capability would have no visibility into the unauthorized API access. Salesforce should consider making basic API audit logging available to all customers.

4. **SaaS-to-SaaS attacks are difficult to detect at the network layer.** When an attacker uses a legitimate OAuth token to make API calls that look identical to normal integration traffic, traditional network security tools see nothing anomalous. Detection requires behavioral baselining of integration account activity -- monitoring for changes in query volume, timing, endpoints accessed, and source IP geolocation.

---

## Sources

- [Huntress Blog: Cybercrime Breaches Klue](https://www.huntress.com/blog/klue-breach-investigation) -- Primary source: detailed technical forensic analysis from an affected company, including timeline, IOCs, API access patterns, and User-Agent strings
- [SecurityWeek: Cybersecurity Firms Impacted by Klue Supply Chain Attack](https://www.securityweek.com/cybersecurity-firms-impacted-by-klue-supply-chain-attack/) -- Reporting on affected companies (Huntress, Recorded Future), Salesforce and Klue responses, and Icarus threat actor profile
- [The Hacker News: Salesforce Disables Klue App](https://thehackernews.com/2026/06/salesforce-disables-klue-app.html) -- Technical analysis including MITRE ATT&CK mapping, ReliaQuest researcher commentary, and attack timeline details
- [SC World: Icarus Threat Actors Exploit Klue OAuth Breach](https://www.scworld.com/brief/icarus-threat-actors-exploit-klue-oauth-breach-to-steal-salesforce-data) -- Brief reporting on the incident (HTTP 403 at time of access)
- [GBHackers: Hackers Exploit Klue Integration to Steal Salesforce CRM Data](https://gbhackers.com/hackers-exploit-klue-integration-to-steal-salesforce-crm-data/) -- Additional coverage (content unavailable at time of access)

---
*Report generated by Actioner -- FINAL*
