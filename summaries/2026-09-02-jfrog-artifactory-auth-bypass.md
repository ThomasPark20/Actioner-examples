# Technical Analysis Report: JFrog Artifactory Authentication Bypass — CVE-2026-82329 (2026-09-02)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-02
Version: 0.1 DRAFT

## Executive Summary

CVE-2026-82329 is a critical (CVSS 9.8) authentication bypass vulnerability in self-managed JFrog Artifactory instances that allows unauthenticated attackers with network access to mint administrator-level access tokens. The flaw resides in JFrog Access, the credential issuance and validation component, where default configurations leave a "phantom" join key that attackers can abuse to forge administrative JWTs. JFrog released patches on August 28, 2026, and active exploitation was confirmed by watchTowr by September 1, 2026 — just three days later. Attackers have been observed generating admin tokens, enumerating users and groups, accessing credential sets, probing federated access topologies, and creating backdoor accounts. No specific IOCs (IPs, domains, hashes) have been publicly disclosed; detection relies on behavioral patterns at the web and application log level. Self-managed Artifactory instances exposed to the internet are at immediate risk; JFrog cloud/SaaS environments are not affected.

## Background: JFrog Artifactory

JFrog Artifactory is a universal binary repository manager widely used across enterprise software supply chains to store, manage, and distribute build artifacts, container images, and software packages. It serves as a central node in CI/CD pipelines — a compromise grants attackers the ability to tamper with build pipelines, inject malicious artifacts, steal secrets, and move laterally into production systems. Self-managed deployments expose web interfaces on ports 8081 (Artifactory API) and 8082 (JFrog Router), with JFrog Access handling all credential issuance and validation behind these services.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-28 | JFrog releases patched Artifactory version 7.161.20 and publishes security advisory for CVE-2026-82329 |
| 2026-08-28 | Patches backported to branches: 7.146.38, 7.133.29, 7.125.20, 7.117.28, 7.111.21 |
| 2026-09-01 | watchTowr confirms active exploitation via global Attacker Eye honeypot network |
| 2026-09-01 | Attackers observed minting admin tokens, enumerating users/groups/credentials, creating backdoor accounts |
| 2026-09-02 | Multiple security outlets report exploitation; broad-scale scanning not yet observed |

## Root Cause: Default-Configuration Authentication Weakness in JFrog Access

CVE-2026-82329 (CWE-287: Improper Authentication) targets the JFrog Access component responsible for credential issuance and validation. Self-managed Artifactory instances deployed without explicit hardening inherit a default configuration that uses static seeds, predictable key generation algorithms, or pre-configured fallback keys. Instances without an additional join key configured receive a "phantom" join key. Attackers abuse this to forge administrative JWTs containing claims that map to administrative roles, which are then transmitted via HTTP Authorization headers to bypass authentication entirely.

The attack requires no authentication, no user interaction, and works against default configurations — yielding a CVSS:3.1 vector of AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.

## Technical Analysis of the Malicious Payload

### 1. Reconnaissance

Attackers first identify vulnerable instances by probing the version endpoint:

```
GET /artifactory/api/system/version HTTP/1.1
```

Responses reveal the Artifactory version, allowing attackers to determine if the instance falls within a vulnerable range. Ports 8081 and 8082 are the primary targets.

### 2. Authentication Bypass and Token Minting

The attacker generates a forged administrative JWT containing claims that map to administrative roles and submits it to the JFrog Access token creation endpoint:

```
POST /access/api/v1/tokens HTTP/1.1
Content-Type: application/json
Authorization: Bearer <forged-jwt>
```

The phantom join key or weak cryptographic defaults allow the forged token to pass validation, and the system issues a legitimate admin-level access token in response.

### 3. Post-Exploitation Enumeration and Persistence

With a valid admin token, attackers perform:

- **User enumeration**: `GET /access/api/v1/users`
- **Group enumeration**: `GET /access/api/v1/groups`
- **Permission discovery**: `GET /access/api/v1/permissions`
- **Credential set access**: probing stored secrets and service connections
- **Federated topology mapping**: identifying connected Artifactory instances
- **Backdoor account creation**: creating new admin-level users for persistence

### 4. Related Attack Surface (Prior CVEs)

The NetSPI research (CVE-2026-42018, CVE-2026-69107) documents related Artifactory attack patterns including:

- Path traversal via semicolon normalization bypass (`/artifactory/..;/`)
- AWS token endpoint trailing-slash bypass (`/access/api/v1/aws/token/`)
- Stash results endpoint abuse for arbitrary file write

These techniques may be chained with CVE-2026-82329 for deeper compromise.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Network

| Type | Value | Context |
|------|-------|---------|
| API Endpoint | `/access/api/v1/tokens` | Primary exploitation target — token minting |
| API Endpoint | `/access/api/v1/users` | Post-exploitation user enumeration |
| API Endpoint | `/access/api/v1/groups` | Post-exploitation group enumeration |
| API Endpoint | `/access/api/v1/permissions` | Post-exploitation permission discovery |
| API Endpoint | `/access/api/v1/configs` | Post-exploitation configuration access |
| API Endpoint | `/artifactory/api/system/version` | Pre-exploitation version reconnaissance |
| Port | 8081 | Artifactory API service port |
| Port | 8082 | JFrog Router service port |

**Note:** No specific attacker IP addresses, domains, or file hashes have been publicly disclosed. watchTowr reported exploitation from "a small number of IP addresses from varying geographies" but withheld specifics. Attribution is uncertain — sources note it is unknown whether exploitation is by human operators or autonomous AI agents.

### Behavioral

- Unauthenticated POST requests to `/access/api/v1/tokens` from external IPs
- Rapid sequential GET requests to `/access/api/v1/users`, `/groups`, `/permissions` from a single source IP
- Token creation events (TKN/C) in the JFrog Access security audit log from unknown IPs or unknown users
- New admin user creation events (USR/C) in the audit log that do not correlate with authorized provisioning
- Version endpoint probing from external, non-monitoring IPs

### Application Log Indicators

The JFrog Access security audit log at `$JFROG_HOME/artifactory/var/log/access-security-audit.log` records:

```
Date | Trace ID | User IP | User | Logged Principal | Entity Name | Event Type | Event | Data Changed
```

Hunt for:
- **Event=TKN, EventType=C** (token creation) with User IP from unexpected sources or User="unknown"
- **Event=USR, EventType=C** (user creation) that does not match authorized provisioning workflows
- **Event=GRP, EventType=U** (group modification) adding unexpected members
- **Event=PRM, EventType=U** (permission changes) granting unexpected access

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of JFrog Access token endpoint via forged JWT |
| T1078.001 | Valid Accounts: Default Accounts | Abusing phantom join key in default configuration to mint admin credentials |
| T1087.004 | Account Discovery: Cloud Account | Post-exploitation enumeration of users and groups via Access API |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Enumeration of groups and permission targets after gaining admin access |
| T1098 | Account Manipulation | Creation of backdoor admin accounts for persistence |
| T1592.002 | Gather Victim Host Information: Software | Version endpoint probing to identify vulnerable instances |

## Impact Assessment

JFrog Artifactory is a central node in enterprise software supply chains. An attacker with admin access can:

- **Supply chain compromise**: Inject malicious artifacts into trusted repositories consumed by build pipelines
- **Secret theft**: Access stored credentials, API keys, and service account tokens
- **Lateral movement**: Pivot to connected systems via federated access topologies and stolen credentials
- **Data exfiltration**: Download proprietary source code, container images, and build artifacts
- **Persistent access**: Create backdoor accounts and tokens that survive credential rotation

The affected version ranges span six major branches, indicating the vulnerability was introduced in or before version 7.111.4 and persisted through 7.161.19 — a wide exposure window across enterprise deployments.

## Detection & Remediation

### Immediate Detection

Check your Artifactory version:

```bash
curl -s https://<your-artifactory>/artifactory/api/system/version
```

If the version falls within a vulnerable range (see Affected Versions below), assume potential compromise.

Review the Access security audit log for suspicious token creation:

```bash
grep "TKN" $JFROG_HOME/artifactory/var/log/access-security-audit.log | grep ",C," | sort -t'|' -k3
```

Review for unexpected user creation:

```bash
grep "USR" $JFROG_HOME/artifactory/var/log/access-security-audit.log | grep ",C," | sort -t'|' -k3
```

### Affected Versions

| Branch | Vulnerable Range | Fixed Version |
|--------|-----------------|---------------|
| 7.161.x | 7.161.0 - 7.161.19 | 7.161.20 |
| 7.146.x | 7.146.0 - 7.146.37 | 7.146.38 |
| 7.133.x | 7.133.0 - 7.133.28 | 7.133.29 |
| 7.125.x | 7.125.0 - 7.125.19 | 7.125.20 |
| 7.117.x | 7.117.0 - 7.117.27 | 7.117.28 |
| 7.111.x | 7.111.4 - 7.111.20 | 7.111.21 |

### Remediation

1. **Patch immediately**: Upgrade to the applicable fixed version for your branch. Prioritize internet-exposed instances.
2. **Rotate all credentials**: Revoke and reissue all access tokens, API keys, and service account credentials.
3. **Audit admin accounts**: Review all admin-level users and tokens for unauthorized additions.
4. **Inspect audit logs**: Search for TKN (token) and USR (user) creation events from unknown IPs.
5. **Review connected systems**: Check federated Artifactory instances and downstream build pipelines for malicious modifications.
6. **Network segmentation**: Restrict access to ports 8081/8082 to authorized networks only.

### Long-Term Hardening

- Configure an explicit join key (do not rely on defaults) for all self-managed deployments.
- Place Artifactory behind a reverse proxy with authentication and rate limiting.
- Enable and forward audit logs to a SIEM for continuous monitoring.
- Implement network-level access controls restricting Access API endpoints to internal management networks.
- Subscribe to JFrog security advisories for timely patch awareness.

## Detection Rules

These rules target the behavioral patterns of CVE-2026-82329 exploitation: token minting via the Access API, post-exploitation enumeration, version reconnaissance, and related path traversal techniques. No specific IOCs (IPs, domains, hashes) have been publicly disclosed, so all rules are behavioral and carry medium confidence. Operators should tune false-positive filters to their environment before promoting to production.

### Sigma Rule 1: JFrog Artifactory Suspicious Admin Token Creation via Access API

Detects unauthenticated POST requests to the JFrog Access token creation endpoint, the primary exploitation vector for CVE-2026-82329.

**Compile**: sigma convert -t splunk PASS, sigma convert -t log_scale PASS, sigma check blocked by environment (MITRE data fetch 403 from proxy)
**Confidence**: Medium

```yaml
title: JFrog Artifactory Suspicious Admin Token Creation via Access API
id: 9c3a7b1e-4d2f-4e8a-b5c6-1f0d9e8a7b3c
status: experimental
description: >
    Detects HTTP POST requests to the JFrog Access token creation endpoint
    (/access/api/v1/tokens), which is the primary exploitation vector for
    CVE-2026-82329. Attackers abuse a default-configuration authentication
    weakness to mint administrator-level tokens without credentials.
references:
    - https://thehackernews.com/2026/09/attackers-exploit-critical-jfrog.html
    - https://docs.jfrog.com/releases/docs/jfrog-security-advisories
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
    - attack.t1078.001
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri:
        cs-uri-stem|contains: '/access/api/v1/tokens'
    filter_authenticated:
        cs-username|contains:
            - 'admin'
            - 'service'
    condition: selection_method and selection_uri and not filter_authenticated
falsepositives:
    - Legitimate token creation by authenticated administrators
    - CI/CD pipelines using service accounts for token rotation
level: high
```

<!-- Audit: sigma check fails due to environment proxy blocking MITRE ATT&CK data fetch (HTTP 403), not a rule defect. sigma convert --without-pipeline -t splunk produces valid SPL: "cs-method"="POST" "cs-uri-stem"="*/access/api/v1/tokens*" NOT ("cs-username" IN ("*admin*", "*service*")). sigma convert -t log_scale also produces valid query. Filter should be tuned per-environment to match actual admin/service account naming conventions. No defanging needed in rules per logsource-encoding ref. -->

### Sigma Rule 2: JFrog Artifactory Access API User and Group Enumeration

Detects requests to JFrog Access API enumeration endpoints used in post-exploitation after CVE-2026-82329 admin token minting.

**Compile**: sigma convert -t splunk PASS, sigma convert -t log_scale PASS, sigma check blocked by environment
**Confidence**: Medium

```yaml
title: JFrog Artifactory Access API User and Group Enumeration
id: b7e4a2c1-5f3d-4a9b-8c6e-2d1f0a9b8c7d
status: experimental
description: >
    Detects HTTP requests to JFrog Access user and group enumeration endpoints.
    After exploiting CVE-2026-82329 to mint admin tokens, attackers enumerate
    users, groups, credential sets and federated access topologies for lateral
    movement and persistence.
references:
    - https://thehackernews.com/2026/09/attackers-exploit-critical-jfrog.html
    - https://docs.jfrog.com/releases/docs/jfrog-security-advisories
author: Actioner
date: 2026-09-02
tags:
    - attack.t1087.004
    - attack.t1069.003
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/access/api/v1/users'
            - '/access/api/v1/groups'
            - '/access/api/v1/permissions'
            - '/access/api/v1/configs'
    condition: selection
falsepositives:
    - Legitimate administrative audit or compliance scanning
    - Automated user sync from identity providers
    - CI/CD tooling querying permissions
level: medium
```

<!-- Audit: Original version used deprecated pipe aggregation syntax (count() by c-ip > 20); rewritten as simple selection to pass pySigma. Threshold/aggregation should be applied at the SIEM layer. sigma convert -t splunk and -t log_scale both produce valid queries. Consider adding threshold logic in the SIEM (e.g., tstats with count by src_ip in Splunk). -->

### Sigma Rule 3: JFrog Artifactory Version Endpoint Probing

Detects external reconnaissance probing of the Artifactory version endpoint used to identify vulnerable instances.

**Compile**: sigma convert -t splunk PASS, sigma convert -t log_scale partial (CIDR OR unsupported in LogScale backend)
**Confidence**: Low

```yaml
title: JFrog Artifactory Version Endpoint Probing
id: d5f8c3a2-6e4b-4d1a-9f7e-3c2b1a0d9e8f
status: experimental
description: >
    Detects HTTP GET requests to the Artifactory version endpoint
    (/artifactory/api/system/version), commonly used for reconnaissance
    to identify vulnerable instances of CVE-2026-82329 before exploitation.
references:
    - https://thehackernews.com/2026/09/attackers-exploit-critical-jfrog.html
    - https://www.penligent.ai/hackinglabs/cve-2026-82329/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1592.002
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/artifactory/api/system/version'
    filter_internal:
        c-ip|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter_internal
falsepositives:
    - Legitimate monitoring or health check systems from external sources
    - Authorized vulnerability scanners
level: medium
```

<!-- Audit: sigma convert -t splunk produces valid SPL. sigma convert -t log_scale fails with "ORing CIDR matching is not yet supported by LogScale backend" — this is a backend limitation, not a rule defect. For LogScale deployment, replace CIDR filter with explicit IP range patterns. The version endpoint is benign on its own — this rule is low confidence as a standalone detection but valuable when correlated with subsequent token creation attempts. -->

### Suricata Rule 1: JFrog Artifactory CVE-2026-82329 Token Minting Attempt

Detects HTTP POST requests to the JFrog Access token creation endpoint from external sources.

**Compile**: suricata -T PASS
**Confidence**: Medium

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - JFrog Artifactory CVE-2026-82329 Token Minting Attempt via Access API"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/access/api/v1/tokens"; fast_pattern; classtype:web-application-attack; reference:cve,2026-82329; reference:url,docs.jfrog.com/releases/docs/jfrog-security-advisories; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-82329; sid:2100101; rev:1;)
```

<!-- Audit: suricata -T validates clean. Uses http protocol with dot-notation sticky buffers (http.method, http.uri). fast_pattern on the URI content for efficient matching. May fire on legitimate token creation from external CI/CD — tune $EXTERNAL_NET or add authorized source exclusions. No defanging in rule content per logsource-encoding ref. -->

### Suricata Rule 2: JFrog Artifactory Path Traversal via Semicolon Normalization Bypass

Detects path traversal attempts using the Tomcat semicolon normalization bypass (`..;/`) documented in related Artifactory CVEs.

**Compile**: suricata -T PASS (after encoding fix)
**Confidence**: Medium

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - JFrog Artifactory Path Traversal via Semicolon Normalization Bypass"; flow:established,to_server; http.uri.raw; content:"/artifactory/"; content:"|2e 2e 3b 2f|"; distance:0; fast_pattern; classtype:web-application-attack; reference:url,www.netspi.com/blog/technical-blog/red-teaming/stealing-the-artifact-jfrog-artifactory-vulnerability/; metadata:author Actioner, created_at 2026-09-02; sid:2100102; rev:1;)
```

<!-- Audit: suricata -T validates clean. The semicolon in "..;/" caused a Suricata parsing error when written as a literal string (content:"..;/") because the semicolon is an option delimiter. Resolved by hex-encoding the pattern: |2e 2e 3b 2f| = "..;/". Uses http.uri.raw to inspect the unnormalized URI where the traversal sequence would appear before server-side normalization. -->

### Suricata Rule 3: JFrog Artifactory Version Endpoint Reconnaissance

Detects repeated external GET requests to the Artifactory version endpoint used for pre-exploitation reconnaissance.

**Compile**: suricata -T PASS
**Confidence**: Low

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - JFrog Artifactory Version Endpoint Reconnaissance"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/artifactory/api/system/version"; fast_pattern; threshold:type both, track by_src, count 3, seconds 60; classtype:attempted-recon; reference:cve,2026-82329; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-82329; sid:2100103; rev:1;)
```

<!-- Audit: suricata -T validates clean. Threshold of 3 hits in 60 seconds reduces false positives from single health-check probes. The version endpoint is inherently benign; this rule is low confidence standalone but useful as a leading indicator when correlated with token minting attempts from the same source. -->

### Suricata Rule 4: JFrog Artifactory Post-Exploitation User and Group Enumeration

Detects rapid enumeration of JFrog Access API management endpoints from external sources following CVE-2026-82329 exploitation.

**Compile**: suricata -T PASS
**Confidence**: Medium

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - JFrog Artifactory Post-Exploitation User and Group Enumeration"; flow:established,to_server; http.uri; content:"/access/api/v1/"; fast_pattern; pcre:"/\/access\/api\/v1\/(users|groups|permissions|configs)/"; threshold:type both, track by_src, count 10, seconds 60; classtype:web-application-activity; reference:cve,2026-82329; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-82329; sid:2100104; rev:1;)
```

<!-- Audit: suricata -T validates clean. PCRE alternation matches the four key management endpoints. Threshold of 10 hits in 60 seconds targets the rapid-enumeration pattern described by watchTowr. Legitimate admin API usage from external sources may trigger — tune threshold and source restrictions to environment. -->

### YARA

No YARA rules generated. The publicly available intelligence contains no file-level indicators (malware samples, hashes, on-disk artifacts) that would support file-based detection.

## Lessons Learned

1. **Default configurations remain a critical attack surface.** CVE-2026-82329 demonstrates that authentication mechanisms relying on implicit defaults — here, a "phantom" join key — create systemic risk at scale. Organizations must treat explicit configuration of security-critical parameters as a deployment prerequisite, not an optional hardening step.

2. **Patch-to-exploit timelines continue to compress.** Three days from patch release to confirmed in-the-wild exploitation leaves virtually no margin for manual patch cycles. Organizations managing critical supply-chain infrastructure must have automated or semi-automated patching pipelines, supplemented by compensating controls (network segmentation, WAF rules) that can be deployed within hours.

3. **Supply chain infrastructure is a high-value target.** Artifactory sits at the center of software delivery pipelines. Compromise of a single instance can cascade into supply chain attacks affecting downstream consumers. This underscores the need for defense-in-depth around build and artifact management systems — including audit log monitoring, token lifecycle management, and network isolation of management APIs.

## Sources

- [The Hacker News — Attackers Exploit Critical JFrog Artifactory Flaw](https://thehackernews.com/2026/09/attackers-exploit-critical-jfrog.html) — primary reporting on active exploitation timeline and attacker behavior
- [The Register — Another Artifactory CVE Under Attack](https://www.theregister.com/security/2026/09/01/another-artifactory-cve-under-attack-by-ai-agents-or-humans/5293769) — exploitation confirmation, watchTowr honeypot findings, AI agent attribution question
- [JFrog Security Advisories](https://docs.jfrog.com/releases/docs/jfrog-security-advisories) — official advisory with affected versions, fixed versions, and vulnerability description
- [CVEReports — CVE-2026-82329](https://cvereports.com/reports/CVE-2026-82329) — CVSS vector, CWE classification, technical root cause analysis, vulnerable code patterns
- [Penligent — CVE-2026-82329 Explained](https://www.penligent.ai/hackinglabs/cve-2026-82329/) — technical analysis noting exact exploit mechanism not yet public, version verification endpoint
- [SecurityWeek — Critical JFrog Artifactory Vulnerability Exploited in the Wild](https://www.securityweek.com/critical-jfrog-artifactory-vulnerability-reportedly-exploited-in-the-wild/) — exploitation scope, self-hosted vs cloud impact, patch versions
- [IONIX Threat Center — CVE-2026-82329](https://www.ionix.io/threat-center/cve-2026-82329/) — affected version ranges, remediation guidance
- [NetSPI — Stealing the Artifact: JFrog Artifactory Vulnerability](https://www.netspi.com/blog/technical-blog/red-teaming/stealing-the-artifact-jfrog-artifactory-vulnerability/) — related CVE technical details (CVE-2026-42018, CVE-2026-69107), exploitation request patterns, path traversal techniques
- [JFrog Documentation — Audit Trail Log](https://docs.jfrog.com/administration/docs/audit-trail-log) — audit log format, event types, file paths for forensic investigation
- [SC World — JFrog Artifactory Flaw Exploited Days After Patch Release](https://www.scworld.com/news/jfrog-artifactory-flaw-exploited-days-after-patch-release) — source returned HTTP 403; content not verified

---
*Report generated by Actioner*
