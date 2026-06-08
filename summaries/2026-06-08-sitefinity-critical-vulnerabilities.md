# Progress Sitefinity Critical Vulnerabilities — CVSS 10.0 Security Alert

**Date:** 2026-06-08
**Author:** Actioner
**Status:** DRAFT
**Classification:** TLP:CLEAR

---

## Executive Summary

On June 2, 2026, Progress Software disclosed five security vulnerabilities affecting Progress Sitefinity CMS, a widely-deployed .NET-based web content management system. The most critical, CVE-2026-7312, carries a maximum CVSS score of 10.0 and allows unauthenticated remote attackers to extract plain-text credentials for the Sitefinity Insight analytics service through exposed OData web service endpoints. A second critical vulnerability, CVE-2026-7198 (CVSS 9.8), permits unauthenticated access to restricted content via improper access controls. Three additional high-severity vulnerabilities address authorization bypass (CVE-2026-7201), input validation flaws (CVE-2026-7195), and a secondary credential exposure issue (CVE-2026-7313). Patches are available for all supported branches. No public exploit code or active exploitation has been confirmed as of this writing.

**No production-ready, high-confidence detection rules are possible at this time.** The advisory and related sources provide no specific exploit payloads, endpoint paths, HTTP request patterns, or file-level indicators. One advisory-based Sigma rule is included at medium confidence for situational awareness monitoring.

---

## Background

Progress Sitefinity is an enterprise .NET CMS platform used globally for web content management, digital experience delivery, and marketing analytics. Sitefinity exposes OData-based web service APIs for content management, user administration, and integration with the Sitefinity Insight analytics service.

The May 2026 security advisory addresses a cluster of five vulnerabilities, several of which target the OData web services layer. The vulnerabilities were assigned CVEs on June 2, 2026 and published simultaneously.

### Vulnerability Timeline

| Date | Event |
|------|-------|
| May 2026 | Progress releases patched versions for supported branches |
| 2026-06-02 | CVEs published to NVD |
| 2026-06-08 | SecurityOnline publishes consolidated alert |

---

## Technical Analysis

### CVE-2026-7312 — Insufficiently Protected Credentials in OData Web Services (CVSS 10.0 Critical)

- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
- **Affected Versions:** 14.0.7700–14.4.8152, 15.0.8200–15.0.8234, 15.1.8300–15.1.8335, 15.2.8400–15.2.8441, 15.3.8500–15.3.8531, 15.4.8600–15.4.8630
- **Description:** When Sitefinity is configured with Sitefinity Insight integration using a non-default configuration, API keys and service account credentials are stored or transmitted insecurely. A remote unauthenticated attacker can send a crafted request to a web service endpoint to retrieve these credentials in plain text.
- **Exploitation Requirements:** (1) Active Sitefinity Insight integration; (2) Non-default site configuration.
- **Impact:** Full credential extraction enabling lateral movement to Insight service, potential data exfiltration from CMS analytics data.

### CVE-2026-7198 — Improper Access Control in OData Web Services (CVSS 9.8 Critical)

- **CWE:** CWE-284 (Improper Access Control)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Affected Versions:** 15.4.8623–15.4.8629
- **Fixed Version:** 15.4.8630+
- **Description:** Improper access control in OData web services allows a remote unauthenticated attacker to access content that should be restricted, compromising confidentiality, integrity, and availability.
- **Impact:** Full system compromise potential — unauthorized access to restricted CMS content and functionality.

### CVE-2026-7201 — Authorization Bypass via User-Controlled Key (CVSS 8.8 High)

- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **CVSS Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (estimated)
- **Affected Versions:** 15.2.x–15.4.x (specific ranges TBD)
- **Description:** An authenticated attacker with low-privileged credentials can manipulate user-controlled keys (user IDs or GUIDs) in API requests to modify other users' account properties, including email addresses, passwords, and role assignments. The system fails to validate whether the caller is authorized to modify the referenced resource.
- **Impact:** Full account takeover of any user, privilege escalation, persistent backdoor access.

### CVE-2026-7195 — Improper Input Validation in Web Services (CVSS 8.8 High)

- **CWE:** CWE-20 (Improper Input Validation)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **Affected Versions:** 14.1.x–15.4.x (before patched versions)
- **Description:** Web service endpoints do not properly sanitize user-supplied data. An unauthenticated remote attacker can send crafted requests; if a legitimate user interacts with the malicious request and the site uses non-default configuration, the attacker can compromise user account integrity and confidentiality.
- **Impact:** User account compromise via social engineering vector.

### CVE-2026-7313 — Insufficiently Protected Credentials (CVSS 8.7 High)

- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Affected Versions:** 8.0.5700–13.3.7652
- **Description:** Similar to CVE-2026-7312 but requires authenticated backend access. An authenticated attacker can retrieve Sitefinity Insight service credentials in plain text. Requires active Insight integration and non-default configuration.
- **Impact:** Credential extraction for lateral movement; lower severity than CVE-2026-7312 due to authentication requirement.

---

## Indicators of Compromise (IOCs)

**No concrete IOCs are available.** The advisory and related sources do not disclose:
- File hashes
- IP addresses or domains associated with exploitation
- Specific malicious payloads
- Specific vulnerable endpoint URLs (beyond the general `/Sitefinity/Services/` prefix noted as a WAF blocking target)

### Known Path Prefix (Advisory-Based, Low Specificity)

| Indicator | Type | Context |
|-----------|------|---------|
| `/Sitefinity/Services/` | URI Path Prefix | General Sitefinity web services path; mentioned as WAF blocking target in advisory. High false-positive rate. |

---

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|----|-----------|
| Unsecured Credentials | T1552 | CVE-2026-7312 and CVE-2026-7313 — credentials stored/transmitted insecurely |
| Unsecured Credentials: Credentials In Files | T1552.001 | Credentials retrievable in plain text from web service responses |
| Exploit Public-Facing Application | T1190 | CVE-2026-7312, CVE-2026-7198 — unauthenticated remote exploitation of web services |
| Valid Accounts | T1078 | Post-exploitation use of stolen Insight service credentials |
| Access Token Manipulation | T1134 | CVE-2026-7201 — IDOR to escalate privileges via user-controlled key manipulation |

---

## Detection & Remediation

### Remediation (Priority)

**Immediate patching is the primary mitigation.** Apply the following minimum versions:

| Branch | Patched Version |
|--------|----------------|
| 15.4.x | 15.4.8630 |
| 15.3.x | 15.3.8531 |
| 15.2.x | 15.2.8441 |
| 15.1.x | 15.1.8335 |
| 15.0.x | 15.0.8234 |
| 14.4.x | 14.4.8152 |
| 13.3.x | 13.3.7652 |

### Interim Mitigations

1. **WAF Rules:** Block unauthenticated external access to `/Sitefinity/Services/` endpoints.
2. **Configuration Review:** If Sitefinity Insight integration is not required, disable it to eliminate the attack surface for CVE-2026-7312 and CVE-2026-7313.
3. **Revert to Default Configuration:** If using non-default configurations that expose vulnerable web services, consider reverting to default until patches are applied.
4. **Network Segmentation:** Restrict access to Sitefinity backend and administrative services to trusted networks only.
5. **Credential Rotation:** If Sitefinity Insight was configured on a vulnerable instance, rotate all Insight API keys and service account credentials immediately.

### Detection Limitations

**No production-ready detection rules can be generated at high confidence.** The available sources provide:
- Generic vulnerability descriptions without specific exploit payloads
- No proof-of-concept code or exploitation details
- No specific endpoint paths beyond the general `/Sitefinity/Services/` prefix
- No file-level, network-level, or behavioral indicators

One advisory-based Sigma rule is provided below for situational awareness. It should be tuned to the specific environment and treated as a low-confidence monitoring aid, not an alerting rule.

---

## Detection Rules

### Sigma Rule: Potential Sitefinity OData Web Services Credential Leak Exploitation (CVE-2026-7312)

- **Compile Status:** PASSED
- **Confidence:** Low (advisory-based, no exploit-specific indicators)
- **Splunk Conversion:** PASSED
- **LogScale (CrowdStrike) Conversion:** PASSED
- **Note:** This rule detects access to general Sitefinity web service paths. It will produce false positives in environments with legitimate Sitefinity API usage. Intended for threat hunting and situational awareness only.

```yaml
title: Potential Sitefinity OData Web Services Credential Leak Exploitation (CVE-2026-7312)
id: 73ab04e2-c894-4b28-a4cf-7050e23c1649
status: experimental
description: >
    Detects HTTP requests targeting Progress Sitefinity OData web service endpoints
    that may indicate exploitation of CVE-2026-7312 (CVSS 10.0) or CVE-2026-7198
    (CVSS 9.8). CVE-2026-7312 allows unauthenticated credential extraction from the
    Sitefinity Insight service via OData endpoints. This is an advisory-based rule
    with limited specificity due to the absence of public exploit details.
references:
    - https://securityonline.info/sitefinity-critical-vulnerabilities/
    - https://community.progress.com/s/article/Sitefinity-Security-Advisory-for-Addressing-Security-Vulnerabilities-CVE-2026-7312-CVE-2026-7198-CVE-2026-7195-CVE-2026-7201-CVE-2026-7313-May-2026
    - https://nvd.nist.gov/vuln/detail/CVE-2026-7198
    - https://cve.threatint.eu/CVE/CVE-2026-7312
author: Actioner
date: 2026/06/08
tags:
    - attack.t1552
    - attack.t1552.001
logsource:
    category: webserver
detection:
    selection_path:
        cs-uri-stem|contains:
            - '/Sitefinity/Services/'
            - '/sf/system/'
            - '/api/default/'
    selection_method:
        cs-method:
            - 'GET'
            - 'POST'
    filter_authenticated:
        cs-uri-stem|contains:
            - '/Sitefinity/Services/Security/'
            - '/Sitefinity/Authenticate/'
    condition: selection_path and selection_method and not filter_authenticated
falsepositives:
    - Legitimate Sitefinity administrative access to web service endpoints
    - Authorized API integrations using Sitefinity OData services
    - Internal monitoring and health check systems
level: medium
```

**Splunk Conversion:**
```spl
"cs-uri-stem" IN ("*/Sitefinity/Services/*", "*/sf/system/*", "*/api/default/*") "cs-method" IN ("GET", "POST") NOT ("cs-uri-stem" IN ("*/Sitefinity/Services/Security/*", "*/Sitefinity/Authenticate/*"))
```

**CrowdStrike LogScale Conversion:**
```
"cs-uri-stem"=/\/Sitefinity\/Services\//i or "cs-uri-stem"=/\/sf\/system\//i or "cs-uri-stem"=/\/api\/default\//i "cs-method"=/^GET$/i or "cs-method"=/^POST$/i not ("cs-uri-stem"=/\/Sitefinity\/Services\/Security\//i or "cs-uri-stem"=/\/Sitefinity\/Authenticate\//i)
```

### Rules Not Generated

| Rule Type | Reason |
|-----------|--------|
| Snort | No specific network-level payloads, signatures, or packet patterns disclosed |
| Suricata | No specific network-level payloads, signatures, or packet patterns disclosed |
| YARA | No file-level indicators (hashes, byte patterns, strings) disclosed |
| Additional Sigma | No specific exploit behavioral chains available for individual CVEs |

---

## Sources

- [SecurityOnline — Sitefinity Critical Vulnerabilities](https://securityonline.info/sitefinity-critical-vulnerabilities/)
- [Progress Community — Sitefinity Security Advisory (May 2026)](https://community.progress.com/s/article/Sitefinity-Security-Advisory-for-Addressing-Security-Vulnerabilities-CVE-2026-7312-CVE-2026-7198-CVE-2026-7195-CVE-2026-7201-CVE-2026-7313-May-2026)
- [NVD — CVE-2026-7198](https://nvd.nist.gov/vuln/detail/CVE-2026-7198)
- [THREATINT — CVE-2026-7312](https://cve.threatint.eu/CVE/CVE-2026-7312)
- [THREATINT — CVE-2026-7195](https://cve.threatint.eu/CVE/CVE-2026-7195)
- [DailyCVE — CVE-2026-7312 (Critical)](https://dailycve.com/progress-sitefinity-credential-leak-cve-2026-7312-critical-dc-jun2026-209/)
- [DailyCVE — CVE-2026-7201 (Critical)](https://dailycve.com/progress-sitefinity-authorization-bypass-cve-2026-7201-critical-dc-jun2026-213/)
- [DailyCVE — CVE-2026-7313 (High)](https://dailycve.com/progress-sitefinity-cwe-522-insufficiently-protected-credentials-cve-2026-7313-high-dc-jun2026-210/)
- [CVEDetails — Progress Sitefinity](https://www.cvedetails.com/vulnerability-list/vendor_id-398/product_id-43002/Progress-Sitefinity.html)
