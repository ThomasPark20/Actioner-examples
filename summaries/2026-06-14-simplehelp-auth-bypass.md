# Technical Analysis Report: SimpleHelp OIDC Authentication Bypass — CVE-2026-48558 (2026-06-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-14
Version: 2.0 (FINAL)
<!-- revision: applied critic verdict NEEDS-REVISION — fixed Rule 1 level/filter, added T1556 rationale, un-defanged remediation URL -->

## Executive Summary

CVE-2026-48558 is a critical (CVSS 3.1: 10.0, CVSS 4.0: 9.5) authentication bypass vulnerability in SimpleHelp remote support software (versions prior to 5.5.16 and 6.0 pre-releases prior to RC2). The flaw resides in the OpenID Connect (OIDC) authentication flow: SimpleHelp accepts identity tokens without verifying their cryptographic signatures (CWE-347), allowing unauthenticated remote attackers to forge tokens with arbitrary identity claims and obtain fully authenticated technician sessions. This bypasses both credential validation and, in some configurations, multi-factor authentication. Successful exploitation grants administrative capabilities including remote access to managed endpoints and arbitrary script execution. Horizon3.ai discovered the vulnerability on May 21, 2026, notified the vendor on May 22, and publicly disclosed on June 12, 2026. Internet scanning shows exposure grew from approximately 3,400 to approximately 14,000 SimpleHelp instances, with roughly 7.2% configured to use the vulnerable OIDC authentication method (approximately 1,000 instances at risk).

## Background: SimpleHelp Remote Support

SimpleHelp is a commercial remote monitoring and management (RMM) platform used by managed service providers (MSPs) and IT support teams to remotely access, monitor, and administer endpoints across organizations. It supports technician-based access with role-based privileges. OIDC (OpenID Connect) integration allows technicians to authenticate via external identity providers. SimpleHelp has been a prior target of ransomware operators: CISA Advisory AA25-163A (June 2025) documented ransomware actors exploiting CVE-2024-57727 (a path traversal vulnerability in SimpleHelp 5.5.7 and earlier) to compromise a utility billing software provider. The current vulnerability (CVE-2026-48558) represents a new, independent attack surface in the OIDC authentication layer.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | Horizon3.ai discovers CVE-2026-48558 and validates it as exploitable |
| 2026-05-22 | Horizon3.ai notifies SimpleHelp vendor |
| 2026-05-22 to 2026-06-01 | Coordinated disclosure communications |
| 2026-05 (exact date undisclosed) | SimpleHelp releases version 5.5.16 and 6.0 RC2 with patches |
| 2026-06-12 | Public disclosure by Horizon3.ai; CVE published |
| 2026-06-13 | SecurityOnline.info publishes advisory summary |

## Root Cause: Improper Verification of Cryptographic Signature (CWE-347)

SimpleHelp's OIDC authentication flow accepts identity tokens submitted during login without verifying their cryptographic signature. The application treats any submitted token as valid regardless of its origin or integrity. This means an attacker does not need access to the identity provider's signing key --- they can construct a token from scratch with arbitrary claims (email, name, group memberships) and submit it to the SimpleHelp login endpoint. The server accepts the forged token, registers the attacker as a technician, and grants an authenticated session with full technician privileges. Because technicians can self-register their own MFA method on first login, an attacker exploiting this flaw also bypasses any existing MFA policies.

## Technical Analysis of the Malicious Payload

### 1. Initial Access: Forged OIDC Token Submission

The attacker constructs a forged OIDC identity token containing arbitrary claims (e.g., email address, display name, group memberships) without a valid cryptographic signature. This token is submitted to the SimpleHelp server's OIDC login endpoint. The server does not validate the token signature and accepts the forged identity, creating a new technician session. Horizon3.ai has stated: "At this time, we will not be releasing any more technical details surrounding the vulnerability." No public PoC exploit code has been released.

### 2. Post-Exploitation: Technician Session Abuse

Once authenticated as a technician, the attacker gains administrative capabilities:
- Remote access to all managed endpoints connected to the SimpleHelp instance
- Execution of scripts and commands on managed endpoints
- Configuration changes to the SimpleHelp server itself
- Potential lateral movement across all endpoints managed by the compromised SimpleHelp instance

### 3. C2 Infrastructure

No specific C2 infrastructure has been published in connection with CVE-2026-48558 exploitation. Horizon3.ai's disclosure focused on detection indicators within SimpleHelp server logs rather than attacker infrastructure.

### 4. Platform-Specific Behavior

SimpleHelp is cross-platform (Windows, Linux, macOS server deployments). The OIDC authentication bypass is server-side and platform-independent. The primary log artifact location varies:
- **Linux**: `/opt/SimpleHelp/logs/server.log` and `/opt/SimpleHelp/logs/<YYYYMMDD-HHMMSS>/server.log`
- **Windows**: Typically `C:\Program Files\SimpleHelp\logs\server.log`

### 5. Anti-Forensics / Evasion Techniques

No specific anti-forensics or evasion techniques have been documented for this vulnerability. The attack leverages the legitimate authentication flow, which means log entries may appear similar to normal OIDC login events unless scrutinized for unfamiliar technician identities.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| SimpleHelp Server | < 5.5.16 | OIDC token signature verification bypass |
| SimpleHelp Server | 6.0 pre-release (< RC2) | Same OIDC token signature verification bypass |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | /opt/SimpleHelp/logs/server.log | N/A | Primary log file containing exploitation evidence |
| Linux | /opt/SimpleHelp/logs/\<YYYYMMDD-HHMMSS\>/server.log | N/A | Rotated log files |

### Network

No network-layer IOCs (malicious IPs, domains, or URL patterns) have been published for CVE-2026-48558. Horizon3.ai withheld exploitation details and no C2 infrastructure has been attributed.

### Behavioral

The following log entries in SimpleHelp `server.log` indicate potential CVE-2026-48558 exploitation:

1. **Unauthorized technician registration**: `"Registering technician login for [email]"` where the email is not a recognized, authorized technician
2. **Forged configuration save**: `"Configuration save requested (Forged Attacker - [email] [(Technicians)] [New Anon])"` --- the `[New Anon]` marker combined with an unrecognized identity indicates a forged OIDC token was used to establish a technician session

Defenders should audit these log entries against known authorized technician email addresses. Any registration from an unrecognized email --- particularly from outside the organization's identity provider domain --- warrants immediate investigation.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1078 | Valid Accounts | Attacker obtains a fully authenticated technician session via forged OIDC token, effectively using a "valid" account created through the bypass |
| T1556 | Modify Authentication Process | The attack exploits the absence of token signature verification in the OIDC authentication flow, subverting the intended authentication process. Rationale: the server's broken verification is treated as a subverted authentication mechanism — the OIDC flow itself becomes the modified process, accepting unsigned tokens as if they were legitimate. |
| T1219 | Remote Access Software | Post-exploitation leverages SimpleHelp's built-in remote access capabilities to control managed endpoints |
| T1059 | Command and Scripting Interpreter | Post-exploitation includes execution of scripts on managed endpoints via the compromised technician session |

## Impact Assessment

- **Breadth**: Approximately 14,000 SimpleHelp instances are internet-exposed; approximately 7.2% (~1,008) use vulnerable OIDC configurations. The actual number of exploitable instances depends on whether OIDC is configured and whether patching has occurred.
- **Depth**: CVSS 10.0 --- full compromise of the SimpleHelp server and all managed endpoints. The attacker inherits the trust relationship between the RMM platform and every endpoint it manages.
- **Stealth**: Moderate --- exploitation leaves log traces but uses the legitimate authentication flow, making automated detection dependent on monitoring for unrecognized technician identities.
- **Supply chain risk**: SimpleHelp is often embedded in MSP infrastructure; compromise of a single SimpleHelp instance can cascade to all downstream managed clients.

## Detection & Remediation

### Immediate Detection

1. **Review SimpleHelp server logs** for unauthorized technician registrations:
   ```bash
   grep -i "Registering technician login for" /opt/SimpleHelp/logs/server.log
   grep -i "Configuration save requested" /opt/SimpleHelp/logs/server.log | grep "\[New Anon\]"
   ```
2. **Audit active technician sessions**: Check the SimpleHelp admin console for any unrecognized technician accounts, especially those with OIDC-sourced identities.
3. **Check historical logs**: Review rotated logs under `/opt/SimpleHelp/logs/<YYYYMMDD-HHMMSS>/` for evidence of exploitation between discovery (May 21) and patching.

### Remediation

1. **Patch immediately**: Update to SimpleHelp 5.5.16 (for 5.5.x users) or 6.0 RC2 (for 6.0 pre-release users). Update URL: https://simple-help.com/releases/5.5.16_202605
2. **Revoke unauthorized sessions**: Terminate any unrecognized technician sessions and remove unauthorized technician accounts.
3. **Rotate credentials**: If exploitation is confirmed, rotate all credentials accessible through the SimpleHelp instance, including technician credentials and any credentials stored for managed endpoints.
4. **Review managed endpoints**: Investigate all endpoints managed by a compromised SimpleHelp instance for evidence of unauthorized access or script execution.

### Long-Term Hardening

1. **Implement IP restrictions** limiting authentication sources to known identity provider IP ranges.
2. **Apply network segmentation** to restrict SimpleHelp server access to authorized management networks.
3. **Monitor SimpleHelp logs** with SIEM integration using the Sigma rules provided below.
4. **Review OIDC configuration**: Ensure OIDC identity providers enforce token signing and that SimpleHelp is configured to require signature validation (post-patch).
5. **Advisory**: Disabling OIDC authentication as an interim mitigation is configuration-dependent; verify that alternative authentication methods are available and that disabling OIDC does not lock out legitimate technicians before applying this measure.

## Detection Rules

Two Sigma rules target the distinctive log entries documented by Horizon3.ai as indicators of CVE-2026-48558 exploitation. Both key on SimpleHelp application log strings specific to unauthorized OIDC technician session creation. No network IOCs were published, so Snort/Suricata rules are not applicable; no file-level indicators exist for YARA. Compiles does not equal fires --- verify these rules against your SimpleHelp log ingestion pipeline and adjust the `logsource` mapping to match your SIEM's field names.

### Sigma: SimpleHelp Unauthorized Technician Registration via OIDC

Detects the `"Registering technician login for"` log entry in SimpleHelp server logs, indicating a new technician session was created --- potentially via a forged OIDC token (CVE-2026-48558). Scope the `filter_known_admins` exclusion to your organization's legitimate technician email addresses.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. No matching pipeline for SimpleHelp (custom app log). logsource product:simplehelp / category:application is a custom mapping — the user must configure their SIEM to route SimpleHelp server.log entries to this source. Confidence medium (not high) because the log string also fires on legitimate first-time OIDC logins; the filter must be tuned to known admins per-environment. FP risk: any legitimate new OIDC technician registration. Evasion: attacker could potentially modify logs post-compromise if they gain OS-level access. -->
<!-- revision: level high→medium (matches confidence medium); removed placeholder email from filter_known_admins, added YAML comment instructing deployer to populate it -->
```yaml
title: SimpleHelp OIDC Authentication Bypass - Unauthorized Technician Registration (CVE-2026-48558)
id: 7c3a1e9f-4d2b-4f8e-a6c1-9e5d3b7f2a08
status: experimental
description: >
    Detects unauthorized technician login registration in SimpleHelp server logs,
    indicative of CVE-2026-48558 exploitation where a forged OIDC identity token
    is used to create an authenticated technician session without valid credentials.
references:
    - https://horizon3.ai/attack-research/disclosures/cve-2026-48558-simplehelp-authentication-bypass-iocs/
    - https://securityonline.info/simplehelp-authentication-bypass/
    - https://simple-help.com/security/simplehelp-security-update-2026-05
author: Actioner
date: 2026/06/14
tags:
    - attack.t1078
    - attack.t1556
logsource:
    category: application
    product: simplehelp
detection:
    selection:
        message|contains: 'Registering technician login for'
    # filter_known_admins:
    #     message|contains:
    #         - 'admin@yourorg.com'       # REPLACE with your authorized technician emails
    #         - 'tech-team@yourorg.com'   # Add one entry per legitimate technician
    condition: selection  # Uncomment and use: selection and not filter_known_admins
falsepositives:
    - Legitimate first-time OIDC technician logins from authorized identity providers
    - Initial setup of OIDC authentication with valid technicians
level: medium
```

### Sigma: SimpleHelp Forged Technician Configuration Save (CVE-2026-48558)

Detects the `"Configuration save requested ... [New Anon]"` log entry in SimpleHelp, a strong indicator of a forged OIDC technician session performing administrative actions post-exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. No matching pipeline (custom app log). The '[New Anon]' marker combined with 'Configuration save requested' is highly specific to the exploitation pattern documented by Horizon3.ai — this combination should not appear in normal operations. Confidence high because the dual-string match is distinctive and unlikely in benign activity. FP risk: very low — only if a legitimate new anonymous technician immediately triggers a config save (unusual). logsource mapping note same as rule 1. -->
```yaml
title: SimpleHelp Forged Technician Configuration Save (CVE-2026-48558)
id: 1b8d4e6a-3f5c-4a9b-b2d7-8e1f0c6a5d39
status: experimental
description: >
    Detects a configuration save event in SimpleHelp server logs initiated by an
    unrecognized technician identity with the '[New Anon]' marker, consistent with
    CVE-2026-48558 post-exploitation where a forged OIDC token grants administrative
    capabilities to an attacker-controlled session.
references:
    - https://horizon3.ai/attack-research/disclosures/cve-2026-48558-simplehelp-authentication-bypass-iocs/
    - https://securityonline.info/simplehelp-authentication-bypass/
    - https://simple-help.com/security/simplehelp-security-update-2026-05
author: Actioner
date: 2026/06/14
tags:
    - attack.t1078
    - attack.t1556
logsource:
    category: application
    product: simplehelp
detection:
    selection:
        message|contains|all:
            - 'Configuration save requested'
            - '[New Anon]'
    condition: selection
falsepositives:
    - Legitimate new technician performing initial configuration via OIDC in an authorized setup
level: critical
```

### Snort: N/A

No network-layer IOCs (IP addresses, domains, URL patterns, HTTP request signatures) were published by Horizon3.ai or the vendor for CVE-2026-48558. Generating a Snort rule without concrete network indicators would produce a broad, false-positive-prone detection.

### Suricata: N/A

No network-layer IOCs were published. Same rationale as Snort above. If network exploitation patterns are disclosed in the future (e.g., specific HTTP request structure for token submission), Suricata rules targeting the OIDC login endpoint could be developed.

### YARA: N/A

No file-level indicators (malware samples, byte patterns, embedded strings) are associated with this vulnerability. CVE-2026-48558 is an authentication bypass exploited via crafted HTTP requests, not via malicious files.

## Lessons Learned

1. **OIDC signature verification is non-negotiable.** Accepting identity tokens without cryptographic signature validation is equivalent to having no authentication. This is a well-known class of vulnerability (CWE-347) that should be caught by security review of any OIDC integration.
2. **RMM platforms are high-value targets.** A single compromised RMM instance grants access to every managed endpoint, making RMM platforms a force-multiplier for attackers. This is the second major SimpleHelp vulnerability exploited in the wild in 18 months (following CVE-2024-57727).
3. **Coordinated disclosure timelines matter.** Horizon3.ai's decision to withhold technical exploitation details while providing detection guidance (log indicators) gives defenders a detection advantage before full exploitation details emerge.
4. **MFA is only as strong as the authentication flow it protects.** Because SimpleHelp allowed technicians to self-register MFA on first login, bypassing the initial authentication also bypassed MFA --- a design flaw that compounds the OIDC vulnerability.

## Sources

- [Horizon3.ai CVE-2026-48558 Disclosure & IOCs](https://horizon3.ai/attack-research/disclosures/cve-2026-48558-simplehelp-authentication-bypass-iocs/) --- primary technical source; discovery, timeline, detection log indicators, disclosure details
- [SecurityOnline.info: SimpleHelp Authentication Bypass](https://securityonline.info/simplehelp-authentication-bypass/) --- initial reporting article covering vulnerability summary and impact
- [SimpleHelp Security Update 2026-05](https://simple-help.com/security/simplehelp-security-update-2026-05) --- vendor advisory with affected/fixed versions and patch download links
- [THREATINT CVE-2026-48558](https://cve.threatint.eu/CVE/CVE-2026-48558) --- CVE metadata including CVSS vectors, CWE classification, and researcher attribution (Zach Hanley / Horizon3.ai)
- [CISA Advisory AA25-163A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-163a) --- prior CISA advisory on ransomware actors exploiting SimpleHelp RMM (CVE-2024-57727), establishing the pattern of RMM-targeted attacks

---
*Report generated by Actioner*
