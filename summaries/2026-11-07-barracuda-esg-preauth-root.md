# Barracuda ESG Pre-Authentication Root Chain (CVE-2026-116606 + CVE-2026-111560)

> **Status**: FINAL -- Actioner CTI Pipeline  
> **Date**: 2026-11-07  
> **Analyst**: Automated Research Pipeline  
> **Classification**: TLP:CLEAR  
> **Confidence**: HIGH (vendor-confirmed, PoC public, detailed technical analysis available)

---

## Executive Summary

Two vulnerabilities in Barracuda Email Security Gateway (ESG) -- CVE-2026-116606 (pre-authentication authorization bypass, CVSS 9.3) and CVE-2026-111560 (OS command injection, CVSS 8.6) -- can be chained by an unauthenticated remote attacker to achieve root-level command execution on the appliance. The authorization bypass allows an unauthenticated attacker to invoke the configuration-import (backup restore) function, and the command injection leverages unsanitized shell metacharacters in the `system_timezone` database field during restore processing. watchTowr published a detailed technical analysis and a detection artifact generator on November 6, 2026. Barracuda released patches on November 2, 2026. No confirmed in-the-wild exploitation has been reported as of the date of this report. Given the high-value nature of email security gateways and historical targeting of Barracuda ESG (cf. CVE-2023-2868 / UNC4841), this vulnerability chain presents a critical risk to organizations with internet-exposed ESG administrative interfaces.

---

## Background

Barracuda Email Security Gateway is an enterprise email security appliance deployed on-premises or in cloud environments to filter inbound and outbound email traffic. It is a high-value target for threat actors seeking access to enterprise communications, as demonstrated by the 2023 zero-day campaign (CVE-2023-2868) attributed to UNC4841, a China-nexus espionage group tracked by Mandiant.

Mandiant assigned both CVE records (advisories MNDT-2026-0042 and MNDT-2026-0041). watchTowr, a security research firm, independently analyzed the vulnerabilities and published a full technical write-up and detection tool. The researcher credited is Sina Kheirkhah (@SinSinology) of watchTowr.

---

## Attack Timeline

| Date | Event |
|------|-------|
| 2026-10-15 | Barracuda receives report for command injection (CVE-2026-111560) |
| 2026-10-22 | Barracuda receives report for authorization bypass (CVE-2026-116606) |
| 2026-11-02 | Barracuda publishes security advisory and releases patches |
| 2026-11-03 | The Hacker News and Security Affairs publish initial coverage |
| 2026-11-05 | Barracuda advisory updated: authentication field for CVE-2026-116606 changed from "Yes" to "No" |
| 2026-11-06 | watchTowr publishes detailed technical analysis and PoC detection tool |
| 2026-11-06 | SecurityWeek and additional outlets publish detailed coverage |
| 2026-11-07 | No confirmed in-the-wild exploitation; neither CVE in CISA KEV catalog |

---

## Root Cause

### CVE-2026-116606: Pre-Authentication Authorization Bypass (CWE-288)

The ESG web interface at `/cgi-mod/index.cgi` has a flawed password change handler. When a password change request is submitted with `new_password` and `retype_password` parameters and fails (e.g., from an unauthenticated session), the error handling code returns a low-privilege role instead of terminating the session. This leaves the backup-restore function reachable without a valid authenticated session. The vulnerability exists only in the ESG product.

### CVE-2026-111560: OS Command Injection (CWE-78)

The `system_timezone` configuration value stored in MySQL (within the `Spam_Config` component) is interpolated without sanitization into shell commands executed as root:

1. **`Backup2.pm`**: Uses backtick execution with `sed` against `/home/product/code/config/tz`, passing the `system_timezone` value unsanitized.
2. **`fix_tz.pl`**: Uses backtick execution with `sed` against `/etc/sysconfig/clock`, invoked via `/usr/bin/sudo` as root.

This vulnerability affects all six Barracuda products that share the common timezone handling code, but requires administrator credentials on products other than the ESG (where the auth bypass provides the necessary access).

---

## Technical Analysis

### Exploitation Flow

```
Step 1: Authorization Bypass (CVE-2026-116606)
+-----------------------------------------------+
| POST /cgi-mod/index.cgi                       |
| Content-Type: multipart/form-data             |
| Fields: user, new_password, retype_password   |
+-----------------------------------------------+
        |
        | Failed password change returns low-priv role
        | instead of terminating unauthenticated session
        v
Step 2: Backup Upload (CVE-2026-116606 continued)
+-----------------------------------------------+
| POST /cgi-mod/index.cgi                       |
| Content-Type: multipart/form-data             |
| Fields: pu_bayesian_upload=1                  |
|         bayesian=<crafted_backup.bak>         |
+-----------------------------------------------+
        |
        | Backup is a tar archive containing backup.xml
        | Checksums are MD5 with hardcoded static secret
        | Attacker can forge valid checksums
        v
Step 3: Restore Processing (CVE-2026-111560)
+-----------------------------------------------+
| Backup2::restore_all processes the archive    |
| Spam_Config component restores MySQL data     |
| system_timezone value contains injection:     |
|   e.g. "UTC;touch /tmp/pwned"                 |
| Backup2.pm: backtick sed on /home/.../tz      |
| fix_tz.pl: sudo backtick sed on /etc/clock    |
| --> Command executes as root                  |
+-----------------------------------------------+
```

### Key Technical Details

**Target Endpoint**: `POST /cgi-mod/index.cgi` (multipart/form-data)

**Auth Bypass Parameters**:
- `user` -- username field
- `new_password` -- new password value
- `retype_password` -- password confirmation
- The failed change triggers `ERROR_PASSWD_CHANGE` response with HTTP 200

**Backup Upload Parameters**:
- `pu_bayesian_upload` -- set to trigger upload handler
- `bayesian` -- file upload field (the crafted `.bak` archive)
- Additional field: `UPDATE_activation_code`

**Backup Archive Structure**:
- Format: tar archive
- Contains: `backup.xml` listing components and per-component MD5 checksums
- Checksum scheme: MD5 with a static, hardcoded secret value appended
- Key component: `Spam_Config` -- restores MySQL data including `system_timezone` row
- Staging directory: `/mail/tmp`

**Injection Sink**:
- The `system_timezone` value is passed unsanitized into backtick-interpolated `sed` commands
- Shell metacharacters (`;`, `|`, `` ` ``, `$()`) in the timezone value execute arbitrary commands as root

**Critical File Paths**:
- `/cgi-mod/index.cgi` -- vulnerable web endpoint
- `/tmp/bypass_password` -- bypass check file (not satisfied during normal operation)
- `/home/product/code/config/tz` -- timezone config written by `Backup2.pm`
- `/etc/sysconfig/clock` -- system clock config written by `fix_tz.pl`
- `/home/product/code/firmware/current/bin/fix_tz.pl` -- root-level timezone script
- `/mail/tmp` -- backup restore staging directory
- `/usr/share/zoneinfo/` -- used by patched code for validation

**Patched Behavior (9.4.0.029+)**: The `system_timezone` value is validated against entries in `/usr/share/zoneinfo/` before use in shell commands.

---

## IOCs

### Network Indicators

- `POST` requests to `/cgi-mod/index.cgi` containing `new_password` + `retype_password` parameters from unauthenticated sessions
- `POST` requests to `/cgi-mod/index.cgi` with `pu_bayesian_upload` parameter and tar archive uploads
- `multipart/form-data` uploads to the ESG admin interface containing `backup.xml` with `Spam_Config` components
- HTTP responses containing `ERROR_PASSWD_CHANGE` with HTTP 200 status

### Host Indicators

- Unexpected files in `/tmp/` or `/mail/tmp/` directories
- `system_timezone` MySQL value containing shell metacharacters (`;`, `|`, `` ` ``, `$`, `(`)
- Anomalous timezone values not matching `/usr/share/zoneinfo/` entries
- Unexpected process spawns from Perl/web service: `sh`, `bash`, `sed` as root
- `sudo` executing `fix_tz.pl` outside of normal administrative operations
- Creation of `/tmp/bypass_password`
- `failed_password_change` audit events without corresponding authenticated sessions
- Unexpected modifications to `/home/product/code/config/tz` or `/etc/sysconfig/clock`

### Tool Signatures

- watchTowr PoC tool: `watchTowr-vs-Barracuda-RCE.py`
- GitHub repository: `watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560`
- Crafted backup artifacts approximately 10240 bytes (observed in PoC output; may vary)

---

## MITRE ATT&CK Mapping

<!-- revision: removed T1211 (auth bypass is T1190 initial access, not defense evasion); relabeled T1505 as speculative (no persistence evidence in advisory/PoC); replaced T1212 with T1114 (root on email GW enables email interception, not credential exploitation). -->

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of internet-exposed ESG admin interface via auth bypass + backup upload |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Command injection via `system_timezone` in `sed` backtick calls |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Auth bypass escalates from unauthenticated to admin; command injection from admin to root |
| Collection | Email Collection | T1114 | Root access on email gateway enables interception of all organizational email traffic |
| Persistence (speculative) | Server Software Component | T1505 | Not observed in advisory or PoC; included as a plausible post-exploitation objective given the appliance type |

---

## Impact Assessment

### Severity: CRITICAL

- **Attack Complexity**: Low -- PoC detection tool is public; full exploit chain is well-documented
- **Authentication**: None required (pre-auth chain on ESG)
- **Privileges Gained**: Root on the appliance
- **Affected Products**: 6 Barracuda products (CVE-2026-111560); ESG uniquely affected by the full chain

### Affected Products and Patch Status

| Product | CVE-2026-116606 | CVE-2026-111560 | Patch ID | Fixed Version |
|---------|:---:|:---:|----------|---------------|
| Email Security Gateway | Yes | Yes | BNSF-40425 (>=9.4.017) / BNSF-40430 (<9.4.017) | 9.4.0.029+ |
| Load Balancer ADC | No | Yes | BNADC-16586 | 6.4.0+ patched |
| Message Archiver | No | Yes | BNMA-32468 | 5.5.4.0+ patched |
| WAF Control Center | No | Yes | BNWF-60060 | 2.2.1+ patched |
| Web Application Firewall | No | Yes | BNADC-16586 | 11.0.1+ patched |
| Web Security Gateway | No | Yes | BNYF-24789 | 16.1.100.100+ patched |

### Risk Factors

- Email security gateways process all organizational email -- root access enables full email interception
- Historical precedent: Barracuda ESG was targeted by UNC4841 in 2023 (CVE-2023-2868) as a zero-day
- Internet-exposed admin interfaces are at highest risk; internal-only deployments face reduced but non-zero risk
- The watchTowr PoC tool lowers the barrier for exploitation significantly

---

## Detection & Remediation

### Immediate Actions

1. **Patch immediately**: Update to ESG version 9.4.0.029 or later. Apply patches for all other affected Barracuda products.
2. **Restrict admin interface**: Ensure administrative interfaces are accessible only from trusted internal networks. Apply network ACLs.
3. **Re-enable auto-patching**: If automatic patching was disabled, re-enable it.
4. **Multi-step upgrades**: Devices several firmware versions behind may require incremental updates.

### Compromise Assessment

1. Review configuration-import and backup restore history for unauthorized operations
2. Export current global configuration and diff against known-good baselines
3. Inspect `system_timezone` MySQL values for shell metacharacters or non-standard timezone strings
4. Review authentication logs for sessions that accessed admin functions without a matching successful login
5. Check for unexpected files in `/tmp/`, `/mail/tmp/`, and web-accessible directories
6. Audit process execution logs for anomalous root commands spawned by web/application services
7. Check for modifications to `/home/product/code/config/tz` and `/etc/sysconfig/clock`

### Long-Term Recommendations

- Implement network segmentation isolating management interfaces from user traffic and the internet
- Deploy web application firewall rules (if not on the ESG itself) to inspect traffic to admin endpoints
- Establish continuous monitoring for the detection rules provided below
- Consider deploying the watchTowr detection tool to verify remediation: [watchTowr Detection Tool](https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560)

---

## Detection Rules

### Sigma: Barracuda ESG Pre-Auth Root Chain Exploitation

<!-- revision: downgraded confidence HIGH->MEDIUM; cs-body is non-standard Sigma webserver field; removed service:barracuda (non-portable); removed tactic tags per spec (technique-only); added body-logging prerequisite note. sigma convert splunk+log_scale exit 0. -->

Detects POST requests to `/cgi-mod/index.cgi` containing auth bypass (password change) or backup upload (`pu_bayesian_upload`) parameters. Inoperable without HTTP body logging enabled on the upstream proxy/WAF.
**Status:** compile ✅ compiles (Splunk + LogScale) · confidence: medium
<!-- audit: sigma check blocked by proxy MITRE fetch; sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. cs-body is not a standard Sigma webserver field; requires body logging. Removed service:barracuda as non-portable; removed tactic tags (attack.initial_access etc.) per Sigma spec (technique-only). FP: legit admin password changes / backup restores; correlate with authenticated session tokens. -->

```yaml
title: Barracuda ESG Pre-Auth Root Chain Exploitation Attempt (CVE-2026-116606 / CVE-2026-111560)
id: a3f7c1e2-9b04-4d8e-b6a1-2c5d8f0e3a7b
status: experimental
description: >
    Detects HTTP POST requests to the Barracuda ESG CGI endpoint /cgi-mod/index.cgi
    containing password change parameters (new_password, retype_password) or backup
    upload parameters (pu_bayesian_upload) that indicate exploitation of the pre-auth
    authorization bypass (CVE-2026-116606) and command injection (CVE-2026-111560) chain.
    Requires HTTP body logging to be enabled.
references:
    - https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection
    - https://labs.watchtowr.com/barracuda-networks-is-your-new-best-friend-barracuda-email-security-gateway-pre-auth-remote-root-rce-cve-2026-116606-cve-2026-111560/
    - https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560
author: Actioner CTI Pipeline
date: 2026-11-07
modified: 2026-11-07
tags:
    - attack.t1190
    - attack.t1059.004
    - attack.t1068
    - cve.2026-116606
    - cve.2026-111560
logsource:
    category: webserver
    # NOTE: cs-body is not a standard Sigma webserver field. Requires HTTP body
    # logging enabled on upstream proxy/WAF. Adapt field names to your pipeline.
detection:
    selection_endpoint:
        cs-uri-stem|contains: '/cgi-mod/index.cgi'
        cs-method: 'POST'
    selection_auth_bypass:
        cs-body|contains|all:
            - 'new_password'
            - 'retype_password'
    selection_backup_upload:
        cs-body|contains: 'pu_bayesian_upload'
    condition: selection_endpoint and (selection_auth_bypass or selection_backup_upload)
falsepositives:
    - Legitimate administrator password changes via the Barracuda ESG web interface (correlate with authenticated sessions)
    - Legitimate backup restore operations performed by administrators
level: medium
```

---

### Snort: Barracuda ESG Exploitation Detection (4 rules)

<!-- revision: SID 2026110703 rev:1->rev:2; added distance:0; within:200; after system_timezone match to anchor backtick byte to timezone field. Clarified description from "payload-dependent" to positional-anchoring note. Snort 2.9.20 -T exit 0. -->

Four Snort rules targeting auth bypass, backup upload, command injection, and PoC tool detection. SID 2026110703 anchors the backtick byte (`|60|`) within 200 bytes of `system_timezone` via `distance:0; within:200;`.
**Status:** compile ✅ compiles (Snort 2.9.20) · confidence: HIGH (SIDs 01/02/04), MEDIUM (SID 03)
<!-- audit: snort -c snort.conf -T exit 0. SID 2026110703 rev:2 adds distance:0/within:200 to anchor |60| relative to system_timezone in http_client_body. Prior rev had no positional constraint, allowing backtick match anywhere in body. All rules require http_inspect preprocessor. -->

| SID | Description | Confidence |
|-----|-------------|------------|
| 2026110701 | Auth bypass - password change fields to CGI endpoint | HIGH |
| 2026110702 | Backup upload via multipart form to CGI endpoint | HIGH |
| 2026110703 | Command injection - backtick within 200 bytes of `system_timezone` | MEDIUM |
| 2026110704 | watchTowr PoC tool User-Agent detection | HIGH |

---

### Suricata: Barracuda ESG Exploitation Detection (4 rules)

Four Suricata rules using native `http.*` sticky buffers. SID 2026110803 uses PCRE to match shell metacharacters near `system_timezone`.
**Status:** compile ✅ compiles (Suricata 7.0.3) · confidence: HIGH (SIDs 01/02/04), MEDIUM (SID 03)
<!-- audit: suricata -T exit 0. SID 03 PCRE hex-escaped metacharacters (\x3b semicolon, \x7c pipe, \x60 backtick, \x24 dollar) with /P flag. No changes from draft. -->

| SID | Description | Confidence |
|-----|-------------|------------|
| 2026110801 | Auth bypass - password change fields (http.request_body) | HIGH |
| 2026110802 | Backup upload via pu_bayesian_upload + multipart content type | HIGH |
| 2026110803 | Command injection - shell metacharacters after system_timezone (PCRE) | MEDIUM |
| 2026110804 | watchTowr PoC tool string in HTTP headers | HIGH |

---

### YARA: Barracuda ESG Backup and Tool Detection (3 rules)

<!-- revision: Post-exploit rule confidence MEDIUM->LOW; removed $sudo_fix from condition (trivially present in legit ESG files, guaranteed FP on clean appliance fix_tz.pl). Condition now requires $inject_marker* (actual injection evidence). yarac exit 0. -->

Three YARA rules for crafted backup detection, PoC tool detection, and post-exploitation filesystem forensics.
**Status:** compile ✅ compiles (yarac) · confidence: HIGH (rules 1-2), LOW (rule 3)
<!-- audit: yarac exit 0. Rule 3 revised: removed $sudo_fix="sudo" alternative from condition; the legit fix_tz.pl contains "sudo" + tz paths + its own name, guaranteeing FP on clean appliances. Now requires any of ($inject_marker*) -- actual shell metacharacter injection evidence in ZONE= values. -->

| Rule | Description | Confidence |
|------|-------------|------------|
| `Barracuda_ESG_Crafted_Backup_CVE_2026_116606` | Detects crafted backup archives with timezone injection payloads | HIGH |
| `Barracuda_ESG_watchTowr_PoC_Script` | Detects the watchTowr PoC Python script | HIGH |
| `Barracuda_ESG_Post_Exploit_Timezone_Injection` | Detects timezone injection artifacts on ESG filesystem | LOW |

---

## Sources

- [Barracuda Security Advisory: Pre-Authentication Authorization Bypass and Command Injection](https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection)
- [watchTowr Technical Analysis: Barracuda ESG Pre-Auth Remote Root RCE](https://labs.watchtowr.com/barracuda-networks-is-your-new-best-friend-barracuda-email-security-gateway-pre-auth-remote-root-rce-cve-2026-116606-cve-2026-111560/)
- [watchTowr Detection Artifact Generator (GitHub)](https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560)
- [The Hacker News: Barracuda Flaws Could Be Chained To... (Nov 3)](https://thehackernews.com/2026/11/barracuda-flaws-could-be-chained-to.html)
- [The Hacker News: Experts Demonstrate Barracuda Email... (Nov 6)](https://thehackernews.com/2026/11/experts-demonstrate-barracuda-email.html)
- [Security Affairs: Two Barracuda ESG Flaws Could Be Combined for Full Root Access (Nov 4)](https://securityaffairs.com/202440/security/two-barracuda-esg-flaws-could-be-combined-for-full-root-access-patches-released.html)
- [SecurityWeek: Barracuda ESG Authentication Bypass Opens Path to Root](https://www.securityweek.com/barracuda-email-security-gateway-authentication-bypass-opens-path-to-root/)
- [Ostorlab: Barracuda ESG Pre-Auth Bypass CVE-2026-116606](https://blog.ostorlab.co/barracuda-esg-pre-auth-bypass-cve-2026-116606.html)
- [Barracuda Campus Patch Guidance](https://documentation.campus.barracuda.com/wiki/x/n4BGOQ)
- [Rescana: Barracuda ESG Root Path Analysis](https://www.rescana.com/post/barracuda-esg-cve-2026-116606-111560-root-prepare-now)
