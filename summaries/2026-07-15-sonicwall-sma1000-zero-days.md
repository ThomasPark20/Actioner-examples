# Technical Analysis Report: SonicWall SMA 1000 Zero-Day Vulnerabilities (2026-07-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-15
Version: FINAL

## Executive Summary

Two critical zero-day vulnerabilities in SonicWall Secure Mobile Access (SMA) 1000 series appliances are under active exploitation. CVE-2026-15409 is a CVSS 10.0 server-side request forgery (SSRF) flaw in the Appliance Work Place interface allowing remote unauthenticated attackers to force the appliance to make requests to unintended internal locations. CVE-2026-15410 is a CVSS 7.2 post-authentication code injection vulnerability in the Appliance Management Console (AMC) enabling authenticated administrators to execute arbitrary OS commands. The two vulnerabilities are being exploited in tandem in observed attacks, forming a chain where the SSRF is used to gain initial access and the code injection achieves command execution.

SonicWall released emergency hotfixes (12.4.3-03453 and 12.5.0-02835) on July 14, 2026. CISA added both to the Known Exploited Vulnerabilities (KEV) catalog with a compliance deadline of July 17, 2026. Affected models include the SMA 6210, SMA 7210, and SMA 8200v. No mitigations exist short of patching; SonicWall advises re-imaging compromised appliances and resetting all credentials and TOTP tokens.

## Background: SonicWall SMA 1000 Series

SonicWall Secure Mobile Access (SMA) 1000 series appliances are enterprise-grade remote access gateways that provide SSL VPN and zero-trust network access to corporate resources. They sit at the network perimeter and authenticate remote users before granting access to internal applications. The SMA 1000 product line includes the SMA 6210, SMA 7210, and SMA 8200v (virtual) models. Due to their perimeter position and role as authentication brokers, these appliances are high-value targets for threat actors -- compromise of an SMA gateway yields direct access to internal networks and the ability to intercept credentials.

The SMA 1000 series is distinct from the SMA 100 series; the SMA 100 is **not** affected by these vulnerabilities. Similarly, SonicWall's firewall-based SSL-VPN products are not impacted.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-July 14, 2026 | Multiple active exploitation incidents observed by SonicWall and Volexity |
| 2026-07-14 | SonicWall contacts affected customers and provides hotfixes ahead of public disclosure |
| 2026-07-14 | SonicWall publishes PSIRT advisory SNWLID-2026-0008 |
| 2026-07-14 | CISA adds CVE-2026-15409 and CVE-2026-15410 to KEV catalog |
| 2026-07-17 | CISA BOD 26-04 compliance deadline for federal agencies |

## Root Cause: Exploitation of Public-Facing SMA 1000 Appliance

The attacker chain exploits two distinct weaknesses in the SMA 1000 appliance interfaces:

**CVE-2026-15409 (CWE-918: Server-Side Request Forgery)** -- The Appliance Work Place interface fails to properly validate user-supplied URLs, allowing a remote unauthenticated attacker to cause the appliance to make HTTP requests to arbitrary internal or external destinations. The CVSS 3.1 vector (`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) reflects maximum severity: no authentication required, low complexity, changed scope, and full impact across confidentiality, integrity, and availability.

**CVE-2026-15410 (CWE-94: Improper Control of Generation of Code)** -- The Appliance Management Console (AMC) contains a code injection flaw that allows a remote authenticated administrator to execute arbitrary operating system commands under specific conditions. While it requires high privileges (PR:H), in observed attacks this is achieved through the SSRF chain.

The two vulnerabilities are exploited **in tandem**: the SSRF (CVE-2026-15409) provides the unauthenticated entry point and is then chained with the code injection (CVE-2026-15410) to achieve full command execution on the appliance.

## Technical Analysis of the Malicious Payload

### 1. Initial Access via SSRF (CVE-2026-15409)

The attacker targets the SMA 1000 Work Place interface with a crafted request that exploits the SSRF vulnerability. This forces the appliance to make requests to unintended locations, potentially accessing internal services, internal management interfaces, or cloud metadata endpoints. The SSRF can be exploited remotely without any authentication.

Exploitation artifacts include the creation of unauthorized routes in the appliance's NGINX Unit configuration file (`/var/lib/unit/conf.json`), specifically adding routes for `/__api__/login` and `/__api__/logout` endpoints that do not exist in legitimate configurations.

### 2. Code Injection and Command Execution (CVE-2026-15410)

Once the attacker achieves authenticated access to the AMC (potentially through the SSRF chain), the code injection vulnerability enables arbitrary OS command execution as administrator. This provides full control over the appliance operating system.

### 3. Persistence and Post-Exploitation Indicators

Observed exploitation indicators include:

- **Hotfix rollback with path traversal**: Entries in `ctrl-service.log` showing hotfix rollbacks with path traversal characters in filenames, suggesting the attacker manipulates the hotfix mechanism to maintain persistence or deploy malicious payloads.
- **WebSocket proxy abuse**: Requests to `/wsproxy` with suspicious host parameters and HTTP 101 (WebSocket upgrade) status, indicating the SSRF is used to proxy attacker connections through the appliance.
- **Unauthorized API routes**: The `/__api__/login` and `/__api__/logout` routes injected into `/var/lib/unit/conf.json` serve as persistent backdoor entry points.

### 4. Platform-Specific Behavior

#### SMA 1000 (Linux-based appliance)

The SMA 1000 runs a Linux-based operating system. Exploitation targets the web application layer (NGINX Unit configuration, Python/Java application stack) rather than the underlying OS directly. Post-exploitation commands execute in the appliance's Linux environment with administrator-level privileges.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| SMA 1000 (Linux) | /var/lib/unit/conf.json | N/A | NGINX Unit configuration file -- check for unauthorized `/__api__/login` or `/__api__/logout` routes |

### Network

No specific IP addresses, domains, or C2 infrastructure have been publicly attributed to the exploitation campaigns at this time.

### Behavioral

**Log-based IOCs (from SonicWall advisory):**

1. **extraweb_access.log** -- Requests to `/__api__/login` or `/__api__/logout` returning HTTP 200 status. These URI endpoints do not exist in legitimate SMA 1000 configurations; their presence in access logs indicates exploitation.

2. **extraweb_access.log** -- Requests to `/wsproxy` with suspicious host parameters returning HTTP 101 (WebSocket upgrade) status. This indicates the SSRF vulnerability is being used to proxy attacker connections through the appliance via WebSocket.

3. **ctrl-service.log** -- Hotfix rollback entries containing path traversal patterns in filenames. This indicates the attacker is manipulating the hotfix mechanism, potentially to deploy malicious payloads or maintain persistence.

4. **/var/lib/unit/conf.json** -- Contains routes for `/__api__/login` or `/__api__/logout`. These URIs do not exist in legitimate NGINX Unit configurations on the SMA 1000; their presence indicates the configuration was tampered with as part of exploitation.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of SSRF (CVE-2026-15409) in the SMA 1000 Work Place interface to gain unauthenticated access |
| T1059 | Command and Scripting Interpreter | Code injection (CVE-2026-15410) enabling arbitrary OS command execution on the appliance |
| T1505.003 | Server Software Component: Web Shell | Injection of unauthorized API routes (`/__api__/login`, `/__api__/logout`) into the NGINX Unit configuration, functioning as persistent backdoor endpoints |
| T1090.001 | Proxy: Internal Proxy | SSRF exploitation to proxy attacker WebSocket connections (`/wsproxy`) through the appliance to internal resources |

## Impact Assessment

**Breadth:** All organizations running vulnerable SMA 1000 series appliances (models 6210, 7210, 8200v) on affected firmware versions are at risk. SMA 1000 is deployed across enterprise and government networks globally.

**Depth:** Full compromise -- the SSRF+code injection chain provides unauthenticated remote code execution with administrator privileges on the appliance. This enables credential theft, internal network access, lateral movement, and data exfiltration.

**Stealth:** The exploitation leverages legitimate appliance interfaces and injects routes into the existing configuration framework, making detection challenging without specific IOC checks. The path traversal in hotfix rollbacks suggests anti-forensic capability.

## Detection & Remediation

### Immediate Detection

Administrators should check for the following indicators on their SMA 1000 appliances:

```bash
# Check for unauthorized API routes in NGINX Unit configuration
grep -E '/__api__/(login|logout)' /var/lib/unit/conf.json

# Check access logs for exploitation indicators
grep -E '/__api__/(login|logout).*200' /path/to/extraweb_access.log
grep -E '/wsproxy.*101' /path/to/extraweb_access.log

# Check control service logs for path traversal in hotfix rollbacks
grep -E 'hotfix.*\.\.' /path/to/ctrl-service.log
```

### Remediation

1. **Patch immediately** -- Apply hotfix 12.4.3-03453 (for 12.4.x branch) or 12.5.0-02835 (for 12.5.x branch) and later.
2. **If IOCs are present:**
   - **Hardware appliances (6210, 7210):** Re-image the appliance.
   - **Virtual appliances (8200v):** Re-deploy from a clean image.
   - **Reset all user and administrator passwords.**
   - **Reset all TOTP tokens.**
3. **Conduct forensic analysis** of appliance logs before remediation to preserve evidence.
4. **Verify standby and disaster-recovery nodes** are also patched, as they are equally vulnerable.

### Long-Term Hardening

- Restrict access to the Appliance Management Console (AMC) to trusted management networks only; do not expose AMC to the internet.
- Implement network monitoring for unusual outbound connections from SMA appliances (SSRF-related traffic).
- Monitor NGINX Unit configuration files for unauthorized modifications.
- Subscribe to SonicWall PSIRT advisories for future vulnerability disclosures.

## Detection Rules

These detections target the specific exploitation artifacts documented in SonicWall's advisory for CVE-2026-15409 and CVE-2026-15410: unauthorized API endpoint access, suspicious WebSocket proxy requests, and configuration file tampering. Rules are at PoC/advisory-specific altitude; Sigma converts cleanly to Splunk and CrowdStrike LogScale. Note: `sigma check` could not fully validate ATT&CK tags in this environment (proxy blocks MITRE STIX data fetch); `sigma convert` exit 0 for both targets confirms portability.

### Sigma: SonicWall SMA1000 Unauthorized API Endpoint Access

Detects HTTP requests to `/__api__/login` or `/__api__/logout` with HTTP 200 on SMA1000 appliances -- these URIs do not exist in legitimate configurations.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (excluding attacktag — proxy blocks MITRE STIX download, not a rule issue); splunk convert exit 0; log_scale convert exit 0. Fields cs-uri-stem / sc-status are W3C extended log format; SMA1000 extraweb_access.log may require field mapping in the ingestion pipeline. Values are real (not defanged). -->
```yaml
title: SonicWall SMA1000 Exploitation - Unauthorized API Endpoint Access (CVE-2026-15409)
id: 7c3e1a94-bf52-4d68-9a0e-2f8b6c4d1e73
status: experimental
description: >
    Detects HTTP requests to /__api__/login or /__api__/logout endpoints on SonicWall SMA1000 appliances
    returning HTTP 200. These URI paths do not exist in legitimate SMA1000 configurations and indicate
    exploitation of CVE-2026-15409 (SSRF) as documented by SonicWall PSIRT (SNWLID-2026-0008).
references:
    - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008
    - https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains:
            - '/__api__/login'
            - '/__api__/logout'
    selection_status:
        sc-status: 200
    condition: selection_uri and selection_status
falsepositives:
    - None expected - these URI paths do not exist in legitimate SMA1000 configurations
level: critical
```

### Sigma: SonicWall SMA1000 Suspicious WebSocket Proxy Request

Detects `/wsproxy` requests with HTTP 101 (WebSocket upgrade) on SMA1000 appliances, indicating potential SSRF-driven proxying. **Caveat:** `/wsproxy` is core SMA1000 remote-access functionality; this rule will fire on legitimate WebSocket sessions. The advisory does not document distinguishing host parameter values. Requires environment-specific baseline tuning before production use.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check exit 0 (excluding attacktag); splunk convert exit 0; log_scale convert exit 0. Confidence low — /wsproxy is core SMA1000 functionality and the advisory provides no distinguishing host parameter values to narrow the detection. Requires environment-specific baseline tuning. -->
```yaml
title: SonicWall SMA1000 Exploitation - Suspicious WebSocket Proxy Request (CVE-2026-15409)
id: 9d4f2b85-ce63-4e79-8b1f-3a9c7d5e2f84
status: experimental
description: >
    Detects HTTP requests to /wsproxy endpoint on SonicWall SMA1000 appliances with HTTP 101
    (WebSocket upgrade) status, which may indicate SSRF exploitation activity linked to
    CVE-2026-15409/CVE-2026-15410 as documented by SonicWall PSIRT (SNWLID-2026-0008).
references:
    - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008
    - https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/
author: Actioner
date: 2026/07/15
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|contains: '/wsproxy'
    selection_status:
        sc-status: 101
    condition: selection_uri and selection_status
falsepositives:
    - Legitimate WebSocket proxy connections — /wsproxy is core SMA1000 remote-access functionality and will generate hits during normal operation
level: low
```

### Snort: SonicWall SMA1000 Unauthorized API Login Endpoint

Detects inbound HTTP requests to `/__api__/login` targeting SMA1000 appliances -- an endpoint that does not exist in legitimate configurations.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check: http service, http_uri sticky buffer, content with fast_pattern, flow established/to_server, all options semicolon-terminated, sid in 2100000+ range, valid classtype. -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 Unauthorized API Login Endpoint";
    flow:established, to_server;
    http_uri;
    content:"/__api__/login", fast_pattern;
    classtype:web-application-attack;
    reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008;
    reference:cve,2026-15409;
    metadata:author Actioner, created 2026-07-15;
    sid:2100001;
    rev:1;
)
```

### Snort: SonicWall SMA1000 Unauthorized API Logout Endpoint

Detects inbound HTTP requests to `/__api__/logout` targeting SMA1000 appliances.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check: same structure as login rule, different content and sid. -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 Unauthorized API Logout Endpoint";
    flow:established, to_server;
    http_uri;
    content:"/__api__/logout", fast_pattern;
    classtype:web-application-attack;
    reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008;
    reference:cve,2026-15409;
    metadata:author Actioner, created 2026-07-15;
    sid:2100002;
    rev:1;
)
```

### Suricata: SonicWall SMA1000 Unauthorized API Login Endpoint

Detects inbound HTTP requests to `/__api__/login` targeting SMA1000 appliances using Suricata dot-notation sticky buffers.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check: http protocol, http.uri dot-notation buffer, content with fast_pattern, flow established/to_server, sid in 2200000+ range, metadata with author and created_at, valid classtype. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 Unauthorized API Login Endpoint";
    flow:established,to_server;
    http.uri;
    content:"/__api__/login"; fast_pattern;
    classtype:web-application-attack;
    reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008;
    reference:cve,2026-15409;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200001;
    rev:1;
)
```

### Suricata: SonicWall SMA1000 Unauthorized API Logout Endpoint

Detects inbound HTTP requests to `/__api__/logout` targeting SMA1000 appliances.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check: same structure as login rule, different content and sid. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Actioner - SonicWall SMA1000 CVE-2026-15409 Unauthorized API Logout Endpoint";
    flow:established,to_server;
    http.uri;
    content:"/__api__/logout"; fast_pattern;
    classtype:web-application-attack;
    reference:url,psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008;
    reference:cve,2026-15409;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200002;
    rev:1;
)
```

### ~~Suricata: SonicWall SMA1000 Suspicious WebSocket Proxy Request~~ (DROPPED)

Dropped: fires on ANY `/wsproxy` request with no status filter or narrowing condition. `/wsproxy` is the core remote-access endpoint and would generate thousands of false positives per day.

### YARA: SonicWall SMA1000 Configuration Tampering

Detects SMA1000 NGINX Unit `conf.json` files containing unauthorized `/__api__/login` or `/__api__/logout` routes injected during exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Constructed positive (conf.json with /__api__/login route + "routes"/"listeners" markers) fired as expected; quiet on negative (conf.json with /workplace/login only). Positive was constructed from the advisory's published IOC pattern, not a real-world sample. The combination of /__api__/(login|logout) + JSON config markers ("routes"/"listeners") is highly specific to this exploitation pattern. -->
```yara
rule Exploit_CVE_2026_15409_SMA1000_Config_Tampering
{
    meta:
        description = "Detects SonicWall SMA1000 Unit conf.json containing unauthorized API routes (/__api__/login or /__api__/logout) indicating exploitation of CVE-2026-15409"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008"
        severity = "critical"

    strings:
        $api_login = "/__api__/login" ascii
        $api_logout = "/__api__/logout" ascii
        $json_routes = "\"routes\"" ascii
        $json_listeners = "\"listeners\"" ascii

    condition:
        filesize < 5MB and
        ($api_login or $api_logout) and
        ($json_routes or $json_listeners)
}
```

## Lessons Learned

This incident reinforces several critical themes in perimeter security:

1. **Perimeter appliances remain prime targets.** SMA 1000 gateways sit at the trust boundary and broker authentication -- their compromise provides direct, privileged access to internal networks. Defenders must treat VPN/remote access appliances as tier-0 assets with aggressive patching cadences.

2. **Vulnerability chaining amplifies severity.** Individually, the SSRF is critical but the code injection requires admin auth. Chained, they form a full unauthenticated-to-RCE kill chain. Vulnerability prioritization models that assess CVEs in isolation may underestimate chained-exploitation risk.

3. **Appliance forensics require vendor-specific IOCs.** The SonicWall advisory provides actionable, platform-specific indicators (specific log files, configuration paths, URI patterns) that generic SIEM rules would miss. Organizations should integrate vendor PSIRT advisory IOCs into their detection pipelines immediately upon disclosure.

4. **Patch latency windows are shrinking.** CISA's 3-day compliance deadline (July 14 disclosure to July 17 deadline) reflects the reality that actively exploited zero-days require emergency response, not standard patch cycles.

## Sources

- [SonicWall PSIRT Advisory SNWLID-2026-0008](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008) -- official vendor advisory for CVE-2026-15409 and CVE-2026-15410
- [BleepingComputer: SonicWall warns of SMA1000 flaws exploited in zero-day attacks](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/) -- detailed reporting with IOC descriptions and remediation guidance
- [The Hacker News: Two SonicWall SMA 1000 Zero-Days Exploited](https://thehackernews.com/2026/07/two-sonicwall-sma-1000-zero-days.html) -- discovery attribution (Adam Babis, Volexity), affected versions, patching details
- [SecurityWeek: SonicWall Issues Urgent SMA Patch Warning](https://www.securityweek.com/sonicwall-issues-urgent-sma-patch-warning-for-two-zero-day-exploits/) -- chain exploitation context, standby/DR node coverage
- [Security Affairs: SonicWall warns of active exploitation of two SMA 1000 zero-days](https://securityaffairs.com/195364/hacking/sonicwall-warns-of-active-exploitation-of-two-sma-1000-zero-days.html) -- CISA KEV addition, BOD 26-04 deadline details
- [Help Net Security: SonicWall SMA appliances targeted in zero-day attacks](https://www.helpnetsecurity.com/2026/07/14/sonicwall-sma-attacks-via-cve-2026-15409-cve-2026-15410/) -- exploitation pattern and remediation context
- [CIRCL Vulnerability Lookup: CVE-2026-15409](https://vulnerability.circl.lu/vuln/CVE-2026-15409) -- CWE-918 classification, CVSS vector, SSVC assessment
- [CIRCL Vulnerability Lookup: CVE-2026-15410](https://vulnerability.circl.lu/vuln/CVE-2026-15410) -- CWE-94 classification, CVSS vector
- [CISA: Adds Four Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/07/14/cisa-adds-four-known-exploited-vulnerabilities-catalog) -- KEV catalog addition, BOD 26-04 compliance deadline

---
*Report generated by Actioner*

<!-- revision: 2026-07-15 REVISE pass — (1) ATT&CK T1557 replaced with T1090.001 (Internal Proxy); (2) Sigma WebSocket rule confidence downgraded to low, level lowered to low, added caveat re: missing advisory-documented narrowing condition; (3) Suricata WebSocket Proxy rule DROPPED (fires on core remote-access endpoint with no narrowing); (4) YARA sample label corrected — removed dishonest "sample: fired" label (positive was constructed, not a real sample); (5) standalone rule files written to rules/. -->
