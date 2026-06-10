# Technical Analysis Report: Ivanti Sentry Pre-Auth RCE (CVE-2026-10520) (2026-06-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-10
Version: 1.0 (DRAFT)

## Executive Summary

A maximum-severity (CVSS 10.0) pre-authenticated OS command injection vulnerability (CVE-2026-10520, CWE-78) has been disclosed in Ivanti Sentry, the secure mobile gateway formerly known as MobileIron Sentry. The flaw exists in the `/mics/api/v2/sentry/mics-config/handleMessage` API endpoint, where user-supplied input in the `message` POST parameter is passed unsanitized to internal shell execution via `CommonUtilities.executeNativeCommand()`. A remote unauthenticated attacker can exploit this to execute arbitrary OS commands as root. A companion authentication bypass vulnerability (CVE-2026-10523, CVSS 9.9, CWE-288) allows unauthenticated creation of arbitrary administrative accounts. watchTowr Labs has published a full technical analysis and a public PoC exploit on GitHub. Ivanti states no customer exploitation has been observed at disclosure time. Affected versions must upgrade to R10.5.2, R10.6.2, or R10.7.1 immediately.

## Background: Ivanti Sentry

Ivanti Sentry (formerly MobileIron Sentry) is an in-line gateway appliance that manages, encrypts, and secures traffic between mobile devices and back-end enterprise systems. It typically sits between corporate mobile fleets and resources such as Microsoft Exchange, controlling ActiveSync email traffic and application data. The MICS (MobileIron Configuration Service) API at `/mics/` provides administrative configuration capabilities. Ivanti Sentry is widely deployed in enterprise environments managing corporate mobile device fleets, making this vulnerability high-impact for organizations relying on mobile access to corporate resources.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-09 | Ivanti publishes Security Advisory for CVE-2026-10520 and CVE-2026-10523 with fixes in R10.5.2, R10.6.2, R10.7.1 |
| 2026-06-09 | watchTowr Labs publishes technical analysis blog post and Detection Artefact Generator on GitHub |
| 2026-06-10 | BleepingComputer and Security Online report on the vulnerability with public PoC availability |
| 2026-06-10 | NVD entry created (CVE-2026-10520), status: Awaiting Enrichment |

## Root Cause: Unsanitized Input to OS Command Execution

The vulnerability exists in the MICS API endpoint `handleMessage` within the `ConfigServiceController.java` class in `mics-core-10.5.1-R10.5.1.jar` (path: `mics-core/com/mi/middleware/rest/controller/`). The controller method accepts a `message` parameter via HTTP POST and passes it directly to `configService.handleMessage(message)` without sanitization. The processing chain is:

1. `ConfigServiceController.handleMessage()` receives the raw `message` parameter
2. `ConfigServiceHandler.handleMessage()` parses the message using `StringTokenizer`
3. Routes to `ConfigRequestProcessor.handleExecute()`
4. Executes via `CommonUtilities.executeNativeCommand()` which passes the command to the OS shell

The `message` parameter accepts a structured format: `execute system /configuration/system/commandexec <commandexec><index>1</index><reqandres>[COMMAND]</reqandres></commandexec>`, where `[COMMAND]` is executed directly as an OS command with root privileges.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (HTTP POST to handleMessage)

The exploit targets the unauthenticated MICS API endpoint:

```
POST /mics/api/v2/sentry/mics-config/handleMessage HTTP/1.1
Content-Type: application/x-www-form-urlencoded

message=execute system /configuration/system/commandexec <commandexec><index>1</index><reqandres>[COMMAND]</reqandres></commandexec>
```

No authentication headers, cookies, or tokens are required. The endpoint is accessible to any network-reachable attacker.

### 2. Command Execution as Root

The injected command within the `<reqandres>` XML element is executed by `CommonUtilities.executeNativeCommand()` with root-level context on the Sentry appliance. The response returns command output in JSON format:

```json
{"status":200,"message":"Message handled successfully","data":"<result><success>[COMMAND_OUTPUT]</success></result>"}
```

### 3. Authentication Bypass (CVE-2026-10523)

A companion authentication bypass vulnerability (CWE-288) allows remote unauthenticated attackers to create arbitrary administrative accounts and obtain full administrative access to the Sentry management interface. This can be chained with CVE-2026-10520 for complete appliance compromise.

### 4. Platform-Specific Behavior

#### Ivanti Sentry Appliance (Linux)
- The Sentry appliance runs on a Linux-based OS
- Commands execute as root, providing full system access
- The MICS API runs within a Java application server (JAR: `mics-core-10.5.1-R10.5.1.jar`)
- The vulnerable endpoint is exposed on the same network interface as the Sentry management console

### 5. Patch Mechanism

Ivanti's fix hardcodes the `message` parameter instead of accepting user input, replacing the vulnerable parsing with a benign default command that only checks system hardware information.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Ivanti Sentry (mics-core) | < R10.5.2, < R10.6.2, < R10.7.1 | Vulnerable MICS API handleMessage endpoint allows unauthenticated OS command injection |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Ivanti Sentry | mics-core/com/mi/middleware/rest/controller/ConfigServiceController.java | N/A | Vulnerable controller class accepting unsanitized message parameter |
| Ivanti Sentry | mics-core-10.5.1-R10.5.1.jar | N/A | Vulnerable JAR containing the command injection flaw |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/mics/api/v2/sentry/mics-config/handleMessage` | Vulnerable API endpoint (POST) |
| HTTP Header | `Content-Type: application/x-www-form-urlencoded` | Exploit request content type |

### Behavioral

- HTTP POST requests to `/mics/api/v2/sentry/mics-config/handleMessage` from external/unauthorized sources
- POST body containing the string `commandexec` combined with `reqandres` XML elements
- POST body containing `execute system /configuration/system/commandexec` command prefix
- HTTP 200 responses containing `Message handled successfully` combined with `<result><success>` output wrapper indicating successful command execution
- Unexpected process execution spawned from the Java application server process on the Sentry appliance

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of unauthenticated MICS API endpoint for RCE |
| T1059 | Command and Scripting Interpreter | OS commands injected via the handleMessage endpoint executed by the system shell |
| T1068 | Exploitation for Privilege Escalation | Commands execute as root on the Sentry appliance |

## Impact Assessment

- **Breadth:** All Ivanti Sentry deployments prior to R10.5.2, R10.6.2, and R10.7.1 are vulnerable. Ivanti Sentry is widely deployed in enterprise environments managing corporate mobile device access.
- **Depth:** Complete appliance compromise — unauthenticated remote code execution as root. An attacker gains full control of the gateway appliance, including access to managed traffic between mobile devices and corporate resources.
- **Stealth:** The exploit uses a single HTTP POST request to a legitimate API endpoint, making it difficult to distinguish from normal management traffic without content inspection. No authentication is required, so there are no failed login indicators.
- **Exploitation Status:** Public PoC available (watchTowr Labs). No confirmed in-the-wild exploitation at disclosure time, but exploitation is trivial given the public PoC.

## Detection & Remediation

### Immediate Detection

1. **Search web server / reverse proxy logs** for POST requests to the handleMessage endpoint:
   ```
   grep -i "handleMessage" /var/log/nginx/access.log /var/log/httpd/access_log
   ```

2. **Search for exploit payload indicators in POST body logs** (if body logging is enabled):
   ```
   grep -i "commandexec" /var/log/nginx/access.log
   grep -i "reqandres" /var/log/nginx/access.log
   ```

3. **Check Sentry appliance for signs of compromise:**
   - Review process listing for unexpected processes
   - Check for unauthorized user accounts or SSH keys
   - Review `/var/log/` for evidence of command execution
   - Check for new cron jobs or persistence mechanisms

4. **Use the watchTowr Detection Artefact Generator** from GitHub to test whether your instance is vulnerable (non-destructively).

### Remediation

1. **Immediate:** Upgrade Ivanti Sentry to R10.5.2, R10.6.2, or R10.7.1
2. **Network Controls:** Restrict access to the `/mics/` API endpoint to authorized management networks only via firewall rules or network segmentation
3. **If compromise is suspected:** Isolate the Sentry appliance, capture forensic images, rotate all credentials that transit through the gateway, and rebuild from a clean image at the patched version
4. **Audit administrative accounts** for unauthorized accounts created via CVE-2026-10523

### Long-Term Hardening

- Restrict management interface access to dedicated management VLANs
- Deploy a WAF or reverse proxy with request inspection in front of the Sentry management API
- Implement network monitoring for POST requests to `/mics/` endpoints from unauthorized sources
- Subscribe to Ivanti security advisories for timely patching

## Detection Rules

These detections target the specific exploit path for CVE-2026-10520 — HTTP POST requests to the Ivanti Sentry MICS `handleMessage` endpoint, optionally with the `commandexec`/`reqandres` payload in the body. Compiles does not equal fires — verify in your pipeline with representative log data.

### Sigma: Ivanti Sentry Pre-Auth RCE via handleMessage Endpoint (CVE-2026-10520)
Detects HTTP POST requests to the vulnerable `/mics/api/v2/sentry/mics-config/handleMessage` endpoint characteristic of CVE-2026-10520 exploitation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk exit 0; log_scale exit 0. Keys on the specific vulnerable endpoint path — distinctive to Ivanti Sentry MICS API, minimal benign overlap outside authorized management consoles. No pipeline conversion attempted (webserver category has no standard pipeline). -->
```yaml
title: Ivanti Sentry Pre-Auth RCE via handleMessage Endpoint (CVE-2026-10520)
id: 7c3e8a1f-4d2b-4e9a-b6f1-2a8c5d0e3f7b
status: experimental
description: >
    Detects HTTP POST requests to the Ivanti Sentry MICS API handleMessage
    endpoint used for pre-authenticated OS command injection (CVE-2026-10520).
    The exploit sends a crafted message parameter containing XML commandexec
    elements to /mics/api/v2/sentry/mics-config/handleMessage.
references:
    - https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/
    - https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-10520
author: Actioner
date: 2026-06-10
tags:
    - attack.t1190
    - attack.t1059
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri:
        cs-uri-stem|contains: '/mics/api/v2/sentry/mics-config/handleMessage'
    condition: selection_method and selection_uri
falsepositives:
    - Legitimate Ivanti Sentry MICS configuration management traffic from authorized management consoles
level: high
```

### Snort: Ivanti Sentry Pre-Auth RCE handleMessage Endpoint (CVE-2026-10520)
Detects POST requests to the handleMessage endpoint with commandexec payload in the body.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed — semicolons terminate all options, http service with http_* sticky buffers, balanced parentheses, msg/sid/rev present. -->
```snort
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Ivanti Sentry Pre-Auth RCE handleMessage Endpoint (CVE-2026-10520)"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/mics/api/v2/sentry/mics-config/handleMessage", fast_pattern; http_client_body; content:"commandexec"; content:"reqandres"; classtype:web-application-attack; reference:url,labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/; reference:cve,2026-10520; metadata:author Actioner, created 2026-06-10; sid:2100001; rev:1;)
```

### Suricata: Ivanti Sentry Pre-Auth RCE handleMessage Endpoint Access (CVE-2026-10520)
Detects HTTP POST requests to the vulnerable handleMessage API endpoint on Ivanti Sentry.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. SID 2200001. Keys on the specific endpoint path in http.uri — highly distinctive to Ivanti Sentry MICS. Low FP risk unless legitimate management traffic reaches the sensor. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Sentry Pre-Auth RCE handleMessage Endpoint Access (CVE-2026-10520)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/mics/api/v2/sentry/mics-config/handleMessage"; fast_pattern; classtype:web-application-attack; reference:url,labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/; reference:cve,2026-10520; metadata:author Actioner, created_at 2026-06-10; sid:2200001; rev:1;)
```

### Suricata: Ivanti Sentry RCE commandexec Payload in POST Body (CVE-2026-10520)
Detects the specific command injection payload (`commandexec` + `reqandres` XML elements) in POST body to the handleMessage endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. SID 2200002. Keys on both the endpoint path and the distinctive XML payload structure from the PoC. Very low FP — the commandexec/reqandres combination is unique to the exploit chain. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Ivanti Sentry RCE commandexec Payload in POST Body (CVE-2026-10520)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/mics/api/v2/sentry/mics-config/handleMessage"; http.request_body; content:"commandexec"; fast_pattern; content:"reqandres"; classtype:web-application-attack; reference:url,labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/; reference:cve,2026-10520; metadata:author Actioner, created_at 2026-06-10; sid:2200002; rev:1;)
```

### YARA: Exploit Payload / Tool Targeting Ivanti Sentry CVE-2026-10520
Detects exploit tools or captured traffic containing the specific handleMessage endpoint path and commandexec payload structure from the published PoC.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt matched (Exploit_Ivanti_Sentry_CVE_2026_10520_Payload); neg.txt no match. Positive sample constructed from the published PoC HTTP request (endpoint + commandexec + reqandres). Strings are directly from the watchTowr PoC — $endpoint is the exact API path, $payload1 is the exact command prefix, $payload2/$payload3 are the XML element wrappers. -->
```yara
rule Exploit_Ivanti_Sentry_CVE_2026_10520_Payload
{
    meta:
        description = "Detects exploit payloads or tools targeting Ivanti Sentry CVE-2026-10520 pre-auth OS command injection via the handleMessage endpoint"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/"
        severity = "critical"

    strings:
        $endpoint = "/mics/api/v2/sentry/mics-config/handleMessage" ascii wide
        $payload1 = "execute system /configuration/system/commandexec" ascii wide
        $payload2 = "<commandexec><index>" ascii wide
        $payload3 = "<reqandres>" ascii wide
        $response = "Message handled successfully" ascii wide

    condition:
        filesize < 1MB and
        $endpoint and
        (2 of ($payload*) or ($payload1 and $response))
}
```

## Lessons Learned

This vulnerability highlights a recurring pattern in Ivanti products: unauthenticated API endpoints that pass user input directly to system-level command execution. The fact that the MICS configuration API accepted arbitrary commands without any authentication or input validation represents a fundamental secure-coding failure. Organizations deploying appliance-based security gateways should ensure management interfaces are never exposed to untrusted networks, regardless of vendor assurances. The rapid availability of a public PoC (same day as advisory) compresses the patching window significantly — defenders must treat this as an emergency patch cycle.

## Sources

- [watchTowr Labs Technical Analysis](https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/) — primary technical analysis with full exploit chain details, vulnerable code path, and PoC
- [watchTowr Labs PoC / Detection Artefact Generator (GitHub)](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523) — public PoC exploit and detection tool
- [BleepingComputer Report](https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/) — news coverage confirming max severity and public PoC availability
- [Security Online Report](https://securityonline.info/ivanti-sentry-rce-poc-disclosed/) — additional reporting with PoC disclosure details
- [NVD - CVE-2026-10520](https://nvd.nist.gov/vuln/detail/CVE-2026-10520) — NIST vulnerability entry (CVSS 10.0, CWE-78, awaiting enrichment)
- [Ivanti Security Advisory](https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-10520-CVE-2026-10523?language=en_US) — vendor advisory with affected/fixed versions

---
*Report generated by Actioner*
