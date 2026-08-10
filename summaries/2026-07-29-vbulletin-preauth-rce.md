<!-- revision: dropped Sigma Rule 2 (cs-uri cannot inspect POST body), dropped YARA Rule 3 (generic webshell, altitude violation), fixed ATT&CK T1059.001->T1059.004 and T1027.013->T1027.010, renumbered Snort SIDs 2100020-2100022 and Suricata SIDs 2200020-2200023 to avoid batch conflicts, fixed invalid confidence labels CRITICAL->high and MEDIUM-HIGH->high -->
# CVE-2026-61511: vBulletin Pre-Authentication Remote Code Execution via Template Runtime eval() Injection

## Executive Summary

A critical pre-authentication remote code execution (RCE) vulnerability in vBulletin forum software (CVE-2026-61511, CVSS 3.1: 9.8) allows unauthenticated attackers to execute arbitrary PHP code on the underlying server through a crafted HTTP POST request. The flaw resides in the `vB5_Template_Runtime::runMaths()` method, which passes insufficiently sanitized user input to PHP's `eval()` function. The exploit leverages the "phpfuck" encoding technique -- constructing PHP function calls using only digits, dots, XOR operators (`^`), and parentheses -- to bypass the regex filter. A public proof-of-concept was released on July 27, 2026, significantly lowering the barrier to exploitation. Patches were issued by the vendor on July 1, 2026, providing a roughly four-week window for administrators to apply updates before the PoC dropped. All self-hosted vBulletin 5.x and 6.x instances through version 6.2.1 are affected.

**Status:** DRAFT  
**TLP:** CLEAR  
**Severity:** CRITICAL (CVSS 3.1: 9.8 / CVSS 4.0: 9.3)

---

## Background

vBulletin is one of the most widely deployed commercial forum platforms, powering thousands of community forums across the internet. It has a history of critical vulnerabilities, including a similar template-engine RCE chain in 2025 (CVE-2025-48827/CVE-2025-48828). The current vulnerability was discovered by independent security researcher Egidio Romano (handle: EgiX) and responsibly disclosed to vBulletin on June 25, 2026. The vendor released version 6.2.2 on July 1, 2026, along with Patch Level 1 backports for versions 6.2.1, 6.2.0, and 6.1.6. No patches were released for the legacy 5.x branch; those users are directed to upgrade. The vulnerability was publicly disclosed via SSD Secure Disclosure on July 27, 2026, alongside an interactive proof-of-concept exploit. As of the disclosure date, no confirmed in-the-wild exploitation had been reported, and CVE-2026-61511 was not listed in CISA's Known Exploited Vulnerabilities catalog.

### Timeline

| Date | Event |
|------|-------|
| 2026-06-25 | Vulnerability reported to vBulletin by Egidio Romano |
| 2026-07-01 | vBulletin 6.2.2 released with fix; Patch Level 1 backports issued |
| 2026-07-27 | Public disclosure via SSD Secure Disclosure with PoC exploit |
| 2026-07-28 | Widespread media coverage (BleepingComputer, The Hacker News, etc.) |

---

## Technical Analysis

### Vulnerability Details

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2026-61511 |
| **CVSS 3.1** | 9.8 Critical (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **CVSS 4.0** | 9.3 Critical (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`) |
| **CWE** | CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection) |
| **Affected Versions** | vBulletin 5.0.0 through 5.7.5; vBulletin 6.0.0 through 6.2.1 |
| **Patched Versions** | vBulletin 6.2.2; Patch Level 1 for 6.2.1, 6.2.0, 6.1.6 |
| **Authentication** | None required (pre-authentication) |
| **Attack Complexity** | Low |

### Vulnerable Code Path

The vulnerability exists in `/includes/vb5/template/runtime.php`, within the `vB5_Template_Runtime::runMaths()` method. This function processes mathematical expressions used by vBulletin's `{vb:math}` template tag. The method applies a regex filter before passing the result to PHP's `eval()`:

```
Vulnerable regex: #([^+\-*=/\(\)\d\^<>&|\.]*)#
```

This pattern removes all characters except: digits (0-9), parentheses `()`, arithmetic operators (`+`, `-`, `*`, `/`, `=`), binary/bitwise operators (`^`, `<`, `>`, `&`, `|`), and the dot (`.`). The filtered string is then passed to:

```
@eval("\$str = $str;");
```

### Exploitation Mechanism

The attack targets the `ajax/render/pagenav` template rendering endpoint. The `pagenav[pagenumber]` parameter flows into the `{vb:math}` template tag, which calls the vulnerable `runMaths()` method.

**Attack Request Structure:**
- **Method:** POST
- **URI Path:** `/ajax/render/pagenav` (or via `routestring=ajax/render/pagenav` as a query parameter or POST body parameter)
- **Content-Type:** `application/x-www-form-urlencoded`
- **Key Parameter:** `pagenav[pagenumber]` (or URL-encoded: `pagenav%5Bpagenumber%5D`)
- **Payload:** phpfuck-encoded PHP function calls

### The "phpfuck" Bypass Technique

The regex filter permits a character set that is sufficient to construct arbitrary PHP code using the "phpfuck" technique. This method uses only five characters -- `9`, `.`, `^`, `(`, `)` -- to encode any PHP string and function call:

1. **Generating INF:** Concatenating enough `9` digits causes PHP numeric overflow, producing the string `"INF"`. Appending a digit (e.g., `"INF9"`) creates letter-containing strings.
2. **XOR String Construction:** The `^` (XOR) operator on strings produces new characters. For example, `"RZA" ^ "123"` yields `"chr"`.
3. **Variable Functions:** PHP's variable function syntax allows strings to be called as functions: `"system"("id")` executes the `system()` function.
4. **Chaining:** By XORing intermediate strings derived from `INF` and digit combinations, the attacker reconstructs function names like `chr`, `system`, `exec`, etc.

The resulting payload is extremely long (potentially 100KB+) but composed entirely of characters permitted by the regex filter.

---

## Indicators of Compromise (IOCs)

### Network-Level Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `POST /ajax/render/pagenav` | HTTP Request | Exploit delivery endpoint (URL path routing) |
| `routestring=ajax/render/pagenav` | HTTP Parameter | Exploit delivery endpoint (query/body routing) |
| `pagenav[pagenumber]` or `pagenav%5Bpagenumber%5D` | POST Parameter | Malicious payload carrier |
| Abnormally long `pagenav[pagenumber]` values (>1KB) | Behavioral | phpfuck payloads are very large |
| High density of `^`, `(`, `)`, `.`, `9` in POST body | Behavioral | phpfuck encoding signature |
| `%5E` (URL-encoded `^`) repeated in POST body | Pattern | XOR operator in URL-encoded form |

### Host-Level Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| Unexpected PHP files in vBulletin directories | File | Post-exploitation webshell deployment |
| Web server process spawning shell commands | Process | Command execution via `system()`, `exec()`, `passthru()` |
| Outbound connections from web server process | Network | Reverse shell or data exfiltration |
| Modified files under `/includes/vb5/template/` | File | Potential backdoor insertion |

### Log Indicators

- Web server access logs: POST requests to URIs containing `ajax/render/pagenav` with unusually large request body sizes
- PHP error logs: eval()-related errors or warnings originating from `runtime.php`
- Application logs: Repeated requests to the pagenav template rendering route from a single source

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Description |
|--------|-----------|---------------|-------------|
| Initial Access | T1190 | -- | Exploit Public-Facing Application |
| Execution | T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell (via PHP system()/exec()) |
| Persistence | T1505 | T1505.003 | Server Software Component: Web Shell |
| Defense Evasion | T1027 | T1027.010 | Obfuscated Files or Information: Command Obfuscation (phpfuck encoding) |
| Discovery | T1082 | -- | System Information Discovery |
| Collection | T1005 | -- | Data from Local System |

---

## Detection & Remediation

### Remediation Steps

1. **Immediate:** Upgrade to vBulletin 6.2.2 or apply Patch Level 1 for versions 6.2.1, 6.2.0, or 6.1.6
2. **Legacy 5.x:** Migrate to a supported 6.x version; no patches are available for the 5.x branch
3. **WAF Rule:** Deploy a web application firewall rule blocking POST requests to `ajax/render/pagenav` with anomalous `pagenav[pagenumber]` values containing XOR operators or excessively long digit-and-operator sequences
4. **Log Review:** Audit web server logs for POST requests to `ajax/render/pagenav` from late June 2026 onward
5. **Forensic Check:** Inspect vBulletin installation directories for unexpected PHP files or modifications to template runtime files
6. **Network Segmentation:** Ensure web server processes cannot initiate outbound connections to arbitrary hosts

### Cloud Deployments

vBulletin cloud-hosted instances have been patched by the vendor and are not at risk.

---

## Detection Rules

### Sigma Rule 1: vBulletin CVE-2026-61511 Pre-Auth RCE Exploit - Web Server Log Detection

**File:** `vbulletin_cve_2026_61511_rce.yml`

- **Compile Status:** PASS (sigma check: 0 errors, 0 issues; sigma convert to Splunk and LogScale: success)
- **Confidence:** HIGH
- **Description:** Detects HTTP POST requests to the vBulletin `ajax/render/pagenav` endpoint in web server access logs.

```yaml
title: vBulletin CVE-2026-61511 Pre-Auth RCE Exploit - Web Server Log Detection
id: a3f1c8d2-7b4e-4a9f-b6c1-d8e2f5a0b3c4
status: experimental
description: Detects HTTP POST requests to the vBulletin ajax/render/pagenav endpoint which is targeted by the CVE-2026-61511 pre-authentication remote code execution exploit. The exploit abuses the runMaths() eval injection via the pagenav[pagenumber] parameter using phpfuck-style encoding.
references:
    - https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/
    - https://ssd-disclosure.com/vbulletin-runtime-template-runmaths-preauth-rce/
    - https://karmainsecurity.com/KIS-2026-13
    - https://nvd.nist.gov/vuln/detail/CVE-2026-61511
author: Actioner (DRAFT)
date: 2026/07/29
tags:
    - attack.t1190
    - attack.t1059.004
    - cve.2026-61511
logsource:
    category: webserver
    definition: Web server access logs with URI and HTTP method fields
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri_path:
        cs-uri|contains: 'ajax/render/pagenav'
    condition: selection_method and selection_uri_path
falsepositives:
    - Legitimate vBulletin page navigation AJAX requests may use this endpoint but typically use GET requests or have short parameter values
level: high
```

### Sigma Rule 2: DROPPED

> **Dropped:** PHPFuck payload rule removed -- the phpfuck payload resides in the POST body (`pagenav[pagenumber]` parameter), but `cs-uri` in webserver access logs contains only path+query, never POST body content. Rule would never fire on actual exploit traffic.

### Snort Rules: vBulletin CVE-2026-61511 Pre-Auth RCE

**File:** `vbulletin_cve_2026_61511.rules`

- **Compile Status:** PASS (Snort successfully validated the configuration)
- **Confidence:** HIGH

```
# SID 2100020 - Detect POST to ajax/render/pagenav endpoint
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"EXPLOIT vBulletin CVE-2026-61511 Pre-Auth RCE - ajax/render/pagenav POST"; flow:to_server,established; content:"POST"; http_method; content:"ajax/render/pagenav"; http_uri; classtype:web-application-attack; sid:2100020; rev:1; metadata:created_at 2026_07_29, cve CVE-2026-61511;)

# SID 2100021 - Detect routestring parameter targeting pagenav in POST body
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"EXPLOIT vBulletin CVE-2026-61511 Pre-Auth RCE - routestring pagenav in POST body"; flow:to_server,established; content:"POST"; http_method; content:"routestring=ajax/render/pagenav"; http_client_body; classtype:web-application-attack; sid:2100021; rev:1; metadata:created_at 2026_07_29, cve CVE-2026-61511;)

# SID 2100022 - Detect phpfuck XOR payload in pagenav parameter
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"EXPLOIT vBulletin CVE-2026-61511 Pre-Auth RCE - PHPFuck XOR payload in pagenumber"; flow:to_server,established; content:"POST"; http_method; content:"pagenav"; http_client_body; content:"%5E"; http_client_body; classtype:web-application-attack; sid:2100022; rev:1; metadata:created_at 2026_07_29, cve CVE-2026-61511;)
```

### Suricata Rules: vBulletin CVE-2026-61511 Pre-Auth RCE

**File:** `vbulletin_cve_2026_61511.suricata.rules`

- **Compile Status:** PASS (Suricata configuration successfully loaded)
- **Confidence:** HIGH

```
# SID 2200020 - Detect POST to ajax/render/pagenav endpoint
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - vBulletin CVE-2026-61511 Pre-Auth RCE via ajax/render/pagenav"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"ajax/render/pagenav"; classtype:web-application-attack; sid:2200020; rev:1; metadata:created_at 2026_07_29, cve CVE_2026_61511;)

# SID 2200021 - Detect routestring targeting pagenav in POST body
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - vBulletin CVE-2026-61511 Pre-Auth RCE routestring pagenav POST"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"routestring=ajax"; content:"render/pagenav"; distance:0; classtype:web-application-attack; sid:2200021; rev:1; metadata:created_at 2026_07_29, cve CVE_2026_61511;)

# SID 2200022 - Detect phpfuck XOR payload in pagenav parameter (URL-encoded)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - vBulletin CVE-2026-61511 PHPFuck XOR Payload in pagenumber"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"pagenav"; content:"%5E"; distance:0; within:2000; classtype:web-application-attack; sid:2200022; rev:1; metadata:created_at 2026_07_29, cve CVE_2026_61511;)

# SID 2200023 - Detect phpfuck XOR payload in pagenav parameter (raw caret)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - vBulletin CVE-2026-61511 PHPFuck XOR Payload raw caret"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"pagenav"; content:"^"; distance:0; within:2000; classtype:web-application-attack; sid:2200023; rev:1; metadata:created_at 2026_07_29, cve CVE_2026_61511;)
```

### YARA Rules: vBulletin CVE-2026-61511 Exploit Detection

**File:** `vbulletin_cve_2026_61511.yar`

- **Compile Status:** PASS (yarac compiled with no errors or warnings)
- **Confidence:** HIGH

```yara
rule CVE_2026_61511_vBulletin_Exploit_Request
{
    meta:
        description = "Detects CVE-2026-61511 exploit HTTP request patterns targeting vBulletin ajax/render/pagenav with phpfuck-encoded payload"
        author = "Actioner (DRAFT)"
        date = "2026-07-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61511"
        severity = "critical"

    strings:
        $uri1 = "ajax/render/pagenav" ascii nocase
        $uri2 = "routestring=ajax" ascii nocase
        $param1 = "pagenav%5Bpagenumber%5D" ascii nocase
        $param2 = "pagenav[pagenumber]" ascii nocase
        $xor_encoded1 = "%5E" ascii
        $xor_raw = ")^(" ascii
        $post_method = "POST " ascii

    condition:
        $post_method and
        ($uri1 or $uri2) and
        ($param1 or $param2) and
        ($xor_encoded1 or $xor_raw)
}

rule CVE_2026_61511_vBulletin_PHPFuck_Payload
{
    meta:
        description = "Detects phpfuck-style payload patterns used in CVE-2026-61511 exploit - long sequences of digits, XOR operators, and parentheses"
        author = "Actioner (DRAFT)"
        date = "2026-07-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61511"
        severity = "critical"

    strings:
        $phpfuck_pattern1 = /\(9{5,}\)\.?\^/ ascii
        $phpfuck_pattern2 = /\^\.?\(9{5,}\)/ ascii
        $phpfuck_pattern3 = /((\(9+\)\.\^){3,})/ ascii
        $vbulletin_context = "pagenav" ascii nocase

    condition:
        $vbulletin_context and
        (any of ($phpfuck_pattern*))
}
```

### YARA Rule 3: DROPPED

> **Dropped:** Generic PHP webshell rule with vBulletin paths bolted on -- not specific to CVE-2026-61511; altitude violation.

---

## Sources

- [BleepingComputer - vBulletin fixes critical pre-auth RCE flaw with public exploit](https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/)
- [SSD Secure Disclosure - vBulletin Runtime Template runMaths Preauth RCE](https://ssd-disclosure.com/vbulletin-runtime-template-runmaths-preauth-rce/)
- [Karma(In)Security - KIS-2026-13: vBulletin <= 6.2.1 (runMaths) Remote Code Execution Vulnerability](https://karmainsecurity.com/KIS-2026-13)
- [NVD - CVE-2026-61511](https://nvd.nist.gov/vuln/detail/CVE-2026-61511)
- [The Hacker News - Public Exploit Released for Patched vBulletin Pre-Auth Code Execution Flaw](https://thehackernews.com/2026/07/public-exploit-released-for-patched.html)
- [Latest Hacking News - Public Exploit Lands for vBulletin's Pre-Auth RCE, CVE-2026-61511](https://latesthackingnews.com/2026/07/28/vbulletin-rce-vulnerability-cve-2026-61511/)
- [PhpFuck - Crafting valid PHP 8 code using only five different characters](https://b-viguier.github.io/PhpFk/)
