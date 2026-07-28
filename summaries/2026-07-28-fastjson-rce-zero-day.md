# Technical Analysis Report: CVE-2026-16723 FastJson 1.x RCE Zero-Day (2026-07-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-28
Version: 1.0

## Executive Summary

A critical unauthenticated remote code execution (RCE) zero-day vulnerability (CVE-2026-16723, CVSS 9.0) is under active exploitation against US organizations. The flaw affects Alibaba's FastJson library versions 1.2.68 through 1.2.83 when deployed as Spring Boot executable fat-JARs with SafeMode disabled (the default configuration). No authentication, no user interaction, no AutoType enablement, and no classpath gadget chain are required for exploitation -- an attacker only needs to send a single crafted JSON request to a reachable endpoint that passes input to `JSON.parse` or `JSON.parseObject`.

FastJson 1.x is no longer actively maintained by Alibaba and no patch has been issued. With millions of estimated exposed instances in enterprise backends, banking systems, and e-commerce platforms, this represents a high-urgency supply-chain-adjacent threat. Active exploitation was confirmed by ThreatBook on July 22, 2026, and Imperva has documented campaigns targeting financial services, healthcare, computing, and retail sectors, primarily in the United States.

## Background: FastJson

FastJson is one of the most widely-used open-source JSON serialization/deserialization libraries in the Java ecosystem, developed and maintained by Alibaba. It is deeply embedded in enterprise Java applications, particularly those built on Spring Boot. The library has a history of deserialization vulnerabilities related to its AutoType feature, which allows polymorphic type handling via the `@type` JSON field. Previous vulnerabilities (e.g., CVE-2022-25845) were mitigated by disabling AutoType or updating blocklists. CVE-2026-16723 breaks this defensive model entirely because it bypasses AutoType restrictions through an alternative code path.

FastJson 1.x reached its final release at version 1.2.83 and is no longer receiving security updates. Alibaba directs users to FastJson2, which uses a fundamentally different type-resolution architecture.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-19 | Kirill Firsov (FearsOff Cybersecurity) publicly discloses the vulnerability |
| 2026-07-20 | ThreatBook catalogs the vulnerability (XVE-2026-39684, detection ID S3100181015) |
| 2026-07-21 | Alibaba publishes security advisory on the fastjson2 GitHub wiki |
| 2026-07-22 | ThreatBook confirms in-the-wild exploitation |
| 2026-07-23 | CVE-2026-16723 published on NVD (CVSS 9.0); CISA-ADP assessment records exploitation as "none" |
| 2026-07-24-25 | Imperva and BleepingComputer report widespread targeting of US firms |
| 2026-07-25 | The Hacker News confirms the flaw is absent from CISA's Known Exploited Vulnerabilities (KEV) catalog |
| 2026-07-28 | No patch available; FastJson 1.x remains unmaintained |

## Root Cause: Deserialization Type-Resolution Bypass in Spring Boot Fat-JARs

The vulnerability stems from FastJson's internal type-resolution logic, which performs attacker-controlled resource lookups (`getResourceAsStream`) **before** enforcing AutoType restrictions. In Spring Boot executable fat-JAR deployments, application classes and dependencies reside in nested JAR paths rather than a flat classpath. An attacker exploits this by:

1. Submitting a crafted JSON payload containing a malicious `@type` value referencing a nested JAR URL (`jar:http:` or `jar:file:`)
2. FastJson's type resolver performs a class-resource lookup using the attacker-supplied value
3. If the referenced resource contains a `@JSONType` annotation, FastJson treats it as a trusted type, bypassing AutoType checks
4. The attacker-controlled class is instantiated and executed with the privileges of the Java process

**Critical differentiators from previous FastJson vulnerabilities:**
- No AutoType enablement required (can remain disabled)
- No classpath gadget chain required (breaks the traditional blocklist defense)
- No third-party dependency required
- Specifying a target class via `JSON.parseObject(body, SomeDto.class)` does NOT mitigate -- attackers nest payloads inside `Object` or `Map` fields

**Confirmed vulnerable entry points:** `JSON.parse`, `JSON.parseObject(String)`, `JSON.parseObject(String, Class)`

**Verified environments:** Spring Boot 2.x, 3.x, 4.x with JDK 8, 11, 17, 21

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery

The exploit is delivered as a standard HTTP POST request containing a JSON body with a crafted `@type` field. The payload targets any network-reachable endpoint that passes user-controlled input to a FastJson parser. Two key payload signatures have been documented by ThreatBook:

- `@type":"jar:file:.` -- local nested JAR path exploitation
- `@type":"jar:http:..` -- remote JAR URL fetching for bytecode download

The `jar:` URL scheme allows the attacker to reference resources within JAR archives, and in the Spring Boot fat-JAR context, this enables reaching attacker-controlled content that the type resolver treats as trusted.

### 2. Post-Exploitation

Once arbitrary code execution is achieved, the attacker's code runs with the full privileges of the Java application process. Based on the attack patterns observed:

- Attackers may establish reverse shells, deploy web shells, or download second-stage payloads
- The Java process may spawn child shell processes (`/bin/sh`, `/bin/bash`, `curl`, `wget`)
- Unauthorized outbound connections to attacker-controlled infrastructure

### 3. Attack Tooling

Imperva's telemetry reveals the following attack tool distribution:
- ~70%: Browser impersonation (spoofed User-Agent headers)
- ~30%: Custom tools written in Ruby and Go

### 4. Deployment-Specific Exposure

**Vulnerable deployments:**
- Spring Boot executable fat-JARs (`java -jar xxx.jar`)
- SafeMode disabled (default)
- FastJson 1.2.68-1.2.83

**NOT vulnerable:**
- FastJson2 (all versions)
- FastJson <= 1.2.60
- Non-fat-JAR deployments (plain JARs, WAR files, Tomcat/Jetty WARs)
- SafeMode enabled deployments
- `com.alibaba:fastjson:1.2.83_noneautotype` build variant

## Indicators of Compromise (IOCs)

> **Note:** No network infrastructure IOCs (IP addresses, domains, URLs) have been publicly disclosed for this campaign as of the report date. The indicators listed below are payload patterns and behavioral signatures derived from vendor reporting, not traditional network-level IOCs.

### Network / Behavioral Indicators

| Type | Value | Context |
|------|-------|---------|
| HTTP Pattern | POST requests with `@type` in JSON body | Exploit delivery vector |
| HTTP Pattern | `jar:http` or `jar:file` in JSON request body | Nested JAR URL exploitation |
| HTTP Pattern | `@type":"jar:file:.` | ThreatBook signature string |
| HTTP Pattern | `@type":"jar:http:..` | ThreatBook signature string |
| Behavioral | Java process spawning `/bin/sh`, `/bin/bash`, `curl`, `wget` | Post-exploitation indicator |
| Behavioral | Unexpected outbound connections from Java application servers | C2 / payload download |
| Tool Signature | Ruby and Go-based HTTP clients (~30% of attacks) | Attack tooling |
| Tool Signature | Browser impersonation User-Agent strings (~70% of attacks) | Attack tooling |

**Note:** No specific attacker IP addresses, domains, file hashes, or C2 infrastructure have been publicly disclosed as of this report date. The IOCs above are behavioral patterns derived from Imperva and ThreatBook reporting.

### Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|-------------------|-------------|
| com.alibaba:fastjson | 1.2.68 - 1.2.83 | Deserialization RCE via type-resolution bypass in Spring Boot fat-JARs |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated RCE via crafted JSON POST to FastJson endpoints |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation shell spawning from Java process on Linux servers |

## Impact Assessment

**Breadth:** FastJson 1.x remains widely deployed across enterprise Java applications globally. Chinese security vendor Qi'anxin estimates millions of exposed instances. The vulnerability affects applications across financial services, healthcare, computing, retail, and other sectors.

**Depth:** Successful exploitation grants the attacker full code execution with the privileges of the Java application process, typically running as a service account with significant system access. This can lead to complete system compromise, lateral movement, data exfiltration, and ransomware deployment.

**Stealth:** The exploit requires only a single HTTP POST request with no unusual headers or parameters beyond the JSON body content. Browser impersonation makes the attack traffic blend with normal web traffic.

**Patch Gap:** No official patch exists. FastJson 1.x is end-of-life. Organizations must either enable SafeMode (which may break application functionality) or migrate to FastJson2 (which requires code changes and testing).

## Detection & Remediation

### Immediate Detection

**Check if your applications use vulnerable FastJson versions:**
```bash
# Maven projects
grep -r "fastjson" pom.xml | grep -v fastjson2
mvn dependency:tree | grep fastjson

# Gradle projects
grep -r "fastjson" build.gradle | grep -v fastjson2
gradle dependencies | grep fastjson

# Running applications - check loaded JARs
find / -name "fastjson-1.2.*.jar" 2>/dev/null

# Check SafeMode status in JVM flags
ps aux | grep java | grep -i safemode
```

**Check web server/WAF logs for exploit attempts:**
```bash
# Search for @type with jar: URL patterns in access logs
grep -i "@type" /var/log/nginx/access.log | grep -i "jar:"
grep -i "@type" /var/log/apache2/access.log | grep -i "jar:"

# Search application logs for deserialization errors
grep -i "fastjson\|autoType\|JSONType\|getResourceAsStream" /var/log/app/*.log
```

### Remediation

1. **Immediate (Priority 0):** Enable SafeMode on all FastJson 1.x deployments:
   - JVM flag: `-Dfastjson.parser.safeMode=true`
   - Programmatic: `ParserConfig.getGlobalInstance().setSafeMode(true)`
   - Properties file: `fastjson.parser.safeMode=true`

2. **Immediate (Priority 0 alternative):** Switch to the noneautotype build:
   - `com.alibaba:fastjson:1.2.83_noneautotype`

3. **Short-term:** Deploy WAF rules to inspect and block JSON requests containing `@type` combined with `jar:http` or `jar:file` patterns

4. **Long-term (Priority 1):** Migrate to FastJson2, which uses an entirely different type-resolution architecture that eliminates the `getResourceAsStream` call on user-controlled class names

5. **Incident Response:** For systems confirmed vulnerable and exposed to the internet, audit for signs of compromise: unexpected processes, web shells, unauthorized file modifications, unusual outbound connections

### Long-Term Hardening

- Adopt FastJson2 or alternative JSON libraries (Jackson, Gson) that do not perform polymorphic deserialization by default
- Implement application-layer input validation to reject JSON containing `@type` fields where polymorphic deserialization is not required
- Deploy WAF/RASP solutions with JSON body inspection capabilities
- Monitor Java application processes for anomalous child process creation (shells, downloaders)
- Maintain an inventory of third-party library dependencies and their support status

## Detection Rules

The following rules target the CVE-2026-16723 exploit delivery mechanism (malicious `@type` + `jar:` URL patterns in HTTP POST bodies). All rules are high-confidence for this specific exploit chain and require validation in the target environment before production deployment.

### Sigma: CVE-2026-16723 FastJson Exploit Pattern in Web Server Logs

Detects HTTP POST requests containing FastJson exploit signatures in web/proxy logs. Requires request body logging to be effective.

Compile: PASS (splunk, log_scale) | Confidence: medium (depends on body logging availability) | Portability note: the `cs-body` field requires custom field mapping in Splunk and CrowdStrike; it is not present in default log schemas

```yaml
title: CVE-2026-16723 FastJson RCE Exploit Pattern in Web Server Logs
id: 8f3a1b5c-6d7e-4a92-b0c4-9e2f8d1a7b3c
status: experimental
description: >
    Detects HTTP POST requests containing FastJson exploit patterns with @type
    and jar: URL references in web server or proxy logs. This targets the
    CVE-2026-16723 deserialization RCE in FastJson 1.2.68-1.2.83 Spring Boot
    fat-JAR deployments. Requires request body logging to be effective.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-16723
    - https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/
author: Actioner
date: 2026-07-28
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_body:
        cs-body|contains|all:
            - '@type'
            - 'jar:'
    condition: selection_method and selection_body
falsepositives:
    - Legitimate applications sending JSON with @type fields and jar references is extremely unlikely but possible in custom serialization frameworks
level: high
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk and -t log_scale. Both conversions produced valid output. sigma check could not complete due to MITRE ATT&CK data fetch 403 in this environment but the rule structure is valid. The cs-body field requires web server or WAF body logging to be enabled, which is not universal. The @type + jar: combination is highly specific to this exploit chain. Values are not defanged per logsource-encoding guidance (rules use real values). -->

Dropped: Java Process Spawning Shell -- pure behavioral rule at TTP altitude, inconsistent with specific altitude request.

### Suricata: CVE-2026-16723 FastJson RCE via jar URL

Inspects HTTP POST request bodies for the @type + jar: URL pattern characteristic of this exploit.

Compile: PASS (suricata -T exit 0) | Confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-16723 FastJson RCE Exploit Attempt via jar URL in JSON Body"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"@type"; fast_pattern; content:"jar:"; distance:0; within:256; classtype:web-application-attack; reference:cve,2026-16723; reference:url,www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/; metadata:author Actioner, created_at 2026-07-28, cve CVE-2026-16723; sid:2100201; rev:1;)
```

<!-- audit: Validated with suricata -T -S, exit code 0, Suricata 7.0.3. Uses http.request_body (dot-notation) for body inspection. The distance:0 / within:256 constraint limits the jar: match to within 256 bytes after @type, reducing false positives while accommodating typical payload structures. The @type + jar: combination in a POST body is highly specific to CVE-2026-16723 exploitation. -->

### Snort: CVE-2026-16723 FastJson RCE via jar URL

Same detection logic as the Suricata rule, adapted for Snort 2.x syntax with underscore-notation buffers.

Compile: PASS (snort -T exit 0) | Confidence: high

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - CVE-2026-16723 FastJson RCE Exploit Attempt via jar URL in JSON Body"; flow:established,to_server; content:"POST"; http_method; content:"@type"; http_client_body; fast_pattern; content:"jar|3a|"; http_client_body; distance:0; within:256; classtype:web-application-attack; reference:cve,2026-16723; reference:url,www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/; metadata:author Actioner, created 2026-07-28; sid:9100201; rev:1;)
```

<!-- audit: Validated with snort -T using Snort 2.9.20. Uses Snort 2 syntax: http_method / http_client_body as post-content modifiers, tcp protocol with $HTTP_PORTS, jar encoded as jar|3a| (hex colon) for robustness. The same distance:0 / within:256 pattern applies. SID changed to 9100201 to avoid collision with Suricata rule SID 2100201. -->

### YARA: FastJson CVE-2026-16723 Exploit Payload Detection

Two rules for detecting exploit payloads in files, PCAP captures, or memory dumps. The first targets full exploit chains; the second catches minimal payload signatures.

Compile: PASS (yarac exit 0) | Confidence: high (Minimal_Payload) / medium (full rule)

```yara
rule Exploit_CVE_2026_16723_FastJson_RCE_Payload
{
    meta:
        description = "Detects FastJson CVE-2026-16723 exploit payloads containing @type with jar: URL patterns used to achieve RCE in Spring Boot fat-JAR deployments"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        severity = "critical"

    strings:
        $type = "\"@type\"" ascii wide nocase
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $jsontype = "@JSONType" ascii wide
        $parse1 = "JSON.parse" ascii
        $parse2 = "JSON.parseObject" ascii
        $getresource = "getResourceAsStream" ascii

    condition:
        filesize < 10MB and
        $type and
        ($jar_http or $jar_file) and
        any of ($jsontype, $parse1, $parse2, $getresource)
}

rule Exploit_CVE_2026_16723_FastJson_Minimal_Payload
{
    meta:
        description = "Detects minimal FastJson CVE-2026-16723 exploit payload signatures in HTTP traffic captures or files containing @type combined with nested jar: URL patterns"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation"
        severity = "high"

    strings:
        $sig1 = "@type\":\"jar:file:" ascii wide nocase
        $sig2 = "@type\":\"jar:http:" ascii wide nocase

    condition:
        filesize < 10MB and
        any of them
}
```

<!-- audit: Validated with yarac, exit code 0. The Minimal_Payload rule directly matches ThreatBook's published signature strings (@type":"jar:file: and @type":"jar:http:) and will have the highest hit rate on raw exploit traffic. The full rule requires additional context strings (JSON.parse, @JSONType, getResourceAsStream) and is more targeted for tooling/PoC detection but may miss minimal exploit payloads. Both rules include ascii wide nocase for encoding resilience. -->

## Lessons Learned

1. **Blocklist-based deserialization defenses are fundamentally fragile.** CVE-2026-16723 demonstrates that even with AutoType disabled, alternative code paths through type-resolution logic can bypass security controls. The industry pattern of responding to each new FastJson deserialization bypass with an updated blocklist was never sustainable.

2. **End-of-life libraries in production create unmitigable risk.** FastJson 1.x reached its final release but remains deeply embedded in enterprise applications. When no patch is forthcoming because the software is EOL, organizations face a choice between disruptive migration and accepting unpatched critical vulnerabilities.

3. **Supply chain depth matters.** FastJson is not typically an application the organization chose to expose -- it is a transitive dependency embedded in application frameworks. Organizations need comprehensive software composition analysis (SCA) to identify and track such deeply embedded dependencies.

4. **Deployment architecture affects vulnerability surface.** The exploit is specific to Spring Boot fat-JAR deployments. The same library in a WAR or plain JAR deployment is not vulnerable to this particular chain, highlighting the importance of understanding how deployment packaging affects attack surface.

## Sources

- [BleepingComputer - Hackers target US firms in FastJson RCE zero-day attacks](https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/) -- primary reporting on active exploitation targeting US organizations
- [SecurityWeek - Unpatched FastJson Vulnerability Exploited in Attacks](https://www.securityweek.com/unpatched-fastjson-vulnerability-exploited-in-attacks/) -- additional reporting with CVSS and technical context
- [Imperva - CVE-2026-16723 Critical FastJson 1.x Zero-Day RCE](https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/) -- WAF telemetry, attack tool distribution, geographic targeting data
- [ThreatBook - Fastjson RCE Active Exploitation Detection & Mitigation](https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation) -- in-the-wild exploitation confirmation, detection signatures, SafeMode configuration
- [The Hacker News - Fastjson 1.x RCE Vulnerability Targeted in Attacks](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html) -- technical chain analysis, vendor response details
- [NVD - CVE-2026-16723 Detail](https://nvd.nist.gov/vuln/detail/CVE-2026-16723) -- official CVE record, CVSS vector, CWE classification
- [Alibaba/FastJson2 GitHub Wiki - Security Advisory](https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83) -- vendor advisory with affected conditions, remediation guidance
- [LatestHackingNews - How the Fastjson RCE Vulnerability Actually Works](https://latesthackingnews.com/2026/07/26/fastjson-rce-vulnerability-how-to-check/) -- technical explanation of @JSONType trust signal and nested JAR path exploitation

<!-- revision: v1.0 2026-07-28 — Dropped Java-spawns-shell Sigma rule (TTP altitude). Removed T1195.001 and redundant T1059 from ATT&CK table. Removed attack.t1059.004 tag from webserver Sigma rule. Added cs-body portability caveat. Changed Snort SID 2100201→9100201 to avoid Suricata collision. Reworded IOC notice to clarify no network infrastructure IOCs available. Promoted from DRAFT to 1.0. -->

---
*Report generated by Actioner*
