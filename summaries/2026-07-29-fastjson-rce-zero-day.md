# Technical Analysis Report: Alibaba FastJson CVE-2026-16723 -- Gadget-Free RCE Zero-Day Actively Exploited Against US Organizations

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-29
Version: 1.0 (DRAFT)

## Executive Summary

CVE-2026-16723 is a **critical remote code execution (RCE) vulnerability** in Alibaba's FastJson, a widely used open-source Java JSON parsing library. Rated **CVSS 9.0** (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H), the flaw affects **FastJson versions 1.2.68 through 1.2.83** when deployed as a **Spring Boot executable fat-JAR** with SafeMode disabled (the default configuration). The vulnerability enables unauthenticated remote code execution **without requiring AutoType enablement or third-party gadget chains** -- a significant departure from prior FastJson deserialization exploits.

The vulnerability was discovered by **Kirill Firsov of FearsOff Cybersecurity** and disclosed on July 19, 2026. Alibaba published a security advisory on July 21, 2026, via the fastjson2 GitHub wiki (GHSA-crf3-v9rr-v7hj). **Active exploitation was confirmed by ThreatBook (July 22) and Imperva (July 25)**, targeting US-based organizations in the financial services, healthcare, computing, and retail sectors, with secondary activity in Singapore and Canada. **No official patch exists** for the FastJson 1.x branch, which is no longer actively maintained. The recommended mitigations are enabling SafeMode or migrating to FastJson 2.x.

## Background: Alibaba FastJson

FastJson is a high-performance Java library for converting Java objects to JSON and vice versa, developed and maintained by Alibaba Group. It has been one of the most widely deployed JSON parsing libraries in Java applications, particularly in Chinese enterprise ecosystems and globally in Spring Boot microservices architectures. FastJson 1.x reached its final release at version 1.2.83, and Alibaba has since focused development on FastJson 2.x (fastjson2), which uses a fundamentally different architecture.

FastJson has a significant history of deserialization vulnerabilities. Prior flaws (CVE-2022-25845 and others) relied on the `AutoType` feature being enabled and the presence of suitable gadget classes in the application classpath. CVE-2026-16723 is notably more dangerous because it requires **neither** -- it operates under FastJson's stock default configuration.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-19 | Kirill Firsov (FearsOff Cybersecurity) discloses the vulnerability |
| 2026-07-21 | Alibaba publishes security advisory on fastjson2 GitHub wiki |
| 2026-07-22 | ThreatBook deploys detection (ID S3100181015), captures exploitation in the wild |
| 2026-07-23 | CVE-2026-16723 formally published |
| 2026-07-25 | ThreatBook and Imperva confirm active exploitation against production targets |
| 2026-07-28 | Widespread media coverage (BleepingComputer, The Hacker News, SecurityWeek, SC World) |

## Technical Analysis

### Root Cause: Unsafe Type Resolution Before Security Enforcement

The vulnerability resides in FastJson 1.x's type-resolution logic, specifically in the `checkAutoType` and `TypeUtils.loadClass` methods. FastJson 1.x **probes user-controlled type names with `getResourceAsStream`** before enforcing its AutoType security restrictions. This means the library performs attacker-controlled resource lookups as part of type validation, before deciding whether to allow or block the type.

### Exploitation Mechanism

The exploit targets the `@type` field in JSON payloads -- FastJson's polymorphic deserialization directive. The attack chain works as follows:

1. **Payload delivery**: The attacker sends a crafted JSON payload containing a malicious `@type` value using `jar:http` or `jar:file` URI schemes to a network-accessible endpoint that parses JSON using FastJson.

2. **Class-resource lookup**: FastJson's type-resolution logic processes the `@type` value and performs a `getResourceAsStream` lookup using the attacker-supplied type name. In Spring Boot fat-JAR deployments, this allows resolution of nested JAR paths that can reference attacker-controlled resources.

3. **Trust signal bypass**: The `@JSONType` annotation present on the attacker-controlled resource serves as a trust signal during type resolution, causing FastJson to treat the class as legitimate and bypass its security checks.

4. **Code execution**: The attacker-controlled bytecode is loaded and executed, achieving remote code execution on the target server.

### Vulnerable Entry Points

The following FastJson parsing methods are vulnerable:
- `JSON.parse()`
- `JSON.parseObject(String)`
- `JSON.parseObject(String, Class)` -- notably, specifying a target class does **not** mitigate the vulnerability, as attackers can nest payloads within `Object` or `Map` typed fields.

### Exploitation Payload Signatures

ThreatBook identified two specific payload signatures used in active exploitation:
- `@type":"jar:file:.` -- references local JAR resources
- `@type":"jar:http:.` -- references remote JAR resources via HTTP

### Confirmed Affected Configurations

| Component | Affected |
|-----------|----------|
| FastJson versions | 1.2.68 through 1.2.83 (inclusive) |
| Deployment model | Spring Boot executable fat-JAR only |
| SafeMode | Disabled (default) |
| AutoType | Not required (works with AutoType OFF) |
| JDK versions | 8, 11, 17, 21 verified |
| Spring Boot versions | 2.x, 3.x, 4.x verified |

### Unaffected Configurations

- FastJson 2.x (architecturally immune -- uses allowlist-first model, no resource-probing)
- Non-fat JARs, generic uber-JARs, Tomcat or Jetty WAR deployments
- FastJson 1.2.60 and earlier (type-resolution logic not present)
- Deployments with SafeMode enabled

### Attack Tool Characteristics

According to Imperva's threat intelligence:
- **~70%** of attacks originate from browser impersonator User-Agents
- **~30%** of attacks use tools written in Ruby and Go
- Attacks are primarily targeting **US-based organizations**, with smaller volumes in **Singapore** and **Canada**
- Targeted sectors: **Financial Services, Healthcare, Computing, Retail, Business**

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation where applicable.

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|--------------------|-------------|
| com.alibaba:fastjson | 1.2.68 -- 1.2.83 | RCE via type-resolution resource probing in Spring Boot fat-JAR deployments |
| com.alibaba:fastjson:1.2.83_noneautotype | N/A (mitigated build) | Alternative build with AutoType code removed |

### Network / Payload Indicators

| Type | Value | Context |
|------|-------|---------|
| Payload Pattern | `@type":"jar:http` | Remote JAR resource lookup exploit payload in JSON body |
| Payload Pattern | `@type":"jar:file` | Local JAR resource lookup exploit payload in JSON body |
| HTTP Method | POST with Content-Type: application/json | Exploit delivery mechanism |
| URI Characters | `:` and `!` in @type values | URL-special characters exploited before validation |

**Note:** As of this writing, no specific attacker IP addresses, domains, or file hashes have been published by ThreatBook, Imperva, or other security vendors in their public reporting. IOCs are limited to payload patterns and behavioral indicators.

### Behavioral Indicators

- HTTP POST requests containing JSON with `@type` values referencing `jar:http` or `jar:file` URIs
- Unexpected outbound HTTP connections from Java processes (fetching remote JAR resources)
- Unexpected child processes spawned by Java/JVM processes (post-exploitation command execution)
- Unauthorized file modifications on Spring Boot application servers
- Web shells or backdoors appearing on Java application servers
- Suspicious `@type` values in web application / WAF logs

### Threat Intelligence Identifiers

| Identifier | Value | Source |
|------------|-------|--------|
| CVE | CVE-2026-16723 | MITRE/NVD |
| GHSA | GHSA-crf3-v9rr-v7hj | GitHub Security Advisory |
| XVE | XVE-2026-39684 | ThreatBook |
| Detection ID | S3100181015 | ThreatBook TDP |
| CWE | CWE-20 (Improper Input Validation) | NVD |
| CWE | CWE-502 (Deserialization of Untrusted Data) | NVD |
| CAPEC | CAPEC-586 (Object Injection) | NVD |

## MITRE ATT&CK Mapping

| TID | Technique | Observed/Expected Behavior |
|-----|-----------|---------------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of FastJson deserialization in internet-facing Spring Boot applications |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation command execution via spawned shell processes from Java (Linux deployments) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Post-exploitation command execution on Windows-hosted Spring Boot deployments |
| T1505.003 | Server Software Component: Web Shell | Expected follow-on persistence via web shell deployment on compromised Java application servers |
| T1071.001 | Application Layer Protocol: Web Protocols | Exploit delivery via HTTP POST with JSON payload; potential C2 over HTTP |

## Impact Assessment

- **Severity:** Critical (CVSS 9.0) -- unauthenticated, no user interaction, scope-changed impact
- **Breadth:** All Spring Boot fat-JAR deployments using FastJson 1.2.68-1.2.83 with SafeMode disabled (the default); FastJson remains one of the most widely deployed Java JSON libraries globally
- **Exploitation status:** Actively exploited in the wild since at least July 22, 2026; public PoC available; exploitation expected to expand globally
- **Patch status:** **No official patch** -- FastJson 1.x is no longer actively maintained; the GitHub wiki advisory references version 1.2.84 as a fixed version, but no release has been confirmed
- **Impact:** Full remote code execution on the application server, enabling data exfiltration, lateral movement, persistence via web shells, and ransomware deployment

## Detection & Remediation

### Immediate Detection

1. **Search web application and WAF logs** for HTTP POST requests containing JSON bodies with `@type` values referencing `jar:http` or `jar:file` URI schemes.
2. **Monitor Java processes** for unexpected child processes (shells, download tools, network utilities).
3. **Review outbound connections** from Java application servers for unexpected HTTP requests to external hosts (remote JAR resource fetching).
4. **Inventory FastJson usage** across all applications -- search build files (pom.xml, build.gradle) for `com.alibaba:fastjson` dependencies in versions 1.2.68-1.2.83.

### Remediation

1. **Enable SafeMode immediately** via one of:
   - JVM parameter: `-Dfastjson.parser.safeMode=true`
   - Code: `ParserConfig.getGlobalInstance().setSafeMode(true)`
   - Configuration file: `fastjson.parser.safeMode=true`
2. **Use the restricted build variant**: Replace dependency with `com.alibaba:fastjson:1.2.83_noneautotype` which has the vulnerable AutoType code removed.
3. **Migrate to FastJson 2.x** (recommended long-term fix) -- FastJson 2.x is architecturally immune as it uses an allowlist-first model for polymorphic deserialization and does not rely on `@JSONType` annotation as a trust signal.
4. **Block at the WAF/IPS**: Filter POST requests with `application/json` content type containing `jar:http` or `jar:file` strings in the request body.

### Long-Term Hardening

- Maintain an inventory of all FastJson dependencies, including transitive dependencies pulled in by third-party libraries.
- Avoid exposing Spring Boot fat-JAR applications directly to the internet without a WAF capable of inspecting JSON payloads.
- Subscribe to the fastjson2 GitHub repository for security advisories.
- Consider adopting alternative JSON libraries (Jackson, Gson) that do not support polymorphic deserialization by default.

## Detection Rules

Six detection rules target CVE-2026-16723 exploitation: three Sigma rules (HTTP payload detection, Windows post-exploitation, Linux post-exploitation), one Snort rule, one Suricata rule set, and one YARA rule set. All are PoC/advisory-specific altitude with strict leniency, targeting the known `@type` + `jar:` URI exploitation pattern.

### Sigma: FastJson CVE-2026-16723 Exploit Payload in HTTP Request Logs

Detects HTTP requests containing FastJson exploitation payloads with `@type` fields referencing `jar:http` or `jar:file` URI schemes in web server logs or request bodies.
**Status:** compile ✅ compiles (sigma convert to Splunk and LogScale successful) -- confidence: high
<!-- audit: sigma check failed only due to MITRE ATT&CK data download blocked by proxy (not a rule defect). splunk convert: "cs-uri" IN ("*jar:http*", "*jar:file*") OR (request_body="*@type*" request_body IN ("*jar:http*", "*jar:file*")). log_scale convert: "cs-uri"=/jar:http/i or "cs-uri"=/jar:file/i or (request_body=/@type/i request_body=/jar:http/i or request_body=/jar:file/i). Values real, not defanged. -->
```yaml
title: FastJson CVE-2026-16723 Exploit Payload in HTTP Request Logs
id: 8e3f2a1b-c4d5-4e6f-a7b8-9c0d1e2f3a4b
status: experimental
description: >
    Detects HTTP requests containing FastJson CVE-2026-16723 exploitation payloads.
    The exploit uses crafted @type values with jar:http or jar:file URI schemes to trigger
    class-resource lookups in Spring Boot fat-JAR deployments. Active exploitation targeting
    US organizations in financial services, healthcare, computing, and retail sectors was
    confirmed by ThreatBook and Imperva starting July 25, 2026.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
    - https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation
    - https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/
    - https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83
author: Actioner
date: 2026/07/29
tags:
    - attack.t1190
    - attack.t1059
    - cve.2026.16723
logsource:
    category: webserver
detection:
    selection_jar_http:
        cs-uri|contains: 'jar:http'
    selection_jar_file:
        cs-uri|contains: 'jar:file'
    selection_body_jar_http:
        request_body|contains: 'jar:http'
    selection_body_jar_file:
        request_body|contains: 'jar:file'
    selection_type_field:
        request_body|contains: '@type'
    condition: (selection_jar_http or selection_jar_file) or (selection_type_field and (selection_body_jar_http or selection_body_jar_file))
falsepositives:
    - Legitimate applications using jar: URI schemes in JSON payloads (unlikely in typical web applications)
level: high
```

### Sigma: Suspicious Child Process Spawned by Java - Windows Post-Exploitation

Detects suspicious child processes spawned by Java on Windows systems, indicating potential post-exploitation activity following FastJson CVE-2026-16723 RCE.
**Status:** compile ✅ compiles (sigma convert to Splunk and LogScale successful) -- confidence: medium
<!-- audit: sigma check failed only due to MITRE ATT&CK data download blocked by proxy (not a rule defect). splunk convert: ParentImage IN ("*\\java.exe", "*\\javaw.exe") Image IN ("*\\cmd.exe", "*\\powershell.exe", ...). log_scale convert successful. Generic Java child process rule — legitimate Java applications may spawn system processes. Values real. -->
```yaml
title: Suspicious Child Process Spawned by Java - Potential FastJson RCE Post-Exploitation
id: 7d2e1b0a-b3c4-4d5e-a6f7-8b9c0d1e2f3a
status: experimental
description: >
    Detects suspicious child processes spawned by Java processes, which may indicate
    successful exploitation of CVE-2026-16723 in FastJson. After achieving RCE through
    the deserialization flaw, attackers typically spawn shell processes or download
    additional payloads. This rule targets the post-exploitation phase where attacker-
    controlled bytecode executes system commands.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
    - https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation
    - https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/
author: Actioner
date: 2026/07/29
tags:
    - attack.t1059.004
    - attack.t1059.001
    - cve.2026.16723
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Java applications that spawn system processes
    - Build tools and CI/CD pipelines using Java
level: high
```

### Sigma: Suspicious Child Process Spawned by Java - Linux Post-Exploitation

Detects suspicious child processes spawned by Java on Linux systems, indicating potential post-exploitation. Spring Boot fat-JAR deployments commonly run on Linux.
**Status:** compile ✅ compiles (sigma convert to Splunk and LogScale successful) -- confidence: medium
<!-- audit: sigma check failed only due to MITRE ATT&CK data download blocked by proxy (not a rule defect). splunk convert: ParentImage IN ("*/java", "*/javaw") Image IN ("*/sh", "*/bash", ...). log_scale convert successful. Generic Java child process rule for Linux. Values real. -->
```yaml
title: Suspicious Child Process Spawned by Java on Linux - Potential FastJson RCE Post-Exploitation
id: 6c1d0a9f-a2b3-4c4d-95e6-7a8b9c0d1e2f
status: experimental
description: >
    Detects suspicious child processes spawned by Java processes on Linux systems,
    which may indicate successful exploitation of CVE-2026-16723 in FastJson.
    Spring Boot fat-JAR deployments commonly run on Linux. After RCE, attackers
    typically spawn shells, download tools, or establish reverse shells.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
    - https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation
    - https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/
author: Actioner
date: 2026/07/29
tags:
    - attack.t1059.004
    - cve.2026.16723
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/java'
            - '/javaw'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
            - '/curl'
            - '/wget'
            - '/python'
            - '/python3'
            - '/perl'
            - '/nc'
            - '/ncat'
            - '/socat'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Java applications that invoke shell commands
    - Application servers running maintenance scripts
    - Build tools and CI/CD pipelines
level: medium
```

### Snort: FastJson CVE-2026-16723 RCE Exploit Detection

Detects HTTP POST requests with JSON content containing `@type` paired with `jar:` URI schemes -- the specific exploitation pattern for CVE-2026-16723. Requires TLS decryption to inspect payload.
**Status:** compile ✅ compiles (Snort 2.9.20 validated) -- confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R fj.rules -T exit 0. Three rules: sid 2100001 (jar:http), 2100002 (jar:file), 2100003 (jar: generic). http_method/http_header/http_client_body content modifiers. distance:0 within:64 ensures @type and jar: are proximate in JSON body. Values real. Requires TLS decryption. -->
```snort
# Snort rules for CVE-2026-16723 - FastJson RCE Zero-Day
# References:
#   https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
#   https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation

# Detect @type with jar:http in JSON POST body
alert tcp any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar:http @type Payload"; flow:to_server,established; content:"POST"; http_method; content:"application/json"; http_header; content:"@type"; http_client_body; content:"jar|3a|http"; http_client_body; distance:0; within:64; reference:cve,2026-16723; classtype:web-application-attack; sid:2100001; rev:1; metadata:created_at 2026_07_29;)

# Detect @type with jar:file in JSON POST body
alert tcp any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar:file @type Payload"; flow:to_server,established; content:"POST"; http_method; content:"application/json"; http_header; content:"@type"; http_client_body; content:"jar|3a|file"; http_client_body; distance:0; within:64; reference:cve,2026-16723; classtype:web-application-attack; sid:2100002; rev:1; metadata:created_at 2026_07_29;)

# Detect @type with jar: URI scheme broadly (fallback)
alert tcp any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar: URI in JSON Body"; flow:to_server,established; content:"POST"; http_method; content:"@type"; http_client_body; content:"jar|3a|"; http_client_body; distance:0; within:128; reference:cve,2026-16723; classtype:web-application-attack; sid:2100003; rev:1; metadata:created_at 2026_07_29;)
```

### Suricata: FastJson CVE-2026-16723 RCE Exploit Detection

Detects HTTP POST requests with JSON content containing `@type` paired with `jar:` URI schemes using Suricata dot-notation sticky buffers. Requires TLS decryption to inspect payload.
**Status:** compile ✅ compiles (Suricata 7.0.3 validated) -- confidence: high
<!-- audit: suricata -T -S fastjson_exploit.suricata.rules exit 0. Four rules: sid 2200001 (jar:http), 2200002 (jar:file), 2200003 (jar: generic), 2200004 (JSONType annotation). Dot-notation sticky buffers (http.method, http.content_type, http.request_body). Values real. Requires TLS decryption. -->
```suricata
# Suricata rules for CVE-2026-16723 - FastJson RCE Zero-Day
# References:
#   https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/
#   https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation

# Detect @type with jar:http in JSON POST body
alert http any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar:http @type Payload"; flow:to_server,established; http.method; content:"POST"; http.content_type; content:"application/json"; http.request_body; content:"@type"; content:"jar|3a|http"; distance:0; within:64; reference:cve,2026-16723; classtype:web-application-attack; sid:2200001; rev:1; metadata:created_at 2026_07_29;)

# Detect @type with jar:file in JSON POST body
alert http any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar:file @type Payload"; flow:to_server,established; http.method; content:"POST"; http.content_type; content:"application/json"; http.request_body; content:"@type"; content:"jar|3a|file"; distance:0; within:64; reference:cve,2026-16723; classtype:web-application-attack; sid:2200002; rev:1; metadata:created_at 2026_07_29;)

# Detect @type with jar: URI scheme broadly in HTTP request body
alert http any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - jar: URI in JSON Body"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"@type"; content:"jar|3a|"; distance:0; within:128; reference:cve,2026-16723; classtype:web-application-attack; sid:2200003; rev:1; metadata:created_at 2026_07_29;)

# Detect @JSONType annotation abuse pattern in JSON body
alert http any any -> any any (msg:"Actioner - FastJson CVE-2026-16723 RCE Exploit - JSONType Annotation Abuse"; flow:to_server,established; http.method; content:"POST"; http.content_type; content:"application/json"; http.request_body; content:"@type"; content:"JSONType"; distance:0; within:256; reference:cve,2026-16723; classtype:web-application-attack; sid:2200004; rev:1; metadata:created_at 2026_07_29;)
```

### YARA: FastJson CVE-2026-16723 Exploit Payload and Tool Detection

Detects FastJson exploitation payloads and exploit tools containing the characteristic `@type` + `jar:` URI pattern, as well as tools specifically referencing CVE-2026-16723.
**Status:** compile ✅ compiles (yarac validated) -- confidence: high
<!-- audit: yarac fastjson_exploit.yar /dev/null exit 0. Two rules: FastJson_CVE_2026_16723_Exploit_Payload (payload in network captures or files), FastJson_CVE_2026_16723_Exploit_Tool (exploit tools referencing the CVE). Values real. -->
```yara
rule FastJson_CVE_2026_16723_Exploit_Payload
{
    meta:
        description = "Detects FastJson CVE-2026-16723 exploitation payloads containing @type with jar: URI schemes"
        author = "Actioner"
        date = "2026-07-29"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        reference2 = "https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation"
        cve = "CVE-2026-16723"
        severity = "critical"
        tlp = "white"

    strings:
        $type_field = "@type" ascii wide
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $json_type = "@JSONType" ascii wide
        $parse_obj = "parseObject" ascii wide
        $fastjson = "fastjson" ascii wide nocase

    condition:
        $type_field and ($jar_http or $jar_file) and (($json_type or $parse_obj or $fastjson) or filesize < 10KB)
}

rule FastJson_CVE_2026_16723_Exploit_Tool
{
    meta:
        description = "Detects tools or scripts designed to exploit FastJson CVE-2026-16723"
        author = "Actioner"
        date = "2026-07-29"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        cve = "CVE-2026-16723"
        severity = "high"
        tlp = "white"

    strings:
        $cve = "CVE-2026-16723" ascii wide nocase
        $fastjson_rce = "fastjson" ascii wide nocase
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $type = "@type" ascii wide
        $safe_mode = "safeMode" ascii wide
        $autotype = "AutoType" ascii wide
        $spring_boot = "spring-boot" ascii wide nocase
        $fat_jar = "fat-jar" ascii wide nocase

    condition:
        $cve or ($fastjson_rce and $type and ($jar_http or $jar_file) and any of ($safe_mode, $autotype, $spring_boot, $fat_jar))
}
```

## Sources

- [BleepingComputer -- Hackers target US firms in FastJson RCE zero-day attacks](https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/) -- primary reporting: active exploitation, targeting details, affected versions, remediation guidance
- [ThreatBook -- Fastjson RCE (<=1.2.83): Active Exploitation Detected -- Detection & Mitigation](https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation) -- first detection of in-the-wild exploitation, payload signatures (`jar:file`, `jar:http`), detection ID S3100181015, mitigation guidance
- [Imperva -- Imperva Customers Protected Against CVE-2026-16723: Critical FastJson 1.x Zero-Day RCE](https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/) -- attack traffic analysis, sector/geographic targeting, exploitation tool characteristics, WAF protection details
- [The Hacker News -- Fastjson 1.x RCE Vulnerability Targeted in Attacks With No Patch Available](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html) -- technical analysis of exploitation mechanism, entry points, timeline, remediation options
- [SecurityWeek -- Unpatched Fastjson Vulnerability Exploited in Attacks](https://www.securityweek.com/unpatched-fastjson-vulnerability-exploited-in-attacks/) -- CVE details, exploitation requirements, industry targeting, Alibaba response
- [SC World -- Hackers exploit FastJson vulnerability for remote code execution](https://www.scworld.com/brief/hackers-exploit-fastjson-vulnerability-for-remote-code-execution) -- brief confirming active exploitation, sector targeting
- [Alibaba/FastJson2 GitHub Wiki -- Security Advisory: Remote Code Execution in fastjson 1.2.68-1.2.83](https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83) -- official vendor advisory, root cause description, remediation steps, affected/unaffected configurations
- [CIRCL Vulnerability Lookup -- CVE-2026-16723](https://vulnerability.circl.lu/vuln/CVE-2026-16723) -- CVSS vectors (v2 7.6, v3 9.0), CWE classifications, EPSS score, KEVIntel exploitation confirmation
- [Tenable -- CVE-2026-16723](https://www.tenable.com/cve/CVE-2026-16723) -- CVE details, CVSS scoring, reference links
- [LatestHackingNews -- How the Fastjson RCE Vulnerability Actually Works](https://latesthackingnews.com/2026/07/26/fastjson-rce-vulnerability-how-to-check/) -- technical explanation, exposure assessment criteria, credited researcher details
