# Technical Analysis Report: Proto6 — Six Vulnerabilities in protobuf.js (2026-06-10)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-10
Version: 1.0 (DRAFT)

## Executive Summary

Six vulnerabilities collectively dubbed "Proto6" were disclosed in protobuf.js (npm `protobufjs` and `protobufjs-cli`), the widely used JavaScript library for compiling and processing Protocol Buffer definitions. The flaws range from denial-of-service (stack exhaustion, process-wide constructor corruption) to remote code execution via prototype pollution gadget chains and code injection in generated JavaScript. The most critical — CVE-2026-44291 (CVSS 8.1) and CVE-2026-44295 (CVSS 8.7) — allow arbitrary JavaScript execution when applications accept untrusted protobuf schemas or JSON descriptors. Affected versions span protobufjs <=7.5.5 and 8.0.0-8.0.1 (runtime) and protobufjs-cli <=1.2.0 and 2.0.0-2.0.1 (CLI tools). Patches are available in protobufjs 7.5.6/8.0.2 and protobufjs-cli 1.2.1/2.0.2.

## Background: protobuf.js

protobuf.js is the dominant JavaScript/TypeScript implementation of Google Protocol Buffers, with over 8 million weekly npm downloads. It provides both runtime reflection APIs (`Root.load()`, `Root.fromJSON()`, `parse()`) and CLI tools (`pbjs` for JavaScript code generation, `pbts` for TypeScript definition generation). The library generates encoder/decoder functions dynamically using `new Function()` and handles schema metadata as trusted input by default — a design assumption that all six vulnerabilities exploit.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-16 | CVE-2026-41242 (precursor GHSA-xq3m-2v4x-88gg) disclosed — code execution via type names in reflection APIs (patched in 7.5.5/8.0.1) |
| 2026-05-12 | Proto6 batch disclosed: CVE-2026-44289, -44290, -44291, -44292, -44293, -44294, -44295, plus CVE-2026-42290 (pbts command injection) |
| 2026-05-13 | NVD publishes CVE-2026-44291 entry |
| 2026-06-10 | The Hacker News publishes consolidated Proto6 analysis |

## Root Cause: Untrusted Schema Metadata Treated as Code

The root cause across all six vulnerabilities is that protobuf.js treats schema-controlled metadata (type names, option paths, field names, default values, namespace structures) as trusted data and embeds it directly into generated JavaScript code or uses it for property lookups on plain objects with inherited prototypes. When any of this metadata is attacker-controlled, the library's code generation and lookup mechanisms become injection vectors.

## Technical Analysis of the Malicious Payload

### 1. CVE-2026-44291 — Prototype Pollution to RCE via Code Generation Gadget (CVSS 8.1)

**GHSA-75px-5xx7-5xc7 | CWE-94 | protobufjs <=7.5.5, 8.0.0-8.0.1**

The library uses plain objects with inherited prototypes for type lookup tables used by generated encode/decode functions. When `Object.prototype` is polluted through a separate gadget (e.g., lodash merge, qs parser), attacker-controlled strings appear as valid type references in the lookup. The library then inserts these strings into generated JavaScript compiled via `new Function()`, achieving arbitrary code execution. The attack chain requires: (1) a reachable prototype pollution primitive, (2) the same process subsequently using protobufjs to encode/decode data, (3) polluted properties resolving as type names, (4) `Function()` compilation of injected code.

### 2. CVE-2026-44295 — Code Injection in pbjs Static Output (CVSS 8.7)

**GHSA-6r35-46g8-jcw9 | CWE-94 | protobufjs-cli <=1.2.0, 2.0.0-2.0.1**

The `pbjs` CLI tool generates static JavaScript from `.proto` schemas. Namespace, enum, service, and derived full names from the schema are embedded into the generated JavaScript output without sanitization. An attacker who can influence the schema (e.g., in a CI/CD pipeline processing third-party `.proto` files) can inject arbitrary executable JavaScript that runs when the generated file is imported or required. This is particularly dangerous in CI/CD pipelines where untrusted schemas may be compiled automatically.

### 3. CVE-2026-44293 — Code Injection via Bytes Field Defaults (CVSS 7.7)

**GHSA-66ff-xgx4-vchm | CWE-94 | protobufjs <=7.5.5, 8.0.0-8.0.1**

When generating `toObject` conversion functions, the library emits default values for `bytes` fields directly into generated code. A crafted JSON descriptor with a non-string default value for a `bytes` field enables arbitrary JavaScript injection into the generated conversion function. Exploitation requires the application to load an attacker-controlled JSON descriptor and call `toObject` with defaults enabled.

### 4. CVE-2026-44290 — Option Path Traversal DoS (CVSS 7.5)

**GHSA-jvwf-75h9-cwgg | CWE-94 | protobufjs <=7.5.5, 8.0.0-8.0.1**

Option paths in schemas can traverse through inherited object properties when applying options. An attacker can craft option paths that write to properties on global JavaScript constructors (e.g., `Object`, `Array`, `Function`), corrupting process-wide built-in functionality and causing persistent denial of service. Triggered via `parse()`, `Root.load()`, `Root.loadSync()`, or `Root.fromJSON()` on untrusted schemas.

### 5. CVE-2026-44292 — Per-Instance Prototype Injection (CVSS 5.3)

**GHSA-fx83-v9x8-x52w | CWE-1321 | protobufjs <=7.5.5, 8.0.0-8.0.1**

Generated message constructors copy enumerable properties from a provided properties object without filtering the `__proto__` key. An attacker who supplies a plain object with an enumerable `__proto__` property (common from `JSON.parse()` of untrusted input) can alter the prototype chain of individual message instances. Real-world exploitation demonstrated in the Baileys WhatsApp library, where crafted messages crash bots.

### 6. CVE-2026-44294 — Control Character DoS in Field Names (CVSS 5.3)

**GHSA-2pr8-phx7-x9h3 | CWE-20 | protobufjs <=7.5.5, 8.0.0-8.0.1**

Control characters in schema-defined field and oneof names are not escaped before being embedded into generated function bodies (encode, decode, verify, fromObject, toObject). This causes the generated functions to throw syntax errors at runtime, resulting in denial of service.

### Related: CVE-2026-42290 — pbts Command Injection (CVSS 7.8)

**GHSA-f84p-cvgm-xgjj | CWE-78 | protobufjs-cli <=1.2.0, 2.0.0-2.0.1**

The `pbts` tool invokes JSDoc by building a shell command string from input file paths via `child_process.exec()`. File paths containing shell metacharacters are interpreted by the shell, enabling arbitrary command execution. Requires local access to control file names supplied to `pbts`.

### Related: CVE-2026-48712 — Unbounded Any Recursion DoS (CVSS 7.5)

**GHSA-wcpc-wj8m-hjx6 | CWE-674 | protobufjs <=7.6.0, 8.0.0-8.4.0**

Unbounded recursion during `toObject()` or JSON conversion of deeply nested `google.protobuf.Any` values exhausts the call stack, crashing the process. Only affects applications performing JSON conversion of Any-containing messages from untrusted sources.

### Related: CVE-2026-45740 — Unbounded JSON Descriptor Recursion (CVSS 5.3)

**GHSA-jggg-4jg4-v7c6 | CWE-674 | protobufjs <=7.5.7, 8.0.0-8.1.x**

Deeply nested `nested` namespace objects in JSON descriptors cause call stack exhaustion during `Root.fromJSON()` and `Namespace.addJSON()` processing.

### 3. C2 Infrastructure

Not applicable — these are vulnerability exploitation chains, not malware campaigns. There is no associated C2 infrastructure.

### 4. Platform-Specific Behavior

#### Node.js (All Platforms)

All Proto6 vulnerabilities target the Node.js runtime environment. The exploitation surface is any Node.js application that:
- Accepts untrusted `.proto` files or JSON descriptors via `Root.load()`, `Root.loadSync()`, `Root.fromJSON()`, or `parse()`
- Runs `pbjs` or `pbts` on untrusted schema files (CI/CD pipeline attacks)
- Constructs protobuf message objects from untrusted JSON (e.g., API inputs parsed via `JSON.parse()`)
- Uses protobufjs encode/decode in processes where prototype pollution exists

### 5. Anti-Forensics / Evasion Techniques

The code injection payloads execute within the Node.js process context, leaving minimal filesystem or network artifacts unless the injected code explicitly performs such actions. Exploitation via prototype pollution (CVE-2026-44291) is particularly stealthy because the malicious code runs inside dynamically generated `Function()` constructors that are part of normal protobufjs operation.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through.

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| protobufjs (npm) | <=7.5.5, 8.0.0-8.0.1 | Core runtime — code injection, prototype pollution, DoS |
| protobufjs-cli (npm) | <=1.2.0, 2.0.0-2.0.1 | CLI tools — code injection in pbjs, command injection in pbts |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | `*.proto` files with embedded JS | N/A | Crafted schemas with code injection payloads in names, options, or defaults |
| Any | JSON descriptor files | N/A | Crafted JSON with `__proto__`, nested namespaces, or bytes field injection |

### Network

No specific network IOCs — exploitation is application-level via schema/payload manipulation.

### Behavioral

- **Prototype pollution indicators:** Node.js process behavior changes after processing untrusted JSON input — unexpected properties appearing on `Object.prototype`, `Array.prototype`, or `Function.prototype`
- **Code generation exploitation:** Unusual strings appearing in `Function()` constructor calls within the protobufjs encode/decode code path — strings containing `require()`, `eval()`, `child_process`, `process.mainModule`
- **CI/CD pipeline indicators:** `pbjs` or `pbts` processing `.proto` files from untrusted external sources (pull requests, third-party registries)
- **DoS indicators:** Node.js processes crashing with "Maximum call stack size exceeded" errors when processing protobuf messages, particularly those containing `google.protobuf.Any` fields
- **WhatsApp bot crashes:** Baileys-based bots crashing on specific incoming messages (CVE-2026-44292 exploitation)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1059.007 | Command and Scripting Interpreter: JavaScript | Code injection via protobufjs generates and executes arbitrary JavaScript through `Function()` constructor |
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious `.proto` schemas injected into CI/CD pipelines exploit pbjs code generation |
| T1190 | Exploit Public-Facing Application | Applications accepting untrusted protobuf schemas/payloads are directly exploitable |
| T1499.004 | Endpoint Denial of Service: Application or System Exploitation | Stack exhaustion via unbounded recursion or constructor corruption causes process crashes |

## Impact Assessment

protobuf.js has approximately 8+ million weekly npm downloads and is a transitive dependency of major frameworks including gRPC-Web, Baileys (WhatsApp), and numerous microservice architectures. The exploitation surface includes any Node.js application that processes untrusted protobuf schemas or JSON descriptors. CI/CD pipelines that automatically compile third-party `.proto` files using `pbjs` are at particular risk for supply-chain-style attacks. The Baileys WhatsApp library scenario demonstrates real-world exploitability for DoS.

## Detection & Remediation

### Immediate Detection

```bash
# Check for vulnerable protobufjs versions in your project
npm ls protobufjs 2>/dev/null | grep -E "protobufjs@[0-7]\." | grep -v "7\.5\.[6-9]"
npm ls protobufjs 2>/dev/null | grep -E "protobufjs@8\.0\.[01]"

# Check for vulnerable protobufjs-cli versions
npm ls protobufjs-cli 2>/dev/null | grep -E "protobufjs-cli@[01]\.[0-2]\." | grep -v "1\.2\.[1-9]"
npm ls protobufjs-cli 2>/dev/null | grep -E "protobufjs-cli@2\.0\.[01]"

# Search for untrusted schema loading patterns in code
grep -rn "Root\.load\|Root\.loadSync\|Root\.fromJSON\|protobuf\.parse" --include="*.js" --include="*.ts" .

# Audit lock file for affected versions
npm audit 2>/dev/null | grep -i protobuf
```

### Remediation

1. **Upgrade immediately:** `npm install protobufjs@latest protobufjs-cli@latest`
2. **Audit schema sources:** Identify all locations where `.proto` files or JSON descriptors are loaded and ensure they come from trusted, version-controlled sources only
3. **Isolate schema processing:** If untrusted schemas must be processed, run `pbjs`/`pbts` and reflection APIs in sandboxed child processes with restricted privileges
4. **Validate JSON input:** Strip `__proto__` and `constructor` keys from any JSON parsed from untrusted sources before passing to protobufjs message constructors
5. **Pin schema dependencies:** In CI/CD pipelines, pin and integrity-check all `.proto` file sources; do not compile schemas from unreviewed pull requests automatically

### Long-Term Hardening

- Adopt a "schemas are code" security model — treat `.proto` files with the same review rigor as source code
- Implement Content Security Policy (CSP) or similar restrictions in Node.js environments to limit `Function()` constructor usage
- Use `Object.create(null)` patterns or `Map` for lookup tables in critical paths to prevent prototype pollution escalation
- Consider frozen/sealed objects for schema metadata in security-sensitive applications
- Run `npm audit` in CI/CD gates to catch vulnerable transitive dependencies automatically

## Detection Rules

These detections target the distinctive artifacts of Proto6 exploitation: malicious protobuf schema files containing code injection payloads, and process-level indicators of protobufjs CLI tools processing untrusted schemas. The YARA rules are file-level and scan for injection patterns in `.proto` and JSON descriptor files; the Sigma rules detect suspicious `pbjs`/`pbts` execution and schema loading from untrusted paths. Compiles != fires — verify in your environment.

### Sigma: Suspicious protobufjs CLI Execution on Untrusted Schema

Detects execution of `pbjs` or `pbts` CLI tools, which are vulnerable to code injection (CVE-2026-44295) and command injection (CVE-2026-42290) when processing untrusted schemas. Scope to CI/CD runners or build servers for best signal-to-noise.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0; splunk 0; log_scale 0. Broad — any pbjs/pbts invocation fires. Precision depends on environment scoping. No pipeline-mapped conversion (no standard Linux process_creation pipeline in sigma list). FP risk: legitimate development use of pbjs/pbts is common. Best as hunt rule in CI/CD environments processing external schemas. -->
```yaml
title: Suspicious protobufjs CLI Execution on Untrusted Schema
id: 8e4a1c3f-6b2d-4f7e-9a5c-1d3e8f0b2c7a
status: experimental
description: >
    Detects execution of protobufjs CLI tools (pbjs, pbts) which are vulnerable to
    code injection via crafted schema names (CVE-2026-44295) and command injection
    via crafted filenames (CVE-2026-42290). Suspicious when run in CI/CD pipelines
    or on schemas from untrusted sources.
references:
    - https://thehackernews.com/2026/06/six-proto6-vulnerabilities-in.html
    - https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-6r35-46g8-jcw9
    - https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-f84p-cvgm-xgjj
author: Actioner
date: 2026/06/10
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_node:
        Image|endswith:
            - '/node'
            - '/nodejs'
    selection_cli:
        CommandLine|contains:
            - 'pbjs'
            - 'pbts'
            - 'protobufjs-cli'
    condition: selection_node and selection_cli
falsepositives:
    - Legitimate protobuf schema compilation during development
    - CI/CD build pipelines using trusted schemas
level: low
```

### Sigma: Node.js Loading Protobuf Schema from Untrusted Source

Detects Node.js processes loading protobuf definitions from temporary directories or remote URLs, which may indicate exploitation of Proto6 reflection API vulnerabilities (CVE-2026-44291, CVE-2026-44290, CVE-2026-44293).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Requires process_creation with CommandLine visibility. Relies on schema path appearing in CommandLine args, which may not always be the case (programmatic loading won't appear). No pipeline-mapped conversion. FP: dev workflows loading from /tmp build dirs. -->
```yaml
title: Node.js Application Loading Protobuf Schema from Untrusted Source
id: 2f7b9e4d-8a1c-4e3f-b6d5-0c9a7f2e1b8d
status: experimental
description: >
    Detects Node.js processes loading protobuf definitions via reflection APIs
    (Root.load, Root.loadSync, Root.fromJSON, parse) from network or temp paths,
    which may enable Proto6 exploitation including prototype pollution to RCE
    (CVE-2026-44291), option path traversal DoS (CVE-2026-44290), and code injection
    via bytes defaults (CVE-2026-44293).
references:
    - https://thehackernews.com/2026/06/six-proto6-vulnerabilities-in.html
    - https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-75px-5xx7-5xc7
    - https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-jvwf-75h9-cwgg
author: Actioner
date: 2026/06/10
tags:
    - attack.t1059.007
logsource:
    category: process_creation
    product: linux
detection:
    selection_node:
        Image|endswith:
            - '/node'
            - '/nodejs'
    selection_protobuf_load:
        CommandLine|contains:
            - 'protobuf'
            - 'protobufjs'
            - '.proto'
    selection_untrusted_path:
        CommandLine|contains:
            - '/tmp/'
            - '/var/tmp/'
            - 'http://'
            - 'https://'
    condition: selection_node and selection_protobuf_load and selection_untrusted_path
falsepositives:
    - Development workflows loading schemas from temporary build directories
level: medium
```

### Snort: N/A

No network-level indicators suitable for Snort detection — Proto6 exploitation occurs at the application layer via schema/payload manipulation within established connections, without distinctive network signatures.

### Suricata: N/A

No network-level indicators suitable for Suricata detection — same rationale as Snort above.

### YARA: Malicious Protobuf Schema with Code Injection Payloads

Detects `.proto` files and JSON descriptors containing JavaScript code injection payloads targeting Proto6 vulnerabilities — identifies files with protobuf schema markers combined with injection strings (`require()`, `eval()`, `child_process`, `__proto__`, etc.). Scope to source code repositories and schema directories.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive: JSON descriptor with require('child_process').execSync in bytes default matched both rules. Negative: benign JSON descriptor with string/int32 fields did not match. Strings sourced from advisory-described exploitation mechanisms (Function() compilation, child_process require, __proto__ injection). FP risk: low for schema files; legitimate protobuf schemas do not contain require(), eval(), or child_process strings. The $inject9 "prototype" string could appear in comments of legitimate schemas but requires 2-of condition with another inject string. -->
```yara
rule Proto6_Malicious_Protobuf_Schema_Code_Injection
{
    meta:
        description = "Detects crafted .proto or JSON descriptor files attempting code injection via protobuf.js Proto6 vulnerabilities (CVE-2026-44291, CVE-2026-44293, CVE-2026-44295, CVE-2026-44294)"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://thehackernews.com/2026/06/six-proto6-vulnerabilities-in.html"
        severity = "high"

    strings:
        // Code injection attempts in schema names, field names, or type references
        // These patterns target CVE-2026-44295 (pbjs static output injection) and
        // CVE-2026-44291 (type name injection into Function() generated code)
        $inject1 = "require(" ascii nocase
        $inject2 = "eval(" ascii nocase
        $inject3 = "Function(" ascii nocase
        $inject4 = "child_process" ascii
        $inject5 = "process.env" ascii
        $inject6 = "process.exit" ascii
        $inject7 = "constructor[" ascii
        $inject8 = "__proto__" ascii
        $inject9 = "prototype" ascii

        // Protobuf schema markers
        $proto_syntax = "syntax" ascii
        $proto_msg = "message" ascii
        $proto_pkg = "package" ascii
        $proto_svc = "service" ascii
        $proto_enum = "enum" ascii

        // JSON descriptor markers (for reflection API attacks)
        $json_nested = "\"nested\"" ascii
        $json_fields = "\"fields\"" ascii

    condition:
        filesize < 1MB and
        (
            // Proto file with injection attempts
            (
                ($proto_syntax or $proto_msg or $proto_pkg or $proto_svc or $proto_enum) and
                2 of ($inject*)
            )
            or
            // JSON descriptor with injection attempts
            (
                ($json_nested and $json_fields) and
                2 of ($inject*)
            )
        )
}

rule Proto6_Malicious_Bytes_Default_Injection
{
    meta:
        description = "Detects crafted protobuf JSON descriptors with code injection in bytes field defaults (CVE-2026-44293)"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-66ff-xgx4-vchm"
        severity = "high"

    strings:
        $json_fields = "\"fields\"" ascii
        $json_type_bytes = "\"bytes\"" ascii
        $json_default = "\"default\"" ascii

        // Injection payloads in default values
        $payload1 = "require(" ascii
        $payload2 = "eval(" ascii
        $payload3 = "Function(" ascii
        $payload4 = "process.mainModule" ascii
        $payload5 = "child_process" ascii
        $payload6 = "execSync" ascii
        $payload7 = "spawnSync" ascii

    condition:
        filesize < 1MB and
        $json_fields and $json_type_bytes and $json_default and
        1 of ($payload*)
}
```

## Lessons Learned

The Proto6 cluster demonstrates a systemic pattern: libraries that generate and execute code from user-controlled metadata are inherently dangerous when the trust boundary for that metadata is not explicitly defined. protobuf.js's use of `new Function()` to compile encoders/decoders from schema-derived strings, combined with plain-object lookup tables vulnerable to prototype pollution, created a compound attack surface where seemingly unrelated vulnerabilities (prototype pollution in a different library) could chain into full RCE through protobufjs. The CI/CD pipeline attack vector for `pbjs` is particularly instructive — treating schema files as inert data when they are effectively code input is a common blind spot.

Organizations should adopt a "schemas are code" security model: `.proto` files and JSON descriptors that feed code-generating libraries must receive the same review, signing, and access control as source code.

## Sources

- [The Hacker News — Six Proto6 Vulnerabilities in protobuf.js](https://thehackernews.com/2026/06/six-proto6-vulnerabilities-in.html) — consolidated reporting on the Proto6 vulnerability cluster
- [GHSA-75px-5xx7-5xc7](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-75px-5xx7-5xc7) — CVE-2026-44291: prototype pollution to RCE via code generation gadget
- [GHSA-6r35-46g8-jcw9](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-6r35-46g8-jcw9) — CVE-2026-44295: code injection in pbjs static output
- [GHSA-66ff-xgx4-vchm](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-66ff-xgx4-vchm) — CVE-2026-44293: code injection via bytes field defaults
- [GHSA-jvwf-75h9-cwgg](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-jvwf-75h9-cwgg) — CVE-2026-44290: option path traversal DoS
- [GHSA-fx83-v9x8-x52w](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-fx83-v9x8-x52w) — CVE-2026-44292: per-instance prototype injection
- [GHSA-2pr8-phx7-x9h3](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-2pr8-phx7-x9h3) — CVE-2026-44294: control character DoS in field names
- [GHSA-f84p-cvgm-xgjj](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-f84p-cvgm-xgjj) — CVE-2026-42290: pbts command injection
- [GHSA-wcpc-wj8m-hjx6](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-wcpc-wj8m-hjx6) — CVE-2026-48712: unbounded Any recursion DoS
- [GHSA-jggg-4jg4-v7c6](https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-jggg-4jg4-v7c6) — CVE-2026-45740: unbounded JSON descriptor recursion
- [NVD — CVE-2026-44291](https://nvd.nist.gov/vuln/detail/CVE-2026-44291) — NIST vulnerability database entry

---
*Report generated by Actioner*
