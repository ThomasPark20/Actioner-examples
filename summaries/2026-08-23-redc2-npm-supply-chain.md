# Technical Analysis Report: RedC2 4.0 npm Supply Chain Attack (2026-08-23)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-23
Version: DRAFT 1.0

## Executive Summary

Fourteen trojanized npm packages masquerading as calendar and streak utility libraries have been discovered delivering the RedC2 4.0 "RedShell" Linux backdoor. The packages are functional date utilities that conceal a bundled ELF implant disguised as a native math accelerator; when imported (no install hook required), the entry file (`dist/index.mjs`) marks the binary executable and launches it as a detached background process. RedC2 4.0 is a commercial C2 framework sold for $99.99 by threat actor "MarlboroMan" via the "Red Offsec" clearnet site, and features an LLM-driven command layer ("Red Agent") that translates natural-language prompts into post-exploitation commands. The campaign exhibits infrastructure overlaps with prior North Korean-linked supply chain attacks targeting Mastra and Axios npm packages. All 14 packages were published at version 1.0.0 or 1.0.1 and have been flagged by the OpenSSF Malicious Packages project.

## Background: npm Supply Chain and RedC2 Framework

npm is the default package manager for Node.js, hosting over 2 million packages. Supply chain attacks on npm exploit the trust model whereby a single `npm install` can pull in arbitrary transitive dependencies, each of which can execute code at import time. RedC2 is a commercial offensive framework under active development since at least August 2025 (v2.0), with v3.0 sold in January 2026 and v4.0 advertised on Hack Forums in early June 2026. The v4.0 release introduced the "RedShell" Linux beacon and the "Red Agent" AI command execution component.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 2025 | RedC2 v2.0 released |
| January 2026 | RedC2 v3.0 sold |
| Early June 2026 | MarlboroMan advertises RedC2 v4.0 on Hack Forums |
| Prior to 2026-08-21 | 14 trojanized packages published to npm registry |
| 2026-08-21 | The Hacker News publishes disclosure article |
| 2026-08-21 | Packages flagged by OpenSSF Malicious Packages project (MAL-2026-13223 et al.) |

## Root Cause: Supply Chain Injection via Typosquatting

The attacker published 14 new npm packages (not hijacked existing packages) with names using combinations of common utility terms ("streak", "map", "kit", "cache", "calc", "metrics", "math", "vim"). These are not typosquats of a single popular package but rather plausible-sounding utility names designed to attract developers searching for calendar/streak functionality. The packages provide genuine date utility functionality, lowering suspicion during code review.

## Technical Analysis of the Malicious Payload

### 1. Package Delivery and Loader Mechanism

Each package bundles a compiled ELF binary in the `dist/` or `dist/internal/` directory alongside a JavaScript entry point at `dist/index.mjs`. The entry file re-exports legitimate date helper functions and simultaneously locates the bundled binary, marks it executable (via `chmod +x`), and launches it as a detached background process. No `postinstall` script or explicit install hook is required -- a single `import` or `require()` call anywhere in the dependency graph, including transitive imports, triggers payload execution.

The binary name varies across packages to avoid simple filename-based detection:
- `math-core.bin`
- `math-calc.bin`
- `calc-math.dat`
- `calc-cache.bin`
- `calc.bin`
- `calc-mapping.bin`

### 2. RedShell Linux Implant

The dropped binary is the RedShell Linux beacon, introduced in RedC2 v4.0. Upon execution, it gathers system information, establishes communication with the C2 server, and enters a command-processing loop. Key capabilities include:

- **Interactive shell access** via `/bin/sh`
- **SSH key harvesting** (reads `~/.ssh/authorized_keys`, `~/.ssh/id_rsa`, and related key files)
- **Browser credential theft** (targets Chrome, Chromium, and Firefox login data stores)
- **ELF in-memory execution** (loads additional payloads without writing to disk)
- **SOCKS5 proxying** for tunneling traffic through the compromised host
- **Network pivoting** for lateral movement to adjacent hosts
- **Persistence mechanisms** (specific methods not disclosed)
- **Data collection and exfiltration** over the C2 channel

### 3. C2 Infrastructure

RedC2 4.0 is a full-featured C2 framework supporting:

- Terminal access and file transfer
- Staged payload delivery
- Multi-beacon operation and network visualization
- Host-to-host tunneling
- In-memory execution of BOFs (Beacon Object Files), .NET assemblies, and shellcode
- "RedC2 EXT" command-line extension for additional modules

**No specific C2 domains, IPs, or network indicators were disclosed in the available reporting.** The framework communicates with a remote Windows or Linux server; the clearnet "Red Offsec" website is used for sales, not C2.

### 4. AI-Assisted Command Generation ("Red Agent")

RedC2 4.0 includes an LLM-driven component called "Red Agent," characterized by Red Offsec as an "AI-powered command execution system specialized for penetration testing." Operators input natural-language prompts (e.g., "harvest SSH keys from all reachable hosts"), and the framework translates them into actionable beacon command sequences. This lowers the skill barrier for post-exploitation operations.

### 5. Anti-Forensics / Evasion Techniques

- **Legitimate functionality**: Packages export working date utilities, passing cursory code review
- **No install hook**: Payload executes on module import, not via `postinstall` script, evading npm audit warnings for lifecycle scripts
- **Detached process**: The implant runs as a detached background process, surviving the parent Node.js process exit
- **Binary disguise**: Filenames mimic native math/acceleration libraries (`.bin`, `.dat` extensions)
- **Framework-level evasion**: RedC2 is described as "built for evasion" with the "latest developments and techniques in the offensive security field"

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| streak-metrics-math | 1.0.0, 1.0.1 | Trojanized date/streak utility; drops RedShell implant |
| kit-map-vim | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-map-cache | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-map-kit | 1.0.0 | Trojanized utility; drops RedShell implant |
| map-streak-kit | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-cache-map | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-calc-metrics | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-calc-math | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-math-abz | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-metricsaz | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-math-metrics | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-metricazbd | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-metricsazb | 1.0.0 | Trojanized utility; drops RedShell implant |
| streak-kit-map | 1.0.0 | Trojanized utility; drops RedShell implant |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `node_modules/<package>/dist/math-core.bin` | Not disclosed | RedShell ELF implant variant |
| Linux | `node_modules/<package>/dist/math-calc.bin` | Not disclosed | RedShell ELF implant variant |
| Linux | `node_modules/<package>/dist/calc-math.dat` | Not disclosed | RedShell ELF implant variant |
| Linux | `node_modules/<package>/dist/calc-cache.bin` | Not disclosed | RedShell ELF implant variant |
| Linux | `node_modules/<package>/dist/calc.bin` | Not disclosed | RedShell ELF implant variant |
| Linux | `node_modules/<package>/dist/calc-mapping.bin` | Not disclosed | RedShell ELF implant variant |
| Any | `node_modules/<package>/dist/index.mjs` | Not disclosed | Trojan loader; re-exports date helpers, launches implant |

### Network

| Type | Value | Context |
|------|-------|---------|
| N/A | No network indicators disclosed | C2 domains/IPs not published in available reporting |

### Behavioral

- Node.js process (`node`) spawns `chmod +x` on a `.bin` or `.dat` file within a `node_modules/*/dist/` path
- Node.js process spawns a detached child process executing a binary from `node_modules/*/dist/`
- Binary initiates outbound connection to C2 server (specific protocol/port unknown)
- Binary reads SSH key files (`~/.ssh/id_rsa`, `~/.ssh/authorized_keys`)
- Binary reads browser credential stores (Chrome `Login Data`, Firefox `logins.json`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | 14 trojanized npm packages published to public registry |
| T1204.002 | User Execution: Malicious File | Payload executes on module import without explicit user action beyond installing the package |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | RedShell spawns interactive `/bin/sh` sessions |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Binaries named as math accelerators (math-core.bin, calc-math.dat) |
| T1222.002 | File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification | Loader uses `chmod +x` to mark implant executable |
| T1106 | Native API | Loader uses Node.js `child_process.spawn` with detached option |
| T1005 | Data from Local System | SSH key harvesting, browser credential theft |
| T1552.004 | Unsecured Credentials: Private Keys | Harvests SSH private keys from `~/.ssh/` |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Targets Chrome, Chromium, Firefox credential stores |
| T1090.001 | Proxy: Internal Proxy | SOCKS5 proxy capability for traffic tunneling |
| T1570 | Lateral Tool Transfer | Network pivoting capability for host-to-host movement |

## Impact Assessment

The 14 packages were published at version 1.0.0/1.0.1, indicating they are new packages (not hijacked popular libraries). No download count data has been disclosed. The attack primarily targets Linux development environments and CI/CD systems where Node.js dependencies are installed. The impact is severe for any developer who installed these packages: the attacker gains persistent shell access, credential theft capability, and a network pivot point. The suspected North Korean nexus (infrastructure overlap with Mastra/Axios campaigns) elevates concern, as DPRK-linked actors have previously used supply chain attacks for revenue generation and espionage.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any of the 14 trojanized packages are installed in your project
for pkg in streak-metrics-math kit-map-vim streak-map-cache streak-map-kit \
  map-streak-kit streak-cache-map streak-calc-metrics streak-calc-math \
  streak-math-abz streak-metricsaz streak-math-metrics streak-metricazbd \
  streak-metricsazb streak-kit-map; do
  if [ -d "node_modules/$pkg" ]; then
    echo "ALERT: Trojanized package found: $pkg"
  fi
done

# Check for the known implant binary names in node_modules
find node_modules -name "math-core.bin" -o -name "math-calc.bin" \
  -o -name "calc-math.dat" -o -name "calc-cache.bin" \
  -o -name "calc.bin" -o -name "calc-mapping.bin" 2>/dev/null

# Check for suspicious detached processes spawned from node_modules
ps aux | grep -E "(math-core|math-calc|calc-math|calc-cache|calc-mapping)\.bin"

# Check package-lock.json / yarn.lock for any of the malicious packages
grep -E "(streak-metrics-math|kit-map-vim|streak-map-cache|streak-map-kit|map-streak-kit|streak-cache-map|streak-calc-metrics|streak-calc-math|streak-math-abz|streak-metricsaz|streak-math-metrics|streak-metricazbd|streak-metricsazb|streak-kit-map)" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
```

### Remediation

1. **Kill active implant processes**: `pkill -f "math-core.bin\|math-calc.bin\|calc-math.dat\|calc-cache.bin\|calc.bin\|calc-mapping.bin"`
2. **Remove the malicious packages**: `npm uninstall <package-name>` for each identified package
3. **Audit and rotate credentials**:
   - Rotate all SSH keys on the affected host (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.)
   - Remove any unauthorized entries from `~/.ssh/authorized_keys`
   - Reset browser-stored passwords for Chrome, Chromium, and Firefox
4. **Check for persistence**: Inspect crontabs, systemd services, `.bashrc`/`.profile`, and `~/.config/autostart/` for unauthorized entries
5. **Assess lateral movement**: Review network logs for SOCKS5 proxy activity or unusual internal connections originating from the compromised host
6. **Rebuild CI/CD environments**: If the package was installed in a CI/CD pipeline, treat the build environment as compromised and rebuild from clean images

### Long-Term Hardening

- Use `npm audit` and supply chain security tools (Socket.dev, Snyk, npm audit signatures) to flag new/unknown dependencies
- Pin dependency versions and use lockfiles; review dependency changes in pull requests
- Restrict or disable npm lifecycle scripts (`--ignore-scripts`) where feasible
- Run builds in isolated, ephemeral containers to limit the blast radius of supply chain compromises
- Monitor for anomalous process creation from Node.js processes in development and CI/CD environments

## Detection Rules

These detections target the RedC2 4.0 npm supply chain campaign at PoC/advisory-specific altitude. The Sigma rules cover process-level indicators (backdoor binary execution, loader chmod behavior, malicious package installation); the YARA rules target the trojan loader and ELF implant at the file level. Network rules (Snort/Suricata) are not applicable -- no C2 network indicators were disclosed. Compiles does not equal fires -- verify against your telemetry.

### Sigma: RedC2 RedShell Backdoor Binary Execution from npm Package

Detects execution of the specific backdoor binary names (math-core.bin, math-calc.bin, calc-math.dat, etc.) dropped by the trojanized packages.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. Keys on six distinct binary names unlikely to appear in legitimate software. No pipeline mapping available for generic linux process_creation. -->

```yaml
title: RedC2 RedShell Backdoor Binary Execution from npm Package
id: 7a3c1e8f-4d2b-4f96-b5a7-9e0d3c6f8b12
status: experimental
description: >
    Detects execution of known RedC2 4.0 RedShell backdoor binaries dropped by
    trojanized npm packages masquerading as calendar/streak utilities. The binaries
    are bundled in dist/ directories with names like math-core.bin, calc-math.dat.
references:
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-23
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_binary:
        Image|endswith:
            - '/math-core.bin'
            - '/math-calc.bin'
            - '/calc-math.dat'
            - '/calc-cache.bin'
            - '/calc.bin'
            - '/calc-mapping.bin'
    condition: selection_binary
falsepositives:
    - Legitimate math acceleration libraries with identical binary names (unlikely)
level: high
```

### Sigma: Node.js Process Spawning chmod on Binary in node_modules dist Directory

Detects a Node.js parent process running chmod +x on a binary file within a node_modules dist directory, consistent with the RedC2 loader mechanism.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. Matches the loader pattern (node -> chmod +x -> dist/*.bin) but chmod in node_modules can occur with legitimate native addons, hence medium confidence. -->

```yaml
title: Node.js Process Spawning chmod on Binary in node_modules dist Directory
id: 2f8e5b1a-c3d7-49e8-a6f0-1d4b7c9e2a35
status: experimental
description: >
    Detects a Node.js process making a binary executable via chmod within a
    node_modules package dist directory, consistent with the RedC2 4.0 npm
    supply chain attack where the loader marks the bundled implant executable
    before launching it as a detached background process.
references:
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-23
tags:
    - attack.t1195.002
    - attack.t1204.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/nodejs'
    selection_chmod:
        Image|endswith: '/chmod'
        CommandLine|contains|all:
            - '+x'
            - 'node_modules'
    selection_target:
        CommandLine|contains:
            - '/dist/'
            - '.bin'
            - '.dat'
    condition: selection_parent and selection_chmod and selection_target
falsepositives:
    - npm packages with legitimate native binary addons using chmod in postinstall
level: medium
```

### Sigma: Installation of Known Trojanized RedC2 npm Packages

Detects npm/yarn/pnpm install commands referencing any of the 14 known malicious package names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk 0, log_scale 0. Exact match on 14 known-malicious package name strings in package manager command lines. Zero expected false positives -- these are not legitimate package names. -->

```yaml
title: Installation of Known Trojanized RedC2 npm Packages
id: 9c4d6e2f-a1b8-4357-8d9e-5f0c3a7b1e64
status: experimental
description: >
    Detects npm install commands referencing one of the 14 known trojanized
    packages that deliver the RedC2 4.0 RedShell Linux backdoor. These packages
    masquerade as calendar/streak utility libraries.
references:
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-23
tags:
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection_npm:
        Image|endswith:
            - '/npm'
            - '/npx'
            - '/yarn'
            - '/pnpm'
        CommandLine|contains:
            - 'streak-metrics-math'
            - 'kit-map-vim'
            - 'streak-map-cache'
            - 'streak-map-kit'
            - 'map-streak-kit'
            - 'streak-cache-map'
            - 'streak-calc-metrics'
            - 'streak-calc-math'
            - 'streak-math-abz'
            - 'streak-metricsaz'
            - 'streak-math-metrics'
            - 'streak-metricazbd'
            - 'streak-metricsazb'
            - 'streak-kit-map'
    condition: selection_npm
falsepositives:
    - None expected - these are known malicious package names
level: critical
```

### YARA: RedC2 RedShell npm Trojan Loader

Detects the trojanized npm package loader pattern: presence of known implant binary names alongside Node.js child_process execution primitives and package name strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on constructed positive (package.json + loader with streak-metrics-math, math-core.bin, spawn, chmod, child_process); quiet on benign date utility. Condition requires convergence of binary names with execution primitives or package names, reducing FP risk. -->

```yara
rule Malware_RedC2_RedShell_NPM_Loader
{
    meta:
        description = "Detects the trojanized npm package loader (dist/index.mjs) that re-exports date helpers and launches a bundled RedC2 RedShell implant binary as a detached background process"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html"
        severity = "critical"

    strings:
        $bin1 = "math-core.bin" ascii
        $bin2 = "math-calc.bin" ascii
        $bin3 = "calc-math.dat" ascii
        $bin4 = "calc-cache.bin" ascii
        $bin5 = "calc-mapping.bin" ascii

        $exec1 = "chmod" ascii
        $exec2 = "spawn" ascii
        $exec3 = "detached" ascii
        $exec4 = "execSync" ascii
        $exec5 = "child_process" ascii

        $streak1 = "streak-metrics" ascii
        $streak2 = "streak-map" ascii
        $streak3 = "streak-calc" ascii
        $streak4 = "streak-cache" ascii
        $streak5 = "streak-kit" ascii
        $streak6 = "kit-map-vim" ascii

    condition:
        filesize < 5MB and
        (
            (1 of ($bin*) and 2 of ($exec*)) or
            (1 of ($bin*) and 1 of ($streak*)) or
            (2 of ($streak*) and 1 of ($exec*))
        )
}
```

### YARA: RedC2 RedShell ELF Implant

Detects the RedShell Linux ELF implant based on ELF header, capability strings (shell, SSH key paths, browser credentials), and RedC2/RedShell identifiers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. No real sample available for fire test -- rule relies on published capability descriptions (shell, SSH key harvesting, browser credential theft, SOCKS5). Condition requires ELF header + convergence of RedC2/RedShell identifier with capability strings OR capability strings with credential theft strings. Medium confidence because string set is derived from reported behavior, not reversed binary. -->

```yara
rule Malware_RedC2_RedShell_ELF_Implant
{
    meta:
        description = "Detects RedC2 4.0 RedShell Linux ELF implant based on characteristic capability strings for interactive shell, credential theft, and C2 communication"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html"
        severity = "critical"

    strings:
        $elf = { 7F 45 4C 46 }

        $s1 = "/bin/sh" ascii
        $s2 = ".ssh/authorized_keys" ascii
        $s3 = ".ssh/id_rsa" ascii
        $s4 = "SOCKS5" ascii nocase
        $s5 = "RedShell" ascii nocase
        $s6 = "RedC2" ascii nocase
        $s7 = "red_agent" ascii nocase
        $s8 = "beacon" ascii nocase

        $cred1 = "Login Data" ascii
        $cred2 = "chrome" ascii nocase
        $cred3 = "firefox" ascii nocase
        $cred4 = "chromium" ascii nocase

    condition:
        $elf at 0 and
        filesize < 50MB and
        (
            (2 of ($s*) and 1 of ($cred*)) or
            ($s5 and 2 of ($s*)) or
            ($s6 and 2 of ($s*))
        )
}
```

### Snort: N/A

No C2 network indicators (domains, IPs, URLs, ports, or protocol patterns) were disclosed in the available reporting. Snort rules cannot be generated at specific altitude without concrete network IOCs. Re-run if C2 infrastructure details are published.

### Suricata: N/A

No C2 network indicators (domains, IPs, URLs, JA3 hashes, or TLS certificate fingerprints) were disclosed in the available reporting. Suricata rules cannot be generated at specific altitude without concrete network IOCs. Re-run if C2 infrastructure details are published.

## Lessons Learned

1. **Import-time execution bypasses install hook auditing**: npm's `--ignore-scripts` flag and lifecycle script warnings do not protect against packages that execute code at module import time via standard `import`/`require()`. Defense must extend to runtime monitoring of process creation by Node.js.

2. **Functional packages are harder to detect**: Unlike typical malicious packages that contain only a payload, these packages provide genuine date utility functionality. Automated scanners that flag packages with no legitimate code will miss this pattern; behavioral analysis (binary file presence, detached process spawning) is required.

3. **Commercial C2 frameworks lower the barrier to entry**: RedC2's $99.99 price point and AI-assisted command generation make sophisticated post-exploitation accessible to less-skilled operators. The "Red Agent" LLM component eliminates the need for deep C2 framework knowledge.

4. **Supply chain attacks increasingly serve as initial access for state-aligned actors**: The suspected North Korean infrastructure overlap with prior Mastra/Axios campaigns suggests nation-state adoption of npm supply chain attacks as a scalable initial access vector.

## Sources

- [The Hacker News - 14 Trojanized npm Packages Drop RedC2 4.0 Linux Backdoor With AI-Assisted C2](https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html) -- primary reporting on the campaign, package names, and technical details
- [InfoSec Today - 14 Trojanized npm Packages Drop RedC2 4.0 Linux Backdoor](https://www.infosectoday.io/14-trojanized-npm-packages-drop-redc2-4-0-linux-backdoor-with-ai-assisted-c2) -- corroborating coverage with package version details
- [Socket.dev - streak-math-metrics Package Security Analysis](https://socket.dev/npm/package/streak-math-metrics) -- package-level security analysis (access restricted)
- [Cybersecurity Tracker - Malicious Packages](https://cybersecuritytracker.ai/malicious-packages/) -- OpenSSF MAL advisory identifiers (MAL-2026-13223, MAL-2026-13459, MAL-2026-13519, MAL-2026-13628, MAL-2026-13632, MAL-2026-13679, MAL-2026-13915)

---
*Report generated by Actioner*
