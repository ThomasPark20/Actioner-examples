# Technical Analysis Report: RedC2 4.0 npm Supply Chain Attack (2026-08-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-28
Version: 1.1

## Executive Summary

Fourteen trojanized npm packages disguised as calendar and streak-calculation utilities have been discovered delivering RedC2 4.0's RedShell Linux implant, an AI-augmented backdoor with autonomous post-exploitation capabilities. The packages function as advertised, providing legitimate date-math features, while an embedded ELF binary executes silently upon module import -- no install hooks or explicit function calls required. A single transitive dependency anywhere in the graph is sufficient for compromise. The implant connects to a hardcoded C2 at 217.60.77[.]63 over TLS, establishing persistence via cron jobs, systemd user services, bashrc modifications, and XDG autostart entries. Its capabilities span credential harvesting (SSH keys, browser credentials), SOCKS5 proxying for network pivoting, in-memory ELF execution via memfd_create, and an LLM-driven command orchestration layer ("Red Agent") that translates natural-language instructions into beacon commands. The campaign was disclosed by TrendAI researcher Aliakbar Zahravi on August 21, 2026. The threat actor "MarlboroMan" has marketed RedC2 4.0 on Hack Forums since early June 2026.

## Background: npm Supply Chain and RedC2 Framework

npm is the default package manager for Node.js, hosting over 2 million packages. Supply chain attacks targeting npm exploit the trust developers place in dependency trees -- a malicious package introduced as a direct or transitive dependency can execute arbitrary code on developer machines and CI/CD pipelines.

RedC2 is a commercial command-and-control framework sold on cybercrime forums by a threat actor operating under the alias "MarlboroMan." Version 2.0 appeared in August 2025, version 3.0 in January 2026, and version 4.0 was advertised in early June 2026 at a price of $99.99 USD. The framework is marketed as cross-platform (Windows, macOS, Linux) and "built for evasion." Prior supply chain campaigns with infrastructure overlaps have targeted Mastra (144 packages) and Axios npm packages, with suspected North Korean attribution.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 2025 | RedC2 v2.0 released by "MarlboroMan" |
| January 2026 | RedC2 v3.0 sold on cybercrime forums |
| Early June 2026 | RedC2 v4.0 advertised on Hack Forums |
| ~August 2026 | 14 trojanized npm packages published to npm registry |
| August 21, 2026 | TrendAI publicly discloses the campaign |

## Root Cause: Trojanized npm Package Dependencies

The attacker published 14 npm packages containing functional date-math code alongside embedded ELF binaries. The packages bypass the `--ignore-scripts` protection because they do not use lifecycle hooks (preinstall, postinstall). Instead, the payload executes through an asynchronous IIFE (Immediately Invoked Function Expression) in `dist/index.mjs` that runs at module load time. Any import -- direct or transitive -- triggers execution. The binary is framed as a "native math accelerator" to avoid suspicion during code review.

## Technical Analysis of the Malicious Payload

### 1. Trojanized npm Loader (dist/index.mjs)

The entry file `dist/index.mjs` re-exports legitimate date helper functions while launching the implant via an async IIFE evaluated at module load. The loader:
1. Locates the bundled binary in `dist/` or `dist/internal/`
2. Verifies the binary's SHA-256 hash for integrity
3. Sets executable permissions (`chmod +x`)
4. Spawns the binary as a detached background process

Binary filenames vary across packages: `math-core.bin`, `math-calc.bin`, `calc-math.dat`, `calc-cache.bin`, `calc.bin`, `calc-mapping.bin`.

### 2. RedShell Linux Implant

The RedShell implant is a statically compiled ELF binary (SHA-256: `4537b1189ce419f1a595cf47216c03f80e9170ce80dad8d9227a1e52f9cb3466`). Upon execution it:
1. Generates an installation ID and writes it to `~/.config/.rsvc`
2. Collects system information (hostname, username, OS, architecture, network interfaces)
3. Computes a SHA-256 hash of concatenated system properties as a unique machine identifier
4. Establishes persistence through four mechanisms (see below)
5. Initiates C2 communication

**Persistence mechanisms:**
- **Cron job:** Adds `@reboot` entry to the user crontab
- **Bashrc modification:** Appends execution line to `~/.bashrc`
- **Systemd user service:** Creates `~/.config/systemd/user/svc-update.service`
- **XDG autostart:** Creates `~/.config/autostart/system-updater.desktop`

### 3. C2 Infrastructure

The implant uses a multi-port architecture on a single hardcoded IP:

| Port | Protocol | Function |
|------|----------|----------|
| 8792 | TCP/TLS 1.2+ | Primary C2 beacon (command/response) |
| 8888 | HTTP | File upload channel |
| 8060 | HTTP | Data exfiltration channel |

Traffic on port 8792 uses a custom three-round XOR and ROR1 encryption routine layered over TLS. Certificate verification is disabled (`SSL_VERIFY_NONE`), making the connection susceptible to interception but resistant to certificate pinning blocks.

The implant also communicates with:
- `litterbox[.]catbox[.]moe` (port 443) -- legitimate file-sharing service used for exfiltration
- `api[.]ipify[.]org` -- used for external IP address discovery

The Red Agent AI component is accessible via a `/_ra_` endpoint on the C2 server, providing LLM-backed orchestration of post-exploitation tasks.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

The RedShell Linux beacon provides:
- **Interactive shell:** Reverse shell via `/bin/sh`
- **System discovery:** Hostname, OS, network interfaces, running processes
- **Credential harvesting:** SSH key extraction, browser credential theft, database detection
- **Fileless execution:** In-memory ELF and shellcode execution via `memfd_create` syscall
- **Network pivoting:** SOCKS5 proxy listener on all IPv4 interfaces (`/socks start <port>`)
- **TCP port forwarding:** Tunnel traffic through compromised host
- **Bulk file exfiltration:** Archive and upload via ports 8060/8888

**Temporary file patterns** used during operations:
- `/tmp/.sc_XXXXXX` -- shellcode staging
- `/tmp/.elf_XXXXXX` -- ELF payload staging
- `/tmp/.dl_XXXXXX.tar.gz` -- download staging
- `/tmp/.ft_XXXXXX.tar.gz` -- file transfer staging
- `/tmp/.st_XXXXXX` -- general staging
- `/tmp/.sk_XXXXXX` -- SSH key staging
- `/tmp/.cr_XXXXXX` -- credential staging

### 5. Anti-Forensics / Evasion Techniques

- No install hooks used -- bypasses `--ignore-scripts` npm flag
- Functional package code provides cover for the embedded binary
- Binary framed as "native math accelerator"
- Detached process execution to avoid parent-process termination
- TLS with disabled certificate verification
- Custom XOR/ROR1 encryption layer on C2 traffic
- Temporary files use dot-prefix for hidden file convention on Linux

## Indicators of Compromise (IOCs)

> **Defanging Convention:** IOCs in prose and tables use defanged notation (`[.]` replacing dots) to prevent accidental resolution. Detection rules and remediation scripts use live (refanged) values so they can be copied directly into tooling.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| streak-metrics-math | 1.0.0, 1.0.1 | Trojanized date/streak utility with embedded RedShell |
| kit-map-vim | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-map-cache | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-map-kit | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| map-streak-kit | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-cache-map | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-calc-metrics | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-calc-math | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-math-abz | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-metricsaz | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-math-metrics | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-metricazbd | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-metricsazb | 1.0.0 | Trojanized date/streak utility with embedded RedShell |
| streak-kit-map | 1.0.0 | Trojanized date/streak utility with embedded RedShell |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | dist/math-core.bin | 4537b1189ce419f1a595cf47216c03f80e9170ce80dad8d9227a1e52f9cb3466 | RedShell Linux implant binary |
| Linux | dist/math-calc.bin | 969ef45e5e1c382d421580b8306aff0abf0c4d302f0af7091ac44ce70a92f789 | RedShell variant |
| Linux | dist/calc-math.dat | 1c5b97ad2212de1046eab1ef66ff5e7e21ca93c918f54f3369c06c64271f2d82 | RedShell variant |
| Linux | dist/calc-cache.bin | 0b9aef51d5ec55d69fb52ada41377ced07c6cff0cad09174390f49081d439b14 | RedShell variant |
| Linux | dist/calc.bin | f71ffec658eb31fb2292f83e02f9451acb6a6d70f1b7988d9ccc308286b288b9 | RedShell variant |
| Linux | dist/calc-mapping.bin | 69fe4881065cf4a5e30cbaeaf30c16fd891d5bfc5a6263e518fb3ef2e23d0889 | RedShell variant |
| Linux | ~/.config/.rsvc | -- | Installation identifier file |
| Linux | ~/.config/systemd/user/svc-update.service | -- | Persistence systemd service |
| Linux | ~/.config/autostart/system-updater.desktop | -- | Persistence XDG autostart entry |
| Linux | /tmp/.sc_XXXXXX | -- | Shellcode staging temp file |
| Linux | /tmp/.elf_XXXXXX | -- | ELF payload staging temp file |
| Linux | /tmp/.dl_XXXXXX.tar.gz | -- | Download staging temp file |
| Linux | /tmp/.ft_XXXXXX.tar.gz | -- | File transfer staging temp file |
| Linux | /tmp/.st_XXXXXX | -- | General staging temp file |
| Linux | /tmp/.sk_XXXXXX | -- | SSH key staging temp file |
| Linux | /tmp/.cr_XXXXXX | -- | Credential staging temp file |

**Additional file hashes from IOC list (npm package tarballs / loader scripts):**

| Hash (SHA256) | Description |
|---------------|-------------|
| 7fcc2baa9d65c190a07add27f84ad0644ac77a62eeb5a49062bad290133e2cd6 | Malicious package component |
| 5537e187a3a1c1cdbd598246079910232add2b0097d15fba9aaf8004b92384c1 | Malicious package component |
| 9e8a5128cea298d21b8e3b24102d48cd3b256bb7f229e75c854ccfbe8ed4fb76 | Malicious package component |
| e9a4d708f22170e7fe307593af7a5ae5feea06907ade075a3fd8a0c116ed707a | Malicious package component |
| 3ca67aa27a7544cfbc8a6b8b73628d6217560cd5f6e13fb167985689ab7bbff0 | Malicious package component |
| 7a5221c06710393fc3893ef8b697bf8a2a24c63b3b8fde77433a9516127cba4d | Malicious package component |
| 3ad446777c04146aa878643fd286094363a3ed74865a1644a39c76079d72960b | Malicious package component |
| 24e51473f03947dcb8ea8898d93067bbd284850dde33ef983b568b113a632fa2 | Malicious package component |
| c753b7cbd2ffb89ad51dc6f48714204df8955d000520174329dd3785aede4562 | Malicious package component |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 217.60.77[.]63:8792 | Primary C2 beacon (TLS) |
| IP | 217.60.77[.]63:8888 | File upload channel (HTTP) |
| IP | 217.60.77[.]63:8060 | Data exfiltration channel (HTTP) |
| Domain | litterbox[.]catbox[.]moe | Legitimate file-sharing service abused for exfiltration |
| Domain | api[.]ipify[.]org | External IP discovery service |

### Behavioral

- Process execution of `.bin` or `.dat` files from `node_modules/` subdirectories
- Creation of hidden files matching `/tmp/\.(sc|elf|dl|ft|st|sk|cr)_` pattern
- Outbound TLS connections on port 8792 with disabled certificate verification
- SOCKS5 proxy listeners spawned on compromised hosts
- Cron `@reboot` entries referencing binaries in user-writable directories
- Modification of `~/.bashrc` to add execution of non-standard binaries

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | 14 trojanized npm packages published to npm registry |
| T1204.002 | User Execution: Malicious File | Module import triggers payload -- no explicit user action beyond `npm install` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Interactive reverse shell via `/bin/sh` |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence via `~/.config/systemd/user/svc-update.service` |
| T1547.013 | Boot or Logon Autostart Execution: XDG Autostart Entries | Persistence via `~/.config/autostart/system-updater.desktop` |
| T1053.003 | Scheduled Task/Job: Cron | Persistence via `@reboot` crontab entry |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence via `~/.bashrc` modification |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over TLS (port 8792), HTTP (ports 8060, 8888) |
| T1041 | Exfiltration Over C2 Channel | Data exfiltration via port 8060 and litterbox[.]catbox[.]moe |
| T1555 | Credentials from Password Stores | Browser credential theft |
| T1552.004 | Unsecured Credentials: Private Keys | SSH key harvesting |
| T1090.001 | Proxy: Internal Proxy | SOCKS5 proxy for network pivoting |
| T1572 | Protocol Tunneling | TCP port forwarding through compromised host |
| T1620 | Reflective Code Loading | In-memory ELF execution via `memfd_create` |
| T1036 | Masquerading | Binary disguised as "native math accelerator" |
| T1074.001 | Data Staged: Local Data Staging | Temporary file staging in /tmp (.sc_, .elf_, .dl_, .ft_, .st_, .sk_, .cr_ prefixes) |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Installation ID written to hidden file ~/.config/.rsvc |
| T1105 | Ingress Tool Transfer | Download and staging of additional payloads |

## Impact Assessment

**Breadth:** Any Node.js project or CI/CD pipeline that installed one of the 14 packages (or had one as a transitive dependency) is potentially compromised. The packages were functional utilities, increasing the likelihood of adoption.

**Depth:** Full Linux host compromise -- the implant provides interactive shell access, credential harvesting, network pivoting, and in-memory code execution. The SOCKS5 proxy capability extends the blast radius to internal networks accessible from the compromised host.

**Stealth:** High. The attack bypasses `--ignore-scripts`, uses no install hooks, delivers functional package code, and operates through a detached background process with TLS-encrypted C2 communications.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any of the 14 malicious packages are installed
npm ls streak-metrics-math kit-map-vim streak-map-cache streak-map-kit \
  map-streak-kit streak-cache-map streak-calc-metrics streak-calc-math \
  streak-math-abz streak-metricsaz streak-math-metrics streak-metricazbd \
  streak-metricsazb streak-kit-map 2>/dev/null

# Check for RedShell persistence artifacts
ls -la ~/.config/.rsvc 2>/dev/null
ls -la ~/.config/systemd/user/svc-update.service 2>/dev/null
ls -la ~/.config/autostart/system-updater.desktop 2>/dev/null
crontab -l 2>/dev/null | grep -E '\.(bin|dat)$'

# Check for RedShell temp file artifacts
ls -la /tmp/.sc_* /tmp/.elf_* /tmp/.dl_* /tmp/.ft_* /tmp/.st_* /tmp/.sk_* /tmp/.cr_* 2>/dev/null

# Check for active connections to C2
ss -tnp | grep '217.60.77.63'
netstat -tnp 2>/dev/null | grep -E ':(8792|8888|8060)'

# Check for SOCKS5 proxy listeners
ss -tlnp | grep -v '127.0.0.1\|::1' | grep LISTEN
```

### Remediation

1. **Containment:** Immediately isolate any host with confirmed IOCs from the network
2. **Remove malicious packages:** `npm uninstall <package-name>` for all 14 packages; verify `package-lock.json` is clean
3. **Kill running implant:** Identify and terminate processes running from `node_modules/` with `.bin` or `.dat` extensions
4. **Remove persistence:**
   - Remove `@reboot` crontab entries referencing suspicious binaries
   - Delete `~/.config/systemd/user/svc-update.service` and reload systemd (`systemctl --user daemon-reload`)
   - Delete `~/.config/autostart/system-updater.desktop`
   - Remove added lines from `~/.bashrc`
   - Delete `~/.config/.rsvc`
5. **Rotate credentials:** Rotate all SSH keys, browser-stored passwords, and API tokens accessible from compromised hosts
6. **Audit network:** Check for SOCKS5 proxy listeners and unexpected TCP tunnels; review firewall logs for connections to 217.60.77[.]63
7. **Scan for lateral movement:** Assess any hosts reachable from the compromised system via SOCKS5 pivoting

### Long-Term Hardening

- Implement npm package allowlisting or lockfile auditing in CI/CD pipelines
- Use `npm audit` and third-party SCA tools (Socket, Snyk) to scan for supply chain risks
- Monitor for binary files within `node_modules/` directories -- legitimate npm packages rarely contain ELF binaries
- Deploy endpoint detection on developer workstations and CI runners
- Enforce network segmentation to limit the impact of SOCKS5 pivoting from compromised dev machines

## Detection Rules

These detections target the RedC2 4.0 / RedShell Linux implant delivered via trojanized npm packages. PoC/advisory-specific altitude; all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Snort and Suricata rules are structurally validated only (compilers not installed). Standalone rule files are provided alongside this report in `rules/`.

### Sigma: RedC2 RedShell C2 Communication to Known Infrastructure

Detects outbound connections to the hardcoded RedC2 C2 IP (217.60.77.63) on its specific operational ports (8792, 8888, 8060).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. sigma check failed due to proxy blocking MITRE ATT&CK data fetch (environment issue, not rule issue). IOC-anchored on hardcoded C2 IP+port combination; will age out if infrastructure rotates. -->

```yaml
title: RedC2 RedShell C2 Communication to Known Infrastructure
id: 00e61bcd-c9b2-40d1-8ffe-67f2225a6144
status: experimental
description: >
    Detects outbound network connections to the hardcoded RedC2 4.0 C2
    infrastructure IP on ports used by the RedShell Linux implant (8792 C2,
    8888 upload, 8060 exfiltration).
references:
    - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp: '217.60.77.63'
    selection_ports:
        DestinationPort:
            - 8792
            - 8888
            - 8060
    condition: selection_ip and selection_ports
falsepositives:
    - Legitimate services hosted on this IP (unlikely given the specific port combination)
level: high
```

### Sigma: RedShell Linux Persistence via Systemd User Service

Detects creation of the specific systemd user service (`svc-update.service`) and XDG autostart entry (`system-updater.desktop`) used by RedShell for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Keys on distinctive file paths published by TrendAI. Low FP: the service/desktop names are specific to RedShell. Requires file event logging (Sysmon for Linux or auditd). -->

```yaml
title: RedShell Linux Persistence via Systemd User Service
id: 0e7d0d9e-8fdd-4838-85da-c95f43ceed1b
status: experimental
description: >
    Detects creation of systemd user service files and XDG autostart entries
    consistent with RedShell Linux implant persistence mechanisms. The implant
    creates svc-update.service and system-updater.desktop in user config paths.
references:
    - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1543.002
    - attack.t1547.013
logsource:
    category: file_event
    product: linux
detection:
    selection_systemd:
        TargetFilename|endswith: '/.config/systemd/user/svc-update.service'
    selection_autostart:
        TargetFilename|endswith: '/.config/autostart/system-updater.desktop'
    condition: selection_systemd or selection_autostart
falsepositives:
    - Legitimate software using identical service/desktop entry names (unlikely)
level: high
```

### Sigma: RedShell Implant Binary Execution from npm Package Directory

Detects execution of the known RedShell binary filenames (math-core.bin, calc-cache.bin, etc.) characteristic of the trojanized npm package campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: fixed tautological condition (selection_binaries OR (npm AND binaries) -> binaries AND npm_path) to enforce npm-path scope. -->
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Keys on 6 specific binary filenames published by TrendAI. calc.bin alone is somewhat generic but is OR'd with highly specific names, maintaining overall precision. Requires Linux process creation logging. -->

```yaml
title: RedShell Implant Binary Execution from npm Package Directory
id: aa08d6f8-0628-4509-bcb7-2a082627afc6
status: experimental
description: >
    Detects execution of RedShell implant binaries (math-core.bin, math-calc.bin,
    calc-math.dat, calc-cache.bin, calc.bin, calc-mapping.bin) launched from
    node_modules directories, consistent with the trojanized npm package campaign.
references:
    - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_binaries:
        Image|endswith:
            - '/math-core.bin'
            - '/math-calc.bin'
            - '/calc-math.dat'
            - '/calc-cache.bin'
            - '/calc.bin'
            - '/calc-mapping.bin'
    selection_npm_path:
        Image|contains: 'node_modules'
    condition: selection_binaries and selection_npm_path
falsepositives:
    - Legitimate npm packages with identical binary names (extremely unlikely)
level: critical
```

### Sigma: RedShell Temporary File Creation Pattern

Detects creation of temporary files matching the RedShell naming convention (`.sc_`, `.elf_`, `.dl_`, `.ft_`, `.st_`, `.sk_`, `.cr_` prefixes) in `/tmp`.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: replaced attack.t1059.004 + attack.t1005 with attack.t1074.001 (Local Data Staging). -->
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Regex-based; medium confidence because short prefixes could theoretically collide with other software, though the dot-prefix plus underscore pattern is distinctive. -->

```yaml
title: RedShell Temporary File Creation Pattern in /tmp
id: dd975aff-d67b-413b-82eb-244601894ad7
status: experimental
description: >
    Detects creation of temporary files matching the RedShell naming convention
    (.sc_, .elf_, .dl_, .ft_, .st_, .sk_, .cr_ prefixes) in /tmp, used during
    shellcode execution, ELF loading, file transfer, and credential staging.
references:
    - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|re: '^/tmp/\.(sc|elf|dl|ft|st|sk|cr)_[A-Za-z0-9]{6}'
    condition: selection
falsepositives:
    - Other software creating temp files with similar short prefixes (low probability given the dot-prefix convention)
level: medium
```

### Sigma: RedShell Installation ID File Creation

Detects creation of the RedShell installation identifier file at `~/.config/.rsvc`, written during initial implant installation.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: replaced attack.t1036 with attack.t1564.001 (Hidden Files and Directories). -->
<!-- audit: sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Highly specific path; .rsvc is not a known legitimate config file. Requires file event logging on Linux. -->

```yaml
title: RedShell Installation ID File Creation
id: 4d4143c8-aaef-43c1-8595-1721120acbe9
status: experimental
description: >
    Detects creation of the RedShell installation identifier file at
    ~/.config/.rsvc, written during initial implant installation to
    track compromised hosts.
references:
    - https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant
    - https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
author: Actioner
date: 2026-08-28
tags:
    - attack.t1564.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/.config/.rsvc'
    condition: selection
falsepositives:
    - Legitimate software creating a .rsvc file in user config directory (highly unlikely)
level: high
```

### Snort: RedC2 RedShell C2 Beacon to Known Infrastructure

Detects TCP connections to the hardcoded RedC2 C2 server on the primary beacon port (8792) with TLS handshake bytes.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural validation only. Rule keys on destination IP + port + TLS record header bytes. Will not fire if C2 infrastructure rotates. -->

```snort
alert tcp $HOME_NET any -> 217.60.77.63 8792 (msg:"Actioner - RedC2 RedShell C2 Beacon to Known Infrastructure"; flow:established, to_server; content:"|16 03|"; depth:2; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created 2026-08-28; sid:2100010; rev:1;)
```

### Snort: RedC2 RedShell Data Exfiltration to Known C2

Detects TCP connections to the RedC2 exfiltration port (8060).
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural validation only. Pure IP+port rule; high confidence because it is anchored on a known-malicious endpoint. -->

```snort
alert tcp $HOME_NET any -> 217.60.77.63 8060 (msg:"Actioner - RedC2 RedShell Data Exfiltration to Known C2"; flow:established, to_server; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created 2026-08-28; sid:2100011; rev:1;)
```

### Snort: RedC2 RedShell File Upload to Known C2

Detects TCP connections to the RedC2 file upload port (8888).
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural validation only. Pure IP+port rule. -->

```snort
alert tcp $HOME_NET any -> 217.60.77.63 8888 (msg:"Actioner - RedC2 RedShell File Upload to Known C2"; flow:established, to_server; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created 2026-08-28; sid:2100012; rev:1;)
```

### Suricata: RedC2 RedShell C2 Beacon to Known Infrastructure

Detects TLS connections to the hardcoded RedC2 C2 server on port 8792.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural validation only. Dot-notation verified; semicolons balanced; sid in 2200000+ range. -->

```suricata
alert tcp $HOME_NET any -> 217.60.77.63 8792 (msg:"Actioner - RedC2 RedShell C2 Beacon to Known Infrastructure"; flow:established,to_server; content:"|16 03|"; depth:2; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created_at 2026-08-28; sid:2200010; rev:1;)
```

### Suricata: RedC2 RedShell Data Exfiltration to Known C2

Detects TCP connections to the RedC2 exfiltration port (8060).
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural validation only. -->

```suricata
alert tcp $HOME_NET any -> 217.60.77.63 8060 (msg:"Actioner - RedC2 RedShell Data Exfiltration to Known C2"; flow:established,to_server; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created_at 2026-08-28; sid:2200011; rev:1;)
```

### Suricata: RedC2 RedShell File Upload to Known C2

Detects TCP connections to the RedC2 file upload port (8888).
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural validation only. -->

```suricata
alert tcp $HOME_NET any -> 217.60.77.63 8888 (msg:"Actioner - RedC2 RedShell File Upload to Known C2"; flow:established,to_server; classtype:trojan-activity; reference:url,www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant; metadata:author Actioner, created_at 2026-08-28; sid:2200012; rev:1;)
```

<!-- revision: dropped Suricata litterbox.catbox.moe rule (sid:2200013). Generic rule on legitimate service with no RedShell-specific content match; unacceptable FP rate. -->

### YARA: RedShell Linux Implant Detection

Detects the RedShell Linux ELF implant via combination of persistence paths, temporary file patterns, C2 IP, and capability strings.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on ELF magic + combination of persistence paths, temp file naming patterns, C2 IP, and capability strings (memfd_create, /socks start). Requires 2+ persist strings with C2 IP, or 3+ temp patterns with command string, ensuring specificity. hash meta from TrendAI IOC list. -->

```yara
rule Malware_RedShell_Linux_Implant
{
    meta:
        description = "Detects RedShell Linux implant (RedC2 4.0) via characteristic strings from the trojanized npm supply chain campaign"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant"
        hash = "4537B1189CE419F1A595CF47216C03F80E9170CE80DAD8D9227A1E52F9CB3466"
        severity = "critical"

    strings:
        $persist1 = "svc-update.service" ascii
        $persist2 = "system-updater.desktop" ascii
        $persist3 = ".config/.rsvc" ascii

        $tmp1 = "/tmp/.sc_" ascii
        $tmp2 = "/tmp/.elf_" ascii
        $tmp3 = "/tmp/.dl_" ascii
        $tmp4 = "/tmp/.ft_" ascii
        $tmp5 = "/tmp/.sk_" ascii
        $tmp6 = "/tmp/.cr_" ascii

        $cmd1 = "/socks start" ascii
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "memfd_create" ascii

        $c2_ip = "217.60.77.63" ascii

        $net1 = "litterbox.catbox.moe" ascii
        $net2 = "api.ipify.org" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($c2_ip and 2 of ($persist*)) or
            (3 of ($tmp*) and 1 of ($cmd*)) or
            ($c2_ip and $cmd3 and 1 of ($tmp*)) or
            ($c2_ip and 1 of ($net*) and 1 of ($persist*))
        )
}
```

## Lessons Learned

1. **Lifecycle hooks are not the only threat vector:** This campaign demonstrates that `--ignore-scripts` is insufficient protection against npm supply chain attacks. Code execution at module load time via top-level async IIFEs bypasses this defense entirely. Organizations must audit the actual code of dependencies, not just their hook declarations.

2. **Functional malware is harder to detect:** Unlike many supply chain attacks that deliver empty or broken packages, these packages provided legitimate date-math utilities. Code review that stops at "does it do what it says?" misses the embedded binary payload.

3. **AI-augmented C2 lowers the operator skill bar:** The Red Agent LLM component allows less sophisticated operators to execute complex post-exploitation workflows using natural language, effectively democratizing advanced tradecraft.

4. **Developer machines are high-value pivot points:** The SOCKS5 proxy capability turns a compromised developer workstation into a gateway to internal networks, CI/CD systems, cloud credentials, and production infrastructure.

## Sources

- [TrendAI Security Blog - Prompting the Payload: RedC2 AI-Powered Linux Implant](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant) -- primary technical analysis by Aliakbar Zahravi
- [The Hacker News - 14 Trojanized npm Packages Drop RedC2 4.0 Linux Backdoor](https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html) -- secondary reporting
- [CyberPress - RedC2 AI-Powered Linux Malware Delivered Through Malicious npm Packages](https://cyberpress.org/redc2-linux-malware/) -- additional IOC context
- [GBHackers - RedC2 Turns Compromised Linux Machines Into SOCKS5 Proxies](https://gbhackers.com/redc2-4-0-linux-implant/) -- SOCKS5 pivoting detail
- [TrendAI IOC File](https://cdn.sanity.io/media-libraries/mllBRzE9QpZ8/files/containers/3IO0zVVPitH4vZwuDAnoNTvmakh/redc2-iocs3.txt) -- published IOC list

---
*Report generated by Actioner*
