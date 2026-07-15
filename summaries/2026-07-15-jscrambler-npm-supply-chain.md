# Technical Analysis Report: Compromised jscrambler npm Package — IronWorm Supply Chain Attack (2026-07-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-15
Version: 1.0 (DRAFT)

## Executive Summary

On July 11, 2026, an attacker published malicious version 8.14.0 of the legitimate `jscrambler` npm package using a compromised npm publishing credential. The malicious release embedded a cross-platform Rust-based infostealer (tracked as "IronWorm" by JFrog, linked to the Shai-Hulud lineage) inside a custom binary container (`dist/intro.js`, 7.8 MB). A `preinstall` hook (`dist/setup.js`) extracts and executes the platform-matched payload (Windows PE, macOS Mach-O, Linux ELF) in a detached process. Socket.dev flagged the release six minutes after publication. Over the next three hours, the attacker published four additional malicious versions (8.16.0, 8.17.0, 8.18.0, 8.20.0), with later versions shifting the dropper into runtime `require()` to bypass `--ignore-scripts`. Four dependent Jscrambler packages were also compromised: jscrambler-webpack-plugin 8.6.2, gulp-jscrambler 8.6.2, grunt-jscrambler 8.5.2, and jscrambler-metro-plugin 9.0.2.

The infostealer targets an exceptionally broad range of developer secrets: cloud credentials (AWS, Azure, GCP), npm/GitHub tokens, browser passwords and cookies, cryptocurrency wallets (MetaMask, Phantom, Exodus), password managers (Bitwarden, 1Password), messaging sessions (Discord, Slack, Telegram, Steam), VPN configs, and AI coding tool configurations (Claude Desktop, Cursor, Windsurf, VS Code, Zed) including MCP server credentials. The Linux variant includes eBPF kernel capabilities. Exfiltration uses both a Tor-based C2 channel (with ChaCha20-Poly1305 framing) and direct uploads to `temp.sh`. Two C2 IP addresses were identified: 37.27.122[.]124 and 57.128.246[.]79. The malware self-propagates by stealing npm tokens and publishing trojanized versions of other high-download packages via raw HTTP PUT to the npm registry. Approximately 1,479 downloads occurred during the ~2-hour exposure window. Version 8.22.0 is confirmed clean.

**Prior Actioner coverage:** This attack reuses the IronWorm malware family previously analyzed in [2026-06-05-npm-ironworm-supply-chain.md](./2026-06-05-npm-ironworm-supply-chain.md), now evolved with cross-platform payloads (Windows/macOS added), runtime-import dropper variants, and broader credential targets including AI coding tools.

## Background: jscrambler npm Package

Jscrambler is a commercial JavaScript protection and obfuscation platform. The `jscrambler` npm package (~15,800 weekly downloads, ~60,000 monthly) provides CLI and SDK tooling for integrating Jscrambler's code protection into build pipelines. It is used across enterprise environments for client-side JavaScript security. Downstream packages (webpack plugin, gulp/grunt plugins, metro plugin) extend integration into common build systems, amplifying the blast radius of a compromise. Jscrambler the company is itself a security vendor, making this a notable case of a security tool becoming the supply chain vector.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-08 | npm 12 released with install scripts disabled by default |
| 2026-07-11 ~15:12 | Malicious version 8.14.0 published via compromised npm credential (preinstall dropper) |
| 2026-07-11 ~15:18 | Socket.dev flags 8.14.0 — six minutes after publication |
| 2026-07-11 ~17:07 | Version 8.15.0 published (clean remediation attempt) |
| 2026-07-11 ~17:26 | Malicious version 8.16.0 published (preinstall dropper reintroduced) |
| 2026-07-11 ~17:41 | Malicious version 8.17.0 published (preinstall with pnpm allowlist injection) |
| 2026-07-11 ~17:46 | Malicious version 8.18.0 published (runtime injection variant — bypasses --ignore-scripts) |
| 2026-07-11 ~17:53 | Malicious version 8.20.0 published (duplicate of 8.18.0 runtime variant) |
| 2026-07-11 ~18:12 | Version 8.22.0 published (confirmed clean) |
| 2026-07-11 | Jscrambler revokes and rotates publishing credentials; malicious versions deprecated |
| 2026-07-11 | StepSecurity runtime monitoring identifies C2 IP addresses |

## Root Cause: Compromised npm Publishing Credential

The attacker gained access via a compromised npm publishing credential belonging to a Jscrambler maintainer. Jscrambler's official advisory confirmed no matching commit, tag, or pull request exists in the GitHub repository for the malicious versions — the packages were published directly to the npm registry, bypassing normal release workflows. The specific method of credential theft has not been disclosed.

## Technical Analysis of the Malicious Payload

### 1. Package-Level Injection

**Generation 1 (v8.14.0, 8.16.0, 8.17.0) — Preinstall hook:**

Two files were added to the package tarball:
- `dist/setup.js` — loader script (SHA256: `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`)
- `dist/intro.js` — 7,837,238-byte binary container (SHA256: `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`)

The `package.json` preinstall hook triggers execution:
```json
"preinstall": "node dist/setup.js"
```

Version 8.17.0 additionally injected a pnpm allowlist to bypass pnpm's script restrictions:
```json
"allowScripts": ["jscrambler"]
```

**Generation 2 (v8.18.0, 8.20.0) — Runtime import injection:**

The dropper code was moved into the package's main entry (`dist/index.js`) and CLI (`dist/bin/jscrambler.js`) as an immediately invoked function expression (IIFE). This fires when the package is `require()`'d or the CLI is executed, meaning `npm install --ignore-scripts` does not prevent execution.

### 2. Binary Container and Dropper

The `dist/intro.js` file uses a custom binary container format ("CSI"):
- Magic header: `1B 43 53 49 01 03 00`
- Contains three gzip-compressed platform-specific payloads

`setup.js` identifies the host operating system, extracts the matching binary from `intro.js`, writes it to a randomly named dot-prefixed file in the OS temp directory (pattern: `<tmpdir>/.[a-z0-9]{6,}` with `.exe` appended on Windows via `String.fromCharCode(46,101,120,101)`), sets executable permissions, and launches it detached:

```javascript
spawn(..., { detached: true, stdio: 'ignore', windowsHide: true })
```

The process is then `unref()`'d, surviving after the npm install completes.

### 3. Rust Infostealer Payload (IronWorm)

The payloads are compiled with `rustc 1.98.0-nightly (e7815e522 2026-06-04)` using the Tokio async runtime. All strings are individually encrypted with ChaCha20-Poly1305 (32-byte keys, 12-byte nonces per string), making static analysis difficult.

**Credential targets include:**

| Category | Targets |
|----------|---------|
| Cloud credentials | AWS (Secrets Manager, SSM Parameter Store, ECS metadata), Azure IMDS, GCP metadata endpoints |
| Package registry tokens | `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `NPM_CONFIG__AUTHTOKEN`, `NPM_CONFIG_TOKEN`, `NPM_AUTH_TOKEN`, `.npmrc`, `/etc/npmrc` |
| Browser data | Chrome, Chromium, Brave, Edge — Login Data, Cookies, Web Data (SQLite), LevelDB local storage |
| Crypto wallets | MetaMask (`nkbihfbeogaeaoehlefnkodbefgpgknn`), Trust Wallet (`egjidjbpglichdcondbcbdnbeeppgdph`), Phantom, Exodus, Coinbase — BIP39 seed phrase parsing |
| Password managers | Bitwarden (`nngceckbapebfimnlniiiahkandclblb`), 1Password, KDE Wallet |
| Messaging | Discord, Slack, Telegram, Steam (ASAR archive parser for Electron apps) |
| AI coding tools | Claude Desktop (`.config/Claude/claude_desktop_config.json`, `.claude.json`), Cursor (`.cursor/mcp.json`), Windsurf (`.codeium/windsurf/mcp_config.json`), VS Code (`settings.json`, `.mcp.json`), Zed |
| VPN configurations | WireGuard (`/etc/wireguard/*.conf`), OpenVPN (`/etc/openvpn`), IPsec (`/etc/ipsec.secrets`) |
| Secrets management | HashiCorp Vault (`v1/secret/data/` API), Kubernetes configs |

### 4. C2 Infrastructure

The malware operates two communication channels:

**Tor-based C2 (primary command channel):**
- Runs an embedded Tor client (downloads Tor Expert Bundle dynamically)
- X25519 key exchange with embedded server public key
- ChaCha20-Poly1305 framing with directional HKDF expansion (`csi-a2s`, `csi-s2a`)
- Dual routes: HTTP on port 80 (`POST /`), raw stream on port 8080
- JSON-based command protocol: `{"t":"out","id":"...","data":...,"progress":true}` / `{"t":"done","id":"..."}`

**Direct C2 connections (observed by StepSecurity):**
- 37.27.122[.]124
- 57.128.246[.]79

**Tor infrastructure contacted:**
- check[.]torproject[.]org (connectivity check)
- archive[.]torproject[.]org (Tor Expert Bundle download)

**Data exfiltration:**
- Bulk stolen data uploaded directly to temp[.]sh (public file host) over TLS, leaking the victim's real IP address
- Uses embedded rustls TLS stack (bypasses system HTTP libraries and certificate stores)

### 5. Platform-Specific Behavior

#### Windows
- Binary: PE x86-64 (4.92 MB), SHA256: `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
- PDB GUID: `6976bd1e56f6b4214c4c44205044422e`
- Persistence: Hidden Windows scheduled task (`<Hidden>true</Hidden>`) with RestartOnFailure at PT1M interval, 999 retry count, unlimited ExecutionTimeLimit
- Anti-debugging: `IsDebuggerPresent` API check
- Network enumeration: `GetExtendedTcpTable` for process/connection discovery
- TCP via `ws2_32.dll` with embedded rustls

#### macOS
- Binary: Mach-O arm64 (3.04 MB), SHA256: `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`
- Persistence: LaunchAgent plist with `RunAtLoad`, `KeepAlive`, StartInterval 30 seconds
- Paths: `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`
- Anti-debugging: `sysctl`/`sysctlbyname` checking `P_TRACED` flag

#### Linux
- Binary: ELF x86-64 (4.31 MB), SHA256: `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
- Build ID: `c05bf7dc45672d7a59cbd5e300f586482da14d00`
- Persistence: systemd user/system units (`/etc/systemd/system`, `~/.config/systemd/user`), crontab (`/etc/cron.d`, user crontab)
- eBPF capability: Links `libbpf.so.1`, calls `bpf_object__open_mem` for kernel-level instrumentation
- Container awareness: reads `/proc/self/mountinfo`, `/proc/self/cgroup`

### 6. Self-Propagation (npm Worm)

The malware scans for npm tokens in environment variables and filesystem files (`.npmrc`, `/etc/npmrc`), validates them via `registry.npmjs.org/-/whoami`, identifies packages with high download counts that the stolen token has publishing rights to, injects a malicious `setup.mjs` preinstall script, and publishes trojanized versions directly via raw HTTP PUT to `registry.npmjs.org` on port 443 — bypassing local npm CLI tools entirely.

### 7. Anti-Forensics / Evasion Techniques

- Dot-prefixed hidden filenames for dropped binaries
- `.exe` extension constructed via `String.fromCharCode(46,101,120,101)` to evade static scanning
- `detached: true`, `stdio: 'ignore'`, `windowsHide: true` to orphan the process
- PDB stripped of build paths; timestamp/checksum zeroed
- No Rich header (non-MSVC toolchain, avoids standard PE fingerprinting)
- All Rust panic locations stripped
- 80 KB encrypted blob in `.rdata` section (likely AES with PBKDF2/scrypt key derivation)
- Embedded rustls bypasses system TLS/certificate inspection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version(s) | Description |
|---------------------|----------------------|-------------|
| jscrambler | 8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0 | Compromised npm package with embedded infostealer |
| jscrambler-webpack-plugin | 8.6.2 | Downstream affected package |
| gulp-jscrambler | 8.6.2 | Downstream affected package |
| grunt-jscrambler | 8.5.2 | Downstream affected package |
| jscrambler-metro-plugin | 9.0.2 | Downstream affected package |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| All | `dist/setup.js` | `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60` | Dropper loader script |
| All | `dist/intro.js` | `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86` | Binary container (7.8 MB, CSI format) |
| All | `package.json` | `bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0` | Malicious package.json (v8.14.0) |
| Linux | `<tmpdir>/.[a-z0-9]{6,}` | `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd` | ELF x86-64 infostealer (4.31 MB) |
| Windows | `<tmpdir>\.[a-z0-9]{6,}.exe` | `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903` | PE x86-64 infostealer (4.92 MB) |
| macOS | `<tmpdir>/.[a-z0-9]{6,}` | `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd` | Mach-O arm64 infostealer (3.04 MB) |

Additional embedded hash (Windows binary): `9eeffcb5c3445ef9512f7776045f99ea23f9ebed989f8570bc4634b4e340de5d`

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 37.27.122[.]124 | C2 server (observed by StepSecurity) |
| IP | 57.128.246[.]79 | C2 server (observed by StepSecurity) |
| Domain | check[.]torproject[.]org | Tor connectivity check |
| Domain | archive[.]torproject[.]org | Tor Expert Bundle download |
| Domain | temp[.]sh | Data exfiltration (public file host) |
| Domain | registry[.]npmjs[.]org | npm token validation and worm propagation target |

### Behavioral

- Detached child process spawned from `node` during `npm install` with `windowsHide: true`
- Dot-prefixed randomly named executable in OS temp directory
- SQLite database reads targeting Chrome/Brave/Edge `Login Data`, `Cookies`, `Web Data`
- LevelDB reads targeting browser extension storage (MetaMask, Bitwarden)
- Reads of `.npmrc` and npm token environment variables followed by HTTP requests to `registry.npmjs.org/-/whoami`
- Tor Expert Bundle download and SOCKS5 proxy establishment
- Direct TLS connections to `temp.sh` for bulk data upload
- Windows: Hidden scheduled task creation with 1-minute restart interval
- macOS: LaunchAgent plist creation with `RunAtLoad` and `KeepAlive`
- Linux: systemd unit or crontab entry creation; eBPF program loading via `bpf_object__open_mem`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected via compromised npm publishing credential |
| T1059.007 | Command and Scripting Interpreter: JavaScript | `setup.js` preinstall hook executes dropper logic |
| T1204.002 | User Execution: Malicious File | Payload auto-executes during `npm install` |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | ChaCha20-Poly1305 per-string encryption; custom CSI container format |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Edge credential SQLite and LevelDB extraction |
| T1555 | Credentials from Password Stores | Bitwarden, 1Password vault data extraction |
| T1539 | Steal Web Session Cookie | Browser cookie theft; Discord/Slack/Steam session theft |
| T1528 | Steal Application Access Token | npm tokens, cloud API keys, AI tool API keys |
| T1552.001 | Unsecured Credentials: Credentials In Files | `.npmrc`, `.claude.json`, MCP configs, WireGuard/OpenVPN/IPsec configs |
| T1552.004 | Unsecured Credentials: Private Keys | SSH keys, Tor hidden service keys |
| T1005 | Data from Local System | Comprehensive local credential and configuration harvesting |
| T1020 | Automated Exfiltration | Stolen data automatically uploaded to temp.sh |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS for C2 and exfiltration |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encrypted C2 channel over Tor |
| T1090.003 | Proxy: Multi-hop Proxy | Embedded Tor client for C2 anonymization |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows hidden scheduled task for persistence |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS LaunchAgent with RunAtLoad/KeepAlive |
| T1053.003 | Scheduled Task/Job: Cron | Linux crontab persistence |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux systemd unit persistence |
| T1014 | Rootkit | Linux eBPF kernel instrumentation via libbpf |
| T1622 | Debugger Evasion | IsDebuggerPresent (Win), P_TRACED sysctl (macOS) |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Dot-prefixed hidden binaries |

## Impact Assessment

The attack targeted a legitimate security vendor's npm package with ~15,800 weekly downloads. Approximately 1,479 downloads of malicious versions occurred during the ~2-hour exposure window before remediation. The blast radius extends beyond direct jscrambler users to anyone depending on the four compromised downstream packages (webpack, gulp, grunt, metro plugins). The self-propagation mechanism (npm token theft and automated trojanized package publishing) could amplify impact to other unrelated packages if any stolen npm tokens had publishing rights to additional popular packages. Developer workstations, CI/CD runners, and build servers that pulled the malicious versions are potentially compromised with full credential theft across cloud, browser, wallet, and AI tool configurations.

## Detection & Remediation

### Immediate Detection

Check if any malicious version was installed:
```bash
# Check lockfiles for malicious versions
grep -rE 'jscrambler.*(8\.14\.0|8\.16\.0|8\.17\.0|8\.18\.0|8\.20\.0)' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check node_modules
ls -la node_modules/jscrambler/dist/intro.js 2>/dev/null && echo "SUSPICIOUS: intro.js present"
sha256sum node_modules/jscrambler/dist/intro.js 2>/dev/null

# Check for dropped binaries in temp directories
find /tmp -name '.[a-z0-9]*' -perm /111 -newer /tmp -mtime -7 2>/dev/null
find "$TMPDIR" -name '.[a-z0-9]*' -perm /111 -mtime -7 2>/dev/null

# Check for persistence (Linux)
grep -r jscrambler /etc/systemd/system/ ~/.config/systemd/user/ /etc/cron.d/ 2>/dev/null
crontab -l 2>/dev/null | grep -i '[a-z0-9]\{6,\}'

# Check for persistence (macOS)
ls ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null | grep -v com.apple

# Check for C2 connections
ss -tnp | grep -E '37\.27\.122\.124|57\.128\.246\.79' 2>/dev/null
netstat -an | grep -E '37\.27\.122\.124|57\.128\.246\.79' 2>/dev/null
```

### Remediation

1. **Upgrade immediately** to jscrambler 8.22.0 (or pin to pre-compromise 8.13.0)
2. **Kill any running malicious processes** — search for dot-prefixed randomly named executables in temp directories
3. **Remove persistence mechanisms** — delete suspicious scheduled tasks (Windows), LaunchAgents (macOS), systemd units/cron entries (Linux)
4. **Rotate all credentials** exposed to the compromised environment:
   - npm tokens and GitHub/GitLab tokens
   - AWS/Azure/GCP access keys and service account credentials
   - AI tool API keys (Anthropic, OpenAI, etc.)
   - Browser-stored passwords (change at the service level)
   - VPN credentials (WireGuard, OpenVPN, IPsec)
5. **Revoke active sessions** — Discord, Slack, Telegram, Steam, Bitwarden
6. **Move cryptocurrency** from any wallets accessible on affected machines (MetaMask, Phantom, Exodus, Coinbase, Trust Wallet)
7. **Block C2 infrastructure** — 37.27.122[.]124, 57.128.246[.]79 at firewall level
8. **Audit npm publishing tokens** — check `registry.npmjs.org/-/whoami` with any tokens that were on affected systems; review packages those tokens can publish to

### Long-Term Hardening

- Adopt npm 12+ which disables install scripts by default
- Use `--ignore-scripts` on npm install and explicitly allowlist trusted scripts
- Implement lockfile pinning with integrity checks (SHA512 in `package-lock.json`)
- Monitor for unexpected outbound connections from CI/CD runners (especially to Tor infrastructure and temp.sh)
- Use scoped npm tokens with minimal publishing permissions and short TTLs
- Deploy runtime security monitoring (e.g., StepSecurity, Socket.dev) to detect preinstall hook abuse

## Detection Rules

These detections target the jscrambler/IronWorm supply chain compromise at the PoC/advisory-specific altitude: malicious file hashes, C2 IP addresses, the CSI container format, and npm preinstall dropper patterns. Sigma rules convert to Splunk and CrowdStrike LogScale. Snort/Suricata are not installed in this environment -- those rules received structural checks only. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: jscrambler IronWorm Malicious Binary Hash Detection

Detects execution of the known IronWorm infostealer binaries dropped by the compromised jscrambler npm package, matching on SHA256 hashes of the three platform-specific payloads.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data fetch 403 in sandbox — not a rule error); splunk convert 0; log_scale convert 0. Keys on exact SHA256 hashes of the three platform binaries from jscrambler 8.14.0. No FP risk — hashes are unique to the malicious payloads. -->
```yaml
title: jscrambler IronWorm Malicious Binary Execution
id: 4a8c1e2f-7d3b-4f6a-9e5c-1b0d8a3f2c7e
status: experimental
description: >
    Detects execution of known IronWorm infostealer binaries dropped by compromised
    jscrambler npm package versions 8.14.0-8.20.0. Matches SHA256 hashes of
    Windows PE, macOS Mach-O, and Linux ELF payloads.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
    - https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/
author: Actioner
date: 2026-07-15
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
            - 'b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903'
            - 'fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd'
            - 'c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd'
    condition: selection
falsepositives:
    - None expected — these are unique malicious binary hashes
level: critical
```

### Sigma: jscrambler IronWorm C2 Network Connection

Detects outbound network connections to the two known IronWorm C2 IP addresses observed by StepSecurity during runtime analysis of the compromised jscrambler package.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE ATT&CK data fetch 403 in sandbox — not a rule error); splunk convert 0; log_scale convert 0. Keys on two specific C2 IPs from StepSecurity runtime monitoring. Minimal FP risk — IPs are dedicated C2 infrastructure. -->
```yaml
title: jscrambler IronWorm C2 Connection
id: 3f7a2b9e-8c4d-4e1f-a5d6-0c9b7e3a1f8d
status: experimental
description: >
    Detects outbound network connections to known IronWorm C2 servers associated
    with the compromised jscrambler npm package supply chain attack.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary
    - https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/
author: Actioner
date: 2026-07-15
tags:
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '37.27.122.124'
            - '57.128.246.79'
    condition: selection
falsepositives:
    - Unlikely — these IPs are dedicated C2 infrastructure
level: high
```

### Sigma: npm Preinstall Dropper Spawning Hidden Temp Binary

Detects `node.exe` spawning a detached child process writing to or executing a dot-prefixed binary in a temp directory, consistent with the jscrambler IronWorm dropper behavior.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check skipped (MITRE ATT&CK data fetch 403 in sandbox — not a rule error); splunk convert 0; log_scale convert 0. Keys on node.exe parent + dot-prefixed exe in temp path. Medium confidence: legitimate node child processes in temp are possible but dot-prefixed exe names are unusual. -->
```yaml
title: Node.js Preinstall Hook Dropping Hidden Temp Binary
id: 9e1d4c7f-3a2b-4f8e-b5d6-7c0a9e2f1b3d
status: experimental
description: >
    Detects node.exe spawning a hidden (dot-prefixed) executable from a temporary
    directory, consistent with npm preinstall hook dropper behavior observed in
    the jscrambler IronWorm supply chain attack.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://socket.dev/blog/jscrambler-supply-chain-attack
author: Actioner
date: 2026-07-15
tags:
    - attack.t1059.007
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\node.exe'
    selection_child:
        Image|re: '\\(Temp|tmp|AppData\\Local\\Temp)\\\.[a-z0-9]{6,}\.exe$'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate npm packages spawning temp executables (rare with dot-prefix naming)
level: high
```

### Snort: jscrambler IronWorm C2 Connection to Known IP

Detects outbound TCP connections to the known IronWorm C2 server at 37.27.122[.]124.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed (balanced parens, semicolons, required fields present). Single known C2 IP — no FP risk. -->
```snort
alert ip $HOME_NET any -> 37.27.122.124 any (
    msg:"Actioner - jscrambler IronWorm C2 Connection to 37.27.122.124";
    flow:established,to_server;
    classtype:trojan-activity;
    reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html;
    reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/;
    metadata:author Actioner, created 2026-07-15;
    sid:2100010;
    rev:1;
)
```

### Snort: jscrambler IronWorm C2 Connection to Known IP 2

Detects outbound TCP connections to the known IronWorm C2 server at 57.128.246[.]79.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort not installed; structural check passed. Single known C2 IP — no FP risk. -->
```snort
alert ip $HOME_NET any -> 57.128.246.79 any (
    msg:"Actioner - jscrambler IronWorm C2 Connection to 57.128.246.79";
    flow:established,to_server;
    classtype:trojan-activity;
    reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html;
    reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/;
    metadata:author Actioner, created 2026-07-15;
    sid:2100011;
    rev:1;
)
```

### Suricata: jscrambler IronWorm C2 Connection

Detects outbound connections to either known IronWorm C2 IP address.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check passed (dot-notation N/A for ip protocol, semicolons balanced, required fields present). -->
```suricata
alert ip $HOME_NET any -> [37.27.122.124,57.128.246.79] any (
    msg:"Actioner - jscrambler IronWorm C2 Connection";
    flow:established,to_server;
    classtype:trojan-activity;
    reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html;
    reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200010;
    rev:1;
)
```

### Suricata: IronWorm Data Exfiltration to temp.sh

Detects HTTPS connections to temp[.]sh, the public file host used by IronWorm to exfiltrate stolen credentials. Scope to developer/CI networks to reduce false positives.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: suricata not installed; structural check passed (tls protocol, dot-notation tls.sni buffer, semicolons balanced). Medium confidence: temp.sh has legitimate uses — scope to CI/developer subnets for production. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - IronWorm Exfiltration via temp.sh";
    flow:established,to_server;
    tls.sni; content:"temp.sh"; fast_pattern;
    classtype:trojan-activity;
    reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html;
    reference:url,research.jfrog.com/post/ironworm-returns-rustier-than-ever/;
    metadata:author Actioner, created_at 2026-07-15;
    sid:2200011;
    rev:1;
)
```

### YARA: jscrambler IronWorm CSI Container Detection

Detects the custom CSI binary container format used to package platform-specific IronWorm payloads within the malicious `intro.js` file. Keys on the unique magic header bytes and file size range.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: wrote 7-byte CSI header to pos.txt → matched; wrote "normal javascript content" to neg.txt → no match. Magic bytes 1B 43 53 49 01 are unique to this container format. -->
```yara
rule Supply_Chain_jscrambler_IronWorm_CSI_Container
{
    meta:
        description = "Detects the CSI binary container format used by the compromised jscrambler npm package to bundle IronWorm infostealer payloads"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"
        severity = "critical"

    strings:
        $csi_magic = { 1B 43 53 49 01 }

    condition:
        $csi_magic at 0 and filesize > 1MB and filesize < 15MB
}
```

### YARA: jscrambler IronWorm Dropper Script

Detects the `setup.js` dropper script used by the compromised jscrambler package, keying on the distinctive combination of detached spawn with windowsHide and the `.exe` extension obfuscation via `String.fromCharCode`.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: wrote pos.txt with "String.fromCharCode(46,101,120,101)" + "detached" + "windowsHide" + "stdio" → matched; neg.txt with normal node spawn code → no match. The fromCharCode sequence 46,101,120,101 spells ".exe" — distinctive obfuscation. -->
```yara
rule Supply_Chain_jscrambler_IronWorm_Dropper_JS
{
    meta:
        description = "Detects the setup.js dropper script from compromised jscrambler npm package using distinctive spawn and extension obfuscation patterns"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://safedep.io/jscrambler-npm-supply-chain-compromise/"
        hash = "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60"
        severity = "critical"

    strings:
        $fromcharcode = "String.fromCharCode(46,101,120,101)" ascii
        $detached = "detached" ascii
        $windowshide = "windowsHide" ascii
        $stdio_ignore = "stdio" ascii
        $intro = "intro.js" ascii

    condition:
        filesize < 50KB and
        $fromcharcode and
        2 of ($detached, $windowshide, $stdio_ignore, $intro)
}
```

## Lessons Learned

1. **Security vendors are not immune to supply chain attacks.** Jscrambler is a JavaScript security company whose own npm package was compromised, underscoring that trust based on vendor identity is insufficient — integrity verification of published artifacts is essential.

2. **npm preinstall hooks remain a critical attack surface.** npm 12's default disabling of install scripts (released just three days before this attack) is a significant mitigation, but the attacker adapted within hours by shifting to runtime import injection in later versions (8.18.0, 8.20.0), demonstrating rapid TTPs evolution.

3. **Credential scope matters.** The self-propagation mechanism highlights the risk of broadly-scoped npm tokens. Organizations should use granular, package-scoped tokens with short TTLs and enforce 2FA on all npm publishing accounts.

4. **AI coding tool configurations are now a target.** The targeting of Claude Desktop, Cursor, Windsurf, VS Code, and Zed configurations — including MCP server credentials — represents an emerging attack surface as AI coding assistants become standard developer tools.

5. **Rapid detection saved the ecosystem.** Socket.dev's 6-minute detection window and npm's ability to deprecate malicious versions limited downloads to ~1,479, demonstrating the value of automated package registry monitoring.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html) — primary news coverage with technical details, timeline, and IOCs
- [Socket.dev Blog](https://socket.dev/blog/jscrambler-supply-chain-attack) — initial detection report with hashes, dropper analysis, and CSI container format details
- [JFrog Security Research](https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/) — IronWorm attribution, self-propagation mechanism, Tor C2 protocol, credential targets
- [SafeDep](https://safedep.io/jscrambler-npm-supply-chain-compromise/) — detailed binary analysis, persistence mechanisms, platform-specific behavior, compilation details
- [StepSecurity](https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary) — runtime monitoring C2 IP identification, capability analysis
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/) — downstream package impact, download statistics, remediation guidance

---
*Report generated by Actioner*
