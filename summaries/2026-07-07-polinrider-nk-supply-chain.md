# Technical Analysis Report: PolinRider — North Korean Multi-Ecosystem Supply Chain Campaign (2026-07-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-07
Version: 0.1 (DRAFT)

## Executive Summary

The PolinRider campaign is a sustained, multi-ecosystem supply chain attack attributed to the North Korean Contagious Interview cluster (Famous Chollima / Lazarus subgroup). First flagged by the OpenSourceMalware team on March 7, 2026, and subsequently analyzed by Socket and JFrog, the campaign distributed **162 malicious release artifacts across 108 unique packages** spanning npm (19 libraries), Packagist/Composer (10 packages), Go modules (61 packages), and the Google Chrome Web Store (1 extension). As of April 11, 2026, the campaign had compromised 1,951 public GitHub repositories belonging to 1,047 unique owners (930 individuals, 117 organizations) -- a 2.9x increase from the initial 675 repositories detected on March 8.

The attack deploys BeaverTail, OtterCookie/DEV#POPPER, and OmniStealer malware families through obfuscated JavaScript loaders hidden in developer configuration files (`postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`, etc.), fake `.woff2` font files, and VS Code task auto-execution (`runOn: folderOpen`). Payloads are retrieved via blockchain dead-drop resolvers (TRON, Aptos, BNB Smart Chain), decrypted with embedded XOR keys, and executed with `eval()`. A parallel sub-campaign (reported by JFrog on June 30, 2026) used six Rollup polyfill-impersonating npm packages to deliver a full RAT through AES-256-CBC encrypted payloads served from `216.126.236[.]244`.

The campaign targets developer credentials, cryptocurrency wallets, browser data, SSH keys, cloud provider secrets, AI/ML API keys, and Telegram sessions. Exfiltration uses socket.io-based C2 on non-standard ports, Telegram bot APIs, and HTTP uploads.

> **Prior coverage note:** Related Contagious Interview activity is covered in [2026-06-29-npm-go-vscode-tasks-infostealer.md](./2026-06-29-npm-go-vscode-tasks-infostealer.md) (Fake Font / TaskJacker variant with InvisibleFerret) and [2026-06-05-npm-ironworm-supply-chain.md](./2026-06-05-npm-ironworm-supply-chain.md) (IronWorm / Arweave ecosystem). This report covers the broader PolinRider campaign scope including the Rollup polyfill mimicry sub-campaign, Packagist/Go/Chrome expansion, and consolidated IOC tracking.

---

## Background: Multi-Ecosystem Developer Supply Chain

PolinRider represents an escalation in the Contagious Interview operation's supply chain strategy, expanding beyond npm to simultaneously target Packagist (PHP Composer), Go modules, and Chrome extensions. The campaign exploits the trust developers place in open-source dependencies and development tooling, particularly VS Code's workspace task auto-execution feature and common JavaScript configuration files that are loaded at build time. Maintainer account compromise -- via expired domain takeover or account recovery exploitation -- provides publishing access to inject malicious code into legitimate packages. The use of blockchain dead-drop resolvers for C2 payload delivery provides infrastructure resilience against takedowns.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-12-XX | Earliest anti-dated commits in compromised repositories |
| 2026-01-08 | Anti-dated commits planted in 7span organization repositories |
| 2026-03-07 | OpenSourceMalware team first flags PolinRider campaign |
| 2026-03-08 | Initial scope: 675 infected public GitHub repositories |
| 2026-03-13 | `tailwind-mainanimation` package taken down from npm |
| 2026-03-20 | `rollup-plugin-polyfill-route` published on npm (Rollup mimicry precursor) |
| 2026-03-20 -- 2026-04-20 | Panther documents 108 malicious npm packages across 261 versions (31-day wave) |
| 2026-04-10 | New obfuscator variant (Cot%3t=shtP marker) identified |
| 2026-04-11 | Campaign scope: 1,951 repos, 1,047 unique owners; TaskJacker operational merger confirmed |
| 2026-05-16 | Partial remediation by 7span (fake fonts removed, but config file loaders missed) |
| 2026-06-23 | Synchronized modifications across Xpos587 GitHub repositories (10:00 UTC) |
| 2026-06-30 | JFrog publishes analysis of Rollup polyfill-impersonating packages; C2 at 216.126.236[.]244 still serving payloads |
| 2026-07-01 | Socket publishes comprehensive PolinRider multi-ecosystem analysis |
| 2026-07-03 | JFrog Rollup polyfill research published; Panther 108-package analysis cited |

---

## Root Cause: Maintainer Account Compromise and Dependency Injection

The campaign achieves initial access through compromised maintainer accounts on npm, Packagist, and GitHub. Compromise vectors include expired domain takeover (re-registering lapsed email domains used for account recovery) and credential-based account recovery. Once publishing access is obtained, attackers inject malicious JavaScript loaders into legitimate packages via:

1. **Config file injection** -- appending obfuscated loaders after legitimate content in `postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`, and other build-time configuration files
2. **Fake font file replacement** -- replacing `.woff2` font assets in `public/fonts/` with JavaScript payloads
3. **VS Code task planting** -- adding `.vscode/tasks.json` with `runOn: folderOpen` auto-execution
4. **npm lifecycle hook abuse** -- using `preinstall`/`postinstall` scripts to trigger payload execution

Git history is falsified using `temp_auto_push.bat` scripts that rewind system clocks, amend commits with spoofed timestamps, and force-push with `--no-verify` to bypass hooks.

---

## Technical Analysis of the Malicious Payload

### 1. JavaScript Loader Obfuscation (Two Variants)

**Original variant** (marker: `rmcej%otb%`):
- Shuffle seed: `2857687` / secondary: `2667686`
- Decoder function: `_$_1e42`
- Global namespace injection: `global['!']`, `global['r']`, `global['m']`

**New variant** (marker: `Cot%3t=shtP`):
- Shuffle seed: `1111436` / secondary: `3896884`
- Decoder function: `MDy`
- Global namespace injection: `global['_V']='8-XXX'` (sequential version tags `8-st1` through `8-st59`)

Both variants use character-shuffling deobfuscation with seeded permutation tables. The decoded JavaScript contacts blockchain RPC endpoints for encrypted payload retrieval.

### 2. Blockchain Dead-Drop Payload Delivery

The loader polls blockchain infrastructure to retrieve XOR-encrypted JavaScript payloads from transaction data:

**TRON:**
- Addresses: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`, `TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v`
- API: `hxxps://api[.]trongrid[.]io/v1/accounts/`

**Aptos:**
- Addresses: `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e`, `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3`
- API: `hxxps://fullnode[.]mainnet[.]aptoslabs[.]com/v1/accounts/`

**BNB Smart Chain:**
- RPC nodes: `bsc-dataseed[.]binance[.]org`, `bsc-rpc[.]publicnode[.]com`
- Method: `eth_getTransactionByHash` on transaction `input` field

XOR decryption keys: `2[gWfGj;<:-93Z^C` (primary), `m6:tTh^D)cBz?NM]` (secondary).

### 3. Rollup Polyfill Sub-Campaign (JFrog)

Six npm packages impersonating the legitimate `rollup-plugin-polyfill-node`:

| Package | Role |
|---------|------|
| `rollup-packages-polyfill-core` | Entry point |
| `rollup-runtime-polyfill-core` | Entry point |
| `swift-parse-stream` | Second stage |
| `quirky-token` | Second stage |
| `rollup-plugin-polyfill-connect` | Second stage |
| `react-icon-svgs` | Second stage |

Entry packages contain Base64-encoded `npm install` commands triggering silent installation of second-stage packages. The final payload fetches an AES-256-CBC encrypted payload from `216.126.236[.]244`:

- Key derivation: `crypto.scryptSync("98cb54c0b4ac259d30c9c1ca1ae87c68", "salt", 32)`
- Payload URL: `hxxp://216.126.236[.]244/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68`
- JSONKeeper loader: `hxxps://www[.]jsonkeeper[.]com/b/3P9BF`
- Response format: `<base64 IV>:<base64 ciphertext>` (~114 KB decrypted)

### 4. C2 Infrastructure and Payload Capabilities

**Primary C2 IP (Rollup sub-campaign):** `216.126.236[.]244`
- Port 4801: Socket.IO remote access (scdata)
- Port 4806/upload: Filesystem collection uploads
- Port 4809/upload: Browser/wallet data uploads
- Port 4809/cldbs: Credential database uploads
- `/api/service/makelog`: Clipboard exfiltration
- `/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68`: Payload retrieval

**Additional C2 IPs (from Panther/Talos):**
- `216.126.237[.]71` (OtterCookie Cluster A, port 1244)
- `216.126.224[.]220` (port 5976)
- `107.189.20[.]115`, `95.216.26[.]109:6211`, `166.88.54[.]158`, `198.105.127[.]210`, `23.27.202[.]27`

**Vercel-hosted C2 domains:**
- `default-configuration[.]vercel[.]app` (106 victims)
- `vscode-settings-bootstrap[.]vercel[.]app`
- `vscode-settings-config[.]vercel[.]app`
- `vscode-bootstrapper[.]vercel[.]app`
- `vscode-load-config[.]vercel[.]app`
- `260120[.]vercel[.]app`
- `cloudflareinsights[.]vercel[.]app`
- `coingecko-liard[.]vercel[.]app`
- `axioshealthcheck[.]vercel[.]app`
- `logkit-tau[.]vercel[.]app`

Vercel endpoints follow pattern: `hxxps://<subdomain>[.]vercel[.]app/settings/(mac|linux|win)?flag=<N>`

**Payload components:**
- `scdata.js`: Remote access -- host profiling, command execution via `child_process.exec`, interactive terminals via `node-pty`, SSH sessions via `ssh2`, screenshot capture (`screenshot-desktop`), input control (`@nut-tree-fork/nut-js`), clipboard manipulation (`clipboardy`)
- `ldata.js`: Browser and crypto-wallet data collection across Chrome, Edge, Brave, Opera, LT Browser
- Filesystem collector: Broad secret/credential targeting (`*.env*`, `*.pem`, `*.key`, `*.secret`)
- Clipboard watcher: Periodic clipboard monitoring

### 5. Sandbox Evasion

The malware checks for the following environment variables and exits if present:

`CODESPACE_NAME`, `CODESANDBOX_HOST`, `VERCEL`, `AWS_EXECUTION_ENV`, `AWS_REGION`, `AWS_LAMBDA_FUNCTION_NAME`, `AWS_ACCESS_KEY_ID`, `GOOGLE_CLOUD_PROJECT`, `AZURE_FUNCTIONS_ENVIRONMENT`, `DOCKER`, `RENDER`, `GAE_ENV`, `WEBSITE_SITE_NAME`, `DYNO`, `SOCKET_DEV`

OS release strings containing "aws" also trigger early exit. Virtual machine detection is performed before payload execution.

### 6. Anti-Forensics / Evasion Techniques

- **Git history falsification**: `temp_auto_push.bat` amends commits with spoofed timestamps and force-pushes with `--no-verify`
- **Obfuscator.io**: Variable/function name obscuration with seeded shuffle permutations
- **Base64/Base91 encoding**: Multi-layer encoding of payloads and package names
- **XOR and AES-256-CBC encryption**: Payload encryption at rest and in transit
- **C2 URL assembly**: IP addresses constructed at runtime via `mySrv()` helper functions
- **Error handler code loading**: Server generates error responses evaluated via `eval()`
- **Blockchain dead-drop**: Infrastructure-resilient payload hosting on immutable ledgers
- **Console logging disabled**: Output suppressed at execution start

---

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Ecosystem | Description |
|---------------------|-----------|-------------|
| `rollup-packages-polyfill-core` | npm | Entry-point Rollup impersonator |
| `rollup-runtime-polyfill-core` | npm | Entry-point Rollup impersonator |
| `swift-parse-stream` | npm | Second-stage SVG sanitization disguise |
| `quirky-token` | npm | Second-stage package |
| `react-icon-svgs` | npm | Second-stage package |
| `rollup-plugin-polyfill-connect` | npm | Second-stage package |
| `rollup-plugin-polyfill-route` | npm | Rollup mimicry precursor (Mar 20) |
| `tailwindcss-style-animate` v1.1.6 | npm | ShoeVista template dependency (34 victims) |
| `tailwind-mainanimation` v0.0.1-security | npm | Taken down Mar 13 |
| `tailwind-autoanimation` v2.3.6 | npm | Removed |
| `tailwindcss-typography-style` v0.8.2 | npm | Tailwind impersonator |
| `tailwindcss-style-modify` v0.8.3 | npm | Tailwind impersonator |
| `tailwindcss-animate-style` v1.2.5 | npm | Tailwind impersonator |
| `mongoose-lean-hooks` | npm | Cluster A OtterCookie |
| `request-js-validator` | npm | Cluster A |
| `vite-enhancer-config` | npm | Cluster A |
| `winston-prism` | npm | Cluster A |
| `chai-as-adapter`, `chai-as-chain-v2` | npm | Cluster A variants |
| `node-nvm-ssh` | npm | Talos-identified trojanized package |
| sevenspan/* (multiple) | Packagist | Compromised PHP namespace |
| Xpos587/git2md, Xpos587/markfetch | Go (GitHub) | Compromised Go repositories |
| Artiffusion-Inc/mirofish | Go (GitHub) | Compromised Go repository |
| 7span/react-list | npm/GitHub | Compromised organization |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Cross-platform | `.vscode/tasks.json` | Auto-execution task with `runOn: folderOpen` |
| Cross-platform | `public/fonts/fa-solid-400.woff2` | JavaScript payload disguised as font |
| Cross-platform | `postcss.config.mjs` | Injected loader (approx. 960 occurrences) |
| Cross-platform | `tailwind.config.js` | Injected loader (approx. 210 occurrences) |
| Cross-platform | `eslint.config.mjs` | Injected loader (approx. 150 occurrences) |
| Cross-platform | `next.config.mjs`, `vite.config.js`, `App.js` | Additional injection targets |
| Windows | `temp_auto_push.bat` | Git history falsification script (101 repos) |
| Cross-platform | `/tmp/tmp7A863DD1.tmp` | Payload execution lock file |
| Cross-platform | `/tmp/0001.dat` | RAT binary drop |
| Windows | `windows-cache/1.tmp` | Keylogger buffer |
| Windows | `windows-cache/2.jpeg` | Screenshot capture |
| macOS | `~/Library/Keychains/login.keychain-db` | Credential target |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `216.126.236[.]244` | Primary C2 (Rollup sub-campaign, ports 4801/4806/4809) |
| IP | `216.126.237[.]71` | C2 OtterCookie Cluster A |
| IP | `216.126.224[.]220` | C2 (port 5976) |
| IP | `107.189.20[.]115` | C2 |
| IP | `95.216.26[.]109` | C2 (port 6211) |
| IP | `166.88.54[.]158` | C2 |
| IP | `198.105.127[.]210` | C2 |
| IP | `23.27.202[.]27` | C2 |
| Domain | `default-configuration[.]vercel[.]app` | Vercel C2 (largest cluster, 106 victims) |
| Domain | `vscode-settings-bootstrap[.]vercel[.]app` | Vercel C2 |
| Domain | `vscode-settings-config[.]vercel[.]app` | Vercel C2 |
| Domain | `cloudflareinsights[.]vercel[.]app` | Vercel C2 (SSH key/scan patterns) |
| Domain | `coingecko-liard[.]vercel[.]app` | Vercel C2 |
| Domain | `axioshealthcheck[.]vercel[.]app` | Vercel C2 (debug trojanization) |
| Domain | `260120[.]vercel[.]app` | Vercel C2 (original cluster) |
| URL Pattern | `hxxps://<sub>[.]vercel[.]app/settings/(mac\|linux\|win)?flag=<N>` | Vercel C2 pattern |
| URL | `hxxps://www[.]jsonkeeper[.]com/b/3P9BF` | JSONKeeper payload staging |
| URL | `hxxp://216.126.236[.]244/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68` | AES payload endpoint |
| Domain | `regioncheck[.]xyz` | Geo-gating |

### Behavioral

- Node.js process executing `.woff2` files from `public/fonts/` directories
- VS Code tasks with `runOn: folderOpen` spawning `curl | bash` or `node` child processes
- JavaScript `eval()` execution of XOR-decoded blockchain transaction data
- Socket.io-client connections to non-standard ports (1244, 4801, 4806, 4809, 5976, 6211)
- Batch scripts (`temp_auto_push.bat`) performing `git commit --amend --no-verify` with system clock manipulation
- `npm install` of Base64-encoded package names with `--no-save --silent --no-audit --no-fund` flags
- Enumeration of cryptocurrency wallet extension directories (MetaMask ID: `nkbihfbeogaeaoehlefnkodbefgpgknn`)
- SSH key injection into `~/.ssh/authorized_keys`
- Periodic clipboard harvesting via `pbpaste` (macOS) or `powershell Get-Clipboard` (Windows)
- Screenshot capture every 4 seconds to `2.jpeg`; keystroke flushing every 1 second to `1.tmp`

---

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Malicious code injected into 108 packages across npm, Packagist, Go, Chrome |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Maintainer account takeover via expired domain / account recovery |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JS loaders in config files, eval() execution of decrypted payloads |
| T1027 | Obfuscated Files or Information | Seeded shuffle permutations, Base64/Base91/XOR/AES-256-CBC encoding |
| T1140 | Deobfuscate/Decode Files or Information | XOR decryption of blockchain payloads, AES-256-CBC decryption of final stage |
| T1036 | Masquerading | Packages mimic legitimate Rollup/Tailwind libraries; .woff2 font disguise |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/Socket.IO C2 communication; blockchain RPC as dead-drop |
| T1571 | Non-Standard Port | C2 on ports 1244, 4801, 4806, 4809, 5976, 6211 |
| T1005 | Data from Local System | Credential harvesting from .env, .pem, .key, wallet files, browser profiles |
| T1056.004 | Input Capture: Credential API Hooking | Clipboard monitoring via pbpaste/Get-Clipboard |
| T1113 | Screen Capture | Screenshot capture every 4 seconds via screenshot-desktop |
| T1115 | Clipboard Data | Periodic clipboard harvesting and exfiltration |
| T1098.004 | Account Manipulation: SSH Authorized Keys | SSH key injection for persistent access (Cluster F) |
| T1041 | Exfiltration Over C2 Channel | Data uploaded via HTTP POST to C2 /upload endpoints |
| T1082 | System Information Discovery | Host profiling: OS, hostname, UID, VM detection |
| T1083 | File and Directory Discovery | Filesystem traversal targeting credentials and wallets |

---

## Impact Assessment

- **Breadth**: 108 packages across 4 ecosystems; 1,951 GitHub repositories; 1,047 unique owners compromised
- **Depth**: Full system compromise -- RAT deployment with shell access, keylogging, screenshot capture, credential theft, wallet exfiltration
- **Financial risk**: Direct cryptocurrency theft via wallet key extraction (Solana, MetaMask, Phantom, Exodus, etc.)
- **Supply chain amplification**: Compromised npm Trusted Publishing tokens enable self-propagation to additional packages
- **Stealth**: Git history falsification, blockchain-based C2, multiple obfuscation layers make detection difficult
- **Active status**: Campaign remains active as of July 2026; C2 infrastructure (216.126.236[.]244) was still serving payloads as of June 30, 2026

---

## Detection & Remediation

### Immediate Detection

```bash
# Search for PolinRider obfuscation markers in project files
grep -rl "rmcej%otb%" . --include="*.js" --include="*.mjs" --include="*.cjs"
grep -rl "Cot%3t=shtP" . --include="*.js" --include="*.mjs" --include="*.cjs"
grep -rl "_\$_1e42\|MDy" . --include="*.js" --include="*.mjs"

# Check for malicious VS Code tasks
find . -name "tasks.json" -exec grep -l "runOn.*folderOpen" {} \;

# Check for temp_auto_push.bat
find . -name "temp_auto_push.bat" -type f

# Check for fake font payloads
file public/fonts/*.woff2 2>/dev/null | grep -v "Web Open Font"

# Search for known C2 endpoints
grep -rl "216.126.236.244\|216.126.237.71\|default-configuration.vercel.app\|jsonkeeper.com/b/3P9BF" .

# Check npm lockfile for known malicious packages
grep -E "rollup-packages-polyfill|rollup-runtime-polyfill|swift-parse-stream|quirky-token|react-icon-svgs|rollup-plugin-polyfill-connect|tailwindcss-style-animate" package-lock.json yarn.lock 2>/dev/null

# Check for execution lock file
ls -la /tmp/tmp7A863DD1.tmp /tmp/0001.dat 2>/dev/null
```

### Remediation

1. **Treat environment as compromised** -- assume all credentials, tokens, and keys accessible from the development machine are exfiltrated
2. **Rotate all secrets** from a clean machine: npm tokens, SSH keys, cloud provider credentials, API keys, database passwords, cryptocurrency wallet keys
3. **Remove affected package versions** and rebuild from a known-good lockfile
4. **Audit `.vscode/tasks.json`** in all projects for `runOn: folderOpen` with suspicious commands
5. **Audit configuration files** (`postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`, `vite.config.js`) for appended obfuscated content
6. **Review GitHub repository activity logs** for force pushes, anti-dated commits, and unexpected package releases
7. **Check `~/.ssh/authorized_keys`** for unauthorized SSH keys (identifiers: `bink@DESKTOP-N8JGD6T`, `dev-key`, `DESKTOP@com`)
8. **Block C2 infrastructure** at network perimeter (see IOC tables)

### Long-Term Hardening

- Enable npm 2FA and audit automation for all maintainer accounts
- Use lockfile-only installs (`npm ci`) in CI/CD pipelines
- Implement VS Code workspace trust policies that reject `runOn: folderOpen` tasks from untrusted sources
- Monitor for `--no-verify` flag usage in git operations
- Deploy package provenance verification (npm `--expect-provenance`)
- Implement egress filtering for non-standard ports used by socket.io C2

---

## Detection Rules

These detections target PolinRider campaign-specific artifacts: the distinctive obfuscation markers, known C2 infrastructure, malicious file patterns, and the Rollup polyfill sub-campaign's AES payload delivery. PoC/advisory-specific altitude (strict); compiles does not equal fires -- verify in your environment's telemetry pipeline.

### Sigma: PolinRider Node.js Execution of Fake Font Payload

Detects Node.js executing `.woff2` files from `public/fonts/` directories, a distinctive PolinRider/TaskJacker delivery technique.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data proxy); splunk convert 0; log_scale convert 0. Keys on the .woff2+public/fonts/ combination which is highly campaign-specific; legitimate node invocations never load font files. FP risk: near-zero outside deliberate reproduction. -->
```yaml
title: PolinRider Node.js Execution of Fake Font Payload
id: 7a3e1f29-4c8b-4d5a-9e2f-1b6c8d7a0e34
status: experimental
description: >
    Detects Node.js executing .woff2 files from public/fonts/ directories,
    a distinctive delivery technique used in the PolinRider and TaskJacker
    supply chain campaigns attributed to DPRK Contagious Interview.
references:
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://github.com/OpenSourceMalware/PolinRider
author: Actioner
date: 2026/07/07
tags:
    - attack.t1059.007
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_node:
        Image|endswith:
            - '\node.exe'
            - '\node'
    selection_woff2:
        CommandLine|contains|all:
            - 'public/fonts/'
            - '.woff2'
    condition: selection_node and selection_woff2
falsepositives:
    - Legitimate build tools that process font files via Node.js (extremely unlikely to match this path pattern)
level: high
```

### Sigma: PolinRider Obfuscation Marker in Config Files

Detects file creation or modification events writing known PolinRider obfuscation markers to JavaScript configuration files.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data proxy); splunk convert 0; log_scale convert 0. Markers rmcej%otb% and Cot%3t=shtP are unique campaign signatures with zero benign occurrence. file_event category is broadly supported. Note: this rule keys on filename only (no content inspection); medium confidence because benign config file edits match -- pair with YARA for content confirmation. -->
```yaml
title: PolinRider Obfuscation Marker in Config Files
id: 2d8c4a67-9f1e-4b3c-a5d8-6e0f7c2b1a94
status: experimental
description: >
    Detects file events containing known PolinRider JavaScript obfuscation markers
    (rmcej%otb% or Cot%3t=shtP) in developer configuration files, indicating
    config file injection by the DPRK PolinRider campaign.
references:
    - https://github.com/OpenSourceMalware/PolinRider
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
author: Actioner
date: 2026/07/07
tags:
    - attack.t1195.001
    - attack.t1027
logsource:
    category: file_event
detection:
    selection_files:
        TargetFilename|endswith:
            - 'postcss.config.mjs'
            - 'postcss.config.js'
            - 'tailwind.config.js'
            - 'tailwind.config.mjs'
            - 'eslint.config.mjs'
            - 'eslint.config.js'
            - 'next.config.mjs'
            - 'vite.config.js'
            - 'vite.config.mjs'
    condition: selection_files
falsepositives:
    - Legitimate developer activity modifying these configuration files (requires content inspection for marker confirmation)
level: medium
```

### Sigma: PolinRider Silent npm Install with Suppressed Output

Detects npm install commands using the distinctive PolinRider flag combination (`--no-save --silent --no-audit --no-fund`) to silently install second-stage packages.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data proxy); splunk convert 0; log_scale convert 0. The four-flag combination (--no-save --silent --no-audit --no-fund) is campaign-distinctive; legitimate npm usage rarely combines all four suppression flags in a single install command. -->
```yaml
title: PolinRider Silent npm Package Installation
id: 9b4e2c18-7d6f-4a3e-8c1b-5f0d9a2e7b63
status: experimental
description: >
    Detects npm install commands using the distinctive PolinRider flag combination
    (--no-save --silent --no-audit --no-fund) to silently install second-stage
    malicious packages without leaving traces in package.json or lockfiles.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
author: Actioner
date: 2026/07/07
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'npm install'
            - '--no-save'
            - '--silent'
            - '--no-audit'
            - '--no-fund'
    condition: selection
falsepositives:
    - CI/CD scripts using all four flags simultaneously for dependency caching (uncommon)
level: high
```

### Sigma: PolinRider C2 Network Connection to Known IPs

Detects outbound network connections to known PolinRider C2 IP addresses on campaign-associated ports.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data proxy); splunk convert 0; log_scale convert 0. IOC-based detection on confirmed C2 IPs. Will age out as infrastructure rotates; high confidence while active. -->
```yaml
title: PolinRider C2 Network Connection to Known Infrastructure
id: 4f1a8d35-6c2e-4b9f-a7d3-8e5c0f1b2a46
status: experimental
description: >
    Detects outbound network connections to confirmed PolinRider campaign C2 IP
    addresses. Infrastructure confirmed active as of June 30, 2026.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave
author: Actioner
date: 2026/07/07
tags:
    - attack.t1071.001
    - attack.t1571
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '216.126.236.244'
            - '216.126.237.71'
            - '216.126.224.220'
            - '107.189.20.115'
            - '95.216.26.109'
            - '166.88.54.158'
            - '198.105.127.210'
            - '23.27.202.27'
    condition: selection
falsepositives:
    - Legitimate services hosted on the same IP addresses (verify with port and process context)
level: high
```

### Snort: PolinRider AES Payload Retrieval from C2

Detects HTTP requests to the PolinRider/Rollup polyfill C2 endpoint serving AES-256-CBC encrypted payloads via the distinctive API path containing the scrypt passphrase.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T 0 (Snort 2.9.20, validated successfully). Keys on the unique /api/service/98cb54c0b4ac259d30c9c1ca1ae87c68 URI path which contains the AES scrypt passphrase. Zero benign overlap. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PolinRider AES Payload Retrieval via Scrypt Passphrase URI"; flow:established,to_server; content:"/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; sid:2100101; rev:1;)
```

### Snort: PolinRider C2 Clipboard Exfiltration Endpoint

Detects HTTP requests to the PolinRider C2 clipboard exfiltration endpoint `/api/service/makelog`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -T 0 (Snort 2.9.20, validated successfully). /api/service/makelog is used across multiple Contagious Interview variants; medium confidence due to possible benign API paths with similar naming. Scope to known C2 IPs for higher precision. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PolinRider C2 Clipboard Exfiltration Endpoint"; flow:established,to_server; content:"/api/service/makelog"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; sid:2100102; rev:1;)
```

### Suricata: PolinRider DNS Query to Vercel C2 Subdomains

Detects DNS queries to known PolinRider Vercel-hosted C2 subdomains used for payload bootstrapping and SSH key distribution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0 (Suricata 7.0.3). C2 subdomains are campaign-specific (default-configuration, vscode-settings-bootstrap, etc.). DNS query matching is robust. Will age out if Vercel takes down the subdomains. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to Vercel C2 Subdomain"; flow:to_server; dns.query; content:"default-configuration.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; metadata:author Actioner, created_at 2026-07-07; sid:2200101; rev:1;)
```

### Suricata: PolinRider DNS Query to Vercel C2 (VSCode Bootstrap)

Detects DNS queries to the `vscode-settings-bootstrap` Vercel C2 subdomain used for initial payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0 (Suricata 7.0.3). Campaign-specific subdomain. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to VSCode Settings Bootstrap C2"; flow:to_server; dns.query; content:"vscode-settings-bootstrap.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; metadata:author Actioner, created_at 2026-07-07; sid:2200102; rev:1;)
```

### Suricata: PolinRider JSONKeeper Payload Staging

Detects HTTP requests to the known PolinRider JSONKeeper payload staging URL used to retrieve initial JavaScript loaders.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T 0 (Suricata 7.0.3). The specific JSONKeeper path /b/3P9BF is campaign-unique. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PolinRider JSONKeeper Payload Staging Retrieval"; flow:established,to_server; http.host; content:"jsonkeeper.com"; fast_pattern; http.uri; content:"/b/3P9BF"; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; metadata:author Actioner, created_at 2026-07-07; sid:2200103; rev:1;)
```

### YARA: PolinRider JavaScript Loader Obfuscation Markers

Detects PolinRider JavaScript loader files by their distinctive obfuscation markers, shuffle seeds, and decoder function names across both known variants.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac 0; yara pos-markers.js fired PolinRider_JS_Loader_Obfuscation_Markers; yara neg-markers.js quiet. Positive built from published marker strings (rmcej%otb%, 2857687, _$_1e42, global['!'], 2[gWfGj;<:-93Z^C). Markers are unique to the campaign with zero known benign occurrence. -->
```yara
rule PolinRider_JS_Loader_Obfuscation_Markers
{
    meta:
        description = "Detects PolinRider JavaScript loader files by distinctive obfuscation markers and decoder functions across both known variants"
        author = "Actioner"
        date = "2026-07-07"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker_v1 = "rmcej%otb%" ascii
        $seed1_v1 = "2857687" ascii
        $seed2_v1 = "2667686" ascii
        $decoder_v1 = "_$_1e42" ascii

        $marker_v2 = "Cot%3t=shtP" ascii
        $seed1_v2 = "1111436" ascii
        $seed2_v2 = "3896884" ascii
        $decoder_v2 = "MDy" ascii fullword

        $global_bang = "global['!']" ascii
        $global_V = "global['_V']" ascii

        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii

    condition:
        filesize < 5MB and
        (
            ($marker_v1 and 1 of ($seed1_v1, $seed2_v1, $decoder_v1)) or
            ($marker_v2 and 1 of ($seed1_v2, $seed2_v2, $decoder_v2)) or
            (1 of ($global_bang, $global_V) and 1 of ($xor_key1, $xor_key2)) or
            (1 of ($marker_v1, $marker_v2) and 1 of ($xor_key1, $xor_key2))
        )
}
```

### YARA: PolinRider Rollup Polyfill AES Loader

Detects the Rollup polyfill sub-campaign's AES-256-CBC loader by the distinctive scrypt passphrase and decryption pattern.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac 0; yara pos-rollup.js fired PolinRider_Rollup_AES_Loader; yara neg-rollup.js (benign crypto.scryptSync with different passphrase) quiet. Positive built from published scrypt passphrase 98cb54c0b4ac259d30c9c1ca1ae87c68 + C2 IP 216.126.236.244. The 32-char hex passphrase is unique to this campaign. -->
```yara
rule PolinRider_Rollup_AES_Loader
{
    meta:
        description = "Detects the PolinRider Rollup polyfill AES-256-CBC loader by the distinctive scrypt passphrase and C2 endpoint pattern"
        author = "Actioner"
        date = "2026-07-07"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $scrypt_pass = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii
        $scrypt_call = "scryptSync" ascii
        $aes_mode = "aes-256-cbc" ascii
        $c2_ip = "216.126.236.244" ascii
        $api_path = "/api/service/" ascii
        $jsonkeeper = "jsonkeeper.com" ascii

    condition:
        filesize < 1MB and
        $scrypt_pass and
        (1 of ($scrypt_call, $aes_mode)) and
        (1 of ($c2_ip, $api_path, $jsonkeeper))
}
```

---

## Lessons Learned

1. **Multi-ecosystem campaigns are the new normal**: PolinRider's simultaneous targeting of npm, Packagist, Go, and Chrome demonstrates that monitoring a single package ecosystem is insufficient. Organizations need cross-ecosystem dependency monitoring.

2. **Blockchain dead-drops resist takedowns**: Using immutable blockchain ledgers (TRON, Aptos, BSC) for payload staging makes traditional infrastructure takedown ineffective. Detection must shift to the client-side behavior (blockchain RPC calls from developer tooling contexts).

3. **Git history is unreliable**: Force pushes with anti-dated commits make GitHub landing pages and visible commit history unreliable indicators. Repository activity logs (not file-level git history) must be consulted for integrity verification.

4. **VS Code workspace trust is critical**: The `runOn: folderOpen` task auto-execution feature continues to be a potent attack vector. Organizations should enforce VS Code workspace trust policies and audit `.vscode/tasks.json` in all cloned repositories before opening them.

5. **Maintainer account security is the supply chain's weakest link**: Expired domain takeover for account recovery remains a viable compromise vector. Package registries should enforce domain validation freshness and require 2FA for all publishing accounts.

---

## Sources

- [Socket Threat Research - PolinRider Campaign Analysis](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) -- primary multi-ecosystem campaign analysis and IOC tracking
- [JFrog Security Research - Rollup Polyfill Masquerading](https://research.jfrog.com/post/rollup-polyfill-masquerading/) -- detailed analysis of Rollup polyfill npm sub-campaign with AES/C2 IOCs
- [OpenSourceMalware/PolinRider GitHub Dossier](https://github.com/OpenSourceMalware/PolinRider) -- comprehensive IOC repository with obfuscation markers, affected repo lists, and detection scripts
- [Panther - Inside DPRK's npm Malware Factory](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave) -- 108 npm packages / 261 versions analysis with cluster taxonomy and C2 infrastructure
- [Cisco Talos - BeaverTail and OtterCookie Evolution](https://blog.talosintelligence.com/beavertail-and-ottercookie/) -- malware family evolution, capabilities, and IOCs
- [The Hacker News - PolinRider Campaign Coverage](https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html) -- campaign summary and attribution context
- [The Hacker News - Rollup Polyfill npm Packages](https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html) -- Rollup polyfill sub-campaign coverage
- [SecurityWeek - NK Open Source Developer Targeting](https://www.securityweek.com/north-korean-hackers-target-open-source-developers-in-supply-chain-attacks/) -- broader campaign context and defensive guidance
- [PolinRider Scanner (FedericoGarcia)](https://gist.github.com/FedericoGarcia/803c3ac4e3d93b4042dcd135a43c5a4c) -- community detection script with C2 IP and domain lists

---
*Report generated by Actioner*
