# Technical Analysis Report: @joyfill npm Supply Chain Compromise -- DEV#POPPER RAT (2026-08-01)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-01
Version: 1.0 (DRAFT)

## Executive Summary

On July 28, 2026, six malicious beta versions of two legitimate @joyfill npm packages (`@joyfill/components` and `@joyfill/layouts`) were published to the npm registry. The compromised packages contain an import-time JavaScript implant that delivers the DEV#POPPER remote access trojan (RAT) and a Python-based credential stealer classified as a likely OmniStealer variant. Unlike typical npm supply chain attacks that rely on `postinstall` lifecycle hooks, this implant executes when the package is imported via `require()` or `import`, bypassing the `--ignore-scripts` defensive flag entirely.

The attack employs a novel multi-blockchain command-and-control resolution mechanism using Tron, Aptos, and BNB Smart Chain transactions to retrieve encrypted payloads, enabling the operators to switch C2 infrastructure without republishing the package. The recovered 77 KB RAT establishes a Socket.IO remote-control channel and implements worm-like propagation by injecting itself into VS Code, Discord, GitHub Desktop, and the global npm CLI. Attribution is assessed with medium-high confidence to North Korean state-sponsored actors (threat cluster PolinRider), overlapping with the Contagious Interview and ViteVenom campaigns. Prior Actioner coverage of related DPRK blockchain-C2 tooling appears in the [2026-06-06 PHANTOMPULSE report](2026-06-06-phantompulse-blockchain-c2.md) and the [2026-06-30 npm/Go VS Code tasks infostealer report](2026-06-30-npm-go-vscode-infostealer.md).

## Background: @joyfill npm Packages

Joyfill is a form-building and document-rendering SDK for JavaScript applications. Its npm namespace (`@joyfill`) includes `@joyfill/components` (React component library) and `@joyfill/layouts` (layout utilities). These are legitimate packages used by developers building form-heavy applications. The attacker compromised the publishing pipeline (not the source repository) to inject malicious code exclusively into published tarballs, with no corresponding source-level changes -- strong evidence of a registry or CI/CD token compromise rather than a codebase backdoor.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02 (est.) | eSentire TRU detects earlier DEV#POPPER RAT variant via "ShoeVista" GitHub lure; publishes analysis linking to North Korean APT |
| 2026-07-28T10:54:57Z | `@joyfill/layouts@0.1.2-2773.beta.0` published to npm |
| 2026-07-28T11:03:59Z | `@joyfill/components@4.0.0-rc24-2773-beta.4` published to npm |
| 2026-07-28 (est.) | Additional beta versions published: layouts `.beta.1`, `.beta.2`; components `-beta.5`, `-beta.6` |
| 2026-07-28 | Socket detects and flags malicious packages; StepSecurity detonates all six versions in Harden-Runner sandbox |
| 2026-07-29 | The Hacker News publishes advisory; widespread community notification |

## Root Cause: npm Publishing Pipeline Compromise

The malicious code resides exclusively in published distribution tarballs (`dist/index.js`, `dist/index.esm.js`, `dist/joyfill.min.js` for components; `dist/index.cjs.js`, `dist/index.es.js` for layouts). No corresponding source-level changes exist in the repository. Both malicious releases were published using Node.js 18.20.0 and npm 10.5.0, with the shared prerelease build marker `2773`. This indicates the attacker compromised either an npm access token or the CI/CD publishing pipeline, then appended ~333 lines of obfuscated malicious code to the compiled distribution bundles.

## Technical Analysis of the Malicious Payload

### 1. Import-Time Bootstrap (Stage 1)

The implant executes when Node.js loads the CommonJS package entry point -- not during `npm install`. This means `npm install --ignore-scripts` provides no protection. The obfuscated loader employs multiple layers:

- **Seeded shuffle decoder** using a PRNG swap loop to rebuild hidden strings
- **LZ77-style dictionary decompression** with 2- and 3-character escape codes
- **Function constructor ladder** avoiding direct `eval()` or `Function()` references
- **Global stashing:** `global.r = require; global.m = module` to enable later stages to access `child_process`, `http`, and other modules without literal string references
- **Campaign marker:** `global["!"] = "9-0135-3"` (later referenced as `_V = "A9-0135-3"`)
- **Re-entry guard:** `global._p_t` enforces a 30-second throttle, defeating repeated sandbox runs

### 2. Blockchain C2 Resolution (Stage 2)

Rather than hardcoding C2 servers, the implant resolves encrypted payloads through public blockchain transactions -- a technique previously documented in PHANTOMPULSE (Actioner report 2026-06-06) and the npm/Go VS Code tasks campaign (2026-06-30):

**Primary path (in-process):**
1. Query Tron address `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` via `api.trongrid.io`
2. Transaction memo (reversed) yields a BNB Smart Chain transaction hash
3. Fetch BSC transaction via `eth_getTransactionByHash` (RPCs: `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com`)
4. Extract transaction input field, reverse, split on `?.?`, XOR-decrypt first segment with key `2[gWfGj;<:-93Z^C`
5. `eval()` the recovered JavaScript (Stage 3 loader)

**Fallback (Aptos):** Account `0xbe037400...80811e` carries the hash in a 0-value transfer recipient address.

**Secondary path (detached process):**
A parallel `child_process.spawn("node", ["-e", payload])` with `detached: true, stdio: "ignore", windowsHide: true` runs independently. It queries Tron address `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`, resolves to `23.27.13.43/$/boot`, and XOR-decrypts the response with key `ThZG+0jfXE6VAGOJ`. The process calls `unref()` to continue independent of the parent.

### 3. DEV#POPPER RAT (Stage 3 -- "clientCode")

The recovered 77 KB payload (SHA-256: `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18`, version `260605`) self-provisions its dependencies by running `npm --prefix "<tmp>" install socket.io-client axios form-data` and establishes a persistent Socket.IO connection to the C2 server.

**Command dispatch:**

| Command | Function |
|---------|----------|
| `ss_info` | Host identification (hostname, OS, PID, timestamps, campaign tag) |
| `ss_ip` | IP geolocation via `ip-api.com` |
| `ss_cb` | Clipboard exfiltration (platform-specific) |
| `ss_upf` / `ss_upd` | File/directory upload to C2 via multipart POST (`/u/f`) |
| `ss_dir` | Directory listing |
| `ss_fcd` | File content download |
| `ss_eval` / `ss_eval64` | Arbitrary JavaScript / base64-decoded JavaScript execution |
| `ss_inz` / `ss_inzx` | Inject/remove worm stager into local applications |
| `ss_connect` | Re-point agent to new C2 |
| `ss_exit` / `ss_exit_f` | Process termination |
| `~py` | Spawn Python credential stealer |

**Campaign-based C2 routing:** The campaign tag `_V = "A9-0135-3"` (Joyfill vector) routes to `166.88.134.62:443` (Socket.IO) and `166.88.134.62` (uploads). Numeric campaigns use `198.105.127.210:443` (primary) and `23.27.202.27:443` (fallback).

### 4. Worm Propagation and Persistence

The RAT injects self-reloading blocks into developer tools using idempotent comment sentinels:

**Injection targets:**
- `@vscode/deviceid/dist/index.js` (VS Code, Cursor, Antigravity)
- `discord_desktop_core/index.js` (Discord Desktop)
- `resources/app/main.js` (GitHub Desktop)
- `<npm root -g>/npm/lib/cli.js` (global npm CLI -- supply-chain amplifier)

**Injection markers:** `/*C250617A*/`, `/*C250618A*/`, `/*C250619A*/`, `/*C250620A*/`, `/*C260511A*/`, `/*C260512A*/`, `/*RS260605*/`

Once the global npm CLI is patched, every subsequent `npm` invocation re-executes the malware, enabling infected developer machines to propagate compromise to downstream packages.

### 5. Python Credential Stealer (OmniStealer Variant)

Staged under `%USERPROFILE%\.npm` (Windows) or `/tmp/.npm` (macOS/Linux), the Python stealer (SHA-256: `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c`, 82,457 bytes) creates AES-encrypted ZIP archives using `pyzipper` with password `,./,./,./`.

**Data targets:**
- Chromium/Chrome and Firefox browser data (cookies, passwords, history, credit cards)
- 145+ cryptocurrency wallet browser extensions (MetaMask, Phantom, Trust Wallet, Ledger, etc.)
- Desktop crypto applications (Solana, Monero GUI, Bitcoin Core, Electrum, Exodus)
- Cloud storage metadata (pCloud, MEGA, Box, iCloud Drive, Dropbox, OneDrive)
- Git credentials and GitHub CLI configuration
- VS Code storage (`state.vscdb`, `storage.json`)
- OS credential stores (Windows Credential Manager, macOS Keychain, Linux GNOME Keyring/KWallet)

**Exfiltration:** HTTP upload to C2 or optional Telegram bot (requires C2-supplied bot token and chat ID).

### 6. Platform-Specific Behavior

#### Windows
- Staging directory: `%USERPROFILE%\.npm`
- Clipboard access: `powershell -NoProfile -Command "Get-Clipboard"`
- Credential harvesting: Windows Credential Manager via PowerShell, DPAPI decryption
- Process enumeration: `tasklist /FO CSV /NH`

#### macOS
- Staging directory: `/tmp/.npm`
- Clipboard access: `pbpaste`
- Credential harvesting: Keychain extraction

#### Linux
- Staging directory: `/tmp/.npm`
- Clipboard access: `xclip -selection clipboard -o` (fallback: `xsel --clipboard --output`)
- Credential harvesting: Secret Service (`org.freedesktop.secrets`) or KWallet (`org.kde.kwalletd5` D-Bus)

### 7. Anti-Forensics / Evasion Techniques

- **CI/CD environment detection:** Skips execution on hostnames containing `github-runner`, `buildbot`, `sandbox-pool-`, `buildkitsandbox`, `cloudchamber`, `microsoft-standard-WSL2`, and `root` markers
- **Cloud provider detection:** Terminates on AWS, Azure, GCP, Vercel environments
- **30-second re-entry guard:** `global._p_t` prevents repeated sandbox detonation
- **Source validation:** Decoder integrity check (`_$af163278 == _$_ccfc[32]`) silently neuters modifications
- **Legitimate API traffic:** Only contacts public blockchain RPCs (api.trongrid.io, bsc-dataseed.binance.org) during resolution -- no direct C2 contact until payload is decoded
- **Detached process:** Secondary bootstrap runs as detached, windowsHidden child with unref() -- survives parent termination
- **Import-time execution:** Bypasses `--ignore-scripts` and install-hook scanning

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| @joyfill/layouts | 0.1.2-2773.beta.0 | Obfuscated DEV#POPPER loader in `dist/index.cjs.js` and `dist/index.es.js` |
| @joyfill/layouts | 0.1.2-2773.beta.1 | Same payload, subsequent beta |
| @joyfill/layouts | 0.1.2-2773.beta.2 | Same payload, subsequent beta |
| @joyfill/components | 4.0.0-rc24-2773-beta.4 | Obfuscated DEV#POPPER loader in `dist/index.js`, `dist/index.esm.js`, `dist/joyfill.min.js` |
| @joyfill/components | 4.0.0-rc24-2773-beta.5 | Same payload, subsequent beta |
| @joyfill/components | 4.0.0-rc24-2773-beta.6 | Same payload, subsequent beta |

### File System

| Platform | Path / Artifact | Hash (SHA-256) | Description |
|----------|-----------------|----------------|-------------|
| All | layouts tarball | `adc4af90540d33cd1e98f44b51482ae9250fbeb97d6f8d7841c81b618cb2c6e6` | Malicious layouts package archive |
| All | layouts CommonJS | `8e8b90dedd456ded0c5748119836e1ca1066112bc569c1b41ca70eb931d1d4dc` | dist/index.cjs.js |
| All | components tarball | `bcc93dc55bc7daedf4ca57254f0e7a7f1c40e09851eab98fe10cde801982db17` | Malicious components package archive |
| All | components dist/index.js | `1352ad22c99983d91e600348b7cbf58235131b1ee34cea9f09623206d5b7dea7` | Primary CJS bundle |
| All | components dist/index.esm.js | `67c6ef602cc850f10d935fee53fa40440df841adf081563bf4fc2631a71249ce` | ESM bundle |
| All | components dist/joyfill.min.js | `c5742ea1875ecd2360022624149994909cd0546e221e4203dffd01f48de45469` | Minified bundle |
| All | First payload loader | `cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3` | Stage 2 loader from blockchain |
| All | Tier-two resolver | `f452f9cfa539f4a1fe25187a99a484391290d5dbaa422ba455edf6b04f81b7d1` | Resolver for secondary chain |
| All | Detached bootstrap | `78f0de8682e0e894a5784eb7e95db4da6088f528918ca3107dd1e76f80a561d8` | Secondary detached process payload |
| All | DEV#POPPER RAT | `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18` | 77 KB "clientCode" RAT (version 260605) |
| All | /$/boot capture 1 | `26e679eaf1e9baeb7c55eb48db482301171d4d26e1728544b23734a90dc70e1b` | Boot payload (66,040 bytes) |
| All | /$/boot capture 2 | `2cfede38fb121a71a2f3607474aa8cd588a99f51b37e5e6f0d8cb789fa275032` | Boot payload variant (65,438 bytes) |
| All | Python stealer | `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c` | OmniStealer variant (82,457 bytes) |
| Windows | `%USERPROFILE%\.npm` | -- | Staging directory for stolen data |
| macOS/Linux | `/tmp/.npm` | -- | Staging directory for stolen data |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 166.88.134[.]62 | Primary Socket.IO C2 (ports 443, 80) |
| IP | 23.27.13[.]43 | Boot payload server (`/$/boot`) |
| IP | 198.105.127[.]210 | Fallback C2 (ports 443, 80, 27017) |
| IP | 23.27.202[.]27 | Alternate C2 (ports 443, 27017) |
| Domain | api[.]trongrid[.]io | Tron blockchain RPC (C2 resolution) |
| Domain | fullnode[.]mainnet[.]aptoslabs[.]com | Aptos blockchain RPC (fallback resolution) |
| Domain | bsc-dataseed[.]binance[.]org | BSC blockchain RPC (payload retrieval) |
| Domain | bsc-rpc[.]publicnode[.]com | BSC fallback RPC |
| Domain | ip-api[.]com | Public IP resolution for host fingerprinting |
| URL Pattern | `hxxp://[C2]/$/boot` | Detached bootstrap payload retrieval |
| URL Pattern | `hxxp://[C2]/u/f` | Multipart file upload (exfiltration) |
| URL Pattern | `hxxp://[C2]/u/e` | Metadata registration |
| URL Pattern | `hxxp://[C2]/0x/js?_V=<ver>&id=<id>` | JavaScript payload retrieval |
| URL Pattern | `hxxp://[C2]/verify-human/` | Status check-in |
| HTTP Header | `Sec-V: A9-0135-3` | Campaign identifier header |

### Blockchain Addresses

| Chain | Address | Role |
|-------|---------|------|
| Tron | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | In-process C2 resolver (primary) |
| Tron | `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Detached branch resolver |
| Tron | `TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v` | Tier-two resolver |
| Aptos | `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e` | Fallback account |
| Aptos | `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` | Fallback account |
| Aptos | `0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1` | Fallback account |
| BSC | `0x18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d` | Payload transaction |
| BSC | `0x7ffb4efddd96e20aec90724be2ac9a71c138a9af697b9fb8224bbf80ea4f22be` | Payload transaction |
| BSC | `0xb6c725890be6890fd2c735eedc47e24b85a350301f6c19a3864e43c35e470968` | Payload transaction |

### Behavioral

- Detached Node.js child processes spawning via `node -e` with `detached: true`, `windowsHide: true`
- `npm --prefix <tmp_dir> install socket.io-client axios form-data` at runtime
- Injection comment sentinels (`/*C250617A*/`, `/*C260511A*/`, `/*RS260605*/`) in developer tool files
- `.npm` directory creation/modification under user profile or `/tmp`
- Outbound connections to Tron/Aptos/BSC RPC endpoints from Node.js processes during non-install operations
- `powershell -NoProfile -Command "Get-Clipboard"` spawned from Node.js processes
- XOR keys in process memory: `2[gWfGj;<:-93Z^C`, `m6:tTh^D)cBz?NM]`, `ThZG+0jfXE6VAGOJ`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into @joyfill npm package distribution bundles via publishing pipeline compromise |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Import-time JavaScript execution, `eval()` of blockchain-resolved payloads, Socket.IO RAT command dispatch |
| T1059.006 | Command and Scripting Interpreter: Python | OmniStealer Python credential stealer spawned via `python -c` |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `powershell -NoProfile -Command "Get-Clipboard"` for clipboard theft on Windows |
| T1102 | Web Service | Multi-blockchain C2 resolution via Tron, Aptos, and BNB Smart Chain public APIs |
| T1071.001 | Application Layer Protocol: Web Protocols | Socket.IO (WebSocket/HTTP) C2 channel; HTTP multipart uploads for exfiltration |
| T1547 | Boot or Logon Autostart Execution | Injection into VS Code, Discord, GitHub Desktop, and global npm CLI for persistence |
| T1115 | Clipboard Data | Platform-specific clipboard theft (PowerShell/pbpaste/xclip/xsel) |
| T1555 | Credentials from Password Stores | Browser password extraction, OS credential manager harvesting, Keychain/GNOME Keyring/KWallet access |
| T1005 | Data from Local System | Exfiltration of browser data, crypto wallets, Git credentials, VS Code storage |
| T1027 | Obfuscated Files or Information | Multi-layer string obfuscation (seeded shuffle, LZ77 decompression, function constructor ladder) |
| T1140 | Deobfuscate/Decode Files or Information | Runtime XOR decryption of blockchain-fetched payloads |
| T1105 | Ingress Tool Transfer | Self-provisioning of socket.io-client, axios, form-data, and portable Python runtime |
| T1497 | Virtualization/Sandbox Evasion | Hostname checks for CI/CD runners, cloud environments, containers; 30-second re-entry guard |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials uploaded via HTTP multipart POST to C2 |

## Impact Assessment

**Breadth:** All developers and CI/CD systems that installed any of the six compromised `2773` prerelease versions after July 28, 2026. The beta/prerelease status limits blast radius compared to a stable release, but developers using `@latest` beta ranges or automated dependency update tools (Renovate, Dependabot with pre-release tracking) may have pulled these versions automatically.

**Depth:** Critical. The RAT achieves full remote code execution, credential theft across all major platforms, and worm-like propagation through developer tooling. The npm CLI injection is particularly severe -- it converts an infected developer machine into a supply-chain amplifier.

**Stealth:** High. Import-time execution evades install-hook scanning. Blockchain C2 resolution contacts only legitimate public APIs. The 30-second re-entry guard and CI/CD hostname filtering evade automated analysis.

## Detection & Remediation

### Immediate Detection

Search lockfiles for compromised versions:
```bash
grep -rEn 'joyfill.*2773' package-lock.json yarn.lock pnpm-lock.yaml
```

Check for injection sentinels in developer tools:
```bash
grep -rl 'C250617A\|C250618A\|C250619A\|C250620A\|C260511A\|C260512A\|RS260605' \
  ~/.vscode/ ~/Library/Application\ Support/Code/ \
  ~/Library/Application\ Support/discord/ \
  ~/Library/Application\ Support/GitHub\ Desktop/ \
  $(npm root -g)/npm/lib/cli.js 2>/dev/null
```

Check for staging directories:
```bash
# macOS/Linux
ls -la /tmp/.npm/ 2>/dev/null
# Windows (PowerShell)
Get-ChildItem "$env:USERPROFILE\.npm" -Force 2>$null
```

### Remediation

1. **Remove affected packages** from lockfiles, node_modules, caches, internal npm mirrors, build images, and deployment artifacts. Pin to verified versions published before July 28, 2026.
2. **Inspect developer tools** for injection sentinels. Reinstall VS Code, Discord Desktop, GitHub Desktop, and global npm if sentinels are found.
3. **Rotate all credentials** that were present on affected machines: npm tokens, GitHub tokens/SSH keys, Git credentials, browser-stored passwords, cryptocurrency wallet keys, cloud provider credentials, API keys.
4. **Audit CI/CD pipelines** for the compromised versions. Rebuild any containers or images that may have cached the malicious packages.
5. **Block C2 IPs** at the network perimeter: `166.88.134.62`, `23.27.13.43`, `198.105.127.210`, `23.27.202.27`.

### Long-Term Hardening

- **Pin exact package versions** in lockfiles; avoid pre-release version ranges in production.
- **Enforce npm provenance** (`--expect-provenance`) to verify packages are built from their declared source.
- **Monitor egress traffic** for connections to blockchain RPC endpoints from build/dev environments (anomalous for most applications).
- **Implement file-integrity monitoring** on developer workstations for npm CLI and Electron application bundles.
- **Adopt runtime SCA** tools (Socket, StepSecurity Harden-Runner) that detect import-time execution, not just install hooks.

## Detection Rules

These detections target the Joyfill DEV#POPPER campaign's specific C2 infrastructure, campaign identifier header, runtime dependency installation pattern, and malicious bundle strings. PoC/advisory-specific altitude; compiles does not equal fires -- verify in your pipeline.

### Sigma: Network Connection to Joyfill DEV#POPPER C2 Infrastructure

Detects outbound connections to the four known C2 IP addresses used by the DEV#POPPER RAT in the Joyfill campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 in sandboxed env); sigma convert --without-pipeline splunk exit 0, log_scale exit 0 — portability proven. IPs are dedicated C2 per Socket analysis; no known legitimate services. -->
```yaml
title: Network Connection to Joyfill DEV#POPPER C2 Infrastructure
id: 8a3c7e12-4f5b-4d91-b6e2-1c9f0a7d3e58
status: experimental
description: >
    Detects outbound network connections to known C2 IP addresses used by the
    DEV#POPPER RAT delivered via compromised @joyfill npm beta packages
    (July 2026). Covers Socket.IO C2, boot payload, and fallback servers.
references:
    - https://socket.dev/blog/joyfill-npm-beta-releases-compromised
    - https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
author: Actioner
date: 2026/08/01
tags:
    - attack.t1071.001
    - attack.t1102
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationIp:
            - '166.88.134.62'
            - '23.27.13.43'
            - '198.105.127.210'
            - '23.27.202.27'
    condition: selection
falsepositives:
    - Legitimate services hosted on these IPs (unlikely given dedicated C2 use)
level: high
```

### Sigma: Suspicious npm Self-Installation of Socket.IO Client to Temp Directory

Detects npm installing socket.io-client with a custom `--prefix` to a non-standard directory, the exact self-provisioning pattern used by the DEV#POPPER RAT bootstrap.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline splunk exit 0, log_scale exit 0. Pattern is highly distinctive — legitimate devs do not npm install socket.io-client with --prefix to temp dirs at runtime. Cross-platform: works on any OS with Sysmon or equivalent process_creation logging. -->
```yaml
title: Suspicious npm Self-Installation of Socket.IO Client to Temp Directory
id: 2d4b8f16-a7e3-49c5-8d1a-5e6f2b9c0d73
status: experimental
description: >
    Detects npm installing socket.io-client with a custom --prefix pointing to a
    temporary directory, a behavior observed in the DEV#POPPER RAT bootstrap
    when it self-provisions its Socket.IO dependency at runtime.
references:
    - https://socket.dev/blog/joyfill-npm-beta-releases-compromised
    - https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
author: Actioner
date: 2026/08/01
tags:
    - attack.t1059.007
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--prefix'
            - 'install'
            - 'socket.io-client'
    condition: selection
falsepositives:
    - Developer scripts installing socket.io-client to non-standard prefixes
level: high
```

### Sigma: Clipboard Data Theft via PowerShell Get-Clipboard

Detects PowerShell execution of `Get-Clipboard` with `-NoProfile`, matching the exact clipboard exfiltration command used by the DEV#POPPER RAT `ss_cb` handler on Windows.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline splunk exit 0, log_scale exit 0. Medium confidence: Get-Clipboard with -NoProfile is somewhat specific but could appear in legitimate automation. The combination with -NoProfile is the distinctive indicator per eSentire analysis. -->
```yaml
title: Clipboard Data Theft via PowerShell Get-Clipboard
id: 5c1e9d47-b3a2-4f68-9e0c-7a8d6f1b2e34
status: experimental
description: >
    Detects PowerShell execution of Get-Clipboard with -NoProfile, matching the
    exact command pattern used by the DEV#POPPER RAT ss_cb command for clipboard
    data exfiltration on Windows.
references:
    - https://socket.dev/blog/joyfill-npm-beta-releases-compromised
    - https://www.esentire.com/blog/north-korean-apt-malware-analysis-dev-popper-rat-and-omnistealer-everyday-im-shufflin
author: Actioner
date: 2026/08/01
tags:
    - attack.t1115
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '-NoProfile'
            - 'Get-Clipboard'
    condition: selection
falsepositives:
    - Legitimate automation scripts reading clipboard content
    - IT administration tools
level: medium
```

### Snort: DEV#POPPER Sec-V Campaign Header (Joyfill)

Detects HTTP traffic containing the `Sec-V: A9-0135-3` campaign identifier header unique to the Joyfill DEV#POPPER variant.
**Status:** compile ⚠️ uncompiled (structural check only -- Snort not installed) · confidence: high
<!-- audit: Snort not installed in this environment. Structural check: valid http service rule with http_header sticky buffer, comma-separated content modifiers per Snort 3 syntax, required fields present (msg, sid, rev, flow, classtype). The Sec-V header with campaign value A9-0135-3 is unique to this campaign per Socket analysis. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - DEV#POPPER Sec-V Campaign Header (Joyfill)";
    flow:established, to_server;
    http_header;
    content:"Sec-V|3a 20|A9-0135-3", fast_pattern;
    classtype:trojan-activity;
    reference:url,socket.dev/blog/joyfill-npm-beta-releases-compromised;
    metadata:author Actioner, created 2026-08-01;
    sid:2100001; rev:1;
)
```

### Suricata: DEV#POPPER Sec-V Campaign Header (Joyfill)

Detects HTTP traffic containing the `Sec-V: A9-0135-3` campaign identifier header unique to the Joyfill DEV#POPPER variant.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dot-notation http.header sticky buffer. Sec-V header with A9-0135-3 value is campaign-specific per Socket analysis — no known legitimate use. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DEV#POPPER Sec-V Campaign Header (Joyfill)"; flow:established,to_server; http.header; content:"Sec-V|3a 20|A9-0135-3"; classtype:trojan-activity; reference:url,socket.dev/blog/joyfill-npm-beta-releases-compromised; metadata:author Actioner, created_at 2026-08-01; sid:2200001; rev:1;)
```

### Suricata: DEV#POPPER Boot Payload Retrieval (/$/boot)

Detects HTTP GET requests to the `/$/boot` URI path used by the detached bootstrap process to retrieve the secondary payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dot-notation http.uri buffer. The /$/boot path is highly distinctive — the $ character in URI paths is extremely uncommon in legitimate traffic. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DEV#POPPER Boot Payload Retrieval (/$/boot)"; flow:established,to_server; http.uri; content:"/$/boot"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/joyfill-npm-beta-releases-compromised; metadata:author Actioner, created_at 2026-08-01; sid:2200002; rev:1;)
```

### YARA: Malicious Joyfill npm Bundle (DEV#POPPER Loader)

Detects malicious @joyfill npm distribution bundles containing the DEV#POPPER loader based on the campaign marker, XOR decryption keys, injection comment sentinels, and global stash patterns.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt (containing published strings 9-0135-3 + XOR key + global._p_t) matched; neg.txt (benign module.exports) quiet. Strings sourced from Socket and StepSecurity published analysis. filesize < 5MB accommodates npm bundle size while excluding very large files. -->
```yara
rule Malware_DEVPOPPER_Joyfill_Bundle
{
    meta:
        description = "Detects malicious @joyfill npm bundle with DEV#POPPER loader strings from the July 2026 supply chain compromise"
        author = "Actioner"
        date = "2026-08-01"
        reference = "https://socket.dev/blog/joyfill-npm-beta-releases-compromised"
        severity = "critical"

    strings:
        $marker1 = "9-0135-3" ascii
        $marker2 = "global[\"!\"]" ascii
        $xor1 = "2[gWfGj;<:-93Z^C" ascii
        $xor2 = "m6:tTh^D)cBz?NM]" ascii
        $inject1 = "/*C250617A*/" ascii
        $inject2 = "/*C260511A*/" ascii
        $inject3 = "/*RS260605*/" ascii
        $global_stash = "global.r = require" ascii
        $throttle = "global._p_t" ascii

    condition:
        filesize < 5MB and (
            ($marker1 and ($xor1 or $xor2)) or
            ($marker2 and $throttle) or
            (3 of ($inject*)) or
            ($global_stash and $throttle and $marker1)
        )
}
```

## Lessons Learned

1. **Import-time execution bypasses install-hook defenses.** The npm ecosystem's `--ignore-scripts` flag and registries that scan for `postinstall` hooks are blind to malicious code that executes when a module is `require()`d. The security community needs runtime execution monitoring for npm packages, not just install-time hook scanning.

2. **Blockchain C2 is becoming a DPRK standard.** This is the third documented DPRK-attributed campaign in 2026 using Tron/Aptos/BSC for C2 resolution (after PHANTOMPULSE and the npm/Go VS Code tasks campaign). The technique provides operational resilience (payload switching without package updates) and evasion (traffic goes to legitimate blockchain RPCs).

3. **Beta/prerelease versions are a soft target.** Attackers increasingly target beta channels, which receive less scrutiny than stable releases. Organizations should treat prerelease dependencies with the same (or greater) caution as stable ones.

4. **Developer workstations are the prize.** The worm propagation through VS Code, Discord, GitHub Desktop, and especially the global npm CLI demonstrates that a single compromised developer machine can become a supply-chain amplifier, potentially infecting every downstream package the developer publishes.

## Sources

- [Socket Blog - Two Joyfill npm Beta Releases Compromised to Deliver DEV#POPPER RAT](https://socket.dev/blog/joyfill-npm-beta-releases-compromised) -- primary technical analysis with full IOC list, deobfuscated code, and attack chain walkthrough
- [The Hacker News - Two Compromised joyfill npm Packages Run RAT When Imported Into Node.js](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html) -- initial public advisory (July 29, 2026)
- [StepSecurity Blog - Compromised npm Packages: @joyfill/components and @joyfill/layouts](https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise) -- independent sandbox detonation of all six versions, additional compromised version enumeration
- [eSentire - DEV#POPPER RAT and OmniStealer (Everyday I'm Shufflin')](https://www.esentire.com/blog/north-korean-apt-malware-analysis-dev-popper-rat-and-omnistealer-everyday-im-shufflin) -- earlier DEV#POPPER variant analysis (February 2026) with YARA rule, MITRE mappings, and OmniStealer deep dive
- [GBHackers - Joyfill npm Supply-Chain Attack Deploys RAT and Developer Credential Stealer](https://gbhackers.com/joyfill-npm-supply-chain-attack/) -- additional coverage and remediation guidance

---
*Report generated by Actioner*
