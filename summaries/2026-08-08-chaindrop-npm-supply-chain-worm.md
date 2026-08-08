# Technical Analysis Report: ChainDrop -- Self-Propagating npm Supply Chain Worm (2026-08-08)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-08-08
Version: 1.0 (FINAL)

## Executive Summary

On August 4, 2026, Microsoft Security Blog disclosed **ChainDrop**, a self-propagating worm that compromised **452 unique npm packages across 2,251 versions** -- including the widely-used `keyv` and `cacheable-request` ecosystems collectively serving approximately **2 billion monthly downloads**. The worm propagated by stealing npm maintainer credentials and republishing poisoned package versions with a malicious `preinstall` hook (`setup.mjs`), which bootstraps the **Bun JavaScript runtime** and executes an obfuscated 727 KB credential-stealing payload (`math_init.js` / `Math_Symbol.js`). Unit 42's independent analysis (August 6) confirmed the campaign's scope: 453 public exfiltration repositories across 5 GitHub accounts, with execution observed in 10 distinct environments spanning 4 continents.

ChainDrop's most novel feature is its **Ethereum smart contract-based C2 routing**: the worm queries a deployed `StringListStore` contract (`0xE1f2395ee43e45A1556EC6438a88c31B83493103`) via `eth_call` across ~60 public RPC endpoints to resolve its current C2 domain, making infrastructure takedown significantly harder. The credential-theft scope is extensive -- 300+ harvesting patterns targeting GitHub Actions runner memory (OIDC tokens and masked secrets), cloud provider credentials (AWS, GCP, Azure), developer tooling (npm, Docker, Vault, Kubernetes), SSH keys, and AI coding assistant credentials. Stolen credentials are exfiltrated via AES-256-GCM + RSA-OAEP-SHA256 encrypted HTTPS to `npm-cache[.]com:443/router`, with fallback channels via GitHub commit markers and public repository creation. This campaign is the most advanced wave of the **Shai-Hulud** supply-chain family, building on earlier variants (Mini Shai-Hulud/@antv in May 2026).

Severity: **Critical** -- active self-propagating worm with credential theft, CI/CD compromise, and blockchain-resilient C2 infrastructure.

## Background: npm Ecosystem and the keyv/cacheable Supply Chain

The `keyv` package is a widely-used key-value storage abstraction layer (6M+ weekly downloads) with `cacheable-request` (used by `got`, one of the most popular HTTP libraries in the Node.js ecosystem). Compromise of a single maintainer account in this ecosystem cascades to thousands of dependent projects and CI/CD pipelines. The ChainDrop campaign weaponized this trust chain: poisoned versions published via the compromised maintainer's own GitHub Actions pipelines carried valid digital signatures and SLSA provenance attestations, defeating conventional supply-chain verification.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-11 | Earliest Dune-themed exfiltration repository created |
| 2026-05-22 13:40:28 | js-mirror[.]com registered |
| 2026-05-22 13:40:32 | npm-cache[.]com registered |
| 2026-05-22 13:40:36 | pypi-get[.]com registered |
| 2026-05-22 13:54:59 | FixedFloat transferred 0.01805723 ETH to operator wallet |
| 2026-05-25 | Ethereum StringListStore resolver contract deployed |
| 2026-05-25 (~2.5h post-deploy) | C2 domain list narrowed to npm-cache[.]com only |
| 2026-05-25 (morning) | Transfer of 0.00436 ETH to Binance-labeled deposit address |
| 2026-08-04 | Microsoft Security Blog publishes initial disclosure |
| 2026-08-04 12:20 | Unit 42 discovers 453 public repos with Shai-Hulud marker across 5 GitHub accounts |
| 2026-08-04 15:15:26 | awqhnjewqjkl[.]icu registered via NameSilo |
| 2026-08-04 16:10:03 | First observed connection to new C2 domain |
| 2026-08-04 | Ethereum tx `0xc55920f1...` updates contract with new domain |
| 2026-08-05 (~19h post-rotation) | Network traffic to victim environments observed spanning 4 continents |
| 2026-08-06 | Unit 42 publishes full technical analysis |

## Root Cause: Maintainer Account Compromise and Supply-Chain Injection

The attack began with the compromise of an npm maintainer account with publish access to the `keyv` and `cacheable-request` ecosystems. The compromised account's GitHub Actions CI/CD pipelines were leveraged to build and publish infected versions directly to the npm registry -- producing packages with **valid digital signatures and SLSA provenance attestations**. No corresponding source-code commit, pull request, tag, or legitimate release existed for these publications, indicating direct tarball modification rather than repository compromise.

## Technical Analysis of the Malicious Payload

### 1. Preinstall Loader (setup.mjs -- Bun Bootstrap)

The trojanized `package.json` adds a `"preinstall": "node setup.mjs"` lifecycle hook. `setup.mjs` (SHA256: `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`) performs the following:

1. Checks for the Bun JavaScript runtime; downloads Bun v1.3.13 from `github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` if absent
2. Sets environment variable `_NODE_RUNTIME_INIT=1` to prevent recursive relaunch
3. Feeds the 727 KB obfuscated payload (`math_init.js` / `Math_Symbol.js`) to the Bun runtime
4. On developer workstations: spawns a **detached background process** (allows `npm install` to complete cleanly)
5. In CI environments (detected via CI-specific environment variables): executes **inline** for immediate credential harvesting
6. Locale check: exits with "Exiting as russian language detected!" on Russian-language systems

### 2. Obfuscated Credential Stealer (math_init.js / Math_Symbol.js)

The main payload uses **three obfuscation layers**:

- **Layer 1 -- Base91 Encoding**: 73 function-specific alphabets with 14-position array rotation; analysis recovered 4,613 hidden string entries
- **Layer 2 -- Custom Byte-Permutation Cipher**: PBKDF2-SHA256 with 200,000 iterations and seeded Fisher-Yates shuffles; recovered 727 additional strings
- **Layer 3 -- AES-256-GCM + Gzip**: Protects 10 large encrypted blobs containing bash/Python helpers, persistence installers, GitHub Actions memory scraper, malicious workflow templates, VS Code/Claude persistence files, and RSA public keys

The stealer harvests **300+ credential patterns** across categories:

- **Cloud Credentials**: AWS (16 regions -- SecretsManager, SSM, IAM), Azure, GCP temporary IAM role credentials, metadata endpoint queries
- **Developer Tooling**: Docker/Helm configs, Git credentials, SSH keys, npm tokens, GitHub PATs, Poetry/PyPI/RubyGems credentials, Terraform state files, Vault tokens, Kubernetes service-account tokens and kubeconfigs
- **AI Coding Tools**: Anthropic/Claude, Cursor, OpenAI, Gemini credentials
- **Additional**: .env files, .netrc configs, Bitcoin/Electrum wallet files, Jenkins encrypted credential material, shell history files

### 3. GitHub Actions Runner Memory Scraping

An embedded **Python helper** performs process memory extraction:

1. Locates the `Runner.Worker` PID via `/proc` enumeration
2. Opens `/proc/<pid>/maps` and `/proc/<pid>/mem`
3. Searches live process memory for JSON fragments matching `"isSecret":true`
4. Captures **ephemeral OIDC tokens and every workflow secret** verbatim from runner memory before logs record them
5. Validates extracted tokens against respective service APIs (npm, GitHub, AWS, Vault, Kubernetes)

### 4. C2 Infrastructure

**Primary C2 Channel (Ethereum-based routing):**
- Queries Ethereum smart contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` using `eth_call` with function selector `0x53ed5143` (getter)
- Rotates through ~60 public Ethereum RPC endpoints (including go.getblock.io, eth.llamarpc.com, eth-mainnet.nodereal.io) for resilience
- Operator uses setter function (selector `0xd3c159e5`) to rotate active C2 domains without modifying the malware
- Current active C2: `npm-cache[.]com:443/router` (rotated to `awqhnjewqjkl[.]icu` on Aug 4)

**Encryption Scheme:**
- JSON serialization -> gzip compression -> AES-256-GCM (random 32-byte key, 12-byte IV) -> RSA-OAEP-SHA256 key wrapping with embedded public key
- Only the operator's RSA private key can decrypt harvested data, even with full traffic capture

**Fallback C2 Channels:**
1. **GitHub commit search**: searches for marker `thebeautifulmarchoftime`; expects signed record (prefix `thebeautifulsnadsoftime`) containing backup domain
2. **GitHub repository creation**: creates public repositories under victim GitHub accounts with description `"Shai-Hulud: Here We Go Again"` and Dune-themed naming (e.g., `sardaukar-futar-421`, `harkonnen-ghola-669`); encodes stolen tokens as double-Base64 in commit messages prefixed with `"IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients"`
3. **Remote Code Execution**: C2 response parsed as JSON; returned JavaScript code executed directly (never written to disk); host-derived UUID enables per-victim targeting

### 5. Self-Propagation Mechanism

**Standard Propagation Path:**
1. Enumerates every package the stolen npm account can publish
2. Downloads and reconstructs each package tarball
3. Injects `preinstall` hook into `package.json`
4. Writes dropper (`setup.mjs`) and payload (`math_init.js`) into package
5. Increments patch version
6. Republishes infected package as the current release
7. Result: 444 packages and 2,212 versions poisoned in under 4 hours

**Targeted Typosquatting Path (opensearch-js specific):**
- Triggered only when `GITHUB_REPOSITORY` contains `/opensearch-js` and `GITHUB_WORKFLOW_REF` contains `release-drafter.yml`
- Uses GitHub OIDC trusted publishing to obtain npm credentials without stolen tokens
- Adds typosquatted dependency `@opensearch/setup` pointing to attacker-controlled repository
- Requests Sigstore certificate and OIDC token for code signing
- Generates in-toto SLSA v1 provenance statement, signs with ephemeral P-256 key
- Uploads to public Rekor transparency log; attaches `.sigstore` bundle to publish

### 6. Persistence Mechanisms

**IDE Cross-Linking (VS Code + Claude Code):**
- `.vscode/tasks.json`: task labeled "Environment Setup" with `runOn: folderOpen` executing `node .claude/setup.mjs`
- `.claude/settings.json`: SessionStart command hook executing `node .vscode/setup.mjs`
- Both files committed by `claude <claude@users.noreply.github.com>` to disguise as AI assistant output with message `"chore: update config"`

**Dropped Persistence Files:**
- `.claude/math_init.js`, `.claude/settings.json`, `.claude/setup.mjs`
- `.vscode/setup.mjs`, `.vscode/tasks.json`

**OS-Level Persistence (embedded, latent in analyzed sample):**
- macOS LaunchAgent: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
- Linux systemd user service: `~/.config/systemd/user/gh-token-monitor.service`
- Bash helper: `~/.local/bin/gh-token-monitor.sh`
- Config directory: `~/.config/gh-token-monitor/`
- Polls `api.github.com/user` every 60 seconds for 24 hours; **executes attacker-supplied handler when stolen GitHub token is revoked** (credential rotation becomes a trigger)

**Malicious Workflow Injection:**
- Plants `.github/workflows/codeql_analysis.yml` containing `${{ toJSON(secrets) }}`
- Uploads secrets as artifact named `format-results`
- Follows up with `DELETE /git/refs/heads/*` calls using harvested `ghs_` tokens to cover tracks

### 7. Anti-Forensics / Evasion Techniques

- **Bun runtime usage**: sidesteps Node.js-focused EDR and monitoring hooks
- **Russian locale detection**: exits on Russian-language systems (geographic targeting / safeguard)
- **Detached process**: separates from npm install lifecycle to avoid timeout/detection
- **Environment variable guard**: `_NODE_RUNTIME_INIT=1` prevents recursive execution
- **No disk artifacts for RCE**: C2-served JavaScript code executed in memory, never written to disk
- **Heavy obfuscation**: three-layer encoding (Base91 + byte-permutation cipher + AES-256-GCM)
- **Valid provenance**: published through legitimate CI pipelines with valid Sigstore signatures and SLSA attestations
- **Blockchain C2**: no static domain to sinkhole; contract updates bypass traditional IOC blocking

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0+ (compromised) | Initial infection vector; preinstall hook added |
| cacheable-request | compromised versions | Part of the infected ecosystem |
| flat-cache | compromised versions | Part of the infected ecosystem |
| cache-manager | compromised versions | Part of the infected ecosystem |
| 452 npm packages total | 2,251 malicious versions | Full scope of self-propagation |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross-platform | setup.mjs (preinstall loader) | 54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668 | Bun bootstrap dropper |
| Cross-platform | setup.mjs (repo loader) | fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb | Repository persistence dropper |
| Cross-platform | math_init.js / Math_Symbol.js | 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc | Obfuscated credential stealer payload |
| Cross-platform | setup.mjs (TLSH variant) | b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678 | TLSH-based variant dropper |
| Cross-platform | .claude/settings.json | -- | Claude Code SessionStart persistence hook |
| Cross-platform | .claude/setup.mjs | -- | Claude Code payload loader |
| Cross-platform | .vscode/tasks.json | -- | VS Code folderOpen persistence task |
| Cross-platform | .vscode/setup.mjs | -- | VS Code payload loader |
| macOS | ~/Library/LaunchAgents/com.user.gh-token-monitor.plist | -- | LaunchAgent persistence |
| Linux | ~/.config/systemd/user/gh-token-monitor.service | -- | Systemd user service persistence |
| Linux | ~/.local/bin/gh-token-monitor.sh | -- | Token monitoring bash helper |
| Cross-platform | ~/.config/gh-token-monitor/ | -- | Token monitor configuration directory |
| Cross-platform | .github/workflows/codeql_analysis.yml | -- | Malicious workflow for secrets exfiltration |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npm-cache[.]com | Primary C2 domain |
| Domain | awqhnjewqjkl[.]icu | Rotated C2 domain (DGA-style, Aug 4) |
| Domain | pypi-get[.]com | Historical C2 domain (inactive) |
| Domain | js-mirror[.]com | Historical C2 domain (inactive) |
| URL Pattern | hxxps://npm-cache[.]com:443/router | Primary C2 exfiltration endpoint |
| URL Pattern | hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum | Fallback C2 endpoint |
| IP | 104.21.91[.]101 | awqhnjewqjkl[.]icu (Cloudflare) |
| IP | 172.67.215[.]154 | awqhnjewqjkl[.]icu (Cloudflare) |
| Ethereum Contract | 0xE1f2395ee43e45A1556EC6438a88c31B83493103 | C2 resolver contract (StringListStore) |
| Ethereum Wallet | 0x55f9780e1492344b7417fa723aedc4d0b97f31cd | Operator wallet |
| Ethereum Wallet | 0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B | Binance deposit address |
| Ethereum Tx | 0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91 | C2 rotation transaction |
| Function Selector | 0x53ed5143 | Contract getter (C2 resolution) |
| Function Selector | 0xd3c159e5 | Contract setter (C2 rotation) |

### Behavioral

- **Process chain**: `node setup.mjs` -> `bun math_init.js` (detached, with `_NODE_RUNTIME_INIT=1`)
- **CI detection**: differentiates CI (inline) vs. developer workstation (detached process)
- **Runner.Worker memory scraping**: `python3` reading `/proc/<pid>/mem` for `"isSecret":true` patterns
- **Credential harvesting commands**: `gh auth token`, `gcloud config`, `az account get-access-token`, `azd auth token`
- **Exfiltration repository markers**: description `"Shai-Hulud: Here We Go Again"`, Dune-themed repo names
- **Git commit markers**: `thebeautifulmarchoftime`, `thebeautifulsnadsoftime`, `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- **Commit author masquerade**: `claude <claude@users.noreply.github.com>` with `"chore: update config"`
- **Cloudflare stylesheet hash** (shared across C2 domains): `d30b4ea6f68456672f5abb35e9dcf7d54226372b66e9d60a7ee26b7a52568e74`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Malicious preinstall hooks injected into 452 npm packages; republished with patch version increments |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated math_init.js/Math_Symbol.js executed via Bun runtime |
| T1059.006 | Command and Scripting Interpreter: Python | Python helper used for Runner.Worker process memory scraping |
| T1528 | Steal Application Access Token | Harvests GitHub PATs, npm tokens, OIDC tokens, cloud provider tokens |
| T1555 | Credentials from Password Stores | Scans filesystem for SSH keys, .env files, cloud configs, Vault tokens, Kubernetes secrets |
| T1003.007 | OS Credential Dumping: Proc Filesystem | Reads /proc/<pid>/mem of Runner.Worker to extract workflow secrets |
| T1547 | Boot or Logon Autostart Execution | VS Code tasks.json (folderOpen) and Claude Code settings.json (SessionStart) persistence |
| T1543 | Create or Modify System Process | LaunchAgent (macOS) and systemd user service (Linux) for gh-token-monitor |
| T1027 | Obfuscated Files or Information | Three-layer obfuscation: Base91 + byte-permutation cipher + AES-256-GCM |
| T1041 | Exfiltration Over C2 Channel | AES-256-GCM + RSA-OAEP encrypted data sent to npm-cache[.]com:443/router |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | DGA-style domain awqhnjewqjkl[.]icu; Ethereum contract-based C2 resolution |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication via /router endpoint |
| T1567 | Exfiltration Over Web Service | GitHub repository creation and commit-based exfiltration channels |
| T1070 | Indicator Removal | DELETE /git/refs/heads/* to remove evidence branches; code executed in memory only |

## Impact Assessment

- **Breadth**: 452 unique packages, 2,251 malicious versions, ~2 billion monthly downloads across affected packages; known compromised organizations include Deliveroo, Ornikar, OneReach, Picsart, Qlik, and ServiceTitan
- **Depth**: Full credential harvesting across cloud providers, CI/CD systems, AI tools, and developer environments; process memory scraping captures ephemeral secrets
- **Stealth**: Valid digital signatures, SLSA provenance attestations, Ethereum-based C2 rotation, three-layer obfuscation, memory-only RCE payloads
- **Propagation velocity**: 444 packages and 2,212 versions poisoned in under 4 hours
- **Persistence**: IDE hooks survive across project reopens; gh-token-monitor turns credential rotation into a destructive trigger

## Detection & Remediation

### Immediate Detection

```bash
# Check for ChainDrop persistence files in repositories
find . -path '*/.claude/setup.mjs' -o -path '*/.claude/math_init.js' \
       -o -path '*/.vscode/setup.mjs' -o -name 'gh-token-monitor.sh' 2>/dev/null

# Check for malicious Claude Code hooks
grep -r 'setup.mjs' .claude/settings.json .vscode/tasks.json 2>/dev/null

# Check for Shai-Hulud exfiltration repositories on your GitHub accounts
gh repo list --json name,description | jq '.[] | select(.description | contains("Shai-Hulud"))'

# Check for malicious workflows
grep -r 'toJSON(secrets)' .github/workflows/ 2>/dev/null

# Check npm package integrity
npm audit signatures

# Check for gh-token-monitor persistence
ls -la ~/.config/systemd/user/gh-token-monitor.service \
       ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
```

### Remediation

1. **Containment**: Block C2 domains (`npm-cache[.]com`, `awqhnjewqjkl[.]icu`) via DNS sinkhole/TLS SNI filtering (prefer sinkholing over HTTP blocks since the worm uses HTTPS)
2. **Credential rotation**: Rotate ALL potentially exposed credentials -- npm tokens, GitHub PATs/OIDC tokens, AWS/GCP/Azure keys, SSH keys, Vault tokens, Kubernetes service-account tokens, Docker credentials. **Caution**: rotating GitHub tokens may trigger the gh-token-monitor destructive handler; disable the systemd/LaunchAgent service first
3. **Package remediation**: Pin to known-clean versions of affected packages; use `npm install --ignore-scripts` until verified clean; remove and reinstall affected dependencies
4. **Repository cleanup**: Remove `.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/setup.mjs`, malicious workflow files; check for unauthorized commits by `claude@users.noreply.github.com`
5. **Monitor Ethereum contract**: Watch `0xE1f2395ee43e45A1556EC6438a88c31B83493103` for `setStrings()` calls (selector `0xd3c159e5`) indicating new C2 domain rotation

### Long-Term Hardening

- **Install script blocking**: Use `npm install --ignore-scripts` or `npm ci --ignore-scripts` by default; selectively allow known-good scripts
- **Minimum release age policies**: npm 11.10+ `min-release-age`, pnpm 10.16+ `minimumReleaseAge`, Yarn 4.10+ `npmMinimalAgeGate`, Bun 1.3+ `minimumReleaseAge` -- a 3-7 day cooldown prevents automatic adoption of freshly-published malicious versions
- **Ephemeral CI runners**: Deploy ephemeral (single-use) CI runners instead of persistent self-hosted runners to limit secret exposure
- **Workload identity binding**: Bind authentication to workload identities (SPIFFE mutual TLS, cloud IAM roles) instead of long-lived tokens
- **Canary credentials**: Plant canary tokens in developer environments for early detection of credential theft
- **Strict egress policies**: Restrict CI/CD egress to known-required endpoints; monitor for Ethereum RPC calls from build environments

## Detection Rules

These detections target ChainDrop's distinctive artifacts at PoC/advisory-specific altitude: the Bun-based execution chain, Runner.Worker memory scraping, IDE persistence files, C2 domain beaconing, and Ethereum contract-based C2 resolution. `sigma check` could not run (MITRE ATT&CK data fetch blocked by proxy), but all Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale. **TLS inspection caveat:** the worm's primary C2 uses HTTPS (port 443); HTTP-inspection Snort and Suricata rules for `npm-cache[.]com` and `awqhnjewqjkl[.]icu` require TLS decryption to inspect request content. The DNS query rule (`sid:2200012`) provides coverage without TLS inspection. Compiles != fires -- verify in your pipeline.

### Sigma: ChainDrop Bun Runtime Payload Execution

Detects the Bun runtime executing the campaign's `math_init.js` or `Math_Symbol.js` payload files.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Field names are standard process_creation/linux. Strings are campaign-specific filenames from Unit42/MSRC publications. FP risk: near-zero — these filenames are campaign artifacts. -->
```yaml
title: ChainDrop Worm - Bun Runtime Executing Malicious Payload
id: 7a3c1e9f-4b2d-48a6-9f5e-1c8d3a6b7e20
status: experimental
description: >
    Detects the ChainDrop npm worm execution chain where the Bun JavaScript
    runtime is used to execute the obfuscated math_init.js or Math_Symbol.js
    payload files, characteristic of the August 2026 supply-chain campaign.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/08
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_bun:
        Image|endswith: '/bun'
    selection_payload:
        CommandLine|contains:
            - 'math_init.js'
            - 'Math_Symbol.js'
    condition: selection_bun and selection_payload
falsepositives:
    - Unlikely - these filenames are specific to ChainDrop campaign artifacts
level: high
```

### Sigma: ChainDrop NPM Preinstall setup.mjs Dropper

Detects Node.js executing `setup.mjs` as an npm preinstall hook, the initial dropper mechanism. Scope to CI/build systems or developer workstations with npm activity to reduce noise.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked (ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence because setup.mjs is a plausible (though uncommon) legitimate filename; the ParentCommandLine npm anchor narrows it. -->
```yaml
title: ChainDrop Worm - NPM Preinstall Executing setup.mjs Dropper
id: 2d8f5a1c-9e3b-47d0-8c6f-4a5b2e7d9f31
status: experimental
description: >
    Detects Node.js executing setup.mjs as a preinstall hook, the initial
    dropper mechanism used by ChainDrop to bootstrap the Bun runtime and
    launch the obfuscated credential-stealing payload.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/08
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/node'
            - '/npm'
        CommandLine|contains: 'setup.mjs'
    selection_env:
        ParentCommandLine|contains: 'npm'
    condition: selection and selection_env
falsepositives:
    - Legitimate npm packages using setup.mjs as a preinstall script (uncommon naming)
level: medium
```

### Sigma: ChainDrop Runner.Worker Memory Scraping

Detects the Python helper reading `/proc/*/mem` of the GitHub Actions Runner.Worker process to extract OIDC tokens and masked secrets. Detection gap: `Runner.Worker` and `isSecret` are search strings inside the dropped Python script, not CLI arguments -- this rule fires only if the helper is invoked inline via `python3 -c`; a dropped temp-file execution will match only `selection_python` + `selection_proc_mem`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked (ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Downgraded from high to medium per critic review: Runner.Worker and isSecret are string literals searched inside the Python helper code, not CLI args. The helper is likely executed as a dropped temp file or piped to stdin, so CommandLine won't contain these strings. Rule fires fully only if helper is passed via python3 -c inline (unlikely for 727KB payload). selection_proc_mem alone (python + /proc/*/mem) is the reliable anchor; selection_context narrows but may not match in practice. -->
<!-- revision: confidence high→medium; tag T1003→T1003.007; added detection-gap caveat per critic verdict. -->
```yaml
title: ChainDrop Worm - GitHub Actions Runner Memory Scraping
id: 5e9b3c7a-1d4f-42e8-a6b0-8f2c5d3e1a94
status: experimental
description: >
    Detects the ChainDrop Python helper reading /proc/*/mem of the GitHub Actions
    Runner.Worker process to extract OIDC tokens and runner secrets from live
    process memory. Note: Runner.Worker and isSecret are search strings inside the
    helper script; this rule fires fully only if the helper is passed inline via
    python3 -c rather than as a dropped temp file.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/08
tags:
    - attack.t1003.007
    - attack.t1528
logsource:
    category: process_creation
    product: linux
detection:
    selection_python:
        Image|endswith:
            - '/python3'
            - '/python'
    selection_proc_mem:
        CommandLine|contains|all:
            - '/proc/'
            - '/mem'
    selection_context:
        CommandLine|contains:
            - 'Runner.Worker'
            - 'isSecret'
    condition: selection_python and selection_proc_mem and selection_context
falsepositives:
    - Debugging tools legitimately inspecting Runner.Worker process memory
level: medium
```

### Sigma: ChainDrop Claude/VSCode Cross-Persistence File Creation

Detects creation of the ChainDrop cross-linked persistence files in `.claude/` and `.vscode/` directories.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. High confidence: setup.mjs under .claude/ is not a standard Claude Code artifact; math_init.js under .claude/ is campaign-specific. file_event category requires Sysmon or equivalent. -->
```yaml
title: ChainDrop Worm - Claude/VSCode Cross-Persistence File Creation
id: 8c4d2f6e-3a1b-49e7-b5d0-7e9f1c8a4b62
status: experimental
description: >
    Detects creation of the ChainDrop cross-linked persistence files that abuse
    VS Code tasks.json and Claude Code settings.json to re-execute the worm
    payload when either IDE opens a project folder.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/08
tags:
    - attack.t1547
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection_claude:
        TargetFilename|endswith:
            - '/.claude/setup.mjs'
            - '/.claude/math_init.js'
    selection_vscode:
        TargetFilename|endswith:
            - '/.vscode/setup.mjs'
    condition: selection_claude or selection_vscode
falsepositives:
    - Legitimate Claude Code or VS Code extension creating setup.mjs files (very rare)
level: high
```

### Snort: ChainDrop C2 Beacon to npm-cache.com

Detects outbound HTTP traffic to the primary ChainDrop C2 domain `npm-cache.com` with the `/router` exfiltration endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort_test.conf -T exit 0. Snort 2.9.20. Campaign-specific domain+path combination. Requires HTTP inspection enabled. TLS inspection required: worm uses HTTPS (port 443); without TLS decryption this rule cannot inspect request content. DNS-based detection (Suricata sid:2200012) covers the gap. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChainDrop C2 Beacon to npm-cache.com"; flow:established,to_server; content:"npm-cache.com"; http_header; fast_pattern; content:"/router"; http_uri; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; sid:2100010; rev:1;)
```

### Snort: ChainDrop Ethereum C2 Resolver Function Selector

Detects Ethereum JSON-RPC `eth_call` requests containing the ChainDrop resolver contract's getter function selector `0x53ed5143`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c snort_test.conf -T exit 0. Snort 2.9.20. The function selector is specific to this contract but eth_call traffic through HTTP may be seen in blockchain-heavy environments. FP: legitimate calls to the same contract (unlikely outside crypto/DeFi infra). -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChainDrop Ethereum C2 Resolver eth_call Selector 0x53ed5143"; flow:established,to_server; content:"0x53ed5143"; fast_pattern; content:"eth_call"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; sid:2100011; rev:1;)
```

### Suricata: ChainDrop C2 Beacon to npm-cache.com /router

Detects HTTP traffic to the primary ChainDrop C2 domain with the `/router` exfiltration path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Suricata 7.0.3. Uses dot-notation sticky buffers (http.host, http.uri). Campaign-specific domain+path. TLS inspection required: worm uses HTTPS (port 443); without TLS decryption this rule cannot inspect HTTP content. DNS-based detection (sid:2200012) covers the gap. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop C2 Beacon to npm-cache.com /router"; flow:established,to_server; http.host; content:"npm-cache.com"; http.uri; content:"/router"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-08; sid:2200010; rev:1;)
```

### Suricata: ChainDrop DGA C2 Domain awqhnjewqjkl.icu

Detects HTTP traffic to the rotated ChainDrop DGA-style C2 domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Suricata 7.0.3. Direct domain IOC match. Short shelf-life if operator rotates again via Ethereum contract. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop DGA C2 Domain awqhnjewqjkl.icu"; flow:established,to_server; http.host; content:"awqhnjewqjkl.icu"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-08; sid:2200011; rev:1;)
```

### Suricata: ChainDrop DNS Query for C2 Domain

Detects DNS resolution queries for the primary ChainDrop C2 domain `npm-cache.com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Suricata 7.0.3. Uses dns.query sticky buffer. Direct domain IOC match. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop DNS Query for C2 Domain npm-cache.com"; dns.query; content:"npm-cache.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-08; sid:2200012; rev:1;)
```

### Suricata: ChainDrop Ethereum C2 Resolver Function Selector

Detects Ethereum JSON-RPC `eth_call` containing the ChainDrop resolver contract getter selector `0x53ed5143` in the HTTP request body.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (after fixing duplicate http.request_body buffer). Suricata 7.0.3. FP risk in crypto/DeFi environments that interact with Ethereum contracts. The specific function selector narrows it substantially. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Ethereum C2 Resolver Function Selector 0x53ed5143"; flow:established,to_server; http.request_body; content:"0x53ed5143"; fast_pattern; content:"eth_call"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-08; sid:2200013; rev:1;)
```

### YARA: ChainDrop setup.mjs Dropper

Detects the ChainDrop `setup.mjs` dropper by its distinctive string combination: the `_NODE_RUNTIME_INIT` environment variable guard, Bun download URL pattern, and payload filenames.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on constructed positive (containing published campaign strings from Unit42); quiet on benign JS negative. String combination is campaign-specific: _NODE_RUNTIME_INIT + oven-sh/bun/releases/download + math_init.js/Math_Symbol.js + detached is unique to ChainDrop. -->
```yara
rule ChainDrop_SetupMjs_Dropper
{
    meta:
        description = "Detects ChainDrop npm worm setup.mjs dropper that bootstraps the Bun runtime and launches the obfuscated credential-stealing payload"
        author = "Actioner"
        date = "2026-08-08"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        severity = "high"

    strings:
        $env_marker = "_NODE_RUNTIME_INIT" ascii
        $bun_dl = "oven-sh/bun/releases/download" ascii
        $payload1 = "math_init.js" ascii
        $payload2 = "Math_Symbol.js" ascii
        $detach = "detached" ascii

    condition:
        filesize < 100KB and
        $env_marker and
        $bun_dl and
        ($payload1 or $payload2) and
        $detach
}
```

### YARA: ChainDrop Math_Init Payload Strings

Detects the ChainDrop obfuscated payload by campaign-specific markers: Shai-Hulud strings, Ethereum contract address, GitHub commit markers, and the Russian locale check.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on constructed positive (3 of: Shai-Hulud, thebeautifulmarchoftime, Ethereum contract address); quiet on benign JS negative. The 3-of-8 threshold with campaign-unique strings provides high specificity. -->
```yara
rule ChainDrop_MathInit_Payload
{
    meta:
        description = "Detects the ChainDrop obfuscated math_init.js/Math_Symbol.js payload containing Base91-encoded credential stealer and propagation logic"
        author = "Actioner"
        date = "2026-08-08"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "Shai-Hulud" ascii nocase
        $marker2 = "thebeautifulmarchoftime" ascii
        $marker3 = "thebeautifulsnadsoftime" ascii
        $marker4 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $eth_selector = "0x53ed5143" ascii
        $c2_domain = "npm-cache.com" ascii
        $exiting_ru = "Exiting as russian language detected" ascii nocase

    condition:
        filesize < 1MB and
        3 of them
}
```

## Lessons Learned

1. **Blockchain-based C2 is a growing evasion technique**: ChainDrop's use of an Ethereum smart contract for C2 domain resolution makes traditional domain-based blocking insufficient. Defenders must monitor for Ethereum RPC `eth_call` patterns from non-crypto infrastructure and consider blockchain-aware threat intelligence.

2. **Valid provenance does not guarantee safety**: The worm published through legitimate CI/CD pipelines with valid Sigstore signatures and SLSA attestations, defeating supply-chain verification mechanisms. Minimum release age policies and install-script restrictions are more effective structural defenses than signature verification alone.

3. **Credential rotation can be weaponized**: The gh-token-monitor persistence component executes an attacker-supplied handler upon detecting token revocation -- turning the standard incident response action of credential rotation into a destructive trigger. Defenders must disable persistence mechanisms before rotating credentials.

4. **AI coding assistants are now persistence vectors**: The cross-linked VS Code/Claude Code persistence mechanism demonstrates that AI assistant configuration files are viable attack surfaces. Security teams should include `.claude/` and `.vscode/` directories in repository security scanning.

5. **Process memory scraping bypasses secret masking**: GitHub Actions' secret masking only applies to log output; secrets remain in plaintext in runner process memory. Ephemeral runners that are destroyed after each job are the most effective mitigation.

## Sources

- [Unit 42 - ChainDrop: Inside a Self-Propagating npm Worm](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) -- primary technical analysis with full IOC set, obfuscation layer breakdown, and Ethereum C2 infrastructure analysis
- [Microsoft Security Blog - ChainDrop Supply Chain Compromise: Anatomy of a Self-Propagating Worm](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) -- initial disclosure with Defender detection signatures, advanced hunting queries, and remediation guidance
- [Elastic Security Labs - Shai-Hulud Strikes Again: CHAINDROP Worm Hits 400+ npm Packages](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain) -- additional IOCs, DNS fallback provider list, and credential targeting scope details
- [StepSecurity - ChainDrop npm Worm: Bun-loaded CI/CD Credential Harvester with Ethereum Dead-Drop C2](https://www.stepsecurity.io/blog/chaindrop-npm-worm) -- CI/CD hardening specifics, minimum release age policies, and gh-token-monitor destructive handler analysis
- [Actioner Prior Coverage - Mini Shai-Hulud @antv Wave (2026-05-30)](summaries/2026-05-30-npm-mini-shai-hulud-antv.md) -- earlier Shai-Hulud variant analysis for campaign lineage context

---
*Report generated by Actioner*
