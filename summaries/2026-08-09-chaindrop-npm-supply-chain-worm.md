# Technical Analysis Report: ChainDrop npm Supply Chain Worm (2026-08-09)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-09
Version: DRAFT

## Executive Summary

ChainDrop is a self-propagating npm supply chain worm that has compromised over 400 npm packages (1,684 poisoned versions across 420 package names tied to nine organizations) downloaded hundreds of millions of times weekly. The worm arrives via malicious `preinstall` lifecycle hooks in npm packages, drops a 727KB obfuscated Bun-based JavaScript payload, and systematically harvests credentials from cloud providers, developer tooling, and CI/CD environments. It uses Ethereum smart contract-based command-and-control for dynamic domain resolution, and installs cross-linked persistence hooks in Claude Code (`.claude/settings.json`) and VS Code (`.vscode/tasks.json`) project directories. The earliest confirmed compromise dates to May 11, 2026, with active propagation observed as recently as August 4, 2026. The worm has been linked to the "Shai-Hulud" malware family, with connections to the previously observed TeamPCP toolchain. Attribution remains uncertain.

## Background: npm Supply Chain Ecosystem

npm is the world's largest software package registry, serving millions of JavaScript and Node.js developers. The ecosystem's dependency model means a single compromised package can cascade into thousands of downstream projects. npm lifecycle hooks (such as `preinstall`, `postinstall`) execute arbitrary code during package installation, providing a powerful attack surface. The ChainDrop campaign exploits this model, using stolen npm publishing tokens to modify and republish legitimate packages with malicious payloads, creating a worm-like propagation pattern across the entire registry.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-11 | Earliest confirmed package compromise |
| 2026-05-22 13:40:28 | Three C2 domains registered within 8 seconds (js-mirror[.]com, npm-cache[.]com, pypi-get[.]com) |
| 2026-05-22 13:54:51 | FixedFloat transferred 0.01805723 ETH to fund operations |
| 2026-05-25 | Ethereum C2 resolver contract deployed |
| 2026-05-25 (+2h35m) | Domain list narrowed to npm-cache[.]com |
| 2026-07-27 | NullReceiver/PolinRider blockchain C2 transactions begin |
| 2026-08-04 | keyv@6.0.0 poisoned release published |
| 2026-08-04 15:15:26 | awqhnjewqjkl[.]icu registered via NameSilo |
| 2026-08-04 16:10:03 | First observed connection to awqhnjewqjkl[.]icu |
| 2026-08-04 | 546 GitHub repositories created with "Shai-Hulud: Here We Go Again" description |
| 2026-08-04 | SafeDep verifies 353 poisoned versions across 79 packages |
| 2026-08-04 (~19h later) | Network traffic to victim environments observed |
| 2026-08-09 | Updated count: 1,684 poisoned versions across 420 packages in 9 organizations |

## Root Cause: Stolen npm Maintainer Credentials

Initial access was achieved through stolen npm maintainer credentials. Once a single token was obtained, the worm's propagation routine automated the compromise: it enumerated all packages the stolen token could publish, downloaded each, injected the malware payload and preinstall hook, incremented the patch version, and republished the package. This created a cascading, self-propagating infection -- one stolen token could poison every package writeable by that maintainer account. Evidence suggests the worm moved between organizations every two to seven minutes, completing cross-organization publishing bursts in roughly half an hour.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery -- Preinstall Hook and Setup Dropper

The worm modifies the target package's `package.json` to add a preinstall lifecycle hook:

```json
"preinstall": "node setup.mjs"
```

The `setup.mjs` dropper (SHA256: `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` for npm tarball variant; `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` for repository variant) checks for the Bun runtime (version 1.3.13), downloads it from legitimate Oven GitHub repositories if missing, then executes the main payload. The dropper sets `_NODE_RUNTIME_INIT=1` as an environment variable to prevent recursive launches.

### 2. Main Payload -- Obfuscated Bun Bundle (math_init.js / Math_Symbol.js)

The primary payload is a 727,680-byte compiled Bun bundle (SHA256: `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`) with three layers of obfuscation:

**Layer 1 -- Base91 Encoding:** 73 function-specific alphabets with 14-position array rotation, concealing 4,613 hidden string entries.

**Layer 2 -- Custom Byte-Permutation Cipher:** PBKDF2-SHA256 with 200,000 iterations seeding Fisher-Yates shuffles, hiding 727 additional strings.

**Layer 3 -- AES-256-GCM + GZIP:** 10 large encrypted blobs containing bash/Python helpers, persistence installers, the GitHub Actions memory scraper, malicious workflow templates, VS Code/Claude configuration files, RSA public keys, and dropper copies.

**Environment-Aware Execution:**
- On developer workstations: spawns as a detached background process
- On CI/CD runners: runs inline to capture active workflow credentials and job logs
- On Russian-language systems: silently exits without stealing data

**Credential Harvesting Targets:**
- Cloud metadata endpoints (AWS, Azure, GCP, Kubernetes)
- npm tokens and `.npmrc` files
- GitHub PATs via `gh auth token`
- SSH keys, Docker/Helm configurations
- Poetry, PyPI, RubyGems, Terraform state, Vault tokens
- Jenkins encrypted materials
- Claude Code and VS Code configurations
- `.env` files, shell histories, Bitcoin/Electrum wallet files
- Kubernetes kubeconfigs and service-account tokens

The malware actively validates stolen credentials by calling service APIs, verifying access, and retrieving additional secrets permitted to those identities.

### 3. C2 Infrastructure

**Ethereum Smart Contract Domain Resolution:**
The worm resolves its active C2 domain from an Ethereum smart contract at address `0xE1f2395ee43e45A1556EC6438a88c31B83493103` using getter function selector `0x53ed5143`. The contract implements a `StringListStore` pattern with getter/setter functions. The worm rotates through approximately 60 public Ethereum RPC endpoints for resilience. The operator wallet is `0x55f9780e1492344b7417fa723aedc4d0b97f31cd`, with a Binance deposit pivot address at `0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B`.

**Active C2 Domains:**
- `npm-cache[.]com` (primary, active during analysis)
- `awqhnjewqjkl[.]icu` (deployed Aug 4, 2026 via on-chain transaction `0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91`)

**Historical C2 Domains:**
- `pypi-get[.]com`
- `js-mirror[.]com`

**Exfiltration Endpoints:**
- Primary: `hxxps://npm-cache[.]com:443/router`
- Backup: `hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum?`
- Both proxied through Cloudflare CDN (block on domain/SNI, not IP)

**Cloudflare IP Destinations:** `104[.]21[.]91[.]101`, `172[.]67[.]215[.]154`

**TLS Certificate (awqhnjewqjkl[.]icu):**
- Issuer: Google Trust Services (WE1)
- Valid: Aug 4 -- Nov 2, 2026
- SANs: awqhnjewqjkl[.]icu, *.awqhnjewqjkl[.]icu

**GitHub Commit Fallback C2:**
If primary C2 fails, the malware searches GitHub commits for the marker `thebeautifulmarchoftime` and expects a signed record containing a backup domain. During analysis, this fallback was unarmed (no valid operator record found).

**Data Encryption:**
Stolen data is JSON-serialized, GZIP-compressed, encrypted with AES-256-GCM (random key), then the AES key is RSA-OAEP-SHA256 wrapped using an embedded RSA public key. Each exfiltration includes a host-derived UUID for per-victim targeting.

**Remote Code Execution:**
Server responses are parsed as JSON and evaluated as JavaScript, providing an operator-controlled RCE channel. No fixed second-stage payload; the operator chooses code at request time. Code is never written to disk.

### 4. Propagation Mechanisms

**Primary -- npm Token-Based Republication:**
1. Enumerates all packages writeable by the compromised npm token
2. Checks for 2FA bypass capability
3. Downloads each package's latest tarball
4. Injects `setup.mjs` dropper and `math_init.js` payload
5. Adds `preinstall: node setup.mjs` to `package.json`
6. Increments patch version
7. Republishes (maintaining legitimate functionality)

**Credential Exfiltration via GitHub:**
- Creates public repositories under victim accounts with description: "Shai-Hulud: Here We Go Again"
- Uses Dune-themed naming: sardaukar, mentat, fremen, atreides, harkonnen variants
- Base64-encodes stolen tokens twice, commits with prefix: `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- A secondary routine searches the GitHub commit API for matching markers, double-decodes tokens for credential sharing across worm instances

**GitHub Actions OIDC-Based Publishing (Advanced Path, Not Observed Executing):**
- Targets repositories with `release-drafter.yml` workflows
- Requests OIDC token with audience `npm:registry.npmjs.org`
- Trades OIDC for npm publish credential via trusted-publishing endpoint
- Modifies package by adding typosquatting dependency
- Obtains Sigstore certificate via second OIDC token
- Constructs valid SLSA v1 in-toto provenance statement
- DSSE-signs with ephemeral P-256 key
- Uploads entry to Rekor transparency log
- Result: packages published with valid provenance from a legitimate workflow identity

**GitHub Actions Memory Exploitation:**
An embedded Python helper reads `/proc/<pid>/maps` and `/proc/<pid>/mem` of the Runner.Worker process to extract OpenID Connect (OIDC) tokens and runner secrets from live process memory -- capturing credentials designed to vanish after job completion. Also deploys `.github/workflows/codeql_analysis.yml` that serializes `${{ toJSON(secrets) }}` as a GitHub Actions artifact.

### 5. Persistence Mechanisms

**IDE Cross-Linking (Claude Code / VS Code):**
- `.claude/settings.json`: `SessionStart` hook running `node .vscode/setup.mjs`
- `.vscode/tasks.json`: `Environment Setup` task executing `node .claude/setup.mjs` (configured with `runOn: folderOpen`)
- `.claude/setup.mjs` and `.vscode/setup.mjs`: dropper copies
- `.claude/math_init.js`: payload copy
- Cross-referenced paths create mutual dependencies obscuring origins; each tool's directory appears to contain setup files for the other

**OS-Level Persistence (Latent, Not Observed Activated):**
- macOS LaunchAgent: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
- Linux systemd user service: `~/.config/systemd/user/gh-token-monitor.service`
- Shell script: `~/.local/bin/gh-token-monitor.sh`
- Configuration directory: `~/.config/gh-token-monitor/`

**Token Revocation Watcher:**
A monitoring component maintains credential access and contains a destructive handler triggered if a monitored token is revoked. SafeDep explicitly warned responders to remove the credential-revocation watcher before rotating exposed tokens.

### 6. Anti-Forensics / Evasion Techniques

- Three-layer obfuscation (Base91 + custom byte-permutation cipher + AES-256-GCM)
- Russian-language host detection and silent exit (anti-forensics / geofencing)
- RCE code never written to disk (memory-only execution)
- Environment variable guard (`_NODE_RUNTIME_INIT=1`) to prevent recursive execution
- Cloudflare CDN proxying of C2 domains (IP-based blocking ineffective)
- Blockchain-based domain resolution (domains updated without malware redeployment)
- Legitimate Bun runtime download from official GitHub repositories
- Patch-version increment without corresponding source commits or pull requests
- Valid SLSA provenance and Sigstore signatures in advanced path (provenance-poisoning)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0 | Poisoned preinstall hook executing `node setup.mjs` |
| flat-cache | Affected versions not specified | Poisoned via same propagation mechanism |
| cache-manager | Affected versions not specified | Poisoned via same propagation mechanism |
| 420+ additional packages | Various patch increments | Worm auto-propagated across 9 organizations |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross-platform | Math_Symbol.js / math_init.js | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Main obfuscated payload (727,680 bytes) |
| Cross-platform | setup.mjs (npm tarball) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | Preinstall dropper (npm tarball variant) |
| Cross-platform | setup.mjs (repository) | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | Repository loader variant |
| Cross-platform | setup.mjs (TLSH variant) | `b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678` | Third observed variant |
| Cross-platform | .claude/settings.json | -- | SessionStart hook persistence |
| Cross-platform | .claude/setup.mjs | -- | Dropper in Claude Code directory |
| Cross-platform | .vscode/tasks.json | -- | VS Code task-based persistence |
| Cross-platform | .vscode/setup.mjs | -- | Dropper in VS Code directory |
| Cross-platform | .github/workflows/codeql_analysis.yml | -- | Secrets-exfiltrating workflow |
| macOS | ~/Library/LaunchAgents/com.user.gh-token-monitor.plist | -- | LaunchAgent persistence (latent) |
| Linux | ~/.config/systemd/user/gh-token-monitor.service | -- | systemd user service (latent) |
| Linux/macOS | ~/.local/bin/gh-token-monitor.sh | -- | Token monitor shell script |
| Cross-platform | ~/.config/gh-token-monitor/ | -- | Configuration directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npm-cache[.]com | Primary active C2 domain |
| Domain | awqhnjewqjkl[.]icu | Secondary C2 domain (deployed Aug 4, 2026) |
| Domain | pypi-get[.]com | Historical C2 domain |
| Domain | js-mirror[.]com | Historical C2 domain |
| URL Pattern | hxxps://npm-cache[.]com:443/router | Primary exfiltration endpoint |
| URL Pattern | hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum? | Backup exfiltration endpoint |
| IP | 104[.]21[.]91[.]101 | Cloudflare CDN (do not block by IP alone) |
| IP | 172[.]67[.]215[.]154 | Cloudflare CDN (do not block by IP alone) |
| Ethereum Contract | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` | C2 domain resolver contract |
| Ethereum Transaction | `0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91` | Domain rotation transaction |
| Ethereum Wallet | `0x55f9780e1492344b7417fa723aedc4d0b97f31cd` | Operator wallet |
| Ethereum Address | `0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B` | Binance deposit pivot |
| Ethereum Selector | `0x53ed5143` | Getter function selector |
| Ethereum Selector | `0xd3c159e5` | Setter function selector |

### Behavioral

- Bun runtime (`bun` / `bun.exe`) executing JavaScript files named `Math_Symbol.js`, `math_init.js`, or `math_<guid>.js`
- Bun process spawning `gh auth token` command
- Creation of `setup.mjs` files in `.claude/` and `.vscode/` project directories simultaneously
- npm patch-version releases without corresponding source commits
- GitHub repository creation with description matching "Shai-Hulud: Here We Go Again"
- GitHub commit messages prefixed with `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- GitHub commit searches for marker `thebeautifulmarchoftime`
- Ethereum JSON-RPC `eth_call` requests targeting the resolver contract address
- HTTP POST to `/router` endpoint on C2 domains
- Python process reading `/proc/<pid>/mem` of Runner.Worker process on GitHub Actions runners
- New versions of packages published every 6--70 minutes without code changes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoning npm packages with malicious preinstall hooks via stolen publishing tokens |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution of obfuscated Bun-based JavaScript payload (math_init.js) |
| T1059.006 | Command and Scripting Interpreter: Python | Python helper for GitHub Actions runner memory scraping |
| T1555 | Credentials from Password Stores | Harvesting npm tokens, GitHub PATs, SSH keys, cloud credentials |
| T1552.001 | Unsecured Credentials: Credentials In Files | Scanning .npmrc, .env, shell histories, cloud config files |
| T1546 | Event Triggered Execution | IDE hooks in Claude Code SessionStart and VS Code folderOpen tasks |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS LaunchAgent for gh-token-monitor (latent) |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux systemd user service for gh-token-monitor (latent) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST to /router endpoint for data exfiltration |
| T1568 | Dynamic Resolution | Ethereum smart contract-based C2 domain resolution |
| T1027 | Obfuscated Files or Information | Three-layer obfuscation (Base91 + byte-permutation + AES-256-GCM) |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential exfiltration over HTTPS to C2 domains |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Stolen tokens committed to attacker-created GitHub repositories |
| T1003 | OS Credential Dumping | Reading /proc/<pid>/mem to extract OIDC tokens from runner process memory |
| T1078 | Valid Accounts | Using stolen npm tokens and GitHub PATs for worm propagation |
| T1105 | Ingress Tool Transfer | Downloading Bun runtime from GitHub; server-side RCE code delivery |

## Impact Assessment

**Breadth:** 420+ package names across 9 organizations compromised, with 1,684 poisoned versions published. The affected packages (including keyv, flat-cache, cache-manager) are deep infrastructure dependencies downloaded hundreds of millions of times weekly. 453 public GitHub repositories created across 5 compromised accounts for credential exfiltration. Infrastructure spans 4 continents.

**Depth:** The worm harvests nearly every credential class (cloud IAM, npm, GitHub, SSH, Kubernetes, Terraform, Vault, Docker, Jenkins, cryptocurrency wallets) and actively validates them via API calls. The RCE channel provides arbitrary code execution on every infected host. The OIDC/Sigstore publishing path could produce supply chain packages with valid provenance signatures, undermining the primary defense against supply chain attacks.

**Stealth:** Blockchain-based C2 resolution, Cloudflare CDN proxying, three-layer obfuscation, legitimate Bun runtime usage, and patch-version-only changes make detection challenging. IDE persistence hooks create reinfection vectors across development sessions.

## Detection & Remediation

### Immediate Detection

Search for the following across all development environments and CI/CD systems:

```bash
# Check for ChainDrop payload files
find / -name "Math_Symbol.js" -o -name "math_init.js" -o -name "setup.mjs" 2>/dev/null | \
  xargs -I{} sha256sum {} 2>/dev/null | \
  grep -iE "9fc2570b7cef51c1b8|54dc7ea54a1317|fd3ca4007b225f|b27b82afa5f155"

# Check for IDE persistence hooks
find / -path "*/.claude/setup.mjs" -o -path "*/.vscode/setup.mjs" 2>/dev/null

# Check for OS-level persistence
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
ls -la ~/.config/systemd/user/gh-token-monitor.service 2>/dev/null
ls -la ~/.local/bin/gh-token-monitor.sh 2>/dev/null

# Check for exfiltration repositories on GitHub
gh search repos "Shai-Hulud: Here We Go Again" --limit 100

# Search for leaked tokens in commits
gh search commits "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients"
```

### Remediation

1. **CRITICAL: Remove the credential-revocation watcher BEFORE rotating tokens.** Revocation is the watcher's trigger; rotating first can execute an attacker-supplied destructive handler. Kill any `gh-token-monitor` processes, remove the LaunchAgent/systemd service, and delete `~/.config/gh-token-monitor/` before proceeding.

2. Compare lockfiles and resolved package versions against the affected-package list. Disable unnecessary npm install lifecycle scripts (`npm config set ignore-scripts true` during triage).

3. Purge npm and yarn caches on all affected systems: `npm cache clean --force && yarn cache clean`.

4. Rebuild projects from known-good dependency baselines (use lockfiles from before the compromise window).

5. Rotate ALL credentials from clean, confirmed-uncompromised hosts: npm tokens, GitHub PATs, SSH keys, cloud IAM credentials, Kubernetes tokens, Vault tokens, and any other harvested credential types.

6. Scan all repositories for malicious `.claude/settings.json`, `.vscode/tasks.json`, and `.github/workflows/codeql_analysis.yml` files.

7. Review GitHub account activity for unauthorized repository creation, especially repositories with Dune-themed names.

### Long-Term Hardening

- Update npm CLI to version 12+ and enable the `min-release-age` feature to delay package consumption after publish
- Enforce strict egress network policies on CI runners, limiting connections to private registries and known targets
- Use ephemeral CI runners instead of persistent self-hosted infrastructure
- Bind authentication to workloads (mutual TLS, SPIFFE identity, cloud IAM roles, projected service tokens)
- Plant canary credentials in `~/.aws/credentials`, `~/.npmrc`, and `.env` files across build images
- Monitor the Ethereum smart contract (`0xE1f2395ee43e45A1556EC6438a88c31B83493103`) for future `setStrings()` calls indicating domain rotation
- Enforce npm package provenance verification and review CI/CD token scopes

## Detection Rules

These detections target the ChainDrop npm supply chain worm's distinctive artifacts: payload filenames, C2 domains, Ethereum contract interactions, and IDE persistence hooks. PoC/advisory-specific altitude (default) with strict leniency. Compiles does not equal fires -- verify each rule in your pipeline with representative telemetry.

### Sigma: ChainDrop Bun Runtime Payload Execution

Detects the Bun runtime executing ChainDrop's distinctive payload filenames (Math_Symbol.js or math_init.js).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data 403 via proxy); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keys on highly distinctive filenames unlikely in legitimate use. No pipeline conversion applicable (cross-platform process_creation). -->

```yaml
title: ChainDrop Bun Runtime Payload Execution
id: 8f3a1c4e-7d2b-4e6a-9c5f-1a8b3d0e2f7c
status: experimental
description: >
    Detects the Bun runtime executing ChainDrop worm payloads (Math_Symbol.js
    or math_init.js), the distinctive execution pattern of the ChainDrop npm
    supply chain worm observed across 400+ compromised packages.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/09
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_bun:
        Image|endswith:
            - '\bun.exe'
            - '/bun'
    selection_payload:
        CommandLine|contains:
            - 'Math_Symbol.js'
            - 'math_init.js'
    condition: selection_bun and selection_payload
falsepositives:
    - Legitimate use of files named Math_Symbol.js or math_init.js is extremely unlikely
level: high
```

### Sigma: ChainDrop Credential Harvesting via GitHub CLI

Detects the Bun runtime spawning `gh auth token` for GitHub PAT extraction.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Parent=bun + child=gh auth token is highly specific. Legitimate bun->gh auth token automation is uncommon but possible; level:high reflects this. -->

```yaml
title: ChainDrop Credential Harvesting via GitHub CLI
id: 2e9d4b7a-6c1f-48a3-b5e0-3f7c8d2a1e9b
status: experimental
description: >
    Detects the Bun runtime spawning GitHub CLI credential extraction commands,
    a distinctive credential harvesting pattern used by the ChainDrop worm to
    steal GitHub PATs for subsequent npm package poisoning.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/09
tags:
    - attack.t1555
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\bun.exe'
            - '/bun'
    selection_cmdline:
        CommandLine|contains: 'gh auth token'
    condition: selection_parent and selection_cmdline
falsepositives:
    - Legitimate automation scripts using Bun to invoke gh auth token
level: high
```

### Sigma: ChainDrop IDE Persistence Hook File Creation

Detects creation of setup.mjs in .claude/ or .vscode/ directories, the cross-linked persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. setup.mjs in .claude/ or .vscode/ directories is a highly distinctive artifact pattern. False positives from legitimate projects using this exact naming convention are low but possible; context review recommended. -->

```yaml
title: ChainDrop IDE Persistence Hook File Creation
id: 4b8c2e1d-9a3f-47d6-8e0b-5c6a7f3d2e1a
status: experimental
description: >
    Detects creation of cross-linked persistence hooks in Claude Code and VS Code
    project directories (.claude/settings.json referencing .vscode/setup.mjs and
    vice versa), the distinctive mutual-dependency persistence pattern used by
    the ChainDrop worm.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/09
tags:
    - attack.t1546
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.claude\setup.mjs'
            - '.claude/setup.mjs'
            - '.vscode\setup.mjs'
            - '.vscode/setup.mjs'
    condition: selection
falsepositives:
    - Legitimate project setup scripts named setup.mjs in .claude or .vscode directories
level: high
```

### Sigma: ChainDrop C2 Domain DNS Query

Detects DNS queries to the four known ChainDrop C2 domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Domain IOCs are highly specific. Domains rotate via on-chain updates; monitor the Ethereum contract for new domains and update this rule accordingly. -->

```yaml
title: ChainDrop C2 Domain DNS Query
id: 7a5e3c9d-1b4f-42e8-a6d0-8f2c5b7e3a1d
status: experimental
description: >
    Detects DNS queries to known ChainDrop C2 domains (npm-cache.com,
    pypi-get.com, js-mirror.com, awqhnjewqjkl.icu) used for exfiltration
    and remote code execution.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
author: Actioner
date: 2026/08/09
tags:
    - attack.t1071.001
    - attack.t1568
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'npm-cache.com'
            - 'pypi-get.com'
            - 'js-mirror.com'
            - 'awqhnjewqjkl.icu'
    condition: selection
falsepositives:
    - Extremely unlikely given domain specificity
level: critical
```

### Sigma: ChainDrop Token Monitor Persistence Installation

Detects creation of gh-token-monitor persistence artifacts (LaunchAgent or systemd service).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. "gh-token-monitor" is a unique artifact name. Latent persistence (not yet observed activated) but file creation is detectable. -->

```yaml
title: ChainDrop Token Monitor Persistence Installation
id: 6d1f9e3a-8c4b-47a2-b5d0-2e7a3f6c9b1d
status: experimental
description: >
    Detects creation of ChainDrop OS-level persistence artifacts including the
    gh-token-monitor LaunchAgent (macOS) or systemd user service (Linux) used
    for credential monitoring and destructive revocation handling.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026/08/09
tags:
    - attack.t1543.001
    - attack.t1543.002
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'com.user.gh-token-monitor.plist'
            - 'gh-token-monitor.service'
            - 'gh-token-monitor.sh'
    condition: selection
falsepositives:
    - Legitimate software named gh-token-monitor is extremely unlikely
level: high
```

### Snort: ChainDrop C2 HTTP Communication

Detects HTTP traffic to known ChainDrop C2 domains (npm-cache[.]com /router endpoint and awqhnjewqjkl[.]icu).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (rules appended to local.rules for Snort 2.9.20 validation). Snort 2 format: http_uri and http_header as post-content modifiers. Domain-based matching is precise but rotates; update rule when new domains are observed. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChainDrop C2 HTTP Beacon to npm-cache.com /router"; flow:established,to_server; content:"/router"; http_uri; content:"npm-cache.com"; http_header; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; sid:2100001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ChainDrop C2 HTTP Beacon to awqhnjewqjkl.icu"; flow:established,to_server; content:"awqhnjewqjkl.icu"; http_header; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; sid:2100002; rev:1;)
```

### Suricata: ChainDrop C2 Domain DNS Queries

Detects DNS queries to all four known ChainDrop C2 domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). Four DNS rules for each known C2 domain. Domain IOCs rotate via on-chain updates. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop C2 Domain DNS Query (npm-cache.com)"; dns.query; content:"npm-cache.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop C2 Domain DNS Query (awqhnjewqjkl.icu)"; dns.query; content:"awqhnjewqjkl.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop C2 Domain DNS Query (pypi-get.com)"; dns.query; content:"pypi-get.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop C2 Domain DNS Query (js-mirror.com)"; dns.query; content:"js-mirror.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200004; rev:1;)
```

### Suricata: ChainDrop Ethereum RPC C2 Resolution

Detects HTTP requests containing Ethereum `eth_call` targeting the ChainDrop C2 resolver contract.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Both eth_call and the contract address must appear in the HTTP request body. Contract address is highly specific. Will not fire on unrelated eth_call traffic because the contract address acts as a discriminator. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Ethereum RPC C2 Resolution"; flow:established,to_server; http.request_body; content:"eth_call"; fast_pattern; content:"0xE1f2395ee43e45A1556EC6438a88c31B83493103"; nocase; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200005; rev:1;)
```

### Suricata: ChainDrop C2 Exfiltration to /router

Detects HTTP POST to the /router endpoint on the npm-cache[.]com C2 host.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Three-buffer match: method POST + URI /router + host npm-cache.com. Highly specific, low FP risk. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop C2 Exfiltration to /router Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/router"; fast_pattern; http.host; content:"npm-cache.com"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-09; sid:2200006; rev:1;)
```

### YARA: ChainDrop Worm Payload Strings

Detects ChainDrop payload files via the token exfiltration commit marker, Dune-themed repository description, runtime guard variable, and Ethereum contract address strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos (file with marker string) matched; yara neg (benign JS) silent. Positive derived from source-published marker string "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients". Condition uses OR across markers and 3-of-N fallback for coverage. -->

```yara
rule ChainDrop_Worm_Payload_Strings
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload via distinctive strings including the token exfiltration marker, Dune-themed repository description, and runtime guard variable"
        author = "Actioner"
        date = "2026-08-09"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $marker2 = "Shai-Hulud: Here We Go Again" ascii
        $marker3 = "thebeautifulmarchoftime" ascii
        $envflag = "_NODE_RUNTIME_INIT" ascii
        $c2path = "/router" ascii
        $contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $getter = "0x53ed5143" ascii
        $setup = "setup.mjs" ascii
        $mathfile1 = "Math_Symbol.js" ascii
        $mathfile2 = "math_init.js" ascii

    condition:
        filesize < 5MB and
        (
            any of ($marker*) or
            ($contract and $getter) or
            ($envflag and any of ($mathfile*)) or
            (3 of them)
        )
}
```

### YARA: ChainDrop Setup Dropper

Detects the ChainDrop setup.mjs dropper by the combination of setup filename, runtime guard variable, and Bun download/preinstall indicators.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. No sample-fire test (dropper samples not available for positive construction from published strings alone without risk of self-matching). Condition requires setup.mjs + _NODE_RUNTIME_INIT + one of preinstall/bun indicators. Medium confidence because the individual strings are not unique, though the combination is specific. -->

```yara
rule ChainDrop_Setup_Dropper
{
    meta:
        description = "Detects the ChainDrop setup.mjs dropper based on known SHA256 hashes of observed variants"
        author = "Actioner"
        date = "2026-08-09"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        hash3 = "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678"
        severity = "critical"

    strings:
        $preinstall = "preinstall" ascii
        $setup = "setup.mjs" ascii
        $bun_dl = "bun-dl-" ascii
        $bun_check = "Bun" ascii
        $node_runtime = "_NODE_RUNTIME_INIT" ascii

    condition:
        filesize < 100KB and
        $setup and
        $node_runtime and
        ($preinstall or $bun_dl or $bun_check)
}
```

## Lessons Learned

1. **Lifecycle hooks remain the npm supply chain's Achilles' heel.** The `preinstall` hook provides automatic, silent code execution during package installation. npm 12's default lifecycle script blocking is a critical mitigation, but the vast majority of the ecosystem still runs older versions.

2. **Blockchain-based C2 creates a resilient, censor-resistant command infrastructure.** The Ethereum smart contract allows the operator to rotate domains without touching the malware itself, and the use of 60+ public RPC endpoints makes blocking infeasible at the network level. This technique (previously seen in EtherHiding campaigns) is increasingly being adopted for supply chain malware.

3. **Developer tool persistence is an emerging attack surface.** The cross-linked `.claude/settings.json` and `.vscode/tasks.json` hooks represent a novel persistence vector that exploits developer trust in their IDE project configurations. Organizations should treat IDE configuration files in repositories as potentially hostile.

4. **Credential-revocation watchers introduce a dangerous remediation trap.** The destructive handler triggered by token revocation means standard incident response procedures (immediate credential rotation) can cause additional damage. This anti-IR technique requires defenders to locate and disable the watcher before beginning remediation.

5. **Provenance signing can be weaponized.** The advanced OIDC/Sigstore publishing path demonstrates that valid SLSA provenance and Sigstore signatures are not proof of legitimacy when the signing workflow itself is compromised. Provenance verification must be paired with workflow integrity monitoring.

## Sources

- [Unit42 -- ChainDrop npm Worm Analysis](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) -- Primary technical analysis with full IOCs, obfuscation layer breakdown, C2 infrastructure, and propagation mechanism details
- [Microsoft Security Blog -- ChainDrop Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) -- Microsoft Threat Intelligence analysis with Defender signatures, behavioral alerts, and advanced hunting queries
- [The Hacker News -- Keyv-Linked npm Worm](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html) -- keyv@6.0.0 compromise details, SafeDep verification of 420 affected packages, and credential-revocation watcher warning
- [The Hacker News -- NullReceiver Blockchain C2](https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html) -- Related NullReceiver/PolinRider campaign using Ethereum transaction recipient addresses for C2 IP encoding (North Korean attribution)
- [The Hacker News -- 800 Malicious npm Packages](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html) -- WEL1DROPPER campaign context with Cloudflare Workers infrastructure and DNS TXT record payload delivery (concurrent but distinct campaign)

---
*Report generated by Actioner*
