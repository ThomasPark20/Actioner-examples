# Technical Analysis Report: ChainDrop npm Supply Chain Worm (2026-08-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-07
Version: 1.0 (DRAFT)

## Executive Summary

ChainDrop is a self-propagating npm supply chain worm that has infected 420+ npm packages (1,684 poisoned versions across nine organizations) including widely-used packages such as `keyv`, `flat-cache`, and `cache-manager` with hundreds of millions of combined weekly downloads. First observed on May 11, 2026, the worm uses stolen npm publishing credentials to inject malicious `preinstall` hooks into legitimate packages, which download the Bun 1.3.13 runtime and execute a 727 KB obfuscated JavaScript payload. The payload harvests cloud credentials (AWS, Azure, GCP, Kubernetes), developer tokens (npm, GitHub, SSH keys), AI coding assistant configurations, and even scrapes GitHub Actions runner process memory to extract ephemeral OIDC tokens. Exfiltrated data is encrypted with AES-256-GCM + RSA-OAEP and sent to C2 infrastructure that uses Ethereum smart contracts for domain resolution, making takedown extremely difficult. The worm self-propagates by republishing infected versions of every package accessible to a stolen npm identity, creating a cascading infection chain across the ecosystem. Likely part of the Shai-Hulud malware lineage.

## Background: npm Ecosystem Supply Chain

The npm registry is the world's largest software package ecosystem, serving as the default package manager for Node.js with over 2 million packages. Developers and CI/CD systems install packages via `npm install`, which executes lifecycle hooks including `preinstall` scripts before package installation completes. This lifecycle hook mechanism is the primary infection vector for ChainDrop. npm trusted publishing via OIDC and SLSA provenance attestations were designed to prevent unauthorized publishing, but ChainDrop subverts these by trading stolen OIDC tokens for legitimate npm credentials, producing packages with valid provenance signatures that appear legitimate.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-11 | Earliest known compromise of npm packages |
| 2026-05-22 13:40:28 | js-mirror[.]com registered |
| 2026-05-22 13:40:32 | npm-cache[.]com registered |
| 2026-05-22 13:40:36 | pypi-get[.]com registered |
| 2026-05-22 13:54:59 | FixedFloat transferred 0.01805723 ETH for infrastructure |
| 2026-05-25 | Ethereum smart contract deployed; C2 domains written to chain |
| 2026-05-25 +2h35m | Domain list narrowed from 3 to npm-cache[.]com only |
| 2026-08-04 12:20 | Unit 42 observed 453 public exfil repositories across 5 GitHub accounts |
| 2026-08-04 15:15:26 | awqhnjewqjkl[.]icu registered (C2 domain rotation) |
| 2026-08-04 ~16:10:03 | New C2 domain operational via on-chain transaction |
| 2026-08-04 | 546 public repositories created with "Shai-Hulud: Here We Go Again" description |
| 2026-08-06 | Unit 42 publishes technical analysis |

## Root Cause: Stolen npm Publishing Credentials

The initial compromise vector was stolen npm maintainer credentials. With valid publishing tokens, the attacker could directly modify npm tarballs without needing source repository access. The worm amplifies this by harvesting npm tokens from every compromised developer and CI environment, then using those tokens to infect all packages accessible to the stolen identity. One stolen token cascades into malicious patch releases across every package available to that publisher, with automated propagation bursts every 2-7 minutes.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via npm preinstall Hook

Infected packages contain a modified `package.json` with a `preinstall` lifecycle hook:

```json
"scripts": {
    "preinstall": "node setup.mjs"
}
```

The package also includes `setup.mjs` and `Math_Symbol.js` (or `math_init.js`) as published files. The original package source code is preserved, maintaining functionality to avoid detection. When installed, `setup.mjs` executes before installation completes, checking for the Bun runtime and downloading Bun 1.3.13 from official GitHub releases if absent. It then feeds the 727,680-byte obfuscated payload (`math_init.js`) to Bun for execution.

In CI environments, the payload runs inline (leaving debug output in workflow logs). On developer machines, it spawns a detached background process marked with the `_NODE_RUNTIME_INIT=1` environment variable. The payload silently exits on Russian-locale systems.

### 2. Multi-Layer Obfuscation and Payload Decryption

The payload employs three obfuscation layers:

**Layer 1 -- Base91 Encoding:** 73 function-specific alphabets with 14-position array rotation. Researchers recovered 4,613 hidden string entries.

**Layer 2 -- PBKDF2-SHA256 Byte-Permutation Cipher:** 200,000 iterations with seeded Fisher-Yates shuffles. Recovered 727 additional hidden strings.

**Layer 3 -- AES-256-GCM + Gzip:** Protected blobs contain bash/Python helpers, persistence installers, the GitHub Actions memory scraper, malicious workflow templates, VS Code/Claude Code persistence files, RSA public keys, and additional dropper copies.

### 3. C2 Infrastructure

**Primary C2:** hxxps://npm-cache[.]com:443/router (active C2, Cloudflare-proxied)

**Rotated C2:** hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum (DGA-style domain registered Aug 4, 2026 via NameSilo)

**Historical C2:** pypi-get[.]com, js-mirror[.]com

**Blockchain-Based Domain Resolution:** The worm queries an Ethereum smart contract at `0xE1f2395ee43e45A1556EC6438a88c31B83493103` using getter selector `0x53ed5143` to resolve the current C2 domain. The contract stores a domain list that the operator updates via setter selector `0xd3c159e5`. The worm rotates through approximately 60 public Ethereum RPC endpoints for resilience. Domain rotation is performed via a single on-chain transaction with no events emitted, making changes undetectable without active contract polling. The operator wallet is `0x55f9780e1492344b7417fa723aedc4d0b97f31cd` with a Binance deposit pivot at `0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B`.

**Fallback -- GitHub Commit Search:** The worm searches GitHub commits for the marker `thebeautifulmarchoftime` to find signed records containing backup C2 domains. A second marker, `thebeautifulsnadsoftime`, serves as fallback C2 record prefix. At analysis time this channel was unarmed (no valid operator record).

**Encrypted Exfiltration:** Stolen data is JSON-serialized, gzip-compressed, encrypted with AES-256-GCM (random 32-byte key, 12-byte IV), and the key is wrapped with RSA-OAEP-SHA256 using an embedded public key. Each exfiltration includes a host-derived UUID for per-victim targeting. The C2 can return a `code` field in its JSON response for arbitrary JavaScript evaluation (RCE channel).

Both C2 domains are proxied through Cloudflare CDN, making IP-based blocking ineffective (shared edge IPs: 104.21.91[.]101, 172.67.215[.]154). Blocking must target domain name or SNI.

### 4. Platform-Specific Behavior

#### Developer Workstations (macOS/Linux/Windows)

- **Credential Harvesting:** AWS IAM credentials, Azure tokens, GCP credentials, Kubernetes kubeconfigs, Vault tokens, Terraform state files, npm tokens, GitHub PATs, SSH keys (~/.ssh/), Docker/Helm configs, git credentials, Poetry/PyPI credentials, RubyGems tokens, .env files, .netrc, Bitcoin/Electrum wallets, Jenkins encrypted credentials, shell history
- **AI/IDE Credentials:** VS Code settings/extensions, Claude Code configurations, cloud-based development platform tokens
- **Persistence:** Cross-linked VS Code tasks.json and Claude Code settings.json (see below)
- **Latent OS persistence (embedded but not invoked):** macOS LaunchAgent (`com.user.gh-token-monitor`), Linux systemd user service (`gh-token-monitor.service`)

#### GitHub Actions / CI Environments

- **Runner Memory Scraping:** Locates the `Runner.Worker` process, reads `/proc/<pid>/maps` and `/proc/<pid>/mem` to extract ephemeral OIDC tokens from live process memory
- **Secrets Exfiltration via Workflow:** Creates `.github/workflows/codeql_analysis.yml` that serializes `${{ toJSON(secrets) }}` and uploads as workflow artifacts
- **Repository Creation:** Creates public repositories under victim accounts with Dune-themed names (sardaukar, mentat, fremen, atreides, harkonnen) as exfiltration drop zones

### 5. Persistence Mechanisms

**Cross-Linked VS Code / Claude Code Persistence:**

The worm creates a mutual-reference persistence scheme:
- `.vscode/tasks.json` with an "Environment Setup" task that executes `node .claude/setup.mjs` on folder open
- `.claude/settings.json` with a `SessionStart` command hook that executes `node .vscode/setup.mjs`
- `.claude/math_init.js` (the actual payload)
- `.claude/setup.mjs` and `.vscode/setup.mjs` (dropper copies)

Files cross-reference each other's directories; only `.claude/math_init.js` exists as the payload, making the `.vscode` path appear broken at first glance.

**Token-Revocation Watcher:** Monitors for credential revocation events and includes destructive handling when tokens are revoked.

### 6. Propagation Mechanisms

**Primary -- npm Token Republishing:** The worm locates stolen npm publishing tokens, identifies all packages the compromised account can publish, downloads/reconstructs each package, injects the `preinstall: node setup.mjs` hook into package.json, copies setup.mjs and math_init.js, increments the patch version, and republishes. Original source code is preserved to maintain functionality.

**Repository-Gated Trusted Publishing (Sophisticated Variant):** Targets specific repositories (e.g., `/opensearch-js`) with `release-drafter.yml` workflows. Uses stolen OIDC tokens (audience: `npm:registry.npmjs.org`) to trade for legitimate npm publishing credentials via npm's trusted-publishing endpoint. Adds typosquatted dependencies, obtains Fulcio certificates, builds in-toto SLSA v1 provenance statements, DSSE-signs with ephemeral P-256 keys, and uploads to public Rekor transparency log -- producing packages with valid npm provenance that appear legitimate.

**GitHub Commit Token Sharing:** Base64-encodes stolen GitHub tokens twice, creates public commits with the marker prefix `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`. All worm instances search the GitHub commit API for this marker, double-decode matches, and reuse tokens -- creating a distributed credential-sharing pool across all infected systems.

### 7. Anti-Forensics / Evasion Techniques

- Russian-language locale gating (exits silently on Russian systems)
- Three-layer obfuscation (Base91 + PBKDF2 + AES-256-GCM)
- Cloudflare CDN proxying of C2 domains
- No fixed second-stage payload (operator chooses at request time; never written to disk)
- Valid npm provenance attestations on republished packages
- Blockchain-based C2 resolution with no emitted events
- Cross-directory IDE persistence to obscure payload location
- Original package functionality preserved to avoid detection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0+ | Initial high-profile compromise; preinstall hook |
| flat-cache | 6.1.23+ | Restored as latest after compromise |
| cache-manager | 7.2.9+ | Restored as latest after compromise |
| 420+ packages total | Various patch bumps | 1,684 poisoned versions across 9 organizations |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross-platform | math_init.js / Math_Symbol.js | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Obfuscated 727 KB payload |
| Cross-platform | setup.mjs (tarball loader) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | Dropper (npm tarball variant) |
| Cross-platform | setup.mjs (repo loader) | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | Dropper (repository variant) |
| Cross-platform | setup.mjs.malicious | `b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678` | Alternate dropper hash |
| Cross-platform | .claude/settings.json | -- | SessionStart hook persistence |
| Cross-platform | .claude/setup.mjs | -- | Dropper copy in .claude directory |
| Cross-platform | .claude/math_init.js | -- | Payload in .claude directory |
| Cross-platform | .vscode/tasks.json | -- | VS Code task persistence |
| Cross-platform | .vscode/setup.mjs | -- | Dropper copy in .vscode directory |
| Cross-platform | .github/workflows/codeql_analysis.yml | -- | Secrets exfiltration workflow |
| macOS | ~/Library/LaunchAgents/com.user.gh-token-monitor.plist | -- | Latent LaunchAgent persistence |
| Linux | ~/.config/systemd/user/gh-token-monitor.service | -- | Latent systemd persistence |
| Linux | ~/.local/bin/gh-token-monitor.sh | -- | Token monitor script |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npm-cache[.]com | Active C2 (Cloudflare-proxied) |
| Domain | awqhnjewqjkl[.]icu | Rotated C2 (DGA-style, registered Aug 4) |
| Domain | pypi-get[.]com | Historical C2 |
| Domain | js-mirror[.]com | Historical C2 |
| IP | 104.21.91[.]101 | Cloudflare edge (shared, not actionable for blocking) |
| IP | 172.67.215[.]154 | Cloudflare edge (shared, not actionable for blocking) |
| URL Pattern | hxxps://npm-cache[.]com:443/router | Primary C2 endpoint |
| URL Pattern | hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum | Rotated C2 endpoint |
| Ethereum Contract | 0xE1f2395ee43e45A1556EC6438a88c31B83493103 | StringListStore for C2 domain resolution |
| Ethereum Wallet | 0x55f9780e1492344b7417fa723aedc4d0b97f31cd | Operator wallet |
| Ethereum Wallet | 0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B | Binance deposit pivot |
| Ethereum TX | 0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91 | Domain rotation transaction |
| Selector | 0x53ed5143 | Smart contract getter (domain lookup) |
| Selector | 0xd3c159e5 | Smart contract setter (domain update) |

### Behavioral

- Bun runtime spawned from node/npm processes executing `math_init.js` or `Math_Symbol.js`
- Detached process with `_NODE_RUNTIME_INIT=1` environment variable
- `gh auth token` executed by Bun process (GitHub credential harvesting)
- Access to `/proc/<pid>/mem` targeting Runner.Worker process on CI runners
- GitHub commit searches for markers `thebeautifulmarchoftime` and `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- Repository descriptions matching "Shai-Hulud: Here We Go Again"
- Ethereum JSON-RPC `eth_call` requests targeting contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`
- npm package patch version increments with injected `preinstall` hooks every 2-7 minutes
- Creation of `.github/workflows/codeql_analysis.yml` containing `toJSON(secrets)` serialization

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Trojanized npm packages via stolen publishing credentials |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Bun runtime executing obfuscated JS payload |
| T1547.014 | Boot or Logon Autostart Execution: Active Setup | Cross-linked VS Code tasks.json / Claude Code settings.json persistence |
| T1543.002 | Create or Modify System Process: Systemd Service | Latent Linux systemd user service (embedded, not invoked) |
| T1547.015 | Boot or Logon Autostart Execution: Login Items | Latent macOS LaunchAgent (embedded, not invoked) |
| T1528 | Steal Application Access Token | Harvesting GitHub PATs, npm tokens, cloud credentials |
| T1555 | Credentials from Password Stores | Stealing dotfile credentials (.npmrc, .aws/credentials, .ssh/) |
| T1003 | OS Credential Dumping | GitHub Actions Runner.Worker process memory scraping for OIDC tokens |
| T1020 | Automated Exfiltration | Serializing GitHub Actions secrets as workflow artifacts |
| T1041 | Exfiltration Over C2 Channel | AES-256-GCM encrypted data to C2 domains |
| T1008 | Fallback Channels | Ethereum smart contract + GitHub commit search fallback C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication via /router endpoint |
| T1027 | Obfuscated Files or Information | Three-layer obfuscation (Base91 + PBKDF2 + AES-GCM) |
| T1078 | Valid Accounts | Stolen npm publishing credentials for worm propagation |
| T1036 | Masquerading | Legitimate package names with injected malicious hooks |

## Impact Assessment

- **Breadth:** 420+ npm packages, 1,684 poisoned versions across 9 organizations, hundreds of millions of weekly downloads exposed
- **Depth:** Complete credential theft (cloud, developer tools, AI assistants), OIDC token extraction from runner memory, npm identity theft enabling cascading infection
- **Stealth:** Valid npm provenance attestations, Cloudflare CDN proxying, blockchain-based C2 with no emitted events, original package functionality preserved
- **Geographic scope:** Four continents (North America, Europe, Asia, Africa)
- **Infrastructure:** 453-546 public GitHub repositories created for exfiltration across 5 accounts
- **Active campaign:** New repositories observed being created during live analysis

## Detection & Remediation

### Immediate Detection

```bash
# Check for ChainDrop persistence files in local projects
find ~/projects -name "math_init.js" -path "*/.claude/*" 2>/dev/null
find ~/projects -name "setup.mjs" -path "*/.vscode/*" 2>/dev/null
find ~/projects -name "setup.mjs" -path "*/.claude/*" 2>/dev/null

# Check for token monitor persistence (macOS)
ls ~/Library/LaunchAgents/com.user.gh-token-monitor* 2>/dev/null

# Check for token monitor persistence (Linux)
ls ~/.config/systemd/user/gh-token-monitor.service 2>/dev/null
ls ~/.local/bin/gh-token-monitor.sh 2>/dev/null

# Check npm lockfiles for known affected packages with suspicious patch bumps
npm audit 2>/dev/null

# Search GitHub Actions workflow logs for ChainDrop debug output
grep -r "_NODE_RUNTIME_INIT" .github/ 2>/dev/null
grep -r "toJSON(secrets)" .github/workflows/ 2>/dev/null

# Check for malicious workflow
ls .github/workflows/codeql_analysis.yml 2>/dev/null
```

### Remediation

1. **Containment:** Immediately revoke all npm tokens, GitHub PATs, and cloud credentials on affected systems. Remove the token-revocation watcher before rotating tokens.
2. **Eradication:** Remove `.claude/math_init.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`, modified `.claude/settings.json` and `.vscode/tasks.json`. Delete `.github/workflows/codeql_analysis.yml` if injected.
3. **Recovery:** Clear lockfiles and npm caches after removing poisoned packages. Pin dependencies to known-good versions. Update dependencies explicitly.
4. **Secret rotation:** Rotate ALL secrets that were present in the compromised environment: AWS keys, Azure tokens, GCP credentials, Kubernetes kubeconfigs, SSH keys, npm tokens, GitHub PATs, Vault tokens.
5. **CI/CD:** Treat all GitHub Actions environments that executed affected releases as fully credential-exposed. Verify runner images are clean.

### Long-Term Hardening

1. **Bind authentication to workload identity:** Use SPIFFE, cloud IAM roles, or projected service account tokens instead of bearer tokens in dotfiles
2. **Ephemeral CI runners:** Replace persistent self-hosted runners to limit cross-job credential accumulation
3. **Canary credentials:** Place non-functional keys in ~/.aws/credentials, ~/.npmrc, .env across build images for early detection
4. **Egress filtering:** Restrict CI/CD outbound connections to private registry and known deployment targets only
5. **Install script controls:** Use npm 12+ which blocks unapproved dependency lifecycle scripts by default; use `--ignore-scripts` where possible
6. **Smart contract monitoring:** Poll Ethereum contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` for `setStrings()` calls to detect domain rotation
7. **Lockfile integrity:** Enforce lockfile-only installs in CI/CD (`npm ci` instead of `npm install`)

## Detection Rules

These detections target ChainDrop npm supply chain worm artifacts at PoC/advisory-specific altitude with strict leniency. The Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale. Note: compiles does not equal fires -- verify in your telemetry pipeline before production deployment.

### Sigma: Bun Runtime Executing ChainDrop Payload

Detects the Bun JavaScript runtime executing ChainDrop-specific payload files (math_init.js, Math_Symbol.js), a combination highly distinctive to this campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 through proxy — not a rule error); splunk convert exit 0; log_scale convert exit 0. Field names match process_creation schema. Values are real (not defanged). -->
```yaml
title: ChainDrop Worm - Bun Runtime Executing Malicious Payload
id: 7a3c1e4b-9f2d-4a6e-8b7c-1d5e0f3a2c9b
status: experimental
description: >
    Detects the Bun JavaScript runtime executing ChainDrop worm payloads
    (math_init.js, Math_Symbol.js, or setup.mjs) as observed in the npm
    supply chain compromise campaign affecting 400+ packages.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-07
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
detection:
    selection_bun:
        Image|endswith:
            - '/bun'
            - '\bun.exe'
    selection_payload:
        CommandLine|contains:
            - 'math_init.js'
            - 'Math_Symbol.js'
    condition: selection_bun and selection_payload
falsepositives:
    - Legitimate use of files named math_init.js or Math_Symbol.js with Bun runtime is unlikely
level: high
```

### Sigma: npm Preinstall Hook Executing setup.mjs

Detects node executing setup.mjs as a child of npm/npx, consistent with ChainDrop's preinstall lifecycle hook infection vector. Scope to CI runners and developer machines with package management activity.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE fetch 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence because setup.mjs is a plausible legitimate filename; the parent-process constraint (npm/npx) adds specificity but legitimate preinstall scripts could match. -->
```yaml
title: ChainDrop Worm - npm Preinstall Hook Executing setup.mjs
id: 2b8d4f6a-1c3e-5d7b-9a0f-4e2c8b6d1a3f
status: experimental
description: >
    Detects node or npm executing setup.mjs as a preinstall lifecycle hook,
    characteristic of ChainDrop worm-infected npm packages. The worm uses
    preinstall hooks to launch its credential-stealing payload.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html
author: Actioner
date: 2026-08-07
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
detection:
    selection_node:
        Image|endswith:
            - '/node'
            - '\node.exe'
    selection_setup:
        CommandLine|contains: 'setup.mjs'
    selection_parent:
        ParentImage|endswith:
            - '/npm'
            - '\npm.cmd'
            - '/npx'
            - '\npx.cmd'
    condition: selection_node and selection_setup and selection_parent
falsepositives:
    - Legitimate npm packages using setup.mjs as a preinstall script
level: medium
```

### Sigma: Cross-Linked IDE Persistence Files

Detects concurrent creation of ChainDrop's .claude/math_init.js alongside IDE persistence configs (.claude/settings.json or .vscode/tasks.json), a combination unique to this worm's dual-IDE persistence scheme.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE fetch 403); splunk convert exit 0; log_scale convert exit 0. High confidence: the AND of .claude/math_init.js with either IDE config is extremely specific to ChainDrop. Requires file_event telemetry (Sysmon EID 11 or equivalent). -->
```yaml
title: ChainDrop Worm - Cross-Linked IDE Persistence Files
id: 5e9f2a1b-3c4d-6e8f-0b7a-2d1c4f6e8a3b
status: experimental
description: >
    Detects creation of ChainDrop worm's cross-linked persistence files in
    .vscode and .claude directories. The worm creates .vscode/tasks.json
    invoking .claude/setup.mjs and .claude/settings.json invoking
    .vscode/setup.mjs for dual IDE persistence.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-07
tags:
    - attack.t1547.014
logsource:
    category: file_event
detection:
    selection_claude_settings:
        TargetFilename|endswith: '.claude/settings.json'
    selection_vscode_tasks:
        TargetFilename|endswith: '.vscode/tasks.json'
    selection_claude_math:
        TargetFilename|endswith: '.claude/math_init.js'
    condition: selection_claude_math and (selection_claude_settings or selection_vscode_tasks)
falsepositives:
    - Unlikely — concurrent creation of .claude/math_init.js with IDE config files is highly specific to ChainDrop
level: high
```

### Sigma: GitHub Actions Runner Memory Scraping

Detects access to /proc/*/mem (excluding /proc/self/), consistent with ChainDrop scraping Runner.Worker process memory for ephemeral OIDC tokens on GitHub Actions runners. Hunt-only; pair with CI runner context for triage.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE fetch 403); splunk convert exit 0; log_scale convert exit 0. Medium confidence: /proc/*/mem access can occur from debugging tools and performance monitors. The filter_self exclusion reduces noise. Best deployed on CI runners specifically. -->
```yaml
title: ChainDrop Worm - GitHub Actions Runner Memory Scraping
id: 8c1d3e5f-2b4a-6c8d-0e9f-1a3b5c7d9e2f
status: experimental
description: >
    Detects access to /proc/*/mem targeting the Runner.Worker process on
    GitHub Actions runners, used by ChainDrop to extract ephemeral OIDC
    tokens and runner secrets from live process memory.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
author: Actioner
date: 2026-08-07
tags:
    - attack.t1003
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: '/proc/'
        TargetFilename|endswith: '/mem'
    filter_self:
        TargetFilename|contains: '/proc/self/'
    condition: selection and not filter_self
falsepositives:
    - Debugging tools reading process memory
    - Performance monitoring agents
level: medium
```

### Sigma: _NODE_RUNTIME_INIT Environment Variable

Detects processes spawned with the _NODE_RUNTIME_INIT environment variable in the command line, a distinctive marker of ChainDrop's detached background payload process and the Shai-Hulud toolchain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE fetch 403); splunk convert exit 0; log_scale convert exit 0. High confidence: _NODE_RUNTIME_INIT is a fabricated env var name specific to Shai-Hulud/ChainDrop, not used by any known legitimate software. -->
```yaml
title: ChainDrop Worm - NODE_RUNTIME_INIT Environment Variable
id: 6d2e4f8a-3b1c-5e7d-9f0a-8c4b2d6e1f3a
status: experimental
description: >
    Detects processes spawned with the _NODE_RUNTIME_INIT=1 environment
    variable, which ChainDrop uses to mark its detached background payload
    process. This is a distinctive marker of the Shai-Hulud toolchain.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
author: Actioner
date: 2026-08-07
tags:
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '_NODE_RUNTIME_INIT'
    condition: selection
falsepositives:
    - Custom Node.js runtime initialization scripts using this exact variable name
level: high
```

### Sigma: Malicious GitHub Workflow File Creation

Detects creation of YAML files in .github/workflows/, which may indicate ChainDrop's injection of secrets-exfiltrating workflow files. Low confidence due to high legitimate baseline; pair with other ChainDrop indicators.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check failed (MITRE fetch 403); splunk convert exit 0; log_scale convert exit 0. Low confidence: workflow file creation is common in legitimate development. This is a hunt-only signal best correlated with other ChainDrop IOCs. Cannot match file content (toJSON(secrets)) via file_event category alone. -->
```yaml
title: ChainDrop Worm - Malicious GitHub Workflow Secrets Exfiltration
id: 4f7a2b8c-1d3e-5f9a-7b0c-2e4d6f8a1c3b
status: experimental
description: >
    Detects creation of a GitHub Actions workflow file containing
    toJSON(secrets) serialization, used by ChainDrop to exfiltrate all
    GitHub Actions secrets as workflow artifacts.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
author: Actioner
date: 2026-08-07
tags:
    - attack.t1020
logsource:
    category: file_event
detection:
    selection_path:
        TargetFilename|contains: '.github/workflows/'
        TargetFilename|endswith: '.yml'
    condition: selection_path
falsepositives:
    - Legitimate GitHub Actions workflow file creation
    - CI/CD pipeline configuration changes
level: low
```

### Snort: ChainDrop C2 HTTP Beacons and Ethereum Contract Query

Detects HTTP traffic to ChainDrop C2 endpoints (/router on npm-cache.com, /cdn-cgi/rum on DGA domain) and Ethereum JSON-RPC calls targeting the worm's smart contract for domain resolution.
**Status:** compile ⚠️ uncompiled (Snort not installed; structural check only) · confidence: high
<!-- audit: snort binary not available in this environment. Rules follow Snort 3 syntax with http service, sticky buffers (http_uri, http_method, http_header, http_client_body), flow:established, valid sids 2100001-2100003. Structural review confirms balanced parentheses, semicolons, and correct buffer usage. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop Worm HTTP C2 Beacon to /router Endpoint on npm-cache.com"; flow:established, to_server; http_uri; content:"/router", fast_pattern; http_header; content:"npm-cache.com"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created 2026-08-07; sid:2100001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop Worm HTTP C2 Beacon to /cdn-cgi/rum on DGA Domain"; flow:established, to_server; http_uri; content:"/cdn-cgi/rum", fast_pattern; http_header; content:"awqhnjewqjkl.icu"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created 2026-08-07; sid:2100002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop Worm Ethereum Smart Contract C2 Query"; flow:established, to_server; http_method; content:"POST"; http_client_body; content:"eth_call", fast_pattern; http_client_body; content:"e1f2395ee43e45a1556ec6438a88c31b83493103", nocase; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created 2026-08-07; sid:2100003; rev:1;)
```

### Suricata: ChainDrop C2 DNS Queries

Detects DNS queries to known ChainDrop C2 domains (npm-cache[.]com, awqhnjewqjkl[.]icu, pypi-get[.]com, js-mirror[.]com).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. dns.query sticky buffer, nocase, fast_pattern. SIDs 2200001-2200004. All domain values are real (not defanged). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to C2 Domain npm-cache.com"; flow:to_server; dns.query; content:"npm-cache.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to C2 Domain awqhnjewqjkl.icu"; flow:to_server; dns.query; content:"awqhnjewqjkl.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to Historical C2 Domain pypi-get.com"; flow:to_server; dns.query; content:"pypi-get.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to Historical C2 Domain js-mirror.com"; flow:to_server; dns.query; content:"js-mirror.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200004; rev:1;)
```

### Suricata: ChainDrop C2 HTTP Beacons

Detects HTTP POST requests to ChainDrop's C2 endpoints (/router on npm-cache[.]com and /cdn-cgi/rum on awqhnjewqjkl[.]icu).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. http.method, http.uri, http.host dot-notation sticky buffers. SIDs 2200005-2200006. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm HTTP C2 Beacon to /router Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/router"; fast_pattern; http.host; content:"npm-cache.com"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200005; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm HTTP C2 Beacon to /cdn-cgi/rum on DGA Domain"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/cdn-cgi/rum"; fast_pattern; http.host; content:"awqhnjewqjkl.icu"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200006; rev:1;)
```

### Suricata: ChainDrop C2 TLS SNI Match

Detects TLS connections with SNI matching ChainDrop C2 domains, effective even when HTTP payload is encrypted.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. tls.sni sticky buffer with fast_pattern. SIDs 2200007-2200008. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS Connection to C2 Domain npm-cache.com"; flow:established,to_server; tls.sni; content:"npm-cache.com"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200007; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS Connection to DGA C2 Domain awqhnjewqjkl.icu"; flow:established,to_server; tls.sni; content:"awqhnjewqjkl.icu"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200008; rev:1;)
```

### Suricata: ChainDrop Ethereum Smart Contract C2 Resolution

Detects HTTP POST requests containing Ethereum `eth_call` targeting the ChainDrop smart contract address used for blockchain-based C2 domain resolution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches eth_call JSON-RPC method and contract address in request body. Contract address is lowercased for nocase match. SID 2200009. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm Ethereum Smart Contract C2 Resolution"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"eth_call"; fast_pattern; content:"e1f2395ee43e45a1556ec6438a88c31b83493103"; nocase; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/; metadata:author Actioner, created_at 2026-08-07; sid:2200009; rev:1;)
```

### YARA: ChainDrop npm Supply Chain Worm Payload

Detects ChainDrop worm payload files by matching distinctive campaign markers (exfiltration token prefix, GitHub commit search markers, Dune-themed identifiers) and C2 infrastructure references (Ethereum contract address, function selectors).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos_chaindrop.txt matched ChainDrop_NPM_Supply_Chain_Worm; neg_chaindrop.txt clean. Positive sample contains published markers ($marker1, $marker2) from Unit42 report. Condition uses any-of for markers and requires multiple infrastructure indicators for env_var path to reduce FP. -->
```yara
rule ChainDrop_NPM_Supply_Chain_Worm
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload files (setup.mjs, math_init.js) by characteristic strings including exfiltration markers, C2 endpoints, environment variable markers, and Dune-themed identifiers"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $marker1 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $marker2 = "thebeautifulmarchoftime" ascii
        $marker3 = "thebeautifulsnadsoftime" ascii
        $marker4 = "Shai-Hulud: Here We Go Again" ascii
        $env_var = "_NODE_RUNTIME_INIT" ascii
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "/router" ascii
        $contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $selector1 = "0x53ed5143" ascii
        $selector2 = "0xd3c159e5" ascii
        $dune1 = "sardaukar" ascii
        $dune2 = "fremen" ascii
        $dune3 = "atreides" ascii
        $dune4 = "harkonnen" ascii
        $file1 = "math_init.js" ascii
        $file2 = "Math_Symbol.js" ascii
        $file3 = "setup.mjs" ascii

    condition:
        filesize < 1MB and
        (
            any of ($marker*) or
            ($env_var and 2 of ($c2_*, $contract, $selector*)) or
            (3 of ($dune*) and 1 of ($file*)) or
            ($contract and 1 of ($selector*))
        )
}
```

### YARA: ChainDrop IDE Persistence Configuration

Detects ChainDrop's cross-linked IDE persistence configuration files -- .claude/settings.json with SessionStart hook pointing to .vscode/setup.mjs, or .vscode/tasks.json with "Environment Setup" task pointing to .claude/setup.mjs.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos_persistence.txt matched ChainDrop_NPM_Persistence_Config; filesize < 10KB scopes to config files only. Cross-reference between IDE directories is the distinctive cue. -->
```yara
rule ChainDrop_NPM_Persistence_Config
{
    meta:
        description = "Detects ChainDrop worm's IDE persistence configuration files -- .claude/settings.json with SessionStart hook or .vscode/tasks.json invoking cross-linked setup.mjs"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "high"

    strings:
        $claude_hook = "SessionStart" ascii
        $claude_cmd = ".vscode/setup.mjs" ascii
        $vscode_task = "Environment Setup" ascii
        $vscode_cmd = ".claude/setup.mjs" ascii

    condition:
        filesize < 10KB and
        (
            ($claude_hook and $claude_cmd) or
            ($vscode_task and $vscode_cmd)
        )
}
```

## Microsoft Defender Detection Names

- Trojan:NPM/ShaiLoader.BY
- Trojan:NPM/MalBun.A
- Trojan:NPM/ShaiWorm.DAY!MTB
- Behavior:Linux/SuspBunActivity.A
- Behavior:Win32/SuspBunActivity.A

## Lessons Learned

1. **npm provenance is not package integrity:** Valid OIDC-based provenance and SLSA attestations only prove a tarball came from a named workflow -- not that the workflow or package content is benign. ChainDrop demonstrates that stolen OIDC tokens can produce fully signed, provenance-verified malicious packages.

2. **Blockchain C2 is an emerging resilience mechanism:** By storing C2 domains in an immutable, censorship-resistant Ethereum smart contract, ChainDrop makes traditional domain takedown ineffective. Defenders need to monitor specific contract addresses and on-chain transactions, not just DNS/HTTP.

3. **CI/CD process memory is a high-value target:** GitHub Actions runner memory contains ephemeral OIDC tokens that are invisible to secret scanning but recoverable via /proc/pid/mem. Ephemeral runners and restricted /proc access are essential mitigations.

4. **IDE persistence is the new autorun:** Cross-linked VS Code tasks.json and Claude Code settings.json hooks silently re-execute payloads whenever developers open projects. IDE vendors must enforce workspace trust boundaries and prompt before executing hooks from untrusted sources.

5. **One credential compromise cascades exponentially:** A single stolen npm token enables automated republishing of every package the identity controls, each of which steals more tokens. The worm's self-propagation architecture turns a linear credential theft into exponential ecosystem compromise.

## Sources

- [Unit42 - ChainDrop npm Worm Analysis](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) — primary technical analysis with full IOCs, infection chain, C2 architecture, and obfuscation details
- [Microsoft Security Blog - ChainDrop Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) — Microsoft Defender detection names, additional IOCs, and credential discovery details
- [The Hacker News - Keyv-Linked npm Worm](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html) — scope assessment (1,684 poisoned versions, 420 packages), timeline, and remediation context
- [The Hacker News - NullReceiver/EtherHiding Blockchain C2](https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html) — related blockchain C2 technique (NullReceiver) using Ethereum transaction destination addresses for IP resolution
- [PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information) — full affected package list (referenced by Unit42)

---
*Report generated by Actioner*
