# Technical Analysis Report: ChainDrop NPM Worm (2026-08-10)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-10
Version: 1.0 (DRAFT)

## Executive Summary

ChainDrop is a self-propagating npm worm that compromised over 400 packages -- including widely-used libraries such as `keyv`, `flat-cache`, and `cache-manager` -- collectively receiving hundreds of millions of weekly downloads. First observed on May 11, 2026, the worm exploits npm preinstall lifecycle hooks to execute a heavily obfuscated Bun-based JavaScript payload that harvests developer credentials (npm tokens, GitHub PATs, cloud access keys, SSH keys), steals GitHub Actions OIDC tokens via runner memory scraping, and automatically republishes infected packages using stolen publishing credentials. SafeDep confirmed 1,684 poisoned versions across 420 package names tied to nine organizations.

The campaign uses a sophisticated three-layer obfuscation scheme (Base91 with custom alphabets, PBKDF2-based byte permutation, AES-256-GCM encryption), blockchain-based C2 domain resolution via an Ethereum smart contract, and GitHub repository-based fallback exfiltration channels. Stolen credentials are published as base64-encoded commit messages in Dune-themed public repositories. The operator wallet traces to a Binance deposit address, providing a potential attribution pivot.

## Background: npm Ecosystem

npm is the default package manager for Node.js, hosting over 2 million packages with billions of monthly downloads. npm's lifecycle hooks (preinstall, postinstall, install) execute arbitrary scripts during package installation, creating a well-known attack surface for supply chain compromise. The `keyv` package alone sees approximately 250 million weekly downloads and sits deep in the dependency tree of many enterprise applications.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-11 | First ChainDrop exfiltration repository created on GitHub |
| 2026-05-22 13:40:28-36 | Three C2 domains registered within 8 seconds: npm-cache[.]com, pypi-get[.]com, js-mirror[.]com |
| 2026-05-25 | Ethereum smart contract deployed at 0xE1f2395ee43e45A1556EC6438a88c31B83493103 |
| 2026-05-25 -- 2026-08-04 | Active credential harvesting and package republishing; 453+ exfiltration repositories created |
| 2026-08-04 | C2 domain rotation via blockchain transaction, switching to awqhnjewqjkl[.]icu |
| 2026-08-04 | 546 public GitHub repositories created with "Shai-Hulud: Here We Go Again" description |
| 2026-08-06 | Unit 42 and Microsoft publish coordinated analysis |

## Root Cause: NPM Token Compromise and Preinstall Hook Abuse

The initial access vector was compromise of npm publishing credentials belonging to maintainers of popular packages. Once a single token was obtained, the worm's self-propagation mechanism created a cascading chain reaction: each compromised maintainer account was used to publish infected versions of all packages that account could access, each of which would then harvest tokens from the next layer of victims. The `preinstall` lifecycle hook ensured malicious code executed before any application code ran, providing a pre-execution window for credential theft.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Loader (setup.mjs)

The worm injects a `preinstall` hook into `package.json`:

```json
"scripts": {
  "preinstall": "node setup.mjs"
}
```

`setup.mjs` checks the `_NODE_RUNTIME_INIT` environment variable to prevent duplicate execution, then downloads the Bun runtime (version 1.3.13) from the legitimate Oven GitHub repository as a portable execution vehicle. The downloaded binary is stored in a temporary directory with `bun-dl-` prefix in the path. On GitHub Actions runners, it detects the `GITHUB_ACTIONS` environment variable and remains attached (foreground execution) to access workflow secrets; on developer workstations, it detaches to continue after installation completes.

**Known hashes (SHA-256):**
- `setup.mjs` (npm tarball variant): `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`
- `setup.mjs` (repository variant): `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`
- `setup.mjs.malicious`: `b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678`

### 2. Stage 2: Obfuscated Payload (Math_Symbol.js / math_init.js)

The core payload is a 727 KB compiled Bun bundle employing three layers of obfuscation:

**Layer 1 -- Base91 Encoding:** 4,613 strings encoded with 73 function-specific Base91 alphabets and 14-position array rotation.

**Layer 2 -- Custom Byte-Permutation Cipher:** 727 additional strings protected by PBKDF2-SHA256 (200,000 iterations) key derivation with Fisher-Yates shuffle-based byte permutation.

**Layer 3 -- AES-256-GCM Encryption:** 10 encrypted blobs (727 KB total) protected by AES-256-GCM plus gzip compression.

**SHA-256:** `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`

The payload includes a locale check that triggers early exit on Russian-language systems with the message "Exiting as russian language detected!"

### 3. C2 Infrastructure

**Primary C2:**
- Domain: npm-cache[.]com
- Endpoint: `hxxps://npm-cache[.]com:443/router`
- IPs: `104.21.91[.]101`, `172.67.215[.]154`

**Secondary C2 (rotated Aug 4):**
- Domain: awqhnjewqjkl[.]icu
- Endpoint: `hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum` (mimics Cloudflare RUM)

**Historical/Fallback Domains:**
- pypi-get[.]com
- js-mirror[.]com

**Blockchain-Based Domain Resolution:**
The worm queries an Ethereum smart contract at address `0xE1f2395ee43e45A1556EC6438a88c31B83493103` using function selector `0x53ed5143` (getter) to retrieve the current C2 domain. The operator uses selector `0xd3c159e5` (setter) to rotate domains. Domain rotation transaction: `0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91`.

**GitHub Fallback C2:**
When primary C2 is unavailable, the worm searches GitHub commits for the marker string `thebeautifulmarchoftime`, expecting cryptographically signed records containing backup domains. A secondary marker `thebeautifulsnadsoftime` is used for planted C2 records.

**Exfiltration Encryption:**
All stolen data is JSON-serialized, gzip-compressed, encrypted with a random AES-256-GCM key and 12-byte IV, then wrapped with RSA-OAEP-SHA256 public key encryption.

### 4. Platform-Specific Behavior

#### GitHub Actions CI/CD Runners

- Detects `GITHUB_ACTIONS` environment variable
- Filters for specific repositories via `GITHUB_REPOSITORY` (e.g., `/opensearch-js`)
- Checks `GITHUB_WORKFLOW_REF` for `release-drafter.yml` workflows
- Scrapes runner process memory via `/proc/<pid>/maps` and `/proc/<pid>/mem` targeting `Runner.Worker` processes to extract OIDC tokens
- Exploits GitHub Actions OIDC tokens for trusted publishing with valid Sigstore provenance attestations

#### Developer Workstations (Linux/macOS/Windows)

- Harvests credentials from:
  - npm tokens (`.npmrc`)
  - GitHub CLI tokens (`.config/gh/hosts.yml`)
  - Docker configs (`.docker/config.json`)
  - Kubernetes configs (`.kube/config`)
  - AWS credentials (`.aws/credentials`)
  - SSH keys (`.ssh/id_*`)
  - Shell histories
  - `.env` files, `.netrc`
  - Bitcoin/Electrum wallets
  - Jenkins encrypted credentials
  - AI tool configurations (Claude Code, etc.)

- Creates persistence files:
  - `.claude/settings.json` (SessionStart hook)
  - `.claude/math_init.js`, `.claude/setup.mjs`
  - `.vscode/tasks.json` (Environment Setup task triggered on folder open)
  - `.vscode/setup.mjs`
  - `.github/workflows/codeql_analysis.yml`

- Latent OS-level persistence artifacts (present but not invoked):
  - `~/.local/bin/gh-token-monitor.sh`
  - `~/.config/gh-token-monitor/`
  - `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` (macOS)
  - `~/.config/systemd/user/gh-token-monitor.service` (Linux)

### 5. Self-Propagation Mechanism

The worm's defining feature is automated republishing:

1. Locates stolen npm tokens from harvested `.npmrc` files
2. Enumerates all packages publishable by the compromised identity
3. Downloads the latest tarball of each package
4. Injects the `setup.mjs` loader and `Math_Symbol.js` payload
5. Adds `preinstall: node setup.mjs` to `package.json`
6. Increments the patch version number
7. Republishes the modified package, preserving legitimate functionality

For packages using GitHub Actions trusted publishing, the worm generates valid OIDC tokens and publishes with authentic Sigstore provenance attestations, bypassing supply chain verification.

### 6. GitHub Exfiltration Channel

Stolen credentials are exfiltrated by creating public repositories under victim GitHub accounts:
- **Repository description:** "Shai-Hulud: Here We Go Again"
- **Naming convention:** Dune-themed combinations using words like `sardaukar`, `mentat`, `fremen`, `atreides`, `harkonnen`
- **Token encoding:** Base64-encoded stolen tokens published as commit messages, prefixed with: `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`

Unit 42 identified 453 public GitHub repositories across 5 accounts matching this exfiltration pattern, with the newest created just 25 minutes before their query.

### 7. Anti-Forensics / Evasion Techniques

- Russian locale detection and early exit (anti-analysis / geofencing)
- `_NODE_RUNTIME_INIT` environment variable to prevent duplicate execution
- Three-layer obfuscation making static analysis extremely difficult
- C2 domain rotation via blockchain (no single domain to block permanently)
- Legitimate Bun binary download from official GitHub (blends with developer tooling)
- Cloudflare RUM URI pattern mimicry (`/cdn-cgi/rum`)
- Multiple rapid patch releases within 70-minute windows to minimize detection window
- GitHub-verified commit badges via `github-actions[bot]` attribution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Versions | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0+ (compromised) | Key-value storage adapter, ~250M weekly downloads |
| flat-cache | 6.1.23 (compromised) | File-based caching library |
| cache-manager | 7.2.9 (compromised) | Multi-tier caching framework |
| cacheable-request | (compromised) | HTTP caching layer |
| 420+ additional packages | 1,684 poisoned versions | Across 9 organizations |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross-platform | setup.mjs (tarball) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | Stage 1 loader (npm tarball variant) |
| Cross-platform | setup.mjs (repo) | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | Stage 1 loader (repository variant) |
| Cross-platform | setup.mjs.malicious | `b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678` | Malicious setup variant |
| Cross-platform | Math_Symbol.js / math_init.js | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Obfuscated Bun payload (727 KB) |
| Cross-platform | .claude/settings.json | -- | Persistence: Claude Code SessionStart hook |
| Cross-platform | .claude/setup.mjs | -- | Persistence: Claude Code malicious loader |
| Cross-platform | .claude/math_init.js | -- | Persistence: Claude Code payload |
| Cross-platform | .vscode/tasks.json | -- | Persistence: VS Code Environment Setup task |
| Cross-platform | .vscode/setup.mjs | -- | Persistence: VS Code malicious loader |
| Cross-platform | .github/workflows/codeql_analysis.yml | -- | Persistence: GitHub Actions workflow |
| Linux | ~/.config/systemd/user/gh-token-monitor.service | -- | Latent systemd persistence (not invoked) |
| macOS | ~/Library/LaunchAgents/com.user.gh-token-monitor.plist | -- | Latent LaunchAgent persistence (not invoked) |
| Cross-platform | ~/.local/bin/gh-token-monitor.sh | -- | Latent token monitoring script (not invoked) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npm-cache[.]com | Primary C2 domain |
| Domain | awqhnjewqjkl[.]icu | Secondary C2 domain (rotated Aug 4) |
| Domain | pypi-get[.]com | Fallback C2 domain |
| Domain | js-mirror[.]com | Fallback C2 domain |
| IP | 104.21.91[.]101 | C2 infrastructure |
| IP | 172.67.215[.]154 | C2 infrastructure |
| URL Pattern | hxxps://npm-cache[.]com:443/router | Primary C2 endpoint |
| URL Pattern | hxxp://awqhnjewqjkl[.]icu/cdn-cgi/rum | Secondary C2 (Cloudflare RUM mimicry) |
| Ethereum Address | 0xE1f2395ee43e45A1556EC6438a88c31B83493103 | Smart contract for C2 domain resolution |
| Ethereum Address | 0x55f9780e1492344b7417fa723aedc4d0b97f31cd | Operator wallet |
| Ethereum Address | 0x35477b7b2df3174B9FE8A681750A7E3fbA20F39B | Binance deposit pivot address |
| Ethereum Tx | 0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91 | C2 domain rotation transaction |
| Ethereum Selector | 0x53ed5143 | Smart contract getter function |
| Ethereum Selector | 0xd3c159e5 | Smart contract setter function |

### Behavioral

- Node process spawning `setup.mjs` followed by Bun runtime execution from `bun-dl-*` temporary paths
- Creation of `.claude/settings.json` or `.vscode/tasks.json` by node/bun processes
- Access to `/proc/<pid>/mem` by node/bun processes (runner memory scraping)
- Rapid sequential reading of `.npmrc`, `.ssh/`, `.aws/credentials`, `.docker/config.json` by a single node/bun process
- Public GitHub repository creation with description containing "Shai-Hulud"
- Commit messages prefixed with "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients"
- GitHub commit searches for "thebeautifulmarchoftime" marker string
- Ethereum `eth_call` to contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` with selector `0x53ed5143`
- Multiple npm patch version publishes within a 70-minute window from the same account

### Microsoft Defender Signatures

| Detection Name | Description |
|---------------|-------------|
| Trojan:NPM/ShaiLoader.BY | Stage 1 loader detection |
| Trojan:NPM/MalBun.A | Malicious Bun payload |
| Trojan:NPM/ShaiWorm.DAY!MTB | Worm propagation component |
| Behavior:Linux/SuspBunActivity.A | Suspicious Bun runtime behavior (Linux) |
| Behavior:Win32/SuspBunActivity.A | Suspicious Bun runtime behavior (Windows) |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into 420+ npm packages via stolen publishing credentials |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Bun runtime downloaded and used to execute obfuscated JavaScript payload |
| T1546 | Event Triggered Execution | npm preinstall hooks, VS Code tasks.json folder open triggers, Claude Code SessionStart hooks |
| T1105 | Ingress Tool Transfer | Bun 1.3.13 runtime downloaded from GitHub as portable execution vehicle |
| T1528 | Steal Application Access Token | npm tokens, GitHub PATs, cloud access tokens harvested from config files |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reading .npmrc, .netrc, .aws/credentials, .docker/config.json, .ssh/id_* |
| T1555 | Credentials from Password Stores | Extraction of credentials from Docker, Helm, Git credential stores |
| T1003 | OS Credential Dumping | /proc/<pid>/mem scraping of GitHub Actions Runner.Worker for OIDC tokens |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communication to npm-cache[.]com/router |
| T1568 | Dynamic Resolution | Ethereum smart contract used for C2 domain rotation and resolution |
| T1098 | Account Manipulation | Republishing packages under compromised maintainer accounts |
| T1537 | Transfer Data to Cloud Account | Exfiltration of stolen tokens via public GitHub repositories |
| T1078.004 | Valid Accounts: Cloud Accounts | Use of stolen OIDC tokens for trusted publishing with valid provenance |
| T1027 | Obfuscated Files or Information | Three-layer obfuscation: Base91, PBKDF2 byte-permutation, AES-256-GCM |
| T1036 | Masquerading | C2 endpoint mimics Cloudflare RUM (/cdn-cgi/rum); workflow named codeql_analysis.yml |

## Impact Assessment

**Breadth:** 1,684 poisoned package versions across 420 package names, affecting 9 organizations. The compromised packages have hundreds of millions of combined weekly downloads, making this one of the largest npm supply chain attacks recorded.

**Depth:** Full credential compromise -- the worm harvests npm tokens, GitHub PATs, cloud provider credentials (AWS, GCP, Azure), SSH keys, Kubernetes configs, Docker configs, and CI/CD secrets. Any developer or CI/CD pipeline that installed an affected version should assume complete credential compromise.

**Stealth:** The three-layer obfuscation, legitimate Bun binary usage, blockchain-based C2 resolution, and valid Sigstore provenance attestations make this exceptionally difficult to detect through casual inspection. Packages retain their legitimate functionality, reducing the likelihood of discovery through behavioral anomalies.

**Attribution:** The operator wallet (`0x55f9780e1492344b7417fa723aedc4d0b97f31cd`) traces to a Binance deposit address, providing a financial pivot for law enforcement. The "Shai-Hulud" malware family has been linked to an April 2026 PyPI compromise (`lightning` package) with identical Claude Code/VS Code hooks, suggesting a single operator or group.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any installed npm packages contain the malicious preinstall hook
find node_modules -name "package.json" -exec grep -l "setup.mjs" {} \;

# Check for ChainDrop persistence artifacts
find . -path "*/.claude/setup.mjs" -o -path "*/.claude/math_init.js" -o -path "*/.vscode/setup.mjs" 2>/dev/null

# Check lockfile for known-compromised package versions
grep -E "(keyv.*6\.0\.0|flat-cache.*6\.1\.23|cache-manager.*7\.2\.9)" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check for Bun downloads in temp directories
find /tmp -name "bun-dl-*" 2>/dev/null

# Check for exfiltration repository patterns
gh repo list --json name,description | jq '.[] | select(.description | contains("Shai-Hulud"))'

# Check npm audit log for recent unexpected publishes
npm audit signatures 2>/dev/null
```

### Remediation

1. **Isolate affected systems immediately.** Do NOT rotate tokens before ensuring the worm is fully removed -- revocation triggers attacker-supplied handlers.
2. **Compare lockfiles** against the published list of affected packages (available in Unit 42's GitHub repository).
3. **Remove malicious persistence files:** `.claude/settings.json`, `.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/setup.mjs`, `.vscode/tasks.json`, `.github/workflows/codeql_analysis.yml`.
4. **Clean-install dependencies** from a known-good lockfile with `--ignore-scripts` flag.
5. **Rotate ALL credentials** that were accessible from compromised environments: npm tokens, GitHub PATs, cloud access keys, SSH keys, Docker registry credentials, Kubernetes service account tokens.
6. **Audit GitHub repositories** for unauthorized Dune-themed repositories or commits with the `IfYouBlockThisAPIKey...` prefix.
7. **Review npm package publish history** for unauthorized patch version bumps.
8. **Notify downstream consumers** if any packages you maintain were affected.

### Long-Term Hardening

- **Enable npm install script restrictions:** Use `--ignore-scripts` by default and explicitly whitelist required lifecycle scripts via `.npmrc` (`ignore-scripts=true`).
- **Enforce 2FA on npm publishing:** Require two-factor authentication for all npm package publishing operations.
- **Pin dependencies:** Use exact version pinning and lockfiles; review all dependency updates before merging.
- **Monitor for unexpected publishes:** Set up alerts for new versions of packages you maintain or depend on.
- **Restrict CI/CD token scope:** Use minimal-privilege tokens in GitHub Actions; avoid storing long-lived credentials in CI.
- **Workspace trust:** Disable automatic VS Code task execution and Claude Code hook execution for untrusted workspaces.

## Detection Rules

These rules target ChainDrop's distinctive artifacts: the `setup.mjs` preinstall loader, Bun runtime download to temporary paths, IDE/editor persistence file injection, C2 domain resolution, and credential file access patterns. All Sigma rules compile against Splunk and LogScale backends; the YARA rules compile with `yarac`. Snort/Suricata rules are structurally valid but were not compiled (tooling not available in the validation environment).

### Sigma Rules

#### 1. ChainDrop NPM Worm - Suspicious Preinstall Script Spawning Bun Runtime

Detects npm preinstall lifecycle hooks executing `setup.mjs`, consistent with ChainDrop's Stage 1 loader.

<!-- audit: sigma check passed (excluding attacktag validator due to proxy restrictions on MITRE ATT&CK data); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; tags attack.t1059.007 (JavaScript execution), attack.t1195.002 (supply chain compromise); logsource process_creation; no auditd hex encoding concerns -->

**Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ChainDrop NPM Worm - Suspicious Preinstall Script Spawning Bun Runtime
id: d8d4af41-6319-4f16-9632-ffda004cb7e8
status: experimental
description: >
    Detects npm preinstall lifecycle hooks executing setup.mjs which then downloads
    and launches the Bun runtime, consistent with the ChainDrop worm's Stage 1 loader.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-10
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/npm'
            - '\node.exe'
            - '\npm.cmd'
    selection_cmdline:
        CommandLine|contains|all:
            - 'setup.mjs'
    condition: selection_parent and selection_cmdline
falsepositives:
    - Legitimate npm packages with setup.mjs preinstall scripts (uncommon)
level: high
```

#### 2. ChainDrop NPM Worm - Bun Runtime Download and Execution

Detects execution of Bun runtime from temporary paths containing `bun-dl-`, matching ChainDrop's portable runtime download pattern.

<!-- audit: sigma check passed; sigma convert splunk/log_scale exit 0; tags attack.t1059.007, attack.t1105; process_creation logsource; Microsoft Defender signatures Behavior:Linux/SuspBunActivity.A and Behavior:Win32/SuspBunActivity.A detect the same pattern -->

**Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ChainDrop NPM Worm - Bun Runtime Download and Execution
id: 993d829a-434e-4268-ae1f-ee0c0340b2c5
status: experimental
description: >
    Detects execution of Bun runtime from temporary or non-standard paths containing
    'bun-dl-' in the path, consistent with ChainDrop downloading Bun 1.3.13 as a portable runtime.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-10
tags:
    - attack.t1059.007
    - attack.t1105
logsource:
    category: process_creation
detection:
    selection:
        Image|contains: 'bun-dl-'
    condition: selection
falsepositives:
    - Developers deliberately downloading and running Bun from temporary directories
level: high
```

#### 3. ChainDrop NPM Worm - IDE Persistence File Creation

Detects creation of `.claude/` or `.vscode/` persistence files by node/bun processes, matching ChainDrop's developer tooling infection.

<!-- audit: sigma check passed; sigma convert splunk/log_scale exit 0; tags attack.t1546, attack.t1137; file_event logsource; persistence files documented in both Unit42 and Microsoft analyses -->

**Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ChainDrop NPM Worm - IDE Persistence File Creation
id: 56dd8b29-6938-4e48-951f-686431a06a8e
status: experimental
description: >
    Detects creation of .claude/settings.json or .vscode/tasks.json persistence files
    by node/npm processes, matching ChainDrop's developer tooling infection vector.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-10
tags:
    - attack.t1546
    - attack.t1137
logsource:
    category: file_event
detection:
    selection_process:
        Image|endswith:
            - '/node'
            - '/bun'
            - '\node.exe'
            - '\bun.exe'
    selection_target:
        TargetFilename|contains:
            - '.claude/settings.json'
            - '.claude/setup.mjs'
            - '.claude/math_init.js'
            - '.vscode/setup.mjs'
    condition: selection_process and selection_target
falsepositives:
    - IDE extensions generating configuration files during normal operation
level: high
```

#### 4. ChainDrop NPM Worm - C2 Domain DNS Resolution

Detects DNS queries to known ChainDrop C2 domains.

<!-- audit: sigma check passed; sigma convert splunk/log_scale exit 0; tags attack.t1071.001, attack.t1568; dns_query logsource; IOC values are NOT defanged in the rule per logsource-encoding.md guidance; all four domains from Unit42 and Microsoft reports -->

**Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ChainDrop NPM Worm - C2 Domain DNS Resolution
id: a1bc9ec0-f88f-4936-b85d-aa72b2005485
status: experimental
description: >
    Detects DNS queries to known ChainDrop C2 domains used for command-and-control
    communication and payload delivery.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-10
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
    - None expected; these are attacker-registered domains
level: critical
```

#### 5. ChainDrop NPM Worm - GitHub Actions Runner Memory Scraping

Detects `/proc/*/mem` access by node/bun processes, consistent with ChainDrop's OIDC token theft.

<!-- audit: sigma check passed; sigma convert splunk/log_scale exit 0; tags attack.t1003, attack.t1528; file_event with product linux; targets Runner.Worker memory scraping documented in Unit42 analysis -->

**Compile status:** ✅ compiles | **Confidence:** medium (procfs access by node is unusual but possible in monitoring tools)

```yaml
title: ChainDrop NPM Worm - GitHub Actions Runner Memory Scraping
id: c10fbafd-0f6c-4426-989f-7189689dc5bc
status: experimental
description: >
    Detects access to /proc/*/mem targeting GitHub Actions Runner.Worker processes,
    consistent with ChainDrop's OIDC token theft from CI runner memory.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
author: Actioner
date: 2026-08-10
tags:
    - attack.t1003
    - attack.t1528
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: '/proc/'
        TargetFilename|endswith: '/mem'
        Image|endswith:
            - '/bun'
            - '/node'
    condition: selection
falsepositives:
    - Debugging tools or profilers that read process memory via procfs
level: high
```

#### 6. ChainDrop NPM Worm - Credential File Access by Node/Bun Process

Detects node/bun processes reading sensitive credential files.

<!-- audit: sigma check passed; sigma convert splunk/log_scale exit 0; tags attack.t1552.001, attack.t1555; file_event logsource; credential paths from Unit42 comprehensive harvesting list; medium confidence due to legitimate npm/node tools that may access .npmrc -->

**Compile status:** ✅ compiles | **Confidence:** medium

```yaml
title: ChainDrop NPM Worm - Credential File Access by Node/Bun Process
id: e5be4891-964f-4d41-9a04-80892a38b893
status: experimental
description: >
    Detects Node.js or Bun processes reading sensitive credential files such as
    .npmrc, .netrc, SSH keys, and cloud configs, matching ChainDrop's credential harvesting.
references:
    - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-10
tags:
    - attack.t1552.001
    - attack.t1555
logsource:
    category: file_event
detection:
    selection_process:
        Image|endswith:
            - '/node'
            - '/bun'
            - '\node.exe'
            - '\bun.exe'
    selection_files:
        TargetFilename|contains:
            - '.npmrc'
            - '.netrc'
            - '.ssh/id_'
            - '.docker/config.json'
            - '.kube/config'
            - '.aws/credentials'
            - '.config/gh/hosts.yml'
    condition: selection_process and selection_files
falsepositives:
    - Node.js applications that legitimately read Docker, Kubernetes, or cloud credentials
level: medium
```

### YARA Rules

Four YARA rules targeting ChainDrop's loader, obfuscated payload, credential harvester, and propagation module.

<!-- audit: yarac chaindrop-payload.yar /dev/null exit 0; all rules compile; second attempt after fixing unreferenced $opensearch string; rules target specific ChainDrop artifacts documented in Unit42 and Microsoft analyses -->

**Compile status:** ✅ compiles | **Confidence:** high (rules use multiple ChainDrop-specific strings with AND logic)

```yara
/*
    ChainDrop NPM Worm - Malicious Payload Detection
    References:
        - https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
        - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
*/

rule ChainDrop_Setup_Loader
{
    meta:
        description = "Detects ChainDrop setup.mjs loader script that bootstraps the Bun runtime and executes the obfuscated payload"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        severity = "critical"

    strings:
        $preinstall = "\"preinstall\"" ascii
        $setup_mjs = "setup.mjs" ascii
        $bun_dl = "bun-dl-" ascii
        $node_runtime = "_NODE_RUNTIME_INIT" ascii
        $math_symbol = "Math_Symbol" ascii
        $math_init = "math_init.js" ascii

    condition:
        filesize < 1MB and
        3 of them
}

rule ChainDrop_Obfuscated_Payload
{
    meta:
        description = "Detects ChainDrop's heavily obfuscated Bun-based payload containing Base91 encoding with custom alphabets and PBKDF2 key derivation"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $shai_hulud = "Shai-Hulud" ascii wide
        $here_we_go = "Here We Go Again" ascii wide
        $russian_check = "russian language detected" ascii nocase
        $marker1 = "thebeautifulmarchoftime" ascii
        $marker2 = "thebeautifulsnadsoftime" ascii
        $api_key_msg = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $eth_selector = "0x53ed5143" ascii

    condition:
        filesize < 2MB and
        2 of them
}

rule ChainDrop_Credential_Harvester
{
    meta:
        description = "Detects ChainDrop credential harvesting component targeting cloud tokens, SSH keys, and developer tool configurations"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "high"

    strings:
        $npm_cache_c2 = "npm-cache.com" ascii
        $pypi_get_c2 = "pypi-get.com" ascii
        $js_mirror_c2 = "js-mirror.com" ascii
        $c2_path = "/router" ascii
        $c2_path2 = "/cdn-cgi/rum" ascii
        $cred1 = ".npmrc" ascii
        $cred2 = ".docker/config.json" ascii
        $cred3 = "gh-token-monitor" ascii
        $cred4 = ".kube/config" ascii
        $proc_mem = "/proc/" ascii
        $proc_maps = "/maps" ascii

    condition:
        filesize < 2MB and
        1 of ($npm_cache_c2, $pypi_get_c2, $js_mirror_c2) and
        2 of ($cred*, $c2_path, $c2_path2, $proc_mem, $proc_maps)
}

rule ChainDrop_NPM_Worm_Propagation
{
    meta:
        description = "Detects ChainDrop's npm self-propagation module that steals tokens and republishes packages with malicious preinstall hooks"
        author = "Actioner"
        date = "2026-08-10"
        reference = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
        severity = "critical"

    strings:
        $dune1 = "sardaukar" ascii
        $dune2 = "mentat" ascii
        $dune3 = "fremen" ascii
        $dune4 = "atreides" ascii
        $dune5 = "harkonnen" ascii
        $shai = "Shai-Hulud" ascii
        $opensearch = "opensearch-js" ascii
        $release_drafter = "release-drafter.yml" ascii
        $preinstall = "preinstall" ascii
        $setup = "setup.mjs" ascii

    condition:
        filesize < 2MB and
        2 of ($dune*) and
        ($shai or ($preinstall and $setup) or ($opensearch and $release_drafter))
}
```

### Snort/Suricata Rules

Eight network-level rules targeting ChainDrop's C2 domains, Ethereum smart contract queries, and GitHub fallback C2 marker searches.

<!-- audit: Snort/Suricata not installed in validation environment; rules follow standard Suricata syntax with tls.sni for encrypted C2 and http.request_body for Ethereum JSON-RPC; SIDs in 2026081001-2026081008 range -->

**Compile status:** ⚠️ uncompiled (structural check only) | **Confidence:** high (IOC-based domain matching)

```
# Rule 1: ChainDrop C2 beacon to primary domain
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - C2 Communication to npm-cache.com"; tls.sni; content:"npm-cache.com"; endswith; classtype:trojan-activity; sid:2026081001; rev:1;)

# Rule 2: ChainDrop C2 beacon to secondary domain
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - C2 Communication to awqhnjewqjkl.icu"; tls.sni; content:"awqhnjewqjkl.icu"; endswith; classtype:trojan-activity; sid:2026081002; rev:1;)

# Rule 3: ChainDrop fallback C2 domains
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - Fallback C2 pypi-get.com"; tls.sni; content:"pypi-get.com"; endswith; classtype:trojan-activity; sid:2026081003; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - Fallback C2 js-mirror.com"; tls.sni; content:"js-mirror.com"; endswith; classtype:trojan-activity; sid:2026081004; rev:1;)

# Rule 4: Ethereum API call for blockchain C2 resolution
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - Ethereum Smart Contract C2 Resolution"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"eth_call"; content:"e1f2395ee43e45a1556ec6438a88c31b83493103"; nocase; classtype:trojan-activity; sid:2026081005; rev:1;)

# Rule 5: GitHub commit search for fallback C2 marker
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - GitHub Fallback C2 Marker Search"; flow:established,to_server; http.uri; content:"api.github.com"; content:"search/commits"; content:"thebeautifulmarchoftime"; classtype:trojan-activity; sid:2026081006; rev:1;)

# Rule 6: ChainDrop C2 beacon URI pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - C2 Router Endpoint"; flow:established,to_server; http.uri; content:"/router"; http.host; content:"npm-cache.com"; classtype:trojan-activity; sid:2026081007; rev:1;)

# Rule 7: ChainDrop exfiltration via Cloudflare-mimicking URI
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ChainDrop NPM Worm - Cloudflare-Mimicking C2 Endpoint"; flow:established,to_server; http.uri; content:"/cdn-cgi/rum"; http.host; content:"awqhnjewqjkl.icu"; classtype:trojan-activity; sid:2026081008; rev:1;)
```

## Lessons Learned

1. **Lifecycle hooks remain the npm ecosystem's Achilles' heel.** The `preinstall` hook provides an unrestricted pre-execution window before any application code runs. Until npm implements mandatory script isolation or opt-in execution (similar to `--ignore-scripts` by default), every `npm install` is a trust exercise with every transitive dependency in the tree.

2. **Supply chain provenance is necessary but not sufficient.** ChainDrop demonstrated that Sigstore provenance attestations and GitHub-verified badges can be produced by malware exploiting legitimate CI/CD infrastructure. Provenance proves "this artifact came from this pipeline" -- it does not prove the pipeline is trustworthy if the pipeline's credentials are compromised.

3. **Blockchain-based C2 creates a resilience challenge for defenders.** Traditional domain takedown processes are ineffective when the malware resolves its current C2 domain from an immutable Ethereum smart contract. Defenders must monitor for the specific contract interaction pattern rather than relying solely on domain blocklists.

4. **Developer tooling is now a persistence vector.** The infection of `.claude/` and `.vscode/` configuration files represents a new class of persistence that targets the developer's daily workflow. IDE and coding assistant vendors should implement workspace trust boundaries and signature verification for configuration files.

5. **Credential rotation order matters.** The worm contains handlers triggered by credential revocation, meaning premature token rotation before full cleanup could alert the attacker or trigger additional malicious actions. Containment must precede rotation.

## Sources

- [Unit 42 - ChainDrop NPM Worm Analysis](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) -- Primary technical analysis with complete IOC list, obfuscation layer details, blockchain C2 mechanism, and propagation chain
- [Microsoft Security Blog - ChainDrop Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) -- Microsoft Defender signatures, OIDC exploitation details, and platform-specific behavioral analysis
- [The Hacker News - Keyv-Linked NPM Worm Poisons Hundreds](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html) -- Scope confirmation (1,684 versions across 420 packages), SafeDep/Aikido verification, and connection to April 2026 PyPI lightning compromise
- [The Hacker News - Nearly 800 Malicious NPM Packages](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html) -- Related WEL1DROPPER campaign context (separate actor, different technique: typosquatting + Cloudflare Workers delivery)
- [The Hacker News - Trojanized NPM Packages Decode C2 IP](https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html) -- Related NullReceiver campaign using Ethereum transaction address bytes for C2 IP encoding (separate DPRK-linked actor)

---
*Report generated by Actioner*
