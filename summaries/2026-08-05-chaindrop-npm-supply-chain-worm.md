# Technical Analysis Report: ChainDrop npm Supply Chain Worm (August 2026)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-05
Version: 1.1 (FINAL)

## Executive Summary

A self-propagating npm supply chain worm, tracked as "ChainDrop" (also known as "Shai-Hulud"), has compromised over 400 npm packages across 1,381 malicious versions with a combined reach exceeding 2 billion monthly downloads. The worm was initially introduced through `keyv@6.0.0` and has since propagated across 79+ package names within the Keyv and Cacheable namespaces. The malware steals developer credentials -- including npm tokens, GitHub PATs, AWS credentials, Kubernetes configs, and cloud CLI tokens -- then uses the stolen npm tokens to automatically republish poisoned versions of packages the compromised developer maintains, creating a self-sustaining infection chain.

The attack employs a sophisticated multi-stage execution chain: a `setup.mjs` preinstall hook bootstraps the Bun runtime (downloading it if absent), which then executes a compiled 727KB stage-2 payload. Exfiltration uses AES-256-GCM encryption with RSA-OAEP key wrapping, transmitted over HTTPS to C2 domains (`npm-cache[.]com`, `pypi-get[.]com`, `js-mirror[.]com`) with a GitHub-based fallback channel. The worm also plants persistence hooks in `.claude/settings.json` and `.vscode/tasks.json` to re-execute when developer environments are opened.

## Background: npm Ecosystem

npm is the default package manager for Node.js, hosting over 2 million packages and serving as the backbone of modern JavaScript/TypeScript development. The ecosystem's `preinstall`/`postinstall` lifecycle hooks allow arbitrary code execution during `npm install`, a feature that has been repeatedly exploited in supply chain attacks. Packages like `keyv` (key-value storage adapter), `flat-cache`, and `cache-manager` are deeply embedded transitive dependencies, meaning a single compromised version can cascade through thousands of downstream projects and CI/CD pipelines.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-01 (est.) | Initial malicious release of `keyv@6.0.0` to npm registry |
| 2026-08-01 -- 2026-08-03 | Worm propagates across Keyv, Cacheable, and related package namespaces via stolen tokens |
| 2026-08-03 (est.) | `flat-cache@6.1.23` and `cache-manager@7.2.9` confirmed compromised |
| 2026-08-04 | Microsoft Security publishes initial analysis; npm begins package takedowns |
| 2026-08-04 -- 2026-08-05 | Security community confirms 400+ packages, 868+ versions, 79+ unique package names affected |
| 2026-08-05 | Microsoft Defender signatures (`Trojan:NPM/ShaiLoader.BY`, `Trojan:NPM/MalBun.A`, `Trojan:NPM/ShaiWorm.DAY!MTB`) deployed |

## Root Cause: Supply Chain Compromise via Stolen npm Tokens

The initial vector appears to be a compromised npm maintainer account or stolen npm token for the `keyv` package. Once the attacker gained the ability to publish to a single high-value package, the worm's self-propagating design took over: each infection harvests npm tokens from the victim's environment, validates them against `registry.npmjs[.]org/-/whoami`, then uses valid tokens to publish malicious versions of other packages the developer maintains. Cross-org publishing bursts occur every 2-7 minutes, explaining the rapid spread across 400+ packages.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Preinstall Hook (setup.mjs)

The worm injects a `setup.mjs` file into compromised package tarballs and adds a preinstall lifecycle hook to `package.json`:

```json
"scripts": {
    "preinstall": "node setup.mjs"
}
```

**SHA256:** `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`

Stage 1 performs the following:
1. Checks for the Bun runtime on the system
2. If absent, downloads Bun v1.3.13 from GitHub releases
3. Launches the Stage 2 compiled bundle via Bun

### 2. Stage 2: Compiled Payload Bundle

The Stage 2 payload is a compiled JavaScript bundle (727,680 bytes) executed by Bun. It performs:

- **Credential harvesting**: Searches for npm tokens (prefix `npm_`), GitHub PATs (`ghp_`, `gho_`, `ghs_`), and executes CLI commands (`gh auth token`, `gcloud config config-helper`, `az account get-access-token`, `azd auth token`) to steal active cloud credentials
- **Broad secret collection**: AWS credentials, Kubernetes configs (`~/.kube/config`), HashiCorp Vault tokens, SSH keys, shell history files, and GitHub Actions runner secrets/OIDC tokens
- **Token validation**: Validates npm tokens against `registry.npmjs[.]org/-/whoami` before use
- **Worm propagation**: Downloads latest tarballs of targetable packages, injects `setup.mjs` + preinstall hook, increments patch version, and republishes using stolen npm tokens

Additional payload variants are dropped as `Math_Symbol.js`, `Math_init.js`, or `math_<guid>.js` files.

**SHA256 (Math_*.js variants):** `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`

### 3. C2 Infrastructure

**Primary C2 domains:**
- `npm-cache[.]com`
- `pypi-get[.]com`
- `js-mirror[.]com`

**C2 endpoint:** `hxxps://npm-cache[.]com:443/router`

**Dynamic domain resolution:** The malware queries an Ethereum smart contract at address `0xE1f2395ee43e45A1556EC6438a88c31B83493103` (function selector `0x53ed5143`) to obtain updated C2 domains, providing resilience against domain takedowns.

**Fallback exfiltration:** When primary C2 is unavailable, the worm exfiltrates data via GitHub repositories whose descriptions contain the marker string "Shai-Hulud: Here We Go Again".

### 4. Persistence Mechanisms

The worm plants two persistence mechanisms targeting developer environments:

**Claude Code hook:**
- Creates `.claude/settings.json` with a `SessionStart` hook pointing to `.vscode/setup.mjs`
- **SHA256:** `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`

**VS Code task:**
- Creates `.vscode/tasks.json` with an "Environment Setup" task configured with `"runOn": "folderOpen"`, causing re-execution when the project folder is opened

### 5. Exfiltration Method

Stolen credentials and secrets are packaged as JSON, compressed with gzip, encrypted with AES-256-GCM (random key and IV per payload), then the AES key is wrapped with RSA-OAEP-SHA256 (using the attacker's embedded public key). The encrypted blob is sent via HTTPS POST to the C2 `/router` endpoint. When HTTPS exfiltration fails, the worm falls back to Base64-encoding the payload and pushing it to GitHub repositories. Result files follow the naming pattern `results-<timestamp>-<counter>.json`.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0 | Initial infection vector; preinstall hook + setup.mjs |
| flat-cache | 6.1.23 | Worm-propagated; preinstall hook + setup.mjs |
| cache-manager | 7.2.9 | Worm-propagated; preinstall hook + setup.mjs |
| 79+ package names | 868+ versions | Keyv, Cacheable namespace packages |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Cross-platform | `setup.mjs` (in package) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | Stage 1 preinstall loader |
| Cross-platform | `.claude/settings.json`, `.vscode/setup.mjs` | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | Persistence hook / repository loader |
| Cross-platform | `Math_Symbol.js`, `Math_init.js`, `math_<guid>.js` | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Stage 2 payload variants |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `npm-cache[.]com` | Primary C2 domain |
| Domain | `pypi-get[.]com` | Secondary C2 domain |
| Domain | `js-mirror[.]com` | Tertiary C2 domain |
| URL Pattern | `hxxps://npm-cache[.]com:443/router` | C2 callback endpoint |
| Ethereum | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` | Smart contract for dynamic C2 domain resolution |

### Behavioral

- `node` or `bun` process executing `setup.mjs` as a child of npm install
- Child processes spawned by `node`/`bun` running `gh auth token`, `gcloud config config-helper`, `az account get-access-token`, or `azd auth token`
- Creation of `Math_Symbol.js`, `Math_init.js`, or `math_<guid>.js` files in package directories
- Unexpected npm publish operations from CI/CD environments
- DNS queries to `npm-cache[.]com`, `pypi-get[.]com`, or `js-mirror[.]com`
- Creation of `.claude/settings.json` or `.vscode/tasks.json` by node/bun processes
- Bun runtime downloads from GitHub during npm install lifecycle

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into legitimate npm packages via stolen tokens; worm auto-publishes poisoned versions |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript (setup.mjs, Math_*.js) executed via Node.js and Bun runtime |
| T1105 | Ingress Tool Transfer | Bun runtime downloaded from GitHub when not present on victim system |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests npm tokens, GitHub PATs, AWS credentials, SSH keys, K8s configs, shell histories |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential bundles sent to C2 via HTTPS POST to /router endpoint |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communication; GitHub fallback exfiltration |
| T1546 | Event Triggered Execution | Persistence via .claude/settings.json SessionStart hooks and .vscode/tasks.json folderOpen tasks |
| T1568 | Dynamic Resolution | Ethereum smart contract queried for updated C2 domain addresses |

## Impact Assessment

**Breadth:** 400+ packages, 1,381+ versions, 79+ unique package names, 2 billion+ combined monthly downloads. Any developer or CI/CD system that installed an affected version is potentially compromised.

**Depth:** Complete credential theft -- npm tokens, GitHub PATs, cloud provider tokens (AWS, GCP, Azure), SSH keys, Kubernetes configs, and CI/CD runner secrets. Stolen npm tokens enable cascading supply chain compromise through automated republishing.

**Stealth:** The preinstall hook executes silently during `npm install`. The compiled Bun payload and encrypted exfiltration make static analysis difficult. The Ethereum-based dynamic domain resolution provides resilience against infrastructure takedowns.

## Detection & Remediation

### Immediate Detection

```bash
# Check for setup.mjs preinstall hooks in node_modules
find ./node_modules -name "setup.mjs" -exec grep -l "preinstall" {} \;

# Check for Math_*.js payload variants
find ./node_modules -regex '.*/Math_\(Symbol\|init\)\.js' -o -regex '.*/math_[0-9a-f-]*\.js'

# Check for .claude/settings.json with SessionStart hooks
find . -path '*/.claude/settings.json' -exec grep -l 'SessionStart' {} \;

# Check for .vscode/tasks.json with folderOpen auto-run
find . -path '*/.vscode/tasks.json' -exec grep -l 'folderOpen' {} \;

# Check package.json for suspicious preinstall hooks referencing setup.mjs
grep -r '"preinstall".*setup\.mjs' ./node_modules/*/package.json

# Verify known-compromised package versions in lockfile
grep -E '(keyv@6\.0\.0|flat-cache@6\.1\.23|cache-manager@7\.2\.9)' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check DNS logs for C2 domains
grep -iE '(npm-cache\.com|pypi-get\.com|js-mirror\.com)' /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Immediate containment**: Remove all affected package versions from `node_modules` and lockfiles; pin to known-good versions before the malicious releases
2. **Credential rotation (CRITICAL)**: Rotate ALL npm tokens, GitHub PATs, AWS access keys, GCP service account keys, Azure tokens, SSH keys, and any other credentials present on affected systems
3. **npm token revocation**: Run `npm token revoke` for all tokens; regenerate with narrowest possible scope
4. **Audit npm publish history**: Review `npm access ls-packages` and `npm info <package> time` for unauthorized publishes
5. **CI/CD pipeline audit**: Check GitHub Actions runner environments and CI/CD secrets for signs of exfiltration
6. **Bun cleanup**: Remove any unexpectedly installed Bun runtimes (`which bun`, check `/tmp/` and `~/.bun/`)
7. **Repository cleanup**: Remove any malicious `.claude/settings.json`, `.vscode/setup.mjs`, or `.vscode/tasks.json` files planted by the worm

### Long-Term Hardening

- Enable npm 2FA for all package maintainers, especially for high-download packages
- Use `npm audit signatures` to verify package provenance
- Implement lockfile-only installs in CI/CD (`npm ci` instead of `npm install`)
- Configure `ignore-scripts=true` globally or use `--ignore-scripts` in CI/CD; explicitly allow needed lifecycle scripts
- Monitor npm publish events via registry webhooks or tools like Socket.dev
- Implement network egress filtering to block unknown domains from CI/CD environments
- Consider using npm package provenance attestations (Sigstore) where available

## Detection Rules

16 detection rules cover the ChainDrop/Shai-Hulud worm across endpoint (6 Sigma), file (3 YARA), and network (6 Snort + 7 Suricata = 13 network) layers. Confidence spread: 2 critical, 10 high, 4 medium. All rules key on concrete artifacts from the intelligence -- C2 domains, filenames, execution patterns, and credential theft commands. Snort SIDs use the 1000010-1000015 range; Suricata SIDs use 1000020-1000026 (both outside the Emerging Threats Pro reserved range). The primary caveat is that the C2 domain-based rules will become stale if the attacker rotates to new infrastructure via their Ethereum-based dynamic resolution mechanism.

### Sigma: Process Creation -- setup.mjs Preinstall Hook Execution

Detects node or bun executing `setup.mjs`, the ChainDrop worm's preinstall lifecycle hook.
**Compile: pass (convert) | Confidence: medium**

<!-- Audit: sigma convert --without-pipeline -t splunk produces valid SPL. sigma check blocked by environment network restriction (MITRE ATT&CK data fetch). No defanged values in rule. Fields match Sysmon process_creation schema. -->
<!-- revision: confidence downgraded high->medium; setup.mjs is a generic filename that could appear in legitimate packages -->

```yaml
title: ChainDrop NPM Worm - Node/Bun Execution of setup.mjs Preinstall Hook
id: 8a3f1e2b-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: experimental
description: >
    Detects execution of setup.mjs via node or bun runtime, as used by the
    ChainDrop/Shai-Hulud npm supply chain worm as a preinstall lifecycle hook
    to bootstrap the malware payload.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.bleepingcomputer.com/news/security/massive-chaindrop-npm-supply-chain-attack-infects-hundreds-of-packages/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_runtime:
        Image|endswith:
            - '/node'
            - '\node.exe'
            - '/bun'
            - '\bun.exe'
    selection_script:
        CommandLine|contains: 'setup.mjs'
    condition: selection_runtime and selection_script
falsepositives:
    - Legitimate packages using setup.mjs as a preinstall hook (uncommon naming)
level: medium
```

### Sigma: Process Creation -- Bun Runtime Download During npm Install

Detects a node process downloading the Bun runtime from GitHub, a ChainDrop Stage 1 behavior.
**Compile: pass (convert) | Confidence: medium**

<!-- Audit: sigma convert produces valid SPL/LogScale. ParentImage and CommandLine fields are standard Sysmon process_creation fields. -->
<!-- revision: confidence downgraded high->medium; developers legitimately install Bun from GitHub via npm lifecycle scripts -->

```yaml
title: ChainDrop NPM Worm - Bun Runtime Download During npm Install
id: 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects a node process spawning a child process that downloads the Bun
    runtime from GitHub, as performed by the ChainDrop worm Stage 1 loader
    when Bun is not already present on the system.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '\node.exe'
    selection_download:
        CommandLine|contains|all:
            - 'bun'
            - 'github.com'
    condition: selection_parent and selection_download
falsepositives:
    - Developers intentionally installing Bun via npm lifecycle scripts
level: medium
```

### Sigma: File Event -- Math_*.js Payload File Drops

Detects creation of Math_Symbol.js, Math_init.js, or math_<guid>.js files characteristic of ChainDrop payload variants.
**Compile: pass (convert) | Confidence: high**

<!-- Audit: Regex pattern in TargetFilename matches the documented file naming convention. sigma convert produces valid SPL with regex command. -->

```yaml
title: ChainDrop NPM Worm - Math_*.js Malicious File Drop
id: 2c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects creation of Math_Symbol.js, Math_init.js, or math_<guid>.js
    files characteristic of the ChainDrop/Shai-Hulud npm worm payload
    variants dropped during the infection chain.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://hackread.com/shai-hulud-npm-worm-poisoning-1280-packages/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|re: '(?i)(Math_Symbol|Math_init|math_[0-9a-f\-]{8,36})\.js$'
    condition: selection
falsepositives:
    - Highly unlikely; Math_Symbol.js and Math_init.js are not standard library filenames
level: critical
```

### Sigma: DNS Query -- C2 Domain Resolution

Detects DNS queries to the three known ChainDrop C2 domains.
**Compile: pass (convert) | Confidence: high**

<!-- Audit: Domains are not defanged in the rule (real values for detection). sigma convert produces valid SPL with IN() operator for QueryName. -->

```yaml
title: ChainDrop NPM Worm - DNS Query to Known C2 Domains
id: 3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: >
    Detects DNS resolution requests to the known ChainDrop/Shai-Hulud C2
    domains npm-cache.com, pypi-get.com, and js-mirror.com used for
    command-and-control and credential exfiltration.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.bleepingcomputer.com/news/security/massive-chaindrop-npm-supply-chain-attack-infects-hundreds-of-packages/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'npm-cache.com'
            - 'pypi-get.com'
            - 'js-mirror.com'
    condition: selection
falsepositives:
    - None expected; these are known malicious infrastructure domains
level: critical
```

### Sigma: Process Creation -- Developer Credential Harvesting Commands

Detects node/bun spawning credential harvesting CLI commands targeting GitHub, GCP, and Azure.
**Compile: pass (convert) | Confidence: high**

<!-- Audit: CommandLine values match documented credential theft commands verbatim. ParentImage filter to node/bun reduces false positives from legitimate CLI usage. -->

```yaml
title: ChainDrop NPM Worm - Developer Credential Harvesting Commands
id: 4e5f6a7b-8c9d-0e1f-2a3b-4c5d6e7f8a9b
status: experimental
description: >
    Detects execution of credential harvesting commands used by the
    ChainDrop/Shai-Hulud worm to steal developer tokens from GitHub CLI,
    GCloud, Azure CLI, and Azure Developer CLI.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1552.001
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '\node.exe'
            - '/bun'
            - '\bun.exe'
    selection_cred_commands:
        CommandLine|contains:
            - 'gh auth token'
            - 'gcloud config config-helper'
            - 'az account get-access-token'
            - 'azd auth token'
    condition: selection_parent and selection_cred_commands
falsepositives:
    - CI/CD pipelines that legitimately invoke these commands with node/bun as parent
level: high
```

### Sigma: File Event -- Malicious Claude/VSCode Hook Files

Detects creation of .claude/settings.json or .vscode/setup.mjs by node/bun processes for re-execution persistence.
**Compile: pass (convert) | Confidence: medium**

<!-- Audit: Correlated file creation + parent process image. Medium confidence because the file names alone are legitimate; the node/bun parent correlation reduces FPs but is not unique to ChainDrop. -->
<!-- revision: fixed YAML description to say .vscode/setup.mjs (matches detection logic), was incorrectly saying .vscode/tasks.json -->

```yaml
title: ChainDrop NPM Worm - Malicious Claude/VSCode Hook Files
id: 5f6a7b8c-9d0e-1f2a-3b4c-5d6e7f8a9b0c
status: experimental
description: >
    Detects creation of .claude/settings.json or .vscode/setup.mjs files
    by node/bun processes, as planted by the ChainDrop worm for
    re-execution persistence via Claude Code SessionStart hooks and
    VS Code folderOpen tasks.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
author: Actioner
date: 2026-08-05
tags:
    - attack.t1546
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection_claude:
        TargetFilename|endswith: '.claude/settings.json'
    selection_vscode_setup:
        TargetFilename|endswith: '.vscode/setup.mjs'
    selection_parent:
        Image|endswith:
            - '/node'
            - '\node.exe'
            - '/bun'
            - '\bun.exe'
    condition: (selection_claude or selection_vscode_setup) and selection_parent
falsepositives:
    - Developers manually creating .claude/settings.json or .vscode configuration files via node scripts
level: high
```

### YARA: ChainDrop/Shai-Hulud Setup Loader

Detects the ChainDrop setup.mjs loader and Stage 2 payload by C2 domains, Ethereum contract, GitHub fallback markers, and encryption indicators.
**Compile: pass (yarac) | Confidence: high**

<!-- Audit: yarac compiles clean (exit 0). All strings referenced in condition. Hashes from Microsoft advisory embedded in meta. No PE header check (JS payload, not PE). filesize < 1MB appropriate for JS payloads. -->

```yara
rule ChainDrop_ShaiHulud_Setup_Loader
{
    meta:
        description = "Detects the ChainDrop/Shai-Hulud npm worm setup.mjs preinstall loader and Math_*.js payload variants based on known hashes and distinctive strings"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash1 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        hash2 = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        hash3 = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "pypi-get.com" ascii
        $c2_3 = "js-mirror.com" ascii
        $uri = "/router" ascii
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii
        $eth_selector = "0x53ed5143" ascii
        $gh_fallback = "Shai-Hulud: Here We Go Again" ascii
        $npm_whoami = "registry.npmjs.org/-/whoami" ascii
        $aes_gcm = "aes-256-gcm" ascii nocase
        $rsa_oaep = "RSA-OAEP" ascii

    condition:
        filesize < 1MB and
        (
            (2 of ($c2_*) and $uri) or
            ($eth_contract and $eth_selector) or
            ($gh_fallback) or
            ($npm_whoami and 1 of ($c2_*)) or
            ($aes_gcm and $rsa_oaep and 1 of ($c2_*))
        )
}
```

### YARA: ChainDrop Math_*.js Payload Variant

Detects ChainDrop Math_Symbol.js / Math_init.js variants by credential theft command strings and C2 indicators.
**Compile: pass (yarac) | Confidence: high**

<!-- Audit: Condition requires C2 domain AND (credential commands OR token prefix patterns) -- tight conjunction reduces false positives on generic JS files. -->

```yara
rule ChainDrop_ShaiHulud_MathJS_Variant
{
    meta:
        description = "Detects ChainDrop Math_Symbol.js / Math_init.js payload variants by filename-embedded strings and C2 indicators"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_1 = "npm-cache.com" ascii
        $c2_2 = "pypi-get.com" ascii
        $c2_3 = "js-mirror.com" ascii
        $cred_1 = "gh auth token" ascii
        $cred_2 = "gcloud config config-helper" ascii
        $cred_3 = "az account get-access-token" ascii
        $cred_4 = "azd auth token" ascii
        $tok_npm = "npm_" ascii
        $tok_ghp = "ghp_" ascii
        $tok_gho = "gho_" ascii
        $tok_ghs = "ghs_" ascii

    condition:
        filesize < 1MB and
        1 of ($c2_*) and
        (2 of ($cred_*) or 3 of ($tok_*))
}
```

### YARA: ChainDrop Persistence Hook Files

Detects .claude/settings.json and .vscode/tasks.json persistence payloads planted by the worm.
**Compile: pass (yarac) | Confidence: medium**

<!-- Audit: filesize < 100KB appropriate for JSON config files. Condition requires specific string combinations (SessionStart + .vscode/setup.mjs, or Environment Setup + folderOpen + setup.mjs). -->

```yara
rule ChainDrop_ShaiHulud_Persistence_Hook
{
    meta:
        description = "Detects ChainDrop persistence files planted in .claude/settings.json or .vscode/tasks.json with malicious hooks"
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        tlp = "WHITE"
        severity = "high"

    strings:
        $claude_hook = "SessionStart" ascii
        $claude_setup = ".vscode/setup.mjs" ascii
        $vscode_task = "Environment Setup" ascii
        $vscode_run = "folderOpen" ascii
        $setup_mjs = "setup.mjs" ascii

    condition:
        filesize < 100KB and
        (
            ($claude_hook and $claude_setup) or
            ($vscode_task and $vscode_run and $setup_mjs)
        )
}
```

### Snort: DNS and TLS Detection for ChainDrop C2 Domains

Six rules detecting DNS queries and TLS ClientHello SNI for the three C2 domains.
**Compile: uncompiled (snort not installed) | Confidence: high**

<!-- Audit: Structural check passed. DNS rules use label-length-encoded domain names in content match on UDP port 53. TLS rules use ssl service with ssl_state:client_hello gating. SIDs 1000010-1000015 avoid Emerging Threats Pro reserved range. All rules include flow, classtype, reference, metadata, sid, rev. -->
<!-- revision: SIDs reassigned from 2100010-2100015 to 1000010-1000015 to avoid Emerging Threats Pro reserved range (2100000-2103999) -->

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - ChainDrop Worm DNS Query to npm-cache.com C2 Domain"; flow:to_server; content:"|09|npm-cache|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000010; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - ChainDrop Worm DNS Query to pypi-get.com C2 Domain"; flow:to_server; content:"|08|pypi-get|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000011; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - ChainDrop Worm DNS Query to js-mirror.com C2 Domain"; flow:to_server; content:"|09|js-mirror|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000012; rev:1;)

alert ssl $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS ClientHello to npm-cache.com C2"; flow:established, to_server; ssl_state:client_hello; content:"npm-cache", fast_pattern; content:".com", distance 0; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000013; rev:1;)

alert ssl $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS ClientHello to pypi-get.com C2"; flow:established, to_server; ssl_state:client_hello; content:"pypi-get", fast_pattern; content:".com", distance 0; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000014; rev:1;)

alert ssl $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS ClientHello to js-mirror.com C2"; flow:established, to_server; ssl_state:client_hello; content:"js-mirror", fast_pattern; content:".com", distance 0; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created 2026-08-05; sid:1000015; rev:1;)
```

### Suricata: DNS, TLS SNI, and HTTP C2 Detection

Seven rules using Suricata-native dns.query, tls.sni, and http.* sticky buffers for C2 detection.
**Compile: uncompiled (suricata not installed) | Confidence: high**

<!-- Audit: Structural check passed. dns.query (dot notation) with dns protocol. tls.sni with tls protocol. http.method/http.uri/http.host with http protocol. All use correct Suricata dot-notation sticky buffers (not Snort underscore). SIDs 1000020-1000026 avoid Emerging Threats Pro reserved range. -->
<!-- revision: SIDs reassigned from 2100020-2100026 to 1000020-1000026 to avoid Emerging Threats Pro reserved range (2100000-2103999) -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to npm-cache.com C2 Domain"; flow:to_server; dns.query; content:"npm-cache.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000020; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to pypi-get.com C2 Domain"; flow:to_server; dns.query; content:"pypi-get.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000021; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ChainDrop Worm DNS Query to js-mirror.com C2 Domain"; flow:to_server; dns.query; content:"js-mirror.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000022; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS SNI to npm-cache.com C2"; flow:established,to_server; tls.sni; content:"npm-cache.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000023; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS SNI to pypi-get.com C2"; flow:established,to_server; tls.sni; content:"pypi-get.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000024; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm TLS SNI to js-mirror.com C2"; flow:established,to_server; tls.sni; content:"js-mirror.com"; fast_pattern; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000025; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChainDrop Worm HTTP POST to /router C2 Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/router"; fast_pattern; http.host; content:"npm-cache.com"; classtype:trojan-activity; reference:url,microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/; metadata:author Actioner, created_at 2026-08-05; sid:1000026; rev:1;)
```

## Lessons Learned

1. **Lifecycle hooks remain the Achilles' heel of npm**: The `preinstall`/`postinstall` mechanism continues to provide trivial arbitrary code execution during package installation. The npm ecosystem needs a default-deny model for lifecycle scripts, similar to Deno's permission system.

2. **Token-based worm propagation is a new escalation**: Unlike previous supply chain attacks that relied on compromising individual maintainer accounts, ChainDrop's self-propagating design turns every compromised developer into an unwitting attack vector. This fundamentally changes the calculus -- a single initial compromise can cascade to hundreds of packages within hours.

3. **Developer tooling as a persistence vector**: The use of `.claude/settings.json` SessionStart hooks and `.vscode/tasks.json` folderOpen tasks represents an evolution in persistence techniques specifically targeting the developer workflow. Security teams should audit IDE and AI coding tool configuration files as part of supply chain incident response.

4. **Blockchain-based C2 resilience**: The Ethereum smart contract for dynamic domain resolution is a sophisticated anti-takedown mechanism that warrants attention. Traditional domain sinkholing is insufficient when the attacker can update C2 addresses via blockchain transactions.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) -- primary technical analysis of the ChainDrop worm and its propagation mechanism
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/massive-chaindrop-npm-supply-chain-attack-infects-hundreds-of-packages/) -- breaking news coverage and scope assessment
- [The Hacker News](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html) -- reporting on keyv-linked infection chain
- [SecurityWeek](https://www.securityweek.com/over-400-npm-packages-infected-in-chaindrop-supply-chain-attack/) -- coverage of 400+ package compromise scope
- [CyberScoop](https://cyberscoop.com/supply-chain-attack-malware-mini-shai-hulud-teampcp/) -- TeamPCP attribution context and Shai-Hulud naming
- [Hackread](https://hackread.com/shai-hulud-npm-worm-poisoning-1280-packages/) -- extended package count and worm behavior analysis

---
*Report generated by Actioner*
