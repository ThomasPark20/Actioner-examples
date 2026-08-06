# Technical Analysis Report: ChainDrop -- Self-Propagating npm Supply-Chain Worm (2026-08-06)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-06
Version: 1.1

## Executive Summary

On August 4, 2026, a self-propagating credential-stealing worm designated "ChainDrop" (Shai-Hulud family) ripped through the npm ecosystem, compromising 444+ packages across 2,200+ versions in under four hours. The attack originated from the compromised GitHub account of the maintainer of `keyv`, a key-value storage library with over 150 million weekly downloads. The worm injected obfuscated JavaScript payloads (`setup.mjs` dropper + `Math_Symbol.js` credential harvester) into package tarballs via npm preinstall hooks, stole npm publishing tokens, GitHub tokens, AWS/GCP/Azure credentials, Kubernetes secrets, and SSH keys, then used the stolen npm tokens to automatically republish poisoned versions of every package accessible to the compromised identity -- creating a cascading, worm-like chain reaction across twelve unrelated organizations.

The combined monthly download footprint of affected packages exceeds 2 billion. The worm uses an Ethereum smart contract as a dead-drop C2 resolver (EtherHiding), exfiltrates credentials via AES-256-GCM encrypted payloads to `npm-cache[.]com`, and maintains persistence through Claude Code SessionStart hooks, VS Code folderOpen tasks, and systemd/LaunchAgent token-monitoring services. Microsoft, Elastic, Wiz, StepSecurity, SafeDep, and Aikido have published analyses. Organizations running affected versions should treat their environments as compromised and rotate all accessible credentials.

## Background: npm Ecosystem and keyv

The npm (Node Package Manager) registry is the world's largest software registry, hosting over 2 million packages used by virtually every JavaScript and Node.js project. `keyv` is a widely-used key-value storage adapter with 153+ million weekly downloads, serving as a transitive dependency for ESLint, flat-cache, file-entry-cache, and thousands of other packages. The `cacheable` family of packages (cache-manager, cacheable-request, flat-cache) maintained by the same author collectively account for hundreds of millions of additional weekly downloads.

The Shai-Hulud malware family has been active since at least early 2026, with prior campaigns targeting PyPI (`lightning` package compromise in April 2026) and npm (earlier Mini Shai-Hulud waves against @AntV packages). Google previously attributed the TeamPCP group behind these campaigns to "one core operator located in South Africa during at least some of the attacks," though hard attribution links remain unconfirmed. ChainDrop represents a significant evolution -- the first confirmed self-propagating worm variant with autonomous cross-organization spreading capability.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-04 09:02:37 | Poisoned commit (`ee2681a`) pushed to `jaredwray/keyv` repository |
| 2026-08-04 09:04:30 | IDE/AI persistence hooks planted (`.claude/`, `.vscode/` directories) via commit `d8c850c` |
| 2026-08-04 ~09:04 | Test files deleted via commit `f97eabc` |
| 2026-08-04 09:35:00 | `keyv@6.0.0` published via GitHub Actions OIDC with valid SLSA provenance |
| 2026-08-04 09:38:13 | Second wave begins -- worm spreads to `@thiennq/docs-viewer@1.6.2` |
| 2026-08-04 09:38-10:46 | Eight organizations compromised at ~1 package/second propagation rate |
| 2026-08-04 10:39+ | npm begins unpublishing malicious versions |
| 2026-08-04 13:18 | Final malicious publish observed (Umacloud); 433 packages / 2,201 versions compromised |
| 2026-08-04 ~17:40 IST | Clean versions restored: `keyv@5.6.0`, `flat-cache@6.1.23`, `cache-manager@7.2.9` |

## Root Cause: GitHub Account Compromise of keyv Maintainer

The attack began with the compromise of the GitHub account belonging to the maintainer of the `keyv` and `cacheable` package families (jaredwray). The exact method of initial account compromise has not been publicly disclosed, but the attacker gained sufficient access to push commits directly to the main branch and trigger the GitHub Actions release workflow. The attacker pushed three commits in rapid succession: one injecting the malicious payload, one planting IDE/AI hook persistence files, and one deleting test files. The release was then published through the legitimate GitHub Actions OIDC workflow, causing `keyv@6.0.0` to carry valid SLSA provenance attestations -- provenance that proves build origin but not that the source was safe.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Dropper (setup.mjs)

The dropper is injected into the target package's `package.json` via a `preinstall` lifecycle script entry: `"preinstall": "node setup.mjs"`. This executes automatically during `npm install` before the package installation completes.

Two dropper variants were observed:
- **Tarball dropper** (SHA-256: `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`, 29,918 bytes) -- injected directly into published npm tarballs
- **Repository dropper** (SHA-256: `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`, 11,017 bytes) -- placed in `.claude/setup.mjs` and `.vscode/setup.mjs` for persistence via IDE hooks

The dropper performs platform detection (`ldd --version` to distinguish glibc vs musl/Alpine), downloads the Bun JavaScript runtime v1.3.13 from official GitHub releases (`github.com/oven-sh/bun/releases/download/bun-v1.3.13/`), stages it in `$TMPDIR/bun-dl-*/`, and then executes the Stage 2 payload. The dropper checks the `_NODE_RUNTIME_INIT` environment variable to avoid duplicate instances and the `LANG` variable to exit on Russian-language systems (`ru_RU`, `uk_UA`, `be_BY`).

### 2. Stage 2: Credential Harvester (Math_Symbol.js / math_init.js)

The second-stage payload is a 727,680-byte heavily obfuscated Bun-based JavaScript module (SHA-256: `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`). It uses control-flow flattening with a Base91-encoded string table of 1,283 entries and a custom charset decoder. Internal variable and function names reference Dune-themed strings: `fedaykin`, `tleilaxu`, `sardaukar`, `ornithopter`, `sandworm`, `navigator`, `sietch`, `lasgun`, `mentat`, `ghola`, `kanly`, `laza`.

**Environment Detection:** The payload determines whether it is running on a developer workstation or in a CI/CD environment (checking `GITHUB_REF`, `GITHUB_REPOSITORY`). On workstations, it detaches to continue after installation; on CI/CD systems, it remains in the active job.

**Credential Collection (140+ target paths, 19+ regex patterns):**
- **npm tokens:** `~/.npmrc`, `~/.yarnrc*`, `~/.pypirc`; validates tokens via `registry.npmjs.org/-/whoami`
- **GitHub tokens:** `gh auth token` CLI extraction; PATs prefixed `ghp_`, `gho_`, `ghs_`; GitHub Actions workflow tokens; Actions runner memory scraping via `sudo python3` reading `/proc/<Runner.Worker PID>/mem` for `"isSecret":true` JSON fragments
- **AWS:** `~/.aws/credentials`, IMDS (`169.254.169.254`), ECS metadata (`169.254.170.2`), STS `GetCallerIdentity`, Secrets Manager `ListSecrets`/`GetSecretValue`, SSM `GetParameters` across 16 regions
- **GCP:** `gcloud config config-helper`, service account JSON files
- **Azure:** `az account get-access-token`, `azd auth token`, `~/.azure/accessTokens.json`
- **Kubernetes:** `~/.kube/config`, service-account tokens, Vault endpoints (`127.0.0.1:8200`, `vault.*.svc.cluster.local:8200`)
- **HashiCorp Vault:** client tokens, KV secrets, auth via `/v1/auth/kubernetes/login` and `/v1/auth/aws/login`
- **SSH keys:** `~/.ssh/id_*`
- **Docker:** `~/.docker/config.json`
- **AI tooling:** `.claude/credentials.json`, `.codex/auth.json`, `.cursor/credentials.json`, `.openai/auth.json`, `.anthropic/auth.json`, `.gemini/.env`
- **CI/CD:** Jenkins `secrets/master.key`, `/proc/self/environ`
- **Other:** Database credentials, Stripe, Slack (cookies), Twilio, Terraform state, `/etc/passwd`, `/etc/shadow`

**Token Validation:** All npm tokens are validated in real-time against `registry.npmjs.org/-/whoami` before use.

### 3. C2 Infrastructure

**EtherHiding (Blockchain-based C2 Resolution):** The payload does not hardcode a C2 domain. Instead, it queries an Ethereum smart contract at address `0xE1f2395ee43e45A1556EC6438a88c31B83493103` using function selector `0x53ed5143` to retrieve the current exfiltration endpoint at runtime. It attempts 75 public Ethereum RPC endpoints sequentially (e.g., `eth.llamarpc.com`, `go.getblock.io`, `eth-mainnet.nodereal.io`).

**Observed Exfiltration Domains:**
- `npm-cache[.]com` (IP: `104.21.35[.]216`, Cloudflare) -- primary; POST to `hxxps://npm-cache[.]com:443/router`
- `awqhnjewqjkl[.]icu` -- secondary domain observed during detonation

**Fallback Candidate Domains:**
- `pypi-get[.]com`
- `js-mirror[.]com`

**GitHub Fallback Exfiltration:** 546 public GitHub repositories created on August 4, 2026 with description `"Shai-Hulud: Here We Go Again"` and a `results/` directory serve as fallback exfiltration destinations. Encrypted credential payloads are committed using author `claude <claude@users.noreply.github.com>` with message `"chore: update config"`. Discovery markers include the strings `thebeautifulmarchoftime` and `thebeautifulsnadsoftime`. Results are stored as `results-<timestamp>-<counter>.json`.

**Encryption:** Exfiltrated data is gzip-compressed, encrypted with a randomly generated AES-256-GCM key (PBKDF2 with 200,000 iterations, salt: `svksjrhjkcejg`), the AES key is RSA-OAEP-SHA256 wrapped with the attacker's RSA-4096 public key, and the result is base64-encoded. GitHub fallback uses double Base64 encoding.

### 4. Worm Propagation Mechanism

After harvesting credentials, the payload uses stolen npm tokens to propagate:

1. Enumerates all packages accessible to the compromised identity via `registry.npmjs.org/-/v1/search?text=maintainer:<user>&size=250` and `registry.npmjs.org/-/org/<org>/package`
2. Downloads each package's latest tarball
3. Copies the current malware bundle (setup.mjs + Math_Symbol.js) into the tarball
4. Adds/modifies the `preinstall` lifecycle script in `package.json`
5. Increments the patch version automatically
6. Republishes the modified package

**GitHub Actions OIDC Abuse:** The payload contains a targeted publishing path for GitHub Actions workflows configured as npm trusted publishers (OIDC token exchange via `registry.npmjs.org/-/npm/v1/oidc/token/exchange/*`). Packages published through this route carry valid provenance because the publication originates from a legitimate workflow identity.

**Propagation Speed:** The worm moved between organizations every 2-7 minutes, completing a cross-organization burst across twelve organizations in roughly 30 minutes (09:35-13:18 UTC).

### 5. Persistence Mechanisms

**IDE/AI Hook Persistence:**
- `.claude/settings.json` -- contains `SessionStart` hook calling `node .claude/setup.mjs`
- `.vscode/tasks.json` -- includes `"Environment Setup"` task with `"runOn": "folderOpen"` calling `node .claude/setup.mjs`
- These re-execute the payload without requiring an `npm install`

**Token Monitor Service:**
- Linux: systemd user service `gh-token-monitor.service` with lingering enabled
- macOS: LaunchAgent at `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
- Config stored at `~/.config/gh-token-monitor/{token,handler,started_at}`
- Helper script at `~/.local/bin/gh-token-monitor.sh`
- Polls `api.github.com/user` every 60 seconds
- Contains a destructive handler triggered on 40x HTTP response (token revocation)

### 6. Anti-Forensics / Evasion Techniques

- **Russian locale kill switch:** Exits on `LANG` values `ru_RU`, `uk_UA`, `be_BY`
- **Duplicate instance prevention:** Checks `_NODE_RUNTIME_INIT` environment variable
- **Background detachment:** On workstations, detaches from the installation process to avoid detection
- **No source code trail:** Malicious versions had no corresponding source-code commit, pull request, tag, or legitimate release in package repositories; tarballs were modified and published directly
- **Legitimate provenance:** Published through GitHub Actions OIDC with valid SLSA attestations, bypassing provenance-based verification
- **Object hardening:** Anti-tamper mechanisms in the obfuscated payload
- **AES-256-GCM encrypted configuration blobs:** Prevent static analysis of embedded configuration
- **Bun runtime:** Uses an alternative JavaScript runtime (Bun) instead of Node.js, evading Node.js-focused detection
- **Camouflaged state files:** `$TMPDIR/tmp.dpkg_<pid>.lock` mimics dpkg lock files

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| keyv | 6.0.0 | Primary worm origin; 153.7M weekly downloads |
| flat-cache | 6.1.24 | Compromised via worm propagation; 149.9M weekly downloads |
| file-entry-cache | 11.1.6 | Compromised via worm propagation; 147.6M weekly downloads |
| cacheable-request | 13.0.20 | Compromised via worm propagation; 33.9M weekly downloads |
| cache-manager | 7.2.10 | Compromised via worm propagation; 4.3M weekly downloads |
| @cacheable/utils | 2.5.1 | Compromised via worm propagation |
| @servicetitan/* | 141 packages | Organizational namespace compromised |
| @onereach/* | 78 packages | Organizational namespace compromised |
| @or-sdk/* | 74 packages | Organizational namespace compromised |
| @ornikar/* | 42 packages | Organizational namespace compromised |
| @qlik/* | 28 packages | Organizational namespace compromised |
| @deliveroo/* | Multiple packages | Organizational namespace compromised |
| @picsart/* | Multiple packages | Organizational namespace compromised |
| @adminide-stack/* | Multiple packages | Organizational namespace compromised |
| @arv-bedrock/* | Multiple packages | Organizational namespace compromised |

**Total: 444+ package names, 2,200+ poisoned versions across 12+ organizations**

### File System

| Platform | Path / Filename | Hash (SHA-256) | Description |
|----------|----------------|---------------|-------------|
| Cross-platform | setup.mjs (tarball) | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | Stage 1 dropper (npm tarball variant, 29,918 bytes) |
| Cross-platform | setup.mjs (repo) | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | Stage 1 dropper (IDE hook variant, 11,017 bytes) |
| Cross-platform | Math_Symbol.js / math_init.js | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Stage 2 credential harvester payload (727,680 bytes) |
| Cross-platform | .claude/setup.mjs | SHA-1: `686aa40d0fc22c8d569494543a0f891f359f2f99` | Claude Code persistence hook |
| Cross-platform | .vscode/setup.mjs | SHA-1: `f525d52ceb966516686b482d3dc0137028cc6a63` | VS Code persistence hook |
| Cross-platform | .claude/settings.json | -- | SessionStart hook configuration |
| Cross-platform | .vscode/tasks.json | -- | folderOpen task configuration |
| Linux | $TMPDIR/bun-dl-*/ | -- | Bun runtime staging directory |
| Linux | $TMPDIR/tmp.dpkg_\<pid\>.lock | -- | Camouflaged state file |
| Linux | ~/.local/bin/gh-token-monitor.sh | -- | Token monitor helper script |
| Linux | ~/.config/gh-token-monitor/ | -- | Token monitor config directory |
| Linux | gh-token-monitor.service (systemd user) | -- | Persistence service unit |
| macOS | ~/Library/LaunchAgents/com.user.gh-token-monitor.plist | -- | Persistence LaunchAgent |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npm-cache[.]com | Primary C2 / exfiltration endpoint |
| Domain | awqhnjewqjkl[.]icu | Secondary C2 domain |
| Domain | pypi-get[.]com | Fallback candidate domain |
| Domain | js-mirror[.]com | Fallback candidate domain |
| IP | 104.21.35[.]216 | npm-cache[.]com resolution (Cloudflare). Shared Cloudflare infrastructure; do not block by IP alone. |
| URL Pattern | hxxps://npm-cache[.]com:443/router | Exfiltration POST endpoint |
| Ethereum Contract | 0xE1f2395ee43e45A1556EC6438a88c31B83493103 | EtherHiding C2 resolver (selector 0x53ed5143) |
| Domain | eth.llamarpc.com | Legitimate Ethereum RPC endpoint abused for EtherHiding C2 resolution (not attacker infra) |
| Domain | go.getblock.io | Legitimate Ethereum RPC endpoint abused for EtherHiding C2 resolution (not attacker infra) |
| Domain | eth-mainnet.nodereal.io | Legitimate Ethereum RPC endpoint abused for EtherHiding C2 resolution (not attacker infra) |
| User-Agent | Bun/1.3.13 | Bun runtime HTTP user-agent |
| User-Agent | npm/11.13.1 node/v24.10.0 | npm client user-agent observed |

### Behavioral

- **Process chain:** `npm install` -> `sh -c node setup.mjs` -> `node setup.mjs` -> `ldd --version` (platform detection) -> `unzip` (Bun extraction) -> `bun Math_Symbol.js`
- **GitHub Actions memory scraping:** `sudo python3` reading `/proc/<Runner.Worker PID>/mem` for `"isSecret":true` JSON fragments
- **Token validation:** HTTP requests to `registry.npmjs.org/-/whoami` to verify stolen npm tokens before use
- **AWS enumeration:** STS `GetCallerIdentity`, Secrets Manager `ListSecrets`/`GetSecretValue`, SSM `GetParameters` across 16 regions
- **GitHub API abuse:** Commits with author `claude <claude@users.noreply.github.com>`, message `"chore: update config"`, repository description `"Shai-Hulud: Here We Go Again"`
- **Token monitor polling:** Persistent 60-second polling of `api.github.com/user` with destructive handler on 40x response
- **GitHub search markers:** API queries for `thebeautifulmarchoftime` and `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- **Git commit markers:** Commits to compromised repos with author `claude@users.noreply.github.com`, commit `ee2681a` (payload), `d8c850c` (hooks), `f97eabc` (test deletion) on keyv; `893f73f` on cacheable; `983ce1a` on ecto

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into legitimate npm packages via compromised maintainer account |
| T1059.007 | Command and Scripting Interpreter: JavaScript | setup.mjs dropper and Math_Symbol.js payload executed via Node.js/Bun |
| T1199 | Trusted Relationship | Abuse of npm trusted publisher OIDC workflow identity for propagation |
| T1552.001 | Unsecured Credentials: Credentials In Files | Systematic scanning of 140+ credential file paths (~/.npmrc, ~/.aws/credentials, etc.) |
| T1555 | Credentials from Password Stores | Extraction of tokens from GitHub CLI, cloud CLI tools, and Vault |
| T1546 | Event Triggered Execution | npm preinstall lifecycle hook for automatic execution; Claude Code SessionStart hooks and VS Code folderOpen tasks |
| T1543.002 | Create or Modify System Process: Systemd Service | gh-token-monitor.service for persistent credential monitoring |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST exfiltration to npm-cache[.]com:443/router |
| T1102 | Web Service | Ethereum smart contract dead-drop for C2 domain resolution; GitHub repos for fallback exfil |
| T1567 | Exfiltration Over Web Service | Credential exfiltration via GitHub repository commits and npm-cache[.]com |
| T1105 | Ingress Tool Transfer | Download of Bun v1.3.13 runtime from official GitHub releases |
| T1580 | Cloud Infrastructure Discovery | AWS STS GetCallerIdentity, region enumeration across 16 regions |
| T1526 | Cloud Service Discovery | Secrets Manager, SSM, Vault, Kubernetes service enumeration |
<!-- revision: T1570 dropped — worm propagation is supply-chain (T1195.002), not lateral tool transfer -->

## Impact Assessment

**Breadth:** 444+ distinct package names, 2,200+ poisoned versions, 12+ affected organizations (Deliveroo, Ornikar, OneReach, Picsart, Qlik, ServiceTitan, and others). Combined monthly download footprint exceeds 2 billion. The keyv, flat-cache, and file-entry-cache packages are transitive dependencies of ESLint, multiplying exposure across virtually all JavaScript/TypeScript development toolchains. Wiz reported affected packages present in 46% of monitored cloud environments.

**Depth:** Full credential compromise -- npm publishing tokens, GitHub PATs/OAuth tokens, AWS/GCP/Azure credentials, Kubernetes secrets, Vault tokens, SSH keys, database credentials, CI/CD runner secrets. The worm's destructive handler on token revocation represents a potential scorched-earth capability if defenders rotate credentials without first disabling the monitor.

**Stealth:** Valid SLSA provenance attestations, legitimate GitHub Actions workflow origins, and the use of blockchain-based C2 resolution made initial detection extremely difficult. The attack bypassed provenance verification, code signing, and standard supply chain integrity checks.

## Detection & Remediation

### Immediate Detection

Check if any affected package versions are present in your lockfiles:

```bash
# Check for keyv@6.0.0 specifically
grep -r '"keyv".*"6\.0\.0"' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check for known malicious file artifacts
find . -name "Math_Symbol.js" -o -name "math_init.js" -o -name "setup.mjs" 2>/dev/null

# Check for Claude Code / VS Code persistence hooks
find . -path "*/.claude/setup.mjs" -o -path "*/.vscode/setup.mjs" 2>/dev/null

# Check for token monitor persistence (Linux)
systemctl --user status gh-token-monitor.service 2>/dev/null
ls -la ~/.config/gh-token-monitor/ ~/.local/bin/gh-token-monitor.sh 2>/dev/null

# Check for token monitor persistence (macOS)
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null

# Check for C2 domain in DNS logs
grep -E "npm-cache\.com|awqhnjewqjkl\.icu" /var/log/dns* /var/log/syslog 2>/dev/null

# Check for Bun staging directories
ls -la /tmp/bun-dl-* 2>/dev/null
```

### Remediation

1. **CRITICAL -- Disable token monitor BEFORE rotating credentials:** The worm installs a credential-revocation watcher with a destructive handler. Remove `gh-token-monitor.service` (Linux) or `com.user.gh-token-monitor.plist` (macOS) and kill associated processes before any token rotation.

2. **Remove malicious files:** Delete `Math_Symbol.js`, `math_init.js`, `setup.mjs` from node_modules and repository directories. Remove `.claude/setup.mjs`, `.vscode/setup.mjs`, and verify `.claude/settings.json` and `.vscode/tasks.json` are clean.

3. **Pin to clean versions:** Update lockfiles to use verified clean versions: `keyv@5.6.0`, `flat-cache@6.1.23`, `cache-manager@7.2.9`. Compare lockfiles against published IOC lists from Wiz, StepSecurity, Aikido, Socket, and Ox Security.

4. **Rotate ALL accessible credentials:** npm tokens, GitHub PATs/OAuth tokens, AWS access keys, GCP service accounts, Azure credentials, Kubernetes service account tokens, Vault tokens, SSH keys, database passwords, and any other credentials accessible from the compromised environment.

5. **Audit for unauthorized activity:** Review GitHub audit logs for unauthorized commits, npm publish events, and repository changes. Check for repositories with description "Shai-Hulud: Here We Go Again".

6. **Treat affected systems as compromised:** Rebuild CI/CD runners and developer workstations from known-good images. Do not assume upgrading the package alone is sufficient.

### Long-Term Hardening

- Enable npm's lifecycle script blocking (npm 12+ blocks unapproved dependency lifecycle scripts by default)
- Use `--ignore-scripts` flag during CI/CD installs where lifecycle scripts are not required
- Implement lockfile integrity verification in CI/CD pipelines
- Monitor for unexpected npm publish events via npm audit logs
- Deploy network monitoring for Ethereum RPC endpoint queries from non-Web3 build environments
- Consider using npm provenance verification with additional source-code audit (provenance alone is insufficient, as this attack demonstrated)

## Detection Rules

These detections target ChainDrop's specific dropper filenames, C2 domains, Bun-based execution patterns, persistence mechanisms, and credential harvesting behavior at advisory-specific altitude. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; `sigma check` failed due to an environment proxy blocking MITRE ATT&CK data download, not a rule defect. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: ChainDrop npm Worm - Suspicious setup.mjs Preinstall Execution
Detects execution of `setup.mjs` via npm preinstall hook, the ChainDrop dropper's primary delivery mechanism.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: confidence high→medium, level high→medium — setup.mjs is a plausible developer convention, not unique to this malware. -->
<!-- audit: sigma check failed (403 fetching MITRE ATT&CK data from proxy — environment issue, not rule defect); splunk exit 0; log_scale exit 0. Fields: ParentCommandLine, CommandLine (process_creation/linux). FP: legitimate preinstall scripts named setup.mjs exist but are uncommon. -->
```yaml
title: ChainDrop npm Worm - Suspicious setup.mjs Preinstall Execution
id: 7c3e8a4b-1f2d-4e6a-9b8c-5d0e3f7a2c1b
status: experimental
description: >
    Detects execution of setup.mjs via npm preinstall lifecycle hook, consistent with
    the ChainDrop supply chain worm dropper that downloads and executes a Bun-based
    credential-stealing payload (Math_Symbol.js / math_init.js).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.stepsecurity.io/blog/chaindrop-npm-worm
    - https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
author: Actioner
date: 2026/08/06
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentCommandLine|contains: 'npm'
    selection_cmd:
        CommandLine|contains|all:
            - 'node'
            - 'setup.mjs'
    condition: selection_parent and selection_cmd
falsepositives:
    - Legitimate npm packages with preinstall scripts named setup.mjs
level: medium
```

### Sigma: ChainDrop npm Worm - Bun Runtime Executing Math Payload
Detects Bun executing Math_Symbol.js or math_init.js, the ChainDrop Stage 2 credential harvester.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/MITRE); splunk exit 0; log_scale exit 0. Bun executing Math_Symbol.js is highly distinctive — near-zero benign overlap. -->
```yaml
title: ChainDrop npm Worm - Bun Runtime Executing Math Payload
id: 2a9d6e3f-5b4c-4d8e-af1b-7c0e9f2a3d5b
status: experimental
description: >
    Detects the Bun JavaScript runtime executing Math_Symbol.js or math_init.js payloads,
    the second-stage credential harvester of the ChainDrop npm supply chain worm.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.stepsecurity.io/blog/chaindrop-npm-worm
author: Actioner
date: 2026/08/06
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_bun:
        Image|endswith:
            - '/bun'
    selection_payload:
        CommandLine|contains:
            - 'Math_Symbol.js'
            - 'math_init.js'
            - 'Math_init.js'
    condition: selection_bun and selection_payload
falsepositives:
    - Very unlikely in production environments
level: critical
```

### Sigma: ChainDrop npm Worm - DNS Query to Known C2 Domains
Detects DNS resolution of ChainDrop exfiltration domains `npm-cache[.]com`, `awqhnjewqjkl[.]icu`, `pypi-get[.]com`, and `js-mirror[.]com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/MITRE); splunk exit 0; log_scale exit 0. All four domains are attacker-controlled with no legitimate use. -->
```yaml
title: ChainDrop npm Worm - DNS Query to Known C2 Domains
id: 4b8f1c2d-6e3a-4f7b-9d5c-1a0e8f3b2c4d
status: experimental
description: >
    Detects DNS queries to known ChainDrop C2 and exfiltration domains including
    npm-cache[.]com and awqhnjewqjkl[.]icu used for credential exfiltration.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
    - https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack
author: Actioner
date: 2026/08/06
tags:
    - attack.t1071.001
    - attack.t1567
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'npm-cache.com'
            - 'awqhnjewqjkl.icu'
            - 'pypi-get.com'
            - 'js-mirror.com'
    condition: selection
falsepositives:
    - None expected
level: critical
```

<!-- revision: Ethereum RPC Endpoint Query rule DROPPED — altitude violation (public infrastructure, not attacker artifacts), massive FP surface (every Web3 app), trivial evasion (only 3 of 75 RPC endpoints listed). -->

### Sigma: ChainDrop npm Worm - Mass Credential File Access by Bun Process
Detects the Bun runtime accessing sensitive credential files targeted by ChainDrop's harvester.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/MITRE); splunk exit 0; log_scale exit 0. Bun reading .npmrc + .aws/credentials + .ssh/id_ is highly abnormal outside of explicit credential-management tooling. -->
```yaml
title: ChainDrop npm Worm - Mass Credential File Access by Bun Process
id: 6e0f3a4b-8c5d-4f9e-b07c-3d2e1a4f6e8c
status: experimental
description: >
    Detects the Bun runtime accessing sensitive credential files consistent with the
    ChainDrop worm's credential harvesting of npm tokens, GitHub tokens, AWS credentials,
    Kubernetes configs, SSH keys, and cloud provider configurations.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://www.stepsecurity.io/blog/chaindrop-npm-worm
author: Actioner
date: 2026/08/06
tags:
    - attack.t1552.001
    - attack.t1555
logsource:
    category: file_event
    product: linux
detection:
    selection_process:
        Image|endswith: '/bun'
    selection_files:
        TargetFilename|contains:
            - '/.npmrc'
            - '/.aws/credentials'
            - '/.kube/config'
            - '/.ssh/id_'
            - '/.docker/config.json'
            - '/.azure/accessTokens.json'
            - '/.claude/credentials.json'
            - '/proc/self/environ'
    condition: selection_process and selection_files
falsepositives:
    - Legitimate Bun applications reading configuration files
level: high
```

### Sigma: ChainDrop npm Worm - Token Monitor Persistence Mechanism
Detects creation of ChainDrop's gh-token-monitor persistence components (systemd service, LaunchAgent, config directory).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/MITRE); splunk exit 0; log_scale exit 0. gh-token-monitor is a unique artifact name with no legitimate use. -->
```yaml
title: ChainDrop npm Worm - Token Monitor Persistence Mechanism
id: 7f1a4b5c-9d6e-4a0f-b18c-4e3f2b5a7f9d
status: experimental
description: >
    Detects creation of the ChainDrop gh-token-monitor persistence components
    including the systemd user service, macOS LaunchAgent, or associated config
    directory used to watch for credential rotation and execute destructive handlers.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://safedep.io/keyv-npm-supply-chain-compromise/
author: Actioner
date: 2026/08/06
tags:
    - attack.t1543.002
    - attack.t1053
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'gh-token-monitor.service'
            - 'gh-token-monitor.sh'
            - 'com.user.gh-token-monitor'
            - '.config/gh-token-monitor/'
    condition: selection
falsepositives:
    - None expected
level: critical
```

### Sigma: ChainDrop npm Worm - Malicious IDE/AI Hook File Creation
Detects creation of `.claude/setup.mjs` or `.vscode/setup.mjs` persistence files used by ChainDrop for reinfection without npm install. Scope to source trees, not general-purpose workstation file monitoring.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (proxy/MITRE); splunk exit 0; log_scale exit 0. setup.mjs in .claude/ or .vscode/ is the specific persistence pattern documented by Microsoft, THN, and StepSecurity. Legitimate .claude/setup.mjs files are theoretically possible but rare. -->
```yaml
title: ChainDrop npm Worm - Malicious IDE/AI Hook File Creation
id: 8a2b5c6d-0e7f-4b1a-c29d-5f4a3c6b8e0f
status: experimental
description: >
    Detects creation of malicious Claude Code or VS Code hook files used by ChainDrop
    for persistence and reinfection. The worm plants setup.mjs in .claude/ and .vscode/
    directories with SessionStart hooks and folderOpen tasks to re-execute without npm install.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
    - https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html
author: Actioner
date: 2026/08/06
tags:
    - attack.t1546
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '.claude/setup.mjs'
            - '.vscode/setup.mjs'
            - '.claude/math_init.js'
    condition: selection
falsepositives:
    - Legitimate Claude Code or VS Code workspace setup scripts named setup.mjs
level: high
```

### Suricata: ChainDrop npm Worm C2 Exfiltration
Detects HTTP POST to `npm-cache[.]com/router` and DNS queries to ChainDrop C2 domains.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: suricata not installed; structural check: dot-notation sticky buffers, semicolons, msg/sid/rev present, flow set. Three rules: HTTP POST exfil (sid 2200001), DNS npm-cache.com (sid 2200002), DNS awqhnjewqjkl.icu (sid 2200003). -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - ChainDrop npm Worm C2 Exfiltration to npm-cache.com";
    flow:established,to_server;
    http.host;
    content:"npm-cache.com"; fast_pattern;
    http.uri;
    content:"/router";
    http.method;
    content:"POST";
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/;
    metadata:author Actioner, created_at 2026-08-06;
    sid:2200001;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - ChainDrop npm Worm DNS Query to C2 Domain npm-cache.com";
    flow:to_server;
    dns.query;
    content:"npm-cache.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/;
    metadata:author Actioner, created_at 2026-08-06;
    sid:2200002;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - ChainDrop npm Worm DNS Query to C2 Domain awqhnjewqjkl.icu";
    flow:to_server;
    dns.query;
    content:"awqhnjewqjkl.icu"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain;
    metadata:author Actioner, created_at 2026-08-06;
    sid:2200003;
    rev:1;
)
```

### Snort: N/A
Snort rules are not generated separately as the Suricata rules above cover the same network indicators. Snort is not installed for compile validation, and the C2 domain detections are better served by Suricata's `dns.query` and `http.host` sticky buffers.

### YARA: ChainDrop npm Worm Payload and Dropper
Detects the ChainDrop Stage 2 credential harvester via Dune-themed obfuscation strings and Ethereum contract references, and the Stage 1 dropper via Bun download patterns. Sample-tested against a constructed positive containing published signature strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test: file containing 4 Dune strings + npmjs whoami + Ethereum contract → fires Malware_ChainDrop_NPM_Worm_Payload. Negative test: benign Express.js module → no match. Dune-themed strings (fedaykin, tleilaxu, sardaukar, ornithopter) combined with credential-harvesting patterns are highly distinctive to this malware family. Hash 9fc2570b… is the published payload hash from Microsoft/StepSecurity/Elastic. -->
```yara
rule Malware_ChainDrop_NPM_Worm_Payload
{
    meta:
        description = "Detects ChainDrop npm supply chain worm payload (Math_Symbol.js / math_init.js) via characteristic Dune-themed obfuscation strings and credential harvesting patterns"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/"
        hash = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        severity = "critical"

    strings:
        $dune1 = "fedaykin" ascii
        $dune2 = "tleilaxu" ascii
        $dune3 = "sardaukar" ascii
        $dune4 = "ornithopter" ascii
        $dune5 = "sandworm" ascii
        $dune6 = "navigator" ascii
        $dune7 = "sietch" ascii
        $dune8 = "lasgun" ascii

        $cred1 = "registry.npmjs.org/-/whoami" ascii
        $cred2 = "gh auth token" ascii
        $cred3 = "gcloud config config-helper" ascii
        $cred4 = "az account get-access-token" ascii

        $c2_1 = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii
        $c2_2 = "0x53ed5143" ascii
        $c2_3 = "npm-cache.com" ascii

        $shai = "Shai-Hulud" ascii nocase
        $marker = "thebeautifulmarchoftime" ascii

    condition:
        filesize < 1MB and
        (
            (3 of ($dune*) and 1 of ($cred*)) or
            (2 of ($c2_*) and 1 of ($dune*)) or
            ($shai and 2 of ($dune*)) or
            ($marker and 1 of ($cred*))
        )
}

rule Malware_ChainDrop_NPM_Worm_Dropper
{
    meta:
        description = "Detects ChainDrop npm worm dropper (setup.mjs) that downloads Bun runtime and stages the credential harvester"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://www.stepsecurity.io/blog/chaindrop-npm-worm"
        hash = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        severity = "high"

    strings:
        $bun_dl = "bun-dl-" ascii
        $bun_ver = "bun-v1.3.13" ascii
        $bun_linux = "bun-linux-x64-baseline" ascii
        $bun_darwin = "bun-darwin-aarch64" ascii

        $math1 = "Math_Symbol.js" ascii
        $math2 = "math_init.js" ascii

        $dpkg = "tmp.dpkg_" ascii
        $runtime = "_NODE_RUNTIME_INIT" ascii

    condition:
        filesize < 50KB and
        (
            ($bun_ver and 1 of ($math*)) or
            (1 of ($bun_*) and $dpkg) or
            ($runtime and 1 of ($math*))
        )
}
```

## Lessons Learned

1. **Provenance attestation is necessary but insufficient.** SLSA provenance and Sigstore signatures proved that `keyv@6.0.0` was built by the legitimate GitHub Actions workflow -- but the source code it built had been poisoned. Provenance verifies build origin, not source safety. Organizations must pair provenance with source-code review, lockfile diffing, and behavioral monitoring.

2. **npm lifecycle scripts remain a critical attack surface.** The `preinstall` hook provides automatic code execution during `npm install` with no user interaction. npm 12+ mitigates this by blocking unapproved dependency lifecycle scripts by default, but earlier npm versions and alternative package managers remain exposed. Organizations should adopt `--ignore-scripts` in CI/CD environments where lifecycle scripts are not required.

3. **Blockchain-based C2 (EtherHiding) creates resilient, censorship-resistant infrastructure.** By storing the exfiltration domain in an Ethereum smart contract, the attacker can rotate C2 endpoints without modifying any malware code, and defenders cannot easily take down the resolution mechanism. Detection must target the Ethereum RPC queries themselves, not just the final C2 domain.

4. **AI/IDE tooling creates new persistence vectors.** The use of Claude Code `SessionStart` hooks and VS Code `folderOpen` tasks for persistence represents a novel attack surface that most security tooling does not monitor. Organizations should audit `.claude/` and `.vscode/` directories in repositories for unexpected configuration changes.

5. **Token revocation must be preceded by persistence removal.** ChainDrop's token-monitoring service with a destructive handler means that naive credential rotation could trigger data destruction. Incident response must follow the sequence: remove persistence -> rotate credentials, not the reverse.

## Sources

- [Microsoft Security Blog - ChainDrop Analysis](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) -- primary technical analysis with IOCs, MITRE ATT&CK mapping, and Microsoft Defender detection signatures
- [BleepingComputer - Massive ChainDrop npm Supply-Chain Attack](https://www.bleepingcomputer.com/news/security/massive-chaindrop-npm-supply-chain-attack-infects-hundreds-of-packages/) -- impact assessment, affected organization list, remediation guidance
- [The Hacker News - Keyv-Linked npm Worm](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html) -- SafeDep analysis, propagation mechanics, Claude Code/VS Code hook details
- [CyberScoop - Mini Shai-Hulud / TeamPCP](https://cyberscoop.com/supply-chain-attack-malware-mini-shai-hulud-teampcp/) -- threat actor attribution context, historical campaign evolution
- [StepSecurity - ChainDrop npm Worm Technical Analysis](https://www.stepsecurity.io/blog/chaindrop-npm-worm) -- comprehensive IOC list, file hashes, Ethereum contract details, credential target paths, process execution chains
- [Elastic Security Labs - Shai-Hulud CHAINDROP](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain) -- C2 domain observations, detection queries, Dune-themed obfuscation strings
- [Wiz Blog - keyv and cacheable Supply Chain Attack](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) -- IP addresses, SLSA provenance analysis, PBKDF2 encryption details, token monitor persistence
- [SafeDep - keyv npm Supply Chain Compromise](https://safedep.io/keyv-npm-supply-chain-compromise/) -- propagation timing analysis, package version enumeration, credential target inventory

---
*Report generated by Actioner*
