# Technical Analysis Report: IronWorm npm Supply Chain Attack (2026-06-05)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-05
Version: 1.0 (DRAFT)

## Executive Summary

A sophisticated supply chain attack dubbed "IronWorm" has compromised 36 npm packages in the Arweave/WeaveDB ecosystem, delivering a Rust-compiled ELF infostealer through hijacked `preinstall` hooks. The malware, discovered by JFrog Security Research, targets 86 environment variables and 20+ credential files spanning AWS, Kubernetes, Docker, AI/ML API keys (Anthropic, OpenAI, Gemini, Cohere, Mistral), SSH keys, and Exodus cryptocurrency wallets. The attack originated from the compromised `asteroiddao` npm account and self-propagates by abusing stolen npm Trusted Publishing tokens to publish trojanized versions of additional packages, creating a worm-like infection chain across developer and CI/CD environments.

IronWorm is distinguished by its eBPF kernel rootkit for process and connection hiding, Tor-based C2 communications, per-call-site string encryption, and a secondary attack vector that hijacks GitHub Actions workflows to exfiltrate secrets without external C2. The affected packages had approximately 32,177 monthly downloads and 148,724 total lifetime downloads. An operator OPSEC failure left a hardcoded BIP-39 seed phrase in the binary, providing an attribution vector to the `ocrybit` account (member of the asteroid-dao GitHub organization).

## Background: Arweave/WeaveDB npm Ecosystem

WeaveDB is a decentralized database protocol built on Arweave, a permanent storage blockchain. The affected npm packages (`weavedb-sdk`, `weavedb-tools`, `weavedb-client`, etc.) form the core SDK and tooling for this Web3 ecosystem. The packages are primarily used by Web3/crypto developers, making them high-value targets: exposed secrets in this community can yield immediate financial gain through cryptocurrency wallet theft. The `asteroiddao` account, which published the malicious versions, was a legitimate maintainer of these packages prior to compromise.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Unknown (pre-2026-06-01) | Compromise of `asteroiddao` npm account and associated GitHub organizations |
| 2026-06-01 (approx.) | Malicious package versions published in rapid succession across 36 packages |
| 2026-06-01 (approx.) | Git commits backdated to appear historical; author identities spoofed as "claude" and "dependabot" |
| 2026-06-03 | JFrog Security Research detects suspicious republication pattern |
| 2026-06-03 | OX Security publishes advisory noting 32,177 monthly downloads impacted |
| 2026-06-04 | BleepingComputer and DarkReading publish coverage; packages being removed from npm |
| 2026-06-05 | JFrog publishes detailed technical analysis identifying eBPF rootkit, Tor C2, and self-propagation mechanism |

## Root Cause: Compromised npm Maintainer Account

The attack originated from the compromised `asteroiddao` npm account. The attacker gained control of this legitimate maintainer account (method of initial compromise not yet disclosed) and used it to publish trojanized versions of all 36 packages the account had publishing rights to. The attacker backdated Git commits to appear historical and spoofed commit authors as `claude` (using `claude[at]users[.]noreply[.]github[.]com`) and automation bots (`dependabot`, `renovate`, `github-actions`) to reduce suspicion.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Preinstall Hook

The attack vector is the npm `preinstall` lifecycle hook. Each malicious package version contains a Rust-compiled Linux ELF binary placed under `tools/setup` or `.github/scripts/precheck` within the package tarball. The `package.json` preinstall script executes this binary automatically during `npm install` before dependency resolution, requiring no user interaction:

```json
"preinstall": "./tools/setup"
```

The binary is a 976 KB Rust release build with a lightly modified UPX packing stub (overwritten magic value to evade UPX signature detection). All strings in the binary are encrypted with per-call-site unique keys, preventing static string extraction without deobfuscation.

### 2. Credential Harvesting (Infostealer)

The IronWorm payload harvests two categories of secrets:

**86 Environment Variables** covering:
- Cloud providers (AWS, GCP, Azure)
- Object storage services
- Database credentials
- Source control tokens (GitHub, GitLab)
- Package registry credentials (npm, PyPI)
- CI/CD system tokens
- Messaging platform tokens (Slack, Discord)
- Vault and Kubernetes configurations
- 14 AI/ML API keys (Anthropic, OpenAI, Gemini, Cohere, Mistral, Groq, Perplexity, xAI)

**20+ Credential Files** including:
- `~/.aws/credentials`
- `~/.kube/config`
- `~/.docker/config.json`
- `~/.claude/.credentials.json`
- `~/.codex/auth.json`
- `~/Cursor/auth.json`
- `~/.gemini/settings.json`
- SSH keys

### 3. C2 Infrastructure

**Primary C2:** Tor-based communication using a custom `torrc` configuration. The malware communicates via plain HTTP over a Tor tunnel to the `/api/agent` endpoint.

**Supported C2 Commands:**
- Extract and upload harvested credentials
- Download and execute arbitrary files
- Interactive remote shell

**Fallback Exfiltration:** When Tor is unavailable, the malware uploads stolen data to the public file-sharing service `temp[.]sh` through the Tor network.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

The IronWorm ELF binary is Linux-only. It deploys an eBPF kernel rootkit compiled with clang 22.1.5 that provides:

- **Process hiding:** Filters `/proc` listings to hide malicious processes from `ps`, `top`, and `ls`
- **Connection hiding:** Filters `/proc/net/tcp` and netlink interfaces to hide C2 TCP connections
- **Anti-debugging:** Intercepts `ptrace` syscalls, returning `SIGKILL` to prevent debugging
- **Auto-hiding:** Maintains a watchlist of processes to automatically conceal
- Contains 10 BPF maps with recoverable type information and 214 source lines extractable from `.BTF.ext` debug sections

**Limitation:** Kernel lockdown restrictions prevent memory rewriting, degrading stealth on hardened systems with Secure Boot / kernel lockdown enabled.

#### Exodus Desktop Wallet Attack (Cross-Platform JavaScript Injection)

The malware specifically targets the Exodus desktop cryptocurrency wallet by:
1. Disabling Electron security settings: `webSecurity`, `sandbox`, `contextIsolation`, `nodeIntegration`
2. Injecting JavaScript hooks to capture wallet password and BIP-39 recovery phrase
3. Exfiltrating captured secrets via a local listener on port 8738

### 5. Self-Propagation Mechanism

IronWorm self-propagates through two vectors:

**npm Trusted Publishing Abuse:** In CI environments, the malware exploits npm's OIDC identity tokens to obtain package-scoped automation tokens without stored credentials, then publishes trojanized versions of packages owned by the victim.

**GitHub Actions Workflow Hijacking:** Replaces existing GitHub Actions workflows using bot identities (`dependabot`, `renovate`, `github-actions`) to exfiltrate secrets via `${{ toJSON(secrets) }}` expressions, embedding them in workflow artifacts without external C2.

**Build System Injection:** Modifies build configurations across multiple ecosystems (npm preinstall, PyPI setup.py, Cargo build scripts, Conan, vcpkg) to execute embedded binaries, extending the infection chain beyond npm.

### 6. Anti-Forensics / Evasion Techniques

- **Commit backdating:** Copies the repository's most recent legitimate commit timestamp onto malicious commits
- **Author spoofing:** Uses author names `claude`, `dependabot`, `renovate`, `github-actions` to mimic AI tools and automation bots
- **UPX magic overwrite:** Modified UPX stub prevents standard UPX detection and unpacking
- **Per-call-site string encryption:** Each string decryption uses a unique key, preventing batch decryption
- **eBPF rootkit:** Hides processes and network connections from standard Linux monitoring tools
- **Commit messages crafted for plausibility:** Uses messages like "fix: resolve lint warnings", "test: add missing edge case", "ci: update workflow configuration"

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| weavedb-sdk | 0.45.3 | Primary example; contains Rust ELF in tools/setup |
| weavedb-lite | 0.1.1 | Trojanized with preinstall hook |
| weavedb-sdk-base | 0.21.1 | Trojanized with preinstall hook |
| test-weavedb-sdk | 1.1.1 | Trojanized with preinstall hook |
| weavedb-warp-contracts-plugin-deploy | 1.0.11 | Trojanized with preinstall hook |
| arnext-arkb | 0.0.2 | Trojanized with preinstall hook |
| weavedb-console | 0.2.1 | Trojanized with preinstall hook |
| arnext | 0.1.5 | Trojanized with preinstall hook |
| roidjs | 0.1.7 | Trojanized with preinstall hook |
| weavedb-exm-sdk | 0.7.4 | Trojanized with preinstall hook |
| create-arnext-app | 0.0.10 | Trojanized with preinstall hook |
| weavedb-tools | 0.45.3 | Trojanized with preinstall hook |
| wdb-core | 0.1.2 | Trojanized with preinstall hook |
| cwao-tools | 0.3.1 | Trojanized with preinstall hook |
| test-ajs | 0.1.19 | Trojanized with preinstall hook |
| monade | 0.0.7 | Trojanized with preinstall hook |
| weavedb-exm-sdk-web | 0.7.4 | Trojanized with preinstall hook |
| testnpmnmp | 1.0.21 | Trojanized with preinstall hook |
| warp-contracts-plugin-deploy-test | 3.0.1 | Trojanized with preinstall hook |
| wdb-cli | 0.1.1 | Trojanized with preinstall hook |
| ai3 | 0.3.5 | Trojanized with preinstall hook |
| cwao-units | 0.8.3 | Trojanized with preinstall hook |
| atomic-notes | 0.5.3 | Trojanized with preinstall hook |
| cwao | 0.5.6 | Trojanized with preinstall hook |
| weavedb-client | 0.45.3 | Trojanized with preinstall hook |
| wdb-sdk | 0.1.2 | Trojanized with preinstall hook |
| weavedb-offchain | 0.45.4 | Trojanized with preinstall hook |
| fpjson-lang | 0.1.7 | Trojanized with preinstall hook |
| weavedb-contracts | 0.45.2 | Trojanized with preinstall hook |
| weavedb-node-client | 0.45.3 | Trojanized with preinstall hook |
| arjson | 0.1.4 | Trojanized with preinstall hook |
| hbsig | 0.3.2 | Trojanized with preinstall hook |
| zkjson | 0.8.5 | Trojanized with preinstall hook |
| aonote | 0.11.1 | Trojanized with preinstall hook |
| weavedb-base | 0.45.3 | Trojanized with preinstall hook |
| weavedb-sdk-node | 0.45.3 | Trojanized with preinstall hook |
| wao | 0.41.2 | Trojanized with preinstall hook |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `<pkg>/tools/setup` | Not disclosed | 976 KB Rust ELF binary, UPX packed (modified magic) |
| Linux | `<pkg>/.github/scripts/precheck` | Not disclosed | Alternative binary placement path |
| Linux | `~/.aws/credentials` | N/A (target) | AWS credential file targeted for exfiltration |
| Linux | `~/.kube/config` | N/A (target) | Kubernetes config targeted for exfiltration |
| Linux | `~/.docker/config.json` | N/A (target) | Docker config targeted for exfiltration |
| Linux | `~/.claude/.credentials.json` | N/A (target) | Claude AI credentials targeted |
| Linux | `~/.codex/auth.json` | N/A (target) | Codex AI credentials targeted |
| Linux | `~/Cursor/auth.json` | N/A (target) | Cursor AI credentials targeted |
| Linux | `~/.gemini/settings.json` | N/A (target) | Gemini AI credentials targeted |

### Network

| Type | Value | Context |
|------|-------|---------|
| Service | Tor hidden service (address not disclosed) | Primary C2 via `/api/agent` endpoint |
| Service | `temp[.]sh` | Fallback exfiltration via public file-sharing |
| Port | 8738 (localhost) | Exodus wallet credential capture listener |
| Email | `claude[at]users[.]noreply[.]github[.]com` | Spoofed commit author email |

### Behavioral

- Rapid republication of multiple npm packages within a tight timeframe from a single account
- `preinstall` hook executing a native ELF binary from `tools/setup` or `.github/scripts/precheck`
- Bulk environment variable harvesting (86 variables) targeting cloud, CI/CD, and AI/ML credentials
- eBPF program loading for process/connection hiding (requires root or `CAP_BPF`/`CAP_SYS_ADMIN`)
- GitHub Actions workflow files modified by processes originating from node_modules
- Git commits with backdated timestamps matching the repository's most recent legitimate commit
- `${{ toJSON(secrets) }}` expressions appearing in workflow files (secret dumping)
- Localhost listener on port 8738 (Exodus wallet hook)

### Attribution Artifacts

| Type | Value | Context |
|------|-------|---------|
| BIP-39 Seed | `bench crane defense corn wheel trial news abuse finish better paddle slush` | Hardcoded operator skip-list (OPSEC failure) |
| Ethereum Address | `0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6` | Derived from operator seed phrase |
| npm Account | `asteroiddao` | Compromised publishing account |
| GitHub User | `ocrybit` | Actual commit author revealed in GitHub Actions logs |
| GitHub Orgs | `asteroid-dao`, `ocrybit`, `alisista`, `warashibe`, `kakedashi-hacker`, `weavedb`, `ArweaveOasis`, `arthursimao`, `mlebjerg` | 9 compromised GitHub organizations |
| Sonatype ID | N/A | Not applicable (JFrog discovery, not Sonatype) |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized npm packages via compromised maintainer account |
| T1204.002 | User Execution: Malicious File | npm preinstall hook executes Rust ELF binary without user interaction |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Binary execution via shell from preinstall hook |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting of 20+ credential files from developer workstations |
| T1552.007 | Unsecured Credentials: Container API | Docker and Kubernetes config harvesting |
| T1083 | File and Directory Discovery | Scanning for credential files across known paths |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 over Tor to /api/agent endpoint |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Tor network for C2 communications |
| T1014 | Rootkit | eBPF kernel rootkit hiding processes and connections |
| T1562.003 | Impair Defenses: Impair Command History Logging | eBPF filtering of /proc to hide from monitoring tools |
| T1027.002 | Obfuscated Files or Information: Software Packing | Modified UPX packing with overwritten magic bytes |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Per-call-site string encryption with unique keys |
| T1560.001 | Archive Collected Data: Archive via Utility | Secrets exfiltrated via workflow artifacts and temp.sh |
| T1098 | Account Manipulation | Self-propagation via stolen npm Trusted Publishing tokens |
| T1199 | Trusted Relationship | Abuse of npm Trusted Publishing OIDC workflow |

## Impact Assessment

- **Breadth:** 36 npm packages compromised, approximately 32,177 monthly downloads and 148,724 total lifetime downloads. Primarily affects the Arweave/WeaveDB Web3 ecosystem but self-propagation mechanism could extend to any package maintainer who installed an affected version.
- **Depth:** Full credential exfiltration (cloud, CI/CD, AI API keys, cryptocurrency wallets, SSH keys), persistent rootkit access, and automatic downstream propagation. The Exodus wallet attack component enables direct financial theft.
- **Stealth:** High. eBPF rootkit hides from standard monitoring, commit timestamps are backdated, author identities are spoofed as legitimate automation, and string encryption prevents static analysis. However, the operator's hardcoded BIP-39 seed phrase is a critical OPSEC failure enabling attribution.
- **Self-Propagation Risk:** The worm-like behavior through npm Trusted Publishing and GitHub Actions workflow hijacking means the true blast radius may exceed the initial 36 packages. Any CI/CD environment that installed an affected package and had npm publishing credentials is a potential vector for further spread.

## Detection & Remediation

### Immediate Detection

Check if any of the 36 affected packages at the specific malicious versions are in your dependency tree:

```bash
# Check package-lock.json for affected packages
for pkg in weavedb-sdk weavedb-lite weavedb-sdk-base weavedb-tools weavedb-client weavedb-offchain weavedb-contracts weavedb-node-client weavedb-base weavedb-sdk-node weavedb-console weavedb-exm-sdk weavedb-exm-sdk-web wao cwao cwao-tools cwao-units arnext arnext-arkb create-arnext-app roidjs wdb-core wdb-sdk wdb-cli ai3 atomic-notes fpjson-lang arjson hbsig zkjson aonote monade testnpmnmp test-ajs test-weavedb-sdk warp-contracts-plugin-deploy-test weavedb-warp-contracts-plugin-deploy; do
  grep -r "\"$pkg\"" package-lock.json node_modules/*/package.json 2>/dev/null && echo "FOUND: $pkg"
done

# Check for the malicious binary paths
find node_modules -name "setup" -path "*/tools/*" -type f 2>/dev/null
find node_modules -name "precheck" -path "*/.github/scripts/*" -type f 2>/dev/null

# Check for eBPF programs (requires root)
bpftool prog list 2>/dev/null | grep -i "unknown\|suspicious"

# Check for local listener on port 8738 (Exodus wallet hook)
ss -tlnp | grep 8738
```

### Remediation

1. **Immediate:** Remove all affected package versions and reinstall from known-good versions. Run `npm audit` and check for advisory references.
2. **Credential Rotation (CRITICAL):** Rotate ALL credentials that may have been exposed:
   - AWS access keys and session tokens
   - Kubernetes service account tokens
   - Docker registry credentials
   - All AI/ML API keys (Anthropic, OpenAI, Gemini, Cohere, Mistral, Groq, Perplexity, xAI)
   - npm publish tokens and GitHub PATs
   - SSH keys
   - Any secrets stored in CI/CD environment variables
3. **Exodus Wallet:** If the Exodus desktop wallet was running on an affected system, assume the wallet password and recovery phrase are compromised. Transfer funds to a new wallet immediately.
4. **CI/CD Audit:** Review GitHub Actions workflow history for unauthorized modifications. Check for commits authored by `claude[at]users[.]noreply[.]github[.]com` or containing `toJSON(secrets)`.
5. **npm 2FA:** Enable two-factor authentication on all npm accounts and review publish access for all packages.

### Long-Term Hardening

- Enforce `--ignore-scripts` for npm installs in CI/CD pipelines, selectively allowing preinstall hooks only for audited packages
- Pin dependencies by exact version and hash (`npm ci` with integrity checks)
- Use Software Composition Analysis (SCA) tools that detect native binaries in npm packages
- Deploy eBPF-aware security monitoring (Falco, Tracee) on developer workstations and CI runners
- Implement npm package provenance verification (`--expect-provenance`)
- Monitor for rapid bulk republication of packages from a single account

## Detection Rules

These detections target the IronWorm npm supply chain attack at PoC/advisory-specific altitude. The Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale. The YARA rule keys on the published BIP-39 seed phrase and has been sample-tested. Note: compiles does not equal fires -- verify in your pipeline with real telemetry.

### Sigma: IronWorm npm Preinstall Hook Binary Execution

Detects execution of suspicious binaries at `tools/setup` or `scripts/precheck` spawned by a Node.js/npm parent process, the primary IronWorm delivery mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. No matching product pipeline for linux/process_creation — portability proven without pipeline only (field names unmapped). -->
```yaml
title: IronWorm npm Preinstall Hook Executing Suspicious Binary
id: 7c3e1a8d-f2b4-4e9a-b6d1-8a5c3f7e2d90
status: experimental
description: >
    Detects execution of the IronWorm malware binary via npm preinstall hook.
    The attack deploys a Rust ELF binary at tools/setup or .github/scripts/precheck
    within npm packages, executed automatically during npm install.
references:
    - https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    - https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/
author: Actioner
date: 2026/06/05
tags:
    - attack.t1204.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/npm'
    selection_binary:
        Image|endswith:
            - '/tools/setup'
            - '/scripts/precheck'
        CommandLine|contains:
            - 'tools/setup'
            - '.github/scripts/precheck'
    condition: selection_parent and selection_binary
falsepositives:
    - Legitimate npm packages with native setup binaries
level: high
```

### Sigma: IronWorm Credential File Access from node_modules

Detects file access to AWS, Kubernetes, Docker, and AI tool credential paths by a process originating from a `node_modules` directory.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Medium confidence because file_event coverage on Linux requires auditd or Sysmon-for-Linux — not universal. -->
```yaml
title: IronWorm Credential File Access via Suspicious Process
id: 9b4f2c6e-a1d3-4e8b-c7f5-2d9a6b3e1f80
status: experimental
description: >
    Detects access to credential files targeted by the IronWorm infostealer,
    including AWS credentials, Kubernetes configs, Docker configs, and AI tool
    credential files, by a process spawned from a node_modules directory.
references:
    - https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    - https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/
author: Actioner
date: 2026/06/05
tags:
    - attack.t1552.001
    - attack.t1083
logsource:
    category: file_event
    product: linux
detection:
    selection_process:
        Image|contains: 'node_modules'
    selection_files:
        TargetFilename|endswith:
            - '/.aws/credentials'
            - '/.kube/config'
            - '/.docker/config.json'
            - '/.claude/.credentials.json'
            - '/.codex/auth.json'
            - '/.gemini/settings.json'
    condition: selection_process and selection_files
falsepositives:
    - Legitimate developer tools accessing these files from within node_modules
level: high
```

### Sigma: IronWorm GitHub Actions Workflow Modification

Detects modification of GitHub Actions workflow YAML files by a process originating from `node_modules` or the `tools/setup` binary, indicating IronWorm's workflow hijacking technique.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Medium confidence: workflow modifications could come from legitimate CI tooling. Scope to systems where node_modules processes should not modify .github/workflows/. -->
```yaml
title: IronWorm GitHub Actions Secret Exfiltration Pattern
id: 3d8a5f1c-b6e2-4c7d-9a0f-1e4b7c3d6a82
status: experimental
description: >
    Detects GitHub Actions workflow modifications that dump all secrets via
    toJSON(secrets) expression, a technique used by IronWorm to exfiltrate CI/CD
    secrets without external C2 by embedding them in workflow artifacts.
references:
    - https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    - https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/
author: Actioner
date: 2026/06/05
tags:
    - attack.t1588.004
    - attack.t1560.001
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: '.github/workflows/'
        TargetFilename|endswith: '.yml'
    selection_process:
        Image|contains:
            - 'node_modules'
            - 'tools/setup'
    condition: selection_path and selection_process
falsepositives:
    - CI/CD automation tools modifying workflow files legitimately
level: critical
```

### Snort: IronWorm C2 and Exfiltration Traffic

Detects HTTP POST requests to the `/api/agent` C2 endpoint and exfiltration to `temp.sh` file-sharing service used as IronWorm's fallback exfil channel.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c minimal -T exit 0. Medium confidence: /api/agent is a generic URI pattern; combine with other indicators for higher fidelity. temp.sh rule is more specific. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - IronWorm C2 Beacon via Tor to /api/agent Endpoint"; flow:established,to_server; content:"/api/agent"; fast_pattern; content:"POST"; content:"Host|3A|"; sid:2100101; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - IronWorm Exfiltration via temp.sh File Sharing Service"; flow:established,to_server; content:"temp.sh"; fast_pattern; content:"POST"; sid:2100102; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin;)
```

### Suricata: IronWorm C2 and Exfiltration Traffic

Detects HTTP POST to `/api/agent` and exfiltration to `temp[.]sh` using Suricata's HTTP-aware dot-notation sticky buffers for higher fidelity matching.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S exit 0. Medium confidence: /api/agent is generic; temp.sh host match is more distinctive. Both use proper http.method/http.uri/http.host buffers. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - IronWorm C2 POST to /api/agent Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/agent"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin; metadata:author Actioner, created_at 2026-06-05; sid:2200101; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - IronWorm Exfil to temp.sh File Sharing"; flow:established,to_server; http.method; content:"POST"; http.host; content:"temp.sh"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin; metadata:author Actioner, created_at 2026-06-05; sid:2200102; rev:1;)
```

### YARA: IronWorm Rust ELF Infostealer Binary

Detects the IronWorm ELF binary via the hardcoded BIP-39 seed phrase (operator OPSEC failure), Ethereum address, and distinctive combination of C2 endpoint with targeted credential file paths.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive: ELF header + published BIP-39 seed phrase matched. Negative: ELF header + benign content, no match. Seed phrase is uniquely distinctive (12-word combination from the published JFrog report). -->
```yara
rule Malware_IronWorm_npm_Infostealer
{
    meta:
        description = "Detects the IronWorm Rust-compiled ELF infostealer distributed via malicious npm packages. Keys on the hardcoded BIP-39 seed phrase, C2 endpoint, and credential file paths unique to this implant."
        author = "Actioner"
        date = "2026-06-05"
        reference = "https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/"
        severity = "critical"

    strings:
        // Hardcoded BIP-39 seed phrase (operator OPSEC failure)
        $seed = "bench crane defense corn wheel trial news abuse finish better paddle slush" ascii

        // Operator Ethereum address
        $eth_addr = "0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6" ascii nocase

        // C2 endpoint path
        $c2_endpoint = "/api/agent" ascii

        // Targeted credential files
        $cred1 = ".aws/credentials" ascii
        $cred2 = ".kube/config" ascii
        $cred3 = ".claude/.credentials.json" ascii
        $cred4 = ".codex/auth.json" ascii
        $cred5 = ".docker/config.json" ascii
        $cred6 = ".gemini/settings.json" ascii

        // Exodus wallet attack indicators
        $exodus1 = "webSecurity" ascii
        $exodus2 = "contextIsolation" ascii
        $exodus3 = "nodeIntegration" ascii

        // Commit spoofing strings
        $spoof1 = "claude@users.noreply.github.com" ascii
        $spoof2 = "dependabot" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 2MB and
        (
            $seed or
            $eth_addr or
            ($c2_endpoint and 3 of ($cred*)) or
            (4 of ($cred*) and 2 of ($exodus*)) or
            ($c2_endpoint and 1 of ($spoof*))
        )
}
```

## Relationship to Other Campaigns

**Lazarus npm Brandjacking (Hackread/Sonatype, June 2026):** A separate, concurrent campaign discovered by Sonatype involving brandjacked npm packages mimicking Buffer, Chai, React, Express, JWT, and Webpack. That campaign uses `eval()` with base64-decoded URLs from `www[.]jsonkeeper[.]com` and a Node.js backdoor connecting to `45[.]59[.]163[.]198:1244`, with payloads dropped as `f.js` and hidden `.vscode` directories. This is **distinct from IronWorm** -- different malware family (JavaScript vs. Rust), different C2 infrastructure (direct IP vs. Tor), different technique (brandjacking/typosquatting vs. compromised maintainer), and different researcher (Sonatype vs. JFrog).

**Prior npm Worm Campaigns (Shai-Hulud family):** JFrog describes IronWorm as "Shai-Hulud's rustier cousin," connecting it to the lineage of npm supply chain worms (mini-shai-hulud, SHA1-Hulud, SANDWORM_MODE). IronWorm represents an evolution with Rust compilation, eBPF rootkit capabilities, and broader credential targeting (especially AI/ML API keys).

## Lessons Learned

1. **npm preinstall hooks remain a critical attack surface.** The ecosystem still allows arbitrary binary execution at install time without sandboxing. The `--ignore-scripts` flag remains the only defense, but breaks many legitimate packages. Progress toward npm package provenance and install-time sandboxing is urgently needed.

2. **AI tool credentials are now primary targets.** IronWorm's targeting of 14 AI/ML API keys (Anthropic, OpenAI, Gemini, Cohere, Mistral, Groq, Perplexity, xAI) and AI coding tool credential files (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/Cursor/auth.json`) reflects the increasing value of these credentials. Organizations must treat AI API keys with the same rigor as cloud infrastructure credentials.

3. **Self-propagating supply chain attacks amplify blast radius.** IronWorm's abuse of npm Trusted Publishing to auto-publish trojanized packages from compromised CI environments creates exponential growth potential. A single compromised developer workstation can cascade into hundreds of downstream infections.

4. **eBPF as a rootkit platform is maturing.** The use of eBPF for process and connection hiding in a supply chain attack payload represents a significant escalation in sophistication. Defenders need eBPF-aware monitoring tools (Falco, Tracee, Tetragon) deployed on developer machines, not just production servers.

## Sources

- [JFrog Security Research - IronWorm: Shai-Hulud's rustier cousin](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/) -- primary technical analysis with full IOC list, eBPF rootkit teardown, and self-propagation mechanism
- [BleepingComputer - New IronWorm malware hits 36 packages in npm supply-chain attack](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/) -- initial news coverage with overview
- [OX Security - IronWorm Supply Chain Malware Hits npm](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/) -- download statistics (32,177 monthly / 148,724 lifetime) and ecosystem impact
- [DarkReading - Rust-Written IronWorm Hits NPM Supply Chain](https://www.darkreading.com/cyberattacks-data-breaches/rust-written-ironworm-npm-supply-chain) -- industry coverage
- [Hackread - Lazarus Group npm Brandjacking](https://hackread.com/lazarus-group-npm-brandjacking-target-developers/) -- separate concurrent campaign (Sonatype discovery), confirmed distinct from IronWorm

---
*Report generated by Actioner*
