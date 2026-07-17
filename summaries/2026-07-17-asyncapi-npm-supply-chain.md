# Technical Analysis Report: AsyncAPI npm Supply Chain Compromise — Miasma Modular Runtime with C2 (2026-07-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-17
Version: 1.0 (DRAFT)

## Executive Summary

On July 14, 2026, five compromised @asyncapi npm packages (collectively exceeding 2 million weekly downloads) were discovered delivering the Miasma modular runtime (M-RED-TEAM v6.4) with active command-and-control infrastructure. The attack exploited a misconfigured GitHub Actions `pull_request_target` workflow to obtain publishing credentials, then injected obfuscated loaders into each package's entry point that execute at module import time -- bypassing npm's `--ignore-scripts` mitigation entirely. The loaders fetch an encrypted ~8.2 MB second-stage payload (`sync.js`) from IPFS, which decrypts through three cryptographic layers into the Miasma runtime -- a 91,973-line, 744-module framework with six C2 channels (HTTP, Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS), RAT capabilities, platform-specific persistence, and credential harvesting targeting 100+ environment variables and credential files. The C2 server operates at `85.137.53[.]71` on ports 8080/8081/8091. While the malware contains the "Miasma" string and uses the same framework codebase, Microsoft and OX Security assess this is NOT attributed to the TeamPCP/Shai-Hulud campaigns documented in the June 2026 Miasma worm incident -- the branding overlap may represent deliberate misdirection or independent reuse of the now-open-sourced toolkit. OX Security disclosed the compromise; Microsoft published the primary technical analysis on July 15, 2026. The affected packages have been removed from npm.

## Background: AsyncAPI and npm Ecosystem

AsyncAPI is an open-source initiative providing specifications and tooling for event-driven APIs, widely used in enterprise microservice architectures. The `@asyncapi/specs` package alone serves as the canonical schema definition consumed by the entire AsyncAPI toolchain. The compromised packages -- `@asyncapi/specs`, `@asyncapi/generator`, `@asyncapi/generator-components`, and `@asyncapi/generator-helpers` -- form the core of the AsyncAPI code generation pipeline, making them high-value supply chain targets. This attack is distinct from the June 2026 Miasma worm (covered in [2026-06-10-miasma-worm-github-supply-chain.md](/home/user/Actioner-examples/summaries/2026-06-10-miasma-worm-github-supply-chain.md)): the June incident used stolen PATs to inject IDE config files into Microsoft GitHub repositories, while this July incident exploits GitHub Actions workflow misconfigurations to poison npm packages at the registry level with import-time execution.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| April 2026 | Vulnerability identified in AsyncAPI GitHub Actions workflow; PoC submitted |
| 2026-07-14 05:08:58 | Malicious commit `47be388` created exploiting `pull_request_target` workflow |
| 2026-07-14 05:11:05 | Docs Preview workflow triggered |
| 2026-07-14 06:58:42 | Commit `3eab3ec` created to trigger release workflow |
| 2026-07-14 07:05:42 | Push-triggered workflow starts |
| 2026-07-14 ~07:10 | Three packages republished: @asyncapi/generator@3.3.1, @asyncapi/generator-components@0.7.1, @asyncapi/generator-helpers@1.1.1 |
| 2026-07-14 07:56-08:04 | Malicious workflows trigger on alpha branch |
| 2026-07-14 08:06:20 | @asyncapi/specs@6.11.2-alpha.1 published |
| 2026-07-14 08:14 | Malicious commit pushed to master branch |
| 2026-07-14 08:28 | Child commit pushed |
| 2026-07-14 08:30:09 | @asyncapi/specs@6.11.2 (stable) published |
| 2026-07-14 08:49:22 | First observed downstream fetch of stable tarball into Yarn cache |
| 2026-07-15 | Microsoft publishes technical analysis; OX Security disclosure |

## Root Cause: GitHub Actions `pull_request_target` Workflow Misconfiguration

The attacker exploited a misconfigured `pull_request_target` workflow (PR #2155) in the AsyncAPI repository. The `pull_request_target` trigger runs in the context of the base branch with access to repository secrets, but the misconfigured workflow checked out the untrusted PR head commit in this privileged context -- a classic "pwn request" attack. This exposed the `asyncapi-bot` PAT, which had npm publishing permissions. The attacker used a placeholder git identity (`npm-oidc-no-reply[at]github[.]com`) and the stolen PAT to publish malicious versions of four packages through the repository's trusted publishing pipeline. No npm maintainer account was directly compromised; the attack pivoted entirely through the CI/CD misconfiguration.

## Technical Analysis of the Malicious Payload

### 1. Import-Time Loader (Stage 1) -- No Install Hooks

The attack's signature innovation is import-time execution: the malicious code was injected directly into each package's exported entry point (e.g., `index.js`, `lib/templates/config/validator.js`, `lib/utils/ErrorHandling.js`, `src/utils.js`), not into npm lifecycle hooks (`preinstall`/`install`/`postinstall`). This means:

- The payload executes when any application calls `require('@asyncapi/generator')` or `import` -- during normal runtime, not during installation
- `npm install --ignore-scripts` provides **zero protection**
- Hook-focused security scanners (Socket, Snyk, npm audit) that gate on lifecycle scripts do not flag this pattern

The injected code deobfuscates a transport routine at runtime and spawns a detached, hidden child process:

```javascript
spawn('node', [payloadPath], {
   detached: true,
   stdio: 'ignore',
   windowsHide: true,
}).unref();
```

The command-line pattern for the spawned process contains the distinctive obfuscation variable `const _0x5af5e1`.

### 2. IPFS Payload Fetch (Stage 1b)

The loader uses hardcoded IPFS Content Identifiers (CIDs) to fetch the encrypted second-stage payload (`sync.js`) from public IPFS gateways:

- **Specs package CID:** `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`
- **Generator family CID:** `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`
- **Gateway URL pattern:** `hxxps://ipfs[.]io/ipfs/[CID]`
- **Blocked public gateways:** ipfs.io, dweb.link, cloudflare-ipfs.com

OS-aware drop logic writes `sync.js` to platform-specific masquerade directories:

| Platform | Drop Path |
|----------|-----------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` |
| Linux | `~/.local/share/NodeJS/sync.js` |
| macOS | `~/Library/Application Support/NodeJS/sync.js` |
| Fallback | `~/.config/NodeJS/sync.js` |

An additional payload source was configured at `rentry[.]co/elzotebo999` for JavaScript retrieval and `eval()` execution.

### 3. Triple-Layer Decryption (Stage 2)

The `sync.js` payload (~8.2 MB encrypted bundle) applies three cryptographic layers:

1. **HKDF-SHA256 key derivation** using master key `rt-vault-master-key-32b-aaaaaaaa` with info string `rt-file-key`
2. **AES-256-GCM decryption** with first 12 bytes as IV and last 16 bytes as authentication tag
3. **ROT-94 character rotation** applied post-decryption

The decrypted payload is executed via `eval()`.

### 4. Miasma Runtime (Stage 3) -- M-RED-TEAM v6.4

The decrypted payload is the Miasma modular runtime, identified as version M-RED-TEAM v6.4 with:

- **Campaign identifier:** `miasma-train-p1`
- **Organization identifier:** `miasma-test-org`
- **Code size:** 91,973 lines across 744 modules

**Active modules in this build:**
- Persistence installation (active)
- C2 communication (active)
- Credential harvesting (implemented but **disabled**)
- Encrypted exfiltration (disabled)
- Supply-chain propagation (disabled)
- Metamorphic generation (disabled)
- AI-tool poisoning (disabled)
- Sandbox evasion (disabled)

The presence of disabled modules suggests this was either a staging/test deployment or the attacker intentionally limited the blast radius.

### 5. C2 Infrastructure

**Primary C2 server:** `85.137.53[.]71`

| Port | Function |
|------|----------|
| 8080 | C2 beacon / command channel |
| 8081 | File upload service |
| 8091 | Management interface |

**HTTP API endpoints:**
- `/api/v1/beacon` -- heartbeat/tasking
- `/api/v1/file-result` -- exfiltration upload
- `/api/v1/file-content/<cid>` -- file retrieval by content ID

**RAT capabilities:** directory listing, file retrieval/upload, remote shell execution, proxying, data exfiltration.

**Six decentralized fallback C2 channels:**
1. HTTP (primary, `85.137.53[.]71`)
2. Nostr relay
3. Ethereum smart contract (address: `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` -- operational use undetermined)
4. BitTorrent DHT (bootstrap nodes: `router[.]bittorrent[.]com`, `router[.]utorrent[.]com`, `dht[.]transmissionbt[.]com`)
5. libp2p GossipSub P2P
6. IPFS

**mDNS service advertisement:** `_miasma._tcp`

### 6. Platform-Specific Persistence

| Platform | Mechanism | Artifact |
|----------|-----------|----------|
| Windows | HKCU Run registry key | Value name: `miasma-monitor` |
| Linux | systemd user unit | `miasma-monitor.service` |
| macOS | Shell RC injection | Appends to `~/.zshrc`, `~/.bashrc`, `~/.bash_profile` |

**Runtime lock file:** `~/.config/.miasma/run/node.lock`

### 7. Credential Harvesting (Disabled but Present)

The runtime includes credential harvesting code targeting 100+ environment variables and disk files:

**Environment variables:** `GITHUB_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCLOUD_SERVICE_KEY`, `DOCKER_TOKEN`, `K8S_AUTH_TOKEN`, `DOPPLER_TOKEN`, `VAULT_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and many more.

**Disk targets:** `~/.npmrc`, `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.vault-token`, `~/.netrc`, `~/.docker/config.json`, `google_credentials.json`.

**Self-propagation capability (disabled):** searches for authentication tokens for npm, PyPI, and Cargo to compromise victim-maintained packages.

### 8. Anti-Forensics / Evasion Techniques

- **No lifecycle hooks:** avoids hook-focused scanners entirely
- **Import-time execution:** triggers during normal application runtime, not installation
- **IPFS delivery:** content-addressed storage resists takedown
- **Detached process:** `detached: true`, `stdio: 'ignore'`, `windowsHide: true` with `.unref()` -- parent process exits cleanly
- **VM detection:** terminates in virtual machine environments
- **EDR detection:** terminates if endpoint detection tools are present
- **Russian locale check:** terminates on Russian locale systems
- **Triple-layer encryption:** AES-256-GCM + HKDF + ROT-94 obfuscation
- **Decentralized fallback:** six independent C2 channels ensure resilience

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `@asyncapi/specs` | 6.11.2-alpha.1 | Injected loader in `index.js` |
| `@asyncapi/specs` | 6.11.2 | Injected loader in `index.js` |
| `@asyncapi/generator` | 3.3.1 | Injected loader in `lib/templates/config/validator.js` |
| `@asyncapi/generator-components` | 0.7.1 | Injected loader in `lib/utils/ErrorHandling.js` |
| `@asyncapi/generator-helpers` | 1.1.1 | Injected loader in `src/utils.js` |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | `@asyncapi/specs` tarball (6.11.2-alpha.1) | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` | Compromised package tarball |
| Any | `@asyncapi/specs` tarball (6.11.2) | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` | Compromised package tarball |
| Any | `@asyncapi/generator` tarball (3.3.1) | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` | Compromised package tarball |
| Any | `@asyncapi/generator-components` tarball (0.7.1) | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | Compromised package tarball |
| Any | `@asyncapi/generator-helpers` tarball (1.1.1) | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` | Compromised package tarball |
| Any | `validator.js` (generator) | `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | Injected loader code |
| Any | `ErrorHandling.js` (generator-components) | `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | Injected loader code |
| Any | `index.js` (specs) | `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | Injected loader code |
| Any | `utils.js` (generator-helpers) | `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71` | Injected loader code |
| Any | `sync.js` wrapper | `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | Second-stage encrypted payload wrapper |
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` | — | Dropped encrypted payload |
| Linux | `~/.local/share/NodeJS/sync.js` | — | Dropped encrypted payload |
| macOS | `~/Library/Application Support/NodeJS/sync.js` | — | Dropped encrypted payload |
| Fallback | `~/.config/NodeJS/sync.js` | — | Dropped encrypted payload |
| Any | `~/.config/.miasma/run/node.lock` | — | Runtime lock file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `85.137.53[.]71:8080` | Primary C2 beacon/command channel |
| IP | `85.137.53[.]71:8081` | C2 file upload service |
| IP | `85.137.53[.]71:8091` | C2 management interface |
| IPFS CID | `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | Stage 2 payload (specs variant) |
| IPFS CID | `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | Stage 2 payload (generator family variant) |
| URL Pattern | `hxxps://ipfs[.]io/ipfs/[CID]` | IPFS gateway payload delivery |
| URL Pattern | `hxxps://rentry[.]co/elzotebo999` | Alternate JavaScript payload source |
| Domain | `router[.]bittorrent[.]com` | BitTorrent DHT bootstrap node (fallback C2) |
| Domain | `router[.]utorrent[.]com` | BitTorrent DHT bootstrap node (fallback C2) |
| Domain | `dht[.]transmissionbt[.]com` | BitTorrent DHT bootstrap node (fallback C2) |
| Ethereum | `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | Smart contract (fallback C2, operational use undetermined) |
| Email | `npm-oidc-no-reply[at]github[.]com` | Publisher identity used in malicious publishes |

### Behavioral

- **Import-time execution:** malicious code runs during `require()`/`import`, not during `npm install`
- **Detached process spawning:** `spawn('node', [...], { detached: true, stdio: 'ignore', windowsHide: true }).unref()`
- **Command-line pattern:** `node -e "const _0x5af5e1...`
- **mDNS service advertisement:** `_miasma._tcp`
- **HTTP beacon pattern:** POST to `/api/v1/beacon` at `85.137.53[.]71:8080`
- **Sandbox/VM evasion:** terminates on VM detection, EDR presence, or Russian locale
- **IPFS gateway rotation:** attempts ipfs.io, dweb.link, cloudflare-ipfs.com

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into @asyncapi npm packages via compromised CI/CD pipeline |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript payload executed via Node.js; import-time execution |
| T1027 | Obfuscated Files or Information | Triple-layer encryption (AES-256-GCM, HKDF-SHA256, ROT-94); obfuscated variable names |
| T1105 | Ingress Tool Transfer | Second-stage payload fetched from IPFS gateways |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Payload dropped to `NodeJS/sync.js` mimicking legitimate Node.js paths |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via HKCU Run key `miasma-monitor` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via `miasma-monitor.service` systemd user unit |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | macOS persistence via shell RC file injection |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 beacon to `/api/v1/beacon` on port 8080 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encrypted C2 communications |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests 100+ env vars and credential files (disabled in build) |
| T1497 | Virtualization/Sandbox Evasion | Terminates in VMs, EDR presence, Russian locale |

## Impact Assessment

**Breadth**: Four @asyncapi packages with combined 2+ million weekly downloads were compromised, with the stable `@asyncapi/specs@6.11.2` fetched into downstream caches within 19 minutes of publication. Any application importing these packages during the exposure window executed the malicious loader.

**Depth**: The Miasma runtime includes full RAT capabilities with six redundant C2 channels, though credential harvesting and propagation modules were disabled in this build. The runtime's 744-module architecture represents significant development investment, and the disabled modules could be enabled remotely via the active C2 channel.

**Stealth**: Import-time execution bypasses all install-hook-based security controls. IPFS-based payload delivery resists centralized takedown. The detached, hidden process spawning leaves minimal parent-process evidence.

**Blast radius limitation**: The disabled state of credential harvesting, exfiltration, and propagation modules suggests this may have been a test run, a staging deployment, or deliberate restraint -- but the active C2 channel means full capabilities could be activated remotely at any time.

## Detection & Remediation

### Immediate Detection

**Check npm/yarn caches for compromised tarballs:**
```bash
find ~/.npm ~/.cache/yarn -name "*.tgz" -exec sha256sum {} \; 2>/dev/null | grep -E '(d425e458|9b2e65db|bfaeb987|082d733d|34014776)'
```

**Scan for Miasma runtime artifacts:**
```bash
# Check for sync.js in masquerade directories
find ~ -path "*/NodeJS/sync.js" 2>/dev/null
ls -la ~/.local/share/NodeJS/sync.js 2>/dev/null
ls -la ~/Library/Application\ Support/NodeJS/sync.js 2>/dev/null

# Check for Miasma lock file
ls -la ~/.config/.miasma/run/node.lock 2>/dev/null
```

**Check for persistence artifacts:**
```bash
# Linux systemd
systemctl --user list-units | grep miasma 2>/dev/null
find ~/.config/systemd/user/ ~/.local/share/systemd/user/ -name "*miasma*" 2>/dev/null

# macOS shell RC
grep -l "miasma\|NodeJS/sync" ~/.zshrc ~/.bashrc ~/.bash_profile 2>/dev/null
```

**Windows registry check:**
```
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v miasma-monitor 2>nul
```

**Network indicators:**
```bash
# Check for active connections to C2
ss -tnp | grep '85.137.53.71' 2>/dev/null
netstat -tnp | grep '85.137.53.71' 2>/dev/null
```

### Remediation

1. **Pin to safe versions immediately:** `@asyncapi/specs` <= 6.11.1, `@asyncapi/generator` <= 3.3.0, `@asyncapi/generator-components` <= 0.7.0, `@asyncapi/generator-helpers` <= 1.1.0
2. **Purge npm and yarn caches:** `npm cache clean --force` and `yarn cache clean`
3. **Block C2 infrastructure:** Block outbound to `85.137.53[.]71` on all ports (8080/8081/8091)
4. **Block IPFS gateways** at the network perimeter if not operationally required
5. **Remove persistence artifacts:** Delete `miasma-monitor` registry key, systemd unit, and shell RC injections
6. **Rotate all credentials:** Especially npm tokens, GitHub tokens, AWS/Azure/GCP keys, SSH keys, and any credentials in targeted environment variables or files
7. **Audit CI/CD workflows:** Review all `pull_request_target` trigger configurations for checkout of untrusted code
8. **Update npm CLI** to v11.10.0+ or enable `min-release-age` feature

### Long-Term Hardening

1. **Eliminate `pull_request_target` with untrusted checkout** -- use `pull_request` trigger or ensure `pull_request_target` never checks out PR head
2. **Enable npm provenance verification** and review publisher identities in lockfiles
3. **Monitor for import-time execution patterns** -- `--ignore-scripts` is insufficient; static analysis of package entry points is needed
4. **Implement subresource integrity (SRI) checks** for all resolved packages
5. **Deploy network monitoring** for IPFS gateway and BitTorrent DHT traffic from CI/CD environments

## Detection Rules

These detections target the AsyncAPI Miasma compromise's concrete artifacts: sync.js payload drops, obfuscated Node.js execution, Miasma lock file creation, platform-specific persistence, C2 beacon communication, IPFS payload delivery, and Miasma runtime strings. All rules are PoC/advisory-specific (default altitude, strict leniency); compiles does not equal fires -- verify in your pipeline. This is a separate incident from the June 2026 Miasma worm GitHub supply chain attack; see [prior coverage](2026-06-10-miasma-worm-github-supply-chain.md) for those detections.

### Sigma: AsyncAPI Miasma Sync.js Payload Drop to NodeJS Masquerade Directory
Detects `sync.js` written to OS-specific `NodeJS` masquerade directories used by the AsyncAPI compromise loader for second-stage payload staging.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: NodeJS masquerade directory + sync.js filename is highly distinctive; legitimate software does not use these exact paths. Covers Windows, Linux, macOS, and fallback paths. -->
```yaml
title: AsyncAPI Miasma Sync.js Payload Drop to NodeJS Masquerade Directory
id: c4a7e3f1-8b29-4d56-9e0a-3f1c2d5b6e7a
status: experimental
description: >
    Detects the Miasma runtime second-stage payload (sync.js) being written to
    OS-specific NodeJS masquerade directories used by the AsyncAPI npm supply
    chain compromise. The loader fetches an encrypted ~8.2 MB bundle from IPFS
    and writes it to %LOCALAPPDATA%\NodeJS\sync.js (Windows),
    ~/.local/share/NodeJS/sync.js (Linux), ~/Library/Application Support/NodeJS/sync.js
    (macOS), or ~/.config/NodeJS/sync.js (fallback).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1105
    - attack.t1036.005
logsource:
    category: file_event
detection:
    selection_linux:
        TargetFilename|endswith:
            - '/.local/share/NodeJS/sync.js'
            - '/.config/NodeJS/sync.js'
    selection_macos:
        TargetFilename|contains: '/Library/Application Support/NodeJS/sync.js'
    selection_windows:
        TargetFilename|endswith: '\NodeJS\sync.js'
        TargetFilename|contains: '\AppData\Local\'
    condition: 1 of selection_*
falsepositives:
    - Legitimate software using a NodeJS directory name in these specific paths (highly unlikely)
level: high
```

### Sigma: AsyncAPI Miasma Obfuscated Node.js Execution Pattern
Detects Node.js execution with the distinctive obfuscation variable `_0x5af5e1` in the command line, characteristic of the AsyncAPI compromise detached loader process.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: _0x5af5e1 is a specific obfuscation variable name from the published loader code; extremely unlikely to appear in legitimate Node.js usage. Requires both node binary and the specific variable pattern. -->
```yaml
title: AsyncAPI Miasma Obfuscated Node.js Execution Pattern
id: b5d8f2e0-7a18-4c45-8d9b-2e0f1c4a5b6d
status: experimental
description: >
    Detects the specific obfuscation variable pattern used by the AsyncAPI npm
    supply chain compromise loader. The injected code spawns a detached Node.js
    child process with the command-line pattern 'node -e "const _0x5af5e1'
    which is characteristic of the Miasma import-time payload execution.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1059.007
    - attack.t1027
logsource:
    category: process_creation
detection:
    selection_obfusc:
        CommandLine|contains: 'const _0x5af5e1'
    selection_node:
        Image|endswith:
            - '/node'
            - '\node.exe'
    condition: selection_obfusc and selection_node
falsepositives:
    - Extremely unlikely - this is a specific obfuscation variable name
level: critical
```

### Sigma: AsyncAPI Miasma Runtime Lock File Creation
Detects creation of the Miasma runtime lock file at `~/.config/.miasma/run/node.lock`, a unique artifact of the M-RED-TEAM v6.4 runtime.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: .miasma directory is unique to the Miasma runtime framework; no legitimate software uses this path. -->
```yaml
title: AsyncAPI Miasma Runtime Lock File Creation
id: a6c9d3e1-5f07-4b34-8c2a-1d0e9f8a7b6c
status: experimental
description: >
    Detects creation of the Miasma runtime lock file at ~/.config/.miasma/run/node.lock.
    The Miasma modular runtime (M-RED-TEAM v6.4) creates this lock file to prevent
    concurrent execution during the AsyncAPI npm supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1027
    - attack.t1059.007
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: '/.config/.miasma/run/node.lock'
    condition: selection
falsepositives:
    - None known - this path is unique to the Miasma runtime
level: critical
```

### Sigma: AsyncAPI Miasma Windows Persistence via Registry Run Key
Detects the `miasma-monitor` value created under HKCU Run for Windows persistence by the Miasma runtime.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: miasma-monitor is a unique identifier not used by any legitimate software. -->
```yaml
title: AsyncAPI Miasma Windows Persistence via Registry Run Key
id: d7e0f4a2-6b19-4c56-9d3e-2f1a0b8c7d5e
status: experimental
description: >
    Detects the Miasma runtime installing Windows persistence via an HKCU Run
    registry value named miasma-monitor. This persistence mechanism is part of
    the AsyncAPI npm supply chain compromise Miasma M-RED-TEAM v6.4 runtime.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\miasma-monitor'
    condition: selection
falsepositives:
    - None known - miasma-monitor is a unique malware identifier
level: critical
```

### Sigma: AsyncAPI Miasma Linux Persistence via Systemd User Unit
Detects creation of the `miasma-monitor.service` systemd user unit file for Linux persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: miasma-monitor.service is a unique malware artifact. -->
```yaml
title: AsyncAPI Miasma Linux Persistence via Systemd User Unit
id: e8f1a5b3-7c20-4d67-ae4f-3a2b1c9d8e6f
status: experimental
description: >
    Detects creation of the miasma-monitor.service systemd user unit file used
    by the Miasma runtime for Linux persistence during the AsyncAPI npm supply
    chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '/miasma-monitor.service'
        TargetFilename|contains:
            - '/.config/systemd/user/'
            - '/.local/share/systemd/user/'
    condition: selection
falsepositives:
    - None known - miasma-monitor is a unique malware identifier
level: critical
```

### Sigma: AsyncAPI Miasma C2 Beacon to Known Infrastructure
Detects network connections to the Miasma C2 server at `85.137.53[.]71` on ports 8080, 8081, or 8091.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk exit 0; log_scale exit 0. High confidence: specific IP + port combination confirmed as active C2 infrastructure for this campaign. -->
```yaml
title: AsyncAPI Miasma C2 Beacon to Known Infrastructure
id: f9a2b6c4-8d31-4e78-bf5a-4b3c2d0e1f7a
status: experimental
description: >
    Detects network connections to the Miasma C2 server at 85.137.53.71 on ports
    8080 (C2 beacon), 8081 (upload), or 8091 (management) used by the AsyncAPI
    npm supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '85.137.53.71'
        DestinationPort:
            - 8080
            - 8081
            - 8091
    condition: selection
falsepositives:
    - Legitimate traffic to this IP address (verify ownership before filtering)
level: critical
```

### Snort: AsyncAPI Miasma C2 HTTP Beacon and IPFS Payload Fetch
Detects HTTP traffic to the Miasma C2 API endpoints (`/api/v1/beacon`, `/api/v1/file-result`) and IPFS payload fetches using the campaign's known CIDs.
**Status:** compile ⚠️ uncompiled (Snort not installed) · confidence: high
<!-- audit: Snort not installed. Structural validation: http service, http_uri sticky buffer, flow established/to_server, comma-separated content modifiers, proper sid range (2100010-2100013), rev:1, classtype:trojan-activity. All rules follow Snort 3 syntax. -->
```snort
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 Beacon to /api/v1/beacon"; flow:established, to_server; http_uri; content:"/api/v1/beacon", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-17; sid:2100010; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 File Upload to /api/v1/file-result"; flow:established, to_server; http_uri; content:"/api/v1/file-result", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-17; sid:2100011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Fetch with Known CID"; flow:established, to_server; http_uri; content:"/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-17; sid:2100012; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Fetch with Known CID 2"; flow:established, to_server; http_uri; content:"/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9", fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created 2026-07-17; sid:2100013; rev:1;)
```

### Suricata: AsyncAPI Miasma C2 HTTP Beacon, IPFS Payload Fetch, and File Retrieval
Detects HTTP traffic to Miasma C2 API endpoints and IPFS payload fetches using known CIDs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Five rules: 2x HTTP C2 (beacon, file-result), 2x IPFS CID fetch (specs, generator), 1x file-content retrieval. All use dot-notation sticky buffers. -->
```suricata
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 HTTP Beacon to /api/v1/beacon"; flow:established,to_server; http.uri; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-17; sid:2200010; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 File Upload to /api/v1/file-result"; flow:established,to_server; http.uri; content:"/api/v1/file-result"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-17; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Fetch Known CID Specs"; flow:established,to_server; http.uri; content:"/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-17; sid:2200012; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI Miasma IPFS Payload Fetch Known CID Generator"; flow:established,to_server; http.uri; content:"/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-17; sid:2200013; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Miasma C2 File Content Retrieval"; flow:established,to_server; http.uri; content:"/api/v1/file-content/"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-17; sid:2200014; rev:1;)
```

### YARA: AsyncAPI Miasma Runtime M-RED-TEAM v6.4 Payload
Detects the Miasma runtime payload via campaign identifiers (`miasma-train-p1`, `miasma-test-org`), the AES master key, C2 API paths, and mDNS service type.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on positive sample containing published campaign/org/version strings. Quiet on negative with generic API paths. Multiple condition branches ensure detection across partial deobfuscation states. -->
```yara
rule AsyncAPI_Miasma_Runtime_Payload
{
    meta:
        description = "Detects the Miasma modular runtime (M-RED-TEAM v6.4) payload delivered via the AsyncAPI npm supply chain compromise, targeting campaign identifiers, encryption parameters, and C2 API paths"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $campaign = "miasma-train-p1" ascii
        $org = "miasma-test-org" ascii
        $version = "M-RED-TEAM" ascii
        $master_key = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $info_str = "rt-file-key" ascii
        $api_beacon = "/api/v1/beacon" ascii
        $api_file_result = "/api/v1/file-result" ascii
        $api_file_content = "/api/v1/file-content/" ascii
        $mdns = "_miasma._tcp" ascii
        $lockpath = ".miasma/run/node.lock" ascii
        $rentry = "rentry.co/elzotebo999" ascii

    condition:
        filesize < 20MB and
        (
            2 of ($campaign, $org, $version) or
            ($master_key and $info_str) or
            (2 of ($api_beacon, $api_file_result, $api_file_content) and 1 of ($campaign, $org, $version, $mdns)) or
            $rentry or
            ($mdns and 1 of ($campaign, $org, $version)) or
            ($lockpath and 1 of ($campaign, $org, $version, $mdns))
        )
}
```

### YARA: AsyncAPI Miasma Import-Time Loader
Detects the import-time loader injected into AsyncAPI packages via IPFS CIDs, detached spawn pattern, or the distinctive obfuscation variable name.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Fired on positive sample containing published IPFS CID and spawn/detached/unref pattern. Quiet on negative with generic child_process usage. IPFS CIDs are content-addressed and unique to this campaign. -->
```yara
rule AsyncAPI_Miasma_ImportTime_Loader
{
    meta:
        description = "Detects the AsyncAPI npm supply chain compromise import-time loader code that spawns a detached Node.js process to fetch and execute the Miasma payload from IPFS"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "high"

    strings:
        $spawn_detached = "detached: true" ascii
        $windows_hide = "windowsHide: true" ascii
        $stdio_ignore = "stdio: 'ignore'" ascii
        $unref = ".unref()" ascii
        $ipfs_url = "ipfs.io/ipfs/" ascii
        $sync_file = "sync.js" ascii
        $obfusc_var = "const _0x5af5e1" ascii
        $ipfs_cid1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs_cid2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii

    condition:
        filesize < 500KB and
        (
            ($spawn_detached and $windows_hide and $stdio_ignore and $unref) or
            ($ipfs_url and $sync_file) or
            $obfusc_var or
            1 of ($ipfs_cid*)
        )
}
```

## Lessons Learned

**Import-time execution invalidates install-hook defenses.** The AsyncAPI compromise demonstrates that `npm install --ignore-scripts` and hook-focused scanners provide zero protection when malicious code is placed in a package's exported entry point. The npm ecosystem's security model must evolve beyond lifecycle hooks to include static analysis of module entry points and runtime behavior monitoring.

**GitHub Actions `pull_request_target` remains a systemic risk.** Despite years of documented abuse, `pull_request_target` workflows that check out untrusted PR commits continue to enable credential theft from CI/CD pipelines. Organizations must audit all `pull_request_target` uses and ensure they never execute attacker-controlled code in the privileged base-branch context.

**Open-sourced attack toolkits lower the barrier for copycat campaigns.** The Miasma toolkit's public availability (since June 9, 2026) enables independent actors to deploy sophisticated supply chain attacks without developing their own infrastructure. The presence of "miasma" branding in this campaign may represent toolkit reuse rather than attribution to the original TeamPCP threat group -- defenders must key on technical indicators, not branding strings, for attribution.

**Decentralized C2 channels complicate takedown.** The six-channel fallback architecture (HTTP, Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS) means that disabling the primary C2 server does not neutralize the threat. Defenders must monitor for and block all fallback channels to achieve complete containment.

## Sources

- [Microsoft Security Blog: Unpacking AsyncAPI npm Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) — Primary technical analysis with full attack chain, IOCs, file hashes, C2 details, Miasma runtime analysis, and Defender XDR hunting queries
- [The Hacker News: Compromised AsyncAPI npm Packages](https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html) — Coverage of C2 channel architecture (six channels), 744-module framework details, attribution assessment (not TeamPCP), and OX Security disclosure context
- [Security Affairs: AsyncAPI npm Supply Chain Attack](https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html) — Additional IOCs including Ethereum address, BitTorrent bootstrap nodes, 91,973 LOC payload size, and OX Security researcher attribution
- [Hackread: Upwind Supply Chain Compromise AsyncAPI](https://hackread.com/upwind-supply-chain-compromise-asyncapi-npm-packages/) — High-level coverage noting Upwind investigation involvement

---
*Report generated by Actioner*
