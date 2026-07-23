# Technical Analysis Report: AsyncAPI npm Supply Chain Compromise (2026-07-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-23
Version: FINAL
<!-- revision: applied critic verdicts — fixed SHA-256 hash (65→64 hex chars), ATT&CK T1543.004→T1543.002 (Linux systemd), T1546→T1546.004 (macOS RC), Sigma registry rule TargetObject fix, Suricata IPFS rule downgraded to hunt-only, YARA sample label removed and rule renamed, YARA condition tightened -->

## Executive Summary

On July 14, 2026, threat actors compromised the AsyncAPI npm organization by exploiting a `pull_request_target` GitHub Actions misconfiguration in the asyncapi/generator repository. The attacker submitted dozens of decoy pull requests to camouflage PR #2155, which exploited the workflow to steal the `asyncapi-bot` personal access token. Using the stolen credentials, the attacker pushed malicious commits through the legitimate CI/CD release pipeline, publishing five poisoned package versions across four package names within a 90-minute window. The packages collectively receive over 3 million weekly downloads.

Unlike typical npm supply chain attacks that rely on `install`/`postinstall` lifecycle hooks, the injected code executes at `require()`/`import` time -- bypassing `--ignore-scripts` mitigations entirely. The payload delivers the Miasma RAT (identified as M-RED-TEAM v6.4, campaign `miasma-train-p1`), a full-featured remote access trojan with credential harvesting (130+ file targets including SSH keys, cloud credentials, npm/GitHub tokens, browser passwords), cross-platform persistence, and six independent C2 channels (HTTP, Nostr, Ethereum smart contracts, BitTorrent DHT, libp2p, IPFS). All five malicious versions were unpublished within approximately 4 hours.

## Background: AsyncAPI Ecosystem

AsyncAPI is an open-source specification and tooling ecosystem for defining, building, and documenting event-driven APIs. The `@asyncapi/specs` package provides the specification schemas and is a transitive dependency of numerous AsyncAPI tooling packages. The `@asyncapi/generator` family provides code generation capabilities. Together, these packages see over 3 million weekly downloads and are used broadly in enterprise CI/CD pipelines, developer workstations, and container build environments. Compromise of these packages provides a high-value initial access vector into software supply chains.

## Attack Timeline (All Times UTC, July 14, 2026)

| Timestamp | Event |
|-----------|-------|
| 05:03-06:14 | 36 spam PRs ("docs: add donation files") opened as cover noise |
| ~05:08:58 | Malicious commit `47be388` authored in `elzotebo999/generator` fork |
| 05:11:05 | PR #2155 opened; vulnerable `manual-netlify-preview.yml` workflow triggered |
| 05:17 | GitHub/Netlify credentials exfiltrated to rentry[.]co/elzotebo |
| 05:40 | Commit `14da44f` pushed to `update` branch with stolen credentials |
| 05:42 | Same commit pushed to `next` branch |
| 05:46 | Branch reset to clean commit `ff010ef` (cover tracks) |
| 05:51 | Commit `224b7fe9` pushed to `next` branch |
| 06:58:42 | Release commit `3eab3ec` force-pushed to `next` branch |
| 07:05:42 | Push-triggered `release-with-changesets.yml` release workflow started |
| ~07:10 | `@asyncapi/generator@3.3.1`, `generator-components@0.7.1`, `generator-helpers@1.1.1` published |
| 07:56 | Second attack begins; commit `36269ce8` pushed to `asyncapi/spec-json-schemas` |
| 08:06:20 | `@asyncapi/specs@6.11.2-alpha.1` published |
| 08:30:09 | `@asyncapi/specs@6.11.2` stable published |
| 08:49:22 | First observed downstream Yarn cache fetch of stable 6.11.2 |
| 11:12-11:18 | All malicious versions unpublished from npm registry |

## Root Cause: GitHub Actions `pull_request_target` Misconfiguration

The attack exploited a well-known class of GitHub Actions vulnerability: a `pull_request_target` trigger combined with checkout of the untrusted pull request head commit. The vulnerable workflow `manual-netlify-preview.yml` in `asyncapi/generator` ran in the context of the base repository (with access to repository secrets) but checked out and executed code from the attacker's fork.

The attacker (GitHub login `elzotebo999`) submitted PR #2155 containing MDX content that, when processed by the Netlify preview workflow, retrieved and executed JavaScript from an external URL. This code:

1. Dumped environment variables from `/proc/*/environ` targeting `INPUT_GITHUB-TOKEN` and `NETLIFY_AUTH_TOKEN`
2. Patched `/home/runner/work/_actions/actions/checkout/v5/dist/index.js` to exfiltrate credentials on subsequent use
3. Exfiltrated stolen tokens to `rentry[.]co/elzotebo`

The vulnerability had been internally flagged 58 days before exploitation, but the fix remained unmerged at the time of the attack. The stolen `asyncapi-bot` PAT granted push access to auto-publish branches, enabling the attacker to trigger the legitimate OIDC-based release workflow which published the poisoned packages with valid SLSA provenance attestations under the automated identity `npm-oidc-no-reply[at]github[.]com`.

## Technical Analysis of the Malicious Payload

### 1. Stage 0 -- Evasion by Design

The attack deliberately avoids declaring any npm lifecycle hooks (`preinstall`, `postinstall`, `install`) in `package.json`. This evades the class of supply chain scanners that focus on hook inspection and renders the `npm install --ignore-scripts` mitigation ineffective, since the malicious code does not run at install time.

### 2. Stage 1 -- Import-Time Loader

Malicious code was injected into each package's main export path:

- `@asyncapi/specs`: `index.js` (prepended, not hidden)
- `@asyncapi/generator`: `lib/templates/config/validator.js` (hidden behind hundreds of trailing whitespace characters)
- `@asyncapi/generator-helpers`: `src/utils.js` (hidden behind trailing whitespace)
- `@asyncapi/generator-components`: `lib/utils/ErrorHandling.js` (hidden behind trailing whitespace)

When any consuming build or application imports a poisoned package, the injected block runs immediately at module-load time. The loader spawns a hidden, detached child process:

```javascript
spawn('node', [payloadPath], {
   detached: true,
   stdio: 'ignore',
   windowsHide: true,
}).unref();
```

The `detached: true` and `.unref()` ensure the child process survives parent termination. `windowsHide: true` prevents a console window from appearing on Windows. `stdio: 'ignore'` suppresses all output.

### 3. Stage 1b -- IPFS Fetch and OS-Specific Drop

The obfuscated loader (~7.7KB, obfuscated via obfuscator.io) reconstructs the IPFS transport routine at runtime and downloads the `sync.js` payload from IPFS:

- Generator-family packages: `hxxps://ipfs[.]io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`
- Specs package: `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`

The payload is written to an OS-specific drop directory:

- Windows: `%LOCALAPPDATA%\NodeJS\sync.js`
- macOS: `~/Library/Application Support/NodeJS/sync.js`
- Linux: `~/.local/share/NodeJS/sync.js`
- Fallback: `~/.config/NodeJS/sync.js`

A hunting-relevant process pattern for Windows: `node.exe -e "const _0x5af5e1`

### 4. Stage 2 -- Encrypted Payload Execution

The downloaded `sync.js` (~8.2 MB) is encrypted using a three-layer cryptographic chain:

1. **HKDF-SHA256** key derivation with master string `rt-vault-master-key-32b-aaaaaaaa`
2. **AES-256-GCM** decryption (IV = first 12 bytes, auth tag = last 16 bytes)
3. **ROT-94de** rotation applied to the decrypted string

The result is executed via `eval()`. The payloads across all five package versions are byte-identical.

### 5. Stage 3 -- Miasma RAT Runtime

The decrypted payload is identified as **M-RED-TEAM v6.4** with campaign configuration `miasma-train-p1` and organization identifier `miasma-test-org`. It provides full RAT functionality:

**Credential Harvesting (130+ targets):**
- Environment variables: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCLOUD_SERVICE_KEY`, `DOCKER_TOKEN`, `K8S_AUTH_TOKEN`, `DOPPLER_TOKEN`, `VAULT_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`
- Credential files: `~/.npmrc`, `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.vault-token`, `~/.netrc`, `~/.docker/config.json`, `google_credentials.json`
- Browser passwords and cookies
- Cryptocurrency wallet data

**GitHub API Enumeration:** When `GITHUB_TOKEN` is present, enumerates accessible repositories and CI/CD context.

**AI Tool Poisoning:** Injects into `.vscode/tasks.json` and `.claude/settings.json` to persist within developer tooling.

### 6. C2 Infrastructure

**Primary C2:**
- IP: `85.137.53[.]71`
- Port 8080: Central C2 (beacon endpoint: `/api/v1/beacon`)
- Port 8081: Upload/exfil service (`/api/v1/file-result`, `/api/v1/file-content/<cid>`)
- Port 8091: Management/configuration

**Fallback C2 Channels:**
- Nostr relays: `wss://relay[.]damus[.]io`, `wss://relay[.]nostr[.]com/`
- Ethereum smart contract: `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` (chainId 1, RPC: `hxxps://ethereum-rpc[.]publicnode[.]com`)
- BitTorrent DHT: `router[.]bittorrent[.]com:6881`, `dht[.]transmissionbt[.]com:6881`
- libp2p mesh network
- IPFS

**mDNS Service Discovery:** `_miasma._tcp`

**Attacker Public Key (secp256k1):** `0432fa4ba871877d94081fe83323fa24dfa1491e9de8725cbab7b734de9e9be3b233ef6742fd6264437c9532223d687b05fa540b70af6a516b8539af84d0eeb48e`

### 7. Platform-Specific Persistence

#### Windows
- HKCU Run registry key with value name `miasma-monitor`

#### Linux
- Systemd user unit: `miasma-monitor.service`
- Lockfile: `~/.config/.miasma/run/node.lock`

#### macOS
- Shell RC injection into `.zshrc`, `.bashrc`, or `.bash_profile`

### 8. Anti-Forensics / Evasion Techniques

- No npm lifecycle hooks declared (evades hook-focused scanners)
- Import-time execution bypasses `--ignore-scripts`
- Obfuscated loader code hidden behind trailing whitespace characters
- Runtime reconstruction of IPFS transport logic
- Three-layer cryptographic chain with static embedded key material
- Hidden detached process spawning with suppressed I/O
- Workflow run #29313420558 deleted to cover tracks
- Byte-identical payloads across releases (alpha and stable)
- Metamorphic generation module implemented but disabled in this build
- Sandbox evasion modules implemented but disabled in this build

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Safe Version | Description |
|---------------------|-------------------|--------------|-------------|
| `@asyncapi/specs` | 6.11.2-alpha.1 | 6.11.1 | Obfuscated loader prepended to `index.js` |
| `@asyncapi/specs` | 6.11.2 | 6.11.1 | Obfuscated loader prepended to `index.js` |
| `@asyncapi/generator` | 3.3.1 | 3.3.0 | Loader hidden in `lib/templates/config/validator.js` |
| `@asyncapi/generator-components` | 0.7.1 | 0.7.0 | Loader hidden in `lib/utils/ErrorHandling.js` |
| `@asyncapi/generator-helpers` | 1.1.1 | 1.1.0 | Loader hidden in `src/utils.js` |

### File System

| Platform | Path / Artifact | Hash (SHA-256) | Description |
|----------|-----------------|----------------|-------------|
| All | specs tarball 6.11.2-alpha.1 | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` | Malicious npm tarball |
| All | specs tarball 6.11.2 | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` | Malicious npm tarball |
| All | generator tarball 3.3.1 | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` | Malicious npm tarball |
| All | generator-components tarball 0.7.1 | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | Malicious npm tarball |
| All | generator-helpers tarball 1.1.1 | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` | Malicious npm tarball |
| All | injected index.js (specs) | `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | Stage 1 loader |
| All | injected validator.js (generator) | `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | Stage 1 loader |
| All | injected ErrorHandling.js (gen-components) | `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | Stage 1 loader |
| All | injected utils.js (gen-helpers) | `6e738713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c7` | Stage 1 loader |
| All | sync.js wrapper | `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | Stage 2 encrypted payload |
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` | -- | Dropped payload |
| macOS | `~/Library/Application Support/NodeJS/sync.js` | -- | Dropped payload |
| Linux | `~/.local/share/NodeJS/sync.js` | -- | Dropped payload |
| All | `~/.config/NodeJS/sync.js` | -- | Fallback drop path |
| All | `~/.config/.miasma/run/node.lock` | -- | Miasma runtime lockfile |
| All | `~/.cache/.sys_cache/.diag.enc` | -- | Encrypted diagnostic/log file |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `85.137.53[.]71:8080` | Primary C2 beacon |
| IP | `85.137.53[.]71:8081` | Data exfiltration upload |
| IP | `85.137.53[.]71:8091` | Management/configuration |
| Domain | `ipfs[.]io` | IPFS gateway for payload delivery |
| URL Pattern | `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | Specs payload IPFS CID |
| URL Pattern | `hxxps://ipfs[.]io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | Generator-family payload IPFS CID |
| Domain | `rentry[.]co` | Credential exfiltration dead-drop |
| URL Pattern | `hxxps://rentry[.]co/elzotebo999` | Initial web payload source |
| URL Pattern | `hxxps://rentry[.]co/elzotebo` | Credential exfiltration endpoint |
| Domain | `relay[.]damus[.]io` | Nostr fallback C2 relay |
| Domain | `relay[.]nostr[.]com` | Nostr fallback C2 relay |
| Domain | `ethereum-rpc[.]publicnode[.]com` | Ethereum RPC for smart contract C2 |
| Domain | `router[.]bittorrent[.]com:6881` | BitTorrent DHT bootstrap |
| Domain | `dht[.]transmissionbt[.]com:6881` | BitTorrent DHT bootstrap |
| Ethereum | `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | Smart contract for C2 instructions |

### Behavioral

- Detached Node.js child processes spawned from npm package imports with `windowsHide: true` and `stdio: 'ignore'`
- IPFS gateway requests from CI/CD runners or build environments
- Outbound HTTP to `/api/v1/beacon` and `/api/v1/file-result` endpoints
- mDNS advertisements for `_miasma._tcp` service
- LAN subnet scanning and mDNS-based lateral movement
- Creation of systemd user services, HKCU Run keys, or shell RC modifications immediately following npm package resolution
- IDE configuration file modification (`.vscode/tasks.json`, `.claude/settings.json`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Poisoned npm packages published via compromised CI/CD pipeline |
| T1199 | Trusted Relationship | Exploited GitHub Actions OIDC trust to publish with valid provenance |
| T1078.001 | Valid Accounts: Default Accounts | Stolen `asyncapi-bot` PAT used to push malicious commits |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Import-time JavaScript execution and `eval()` of decrypted payload |
| T1027 | Obfuscated Files or Information | obfuscator.io obfuscation, trailing whitespace concealment, three-layer crypto |
| T1140 | Deobfuscate/Decode Files or Information | HKDF-SHA256 + AES-256-GCM + ROT-94de decryption chain |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Drop path mimics legitimate NodeJS directory structure |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via HKCU Run `miasma-monitor` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via systemd user unit `miasma-monitor.service` |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | macOS persistence via shell RC file injection (.zshrc, .bashrc, .bash_profile) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 communication to `/api/v1/beacon` |
| T1008 | Fallback Channels | Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS fallback C2 |
| T1005 | Data from Local System | Harvesting of credential files, SSH keys, cloud configs |
| T1552.001 | Unsecured Credentials: Credentials In Files | Targeting `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_rsa`, etc. |
| T1555 | Credentials from Password Stores | Browser password and cookie extraction |
| T1041 | Exfiltration Over C2 Channel | Credential exfiltration via HTTP upload to port 8081 |
| T1105 | Ingress Tool Transfer | IPFS-based payload download |

## Impact Assessment

**Breadth:** The four affected packages collectively receive over 3 million weekly downloads. `@asyncapi/specs` is a transitive dependency of the broader AsyncAPI toolchain, amplifying reach beyond direct consumers. Affected environments include developer workstations, CI/CD pipelines, container builds, and potentially production services.

**Exposure Window:** Approximately 4 hours (07:10 to 11:18 UTC). The generator-family packages had roughly 4 hours of exposure; specs had 2-3 hours. First downstream cache fetch of the stable specs version was observed at 08:49:22 UTC.

**Severity:** Critical. The payload is a full-featured RAT with credential harvesting, persistence, lateral movement, and six C2 channels. Valid SLSA provenance attestations were generated, undermining a key supply chain trust signal.

**Stealth:** High. Import-time execution evades hook-based scanning; trailing whitespace concealment makes visual code review difficult; legitimate release infrastructure was used throughout.

## Detection & Remediation

### Immediate Detection

**Check for compromised package versions in lockfiles:**
```bash
# npm
grep -E '@asyncapi/(specs@6\.11\.2|generator@3\.3\.1|generator-components@0\.7\.1|generator-helpers@1\.1\.1)' package-lock.json

# yarn
grep -E '@asyncapi/(specs@6\.11\.2|generator@3\.3\.1|generator-components@0\.7\.1|generator-helpers@1\.1\.1)' yarn.lock

# pnpm
grep -E '@asyncapi/(specs@6\.11\.2|generator@3\.3\.1|generator-components@0\.7\.1|generator-helpers@1\.1\.1)' pnpm-lock.yaml
```

**Check for payload drop files:**
```bash
# Linux/macOS
ls -la ~/.local/share/NodeJS/sync.js ~/Library/Application\ Support/NodeJS/sync.js ~/.config/NodeJS/sync.js ~/.config/.miasma/ ~/.cache/.sys_cache/.diag.enc 2>/dev/null

# Windows (PowerShell)
Test-Path "$env:LOCALAPPDATA\NodeJS\sync.js", "$env:USERPROFILE\.config\.miasma\run\node.lock"
```

**Check for persistence artifacts:**
```bash
# Linux - systemd
systemctl --user status miasma-monitor.service 2>/dev/null

# Windows - Registry
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v miasma-monitor 2>nul

# macOS - check shell RCs for injected content
grep -l "miasma\|NodeJS/sync" ~/.zshrc ~/.bashrc ~/.bash_profile 2>/dev/null
```

**Check for orphaned node processes:**
```bash
# Linux/macOS
ps aux | grep -E 'node.*sync\.js|node.*_0x5af5e1|node.*NodeJS'

# Windows
Get-Process node -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'sync\.js|_0x5af5e1|NodeJS' }
```

### Remediation

1. **Pin to safe versions immediately:** `@asyncapi/generator@3.3.0`, `@asyncapi/generator-helpers@1.1.0`, `@asyncapi/generator-components@0.7.0`, `@asyncapi/specs@6.11.1`
2. **Remove payload files:** Delete `sync.js` from OS-specific drop directories and `~/.config/.miasma/` directory tree
3. **Kill orphaned processes:** Terminate all detached Node.js processes spawned from the NodeJS payload directory
4. **Remove persistence:** Delete `miasma-monitor` registry key (Windows), disable/remove `miasma-monitor.service` (Linux), remove injected lines from shell RC files (macOS)
5. **Rotate credentials in priority order:** npm tokens, GitHub tokens/PATs, SSH keys, cloud provider credentials (AWS/Azure/GCP), Docker registry credentials, browser passwords
6. **Block egress:** Block outbound traffic to `85.137.53[.]71` on all ports; monitor for IPFS gateway traffic and connections to Nostr relays from build infrastructure
7. **Audit AI assistant configurations:** Check `.vscode/tasks.json` and `.claude/settings.json` for unauthorized modifications
8. **Regenerate lockfiles:** Delete and regenerate `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` after pinning safe versions

### Long-Term Hardening

- Audit GitHub Actions workflows for `pull_request_target` + untrusted checkout patterns (use `actions/checkout` with explicit `ref: ${{ github.event.pull_request.base.sha }}` for base branch)
- Enforce npm provenance verification but understand its limitations: provenance does not protect against compromised push credentials
- Implement lockfile monitoring and alerting for unexpected version bumps in critical dependencies
- Use `npm install --ignore-scripts` as defense-in-depth but recognize its limitation against import-time attacks
- Deploy network egress controls on CI/CD runners to block IPFS gateways and non-essential outbound connections

## Detection Rules

These detections target the specific artifacts and behaviors of the AsyncAPI npm supply chain compromise (Miasma RAT). PoC/advisory-specific altitude, strict leniency. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles verified for all rule types (note: `sigma check` ATT&CK tag validation unavailable due to network restrictions -- conversion-validated instead).

### Sigma: Suspicious Detached Node.js Process Spawn (Windows)

Detects the import-time spawn pattern used by the AsyncAPI compromise where node.exe spawns a detached child node.exe executing from the Miasma drop directory or with the campaign's obfuscated variable prefix.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Keys on distinctive drop path '\NodeJS\sync.js' and obfuscation marker 'const _0x5af5e1' from Microsoft blog. FP risk low — legitimate node apps do not use %LOCALAPPDATA%\NodeJS\sync.js. -->
```yaml
title: AsyncAPI NPM Supply Chain - Suspicious Detached Node.js Process Spawn
id: 7a1c3d5e-2b4f-4e8a-9c6d-1f3e5a7b9c2d
status: experimental
description: >
    Detects the import-time payload execution pattern used in the AsyncAPI npm supply chain
    compromise where a detached hidden Node.js child process is spawned to execute a downloaded
    sync.js payload from OS-specific drop directories.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://securitylabs.datadoghq.com/articles/compromised-asyncapi-npm-packages/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\node.exe'
    selection_child:
        Image|endswith: '\node.exe'
        CommandLine|contains:
            - '\NodeJS\sync.js'
            - 'const _0x5af5e1'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Node.js applications spawning child processes with similar path patterns
level: high
```

### Sigma: Miasma Payload Drop Path Creation (Windows)

Detects creation of `sync.js` in the Windows-specific drop directory used by the Miasma RAT, or creation of the Miasma runtime lockfile.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Drop path %LOCALAPPDATA%\NodeJS\sync.js is highly distinctive. Lockfile path .miasma\run\node.lock is campaign-unique. -->
```yaml
title: AsyncAPI NPM Supply Chain - Miasma Payload Drop Path Creation
id: 8b2d4e6f-3c5a-4f9b-ad7e-2a4c6b8d0e3f
status: experimental
description: >
    Detects creation of sync.js payload files in the OS-specific drop directories used by the
    AsyncAPI npm supply chain compromise Miasma RAT. Also detects creation of the lockfile
    used by the malware runtime.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://www.chainguard.dev/unchained/asyncapi-supply-chain-compromise-npm-packages-backdoored-via-github-actions
author: Actioner
date: 2026/07/23
tags:
    - attack.t1059.007
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection_syncjs:
        TargetFilename|endswith: '\NodeJS\sync.js'
        TargetFilename|contains: '\AppData\Local\'
    selection_lockfile:
        TargetFilename|contains|all:
            - '\.miasma\'
            - '\run\'
            - '\node.lock'
    condition: selection_syncjs or selection_lockfile
falsepositives:
    - Legitimate applications using a NodeJS directory under AppData
level: high
```

### Sigma: Miasma Registry Persistence (Windows)

Detects the Miasma RAT HKCU Run registry persistence with value name `miasma-monitor`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. miasma-monitor registry value is unique to this campaign. Zero expected FPs. -->
<!-- revision: fixed detection logic — 'miasma-monitor' is the registry value NAME (part of TargetObject), not the value DATA (Details). Changed Details|contains to TargetObject|endswith: '\Run\miasma-monitor'. -->
```yaml
title: AsyncAPI NPM Supply Chain - Miasma Registry Persistence
id: 9c3e5f7a-4d6b-4a0c-be8f-3b5d7c9e1f4a
status: experimental
description: >
    Detects the Miasma RAT persistence mechanism on Windows via HKCU Run registry key
    with the value name miasma-monitor, as observed in the AsyncAPI npm supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://securitylabs.datadoghq.com/articles/compromised-asyncapi-npm-packages/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Run\miasma-monitor'
    condition: selection
falsepositives:
    - None expected - miasma-monitor is a known malicious indicator
level: critical
```

### Sigma: Linux Miasma Payload and Persistence

Detects creation of the Miasma payload in Linux drop paths or the `miasma-monitor` systemd user service.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check skipped (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Linux file_event logsource; drop paths and systemd service name are campaign-unique. -->
<!-- revision: fixed ATT&CK tag — Linux systemd persistence is T1543.002 (Systemd Service), not T1543.004 (Launch Daemon / macOS). -->
```yaml
title: AsyncAPI NPM Supply Chain - Linux Miasma Payload and Persistence
id: ad4f6a8b-5e7c-4b1d-cf9a-4c6e8d0f2a5b
status: experimental
description: >
    Detects creation of the Miasma RAT payload sync.js in Linux-specific drop paths
    or the miasma-monitor systemd user service, as observed in the AsyncAPI npm supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm
author: Actioner
date: 2026/07/23
tags:
    - attack.t1543.002
    - attack.t1059.007
logsource:
    category: file_event
    product: linux
detection:
    selection_syncjs:
        TargetFilename|endswith:
            - '/.local/share/NodeJS/sync.js'
            - '/.config/NodeJS/sync.js'
    selection_systemd:
        TargetFilename|endswith: '/miasma-monitor.service'
    selection_lockfile:
        TargetFilename|contains|all:
            - '/.miasma/'
            - '/run/'
            - '/node.lock'
    condition: 1 of selection_*
falsepositives:
    - Legitimate applications creating files in .local/share/NodeJS
level: high
```

### Snort: Miasma C2 Communication to Known Infrastructure

Detects outbound HTTP traffic to the Miasma C2 server at `85.137.53.71` with the campaign's known beacon and exfiltration URI paths.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R exit 0 (pidfile warning is non-fatal). Rules key on hardcoded C2 IP + distinctive URI paths /api/v1/beacon and /api/v1/file-result. -->
```snort
alert tcp $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Supply Chain Miasma C2 Communication to 85.137.53.71"; flow:established,to_server; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> 85.137.53.71 8081 (msg:"Actioner - AsyncAPI Supply Chain Miasma Data Exfiltration Upload"; flow:established,to_server; content:"/api/v1/file-result"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; sid:2100102; rev:1;)
```

### Suricata: Miasma C2 Beacon and IPFS Payload Retrieval

Detects HTTP C2 beacon traffic to `85.137.53.71` (high confidence) and DNS lookups to `ipfs.io` used for payload staging (hunt-only, low confidence -- ipfs.io has legitimate uses).
**Status:** compile ✅ compiles · confidence: high (sid:2200101, 2200102) / low (sid:2200103, hunt-only)
<!-- audit: suricata -T exit 0. HTTP rules use dot-notation sticky buffers. DNS rule for ipfs.io fires on ANY ipfs.io query — high FP outside build/CI environments. -->
<!-- revision: downgraded sid:2200103 (IPFS DNS) from confidence:high to confidence:low, classtype policy-violation, hunt-only per critic — ANY ipfs.io DNS query triggers, high FP risk. -->
```suricata
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Supply Chain Miasma C2 Beacon"; flow:established,to_server; http.uri; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-23; sid:2200101; rev:1;)

alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - AsyncAPI Supply Chain Miasma Exfil Upload"; flow:established,to_server; http.uri; content:"/api/v1/file-result"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-23; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - HUNT AsyncAPI Supply Chain IPFS Payload Retrieval via ipfs.io"; flow:to_server; dns.query; content:"ipfs.io"; nocase; fast_pattern; classtype:policy-violation; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-23, confidence low, hunt_only true; sid:2200103; rev:2;)
```

### YARA: AsyncAPI Miasma Loader Artifacts

Detects the Miasma RAT loader and payload components by matching the HKDF master key, IPFS CIDs, campaign identifiers, OS-specific drop paths, and other distinctive strings from the compromised AsyncAPI packages. Scope to npm caches, `node_modules`, and build artifact directories.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Master key string sourced from Microsoft blog (published indicator). Second rule keys on obfuscation marker, rentry dead-drop, mDNS service name, and Ethereum contract address — all from published IOCs. -->
<!-- revision: removed 'sample: fired' label — pos.txt was fabricated test input, not a real published sample; label was dishonest per skill spec. Renamed second rule from AsyncAPI_NPM_Compromised_Package_Hashes to AsyncAPI_NPM_Miasma_Campaign_Strings (it does string matching, not hash matching). Tightened condition: $obfusc now requires co-occurrence with at least one other indicator. -->
```yara
rule AsyncAPI_NPM_Miasma_Loader
{
    meta:
        description = "Detects the obfuscated import-time loader injected into compromised AsyncAPI npm packages, including the HKDF master key, spawn pattern, and IPFS CID strings"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $master_key = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $ipfs_cid1 = "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf" ascii
        $ipfs_cid2 = "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9" ascii
        $campaign = "miasma-train-p1" ascii
        $org_id = "miasma-test-org" ascii
        $drop_win = "\\NodeJS\\sync.js" ascii
        $drop_linux = "/.local/share/NodeJS/sync.js" ascii
        $drop_macos = "/Library/Application Support/NodeJS/sync.js" ascii
        $spawn_pattern = "detached" ascii
        $spawn_hide = "windowsHide" ascii
        $miasma_svc = "miasma-monitor" ascii

    condition:
        filesize < 10MB and
        (
            $master_key or
            any of ($ipfs_cid*) or
            ($campaign and $org_id) or
            (2 of ($drop_*) and $spawn_pattern and $spawn_hide) or
            ($miasma_svc and any of ($drop_*))
        )
}

rule AsyncAPI_NPM_Miasma_Campaign_Strings
{
    meta:
        description = "Detects AsyncAPI npm supply chain compromise artifacts by campaign-specific strings: obfuscation markers, dead-drop URLs, mDNS service name, and Ethereum contract address"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $obfusc = "const _0x5af5e1" ascii
        $rentry = "rentry.co/elzotebo" ascii
        $mdns = "_miasma._tcp" ascii
        $eth_addr = "0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710" ascii

    condition:
        filesize < 10MB and
        (
            ($obfusc and 1 of ($rentry, $mdns, $eth_addr)) or
            2 of ($rentry, $mdns, $eth_addr)
        )
}
```

## Lessons Learned

1. **Import-time execution is the next frontier for npm supply chain attacks.** The `--ignore-scripts` mitigation only blocks lifecycle hooks; malicious code embedded in module exports runs when `require()` or `import` is called. This attack demonstrates that static analysis of `package.json` hooks is insufficient -- file content analysis at the module-export level is required.

2. **`pull_request_target` remains one of the most dangerous GitHub Actions trigger patterns.** This class of vulnerability has been documented since 2020, yet continues to enable real-world compromise. Organizations must audit all workflows for this pattern and never check out untrusted PR code in the base repository context.

3. **Valid provenance does not equal trust.** The attacker used the legitimate CI/CD pipeline to generate valid SLSA provenance attestations for the poisoned packages. Provenance verifies *how* a package was built, not *what* was committed -- it cannot protect against a compromised push credential.

4. **Trailing whitespace as a concealment technique** is trivially effective against visual code review but detectable by automated tools. Pre-commit hooks and CI checks that flag excessive trailing whitespace in critical files would have surfaced the injection.

5. **Multi-channel C2 resilience** (HTTP + Nostr + Ethereum + BitTorrent DHT + libp2p + IPFS) demonstrates increasing sophistication in supply chain malware, making takedown significantly more difficult than single-channel operations.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) -- primary technical analysis with full payload breakdown, IOCs, and MITRE ATT&CK mappings
- [Chainguard](https://www.chainguard.dev/unchained/asyncapi-supply-chain-compromise-npm-packages-backdoored-via-github-actions) -- GitHub Actions exploitation details, SHA-1 hashes of injected files, remediation steps
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/compromised-asyncapi-npm-packages/) -- detailed attack chain analysis, Ethereum contract address, Rentry paste URLs, attacker public key, detection queries
- [StepSecurity](https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm) -- cross-repository attack coordination, Nostr relay and BitTorrent DHT infrastructure, exposure window calculations

---
*Report generated by Actioner*
