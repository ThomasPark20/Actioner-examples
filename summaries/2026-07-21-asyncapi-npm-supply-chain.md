# Technical Analysis Report: AsyncAPI npm Supply Chain Compromise (2026-07-21)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-21
Version: 1.0 (DRAFT)

## Executive Summary

On July 14, 2026, threat actors compromised the @asyncapi npm organization by exploiting a misconfigured GitHub Actions workflow (`pull_request_target`) in the asyncapi/generator repository. The attacker submitted a malicious pull request that executed attacker-controlled code within the CI pipeline, exfiltrated repository credentials (GitHub PAT and Netlify tokens) to a Rentry paste service, then used the stolen PAT to push malicious commits to auto-publish branches across two repositories. Five package versions across four packages were republished within roughly 90 minutes, each carrying the Miasma modular RAT framework. The combined weekly download count of affected packages exceeds 2.9 million. Critically, the malware executes at module import-time (not install-time), defeating the common `npm install --ignore-scripts` mitigation. The Miasma runtime bundles 744 modules supporting six independent C2 channels (HTTP, Nostr, IPFS, BitTorrent DHT, libp2p, and Ethereum smart contract), though most offensive capabilities (credential harvesting, propagation, AI tool poisoning) were toggled off -- only persistence was enabled. All five malicious versions were unpublished from npm by 11:18 UTC on July 14. The attack is unattributed; while it shares branding with the TeamPCP/Miasma campaign documented in June 2026, technical divergences suggest either parallel development or brand imitation.

## Background: AsyncAPI Ecosystem

AsyncAPI is an open-source specification for defining event-driven APIs, analogous to OpenAPI for REST. The @asyncapi npm namespace provides the reference implementation used in code generators, parsers, and documentation tools. The `@asyncapi/specs` package alone accounts for approximately 2.7 million weekly downloads, and is a transitive dependency of `@asyncapi/parser` via the semver range `^6.11.1`, meaning the malicious `6.11.2` was automatically pulled into dependent projects. The ecosystem's integration with CI/CD pipelines and build systems makes it a high-value supply chain target: the malicious payload would execute not only on developer machines but in automated build environments where credentials are commonly available as environment variables.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-29 | Researcher Florence Njeri submits PoC identifying `pull_request_target` vulnerability in asyncapi/generator |
| 2026-05-17 | Fix proposal submitted (still under review at time of compromise) |
| 2026-07-14 05:08:58 | Malicious PR #2155 commit `47be388` authored against asyncapi/generator |
| 2026-07-14 05:11:05 | Vulnerable "Docs Preview (Netlify)" workflow (`manual-netlify-preview.yml`) triggers |
| 2026-07-14 ~05:17 | Stolen credentials (GITHUB_TOKEN, NETLIFY_AUTH_TOKEN) exfiltrated to `rentry[.]co/elzotebo999` |
| 2026-07-14 05:40 | Attacker pushes commit `14da44f` to `update` branch |
| 2026-07-14 05:42 | Same commit pushed to `next` branch |
| 2026-07-14 05:46 | Branch force-reset to clean state (cover-up) |
| 2026-07-14 05:51 | Commit `224b7fe9` ("fix: test release workflow on next") pushed |
| 2026-07-14 06:58:42 | Injection commit `3eab3ec9304aa26081358330491d3cfeb55cc245` force-pushed to `next` branch |
| 2026-07-14 07:05:42 | Push-triggered release workflow (`release-with-changesets.yml`) starts |
| 2026-07-14 ~07:10 | @asyncapi/generator@3.3.1, generator-helpers@1.1.1, generator-components@0.7.1 published to npm |
| 2026-07-14 07:56:11 | Dropper injected into asyncapi/spec-json-schemas (`master` branch) |
| 2026-07-14 08:06:20 | @asyncapi/specs@6.11.2-alpha.1 published |
| 2026-07-14 08:14 | Final malicious commit pushed to `master` |
| 2026-07-14 08:30:09 | @asyncapi/specs@6.11.2 (stable) published |
| 2026-07-14 08:49:22 | First downstream tarball fetch observed |
| 2026-07-14 11:12-11:18 | All five malicious versions unpublished from npm registry |

## Root Cause: GitHub Actions `pull_request_target` Misconfiguration

The root cause was a vulnerable GitHub Actions workflow (`manual-netlify-preview.yml`) in the asyncapi/generator repository that used the `pull_request_target` trigger. This trigger runs workflow code in the context of the base repository (with access to secrets) but checks out the pull request's head commit -- meaning attacker-controlled code from an untrusted fork executes with the target repository's privileges.

The attacker exploited this by:
1. Submitting spam PRs ("docs: add donation files") as noise cover
2. Hiding malicious PR #2155 among the noise
3. The vulnerable workflow checked out the attacker's untrusted head commit with `persist-credentials: true`
4. Attacker-controlled code patched `actions/checkout@v5/dist/index.js` to inject exfiltration logic
5. The `INPUT_GITHUB-TOKEN` and `NETLIFY_AUTH_TOKEN` were posted to `rentry[.]co/elzotebo999`
6. After exfiltration, the Rentry paste was overwritten with the benign string "Hello" (anti-forensics)

The stolen `asyncapi-bot` PAT was then used to push unsigned commits under the placeholder git identity "Your Name" / `you[at]example[.]com` (GitHub user ID `148100`) directly to auto-publish branches (`next` in asyncapi/generator, `master` in asyncapi/spec-json-schemas). Each repository's legitimate release workflow then published the trojanized packages via npm's GitHub OIDC trusted-publisher integration, generating valid SLSA provenance attestations -- the provenance proved the package was built by the CI workflow, but could not validate that the triggering commit was authorized.

## Technical Analysis of the Malicious Payload

### 1. Import-Time Payload Delivery (Stage 0)

Unlike typical npm supply chain attacks that use `preinstall`/`postinstall` lifecycle hooks, this campaign injects the malicious loader directly into source files that execute when the module is `require()`d or `import`ed. This defeats the `npm install --ignore-scripts` mitigation entirely.

**Injected files per package:**
- `@asyncapi/generator` -- `lib/templates/config/validator.js` (SHA256: `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a`)
- `@asyncapi/generator-helpers` -- `src/utils.js` (SHA256: `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71`)
- `@asyncapi/generator-components` -- `lib/utils/ErrorHandling.js` (SHA256: `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292`)
- `@asyncapi/specs` -- `index.js` (SHA256: `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c`)

**Obfuscation techniques:**
- ~7.7KB obfuscator.io-obfuscated payload per injected file
- 880+ leading space characters to conceal the injection in diff views
- Hex-encoded function names (`const _0x5af5e1` pattern)
- Base64-encoded string tables with `decodeURIComponent()` decoders
- Array-rotation loops with numeric targets

**Deobfuscated execution flow:**
```javascript
async function main() {
  spawn('node', ['-e', PAYLOAD], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
  }).unref();
}
main();
```

No npm lifecycle hooks are declared -- there is nothing for install-time scanners to flag.

### 2. IPFS Payload Retrieval (Stage 1-2)

The spawned detached process downloads the encrypted Miasma payload from IPFS:
- Generator packages use CID: `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9`
- Specs packages use CID: `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf`

The payload (~8.25 MB encrypted) is downloaded via IPFS gateways (`ipfs[.]io`, `dweb[.]link`, `cloudflare-ipfs[.]com`) and written as `sync.js` to platform-specific paths:

| Platform | Drop Path |
|----------|-----------|
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` |
| macOS | `~/Library/Application Support/NodeJS/sync.js` |
| Linux | `~/.local/share/NodeJS/sync.js` |
| Fallback | `~/.config/NodeJS/sync.js` |

**Decryption chain:**
- HKDF-SHA256 key derivation with master string `rt-vault-master-key-32b-aaaaaaaa`
- Config blob uses HKDF salt `rt-baked-key`, 32-byte output
- File blob uses HKDF info string `rt-file-key`, 32-byte output
- AES-256-GCM (IV from first 12 bytes, auth tag from last 16 bytes)
- ROT-94 character transform (shift=4, delta=90, printable ASCII range 33-126) applied post-decryption
- Final payload is `eval()`d

The entire decryption chain uses static embedded key material, meaning the runtime can be recovered offline without execution.

### 3. C2 Infrastructure

The Miasma runtime (M-RED-TEAM v6.4, campaign identifier `miasma-train-p1`) establishes resilient C2 via six independent channels in a tiered hierarchy:

**Primary: HTTP REST C2**
- Command server: `85.137.53[.]71:8080` (AS43641, Netherlands)
- Upload/exfil server: `85.137.53[.]71:8081`
- Proxy management: `85.137.53[.]71:8091`
- Local fallback: `127.0.0[.]1:8090`

**API endpoints:**
- `/api/v1/beacon` -- beaconing / check-in
- `/api/v1/upload` -- data exfiltration
- `/api/v1/commands/{nodeId}` -- command polling
- `/api/v1/file-result` -- file operation results
- `/api/v1/file-content/<cid>` -- file content retrieval

**Distributed Fallback Channels:**
- **Nostr relays:** `wss://relay.damus[.]io`, `wss://relay.nostr[.]com`
- **Ethereum smart contract:** `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` on Ethereum mainnet (chainId: 1) via RPC endpoint `hxxps://ethereum-rpc[.]publicnode[.]com`
- **BitTorrent DHT bootstrap:** `router.bittorrent[.]com:6881`, `dht.transmissionbt[.]com:6881`, `router.utorrent[.]com:6881`
- **libp2p GossipSub:** P2P mesh networking for peer-to-peer command distribution
- **IPFS:** Decentralized payload hosting and content-addressed data exchange

**Cryptographic identity:**
- Attacker EC public key: `0432fa4ba871877d94081fe83323fa24dfa1491e9de8725cbab7b734de9e9be3b233ef6742fd6264437c9532223d687b05fa540b70af6a516b8539af84d0eeb48e`
- Parent key: `04166c33b1bcbd7a76bc68d1e4a5b795f334e5bd9c64007b1c30715b1b1044fd6d7490cd5e6e69b9b5988049cf707bc1f58b9ace7255b00ad4425760180a2d8723`
- Uses secp256k1 elliptic curve cryptography

### 4. Platform-Specific Behavior

The Miasma framework is a 3.09 MB bundled Node.js application with 744 modules (compiled from a TypeScript monorepo with 8,362 dead-code junk variables for obfuscation). Build timestamp: `1784002253701` (2026-07-14 04:10 UTC).

#### Windows
- Drop path: `%LOCALAPPDATA%\NodeJS\sync.js`
- Persistence: HKCU Run key `miasma-monitor`
- Process hide: `windowsHide: true` flag on spawn

#### macOS
- Drop path: `~/Library/Application Support/NodeJS/sync.js`
- Persistence: Shell RC injection (`.zshrc`, `.bashrc`, or `.bash_profile`)

#### Linux
- Drop path: `~/.local/share/NodeJS/sync.js`
- Persistence: systemd user unit `miasma-monitor.service` at `~/.config/systemd/user/miasma-monitor.service`
- Service executes: `nohup node /opt/miasma/bin/miasma-monitor.js`

#### All Platforms
- Lock file: `~/.config/.miasma/run/node.lock`
- Encrypted log: `~/.cache/.sys_cache/.diag.enc`
- Shader cache camouflage: `~/.cache/mesa_shader_cache/gl_cache.bin`
- mDNS service broadcast: `_miasma._tcp`

### 5. Anti-Forensics / Evasion Techniques

- **No lifecycle hooks**: Avoiding the most common detection vector for npm supply chain attacks
- **Whitespace concealment**: 880+ leading spaces hide injected code in diff views
- **Obfuscator.io obfuscation**: Hex-encoded function names, base64 string tables, array rotation
- **Rentry paste overwrite**: Exfiltrated credentials overwritten with "Hello" after retrieval
- **Workflow run deletion**: Successful CI run (ID 29313420558) deleted from GitHub (but provenance recorded on Sigstore)
- **Placeholder git identity**: Commits attributed to "Your Name" / `you[at]example[.]com` to obscure attribution
- **Detached process**: `spawn()` with `detached: true`, `stdio: 'ignore'` hides child process
- **Static key decryption**: Allows offline analysis but prevents sandbox dynamic analysis from intercepting key exchange

**Implemented but disabled capabilities:**
- Sandbox/VM detection and evasion
- Security tool detection: CrowdStrike, SentinelOne, Microsoft Defender, CarbonBlack, Cylance, Osquery, Tanium, Qualys
- Russian language system avoidance (locale-based termination)
- Dead man's switch (`safe-wipe.js`): triggers directory wipe if stolen token is revoked
- Metamorphic mutation engine for self-modification
- AI tool poisoning targeting Claude Code, VS Code, Gemini CLI, and Cursor (marked `[SIMULATION ONLY]`)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `85.137.53[.]71`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| @asyncapi/generator | 3.3.1 | Loader injected into `lib/templates/config/validator.js` |
| @asyncapi/generator-helpers | 1.1.1 | Loader injected into `src/utils.js` |
| @asyncapi/generator-components | 0.7.1 | Loader injected into `lib/utils/ErrorHandling.js` |
| @asyncapi/specs | 6.11.2 | Loader injected into `index.js` |
| @asyncapi/specs | 6.11.2-alpha.1 | Loader injected into `index.js` |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | @asyncapi/generator-3.3.1.tgz | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` | Malicious tarball |
| All | @asyncapi/generator-helpers-1.1.1.tgz | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` | Malicious tarball |
| All | @asyncapi/generator-components-0.7.1.tgz | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | Malicious tarball |
| All | @asyncapi/specs-6.11.2.tgz | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` | Malicious tarball |
| All | @asyncapi/specs-6.11.2-alpha.1.tgz | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` | Malicious tarball |
| All | validator.js (injected) | `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | Injected loader in generator |
| All | utils.js (injected) | `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71` | Injected loader in helpers |
| All | ErrorHandling.js (injected) | `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | Injected loader in components |
| All | index.js (injected) | `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | Injected loader in specs |
| All | sync.js (wrapper) | `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | Encrypted IPFS payload wrapper |
| Windows | `%LOCALAPPDATA%\NodeJS\sync.js` | -- | Dropped Miasma payload |
| macOS | `~/Library/Application Support/NodeJS/sync.js` | -- | Dropped Miasma payload |
| Linux | `~/.local/share/NodeJS/sync.js` | -- | Dropped Miasma payload |
| Linux | `~/.config/systemd/user/miasma-monitor.service` | -- | Persistence systemd unit |
| All | `~/.config/.miasma/run/node.lock` | -- | Miasma lock file |
| All | `~/.cache/.sys_cache/.diag.enc` | -- | Encrypted diagnostic log |
| All | `~/.cache/mesa_shader_cache/gl_cache.bin` | -- | Camouflaged artifact |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `85.137.53[.]71:8080` | Primary HTTP C2 server (AS43641, Netherlands) |
| IP | `85.137.53[.]71:8081` | Upload / data exfiltration server |
| IP | `85.137.53[.]71:8091` | Proxy management endpoint |
| IPFS CID | `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | Generator-family encrypted payload |
| IPFS CID | `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | Specs encrypted payload |
| URL | `hxxps://ipfs[.]io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | IPFS payload download |
| URL | `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | IPFS payload download |
| Domain | `relay.damus[.]io` | Nostr relay (C2 fallback) |
| Domain | `relay.nostr[.]com` | Nostr relay (C2 fallback) |
| Domain | `router.bittorrent[.]com:6881` | BitTorrent DHT bootstrap |
| Domain | `dht.transmissionbt[.]com:6881` | BitTorrent DHT bootstrap |
| Domain | `router.utorrent[.]com:6881` | BitTorrent DHT bootstrap |
| Domain | `ethereum-rpc[.]publicnode[.]com` | Ethereum RPC endpoint for contract C2 |
| Ethereum | `0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710` | Blockchain C2 dead-drop contract (mainnet) |
| URL | `hxxps://rentry[.]co/elzotebo999` | Credential exfiltration paste |
| URL | `hxxps://rentry[.]co/elzotebo` | Secondary credential exfiltration paste |

### Behavioral

- Detached `node` child process spawned with `stdio: 'ignore'` and `windowsHide: true` from package import
- `node -e` execution with large obfuscated payload string from within npm package code
- Outbound HTTPS to IPFS gateways (`ipfs[.]io`, `dweb[.]link`, `cloudflare-ipfs[.]com`) during package import/build
- HTTP POST beaconing to `/api/v1/beacon` on port 8080
- mDNS service advertisement as `_miasma._tcp`
- Connections to BitTorrent DHT bootstrap nodes on port 6881 from Node.js processes
- WebSocket connections to Nostr relay endpoints
- Ethereum JSON-RPC calls to `publicnode[.]com` from non-blockchain applications
- Creation of `NodeJS` directory in user application data (masquerading as legitimate cache)
- systemd user service creation containing "miasma" in service name or exec path

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized npm packages published via compromised CI/CD pipeline |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript payload executed at import-time via `eval()` |
| T1059 | Command and Scripting Interpreter | `node -e` spawning detached process to execute downloaded payload |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Windows persistence via `HKCU\...\Run\miasma-monitor` |
| T1543.002 | Create or Modify System Process: Systemd Service | Linux persistence via `miasma-monitor.service` systemd user unit |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | macOS persistence via `.zshrc`/`.bashrc` injection |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP REST C2 beaconing to `/api/v1/beacon` |
| T1105 | Ingress Tool Transfer | Miasma payload downloaded from IPFS gateways |
| T1027 | Obfuscated Files or Information | obfuscator.io obfuscation, AES-256-GCM encryption, ROT-94 transform |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | Encrypted payload embedded via IPFS content-addressing |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Drop path `NodeJS/sync.js` masquerades as legitimate Node.js cache |
| T1102 | Web Service | C2 via Nostr relays, IPFS, Ethereum smart contract |
| T1568 | Dynamic Resolution | Ethereum smart contract and IPFS as fallback C2 resolution |
| T1140 | Deobfuscate/Decode Files or Information | HKDF-SHA256 + AES-256-GCM + ROT-94 decryption chain |
| T1552.001 | Unsecured Credentials: Credentials in Files | Targets ~/.npmrc, ~/.aws/credentials, SSH keys, browser credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen GitHub OIDC publishing credentials used for package publication |

## Impact Assessment

- **Breadth:** 5 malicious package versions published across 4 packages totaling 2.9+ million weekly downloads. `@asyncapi/specs` (2.7M weekly) is a transitive dependency of `@asyncapi/parser` via semver `^6.11.1`, automatically pulling the malicious `6.11.2` into downstream projects.
- **Exposure window:** ~4 hours (07:10 to 11:18 UTC on July 14, 2026). First downstream tarball fetch at 08:49 UTC.
- **Depth:** Import-time execution means any project that imported (not just installed) the affected version had the payload execute. This includes CI/CD build environments, development machines, and automated testing pipelines.
- **Stealth:** No lifecycle hooks to flag; valid SLSA provenance attestations; obfuscated code concealed in diff views via whitespace padding.
- **Limiting factor:** Most offensive modules were disabled (`propagate: false`, `recon: false`, `poisonAI: false`, `deadman: false`, `evasion: false`). Only `persist: true` was enabled. This may indicate a testing/staging deployment ("miasma-train-p1") or a deliberate choice to establish persistence before enabling data theft.

## Detection & Remediation

### Immediate Detection

Check for compromised package versions in your dependency tree:
```bash
# Check package-lock.json / yarn.lock for affected versions
grep -E '"@asyncapi/(generator|generator-helpers|generator-components|specs)"' package-lock.json
npm ls @asyncapi/generator @asyncapi/generator-helpers @asyncapi/generator-components @asyncapi/specs 2>/dev/null | grep -E '3\.3\.1|1\.1\.1|0\.7\.1|6\.11\.2'

# Hunt for Miasma file system artifacts
find ~ -name "sync.js" -path "*/NodeJS/*" 2>/dev/null
find ~ -name "node.lock" -path "*/.miasma/*" 2>/dev/null
find ~/.config/systemd/user -name "miasma-monitor.service" 2>/dev/null
ls -la "$LOCALAPPDATA/NodeJS/sync.js" 2>/dev/null

# Check for persistence (Linux)
systemctl --user list-units | grep miasma
grep -r "miasma" ~/.config/systemd/user/ 2>/dev/null

# Check for persistence (Windows - PowerShell)
# Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "miasma-monitor" -ErrorAction SilentlyContinue

# Network indicators
# Monitor for connections to 85.137.53.71 on ports 8080, 8081, 8091
```

### Remediation

1. **Pin safe versions immediately:** `@asyncapi/specs` <= 6.11.1, `@asyncapi/generator` <= 3.3.0, `@asyncapi/generator-components` <= 0.7.0, `@asyncapi/generator-helpers` <= 1.1.0
2. **Treat affected endpoints as compromised:** Any machine or CI runner that imported the malicious version may have persistence installed
3. **Remove persistence artifacts:** Delete `sync.js` from drop paths, remove `miasma-monitor` registry key (Windows) or systemd service (Linux), check shell RC files (macOS)
4. **Rotate all credentials** from clean hosts: npm tokens, GitHub tokens, AWS keys, SSH keys, Docker credentials, Kubernetes configs
5. **Purge caches:** `npm cache clean --force`, delete `node_modules`, regenerate lockfiles from pinned versions
6. **Block network indicators:** Firewall `85.137.53[.]71` (all ports); block IPFS gateway access if not business-required (`ipfs[.]io`, `dweb[.]link`, `cloudflare-ipfs[.]com`)

### Long-Term Hardening

- **Audit GitHub Actions workflows** for `pull_request_target` misconfigurations; never check out untrusted PR code with `persist-credentials: true`
- **Require commit signing** and reject unsigned pushes to release branches
- **Use branch protection rules** that require PR reviews before merging to auto-publish branches
- **Deploy runtime security** (e.g., StepSecurity Harden-Runner) to detect unexpected outbound connections and detached child processes in CI
- **Monitor for import-time execution**: `npm install --ignore-scripts` is insufficient; supplement with SCA tools that analyze actual source code for obfuscated payloads
- **Restrict OIDC trusted publishing** scope and monitor for unexpected package publications

## Detection Rules

These detections target the AsyncAPI/Miasma supply chain compromise at the PoC/advisory-specific altitude. Sigma rules cover host-level indicators (payload execution, persistence, C2 connections); the YARA rule detects the Miasma runtime in file scans; Snort and Suricata rules detect network C2 communication. All rules key on campaign-specific artifacts; compiles does not equal fires -- verify in your pipeline.

### Sigma: Miasma Payload Execution from Masquerading NodeJS Directory

Detects `node.exe` executing `sync.js` from the campaign's distinctive masquerading drop directories.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download blocked by proxy - not a rule error); sigma convert splunk exit 0; sigma convert log_scale exit 0. Both portability targets pass. Fields: Image (endswith), CommandLine (contains) - standard Sysmon/4688 fields. FP risk low: legitimate software unlikely to use NodeJS\sync.js path pattern. -->

```yaml
title: Miasma Payload Execution from Masquerading NodeJS Directory
id: e9fff3e7-56ee-4e22-8d4e-3d0470276658
status: experimental
description: >
    Detects node.exe executing sync.js from Miasma-specific drop directories
    that masquerade as legitimate NodeJS cache paths, as observed in the
    AsyncAPI npm supply chain compromise (July 2026).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://socket.dev/blog/asyncapi-supply-chain-attack
author: Actioner
date: 2026/07/21
tags:
    - attack.t1059.007
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\node.exe'
    selection_cmdline:
        CommandLine|contains:
            - '\NodeJS\sync.js'
            - 'AppData\Local\NodeJS\sync.js'
    condition: selection_image and selection_cmdline
falsepositives:
    - Legitimate NodeJS applications with a sync.js file in a directory named NodeJS (unlikely)
level: high
```

### Sigma: Miasma Monitor Windows Registry Persistence

Detects creation of the distinctive `miasma-monitor` Run key used for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. TargetObject endswith match on the specific Run key value name. Zero expected false positives - "miasma-monitor" is a unique, campaign-specific string. -->

```yaml
title: Miasma Monitor Windows Registry Persistence
id: 045b243d-1c64-440c-a3af-5d1fd58df661
status: experimental
description: >
    Detects creation of the miasma-monitor Registry Run key used by the
    Miasma RAT for persistence, as seen in the AsyncAPI npm supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://socket.dev/blog/asyncapi-supply-chain-attack
author: Actioner
date: 2026/07/21
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
    - None expected
level: critical
```

### Sigma: Network Connection to Miasma C2 Server

Detects outbound connections to the campaign's known C2 IP `85.137.53[.]71`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. DestinationIp exact match on campaign-specific C2 infrastructure in AS43641 (Netherlands). IP is dedicated C2, not shared hosting - FP risk negligible. Value is real (not defanged) per logsource-encoding spec. -->

```yaml
title: Network Connection to Miasma C2 Server
id: 11dd2a45-1201-4fe5-bcea-12ccd5d6c891
status: experimental
description: >
    Detects outbound network connections to the known Miasma C2 server IP
    85.137.53.71 used in the AsyncAPI npm supply chain compromise (July 2026).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
    - https://safedep.io/asyncapi-generator-supply-chain-attack-miasma-rat/
author: Actioner
date: 2026/07/21
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '85.137.53.71'
    condition: selection
falsepositives:
    - Legitimate traffic to this IP address (unlikely given its role as dedicated C2 infrastructure)
level: critical
```

### Snort: Miasma RAT HTTP C2 Beacon

Detects HTTP traffic to the Miasma C2 IP with the campaign's `/api/v1/beacon` URI pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort-test.conf -T exit 0. Snort 2.9.20 syntax (tcp + http_uri modifier). Matches on destination IP 85.137.53.71 + URI path /api/v1/beacon. Dual-anchor (IP + URI) minimizes FP. fast_pattern:only on URI for performance. -->

```snort
alert tcp $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - Miasma RAT HTTP C2 Beacon to Known Server"; flow:established,to_server; content:"/api/v1/beacon"; http_uri; fast_pattern:only; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery; sid:2100101; rev:1;)
```

### Suricata: Miasma RAT HTTP C2 Beacon

Detects HTTP traffic to the Miasma C2 IP with the campaign's `/api/v1/beacon` URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation sticky buffer (http.uri). Dual-anchor on destination IP + URI path. -->

```suricata
alert http $HOME_NET any -> 85.137.53.71 any (msg:"Actioner - Miasma RAT HTTP C2 Beacon to Known Server"; flow:established,to_server; http.uri; content:"/api/v1/beacon"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/; metadata:author Actioner, created_at 2026-07-21; sid:2200101; rev:1;)
```

### Suricata: AsyncAPI Campaign IPFS Payload Retrieval

Detects HTTP requests to IPFS gateways for the campaign-specific payload CID.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches the full IPFS CID path in http.uri. CID is content-addressed and unique to this campaign's payload. FP only if the same CID is legitimately fetched for analysis. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AsyncAPI IPFS Payload Retrieval via Known CID"; flow:established,to_server; http.uri; content:"/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/asyncapi-supply-chain-attack; metadata:author Actioner, created_at 2026-07-21; sid:2200102; rev:1;)
```

### YARA: Miasma AsyncAPI Runtime Strings

Detects the Miasma RAT runtime via distinctive campaign identifiers, encryption key material, and C2 configuration strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt matched (Malware_Miasma_AsyncAPI_Runtime_Strings); yara neg.txt no match. Positive sample uses published source strings: miasma-train-p1, rt-vault-master-key-32b-aaaaaaaa, /api/v1/beacon, miasma-monitor. Condition: 3 of 9 strings + filesize<15MB. Strings are campaign-specific (master key, campaign ID, service name, Ethereum address) - low FP risk. -->

```yara
rule Malware_Miasma_AsyncAPI_Runtime_Strings
{
    meta:
        description = "Detects the Miasma RAT runtime via distinctive configuration and campaign strings from the AsyncAPI npm supply chain compromise (July 2026)"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/"
        severity = "critical"

    strings:
        $cfg1 = "miasma-train-p1" ascii
        $cfg2 = "rt-vault-master-key-32b-aaaaaaaa" ascii
        $cfg3 = "rt-file-key" ascii
        $cfg4 = "rt-baked-key" ascii
        $svc1 = "_miasma._tcp" ascii
        $svc2 = "miasma-monitor" ascii
        $c2_1 = "/api/v1/beacon" ascii
        $c2_2 = "/api/v1/file-result" ascii
        $eth1 = "0x12c37A86a0Ed0beBe5d1d6a43E42f07860eAc710" ascii

    condition:
        filesize < 15MB and 3 of them
}
```

## Lessons Learned

1. **Import-time execution is the new frontier for npm supply chain attacks.** The common `--ignore-scripts` mitigation is ineffective against code that triggers on `require()`/`import` rather than lifecycle hooks. Defenders need source-level analysis and runtime monitoring, not just install-hook blocking.

2. **`pull_request_target` remains a systemic risk in open-source CI/CD.** Despite documented warnings, this workflow trigger continues to enable "pwn request" attacks by executing attacker-controlled code with base repository privileges. The vulnerability was reported two months before exploitation.

3. **OIDC trusted publishing proves provenance, not authorization.** SLSA attestations validated that the packages were built by the repository's CI -- but could not determine whether the triggering commit was legitimate. Provenance alone is insufficient without commit-level authorization controls.

4. **Decentralized C2 raises the cost of takedowns.** The use of six independent C2 channels (HTTP, Nostr, IPFS, DHT, libp2p, Ethereum) means that blocking the primary HTTP C2 IP does not disable the malware's ability to receive commands.

5. **The Miasma toolkit's open-sourcing (June 2026) has lowered the barrier for supply chain attacks.** This campaign may represent either the original authors or an adopter of the publicly available toolkit, making attribution unreliable.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) -- primary technical analysis with full IOC set, timeline, and malware reverse engineering
- [The Hacker News](https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html) -- attack summary with impact assessment and researcher attribution
- [StepSecurity Blog](https://www.stepsecurity.io/blog/compromised-next-branch-pushes-malicious-asyncapi-generator-generator-helpers-and-generator-components-to-npm) -- GitHub Actions vulnerability details, commit hashes, attacker identity, and Harden-Runner detection data
- [Socket.dev](https://socket.dev/blog/asyncapi-supply-chain-attack) -- detailed malware stage analysis, IPFS retrieval mechanism, credential harvesting targets, and dormant capability inventory
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/compromised-asyncapi-npm-packages/) -- C2 configuration extraction, Ethereum contract details, persistence mechanisms, and CI pipeline attack chain
- [SafeDep](https://safedep.io/asyncapi-generator-supply-chain-attack-miasma-rat/) -- Miasma RAT capability analysis, cryptographic implementation details, and EC public key material
- [OX Security](https://www.ox.security/blog/asyncapi-npm-organization-compromised-2m-weekly-downloads-affected/) -- impact assessment, attribution analysis, and BitTorrent DHT bootstrap node inventory

---
*Report generated by Actioner*
