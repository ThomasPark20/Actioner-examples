# Technical Analysis Report: Malicious npm packages colortoolsv2 / mimelib2 (Ethereum-smart-contract downloader supply-chain campaign) (2026-05-30)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-05-30
Version: 1.0 (DRAFT)

## Executive Summary

In July 2025 two malicious npm packages — `colortoolsv2` (published July 7) and a near-identical successor `mimelib2` (published late July) — were uploaded to the public npm registry and disclosed by ReversingLabs (researcher Lucija Valentic) in early September 2025. Each package ships a tiny `index.js` containing an obfuscated, `ethers.js`-based loader that reads a string from an Ethereum smart contract (a "EtherHiding"-style technique) to obtain the URL of a second-stage download server, then fetches and executes the next-stage malware. Hiding the C2 *pointer* in an immutable on-chain contract — rather than hard-coding it in the package — defeats static scanning and complicates takedown. The packages were promoted through fake GitHub cryptocurrency-trading-bot repositories (e.g. `solana-trading-bot-v2`, `ethereum-mev-bot-v2`, `arbitrage-bot`, `hyperliquid-trading-bot`) whose stars/commits/maintainers were inflated by the "Stargazers Ghost Network," so developers would add the malicious dependency believing the project was reputable.

Scope was small by downloads (colortoolsv2 ≈7, mimelib2 ≈1) but the technique is the story: any developer workstation or CI runner that pulled these as a transitive dependency would fetch and run attacker-controlled second-stage code. Both packages have been removed from npm and the linked GitHub accounts closed. This report carries concrete, durable artifacts (exact package names+versions+hashes, the Ethereum contract address, second-stage host IPs/ports), so the viability gate **passes** and rules are emitted across all four formats.

## Background: npm registry and the developer software supply chain

npm is the default package registry for the JavaScript/Node.js ecosystem; a single `npm install` resolves and runs arbitrary package code (directly or transitively). Crypto/Web3 developers frequently pull niche tooling (trading bots, dApp helpers, wallet utilities), making them a high-value, lightly-scrutinized target. This campaign weaponizes that trust: the malicious logic lives in an npm dependency rather than in the GitHub source a developer reviews, so reading the repo reveals nothing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-07-07 | `colortoolsv2` 1.0.0 published to npm; wired as a dependency into fake GitHub trading-bot repos |
| 2025-07 (mid) | Additional colortoolsv2 versions (1.0.1, 1.0.2) published |
| 2025-07 (late) | After colortoolsv2 takedown, attacker swaps in `mimelib2` (1.0.0, 1.0.1) — identical logic, same contract and second stage |
| 2025-09-03/04 | ReversingLabs publicly discloses the campaign; packages removed, GitHub accounts closed |

## Root Cause: Initial Access Vector

Social-engineering-driven dependency confusion of intent. Developers were lured to fabricated, popularity-inflated GitHub "crypto trading bot" projects (credibility manufactured by the Stargazers Ghost Network — puppet maintainers, July-created accounts, auto-generated commits/stars). Those projects declared `colortoolsv2`/`mimelib2` as dependencies; installing or building the project executed the package's loader. The GitHub account `slunfuedrac` introduced the malicious dependency into `bot.ts` of `solana-trading-bot-v2` and later switched it from colortoolsv2 to mimelib2.

## Technical Analysis of the Malicious Payload

### 1. First stage — the npm loader (index.js)

Each package contains just two files; `index.js` holds an obfuscated payload (javascript-obfuscator-style). On require/execution it uses the `ethers.js` library to call a read function — reported as `getString(address)` — on an Ethereum smart contract, which returns the URL of the second-stage server. This indirection means the operative C2 URL is never a literal string in the package; the contract can be updated on-chain to rotate C2 over time.

### 2. Second stage — downloader payload

The resolved URL serves the next-stage payload, which is downloaded and executed on the host. ReversingLabs reports a second-stage artifact with SHA1 `021d0eef8f457eb2a9f9fb2260dd2e39ff009a21` and second-stage infrastructure at `45.125.67.172` and `193.233.201.21`, with ports `1337` and `3001` observed.

### 3. C2 Infrastructure

Two-tier: (a) an Ethereum smart contract at `0x1f171a1b07c108eae05a5bccbe86922d66227e2b` acts as a resilient, decentralized *resolver* whose read function returns the current C2 URL; (b) the returned URL points at conventional attacker infrastructure (hosts `45.125.67.172`, `193.233.201.21`; ports `1337`/`3001`) that serves the second stage. The on-chain layer is takedown-resistant; the host layer rotates.

### 4. Platform-Specific Behavior

The loader runs wherever Node executes the package (Windows, macOS, Linux developer/CI hosts). Public reporting does not break out per-OS second-stage behavior; treat all Node-capable hosts that resolved the dependency as in-scope.

### 5. Anti-Forensics / Evasion Techniques

EtherHiding: storing the C2 pointer in an immutable smart contract evades static package scanning and resists takedown. Obfuscated `index.js` frustrates manual review. Placing malice in the npm dependency (not the GitHub source) defeats source-code review. Stargazers Ghost Network manufactures repo reputation; package name was swapped (colortoolsv2 to mimelib2) to survive removal.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs `[.]`; emails `[at]`. Hashes, file paths, package names, and on-chain addresses are not network-resolvable and are shown un-defanged for matching.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `colortoolsv2` | 1.0.0 (SHA1 `678c20775ff86b014ae8d9869ce5c41ee06b6215`), 1.0.1 (SHA1 `1bb7b23f45ed80bce33a6b6e6bc4f99750d5a34b`), 1.0.2 (SHA1 `db86351f938a55756061e9b1f4469ff2699e9e27`) | Obfuscated `index.js` loader; ethers.js → smart-contract C2 resolution. Removed from npm. |
| `mimelib2` | 1.0.0 (SHA1 `bda31e9022f5994385c26bd8a451acf0cd0b36da`), 1.0.1 (SHA1 `c5488b605cf3e9e9ef35da407ea848cf0326fdea`) | Duplicate of colortoolsv2; same contract + second stage. Removed from npm. |

### File System

| Platform | Path | Hash | Description |
|----------|------|------|-------------|
| any (Node) | `node_modules/colortoolsv2/index.js` | SHA1 `678c20775ff86b014ae8d9869ce5c41ee06b6215` (colortoolsv2 1.0.0) | First-stage obfuscated loader |
| any | second-stage payload | SHA1 `021d0eef8f457eb2a9f9fb2260dd2e39ff009a21` | Downloaded next-stage malware |

### Network

| Type | Value | Context |
|------|-------|---------|
| Ethereum contract | `0x1f171a1b07c108eae05a5bccbe86922d66227e2b` | C2-URL resolver (read function `getString`); EtherHiding pointer |
| IP | `45.125.67[.]172` (ports 1337, 3001) | Second-stage server |
| IP | `193.233.201[.]21` (ports 1337, 3001) | Second-stage server |

### Behavioral

- Node/npm process spawning a network downloader (curl/wget/PowerShell) during/after `npm install`.
- Outbound calls to an Ethereum JSON-RPC endpoint resolving a string from contract `0x1f171a1b...` immediately followed by an outbound download to an unfamiliar host (C2-resolution-then-fetch chain).
- GitHub "crypto trading bot" repos with anomalous July-2025 star/commit inflation referencing `colortoolsv2`/`mimelib2` (repos: `solana-trading-bot-v2`, `ethereum-mev-bot-v2`, `arbitrage-bot`, `hyperliquid-trading-bot`; actor `slunfuedrac`).

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages distributed as dependencies |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated Node/`index.js` loader executes |
| T1102 | Web Service | Ethereum smart contract abused as a C2-resolution channel (EtherHiding) |
| T1027 | Obfuscated Files or Information | Obfuscated `index.js`; C2 URL hidden off-package on-chain |
| T1105 | Ingress Tool Transfer | Loader downloads and runs second-stage payload |
| T1608.001 | Stage Capabilities: Upload Malware | Second stage staged on attacker hosts 45.125.67[.]172 / 193.233.201[.]21 |

## Impact Assessment

Breadth: low by raw downloads (≈7 and ≈1) but each install could chain to full second-stage execution on a dev/CI host with access to source, secrets, and crypto wallets. Depth: high per-victim (arbitrary code execution, crypto-developer targeting). Stealth: high — on-chain C2 pointer + obfuscation + reputation laundering.

## Detection & Remediation

### Immediate Detection
- Scan repos/`node_modules`/lockfiles/npm cache for `colortoolsv2` and `mimelib2`: `grep -rinE '"(colortoolsv2|mimelib2)"' --include=package*.json .`
- Hash-check `node_modules/colortoolsv2/index.js` against SHA1 `678c20775ff86b014ae8d9869ce5c41ee06b6215`.
- Hunt egress to `45.125.67.172` / `193.233.201.21` (ports 1337/3001) and any host-resolved-from-contract `0x1f171a1b07c108eae05a5bccbe86922d66227e2b`.

### Remediation
Remove the packages and any project that referenced them; rebuild from clean dependencies; rotate any secrets/wallet keys reachable from affected hosts; block the two C2 IPs; review CI build logs for downloader activity.

### Long-Term Hardening
Dependency allow-listing / SCA gating in CI; pin and review lockfiles; disable install scripts where feasible (`npm install --ignore-scripts`); egress filtering from build hosts; treat GitHub star/commit counts as non-evidence of trust.

## Detection Rules

These detections cover the campaign's durable artifacts: exact package names (YARA, sample-tested), a behavioral install-time downloader heuristic (Sigma), and the published second-stage host IPs plus the on-chain C2-resolver contract address (Snort/Suricata). All four compiled clean (Sigma check is blocked only by an offline D3FEND-tag fetch — see audit; its Splunk/log_scale conversions pass); compiles ≠ fires — validate in your pipeline. Contract-address content rules are medium confidence: one source rendered the address with a transposed variant (`0x1f117a1b...`), and a JSON-RPC `eth_call` encodes the target address in the request body (not the URL), so the HTTP rule is a best-effort heuristic.

### Sigma: npm/node spawning a network downloader
Detects a Node/npm/npx process spawning `curl` or `wget`, consistent with the loader fetching its second stage. Behavioral heuristic — benign install scripts also fetch assets, so triage the child command line.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: altitude=ttp/behavioral (no static command-line published), hence low. `sigma check` exits 1 ONLY because the pySigma D3FEND tag-validator tries to fetch d3fend data and gets HTTP 403 in this offline sandbox (RuntimeError: Failed to load MITRE D3FEND data) — NOT a rule defect; the rule parses fine. Portability oracle passed: `sigma convert --without-pipeline -t splunk` exit 0 => ParentImage IN ("*/node","*/npm","*/npx") Image IN ("*/curl","*/wget"); `-t log_scale` exit 0 => ParentImage=/\/node$/i or ... Image=/\/curl$/i or ... . product:linux chosen; for Windows add powershell + Invoke-WebRequest/DownloadString. Single selection-map so AND/OR grouping converts unambiguously. tags are technique-only per spec. -->
```yaml
title: npm or node spawning a network downloader during package install
id: 6f3a1c4e-2b7d-4f6a-9c1e-8d2a7b4e1f90
status: experimental
description: >-
  Detects npm/node processes spawning a command-line network downloader
  (curl or wget), consistent with the colortoolsv2/mimelib2 npm loader fetching
  an Ethereum-smart-contract-resolved second stage (ReversingLabs, 2025).
references:
  - https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code
  - https://thehackernews.com/2025/09/malicious-npm-packages-exploit-ethereum.html
author: Actioner
date: 2026/05/30
tags:
  - attack.t1059.007
  - attack.t1105
  - attack.t1195.002
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith:
      - '/node'
      - '/npm'
      - '/npx'
    Image|endswith:
      - '/curl'
      - '/wget'
  condition: selection
falsepositives:
  - Legitimate build/install scripts that fetch assets
level: medium
```

### Snort: second-stage C2 host contact
Alerts on outbound traffic to the two published second-stage server IPs.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: compiled with `snort -c /tmp/actioner/snort-min.conf -T` (rule placed at /tmp/actioner/test.rules per the min-config include) -> SNORT_EXIT=0, "Snort exiting" clean. IPs are real published IOCs but commodity hosting rotates → medium. Defanged in prose, real in rule per spec. -->
```snort
alert ip $HOME_NET any -> [45.125.67.172,193.233.201.21] any (msg:"colortoolsv2/mimelib2 npm second-stage C2 host contact"; flow:to_server; reference:url,reversinglabs.com/blog/ethereum-contracts-malicious-code; classtype:trojan-activity; sid:2100801; rev:1;)
```

### Suricata: second-stage C2 host + on-chain resolver address
Alerts on contact with the two second-stage IPs, and (heuristically) on the EtherHiding contract address appearing in an HTTP URI.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: compiled with `suricata -T -S colortoolsv2_net.rules -l /tmp` on Suricata 7.0.3 -> exit 0, "Configuration provided was successfully loaded. Exiting." (no rule load errors). Structural: balanced parens, unique sids 2200801/2200802, dot-notation http.uri sticky buffer, flow/classtype/reference/metadata present, msg prefixed "Actioner -". sid2 caveat: an ethers.js eth_call carries the contract address in the JSON-RPC POST body, not typically the URI — http.uri match is best-effort; for full coverage also inspect http.request_body. Address variant risk: most sources show 0x1f171a1b..., one showed 0x1f117a1b... (likely transposition) → medium. -->
```suricata
alert ip $HOME_NET any -> [45.125.67.172,193.233.201.21] any (msg:"Actioner - colortoolsv2/mimelib2 npm second-stage C2 host contact"; flow:to_server; reference:url,reversinglabs.com/blog/ethereum-contracts-malicious-code; classtype:trojan-activity; sid:2200801; rev:1; metadata:author Actioner, created_at 2026-05-30;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - colortoolsv2 Ethereum C2-resolution contract address in HTTP"; flow:established,to_server; http.uri; content:"1f171a1b07c108eae05a5bccbe86922d66227e2b"; nocase; reference:url,reversinglabs.com/blog/ethereum-contracts-malicious-code; classtype:trojan-activity; sid:2200802; rev:1; metadata:author Actioner, created_at 2026-05-30;)
```

### YARA: malicious package manifest name
Flags any `package.json` whose `name` is `colortoolsv2` or `mimelib2`. Scan repos, `node_modules`, npm caches, CI artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: `yarac colortoolsv2.yar /tmp/yara_out.yarc` exit 0. Sample-tested with `yara`: positive package.json containing "name": "colortoolsv2" MATCHED; negative with "name": "colortools" did NOT match. The matched token is the source-published package name (a real IOC), so sample: fired is asserted honestly. filesize<64KB scopes to manifests. Package SHA1 678c20775ff86b014ae8d9869ce5c41ee06b6215 recorded in meta; YARA's hash module needs the file present at scan time so name-match is the durable signature. -->
```yara
rule npm_colortoolsv2_malicious_package
{
    meta:
        description = "Malicious npm packages colortoolsv2 / mimelib2 (ReversingLabs, 2025) detected by manifest package name; Ethereum-smart-contract downloader campaign."
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code"
        hash = "678c20775ff86b014ae8d9869ce5c41ee06b6215"
    strings:
        $name1 = "\"name\": \"colortoolsv2\"" ascii nocase
        $name2 = "\"name\":\"colortoolsv2\"" ascii nocase
        $name3 = "\"name\": \"mimelib2\"" ascii nocase
        $name4 = "\"name\":\"mimelib2\"" ascii nocase
    condition:
        filesize < 64KB and any of them
}
```

## Lessons Learned

EtherHiding turns an immutable public blockchain into resilient C2-resolution infrastructure that resists takedown — defenders must detect the *behavior* (npm loader → contract read → outbound download) and the *host* tier, since the on-chain pointer is durable. Manufactured GitHub reputation (Stargazers Ghost Network) means stars/commits are not trust signals; SCA and lockfile review must gate dependencies regardless of a repo's apparent popularity.

## Sources

<!-- Direct WebFetch of primary RL/Hacker News article permalinks returned HTTP 403/Forbidden in this environment; IOCs (contract address, hashes, IPs/ports, versions) are corroborated across multiple independent secondary summaries of the same ReversingLabs research. The orchestrator-provided candidate URL (bleepingcomputer.com/.../npm-package-colortoolsv2-supply-chain-attack/) does NOT resolve (404) and was not cited. Contract address: 0x1f171a1b07c108eae05a5bccbe86922d66227e2b is the majority rendering; one source showed 0x1f117a1b... (treated as transcription error). -->

- [ReversingLabs — Ethereum smart contracts used to push malicious code on npm](https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code) — primary research (Lucija Valentic); packages, EtherHiding technique, campaign linkage
- [The Hacker News — Malicious npm Packages Exploit Ethereum Smart Contracts to Target Crypto Developers](https://thehackernews.com/2025/09/malicious-npm-packages-exploit-ethereum.html) — corroborates package names, repos, downloader behavior
- [Infosecurity Magazine — Malicious npm Packages Exploit Ethereum Smart Contracts](https://www.infosecurity-magazine.com/news/malicious-npm-packages-exploit/) — campaign overview and technique
- [securityonline.info — Malicious npm Packages Use Ethereum Smart Contracts for C2](https://securityonline.info/crypto-as-a-weapon-malicious-npm-packages-use-ethereum-smart-contracts-for-c2/) — contract address, versions, second-stage hash, host IOCs
- [bitcoinsensus — Ethereum Smart Contracts Abused to Hide npm Malware](https://www.bitcoinsensus.com/news/blockchain/ethereum-smart-contracts-abused-to-hide-npm-malware) — contract address and SHA1 hashes
- [GitHub Advisory Database — Malware in colortoolsv2 (GHSA-748f-36r4-4gj6)](https://github.com/advisories/GHSA-748f-36r4-4gj6) — authoritative malicious-package listing

---
*Report generated by Actioner*
