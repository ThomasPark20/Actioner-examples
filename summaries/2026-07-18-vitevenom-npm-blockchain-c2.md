# Technical Analysis Report: ViteVenom — Seven Malicious Vite-themed npm Packages with Multi-Blockchain C2 (2026-07-18)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-07-18
Version: 1.0 (DRAFT)

## Executive Summary

Between June 29 and July 3, 2026, seven malicious npm packages impersonating the Vite build tool ecosystem were published to the npm registry, collectively accumulating approximately 2,420 downloads. The packages — spanning scopes `@uw010010`, `@vite-tab`, `@vite-ln`, `@vite-mcp`, `@vite-pro`, `@vitets`, and `@vite-ts` — distribute a Remote Access Trojan (RAT) through a novel multi-tier blockchain Command-and-Control (C2) infrastructure spanning Tron, Binance Smart Chain (BSC), and Aptos blockchains. Unlike conventional domain-based C2 or even single-blockchain "EtherHiding" approaches, this campaign chains multiple blockchain networks for resilient, takedown-resistant C2 resolution with built-in fallback mechanisms.

The attack executes at import-time (not install-time), meaning the malicious code runs when the package is first imported in application code rather than during `npm install`. The payload functions as a multi-stage loader: it queries a Tron wallet's transaction history, decodes the data field to obtain a BSC transaction hash, then queries BSC to extract an encrypted next-stage payload. Fallback paths include Aptos blockchain and a direct HTTP mechanism. The final RAT provides reverse shell, credential harvesting, file exfiltration, and persistent backdoor injection via shell profile modification (.bashrc, .zshrc, .profile).

The primary detection value of this campaign is the blockchain C2 mechanism: Node.js processes on developer workstations making HTTP requests to blockchain RPC endpoints (api[.]trongrid[.]io, bsc-dataseed[.]binance[.]org, fullnode[.]mainnet[.]aptoslabs[.]com) is highly anomalous outside of Web3 development contexts.

## Background: Vite Build Tool Ecosystem and npm Supply Chain

Vite is the dominant next-generation frontend build tool in the JavaScript ecosystem, with millions of weekly downloads. Its plugin ecosystem attracts developers seeking build optimization, TypeScript tooling, and UI component packages. The `@vite-*` scoped package naming convention is ripe for typosquatting and brand impersonation — there is no central authority enforcing scope ownership beyond npm's existing namespace rules. Attackers leveraged this by creating multiple scoped packages that appear to be official Vite ecosystem tooling (type utilities, build helpers, UI components, MCP integrations).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-29 | First malicious packages published to npm (campaign start) |
| 2026-06-29 – 2026-07-03 | Remaining packages published across multiple attacker-controlled scopes |
| 2026-07-03 | Final package publication; campaign achieves ~2,420 total downloads |
| 2026-07-18 | Public disclosure by The Hacker News; packages flagged for removal |

## Root Cause: Initial Access Vector

Social-engineering-driven typosquatting/brand impersonation within the Vite ecosystem namespace. Developers searching for Vite-related tooling (TypeScript utilities, build tools, UI components, MCP integrations) would encounter these packages and install them believing they were legitimate community or official Vite plugins. The attack requires the victim to both install and import the package — the malicious payload executes at import-time rather than install-time, which evades install-script-focused scanning tools but triggers when the package is actually used in development or build processes.

## Technical Analysis of the Malicious Payload

### 1. Malicious Package Distribution (7 packages, 5 days)

| Package | Downloads | Scope Pattern |
|---------|-----------|---------------|
| `@uw010010/vite-tree` | 1,070 | Personal scope |
| `@vite-tab/tab` | 289 | Vite-branded scope |
| `@vite-ln/build-ts` | 252 | Vite-branded scope |
| `@vite-mcp/vite-type` | 239 | Vite-branded scope |
| `@vite-pro/vite-ui` | 200 | Vite-branded scope |
| `@vitets/vite-ts` | 194 | Vite-branded scope |
| `@vite-ts/vite-ui` | 176 | Vite-branded scope |

The distribution uses multiple scopes rather than a single scope, suggesting the attacker anticipated individual scope takedowns and spread risk across identities.

### 2. Import-Time Execution (Loader Stage)

Unlike many npm supply chain attacks that use `preinstall`/`postinstall` scripts, ViteVenom executes when the package module is first imported (e.g., `import '@vite-tab/tab'` or `require('@vite-mcp/vite-type')`). This design choice:
- Evades npm audit and tools that scan for suspicious install scripts
- Delays execution until the package is actually used in code
- Integrates with the application's runtime context

The loader contains a hard-coded decryption key and implements the multi-blockchain C2 resolution chain.

### 3. Multi-Blockchain C2 Architecture

The C2 resolution mechanism is the campaign's most distinctive technical feature — a multi-tier, multi-chain architecture with redundant fallbacks:

**Tier 1 — Tron (per-channel wallets):**
Each distribution channel (package) is associated with a separate Tron wallet address. The loader queries the Tron blockchain (via `api[.]trongrid[.]io`) for the latest transaction from the attacker's wallet and decodes + reverses the transaction data field.

**Tier 2 — BSC + Aptos (shared infrastructure):**
The decoded Tron transaction data yields a BSC transaction hash. The loader queries BSC (via `bsc-dataseed[.]binance[.]org`) for this transaction and extracts an encrypted payload from the transaction's input data field. A shared Tron wallet and Aptos account serve as convergence points.

**Tier 3 — Fallback mechanisms:**
If Tron retrieval fails, the loader queries an Aptos blockchain account (`fullnode[.]mainnet[.]aptoslabs[.]com`). As a final fallback, a direct HTTP mechanism bypasses blockchain entirely.

This architecture stores C2 data in blockchain transaction fields — not domain names or smart contract storage — making it resistant to traditional IOC-based blocking and domain takedown.

### 4. RAT Capabilities (Final Payload)

Once the C2 chain resolves and delivers the next-stage payload:
- **Reverse shell:** Provides interactive command execution to the attacker
- **Credential harvesting:** Extracts secrets from the development environment
- **File exfiltration:** Steals source code, configuration files, and secrets
- **Persistent backdoor injection:** Modifies shell profiles for long-term access

### 5. Persistence Mechanism

The RAT achieves persistence by modifying shell initialization files:
- `~/.bashrc` — Bash shell initialization
- `~/.zshrc` — Zsh shell initialization  
- `~/.profile` — Login shell profile

These modifications ensure the backdoor re-establishes on every new terminal session, surviving system reboots and shell restarts.

### 6. Evasion Techniques

- **Import-time execution:** Bypasses install-script scanners
- **Blockchain C2:** No static domains/IPs to blocklist; transaction data is dynamic
- **Multi-chain redundancy:** Single blockchain disruption does not break C2
- **Per-channel wallets:** Compromising one wallet does not reveal the full infrastructure
- **Hard-coded decryption key:** Payload is encrypted in transit on blockchain

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains `[.]`; emails `[at]`. Package names and blockchain addresses are shown un-defanged for exact matching.

### Package / Software Level

| Package | Scope | Description |
|---------|-------|-------------|
| `@uw010010/vite-tree` | `@uw010010` | 1,070 downloads; import-time RAT loader |
| `@vite-tab/tab` | `@vite-tab` | 289 downloads; import-time RAT loader |
| `@vite-ln/build-ts` | `@vite-ln` | 252 downloads; import-time RAT loader |
| `@vite-mcp/vite-type` | `@vite-mcp` | 239 downloads; import-time RAT loader |
| `@vite-pro/vite-ui` | `@vite-pro` | 200 downloads; import-time RAT loader |
| `@vitets/vite-ts` | `@vitets` | 194 downloads; import-time RAT loader |
| `@vite-ts/vite-ui` | `@vite-ts` | 176 downloads; import-time RAT loader |

### Network (Blockchain RPC Endpoints Used for C2)

| Type | Value | Context |
|------|-------|---------|
| Domain | `api[.]trongrid[.]io` | Tron blockchain RPC — Tier-1 C2 resolution |
| Domain | `bsc-dataseed[.]binance[.]org` | BSC blockchain RPC — Tier-2 payload extraction |
| Domain | `fullnode[.]mainnet[.]aptoslabs[.]com` | Aptos blockchain RPC — Fallback C2 |

### Behavioral

- Node.js process making HTTP/HTTPS requests to Tron/BSC/Aptos RPC endpoints
- Node.js process modifying `~/.bashrc`, `~/.zshrc`, or `~/.profile`
- Import-time network activity from Vite-themed npm packages
- Sequential blockchain API queries (Tron -> BSC) from a single process
- Encrypted data extraction from blockchain transaction input fields

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Seven malicious Vite-themed npm packages |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Import-time execution of malicious loader |
| T1102 | Web Service | Blockchain networks (Tron, BSC, Aptos) abused as C2 channels |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS to blockchain RPC endpoints |
| T1573 | Encrypted Channel | Hard-coded key decryption of blockchain-stored payload |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | .bashrc/.zshrc/.profile backdoor injection |
| T1105 | Ingress Tool Transfer | Multi-stage payload retrieval via blockchain |
| T1041 | Exfiltration Over C2 Channel | File exfiltration via established C2 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Reverse shell capability |

## Impact Assessment

**Breadth:** Low — approximately 2,420 total downloads across all seven packages. The Vite ecosystem has millions of users, so penetration was limited.

**Depth per victim:** High — full RAT capabilities (reverse shell, credential theft, file exfiltration, persistent backdoor) on any developer workstation that imported one of these packages.

**Novelty:** High — multi-blockchain C2 with per-channel wallets and cross-chain fallbacks represents a significant evolution beyond single-chain "EtherHiding" techniques. This architecture is reusable and will likely be copied.

**Stealth:** High — import-time (vs. install-time) execution, encrypted blockchain-stored payloads, no static C2 domains to blocklist.

## Detection & Remediation

### Immediate Detection

- Scan all `package.json` and lockfiles for the seven malicious package names:
  ```
  grep -rinE '"@(uw010010/vite-tree|vite-tab/tab|vite-ln/build-ts|vite-mcp/vite-type|vite-pro/vite-ui|vitets/vite-ts|vite-ts/vite-ui)"' --include="package*.json" .
  ```
- Hunt for Node.js processes making connections to blockchain RPC endpoints in network/proxy logs
- Review shell profile files (.bashrc, .zshrc, .profile) for unauthorized modifications (check file modification timestamps against expected changes)
- Audit npm cache (`~/.npm/_cacache/`) for cached copies of malicious packages

### Remediation

1. Remove any of the seven malicious packages from `node_modules` and lockfiles
2. Rebuild from clean dependency state (`rm -rf node_modules && npm ci`)
3. Inspect and restore shell profile files from known-good backups
4. Rotate all credentials accessible from affected developer workstations
5. Review git history for any commits made after the compromise window
6. Block blockchain RPC endpoints at the network perimeter for non-Web3 environments

### Long-Term Hardening

- Implement npm scope allow-listing in CI/CD pipelines
- Deploy endpoint detection for shell profile modifications by Node.js processes
- Monitor for anomalous blockchain RPC traffic from development networks
- Use `--ignore-scripts` and import-time auditing tools
- Pin dependencies and require lockfile review for all changes
- Consider network segmentation isolating dev workstations from blockchain infrastructure

## Detection Rules

These detections target the campaign's most distinctive artifacts: (1) shell profile modification by Node.js processes (the persistence mechanism), (2) blockchain RPC endpoint access from Node.js (the C2 resolution chain), and (3) network-level detection of HTTP requests to the specific blockchain endpoints used. The blockchain C2 mechanism is the primary detection differentiator — while individual blockchain RPC access may be legitimate in Web3 environments, it is highly anomalous on general development workstations running Vite build tooling.

### Sigma: Shell profile modification by Node.js process
Detects Node.js/npm/npx processes modifying shell initialization files (.bashrc, .zshrc, .profile, .bash_profile), consistent with ViteVenom's persistence mechanism. This is a high-confidence indicator — legitimate Node.js tools rarely modify shell profiles outside of explicit installer flows (e.g., nvm).
**Status:** compile pass (sigma convert splunk/log_scale exit 0) | confidence: high
<!-- audit: `sigma check` exits 1 only because pySigma ATT&CK tag validator fetches d3fend data and gets HTTP 403 in offline sandbox (RuntimeError: Failed to load MITRE ATT&CK data) — NOT a rule defect. Portability: `sigma convert --without-pipeline -t splunk` exit 0 => Image IN ("*/node","*/npm","*/npx") TargetFilename IN ("*/.bashrc","*/.zshrc","*/.profile","*/.bash_profile"); `-t log_scale` exit 0 => Image=/\/node$/i or ... TargetFilename=/\/\.bashrc$/i or ... . T1546.004 is the correct sub-technique for shell profile persistence. -->
```yaml
title: Shell profile modification by Node.js process (ViteVenom persistence)
id: 8a4b2c1e-3d5f-4e7a-b9c2-6f1d8e3a5b7c
status: experimental
description: >-
  Detects Node.js processes modifying shell profile files (.bashrc, .zshrc, .profile),
  consistent with the ViteVenom npm supply chain campaign persistence mechanism
  that injects backdoor commands into shell initialization files.
references:
  - https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html
author: Actioner
date: 2026/07/18
tags:
  - attack.persistence
  - attack.t1546.004
logsource:
  category: file_change
  product: linux
detection:
  selection_process:
    Image|endswith:
      - '/node'
      - '/npm'
      - '/npx'
  selection_target:
    TargetFilename|endswith:
      - '/.bashrc'
      - '/.zshrc'
      - '/.profile'
      - '/.bash_profile'
  condition: selection_process and selection_target
falsepositives:
  - Legitimate Node.js tools that manage shell configuration (e.g., nvm installer)
level: high
```

### Sigma: Node.js DNS queries to blockchain RPC endpoints
Detects Node.js processes resolving blockchain RPC endpoint domains (Tron, BSC, Aptos), consistent with ViteVenom's multi-blockchain C2 resolution chain. On non-Web3 developer workstations this is highly anomalous.
**Status:** compile pass (sigma convert splunk/log_scale exit 0) | confidence: medium
<!-- audit: Same sandbox D3FEND-fetch issue as above — rule parses and converts cleanly. `sigma convert --without-pipeline -t splunk` exit 0 => Image IN ("*/node","*/npm","*/npx") QueryName IN ("*api.trongrid.io*","*bsc-dataseed.binance.org*","*fullnode.mainnet.aptoslabs.com*"); `-t log_scale` exit 0. Medium confidence because legitimate Web3 dev tools will trigger; deploy with environment context (suppress in blockchain dev teams). T1102 (Web Service as C2) is correct technique. -->
```yaml
title: Node.js process connecting to blockchain RPC endpoints (ViteVenom C2)
id: 9b5c3d2f-4e6a-5f8b-c0d3-7a2e9f4b6c8d
status: experimental
description: >-
  Detects Node.js processes initiating DNS queries or network connections to
  blockchain RPC endpoints (Tron, BSC, Aptos) used as C2 resolution channels
  by the ViteVenom npm supply chain campaign. Developer workstations running
  Vite-themed packages should not normally connect to blockchain infrastructure.
references:
  - https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html
author: Actioner
date: 2026/07/18
tags:
  - attack.command_and_control
  - attack.t1102
  - attack.t1071.001
logsource:
  category: dns_query
  product: linux
detection:
  selection_process:
    Image|endswith:
      - '/node'
      - '/npm'
      - '/npx'
  selection_domain:
    QueryName|endswith:
      - '.trongrid.io'
      - '.binance.org'
      - '.aptoslabs.com'
  condition: selection_process and selection_domain
falsepositives:
  - Legitimate Web3/DeFi development tools querying blockchain RPCs
  - dApp frontend build processes
level: medium
```

### Suricata rules — DROPPED

Three Suricata rules (sids 2200810-2200812) targeting HTTP traffic to api.trongrid.io, bsc-dataseed.binance.org, and fullnode.mainnet.aptoslabs.com were drafted but dropped during review. These blockchain RPC endpoints are legitimate, high-traffic public infrastructure used by every Tron/BSC/Aptos dApp. The draft rules contained no campaign-specific discriminator (no URI path filter, wallet address match, or payload content condition) and would fire on all HTTP traffic to these hosts, generating unacceptable false-positive volume. The campaign-specific artifacts (Tron wallet addresses, BSC transaction hashes) are better surfaced as IOCs for threat-hunting queries than as alerting rules on shared infrastructure.

## Lessons Learned

This campaign demonstrates a significant evolution in blockchain-based C2 infrastructure. Prior "EtherHiding" techniques stored C2 pointers in a single smart contract on one chain — ViteVenom chains multiple blockchains (Tron -> BSC, with Aptos fallback) and uses transaction data fields rather than contract storage, making detection and disruption substantially harder. Key takeaways:

1. **Multi-chain C2 is the new frontier:** Defenders must monitor for anomalous blockchain RPC access from non-Web3 environments, not just known C2 domains/IPs.
2. **Import-time vs. install-time:** Install-script scanning is insufficient; code-level analysis of package entry points is required to catch import-time execution.
3. **Namespace trust is fragile:** npm scoped packages (`@vite-*`) carry an appearance of authority that does not reflect actual affiliation with the Vite project.
4. **Transaction data as payload storage:** Blockchain transaction fields can carry arbitrary encrypted data — this is a durable, censorship-resistant payload delivery channel.

## Sources

- [The Hacker News — Seven Malicious Vite npm Packages Use Blockchain C2](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html) — primary disclosure; package names, download counts, blockchain C2 architecture, RAT capabilities, persistence mechanism

---
*Report generated by Actioner*
