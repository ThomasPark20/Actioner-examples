# Technical Analysis Report: ViteVenom — Blockchain-Based C2 Supply Chain Campaign via Malicious npm Packages (2026-07-21)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-21
Version: 1.0 (FINAL)

## Executive Summary

ViteVenom is a software supply chain campaign discovered by Checkmarx researcher Pavan Gudimalla, targeting developers in the Vite frontend tooling ecosystem. Seven malicious npm packages impersonating the legitimate `@vitejs/*` namespace were published between June 29 and July 3, 2026, accumulating approximately 2,420 combined downloads. The campaign is attributed to threat actor **SuccessKey** and represents an expansion of the earlier **ChainVeil** operation, which pioneered a four-tier blockchain-based command-and-control (C2) architecture spanning Tron, Aptos, and Binance Smart Chain (BSC). The delivered payload is a remote access trojan (RAT) capable of reverse shell, credential harvesting, file exfiltration, and persistent backdoor injection.

The campaign shares infrastructure overlaps with **PolinRider**, a DPRK-linked supply chain operation attributed to Lazarus Group / Famous Chollima. Shared indicators include Tron wallet addresses, Aptos fallback addresses, and both XOR decryption keys. ViteVenom distinguishes itself by using import-time execution rather than install-time hooks, evading many endpoint security tools that only monitor the `npm install` lifecycle. The blockchain-based C2 makes traditional infrastructure takedown nearly impossible since payload pointers are stored as immutable on-chain transaction data.

## Background: Vite Ecosystem and npm Scope Impersonation

Vite is a popular frontend build tool created by Evan You (creator of Vue.js) with millions of weekly npm downloads. The legitimate Vite packages use the `@vitejs/*` scoped namespace. ViteVenom exploits developer trust by publishing packages under similar scoped namespaces (e.g., `@vite-tab/*`, `@vite-pro/*`, `@vitets/*`) that visually resemble the legitimate namespace in package managers and IDE autocomplete. This is an evolution from ChainVeil, which targeted Tailwind, Sass, ORM, and rate-limiting library namespaces.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02-27 | Cryptocurrency wallets linked to ViteVenom campaign activated |
| 2026-06-29 | First batch of malicious packages published to npm |
| 2026-07-03 | Last malicious packages published to npm |
| 2026-07-17 | The Hacker News publishes article covering Checkmarx research |
| 2026-07-19 | Article updated with PolinRider attribution from OpenSourceMalware |

## Root Cause: Supply Chain Compromise via npm Scope Impersonation

The attacker registered npm scoped namespaces that closely resemble the legitimate `@vitejs/*` namespace, then published packages with plausible names (`vite-tree`, `vite-ui`, `vite-type`, `build-ts`, `tab`, `vite-ts`). Developers searching for Vite-related tooling could inadvertently install these packages, especially when relying on autocomplete or search results. The malicious code activates at **import time** (when the package is `require()`d or `import`ed in code), not during `npm install`, bypassing endpoint security tools that monitor the install lifecycle.

## Technical Analysis of the Malicious Payload

### 1. Package Delivery and Import-Time Execution

The seven malicious packages contain obfuscated JavaScript that executes when the module is imported. Unlike install-time attacks (via `preinstall`/`postinstall` scripts), import-time execution delays the malicious activity until the developer actually uses the package in their code, making detection harder and the attack more targeted.

The malicious code uses multi-layer string obfuscation with two known variants:
- **Original variant**: marker `rmcej%otb%`, shuffle seed `2857687`/`2667686`, decoder function `_$_1e42`, global injection via `global['!']`
- **New variant**: marker `Cot%3t=shtP`, shuffle seed `1111436`/`3896884`, decoder function `MDy`, global injection via `global['_V']='8-XXX'`

### 2. Four-Tier Blockchain C2 Resolution Chain

The payload implements a multi-blockchain dead drop resolver to obtain C2 configuration:

1. **Tier 1 (Tron)**: Queries the Tron blockchain via `api[.]trongrid[.]io` for the latest transaction from the attacker's wallet address. The transaction data field contains an encoded pointer to the next tier.
2. **Tier 2 (BSC Decode)**: The Tron transaction data is decoded and reversed to extract a Binance Smart Chain (BSC) transaction hash.
3. **Tier 3 (BSC Payload)**: The BSC transaction is queried to extract an encrypted JavaScript payload from the transaction input data.
4. **Tier 4 (Decrypt and Execute)**: The payload is XOR-decrypted using a hard-coded key and executed via `eval()`.

**Fallback mechanism**: If blockchain resolution fails, the malware falls back to direct HTTP C2 retrieval from Vercel-hosted domains and, ultimately, direct RAT fetching from an HTTP server.

### 3. C2 Infrastructure

**Blockchain Addresses (C2 dead drops):**
- Tron wallets: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` (primary), `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` (secondary)
- Aptos accounts: `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e` (primary), `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` (secondary)

**XOR Decryption Keys:**
- Primary: `2[gWfGj;<:-93Z^C`
- Secondary: `m6:tTh^D)cBz?NM]`

**Vercel C2 Domains (HTTP fallback):**
- `260120[.]vercel[.]app` (56 references in PolinRider tracker)
- `default-configuration[.]vercel[.]app` (106 references)
- `vscode-settings-bootstrap[.]vercel[.]app` (16 references)
- `vscode-settings-config[.]vercel[.]app` (11 references)
- `vscode-bootstrapper[.]vercel[.]app` (6 references)
- `vscode-load-config[.]vercel[.]app` (6 references)

**C2 Endpoint Pattern:** `hxxps://<subdomain>[.]vercel[.]app/settings/(mac|linux|win)?flag=<N>`

### 4. Platform-Specific Behavior

#### All Platforms (Node.js)
The initial payload executes in the Node.js runtime context where the malicious package is imported. The RAT capabilities include:
- **Reverse shell**: Provides interactive command execution to the attacker
- **Credential harvesting**: Extracts stored credentials from browsers, SSH keys, and environment variables
- **File exfiltration**: Uploads sensitive files to C2 infrastructure
- **Persistent backdoor injection**: Modifies shell configuration files (`.bashrc`, `.zshrc`, `.profile`) for persistence

#### Propagation Artifact
A batch file `temp_auto_push.bat` (observed in 101 confirmed instances in the broader PolinRider campaign) performs `git commit --amend` with timestamp spoofing and force-push operations to spread malicious config file modifications while preserving original authorship metadata.

### 5. Anti-Forensics / Evasion Techniques

- **Import-time (not install-time) execution**: Bypasses npm audit hooks and endpoint tools monitoring the install lifecycle
- **Multi-layer string obfuscation**: Custom shuffling with seeded permutations and decoder functions
- **Blockchain C2 dead drops**: No traditional domains to blocklist or seize; payload pointers stored as immutable on-chain data
- **Multi-chain fallback**: Tron -> Aptos -> BSC -> HTTP, providing redundant C2 channels
- **Scoped namespace impersonation**: Visual similarity to `@vitejs/*` reduces developer suspicion
- **Commit timestamp manipulation**: `temp_auto_push.bat` anti-dates commits to blend with repository history

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Downloads | Description |
|---------------------|-----------|-------------|
| `@uw010010/vite-tree` | 1,070 | Malicious Vite ecosystem impersonator |
| `@vite-tab/tab` | 289 | Malicious Vite ecosystem impersonator |
| `@vite-ln/build-ts` | 252 | Malicious Vite ecosystem impersonator |
| `@vite-mcp/vite-type` | 239 | Malicious Vite ecosystem impersonator |
| `@vite-pro/vite-ui` | 200 | Malicious Vite ecosystem impersonator |
| `@vitets/vite-ts` | 194 | Malicious Vite ecosystem impersonator |
| `@vite-ts/vite-ui` | 176 | Malicious Vite ecosystem impersonator |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| All | `.bashrc`, `.zshrc`, `.profile` | Shell config files modified for backdoor persistence |
| Windows | `temp_auto_push.bat` | Propagation script for git commit manipulation |
| All | `postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs` | Config files targeted for loader injection (PolinRider overlap) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Blockchain | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | Primary Tron C2 wallet |
| Blockchain | `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Secondary Tron C2 wallet |
| Blockchain | `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e` | Primary Aptos C2 account |
| Blockchain | `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` | Secondary Aptos C2 account |
| Domain | `260120[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `default-configuration[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `vscode-settings-bootstrap[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `vscode-settings-config[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `vscode-bootstrapper[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `vscode-load-config[.]vercel[.]app` | HTTP fallback C2 domain |
| Domain | `api[.]trongrid[.]io` | Tron blockchain API endpoint (legitimate service abused for C2) |
| URL Pattern | `hxxps://<subdomain>[.]vercel[.]app/settings/(mac\|linux\|win)?flag=<N>` | C2 endpoint pattern |

### Behavioral

- Import-time execution in Node.js when malicious packages are `require()`d or `import`ed
- HTTP GET requests to Tron blockchain API (`api[.]trongrid[.]io`) with attacker wallet address in the URI path
- XOR decryption of payloads retrieved from blockchain transaction data using keys `2[gWfGj;<:-93Z^C` or `m6:tTh^D)cBz?NM]`
- Execution of decrypted JavaScript via `eval()`
- Modification of shell configuration files (`.bashrc`, `.zshrc`, `.profile`) for persistence
- Git commit amendment with timestamp manipulation via `temp_auto_push.bat`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages published under deceptive scoped namespaces impersonating @vitejs/* |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript executed at import time via Node.js runtime; `eval()` of decrypted payloads |
| T1102.001 | Web Service: Dead Drop Resolver | Blockchain transactions on Tron/Aptos/BSC used as read-only dead drop C2 resolver (one-directional: malware reads on-chain data, does not write back) |
| T1140 | Deobfuscate/Decode Files or Information | Multi-layer string obfuscation with seeded shuffle; XOR decryption of blockchain-stored payloads |
| T1027 | Obfuscated Files or Information | Custom obfuscator with marker strings, shuffled arrays, and decoder functions |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP requests to Tron API and Vercel C2 domains for payload retrieval |
| T1041 | Exfiltration Over C2 Channel | File exfiltration and credential theft transmitted over established C2 |
| T1005 | Data from Local System | Credential harvesting from browsers, SSH keys, environment variables |
| T1204.002 | User Execution: Malicious File | Developer imports the malicious package, triggering payload execution at module load time |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Package names designed to impersonate legitimate @vitejs/* namespace |

## Impact Assessment

**Breadth**: Approximately 2,420 combined downloads across seven packages. The broader PolinRider campaign has compromised 1,951 repositories across 1,047 unique owners. The ViteVenom packages specifically target the Vite ecosystem, affecting JavaScript/TypeScript developers building modern web applications.

**Depth**: Full RAT capabilities (reverse shell, credential theft, file exfiltration, persistent backdoor) give the attacker complete system access on compromised developer workstations. Developers often have elevated privileges, access to production credentials, CI/CD pipelines, and source code repositories, amplifying the impact.

**Stealth**: The blockchain-based C2 is exceptionally difficult to disrupt. Payload pointers stored on-chain are immutable and censorship-resistant. Import-time execution avoids triggering install-phase security scanners. The multi-chain fallback (Tron -> Aptos -> BSC -> HTTP) provides resilient command retrieval.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any ViteVenom packages are installed in your project
npm ls @uw010010/vite-tree @vite-tab/tab @vite-ln/build-ts @vite-mcp/vite-type @vite-pro/vite-ui @vitets/vite-ts @vite-ts/vite-ui 2>/dev/null

# Search node_modules for blockchain C2 indicators
grep -rl "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP\|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" node_modules/ 2>/dev/null

# Search for XOR keys in JavaScript files
grep -rl '2\[gWfGj;<:-93Z\^C\|m6:tTh\^D)cBz?NM\]' node_modules/ 2>/dev/null

# Check for obfuscator markers
grep -rl "rmcej%otb%\|Cot%3t=shtP\|_\$_1e42\|global\['!'\]" node_modules/ 2>/dev/null

# Check for persistence modifications
grep -l "vercel.app" ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null
```

### Remediation

1. **Immediately remove** any of the seven malicious packages from all projects and lockfiles
2. **Audit all dependencies** with `npm audit` and review any unfamiliar scoped packages
3. **Rotate all credentials** — SSH keys, API tokens, environment variables, cloud provider credentials, npm tokens
4. **Inspect shell config files** (`.bashrc`, `.zshrc`, `.profile`) for unauthorized modifications and remove any injected content
5. **Review git history** for unauthorized commits, especially force pushes with anti-dated timestamps
6. **Scan CI/CD pipelines** for any references to the malicious packages
7. **Monitor network traffic** for connections to the identified Vercel C2 domains and Tron API queries containing the wallet addresses

### Long-Term Hardening

- **Pin dependencies** to exact versions and use lockfiles (`package-lock.json`) with integrity hashes
- **Use npm scope verification**: confirm package scopes match the expected organization before installing
- **Deploy dependency scanning tools** (Socket, Snyk, npm audit) in CI/CD pipelines
- **Monitor for suspicious blockchain API calls** from developer workstations (unusual for most development workflows)
- **Implement allowlisting** for npm scopes in enterprise environments
- **Restrict `eval()` usage** via CSP headers and linting rules; flag any `eval()` calls in dependency code

## Detection Rules

These detections target the ViteVenom/ChainVeil campaign's distinctive artifacts: known Vercel C2 domains, Tron blockchain wallet addresses used for C2 resolution, XOR decryption keys, and obfuscator signatures. PoC/advisory-specific altitude (default); compiles does not equal fires -- verify in your environment.

### Sigma: DNS Query to ViteVenom/PolinRider C2 Vercel Domains

Detects DNS resolution of six confirmed Vercel-hosted C2 domains used by the ViteVenom/ChainVeil/PolinRider campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 — proxy limitation, not a rule defect). splunk convert exit 0; log_scale convert exit 0. Six domains from OpenSourceMalware PolinRider tracker, confirmed malicious C2 infrastructure. FP risk negligible — these are attacker-registered Vercel subdomains with no legitimate use. -->
```yaml
title: DNS Query to ViteVenom/PolinRider C2 Vercel Domains
id: c8d4a1e7-6f3b-4e92-8a5c-d7b0f2e9c163
status: experimental
description: >
    Detects DNS resolution of Vercel-hosted C2 domains used by the
    ViteVenom/ChainVeil/PolinRider supply chain campaign for payload delivery
    and RAT command retrieval.
references:
    - https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html
    - https://github.com/OpenSourceMalware/PolinRider
author: Actioner
date: 2026/07/21
tags:
    - attack.t1102.001
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - '260120.vercel.app'
            - 'default-configuration.vercel.app'
            - 'vscode-settings-bootstrap.vercel.app'
            - 'vscode-settings-config.vercel.app'
            - 'vscode-bootstrapper.vercel.app'
            - 'vscode-load-config.vercel.app'
    condition: selection
falsepositives:
    - Unlikely - these are confirmed malicious C2 infrastructure domains
level: high
```

### Snort: ViteVenom Blockchain C2 Tron Wallet Query

Detects HTTP traffic containing the primary Tron wallet address used by ViteVenom/ChainVeil for blockchain-based C2 resolution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (Snort 2.9.20). Wallet address TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP is a 34-char Base58 Tron address — extremely unlikely in benign HTTP traffic. Matches in URI path (REST API) or POST body (JSON-RPC). Does not match HTTPS/TLS-encrypted traffic — requires TLS inspection or proxy log integration. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ViteVenom Blockchain C2 Tron Wallet Query"; flow:established,to_server; content:"TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html; sid:2100010; rev:1;)
```

### Suricata: ViteVenom C2 DNS Query to Vercel Domains

Detects DNS queries to the two most-referenced ViteVenom Vercel C2 domains (260120 and default-configuration).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Two separate rules for the highest-reference-count domains from the PolinRider tracker. Additional domains (vscode-settings-bootstrap, vscode-settings-config, vscode-bootstrapper, vscode-load-config) can be added as separate rules with SIDs 2200013-2200016. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - ViteVenom C2 DNS Query to Vercel Domain (260120)"; dns.query; content:"260120.vercel.app"; nocase; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html; metadata:author Actioner, created_at 2026-07-21; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ViteVenom C2 DNS Query to Vercel Domain (default-configuration)"; dns.query; content:"default-configuration.vercel.app"; nocase; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html; metadata:author Actioner, created_at 2026-07-21; sid:2200011; rev:1;)
```

### Suricata: ViteVenom Blockchain C2 Tron Wallet Resolution via HTTP

Detects HTTP requests containing the attacker's Tron wallet address in the URI, indicating blockchain-based C2 resolution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Matches HTTP URI containing Tron wallet address TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP. Typical pattern is GET /v1/accounts/TMfKQEd7.../transactions to api.trongrid.io. Requires HTTP traffic visibility (not TLS-encrypted). -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ViteVenom Blockchain C2 Tron Wallet Resolution via HTTP"; flow:established,to_server; http.uri; content:"TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html; metadata:author Actioner, created_at 2026-07-21; sid:2200012; rev:1;)
```

### YARA: ViteVenom/ChainVeil NPM Loader Strings

Detects malicious npm package loaders via campaign-specific XOR keys, obfuscator markers, and blockchain wallet addresses. Scope to npm package archives and JavaScript files.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. Sample test used a constructed file containing published IOC strings (XOR key + wallet address), not a real malware sample — hence "constructed" not "fired". Negative benign vite config did not match. Condition requires cross-category string combinations (XOR key + blockchain indicator, OR obfuscator marker pair, OR multiple blockchain addresses + eval), minimizing FP. The XOR keys and obfuscator markers are distinctive to this campaign and unlikely in benign code. -->
```yara
rule ViteVenom_ChainVeil_NPM_Loader
{
    meta:
        description = "Detects ViteVenom/ChainVeil malicious npm package loader via XOR keys, obfuscator markers, and blockchain wallet addresses used for C2 resolution"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
        severity = "high"

    strings:
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $tron_wallet1 = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $tron_wallet2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $aptos_addr1 = "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e" ascii
        $aptos_addr2 = "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3" ascii
        $obf_marker1 = "rmcej%otb%" ascii
        $obf_marker2 = "Cot%3t=shtP" ascii
        $obf_func1 = "_$_1e42" ascii
        $obf_func2 = "function MDy(f)" ascii
        $global_inject1 = "global['!']" ascii
        $global_inject2 = "global['_V']" ascii
        $api_tron = "api.trongrid.io" ascii
        $eval_call = "eval(" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($xor_key*) and any of ($tron_wallet*, $aptos_addr*, $api_tron)) or
            (any of ($obf_marker*) and any of ($obf_func*, $global_inject*)) or
            (2 of ($tron_wallet*, $aptos_addr*) and $eval_call)
        )
}
```

## Lessons Learned

1. **Blockchain C2 is an emerging resilient technique**: Storing C2 pointers on immutable public blockchains eliminates traditional takedown mechanisms (domain seizure, hosting provider cooperation). Defenders must shift to detecting the blockchain API query patterns rather than blocking infrastructure.

2. **Import-time execution is harder to detect than install-time**: Most npm security scanners focus on `preinstall`/`postinstall` script hooks. Import-time payloads activate only when the code is actually used, evading lifecycle-based detection. Static analysis of package source code is essential.

3. **Scoped namespace impersonation exploits developer trust**: The `@scope/package` naming convention gives packages an appearance of organizational ownership. Developers should verify scope ownership and not rely on visual similarity to trusted namespaces.

4. **DPRK supply chain operations are expanding in sophistication**: The PolinRider connection demonstrates North Korean threat actors are investing in multi-ecosystem (npm, Packagist, Go, Chrome), multi-blockchain (Tron, Aptos, BSC, Ethereum) infrastructure for supply chain attacks targeting the developer community.

## Sources

- [The Hacker News - Seven Malicious Vite npm Packages Use Blockchain C2 to Deliver a RAT](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html) — primary reporting on ViteVenom campaign with package names, download counts, and ChainVeil connection
- [OpenSourceMalware/PolinRider GitHub Repository](https://github.com/OpenSourceMalware/PolinRider) — technical dossier with blockchain addresses, XOR keys, obfuscator signatures, and Vercel C2 domains
- [Socket.dev - PolinRider: North Korea-Linked Supply Chain Campaign](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) — expanded analysis covering npm, Packagist, Go modules, and Chrome extensions with DPRK attribution
- [CoinTrust - ViteVenom Targets Vite Developers With Blockchain Malware](https://www.cointrust.com/market-news/vitevenom-targets-vite-developers-with-blockchain-malware) — additional campaign details and remediation guidance
- [OpenSourceMalware - PolinRider Jumps the Fence](https://opensourcemalware.com/blog/polinrider-jumps-the-fence) — blockchain C2 dead drop infrastructure details and campaign expansion analysis
- [Rescana - Active Exploitation Alert: North Korean PolinRider Supply Chain Attack](https://www.rescana.com/post/active-exploitation-alert-north-korean-polinrider-supply-chain-attack-targets-npm-packagist-go-modules-and-chrome-extens) — DPRK attribution to Lazarus Group / Famous Chollima with cross-ecosystem targeting
- [Infosecurity Magazine - Supply Chain Attack Uses Smart Contracts for C2 Ops](https://www.infosecurity-magazine.com/news/supply-chain-attack-smart/) — prior Checkmarx research on blockchain-based C2 in npm (jest-fet-mock, November 2024), establishing the technique's lineage

<!-- revision: v0.1→v1.0. ATT&CK T1102.002→T1102.001 (blockchain C2 is read-only dead drop, not bidirectional). T1546→T1204.002 (Node.js import-time exec is user-triggered, not OS event-triggered). Sigma tag updated to match (attack.t1102.001). YARA status "sample: fired ✓" → "sample: constructed" (positive was built from published IOCs, not a confirmed upstream sample). Standalone rule files written to rules/. -->

---
*Report generated by Actioner*
