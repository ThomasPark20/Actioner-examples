# Injective Labs npm Supply Chain Attack --- Cryptocurrency Key Theft via Compromised Maintainer Account

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-12
Version: 1.0 (DRAFT)

## Executive Summary

On July 8, 2026, attackers compromised the GitHub account of Injective Labs maintainer "thomasRalee" and used the project's trusted-publisher OIDC pipeline to publish malicious version 1.20.21 of `@injectivelabs/sdk-ts` and 17 dependent wallet packages to npm. The malicious code introduced a `trackKeyDerivation()` function disguised as SDK telemetry that captured cryptocurrency private keys (hex format) and mnemonic seed phrases at runtime --- not during installation --- and exfiltrated them via HTTPS POST requests to `testnet.archival.chain.grpc-web.injective[.]network`, a domain crafted to mimic legitimate Injective Labs infrastructure. The malware batched stolen keys over a two-second window to minimize detectable network traffic volume. The compromised packages were downloaded approximately 310 times before being deprecated on the npm registry, but 87 downstream dependent packages with a combined ~112,000 cumulative downloads amplified the blast radius. Security firms Socket, Ox Security, and StepSecurity detected the compromise. Clean version 1.20.23 was released as remediation.

## Background: Injective Labs and the @injectivelabs SDK Ecosystem

Injective Labs maintains a suite of npm packages under the `@injectivelabs` scope that provide JavaScript/TypeScript SDKs for interacting with the Injective blockchain --- a layer-1 decentralized exchange protocol. The primary package, `@injectivelabs/sdk-ts`, receives approximately 50,000 weekly downloads and serves as the foundational dependency for 17 wallet integration packages covering Cosmos, EVM, Trezor, Ledger, WalletConnect, Cosmostation, Magic, Turnkey, and other wallet types. These packages are used by DeFi application developers building on the Injective Protocol, making them high-value targets for cryptocurrency theft via supply chain compromise --- any application importing these wallet packages processes private keys and seed phrases during key generation and wallet import flows.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-07-08 | Attacker compromises GitHub account of maintainer "thomasRalee" |
| 2026-07-08 | Malicious commits pushed under thomasRalee's identity via trusted-publisher OIDC pipeline |
| 2026-07-08 | Malicious version 1.20.21 of @injectivelabs/sdk-ts published to npm |
| 2026-07-08 | 17 dependent wallet packages published at version 1.20.21 with pinned malicious SDK |
| ~2026-07-08 | Legitimate account owner detects compromise "within minutes" |
| 2026-07-08--09 | Package versions deprecated on npm registry (but not removed; GitHub release artifacts remain) |
| 2026-07-09 | Socket, Ox Security, and StepSecurity publish advisories |
| 2026-07-09--10 | Clean version 1.20.23 released |

## Root Cause: Compromised GitHub Account via Trusted-Publisher OIDC Pipeline

The attacker gained access to the GitHub account of "thomasRalee," a legitimate, trusted contributor to the Injective Labs repositories with an established commit history. Using this compromised account, the attacker leveraged the project's **trusted-publisher OIDC pipeline** --- a mechanism that allows GitHub Actions workflows to publish packages to npm without requiring stored npm access tokens. Because the pipeline trusts any commit author with repository push access, compromising a single maintainer account was sufficient to bypass all publication controls and push malicious code to the npm registry through the legitimate CI/CD pipeline.

The specific method of initial account compromise (credential phishing, token theft, session hijack, or other) has not been publicly disclosed.

## Technical Analysis of the Malicious Payload

### 1. Delivery Mechanism: Runtime Activation, Not Lifecycle Scripts

Unlike many npm supply chain attacks that execute during `npm install` via `preinstall` or `postinstall` lifecycle scripts, this malware was designed to evade automated security scanners that flag installation-time execution. The malicious payload activated only at **runtime** --- specifically when a developer's application called SDK functions for wallet key generation or import. This made the malware invisible to static analysis tools that focus on lifecycle hooks and delayed detection until actual key-handling operations occurred.

### 2. The `trackKeyDerivation()` Function

The core malicious payload was a function named `trackKeyDerivation()`, injected into the SDK's key derivation code paths. It was disguised as legitimate telemetry, described in code comments as tracking "which key derivation methods are used (hex vs mnemonic) and derives timing patterns" for "SDK optimization."

The function captured:
- **Private keys** in hexadecimal format
- **Mnemonic seed phrases** (BIP-39 recovery phrases --- the master key for HD wallets)
- **Key derivation timing patterns** (which derivation method was used, timing metadata)

This data is sufficient for an attacker to fully reconstruct any wallet whose keys were processed through the compromised SDK.

### 3. Exfiltration Infrastructure and Method

**Exfiltration domain:** `testnet.archival.chain.grpc-web.injective[.]network`

The domain was crafted to blend with legitimate Injective Labs infrastructure, which uses the `injective.network` base domain and subdomains containing terms like "testnet," "chain," and "grpc-web" for real API endpoints.

**Exfiltration method:**
1. Stolen keys were encoded in **base64** format
2. Multiple key derivation events were **queued over a two-second window** and batched together
3. Batched data was bundled into **HTTP request headers**
4. Data was sent via **HTTPS POST** request to the exfiltration domain
5. The batching mechanism reduced the number of outbound requests, making the exfiltration harder to detect via request-volume anomaly detection

### 4. Package Propagation and Blast Radius

The 18 compromised packages (1 primary SDK + 17 wallet packages):

| Package | Purpose |
|---------|---------|
| `@injectivelabs/sdk-ts` | Core TypeScript SDK |
| `@injectivelabs/utils` | Utility functions |
| `@injectivelabs/networks` | Network configuration |
| `@injectivelabs/ts-types` | TypeScript type definitions |
| `@injectivelabs/exceptions` | Error handling |
| `@injectivelabs/wallet-base` | Base wallet abstraction |
| `@injectivelabs/wallet-core` | Core wallet functionality |
| `@injectivelabs/wallet-cosmos` | Cosmos wallet integration |
| `@injectivelabs/wallet-private-key` | Raw private key wallet |
| `@injectivelabs/wallet-evm` | Ethereum/EVM wallet integration |
| `@injectivelabs/wallet-trezor` | Trezor hardware wallet |
| `@injectivelabs/wallet-cosmostation` | Cosmostation wallet |
| `@injectivelabs/wallet-ledger` | Ledger hardware wallet |
| `@injectivelabs/wallet-wallet-connect` | WalletConnect protocol |
| `@injectivelabs/wallet-magic` | Magic link wallet |
| `@injectivelabs/wallet-strategy` | Wallet strategy selector |
| `@injectivelabs/wallet-turnkey` | Turnkey wallet integration |
| `@injectivelabs/wallet-cosmos-strategy` | Cosmos wallet strategy |

**Impact metrics:**
- Direct downloads of malicious versions: ~310
- Downstream dependent packages: 87
- Cumulative downloads of dependent packages: ~112,000
- Packages deprecated but not removed; GitHub release artifacts remain available

### 5. Anti-Forensics / Evasion Techniques

- **No lifecycle script triggers** --- avoided `preinstall`/`postinstall` hooks that are commonly flagged by npm audit tools
- **Runtime-only activation** --- malicious code executes only when wallet key functions are called, not during package installation
- **Telemetry disguise** --- function and comments framed as legitimate SDK usage analytics
- **Infrastructure mimicry** --- exfiltration domain uses the legitimate `injective.network` base domain with plausible subdomain structure
- **Request batching** --- two-second aggregation window reduces outbound request count
- **Header-based exfiltration** --- embedding stolen data in HTTP headers rather than request bodies may evade some DLP/content inspection rules focused on POST body analysis

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `testnet.archival.chain.grpc-web.injective[.]network`)

### Package / Software Level

| Package | Malicious Version | Clean Version | Description |
|---------|-------------------|---------------|-------------|
| @injectivelabs/sdk-ts | 1.20.21 | 1.20.23 | Core SDK with injected trackKeyDerivation() |
| @injectivelabs/utils | 1.20.21 | 1.20.23 | Utility package pinned to malicious SDK |
| @injectivelabs/networks | 1.20.21 | 1.20.23 | Network config pinned to malicious SDK |
| @injectivelabs/ts-types | 1.20.21 | 1.20.23 | Type definitions pinned to malicious SDK |
| @injectivelabs/exceptions | 1.20.21 | 1.20.23 | Exception handling pinned to malicious SDK |
| @injectivelabs/wallet-base | 1.20.21 | 1.20.23 | Base wallet abstraction |
| @injectivelabs/wallet-core | 1.20.21 | 1.20.23 | Core wallet functionality |
| @injectivelabs/wallet-cosmos | 1.20.21 | 1.20.23 | Cosmos wallet integration |
| @injectivelabs/wallet-private-key | 1.20.21 | 1.20.23 | Private key wallet |
| @injectivelabs/wallet-evm | 1.20.21 | 1.20.23 | EVM wallet integration |
| @injectivelabs/wallet-trezor | 1.20.21 | 1.20.23 | Trezor wallet integration |
| @injectivelabs/wallet-cosmostation | 1.20.21 | 1.20.23 | Cosmostation wallet |
| @injectivelabs/wallet-ledger | 1.20.21 | 1.20.23 | Ledger wallet integration |
| @injectivelabs/wallet-wallet-connect | 1.20.21 | 1.20.23 | WalletConnect integration |
| @injectivelabs/wallet-magic | 1.20.21 | 1.20.23 | Magic link wallet |
| @injectivelabs/wallet-strategy | 1.20.21 | 1.20.23 | Wallet strategy selector |
| @injectivelabs/wallet-turnkey | 1.20.21 | 1.20.23 | Turnkey wallet integration |
| @injectivelabs/wallet-cosmos-strategy | 1.20.21 | 1.20.23 | Cosmos wallet strategy |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | testnet.archival.chain.grpc-web.injective[.]network | Exfiltration endpoint for stolen keys |

### Behavioral

- `trackKeyDerivation()` function present in SDK source code
- HTTPS POST requests with base64-encoded data in HTTP headers to the exfiltration domain
- Two-second batching window between key capture and exfiltration
- Key derivation telemetry data structures containing `privateKey`, `mnemonic`, and timing fields
- GitHub commits attributed to "thomasRalee" pushing code containing the `trackKeyDerivation` function

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Attacker compromised the GitHub account of a trusted maintainer and used the project's OIDC trusted-publisher pipeline to publish malicious package versions to npm |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Stolen private keys and seed phrases exfiltrated via HTTPS POST to an attacker-controlled subdomain of the legitimate injective.network domain |
| T1552.004 | Unsecured Credentials: Private Keys | Malware specifically targeted cryptocurrency private keys in hex format and BIP-39 mnemonic seed phrases |
| T1036.004 | Masquerading: Masquerade as Legitimate Application | Exfiltration function disguised as SDK telemetry ("trackKeyDerivation") and domain mimicked legitimate Injective infrastructure |

## Impact Assessment

**Breadth:** 18 packages compromised, ~310 direct downloads of the malicious version, 87 downstream dependent packages with ~112,000 cumulative downloads. The attack targeted the entire Injective developer ecosystem.

**Depth:** Any private key or mnemonic seed phrase processed through the compromised SDK version must be treated as fully compromised. Attackers can reconstruct wallets and drain all associated cryptocurrency holdings across any blockchain the wallet was used on.

**Stealth:** High. The runtime-only activation, telemetry disguise, infrastructure mimicry, and header-based batched exfiltration made this attack difficult to detect through standard npm security tooling. Detection occurred "within minutes" by the legitimate account owner, likely through GitHub notification of unexpected pushes, not through automated security scanning.

**Exposure window:** Approximately 24-48 hours between publication and deprecation.

## Detection & Remediation

### Immediate Detection

Check for the malicious version in your project:

```bash
# Check if any malicious version is installed
npm ls @injectivelabs/sdk-ts 2>/dev/null | grep "1.20.21" && echo "COMPROMISED" || echo "Clean"

# Check all @injectivelabs packages
npm ls 2>/dev/null | grep "@injectivelabs.*1.20.21" && echo "COMPROMISED" || echo "Clean"

# Check package-lock.json for the malicious version
grep -r "1.20.21" package-lock.json | grep "injectivelabs" && echo "COMPROMISED" || echo "Clean"

# Check yarn.lock
grep -A2 "@injectivelabs" yarn.lock | grep "1.20.21" && echo "COMPROMISED" || echo "Clean"

# Search for the malicious function in node_modules
grep -rl "trackKeyDerivation" node_modules/@injectivelabs/ 2>/dev/null && echo "COMPROMISED" || echo "Clean"

# Check DNS logs for the exfiltration domain
grep "testnet.archival.chain.grpc-web.injective.network" /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Immediately update** all @injectivelabs packages to version 1.20.23 or later:
   ```bash
   npm install @injectivelabs/sdk-ts@latest
   ```

2. **Treat all keys as compromised** --- any private key or mnemonic seed phrase that was used with the malicious version must be considered stolen.

3. **Transfer funds immediately** --- move all cryptocurrency from potentially compromised wallets to newly generated wallets using the clean SDK version or an independent key generation tool.

4. **Rotate all secrets** --- any API keys, tokens, or credentials that were in the environment where the malicious package ran should be rotated.

5. **Audit CI/CD artifacts** --- check build pipelines for cached copies of version 1.20.21 in npm caches, Docker layers, or artifact storage.

6. **Review network logs** --- search proxy, DNS, and firewall logs for connections to `testnet.archival.chain.grpc-web.injective.network`.

### Long-Term Hardening

1. **Pin exact dependency versions** and use lockfiles (`package-lock.json`, `yarn.lock`) to prevent automatic installation of new minor/patch versions.

2. **Enable npm audit** in CI/CD pipelines to catch known-compromised package versions.

3. **Monitor for dependency updates** using tools like Socket, Snyk, or Dependabot with review requirements before merging.

4. **Require multi-factor authentication** for all npm publish accounts and GitHub accounts with push access to published packages.

5. **Implement Subresource Integrity (SRI)** where applicable and consider npm provenance verification.

6. **Audit trusted-publisher OIDC configurations** --- restrict which repository branches and workflows can trigger package publication.

## Detection Rules

The following rules detect network indicators (exfiltration domain) and endpoint activity (npm package installation) associated with the Injective Labs supply chain compromise. All rules target specific, high-fidelity IOCs; the exfiltration domain is the primary network pivot. The Sigma process-creation rule will fire on any installation of @injectivelabs packages (not just the malicious version) and should be tuned or used for retroactive hunting rather than real-time alerting in environments that legitimately use these packages.

### Sigma: NPM Install of Malicious Injective Labs Packages

Detects npm/yarn commands installing @injectivelabs packages associated with the supply chain compromise.
compile: sigma convert pass | confidence: medium

```yaml
title: NPM Install of Malicious Injective Labs Packages
id: 8a3c1d4e-5f6b-4a2c-9e7d-1b0f3c8a5d2e
status: experimental
description: >
    Detects npm or yarn commands installing known malicious versions of
    @injectivelabs packages compromised in the July 2026 supply chain attack.
    The malicious version 1.20.21 contained a trackKeyDerivation function that
    exfiltrated cryptocurrency private keys and mnemonic seed phrases.
references:
    - https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html
    - https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1195.001
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_package_manager:
        Image|endswith:
            - '/npm'
            - '/yarn'
            - '\npm.cmd'
            - '\yarn.cmd'
            - '/npx'
            - '\npx.cmd'
        CommandLine|contains:
            - '@injectivelabs/sdk-ts'
            - '@injectivelabs/wallet-base'
            - '@injectivelabs/wallet-core'
            - '@injectivelabs/wallet-cosmos'
            - '@injectivelabs/wallet-private-key'
            - '@injectivelabs/wallet-evm'
            - '@injectivelabs/wallet-trezor'
            - '@injectivelabs/wallet-cosmostation'
            - '@injectivelabs/wallet-ledger'
            - '@injectivelabs/wallet-wallet-connect'
            - '@injectivelabs/wallet-magic'
            - '@injectivelabs/wallet-strategy'
            - '@injectivelabs/wallet-turnkey'
            - '@injectivelabs/wallet-cosmos-strategy'
    condition: selection_package_manager
falsepositives:
    - Legitimate installations of non-malicious versions of these packages
    - The clean version 1.20.23 and later are safe but will also trigger this rule
level: medium
```

<!--
AUDIT: Sigma rule 8a3c1d4e — NPM Install Detection
- Validation: `sigma convert --without-pipeline -t splunk` passed (exit 0). `sigma check` failed due to network
  restrictions fetching MITRE ATT&CK data (HTTP 403) — not a rule syntax issue.
- Encoding: Field values are not defanged; package names match real npm scope/package format.
- Logsource: process_creation is appropriate for npm CLI invocations. Image|endswith covers both Unix
  (/usr/bin/npm) and Windows (npm.cmd) path forms.
- FP note: Cannot distinguish malicious version 1.20.21 from clean versions via command-line alone because
  `npm install @injectivelabs/sdk-ts` resolves to latest. Use as a hunting rule in environments that do not
  normally install these packages, or correlate with lockfile audits.
- Tag provenance: T1195.001 (Supply Chain Compromise) is the primary technique. T1059.007 (JavaScript)
  covers the npm/Node.js execution context.
-->

### Sigma: DNS Query to Injective Labs Exfiltration Domain

Detects DNS resolution of the exfiltration domain used by the compromised packages.
compile: sigma convert pass | confidence: high

```yaml
title: DNS Query to Injective Labs Exfiltration Domain
id: 2b7e9f1a-4c3d-4e8b-a5f6-0d1c2e3b4a5f
status: experimental
description: >
    Detects DNS queries to the exfiltration domain used by the compromised
    @injectivelabs/sdk-ts package to steal cryptocurrency private keys and
    mnemonic seed phrases. The domain mimics legitimate Injective Labs
    infrastructure naming conventions.
references:
    - https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html
    - https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1567.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'testnet.archival.chain.grpc-web.injective.network'
    condition: selection
falsepositives:
    - Unlikely. This specific subdomain structure was created for exfiltration and is not legitimate Injective Labs infrastructure.
level: critical
```

<!--
AUDIT: Sigma rule 2b7e9f1a — DNS Query Detection
- Validation: `sigma convert --without-pipeline -t splunk` passed (exit 0).
- Encoding: Domain is NOT defanged (real value for detection matching). Uses endswith to catch both
  bare domain and any prepended subdomains.
- Logsource: dns_query maps to Sysmon EID 22 and equivalent DNS logging on other platforms.
- FP assessment: Very low. The subdomain `testnet.archival.chain.grpc-web` is not part of legitimate
  Injective Labs infrastructure and was purpose-built for this attack.
-->

### Sigma: Network Connection to Injective Labs Exfiltration Domain

Detects outbound connections to the exfiltration endpoint.
compile: sigma convert pass | confidence: high

```yaml
title: Network Connection to Injective Labs Exfiltration Domain
id: 6c4d8e2f-3a1b-4d5c-b9e7-2f0a1c3d5e4b
status: experimental
description: >
    Detects outbound network connections to the exfiltration domain used
    by the compromised @injectivelabs npm packages. The malware sends
    stolen private keys and seed phrases via HTTPS POST requests to this
    domain, batching multiple key derivations over a two-second window.
references:
    - https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html
    - https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
author: Actioner
date: 2026-07-12
tags:
    - attack.t1567.002
logsource:
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'testnet.archival.chain.grpc-web.injective.network'
    condition: selection
falsepositives:
    - Unlikely. This subdomain was purpose-built for exfiltration.
level: critical
```

<!--
AUDIT: Sigma rule 6c4d8e2f — Network Connection Detection
- Validation: `sigma convert --without-pipeline -t splunk` passed (exit 0).
- Encoding: Domain is NOT defanged. DestinationHostname with endswith matches Sysmon EID 3 field.
- FP assessment: Very low — same rationale as DNS rule.
-->

### YARA: Injective SDK Key Stealer Payload Detection

Detects the malicious trackKeyDerivation function combined with the exfiltration domain in file content.
compile: yarac pass | confidence: high

```yara
rule SupplyChain_Injective_SDK_KeyStealer
{
    meta:
        description = "Detects malicious @injectivelabs/sdk-ts payload containing trackKeyDerivation function and exfiltration domain"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $func1 = "trackKeyDerivation" ascii
        $func2 = "trackKeyDerivation" wide

        $domain1 = "testnet.archival.chain.grpc-web.injective.network" ascii
        $domain2 = "testnet.archival.chain.grpc-web.injective.network" wide

        $telemetry1 = "SDK optimization" ascii nocase
        $telemetry2 = "key derivation" ascii nocase
        $telemetry3 = "timing patterns" ascii nocase

        $key_indicator1 = "mnemonic" ascii
        $key_indicator2 = "privateKey" ascii
        $key_indicator3 = "seed" ascii
        $key_indicator4 = "hex" ascii

    condition:
        filesize < 10MB and
        (
            ($func1 or $func2) and ($domain1 or $domain2)
        ) or
        (
            ($func1 or $func2) and 2 of ($telemetry*) and 2 of ($key_indicator*)
        )
}
```

<!--
AUDIT: YARA rule SupplyChain_Injective_SDK_KeyStealer
- Validation: `yarac rule.yar /dev/null` passed (exit 0).
- Logic: Two detection paths — (1) function name + exfil domain is high-confidence direct match;
  (2) function name + telemetry disguise strings + key material indicators catches variants where
  the domain may have been changed but the function/disguise pattern persists.
- FP note: The second condition path (without domain) could match legitimate telemetry code that
  references key derivation concepts. The requirement for the specific "trackKeyDerivation" function
  name plus 2 telemetry strings plus 2 key indicators constrains this adequately.
- filesize < 10MB prevents scanning very large archives.
-->

### YARA: Injective SDK Package-Level Indicators

Detects compromised @injectivelabs package artifacts by matching package identifiers with malicious version and exfiltration indicators.
compile: yarac pass | confidence: high

```yara
rule SupplyChain_Injective_SDK_Package_Indicators
{
    meta:
        description = "Detects compromised @injectivelabs npm package artifacts by matching package name with malicious version and exfiltration indicators"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pkg_name1 = "@injectivelabs/sdk-ts" ascii
        $pkg_name2 = "@injectivelabs/wallet-base" ascii
        $pkg_name3 = "@injectivelabs/wallet-core" ascii
        $pkg_name4 = "@injectivelabs/wallet-private-key" ascii
        $pkg_name5 = "@injectivelabs/wallet-cosmos" ascii
        $pkg_name6 = "@injectivelabs/wallet-evm" ascii

        $mal_version = "1.20.21" ascii

        $exfil_domain = "testnet.archival.chain.grpc-web.injective.network" ascii
        $func_name = "trackKeyDerivation" ascii

    condition:
        filesize < 10MB and
        any of ($pkg_name*) and
        $mal_version and
        ($exfil_domain or $func_name)
}
```

<!--
AUDIT: YARA rule SupplyChain_Injective_SDK_Package_Indicators
- Validation: `yarac rule.yar /dev/null` passed (exit 0).
- Logic: Requires (1) an @injectivelabs package name AND (2) the malicious version string AND
  (3) either the exfil domain or the malicious function name. This three-factor requirement
  reduces false positives from files that merely reference these packages or version numbers.
- FP note: A changelog or security advisory file that mentions all three indicators could match.
  Acceptable trade-off for scanning npm tarballs and node_modules directories.
-->

### Snort: DNS Query to Injective Labs Exfiltration Domain

Detects DNS queries for the exfiltration domain in wire-format DNS payloads.
compile: structural only | confidence: high

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to Injective Labs Exfiltration Domain"; flow:to_server; content:"|07|testnet|08|archival|05|chain|08|grpc-web|09|injective|07|network|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html; metadata:author Actioner, created 2026-07-12; sid:2100101; rev:1;)
```

<!--
AUDIT: Snort rule sid:2100101 — DNS Query Detection
- Validation: Structural review only (no Snort 3 compiler available). Verified: semicolons terminate
  all options, parentheses balanced, msg/sid/rev present, DNS label-length encoding is correct
  (testnet=7→|07|, archival=8→|08|, chain=5→|05|, grpc-web=8→|08|, injective=9→|09|, network=7→|07|).
- Protocol: udp on port 53 (not dns service) for raw payload content matching of wire-format labels.
- FP assessment: Very low — full domain wire-format match.
-->

### Snort: TLS ClientHello to Injective Labs Exfiltration Domain

Detects TLS handshakes with SNI matching the exfiltration domain.
compile: structural only | confidence: high

```
alert ssl $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS ClientHello to Injective Labs Exfiltration Domain"; flow:established, to_server; ssl_state:client_hello; content:"testnet.archival.chain.grpc-web.injective", fast_pattern; content:".network", distance 0; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html; metadata:author Actioner, created 2026-07-12; sid:2100102; rev:1;)
```

<!--
AUDIT: Snort rule sid:2100102 — TLS SNI Detection
- Validation: Structural review only. Verified: ssl service used with ssl_state keyword, semicolons
  terminate all options, flow/msg/sid/rev present, content split avoids fast_pattern length issues.
- Note: Snort 3 has no tls.sni sticky buffer. This rule gates on ssl_state:client_hello and matches
  the SNI string in the raw ClientHello payload. Domain is NOT defanged.
- FP assessment: Very low — highly specific domain substring match.
-->

### Suricata: DNS Query to Injective Labs Exfiltration Domain

Detects DNS queries for the exfiltration domain using Suricata's dns.query sticky buffer.
compile: suricata -T pass | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Injective Labs Exfiltration Domain"; flow:to_server; dns.query; content:"testnet.archival.chain.grpc-web.injective.network"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html; metadata:author Actioner, created_at 2026-07-12; sid:2100201; rev:1;)
```

<!--
AUDIT: Suricata rule sid:2100201 — DNS Query Detection
- Validation: `suricata -T -S rules.rules -l /tmp` passed (exit 0).
- Protocol: dns with dns.query sticky buffer (dot notation, Suricata-native).
- Encoding: Domain is NOT defanged. nocase handles case variations in DNS queries.
- FP assessment: Very low — exact domain match.
-->

### Suricata: TLS SNI to Injective Labs Exfiltration Domain

Detects TLS connections with SNI matching the exfiltration domain using Suricata's tls.sni sticky buffer.
compile: suricata -T pass | confidence: high

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Injective Labs Exfiltration Domain"; flow:established,to_server; tls.sni; content:"testnet.archival.chain.grpc-web.injective.network"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html; metadata:author Actioner, created_at 2026-07-12; sid:2100202; rev:1;)
```

<!--
AUDIT: Suricata rule sid:2100202 — TLS SNI Detection
- Validation: `suricata -T -S rules.rules -l /tmp` passed (exit 0).
- Protocol: tls with tls.sni sticky buffer (Suricata-native, not available in Snort 3).
- Encoding: Domain is NOT defanged.
- FP assessment: Very low — exact SNI match to exfiltration-specific subdomain.
-->

## Lessons Learned

1. **Trusted-publisher OIDC pipelines are single points of failure.** The OIDC trusted-publisher mechanism eliminates stored npm tokens but concentrates trust in GitHub account security. A single compromised maintainer account bypasses all publication controls. Organizations should enforce branch protection rules, require multiple approvals for releases, and restrict which workflows can trigger publication.

2. **Runtime-activated supply chain malware evades installation-phase scanners.** Traditional npm security tools focus on lifecycle scripts (`preinstall`/`postinstall`). This attack demonstrates that malicious code embedded in library functions --- activated only when specific SDK methods are called --- can bypass these defenses entirely. Detection must extend to runtime behavior analysis and source code diffing between versions.

3. **Infrastructure mimicry in exfiltration domains demands protocol-level detection.** Using a subdomain of the legitimate `injective.network` domain made the exfiltration traffic appear as normal SDK API communication. Domain-reputation blocklists may not catch attacker-controlled subdomains of legitimate parent domains. DNS query monitoring and TLS SNI inspection for specific subdomain patterns are essential complements to reputation-based blocking.

4. **Cryptocurrency supply chain attacks have irreversible impact.** Unlike credential theft for traditional services where passwords can be rotated, stolen cryptocurrency private keys and seed phrases enable immediate, irreversible fund theft. The time window between compromise and detection is the attacker's window for draining all associated wallets.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html) --- primary reporting on the supply chain compromise, technical details of the trackKeyDerivation function, exfiltration mechanism, and affected package list
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/) --- additional technical details including download counts, detection timeline, base64 encoding of exfiltrated data, and HTTP header-based exfiltration method

---
*Report generated by Actioner*
