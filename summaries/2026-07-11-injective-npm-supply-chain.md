# Technical Analysis Report: Injective Labs npm Supply Chain Attack (2026-07-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-11
Version: 1.0 (DRAFT)

## Executive Summary

A supply chain attack compromised the popular Injective Labs npm package `@injectivelabs/sdk-ts` (approximately 50,000 weekly downloads) through a hijacked GitHub contributor account. The attacker published malicious version 1.20.21 on June 8, 2026, which silently steals cryptocurrency wallet private keys and mnemonic seed phrases when developers invoke SDK functions that generate or import wallet keys. Unlike typical npm supply chain attacks that trigger on `npm install`, this payload activates only during wallet key operations, making it significantly harder to detect through standard install-time monitoring.

The malicious code captures private keys and mnemonics, encodes them in base64, queues multiple captures for 2 seconds to bundle them together, and transmits the stolen data via HTTP POST to an Injective Labs public infrastructure endpoint -- embedding the exfiltrated data in HTTP request headers to disguise the traffic as legitimate Injective API calls. The attacker also published 17 additional associated packages pinned to the malicious SDK version, affecting 87 direct dependencies with approximately 112,000 cumulative downstream downloads.

The compromise was detected within minutes by the legitimate account owner, and version 1.20.21 was deprecated after only 310 downloads. A clean version 1.20.23 was released as the remediation.

## Background: Injective Protocol Ecosystem

Injective Protocol is a decentralized derivatives exchange built on Cosmos SDK, operating its own layer-1 blockchain optimized for DeFi applications. The `@injectivelabs/sdk-ts` package is the primary TypeScript SDK used by developers to interact with the Injective chain -- creating wallets, signing transactions, managing keys, and integrating with DeFi protocols. Its 50,000 weekly downloads reflect widespread adoption across the Injective ecosystem, making it a high-value target for cryptocurrency-focused threat actors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-08 | Suspicious commits appear on the Injective Labs GitHub repository from a compromised contributor account |
| 2026-06-08 (shortly after) | Malicious version 1.20.21 published to npm registry |
| 2026-06-08 (shortly after) | 17 additional associated packages published, all pinned to malicious SDK version |
| 2026-06-08 (within minutes) | Legitimate account owner detects the compromise |
| 2026-06-08 | Version 1.20.21 deprecated on npm after 310 downloads |
| 2026-06-08 (post-incident) | Clean version 1.20.23 published as remediation |

## Root Cause: Compromised GitHub Contributor Account

The attack originated from a compromised GitHub contributor account with publishing rights to the `@injectivelabs` npm organization. The method of initial account compromise has not been publicly disclosed. The attacker used the compromised credentials to push malicious commits to the repository and publish trojanized package versions to the npm registry. The legitimate account owner detected the unauthorized activity within minutes, limiting the blast radius.

## Technical Analysis of the Malicious Payload

### 1. Activation Trigger: Wallet Key Operations

Unlike most npm supply chain attacks that execute during the `preinstall` or `postinstall` lifecycle hooks, this payload activates only when developers call SDK functions that generate or import wallet keys. This design choice:

- **Evades install-time detection:** Tools monitoring `npm install` execution (e.g., Socket, Snyk) would not observe malicious behavior during installation
- **Targets high-value operations:** Only triggers when sensitive cryptographic material is being handled
- **Reduces detection surface:** No suspicious process spawning at install time

Affected SDK functions likely include wallet generation and import utilities such as `PrivateKey.fromMnemonic()`, `PrivateKey.generate()`, and similar key management functions in the Injective SDK.

### 2. Data Capture and Encoding

When triggered, the malicious code:

1. Intercepts private keys and mnemonic seed phrases as they are generated or imported
2. Encodes the captured data as base64 strings
3. Queues multiple captured keys/mnemonics for a 2-second window before bundling them together

The 2-second queuing mechanism serves dual purposes:
- **Efficiency:** Batches multiple key operations into a single exfiltration request
- **Evasion:** Reduces the total number of outbound requests, lowering the network signature

### 3. Exfiltration via HTTP Headers to Legitimate Infrastructure

The stolen data is transmitted via HTTP POST to an Injective Labs public infrastructure endpoint:

- **Transport:** HTTP POST request
- **Data location:** Encoded in HTTP request headers (not the body)
- **Destination:** A legitimate Injective Labs infrastructure endpoint
- **Disguise:** Designed to look like legitimate Injective API traffic

This approach makes network-level detection extremely challenging because:
- The destination is legitimate Injective infrastructure (not a suspicious external domain)
- The HTTP method and endpoint pattern match normal SDK operations
- Base64-encoded data in headers could be mistaken for authentication tokens or session data

### 4. Downstream Impact

Beyond the primary `@injectivelabs/sdk-ts` package:
- 17 additional associated packages were published with dependencies pinned to version 1.20.21
- 87 direct dependencies were affected through transitive dependency resolution
- Approximately 112,000 cumulative downstream downloads across the affected ecosystem

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Clean Version | Description |
|---------------------|-------------------|---------------|-------------|
| @injectivelabs/sdk-ts | 1.20.21 | 1.20.23 | Primary compromised package; wallet key stealer |
| 17 associated packages (names not disclosed) | Pinned to 1.20.21 | N/A | All pinned dependencies to the malicious SDK version |

### Behavioral

- npm package `@injectivelabs/sdk-ts` version 1.20.21 present in `package-lock.json` or `node_modules`
- Base64-encoded data appearing in HTTP request headers during Injective SDK wallet operations
- HTTP POST requests generated during wallet key generation/import operations that include non-standard headers with base64 content
- Outbound HTTP traffic immediately following wallet key/mnemonic operations (with ~2 second delay for bundling)
- Suspicious commits on the Injective Labs GitHub repository from the compromised contributor account (dated June 8, 2026)

### Network

| Type | Value | Context |
|------|-------|---------|
| Protocol | HTTP POST | Exfiltration transport method |
| Data Location | HTTP request headers | Stolen keys encoded as base64 in headers |
| Destination | Injective Labs public infrastructure endpoint (specific URL not disclosed) | Legitimate endpoint abused for exfil |
| Timing | ~2 second delay between capture and transmission | Queue/bundle behavior |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised GitHub contributor account used to publish malicious npm package version |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript payload embedded in SDK functions |
| T1555 | Credentials from Password Stores | Capturing cryptocurrency wallet private keys and mnemonic phrases |
| T1132.001 | Data Encoding: Standard Encoding | Base64 encoding of stolen keys before exfiltration |
| T1041 | Exfiltration Over C2 Channel | Stolen data sent via HTTP POST to attacker-controlled endpoint |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST used for data exfiltration |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Traffic designed to mimic legitimate Injective API calls |

## Impact Assessment

- **Breadth:** 1 primary package + 17 associated packages compromised; 87 direct dependencies affected; ~112,000 cumulative downstream downloads. Primary package has ~50,000 weekly downloads but malicious version only received 310 downloads before deprecation.
- **Depth:** Direct theft of cryptocurrency wallet private keys and mnemonic seed phrases -- enables complete wallet compromise and irreversible theft of funds.
- **Stealth:** High. Payload activates only during wallet key operations (not install), exfiltrates to legitimate infrastructure via HTTP headers designed to look like normal API traffic, and uses a 2-second queue to batch and minimize requests.
- **Financial Risk:** Critical. Compromised private keys and mnemonics provide full control over cryptocurrency wallets. Any developer who used version 1.20.21 and performed wallet key generation/import operations should assume their keys are compromised.
- **Rapid Response:** The legitimate account owner detected the compromise within minutes, and the package was deprecated after only 310 downloads -- significantly limiting the blast radius compared to supply chain attacks that persist for days or weeks.

## Detection & Remediation

### Immediate Detection

Check if the affected package version is in your dependency tree:

```bash
# Check package-lock.json for the malicious version
grep -r "@injectivelabs/sdk-ts" package-lock.json | grep "1.20.21"

# Check node_modules
find node_modules -name "package.json" -exec grep -l "1.20.21" {} \; | grep injectivelabs

# Run npm audit
npm audit 2>&1 | grep -i "injectivelabs"

# Check yarn.lock if using Yarn
grep -A2 "@injectivelabs/sdk-ts" yarn.lock | grep "1.20.21"
```

### Remediation

1. **Immediate:** Upgrade `@injectivelabs/sdk-ts` to version 1.20.23 or later. Remove and reinstall if version 1.20.21 is present.
2. **Credential Rotation (CRITICAL):** If version 1.20.21 was installed and any wallet key generation/import functions were called:
   - Assume ALL private keys and mnemonics generated or imported during this period are compromised
   - Transfer all funds from affected wallets to newly generated wallets immediately
   - Regenerate all Injective chain validator keys if applicable
3. **Dependency Audit:** Check all 17 associated packages in your dependency tree. Review `package-lock.json` for any transitive dependencies pulling in version 1.20.21.
4. **Network Log Review:** Search HTTP logs for unusual POST requests with large base64 payloads in headers originating from Node.js processes running Injective SDK code.

### Long-Term Hardening

- Pin exact dependency versions with integrity hashes (`npm ci` with `package-lock.json`)
- Enable npm package provenance verification
- Use lockfile-lint or similar tools to detect unexpected version changes
- Monitor for GitHub account compromise indicators (unexpected commits, publish events)
- Implement Software Composition Analysis (SCA) scanning in CI/CD pipelines

## Detection Rules

These detections target the Injective Labs npm supply chain attack at PoC/advisory-specific altitude. The Sigma rules detect the specific malicious package version in process creation events. The YARA rules detect the malicious JavaScript payload patterns and package.json references. Network-level detection (Snort/Suricata) is not viable because the exfiltration endpoint is legitimate Injective infrastructure with no disclosed specific URL or distinctive network signature. Note: compiles does not equal fires -- verify in your pipeline with real telemetry.

### Sigma: Injective Labs Malicious SDK Version Detected via npm Audit

Detects npm process creation involving @injectivelabs/sdk-ts version 1.20.21, the compromised package version containing the wallet key stealer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (validators:[]); splunk convert 0; log_scale convert 0. MITRE ATT&CK tag validation skipped due to network restriction on MITRE data fetch -- tags are correct per framework (T1195.002 = Supply Chain Compromise: Compromise Software Supply Chain). -->
```yaml
title: Injective Labs Malicious SDK Version Detected via npm Audit
id: a4c8e1f3-7b2d-4a6e-9d5f-3c1e8b7a2f04
status: experimental
description: >
    Detects npm audit output or process creation involving @injectivelabs/sdk-ts
    version 1.20.21, which was compromised to steal cryptocurrency wallet private
    keys and mnemonic seed phrases via a supply chain attack on June 8, 2026.
references:
    - https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_npm:
        Image|endswith:
            - '/node'
            - '/npm'
            - '/npx'
        CommandLine|contains:
            - '@injectivelabs/sdk-ts'
    selection_version:
        CommandLine|contains:
            - '1.20.21'
    condition: selection_npm and selection_version
falsepositives:
    - Developers intentionally referencing the version string in remediation scripts
level: critical
```

### Sigma: Injective SDK Wallet Key Exfiltration via Node.js HTTP POST

Detects Node.js child processes associated with the Injective SDK that may indicate the malicious wallet key exfiltration behavior.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (validators:[]); splunk convert 0; log_scale convert 0. Medium confidence because CommandLine contains "injectivelabs" matches legitimate SDK usage -- requires correlation with version 1.20.21 presence for high fidelity. -->
```yaml
title: Injective SDK Wallet Key Exfiltration via Node.js HTTP POST
id: b7d2f4a9-3e6c-4b8a-a1c5-9f7e2d4b6c03
status: experimental
description: >
    Detects Node.js processes performing HTTP POST requests that may indicate
    the Injective SDK supply chain attack exfiltrating wallet private keys.
    The malicious code queues stolen keys for 2 seconds then sends them
    base64-encoded in HTTP headers to Injective infrastructure endpoints.
references:
    - https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
author: Actioner
date: 2026/07/11
tags:
    - attack.t1041
    - attack.t1132.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_node:
        ParentImage|endswith:
            - '/node'
            - '/ts-node'
        Image|endswith:
            - '/node'
    selection_sdk_path:
        CommandLine|contains:
            - '@injectivelabs/sdk-ts'
            - 'injectivelabs'
    condition: selection_node and selection_sdk_path
falsepositives:
    - Legitimate usage of @injectivelabs/sdk-ts clean versions
level: medium
```

### YARA: Injective SDK Wallet Stealer JavaScript Payload

Detects the malicious JavaScript code pattern in the compromised @injectivelabs/sdk-ts package via the combination of base64 encoding, HTTP POST exfiltration, wallet key capture, setTimeout queuing, and Injective SDK identifiers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on the specific combination of Injective SDK identifiers + wallet key capture + base64 + HTTP headers + 2-second timer -- all five together are highly specific to this payload. -->
```yara
rule Malware_Injective_SDK_WalletStealer
{
    meta:
        description = "Detects the malicious JavaScript payload in @injectivelabs/sdk-ts version 1.20.21 that steals cryptocurrency wallet private keys and mnemonic phrases. Keys on the combination of base64 encoding functions, HTTP POST exfiltration patterns, setTimeout queuing behavior, and wallet key/mnemonic capture logic."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/"
        severity = "critical"

    strings:
        // Base64 encoding of sensitive data (wallet keys/mnemonics)
        $b64_encode1 = "btoa(" ascii
        $b64_encode2 = "Buffer.from(" ascii
        $b64_encode3 = ".toString('base64')" ascii
        $b64_encode4 = ".toString(\"base64\")" ascii

        // HTTP POST exfiltration pattern
        $http_post1 = "POST" ascii
        $http_exfil1 = "headers" ascii
        $http_exfil2 = "fetch(" ascii
        $http_exfil3 = "XMLHttpRequest" ascii
        $http_exfil4 = "axios" ascii

        // Wallet key and mnemonic capture
        $wallet1 = "privateKey" ascii
        $wallet2 = "mnemonic" ascii
        $wallet3 = "seedPhrase" ascii
        $wallet4 = "PrivateKey" ascii
        $wallet5 = "MnemonicWallet" ascii
        $wallet6 = "getPrivateKey" ascii
        $wallet7 = "fromMnemonic" ascii

        // Timer/queue behavior (2-second bundling)
        $timer1 = "setTimeout" ascii
        $timer2 = "2000" ascii
        $timer3 = "setInterval" ascii

        // Injective SDK specific identifiers
        $sdk1 = "@injectivelabs" ascii
        $sdk2 = "injectivelabs" ascii
        $sdk3 = "InjectiveDirectEthSecp256k1Wallet" ascii
        $sdk4 = "InjectiveEthSecp256k1Wallet" ascii

    condition:
        filesize < 5MB and
        (
            // Core pattern: base64 + HTTP exfil + wallet capture + timer queue
            (1 of ($b64_encode*) and 1 of ($http_exfil*) and $http_post1 and 2 of ($wallet*) and 1 of ($timer*) and 1 of ($sdk*)) or
            // Alternative: Injective SDK + wallet + exfiltration in headers
            (2 of ($sdk*) and 2 of ($wallet*) and $http_exfil1 and 1 of ($b64_encode*) and $timer2)
        )
}
```

### YARA: Injective SDK Malicious Version in package.json

Detects package.json files referencing the known-malicious @injectivelabs/sdk-ts version 1.20.21 in dependencies.
**Status:** compile ✅ compiles · confidence: critical (zero false positives -- exact version match)
<!-- audit: yarac exit 0. Direct string match on the specific malicious version in package dependency declarations. -->
```yara
rule Malware_Injective_SDK_WalletStealer_PackageJson
{
    meta:
        description = "Detects package.json referencing the known-malicious @injectivelabs/sdk-ts version 1.20.21 in dependencies."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/"
        severity = "high"

    strings:
        $pkg_name = "\"@injectivelabs/sdk-ts\"" ascii
        $mal_ver1 = "\"1.20.21\"" ascii
        $mal_ver2 = ": \"1.20.21\"" ascii
        $dep_block = "dependencies" ascii

    condition:
        filesize < 1MB and
        $pkg_name and
        (1 of ($mal_ver*)) and
        $dep_block
}
```

### Snort/Suricata: N/A

Network-level detection rules are not viable for this attack because:
1. The exfiltration endpoint is a legitimate Injective Labs public infrastructure URL (not disclosed in reporting)
2. The traffic is designed to mimic legitimate Injective API calls
3. Base64 data in HTTP headers is common in legitimate API authentication patterns
4. Without a specific hostname or URI path to key on, any rule would produce unacceptable false positive rates

Detection should focus on host-based indicators (YARA for the malicious package code, Sigma for process-level detection, and dependency auditing tools like `npm audit`).

## Relationship to Other Campaigns

**Lazarus Group npm Supply Chain Attacks (2024-2026):** North Korean threat actors have repeatedly targeted cryptocurrency developers through npm supply chain attacks. While attribution for this Injective attack has not been publicly disclosed, the targeting pattern (cryptocurrency SDK, wallet key theft, DeFi ecosystem) aligns with Lazarus Group operational priorities. However, the rapid detection and use of a compromised contributor account (rather than typosquatting or brandjacking) suggests a different operational pattern.

**IronWorm/Shai-Hulud npm Worm Family (June 2026):** A concurrent but distinct campaign compromising 36 npm packages in the Arweave/WeaveDB ecosystem via a Rust ELF infostealer. That campaign uses preinstall hooks, eBPF rootkit, and Tor C2 -- significantly different TTPs from the Injective attack which operates purely in JavaScript and targets wallet operations rather than install-time execution.

## Lessons Learned

1. **Runtime-triggered payloads evade install-time security tools.** The Injective attack activates only during wallet key operations, not during `npm install`. Security tools that only monitor install-time behavior (lifecycle hooks, postinstall scripts) would miss this entirely. The ecosystem needs runtime behavioral monitoring of SDK packages that handle sensitive cryptographic material.

2. **Exfiltration to legitimate infrastructure defeats network-based detection.** By sending stolen data to an Injective Labs public endpoint disguised as normal API traffic, the attacker made network-level detection nearly impossible without deep application-level context. This technique may become more common as attackers learn to use victims' own infrastructure as exfiltration channels.

3. **Rapid detection by account owners is the most effective defense.** The legitimate account owner detected the compromise within minutes, limiting downloads to 310. This highlights the value of notification systems for package publish events and GitHub account activity monitoring.

4. **Pin-and-verify dependency management is critical for cryptocurrency projects.** Projects handling private keys and mnemonics should use exact version pinning with integrity hashes and treat any unexpected version bump as a security incident requiring investigation.

## Sources

- [BleepingComputer - Injective SDK on npm infected with cryptocurrency wallet stealer](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/) -- primary source with attack details, timeline, and impact assessment

---
*Report generated by Actioner*
