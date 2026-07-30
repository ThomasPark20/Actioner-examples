# Technical Analysis Report: North Korea-Attributed npm Supply Chain Attack on debug, chalk, and Related Packages (2026-07-30)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-30
Version: 1.0 (DRAFT)

## Executive Summary

Amazon Threat Intelligence has formally attributed a series of npm supply chain compromises to North Korean threat actors tracked as Sapphire Sleet (Microsoft), UNC1069 (Google), and Stardust Chollima (CrowdStrike). The campaign spans from March 2025 to at least March 2026 and has targeted some of the most widely depended-upon npm packages in the JavaScript ecosystem, including **debug**, **chalk**, **axios**, and **Mastra**, as well as the typosquat package **typo-crypto**. These packages collectively receive billions of weekly downloads. In a separate but related incident, two **@joyfill** beta packages were compromised to deliver a remote access trojan (RAT) linked to the PolinRider threat cluster and the DEV#POPPER malware family. The attackers gained access by social-engineering package maintainers into handing over publishing credentials, then injected browser-side wallet-draining scripts (debug/chalk) and stage-two payload loaders (typo-crypto) with C2 infrastructure at `npmjs[.]store` (IP `216[.]74[.]123[.]126`). The Joyfill RAT used a novel blockchain-based command resolution mechanism across Tron, Aptos, and BNB Smart Chain networks, with a boot payload server at `23[.]27[.]13[.]43`.

## Background: npm Ecosystem as Attack Surface

npm (Node Package Manager) is the world's largest software registry, serving millions of JavaScript and TypeScript developers. Packages like `debug` (used by virtually every Node.js application for diagnostic logging) and `chalk` (terminal string styling) are foundational transitive dependencies -- they sit deep in dependency trees and are installed automatically without developer awareness. The `axios` HTTP client alone receives over 100 million weekly downloads. This extreme centrality makes these packages high-value targets: a single compromised version propagates to millions of downstream projects within hours. The September 2025 compromise of debug and chalk represents one of the highest-impact supply chain attacks in npm history by package reach, although the financial damage was limited (approximately $600 in cryptocurrency theft from the wallet-draining scripts).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-03-31 | **typo-crypto@4.3.0** published to npm; Amazon later describes this as a "rehearsal" attack |
| 2025-09 | **debug** and **chalk** packages hijacked via social-engineered maintainer credentials; browser-side wallet-draining interceptors injected |
| 2026-03 | **axios** package compromised; WAVESHAPER.V2 backdoor variant deployed via post-install hooks |
| 2026-05-08 | OSV record MAL-2026-3400 published for typo-crypto, credited to Amazon Inspector (actran@amazon.com) |
| 2026-07 (mid) | Compromised **@joyfill/layouts@0.1.2-2773.beta.0** and **@joyfill/components@4.0.0-rc24-2773-beta.4** discovered delivering a RAT |
| 2026-07-29 | Amazon publicly attributes the debug/chalk/typo-crypto campaign to North Korea's Sapphire Sleet with medium confidence |

## Root Cause: Social Engineering of Package Maintainers

The attackers did not exploit a technical vulnerability in the npm registry itself. Instead, they employed patient social engineering against individual package maintainers. According to reporting from CyberScoop, the threat actors "build a relationship with a maintainer who already had access" and eventually "earned the trust of an employee to hand them the keys" -- i.e., npm publishing credentials or tokens. This is consistent with known North Korean tradecraft in the DEV#POPPER campaign, where DPRK-affiliated actors pose as recruiters, collaborators, or community members to establish trust before requesting access. Phishing using lookalike npm domains was also reported. For the @joyfill packages, the compromise vector remains unclear -- it could involve a developer workstation compromise, source repository access, CI environment compromise, or stolen publishing credentials.

## Technical Analysis of the Malicious Payload

### 1. typo-crypto (Rehearsal Attack -- March 2025)

The `typo-crypto@4.3.0` package was a typosquat designed to impersonate `crypto`-related functionality. The malicious payload was contained in a file named `core.js`, masquerading as the legitimate `core-js` package. Key technical characteristics:

- **Trigger condition:** The payload activated only upon receiving a specific numeric input starting with `0098273`, acting as a gating mechanism to avoid detection in automated scanning
- **Obfuscation:** Base64 encoding layered over XOR encryption using the key `01042025`
- **C2 communication:** Contacted `npmjs[.]store` (`216[.]74[.]123[.]126`) to retrieve stage-two payloads
- **Cross-platform:** Delivered platform-specific payloads for Windows, macOS, and Linux
- **SHA256:** `64edea611ad8e383c09495a7a6f7afd4fb86b88136c331ddf787bf0285259bf3` (per OSV MAL-2026-3400)

### 2. debug and chalk Hijack (September 2025)

The compromise of debug and chalk took a different approach from typo-crypto. Rather than server-side execution, the injected code was a **browser-side interceptor** designed for cryptocurrency theft:

- **Hooking mechanism:** The malicious code hooked `fetch`, `XMLHttpRequest`, and cryptocurrency wallet APIs
- **Payload behavior:** Rewrote cryptocurrency transaction addresses before signing, redirecting funds to attacker-controlled wallets
- **No host persistence:** The wallet-draining scripts did not establish persistence on the victim's machine -- they operated transiently in the browser context
- **Financial impact:** Approximately $600 was stolen through the wallet-rewriting mechanism in September 2025
- **No post-install hooks:** Unlike the axios compromise, debug and chalk did not use npm lifecycle scripts, making detection via install-hook scanning ineffective

### 3. axios and Mastra (March 2026)

The axios compromise deployed the **WAVESHAPER.V2** backdoor and used **post-install hooks** (npm lifecycle scripts) for execution. Microsoft and Google independently attributed this to UNC1069/Sapphire Sleet. Technical details of the WAVESHAPER.V2 payload are pending further public disclosure.

### 4. C2 Infrastructure

**typo-crypto/debug/chalk cluster:**
- **Domain:** `npmjs[.]store` -- a lookalike of the legitimate `npmjs.com` registry domain
- **IP:** `216[.]74[.]123[.]126`
- **Encryption:** XOR cipher with key `01042025`, then Base64 encoded
- **Protocol:** HTTPS for C2 communication and stage-two payload retrieval

**Joyfill RAT cluster:**
- **Boot payload IP:** `23[.]27[.]13[.]43`
- **Command resolution:** Blockchain-based C2 using smart contracts on Tron, Aptos, and BNB Smart Chain networks -- a novel technique that makes takedown significantly harder since blockchain transactions are immutable and decentralized

### 5. @joyfill RAT Capabilities (DEV#POPPER / PolinRider)

The RAT implant delivered via the compromised @joyfill beta packages had the following capabilities:

- **Clipboard exfiltration:** Read clipboard data using platform-specific tools (PowerShell `Get-Clipboard` on Windows, `pbpaste` on macOS, `xclip`/`xsel` on Linux)
- **File upload:** Exfiltrate files to a configured upload host
- **Code execution:** Retrieve and execute additional JavaScript payloads
- **Host reconnaissance:** Collect basic host identification details
- **Status beaconing:** Send periodic check-in messages to C2
- **Credential harvesting:** Targeted Windows Credential Manager, Linux Secret Service, browser credentials, Git configurations, and IDE storage
- **Execution mechanism:** Import-time CommonJS loading (no npm lifecycle hooks), with a secondary detached Node.js process for persistence
- **Build environment:** Published using Node.js 18.20.0 and npm 10.5.0

### 6. Anti-Forensics / Evasion Techniques

- **Trigger gating (typo-crypto):** Malicious behavior only activates on specific input (`0098273`), evading dynamic analysis that does not supply the trigger
- **Base64+XOR obfuscation:** Encoded communications prevent simple string-matching detection
- **Browser-only execution (debug/chalk):** No file-system artifacts on the host machine
- **No lifecycle hooks (debug/chalk):** Avoided the most common npm supply chain detection heuristic
- **Blockchain C2 (Joyfill):** Decentralized command resolution resistant to domain takedowns
- **Import-time loading (Joyfill):** CommonJS require-time execution avoids install-hook scanners
- **Detached process (Joyfill):** Secondary Node.js process runs independently of the parent, surviving process termination

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| typo-crypto | 4.3.0 | Typosquat with XOR+Base64-obfuscated stage-two loader in `core.js` |
| debug | Unknown (Sept 2025 release) | Browser-side wallet-draining interceptor hooking fetch/XHR/wallet APIs |
| chalk | Unknown (Sept 2025 release) | Browser-side wallet-draining interceptor (same payload as debug) |
| axios | Unknown (Mar 2026 release) | WAVESHAPER.V2 backdoor via post-install hooks |
| Mastra | Unknown | Compromised with post-install hooks (details pending) |
| @joyfill/layouts | 0.1.2-2773.beta.0 | RAT implant with clipboard/credential exfiltration |
| @joyfill/components | 4.0.0-rc24-2773-beta.4 | RAT implant with clipboard/credential exfiltration |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | core.js (within typo-crypto package) | 64edea611ad8e383c09495a7a6f7afd4fb86b88136c331ddf787bf0285259bf3 | Malicious loader masquerading as core-js |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | npmjs[.]store | C2 domain for typo-crypto stage-two delivery and debug/chalk infrastructure |
| IP | 216[.]74[.]123[.]126 | C2 IP resolving from npmjs[.]store |
| IP | 23[.]27[.]13[.]43 | Joyfill RAT boot payload server |

### Behavioral

- **typo-crypto:** Outbound HTTPS to `npmjs[.]store` triggered only when a function receives input starting with `0098273`; XOR decryption with key `01042025` applied to C2 responses; OS-specific binary download and execution
- **debug/chalk:** Browser-context hooking of `fetch`, `XMLHttpRequest`, and wallet provider APIs; real-time rewriting of cryptocurrency transaction destination addresses before signing
- **Joyfill RAT:** Import-time CommonJS execution spawning a detached Node.js child process; clipboard reads via platform-native commands (`pbpaste`, `xclip`, `xsel`, `Get-Clipboard`); blockchain smart contract queries to Tron/Aptos/BNB for C2 address resolution; periodic status check-in beacons; credential harvesting from browser stores, Git config, and IDE storage

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Hijacking legitimate npm packages (debug, chalk, axios, Mastra) and publishing typosquats (typo-crypto) to distribute malicious code |
| T1566.002 | Spearphishing Link | Social engineering of maintainers using phishing with lookalike npm domains |
| T1566.003 | Spearphishing via Service | Building trust relationships with maintainers through developer community platforms |
| T1059.007 | JavaScript | Malicious JavaScript executed via npm package import (CommonJS require) and browser-side scripts |
| T1071.001 | Web Protocols | C2 communication over HTTPS to npmjs[.]store |
| T1573.001 | Symmetric Cryptography | XOR encryption (key: 01042025) for C2 payload encoding |
| T1102 | Web Service | Blockchain-based C2 command resolution via Tron/Aptos/BNB smart contracts (Joyfill RAT) |
| T1115 | Clipboard Data | Joyfill RAT reading clipboard via pbpaste/xclip/xsel/Get-Clipboard |
| T1555 | Credentials from Password Stores | Harvesting Windows Credential Manager, Linux Secret Service, browser credentials |
| T1005 | Data from Local System | Collection of Git configurations and IDE storage data |
| T1041 | Exfiltration Over C2 Channel | Exfiltration of collected credentials and clipboard data over the established C2 |
| T1547 | Boot or Logon Autostart Execution | npm lifecycle scripts (post-install hooks) in axios/Mastra compromise |
| T1185 | Browser Session Hijacking | debug/chalk wallet-draining scripts intercepting browser API calls to rewrite transaction data |

## Impact Assessment

**Breadth:** The compromised packages (debug, chalk, axios) collectively have billions of weekly npm downloads. Any developer or CI/CD system that ran `npm install` or `yarn install` during the window of compromise could have received the malicious versions. The @joyfill packages are less widely used (beta versions), but target enterprise document automation workflows.

**Depth:** The debug/chalk wallet-draining scripts had narrow financial impact (~$600). However, the typo-crypto and axios compromises delivered full stage-two payloads capable of arbitrary code execution. The Joyfill RAT had comprehensive credential harvesting capabilities across all three major platforms.

**Stealth:** The attacks employed multiple evasion techniques -- trigger gating, browser-only execution without host artifacts, avoidance of lifecycle hooks (debug/chalk), and blockchain-based C2 (Joyfill) -- making detection through standard supply chain security tooling difficult.

**Attribution confidence:** Amazon assessed medium confidence for North Korea attribution. Microsoft (Sapphire Sleet) and Google (UNC1069) independently corroborated the attribution for the axios compromise.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any compromised package versions are in your lockfiles
grep -r "typo-crypto" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check for Joyfill beta compromised versions
grep -E "@joyfill/layouts.*0\.1\.2-2773\.beta\.0|@joyfill/components.*4\.0\.0-rc24-2773-beta\.4" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Check npm cache for malicious package artifacts
find ~/.npm -name "typo-crypto" -o -name "core.js" 2>/dev/null | xargs grep -l "npmjs.store" 2>/dev/null

# Check DNS logs for C2 domain
grep -i "npmjs.store" /var/log/dns* /var/log/syslog 2>/dev/null

# Check network logs for C2 IPs
grep -E "216\.74\.123\.126|23\.27\.13\.43" /var/log/syslog /var/log/auth.log 2>/dev/null
```

### Remediation

1. **Immediate:** Remove `typo-crypto` from all `package.json`, lockfiles, and `node_modules`. Remove the specific compromised @joyfill versions from lockfiles, caches, mirrors, and deployment artifacts.
2. **Verify debug/chalk/axios versions:** Ensure you are running known-clean versions from after the malicious releases were reverted by npm.
3. **Rotate credentials:** If any compromised packages were installed in developer or CI environments, rotate all credentials accessible from those environments -- including npm tokens, Git credentials, browser-stored passwords, API keys in IDE storage, and cryptocurrency wallet keys.
4. **Audit CI/CD pipelines:** Review build logs for network connections to `npmjs[.]store` or `216[.]74[.]123[.]126` during the compromise window.
5. **Block C2 infrastructure:** Add `npmjs[.]store`, `216.74.123.126`, and `23.27.13.43` to network blocklists (firewalls, DNS sinkhole, proxy deny lists).

### Long-Term Hardening

- **Enable npm provenance and Sigstore verification** to validate package integrity against the source repository.
- **Use lockfile-only installs** (`npm ci` / `yarn --frozen-lockfile`) in CI/CD to prevent unexpected version resolution.
- **Pin dependencies** to exact versions and review all version bumps before merging.
- **Deploy Software Composition Analysis (SCA)** tools (Socket, Snyk, npm audit) that detect anomalous package behavior beyond known CVEs.
- **Monitor for npm account compromise indicators** -- unexpected version publishes, new maintainers added to critical packages, and metadata changes.
- **Enforce multi-factor authentication** on all npm publishing accounts, especially for packages with high downstream dependency counts.
- **Consider using package registries with malware scanning** (e.g., Artifactory, Cloudsmith) as a proxy layer.

## Detection Rules

These detections target the confirmed C2 infrastructure (npmjs[.]store / 216[.]74[.]123[.]126 / 23[.]27[.]13[.]43), malicious package artifacts, and behavioral patterns (clipboard exfiltration via Node.js) from this campaign. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; compiles != fires -- verify in your pipeline before production deployment.

### Sigma: DNS Query to typo-crypto C2 Domain npmjs.store

Detects DNS resolution of `npmjs[.]store`, the C2 domain used by the malicious typo-crypto npm package and associated debug/chalk infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403 in sandboxed env); splunk convert exit 0; log_scale convert exit 0. Domain is highly distinctive with no legitimate use. -->
```yaml
title: DNS Query to typo-crypto C2 Domain npmjs.store
id: 7f3a1b4e-2c8d-4e9f-a6b5-1d0e3f7c8a9b
status: experimental
description: >
    Detects DNS queries to npmjs.store, the known C2 domain used by the
    malicious typo-crypto npm package attributed to North Korean threat actors
    (Sapphire Sleet). The domain was used to retrieve stage-two payloads.
references:
    - https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html
    - https://cyberscoop.com/amazon-north-korea-open-source-software-attacks/
    - https://osv.dev/vulnerability/MAL-2026-3400
author: Actioner
date: 2026/07/30
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'npmjs.store'
    condition: selection
falsepositives:
    - Unlikely - this domain has no legitimate use
level: high
```

### Sigma: Network Connection to typo-crypto C2 IP 216.74.123.126

Detects outbound connections to the typo-crypto stage-two payload delivery IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403); splunk convert exit 0; log_scale convert exit 0. IP is confirmed malicious infrastructure per Amazon/OSV. -->
```yaml
title: Network Connection to typo-crypto C2 IP 216.74.123.126
id: 8e2b4c5d-3f9a-4d1e-b7c6-2a0f5e8d9b4c
status: experimental
description: >
    Detects outbound network connections to 216.74.123.126, the C2 IP used by
    the malicious typo-crypto npm package for stage-two payload delivery.
    Attributed to North Korean Sapphire Sleet threat actor.
references:
    - https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html
    - https://cyberscoop.com/amazon-north-korea-open-source-software-attacks/
author: Actioner
date: 2026/07/30
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '216.74.123.126'
    condition: selection
falsepositives:
    - Unlikely - this IP is associated with confirmed malicious infrastructure
level: high
```

### Sigma: Network Connection to Joyfill RAT C2 IP 23.27.13.43

Detects outbound connections to the Joyfill RAT boot payload server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403); splunk convert exit 0; log_scale convert exit 0. IP confirmed as Joyfill RAT C2 per THN reporting. -->
```yaml
title: Network Connection to Joyfill RAT C2 IP 23.27.13.43
id: 9d1c3e6f-4a8b-5c2d-e0f7-3b1a6d9e8c5f
status: experimental
description: >
    Detects outbound network connections to 23.27.13.43, the C2 IP used by the
    compromised @joyfill npm packages to retrieve boot payloads. The RAT is
    linked to the PolinRider/DEV#POPPER threat cluster.
references:
    - https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
author: Actioner
date: 2026/07/30
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '23.27.13.43'
    condition: selection
falsepositives:
    - Unlikely - this IP is associated with confirmed malicious infrastructure
level: high
```

### Sigma: Clipboard Data Access via Node.js Child Process (Joyfill RAT Pattern)

Detects Node.js spawning platform-specific clipboard-reading utilities, consistent with the Joyfill RAT's cross-platform clipboard exfiltration.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by MITRE ATT&CK data fetch (403); splunk convert exit 0; log_scale convert exit 0. Behavioral rule -- legitimate Node.js clipboard libraries (e.g. clipboardy) use the same utilities, so medium confidence. -->
```yaml
title: Clipboard Data Access via Node.js Child Process (Joyfill RAT Pattern)
id: a0e2d4f5-5b9c-6d3e-f1a8-4c2b7e0f9d6a
status: experimental
description: >
    Detects Node.js spawning clipboard-reading utilities (pbpaste, xclip, xsel,
    or PowerShell Get-Clipboard), consistent with the Joyfill RAT's clipboard
    exfiltration behavior observed in the DEV#POPPER campaign.
references:
    - https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
author: Actioner
date: 2026/07/30
tags:
    - attack.t1115
    - attack.t1059.007
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '\node.exe'
    selection_clipboard:
        CommandLine|contains:
            - 'pbpaste'
            - 'xclip'
            - 'xsel'
            - 'Get-Clipboard'
    condition: selection_parent and selection_clipboard
falsepositives:
    - Legitimate Node.js applications that access clipboard programmatically
level: medium
```

### Snort: DNS Query to typo-crypto C2 Domain npmjs.store

Detects DNS queries for `npmjs[.]store` via DNS label-length encoding in UDP packets to port 53.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (rules loaded via local.rules). Label-length encoding |05|npmjs|05|store|00| matches the DNS wire format. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to typo-crypto C2 Domain npmjs.store"; content:"|05|npmjs|05|store|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html; sid:2100001; rev:1;)
```

### Snort: Connection to typo-crypto C2 IP 216.74.123.126

Detects any TCP connection to the confirmed typo-crypto C2 IP address.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0. IP-only rule, minimal FP risk for confirmed malicious infrastructure. -->
```snort
alert tcp $HOME_NET any -> 216.74.123.126 any (msg:"Actioner - Connection to typo-crypto C2 IP 216.74.123.126"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html; sid:2100002; rev:1;)
```

### Snort: Connection to Joyfill RAT C2 IP 23.27.13.43

Detects any TCP connection to the confirmed Joyfill RAT boot payload server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0. IP-only rule, confirmed malicious infrastructure. -->
```snort
alert tcp $HOME_NET any -> 23.27.13.43 any (msg:"Actioner - Connection to Joyfill RAT C2 IP 23.27.13.43"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html; sid:2100003; rev:1;)
```

### Suricata: DNS Query to typo-crypto C2 Domain npmjs.store

Detects DNS queries for `npmjs[.]store` using Suricata's native `dns.query` sticky buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Uses dot-notation dns.query buffer; domain is highly distinctive. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to typo-crypto C2 Domain npmjs.store"; flow:to_server; dns.query; content:"npmjs.store"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html; metadata:author Actioner, created_at 2026-07-30; sid:2200001; rev:1;)
```

### Suricata: Connection to typo-crypto C2 IP 216.74.123.126

Detects TCP connections to the confirmed typo-crypto C2 IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Confirmed malicious IP; no FP risk. -->
```suricata
alert tcp $HOME_NET any -> 216.74.123.126 any (msg:"Actioner - Connection to typo-crypto C2 IP 216.74.123.126"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html; metadata:author Actioner, created_at 2026-07-30; sid:2200002; rev:1;)
```

### Suricata: Connection to Joyfill RAT C2 IP 23.27.13.43

Detects TCP connections to the confirmed Joyfill RAT boot payload server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Confirmed malicious IP per THN reporting. -->
```suricata
alert tcp $HOME_NET any -> 23.27.13.43 any (msg:"Actioner - Connection to Joyfill RAT C2 IP 23.27.13.43"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html; metadata:author Actioner, created_at 2026-07-30; sid:2200003; rev:1;)
```

### YARA: Malicious typo-crypto npm Package

Detects the malicious typo-crypto package artifacts by matching the C2 domain `npmjs.store` combined with the XOR key, trigger value, or file/package names.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on pos-typo-crypto.txt (contains published strings npmjs.store + 01042025 + 0098273), quiet on neg-typo-crypto.txt (clean crypto module). Hash 64edea611ad8e383c09495a7a6f7afd4fb86b88136c331ddf787bf0285259bf3 from OSV MAL-2026-3400. -->
```yara
rule NPM_NK_Typo_Crypto_Malicious_Package
{
    meta:
        description = "Detects the malicious typo-crypto npm package (core.js payload) used by North Korean Sapphire Sleet for stage-two delivery via npmjs.store C2"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html"
        hash = "64edea611ad8e383c09495a7a6f7afd4fb86b88136c331ddf787bf0285259bf3"
        severity = "high"

    strings:
        $c2_domain = "npmjs.store" ascii wide
        $xor_key = "01042025" ascii wide
        $trigger = "0098273" ascii wide
        $core_js = "core.js" ascii
        $pkg_name = "typo-crypto" ascii

    condition:
        filesize < 1MB and
        $c2_domain and
        (2 of ($xor_key, $trigger, $core_js, $pkg_name))
}
```

### YARA: debug/chalk Wallet-Draining Interceptor

Detects the browser-side wallet-draining code injected into compromised debug/chalk packages, keyed on the C2 domain combined with fetch/XHR/wallet API hooking patterns.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Medium confidence because individual strings (fetch, XMLHttpRequest, wallet) are common in legitimate JS; the npmjs.store anchor raises specificity. No published sample hash available for debug/chalk malicious versions. -->
```yara
rule NPM_NK_Debug_Chalk_Wallet_Drainer
{
    meta:
        description = "Detects browser-side wallet-draining interceptor injected into compromised debug/chalk npm packages, hooking fetch/XMLHttpRequest and wallet APIs"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html"
        severity = "high"

    strings:
        $hook_fetch = "fetch" ascii
        $hook_xhr = "XMLHttpRequest" ascii
        $wallet_api = "wallet" ascii nocase
        $rewrite_addr = "transaction" ascii nocase
        $signing = "signing" ascii nocase
        $npmjs_store = "npmjs.store" ascii

    condition:
        filesize < 5MB and
        $npmjs_store and
        2 of ($hook_fetch, $hook_xhr, $wallet_api, $rewrite_addr, $signing)
}
```

### YARA: Joyfill RAT Implant (DEV#POPPER / PolinRider)

Detects the cross-platform RAT implant from compromised @joyfill packages, keyed on the combination of multi-platform clipboard access utilities and C2/exfiltration patterns.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Clipboard utility names are legitimate but their co-presence in a single JS file with upload/check-in/joyfill references is distinctive. No published sample hash for Joyfill RAT. -->
```yara
rule NPM_NK_Joyfill_RAT_Implant
{
    meta:
        description = "Detects the RAT implant delivered via compromised @joyfill npm packages, linked to PolinRider/DEV#POPPER cluster"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
        severity = "high"

    strings:
        $clip_win = "Get-Clipboard" ascii wide
        $clip_mac = "pbpaste" ascii
        $clip_linux1 = "xclip" ascii
        $clip_linux2 = "xsel" ascii
        $upload = "upload" ascii nocase
        $checkin = "check-in" ascii nocase
        $joyfill = "joyfill" ascii nocase

    condition:
        filesize < 5MB and
        (2 of ($clip_win, $clip_mac, $clip_linux1, $clip_linux2)) and
        1 of ($upload, $checkin, $joyfill)
}
```

## Lessons Learned

1. **Social engineering remains the weakest link in supply chain security.** Despite npm's support for MFA and token-based publishing, the attackers bypassed technical controls by building personal trust with maintainers. The open-source ecosystem's reliance on volunteer maintainers creates inherent vulnerability to long-con social engineering.

2. **Transitive dependency depth amplifies blast radius.** Packages like debug and chalk are so deeply embedded in the npm dependency graph that their compromise silently propagates to millions of applications. Organizations need visibility not just into their direct dependencies, but into the full transitive dependency tree.

3. **Detection tooling must evolve beyond lifecycle hooks.** The debug/chalk compromise deliberately avoided `postinstall` scripts, bypassing the primary detection heuristic used by most supply chain security scanners. Behavioral analysis of package code (not just metadata) is essential.

4. **Blockchain-based C2 is an emerging resilience technique.** The Joyfill RAT's use of Tron/Aptos/BNB smart contracts for command resolution represents a hardening of C2 infrastructure that makes traditional domain/IP takedowns insufficient.

5. **Nation-state actors are investing in ecosystem-scale supply chain attacks.** The progression from typo-crypto (rehearsal) to debug/chalk (mainstream packages) to axios (100M+ weekly downloads) shows deliberate capability development and escalation by DPRK-affiliated actors.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [The Hacker News - Amazon Links Debug and Chalk npm Hijack to North Korea](https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html) -- Primary reporting on Amazon's attribution of the debug/chalk/typo-crypto campaign to Sapphire Sleet; technical details on payload types, C2 domain, XOR key, and timeline
- [CyberScoop - Amazon North Korea Open Source Software Attacks](https://cyberscoop.com/amazon-north-korea-open-source-software-attacks/) -- Social engineering methodology details; maintainer trust exploitation; attribution to UNC1069/Sapphire Sleet/Stardust Chollima; quote on "rehearsal" characterization of typo-crypto
- [GBHackers - North Korean Compromise npm Packages](https://gbhackers.com/north-korean-compromise-npm-packages/) -- Additional coverage of the npm compromise campaign (content unavailable at time of fetch)
- [The Hacker News - Two Compromised Joyfill npm Packages](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html) -- Technical analysis of the @joyfill RAT implant; C2 IP, blockchain C2 mechanism, clipboard exfiltration details, PolinRider/DEV#POPPER attribution
- [OSV - MAL-2026-3400 (typo-crypto)](https://osv.dev/vulnerability/MAL-2026-3400) -- Formal vulnerability advisory for typo-crypto@4.3.0; SHA256 hash; Amazon Inspector detection credit

---
*Report generated by Actioner*
