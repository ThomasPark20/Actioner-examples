# Technical Analysis Report: Jscrambler 8.14.0 NPM Supply Chain Compromise (2026-07-13)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-13
Version: 1.0

## Executive Summary

The jscrambler npm package (15,800+ weekly downloads), a legitimate JavaScript code obfuscation tool, was compromised on July 11, 2026 when an attacker used stolen npm publishing credentials to publish version 8.14.0 containing a malicious preinstall hook. The hook deployed "IronWorm," a cross-platform Rust-based infostealer binary targeting Windows, macOS, and Linux. Additional compromised versions (8.16.0, 8.17.0, 8.18.0, 8.20.0) followed, with later versions embedding the malicious payload directly in the package code and CLI to bypass npm's `--ignore-scripts` protection. The malware exfiltrates cloud credentials (AWS, Azure, GCP), browser passwords, cryptocurrency wallets, password manager vaults, AI tool configurations, and npm/GitHub tokens. It includes a self-propagation routine that hunts npm tokens and attempts to inject malicious preinstall scripts into other high-download packages. Socket detected the initial compromise within six minutes of publication.

## Background: Jscrambler NPM Package

Jscrambler is a widely-used commercial JavaScript protection and code obfuscation tool distributed via npm. With over 15,800 weekly downloads, it is integrated into many CI/CD pipelines and developer workflows. Its legitimate use in build processes means installations often run with elevated privileges and access to sensitive tokens and credentials, making it a high-value supply chain target. The compromise coincided with npm 12's release on July 8, 2026, which disabled install scripts by default -- the attacker adapted by embedding payload delivery in the main package code in later versions.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-08 | npm 12 released with install scripts disabled by default |
| 2026-07-11 | Malicious jscrambler 8.14.0 published to npm; detected by Socket within six minutes |
| 2026-07-11 | Additional compromised versions 8.16.0, 8.17.0 published with same preinstall hook mechanism |
| 2026-07-11 (later) | Versions 8.18.0, 8.20.0 released with payload embedded in main package code and CLI (bypasses --ignore-scripts) |
| 2026-07-11+ | Clean version 8.15.0 confirmed unaffected (published between initial malicious releases) |
| 2026-07-11+ | Jscrambler revoked publishing credentials and hardened pipeline; clean version 8.22.0 published |

## Root Cause: Stolen NPM Publishing Credential

Jscrambler confirmed the compromise vector was a stolen npm publishing credential. The attacker used the compromised credential to publish multiple malicious versions in rapid succession, progressively adapting the delivery mechanism from preinstall hooks (versions 8.14.0, 8.16.0, 8.17.0) to embedded execution (versions 8.18.0, 8.20.0) to circumvent npm 12's default script-disabling behavior.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Preinstall Hook

The initial compromised versions (8.14.0, 8.16.0, 8.17.0) used npm's `preinstall` lifecycle hook to execute malicious JavaScript. The dropper consisted of two modified files in the `dist/` directory:
- `dist/setup.js` (SHA-256: `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`)
- `dist/intro.js` (SHA-256: `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`)

These scripts detected the host OS and dropped the corresponding native Rust binary to a randomly named hidden file in the system temp directory (`.{random}` on Linux/macOS, `.{random}.exe` on Windows).

### 2. IronWorm Infostealer Binary

The dropped payload, identified as "IronWorm," is a Rust-compiled infostealer binary with platform-specific variants:

| Platform | SHA-256 |
|----------|---------|
| Linux | `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd` |
| Windows | `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903` |
| macOS | `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd` |

The binary targets an extensive range of credentials and sensitive data:
- **Cloud credentials:** AWS, Azure, Google Cloud keys; CI/CD runner metadata endpoints
- **Authentication tokens:** npm tokens, GitHub tokens, browser-stored passwords and cookies
- **Communication sessions:** Discord, Slack, Telegram, Steam
- **Cryptocurrency wallets:** MetaMask, Phantom, Exodus wallets and seed phrases
- **Password managers:** Bitwarden vault, 1Password vault
- **AI/Dev tools:** Claude Desktop, Cursor, Windsurf, VS Code, Zed config files; MCP server credentials
- **Security/VPN:** VPN configuration files; Metasploit, Sliver, Havoc installations; Tor hidden-service keys

### 3. C2 Infrastructure

IronWorm runs its own embedded Tor client for the command channel, contacting Tor infrastructure via:
- `check.torproject[.]org`
- `archive.torproject[.]org`

Direct C2 communication (which leaks the victim's real IP) uses two known IP addresses:
- `37.27.122[.]124`
- `57.128.246[.]79`

Bulk data exfiltration is performed via `temp[.]sh`, a public file hosting service.

### 4. Platform-Specific Behavior

#### Windows
- Payload dropped as `.{random}.exe` in system temp directory
- Establishes persistence via a hidden Windows Scheduled Task that relaunches the binary every minute
- Anti-debugging checks present in the binary
- Encrypted C2 details embedded in binary (resistant to static analysis)

#### macOS
- Payload dropped as `.{random}` in system temp directory
- Establishes persistence via a LaunchAgent plist in `~/Library/LaunchAgents/` for login persistence
- Anti-debugging checks present in the binary

#### Linux
- Payload dropped as `.{random}` in system temp directory
- Links kernel BPF library and loads eBPF programs directly into kernel from memory for stealth
- Kernel-level capabilities for enhanced evasion

### 5. Self-Propagation (Worm Behavior)

IronWorm includes a self-propagation routine:
1. Hunts npm tokens in environment variables and `.npmrc` files
2. Validates discovered tokens against the npm registry
3. Injects malicious `setup.mjs` preinstall scripts into high-download packages accessible via the stolen tokens
4. Publishes infected tarballs via raw HTTP PUT to `registry.npmjs.org`

JFrog confirmed the self-propagation code was functional but no successful secondary publications were detected. Rotating compromised npm tokens removes the credentials needed for worm spread.

### 6. Anti-Forensics / Evasion Techniques

- Anti-debugging checks on Windows and macOS builds
- Encrypted C2 configuration embedded in binary (no static analysis exposure)
- Hidden (dot-prefixed) filenames for dropped binaries
- eBPF kernel programs on Linux for kernel-level stealth
- Tor client for anonymized command channel
- Later versions (8.18.0, 8.20.0) bypassed `--ignore-scripts` by embedding execution in main package code

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| jscrambler | 8.14.0 | Preinstall hook deploying IronWorm binary |
| jscrambler | 8.16.0 | Preinstall hook deploying IronWorm binary |
| jscrambler | 8.17.0 | Preinstall hook deploying IronWorm binary |
| jscrambler | 8.18.0 | Payload embedded in main package code (bypasses --ignore-scripts) |
| jscrambler | 8.20.0 | Payload embedded in main package code (bypasses --ignore-scripts) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | dist/setup.js | a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60 | Dropper script in compromised package |
| All | dist/intro.js | a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86 | Dropper script in compromised package |
| Linux | /tmp/.{random} | fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd | IronWorm Linux binary |
| Windows | %TEMP%\\.{random}.exe | b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903 | IronWorm Windows binary |
| macOS | /tmp/.{random} | c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd | IronWorm macOS binary |
| macOS | ~/Library/LaunchAgents/{unknown}.plist | -- | Persistence LaunchAgent |
| Windows | Scheduled Task (hidden) | -- | Persistence scheduled task relaunching every minute |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 37.27.122[.]124 | C2 communication (leaks victim IP) |
| IP | 57.128.246[.]79 | C2 communication (leaks victim IP) |
| Domain | check.torproject[.]org | Contextual -- legitimate Tor Project domain used by embedded Tor client; blocking will cause collateral disruption to legitimate Tor users |
| Domain | archive.torproject[.]org | Contextual -- legitimate Tor Project domain used by embedded Tor client; blocking will cause collateral disruption to legitimate Tor users |
| Domain | temp[.]sh | Data exfiltration via public file host |

### Behavioral

- Node.js / npm process spawning hidden (dot-prefixed) binary from system temp directory
- Windows: Creation of hidden scheduled task with one-minute relaunch interval
- macOS: LaunchAgent plist creation in ~/Library/LaunchAgents/
- Linux: eBPF program loaded into kernel from memory
- Outbound connections to C2 IPs (37.27.122[.]124, 57.128.246[.]79)
- npm token harvesting from environment variables and .npmrc files
- HTTP PUT requests to registry.npmjs.org attempting to publish infected packages

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into legitimate jscrambler npm package via stolen credentials |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Preinstall hook executes JavaScript dropper (setup.js/intro.js) to deploy native binary |
| T1204.002 | User Execution: Malicious File | Package installation triggers automatic execution via npm lifecycle hooks |
| T1105 | Ingress Tool Transfer | Dropper script extracts and writes platform-specific binary to disk |
| T1027 | Obfuscated Files or Information | C2 details encrypted within binary; hidden dot-prefixed filenames |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows persistence via hidden scheduled task (one-minute interval) |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent in ~/Library/LaunchAgents/ |
| T1071 | Application Layer Protocol | C2 communication via Tor and direct IP connections |
| T1041 | Exfiltration Over C2 Channel | Data exfiltrated via direct C2 IP connections |
| T1567 | Exfiltration Over Web Service | Bulk data exfiltration via temp.sh public file host |
| T1555 | Credentials from Password Stores | Theft of Bitwarden/1Password vaults, browser-stored passwords |
| T1539 | Steal Web Session Cookie | Theft of browser cookies, Discord/Slack/Telegram sessions |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting npm tokens from .npmrc, AWS/Azure/GCP key files |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Self-propagation via stolen npm tokens to inject malicious preinstall scripts into other high-download packages |

## Impact Assessment

- **Breadth:** 15,800+ weekly downloads; any developer or CI/CD pipeline that installed jscrambler versions 8.14.0, 8.16.0, 8.17.0, 8.18.0, or 8.20.0 between July 11, 2026 and remediation is potentially affected
- **Depth:** Critical -- IronWorm targets an exceptionally broad range of sensitive data including cloud credentials, cryptocurrency wallets, password manager vaults, AI tool configurations, and developer tokens; includes kernel-level stealth (eBPF on Linux) and self-propagation capabilities
- **Stealth:** High -- anti-debugging, encrypted C2, Tor anonymization, hidden filenames, eBPF kernel programs (Linux)
- **Self-propagation risk:** The worm routine can spread to other npm packages via stolen tokens, though no successful secondary infections were confirmed

## Detection & Remediation

### Immediate Detection

Check if any compromised version was installed:
```bash
# Check lockfiles for compromised versions
grep -rn '"jscrambler"' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Check npm cache
npm cache ls jscrambler 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Search for hidden binaries in temp directories (Linux/macOS)
find /tmp -maxdepth 1 -name '.*' -type f -executable 2>/dev/null

# Windows: Check for suspicious scheduled tasks
schtasks /query /fo LIST /v | findstr /i "tmp temp"

# macOS: Check LaunchAgents
ls -la ~/Library/LaunchAgents/

# Check for connections to known C2 IPs
netstat -an | grep -E '37\.27\.122\.124|57\.128\.246\.79'
```

### Remediation

1. **Immediately** update jscrambler to version 8.22.0 or revert to 8.13.0
2. Remove compromised versions from lockfiles and package manager caches
3. Audit installation timestamps against Node child processes and temp directory execution
4. **Rotate all credentials:** cloud keys (AWS/Azure/GCP), npm tokens, GitHub tokens, AI tool API keys
5. **Revoke sessions:** browser, Discord, Slack, Bitwarden, cryptocurrency wallet sessions
6. Block C2 IP addresses `37.27.122[.]124` and `57.128.246[.]79` at the network perimeter
7. Windows: Search Task Scheduler for hidden tasks; macOS: audit `~/Library/LaunchAgents/` for unfamiliar plists
8. Search for and terminate any running hidden binaries from temp directories

### Long-Term Hardening

- Enable npm `--ignore-scripts` by default (npm 12 default behavior) and explicitly allowlist trusted packages
- Use lockfile-only installs (`npm ci`) in CI/CD pipelines
- Implement package integrity verification and provenance checking
- Deploy npm token monitoring and rotation policies
- Monitor for anomalous npm publish events from CI/CD service accounts
- Consider using Socket, Snyk, or similar supply chain security tools for real-time package analysis

## Detection Rules

These detections target the jscrambler IronWorm supply chain compromise at PoC/advisory-specific altitude, keying on distinctive artifacts (C2 IPs, process execution patterns, binary string combinations). Compiles does not equal fires -- verify in your pipeline with representative telemetry before promoting to production.

### Sigma: Jscrambler IronWorm C2 Network Connection

Detects outbound network connections to the two known C2 IPs (37.27.122[.]124, 57.128.246[.]79) used by the IronWorm infostealer.
**Scope:** Windows/Sysmon only (`product: windows`, `category: network_connection`). Requires equivalent EDR telemetry rules for macOS and Linux coverage.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 errors 0 issues (attacktag validator excluded due to proxy-blocked MITRE fetch, not a rule defect); splunk convert exit 0; log_scale convert exit 0. C2 IPs are distinctive, non-shared infrastructure; low FP risk. IPs will age out if attacker rotates infrastructure. -->

```yaml
title: Jscrambler IronWorm C2 Network Connection
id: 7a3b9c1e-4d2f-48a6-b5e7-9f0c1d2e3a4b
status: experimental
description: Detects outbound network connections to known C2 IP addresses associated with the compromised jscrambler 8.14.0 npm package deploying the IronWorm infostealer.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
author: Actioner
date: 2026/07/13
tags:
    - attack.t1071
    - attack.t1041
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '37.27.122.124'
            - '57.128.246.79'
    condition: selection
falsepositives:
    - Legitimate traffic to these IP addresses (unlikely in enterprise environments)
level: critical
```

### Sigma: NPM Preinstall Hook Spawning Hidden Binary From Temp Directory

Detects Node.js or npm spawning a dot-prefixed (hidden) executable from a system temp directory, the distinctive delivery mechanism used by jscrambler 8.14.0's preinstall hook.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 errors 0 issues; splunk convert exit 0; log_scale convert exit 0. Windows-scoped (product: windows); Linux/macOS process_creation logs vary by EDR. Medium confidence because legitimate npm packages could theoretically execute from temp, though dot-prefixed binaries in temp are uncommon. -->

```yaml
title: NPM Preinstall Hook Spawning Hidden Binary From Temp Directory
id: 8b4c0d2f-5e3a-49b7-c6f8-0a1d2e3f4b5c
status: experimental
description: Detects Node.js or npm spawning a hidden executable (dot-prefixed filename) from a system temp directory, consistent with the jscrambler 8.14.0 supply chain attack dropping IronWorm via a preinstall hook.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
author: Actioner
date: 2026/07/13
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '\npm.cmd'
    selection_image:
        Image|contains: '\Temp\.'
    condition: selection_parent and selection_image
falsepositives:
    - Legitimate npm packages executing dot-prefixed binaries from temp directories (uncommon)
level: high
```

### Snort: Jscrambler IronWorm C2 IP Connection

Detects any IP traffic from the protected network to the two known IronWorm C2 addresses.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -c /etc/snort/snort.conf -T exit 0 with rule included. IP-header-only rule; no payload inspection needed. Same IP-aging caveat as the Sigma rule. -->

```snort
alert ip $HOME_NET any -> [37.27.122.124,57.128.246.79] any (msg:"Actioner - Jscrambler IronWorm C2 Connection"; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; sid:2100001; rev:1;)
```

### Suricata: Jscrambler IronWorm C2 IP Connection

Detects any IP traffic from the protected network to the two known IronWorm C2 addresses.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S exit 0. IP-header-only rule matching both C2 IPs. No flow keyword needed for ip protocol. Same IP-aging caveat as Sigma/Snort rules. -->

```suricata
alert ip $HOME_NET any -> [37.27.122.124,57.128.246.79] any (msg:"Actioner - Jscrambler IronWorm C2 Connection to Known Infrastructure"; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-13; sid:2200001; rev:1;)
```

### YARA: IronWorm Rust Infostealer Binary

Detects the IronWorm binary via a distinctive combination of Tor infrastructure strings, exfiltration target (temp[.]sh), npm propagation artifacts, and cryptocurrency/password-manager target strings. Scope to npm cache directories and temp paths to reduce scan cost.
**Status:** compile ✅ compiles · confidence: medium · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive sample containing published string set (torproject, temp.sh, .npmrc, registry.npmjs.org, MetaMask, Bitwarden); silent on benign negative sample. Medium confidence because string combination is distinctive but Rust binaries may inline/obfuscate strings differently across builds; condition requires convergence from three independent string clusters to minimize FP. Hash meta fields provided for exact-match lookups in external hash-based systems. -->

```yara
rule Supply_Chain_Jscrambler_IronWorm
{
    meta:
        description = "Detects IronWorm Rust infostealer binaries deployed by compromised jscrambler 8.14.0 npm package via distinctive string combination"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        hash2 = "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903"
        hash3 = "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd"
        severity = "critical"

    strings:
        $tor1 = "check.torproject.org" ascii
        $tor2 = "archive.torproject.org" ascii
        $exfil = "temp.sh" ascii
        $npmrc = ".npmrc" ascii
        $registry = "registry.npmjs.org" ascii
        $setup_mjs = "setup.mjs" ascii
        $metamask = "MetaMask" ascii nocase
        $phantom = "Phantom" ascii nocase
        $bitwarden = "Bitwarden" ascii nocase
        $exodus = "Exodus" ascii nocase

    condition:
        filesize < 50MB and
        (
            2 of ($tor1, $tor2, $exfil) and
            1 of ($npmrc, $registry, $setup_mjs) and
            1 of ($metamask, $phantom, $bitwarden, $exodus)
        )
}
```

## Lessons Learned

1. **Supply chain attacks adapt to defenses in real time.** The attacker published initial versions using preinstall hooks, then shifted to embedding execution in the main package code within hours when npm 12's default script-disabling policy was recognized as a barrier. Defenders must assume script-disabling is necessary but insufficient.

2. **Credential theft enables cascading supply chain compromise.** A single stolen npm publishing credential enabled not just the initial compromise but a worm-like propagation mechanism that could infect downstream packages. Organizations must enforce MFA, token rotation, and least-privilege scoping on all package registry credentials.

3. **Broad credential harvesting maximizes attacker ROI.** IronWorm's target list spans cloud providers, password managers, crypto wallets, AI tools, and developer credentials, demonstrating the modern infostealer's shift from narrow credential theft to comprehensive identity harvesting.

4. **Rapid detection matters.** Socket's six-minute detection window limited exposure but did not prevent all installations. Continuous monitoring of package registries for anomalous publishes, combined with network-level C2 detection, provides defense in depth.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html) -- primary technical analysis with IOCs, timeline, and payload details
- [Cyber Security News](https://cybersecuritynews.com/hackers-compromised-jscrambler/) -- secondary coverage (content not retrievable at time of analysis)

<!-- revision: v1.0 (2026-07-13) — Applied critic NEEDS-REVISION fixes: (1) T1496→T1195.002 for npm self-propagation worm behavior; (2) defanged IPs in remediation step 6; (3) added Windows/Sysmon-only scope caveat to Sigma C2 rule; (4) added "Contextual — legitimate domain; blocking will cause collateral disruption" qualifier to torproject domains in IOC table; (5) removed dead Unix path logic ('\tmp\.') from Sigma Rule 2 (Windows-only rule had unreachable Unix path arm); (6) T1059→T1059.007 (JavaScript sub-technique) in MITRE table and Sigma Rule 2 tags. -->

---
*Report generated by Actioner*
