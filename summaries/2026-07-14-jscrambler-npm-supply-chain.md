# Technical Analysis Report: Jscrambler npm Supply Chain Attack (2026-07-14)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-14
Version: 1.0 (FINAL)

<!-- revision: v0.1→v1.0 (2026-07-14)
  Applied critic verdicts:
  - Sigma temp.sh rule: changed r-dns|contains to r-dns exact + r-dns|endswith to prevent substring false positives (e.g. "notemp.sh")
  - YARA IronWorm Payload: downgraded confidence from high to medium (ChaCha20-Poly1305 per-string encryption may prevent static string matches in real samples)
  - YARA Dropper Scripts: DROPPED both rules (matched IOC-report text containing hash strings, not actual malware; useless for detection)
  - Suricata npm Registry Self-Propagation: DROPPED (fires on every legitimate npm publish; unacceptable false-positive rate)
  - Snort C2 rules: fixed syntax — removed space in "flow:established, to_server" (was invalid) → "flow:established,to_server"
  - MITRE ATT&CK: removed T1068 (no evidence of privilege escalation exploitation in this campaign)
-->

## Executive Summary

On July 11, 2026, attackers published malicious versions of the jscrambler npm package (versions 8.14.0, 8.16.0, 8.17.0, 8.18.0, and 8.20.0) using compromised npm publishing credentials. The trojanized releases delivered "IronWorm," a Rust-based cross-platform infostealer from the Shai-Hulud malware lineage, via npm preinstall hooks. The malware targets an extensive set of developer credentials including cloud provider keys (AWS, Azure, GCP), cryptocurrency wallets, browser sessions, AI tool configurations, npm/GitHub tokens, and messaging application sessions. Socket.dev detected and flagged the malicious release within six minutes of publication. Approximately 1,479 downloads occurred during the roughly two-hour window before the packages were deprecated. Jscrambler published version 8.22.0 as the clean replacement. Four dependent packages (jscrambler-webpack-plugin, gulp-jscrambler, grunt-jscrambler, jscrambler-metro-plugin) were also affected due to poisoned dependency resolution.

This attack represents the second major IronWorm supply chain campaign, following the [June 2026 Arweave/WeaveDB attack](/summaries/2026-06-05-npm-ironworm-supply-chain.md) that compromised 36 packages. The jscrambler campaign adds Windows and macOS payloads (the earlier wave was Linux-only ELF), self-propagation via stolen npm tokens, and uses ChaCha20-Poly1305 per-string obfuscation.

## Background: Jscrambler

Jscrambler is a widely-used JavaScript obfuscation and code-integrity platform. The official `jscrambler` npm package provides CLI and programmatic access for integrating Jscrambler's code protection services into build pipelines. With approximately 15,800--17,000 weekly downloads, it is commonly installed in CI/CD environments where developer credentials, cloud tokens, and deployment secrets are present --- making it a high-value supply chain target.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-08 | npm 12 released with install scripts disabled by default |
| 2026-07-11 | Attacker publishes malicious jscrambler versions 8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0 using compromised npm credential |
| 2026-07-11 (T+6 min) | Socket.dev flags malicious release and begins analysis |
| 2026-07-11 (~T+2 hrs) | Malicious versions deprecated; 1,479 downloads recorded |
| 2026-07-11--12 | Dependent packages (webpack-plugin, gulp, grunt, metro-plugin) identified as affected |
| 2026-07-12 | Jscrambler publishes clean version 8.22.0 |
| 2026-07-13--14 | Socket.dev, StepSecurity, SafeDep, and JFrog publish detailed analyses |

## Root Cause: Compromised npm Publishing Credential

The attacker gained access to a compromised npm publishing credential associated with the jscrambler package. The specific method of credential compromise has not been disclosed by Jscrambler. The attacker used this credential to publish five trojanized releases in rapid succession, skipping version numbers (8.15.0, 8.19.0) to avoid sequential-publish detection heuristics. The timing --- three days after npm 12 disabled install scripts by default --- suggests the attacker accelerated their campaign before ecosystem-wide adoption of the new protection reduced the attack surface.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection via Preinstall Hook

The attack vector is the npm `preinstall` lifecycle hook. In versions 8.14.0, 8.16.0, and 8.17.0, the `package.json` contained a preinstall script that executed `dist/setup.js`, which loaded a platform-specific Rust binary. Versions 8.18.0 and 8.20.0 shifted the execution trigger to main package code and CLI invocation, likely to evade preinstall-focused scanners.

Two JavaScript files were added to the package's `dist/` directory:
- `dist/setup.js` --- initial dropper that detects the host OS and extracts the corresponding binary
- `dist/intro.js` --- secondary loader that executes the Rust payload

### 2. Platform-Specific Rust Infostealer (IronWorm)

The payload is a Rust-compiled binary from the Shai-Hulud / IronWorm malware lineage. It ships as three platform-specific variants (Linux, Windows, macOS) and targets an extensive range of secrets:

**Cloud & Infrastructure:**
- AWS credentials and metadata endpoints
- Azure credentials
- Google Cloud Platform credentials
- Kubernetes configs

**Developer Tokens:**
- npm tokens (used for self-propagation)
- GitHub tokens
- CI/CD pipeline secrets

**AI Tool Configurations:**
- Claude Desktop
- Cursor
- Windsurf
- VS Code
- Zed API keys

**Cryptocurrency:**
- MetaMask, Phantom, Exodus, Coinbase, Trust Wallet

**Applications & Sessions:**
- Browser passwords, cookies, sessions
- Discord, Slack, Telegram
- Steam sessions
- Bitwarden password vault
- VPN configuration files

**Red-Team Frameworks:**
- Metasploit, Sliver, Havoc configurations

### 3. C2 Infrastructure

The malware communicates with two known C2 IP addresses over TLS using the `rustls` library:
- `37.27.122[.]124`
- `57.128.246[.]79`

C2 details are encrypted within the binary. The malware also interacts with Tor infrastructure (`check.torproject[.]org`, `archive.torproject[.]org`) likely for anonymized C2 fallback channels.

Bulk exfiltration of harvested data is performed via HTTP PUT requests to `temp[.]sh`, a public file hosting service.

### 4. Platform-Specific Behavior

#### Linux
- Payload hash: `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
- eBPF kernel loading capability for process and connection hiding
- Persistence via randomly named hidden file in temp directory (`.{random}`)

#### Windows
- Payload hash: `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
- Persistence via hidden scheduled task executing every minute
- Dropped as `.{random}.exe` in temp directory
- Anti-debugging checks

#### macOS
- Payload hash: `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`
- Persistence via LaunchAgent in `~/Library/LaunchAgents/`
- Anti-debugging checks

### 5. Anti-Forensics / Evasion Techniques

- **Per-string obfuscation:** ChaCha20-Poly1305 encryption applied per call site, preventing static string extraction
- **Anti-debugging:** Platform-specific anti-debugging checks on Windows and macOS
- **Self-propagation:** Steals npm tokens and uses them to publish trojanized versions of other packages via direct HTTP PUT to `registry.npmjs[.]org`, creating a worm-like spreading mechanism
- **Version skipping:** Malicious versions skip numbers (no 8.15.0, 8.19.0) to evade sequential-publish heuristics

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| jscrambler | 8.14.0 | Preinstall hook drops Rust infostealer |
| jscrambler | 8.16.0 | Preinstall hook drops Rust infostealer |
| jscrambler | 8.17.0 | Preinstall hook drops Rust infostealer |
| jscrambler | 8.18.0 | Main code / CLI execution triggers infostealer |
| jscrambler | 8.20.0 | Main code / CLI execution triggers infostealer |
| jscrambler-webpack-plugin | 8.6.2 | Affected via dependency on malicious jscrambler |
| gulp-jscrambler | 8.6.2 | Affected via dependency on malicious jscrambler |
| grunt-jscrambler | 8.5.2 | Affected via dependency on malicious jscrambler |
| jscrambler-metro-plugin | 9.0.2 | Affected via dependency on malicious jscrambler |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| All | dist/setup.js | a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60 | Dropper script added to malicious package |
| All | dist/intro.js | a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86 | Loader script added to malicious package |
| Linux | (temp dir)/.{random} | fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd | Rust infostealer binary (Linux ELF) |
| Windows | (temp dir)/.{random}.exe | b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903 | Rust infostealer binary (Windows PE) |
| macOS | (temp dir)/.{random} | c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd | Rust infostealer binary (macOS Mach-O) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 37.27.122[.]124 | C2 server |
| IP | 57.128.246[.]79 | C2 server |
| Domain | check.torproject[.]org | Tor connectivity check |
| Domain | archive.torproject[.]org | Tor binary download |
| Domain | temp[.]sh | Data exfiltration endpoint (HTTP PUT) |
| Domain | registry.npmjs[.]org | Self-propagation target (HTTP PUT with stolen tokens) |

### Behavioral

- Preinstall hook executes `dist/setup.js` which spawns platform-specific Rust binary from temporary directory
- Binary creates hidden files with random names in system temp directory
- Windows: Creates scheduled task executing every minute
- macOS: Creates LaunchAgent plist in `~/Library/LaunchAgents/`
- Linux: Attempts eBPF kernel module loading for stealth
- Bulk data exfiltration via HTTP PUT to `temp[.]sh`
- Self-propagation: steals npm tokens and publishes trojanized packages via direct PUT to npm registry

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised npm publishing credential used to publish trojanized jscrambler package |
| T1059.007 | Command and Scripting Interpreter: JavaScript | setup.js and intro.js scripts execute malicious logic during npm install |
| T1204.002 | User Execution: Malicious File | Developers unknowingly trigger payload by running npm install |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | ChaCha20-Poly1305 per-string obfuscation in Rust binary |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows persistence via hidden scheduled task executing every minute |
| T1543.001 | Create or Modify System Process: Launch Agent | macOS persistence via LaunchAgent in ~/Library/LaunchAgents/ |
| T1555 | Credentials from Password Stores | Harvests browser passwords, Bitwarden vault, OS keyrings |
| T1539 | Steal Web Session Cookie | Steals browser cookies and application session tokens |
| T1552.001 | Unsecured Credentials: Credentials In Files | Targets cloud credential files, AI tool configs, VPN configs, SSH keys |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over TLS via rustls |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Bulk data exfiltration via HTTP PUT to temp.sh |
| T1041 | Exfiltration Over C2 Channel | Encrypted credential exfiltration over TLS to C2 IPs |
| T1014 | Rootkit | eBPF kernel loading for process/connection hiding (Linux) |

## Impact Assessment

- **Breadth:** 1,479 downloads of malicious versions during ~2-hour exposure window; 4 dependent packages also affected. Normal weekly download rate of 15,800--17,000 suggests exposure in active CI/CD and developer environments.
- **Depth:** Critical. The infostealer targets the broadest credential surface observed in npm supply chain attacks to date: cloud providers, cryptocurrency wallets, AI tools, messaging apps, password managers, red-team frameworks, and developer tokens.
- **Stealth:** High. ChaCha20-Poly1305 per-string obfuscation, anti-debugging, eBPF rootkit (Linux), and self-propagation via stolen npm tokens make detection and containment challenging.
- **Self-propagation risk:** The worm-like npm token theft and automated package republishing capability means any affected developer's packages may also have been trojanized.

## Detection & Remediation

### Immediate Detection

```bash
# Check if any malicious jscrambler versions are installed
npm ls jscrambler 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Check package-lock.json / yarn.lock for malicious versions
grep -r '"jscrambler"' package-lock.json yarn.lock 2>/dev/null | grep -E '8\.(14|16|17|18|20)\.0'

# Check for the malicious dropper files in node_modules
find node_modules -path '*/jscrambler/dist/setup.js' -o -path '*/jscrambler/dist/intro.js' 2>/dev/null

# Check for IoC file hashes
find /tmp -name '.*' -executable 2>/dev/null | xargs sha256sum 2>/dev/null | grep -E '(fbbcf4d8|b7ca95d1|c8fd47d3)'

# macOS: Check for persistence
ls -la ~/Library/LaunchAgents/ 2>/dev/null

# Windows: Check for suspicious scheduled tasks (PowerShell)
# Get-ScheduledTask | Where-Object {$_.TaskPath -eq "\"} | Where-Object {$_.Actions.Execute -like "*tmp*"}
```

### Remediation

1. **Immediate:** Remove affected jscrambler versions; upgrade to 8.22.0
2. **Credential rotation (CRITICAL):** Rotate ALL secrets accessible from affected machines:
   - Cloud keys (AWS, Azure, GCP)
   - npm tokens and GitHub tokens
   - AI tool API keys (Claude, Cursor, Windsurf, VS Code, Zed)
   - Browser sessions, messaging app sessions (Discord, Slack, Telegram)
   - Bitwarden master password and vault
   - VPN configurations
3. **Cryptocurrency:** Move funds from any wallets (MetaMask, Phantom, Exodus, Coinbase, Trust) accessible from affected systems to new wallets with fresh seed phrases
4. **Audit npm publications:** Check if any packages owned by affected developers were republished with unauthorized versions (self-propagation vector)
5. **Network blocking:** Block C2 IPs `37.27.122[.]124` and `57.128.246[.]79` at the firewall
6. **System scan:** Run malware scans for hidden files in temp directories; check for LaunchAgents (macOS) and scheduled tasks (Windows)

### Long-Term Hardening

1. **Adopt npm 12** with install scripts disabled by default
2. **Enable npm audit signatures** and verify package provenance
3. **Use lockfile-only installs** (`npm ci`) in CI/CD
4. **Implement Socket.dev or similar** supply chain security scanning
5. **Enforce MFA** on all npm publishing accounts
6. **Scope npm tokens** with minimal permissions and short expiry

## Detection Rules

These rules target the concrete IOCs from the July 2026 jscrambler supply chain attack at PoC/advisory-specific altitude. They cover C2 network connections, malicious script execution, exfiltration patterns, and payload file matching. The primary caveat is that the C2 IPs and exfiltration infrastructure may rotate in future campaigns.

### Sigma: Jscrambler IronWorm C2 Network Connection

Detects outbound connections to the two known C2 IPs used by the IronWorm payload.
**Status:** compile check-splunk pass, compile check-logscale pass | confidence: **high**

```yaml
title: Jscrambler IronWorm C2 Network Connection
id: 8a3c1e7f-4b2d-4f9a-b6e8-1c5d0a9f3e2b
status: experimental
description: >
    Detects outbound network connections to known C2 IP addresses used by
    the IronWorm infostealer delivered via the compromised jscrambler npm
    package (versions 8.14.0 through 8.20.0). July 2026 supply-chain attack.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/
    - https://www.securityweek.com/multiple-jscrambler-packages-impacted-by-supply-chain-attack/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '37.27.122.124'
            - '57.128.246.79'
    condition: selection
falsepositives:
    - Unlikely; these IPs are dedicated attacker infrastructure
level: critical
```

<!-- VALIDATION AUDIT
- sigma check: failed (MITRE ATT&CK data fetch blocked by proxy 403 — not a rule syntax issue)
- sigma convert --without-pipeline -t splunk: PASS → DestinationIp IN ("37.27.122.124", "57.128.246.79")
- sigma convert --without-pipeline -t log_scale: PASS → DestinationIp=/^37\.27\.122\.124$/i or DestinationIp=/^57\.128\.246\.79$/i
- Field encoding: IPs are real (not defanged) per logsource-encoding spec
- Confidence: high — C2 IPs are dedicated attacker infrastructure with no legitimate use
-->

### Sigma: Jscrambler Malicious Preinstall Hook Execution

Detects execution of the malicious setup.js or intro.js scripts from the jscrambler package path.
**Status:** compile check-splunk pass, compile check-logscale pass | confidence: **medium**

```yaml
title: Jscrambler Malicious Preinstall Hook Execution
id: 2f7e9a1b-6c3d-4e8f-a5b0-9d4c1e7f2a3b
status: experimental
description: >
    Detects execution of the malicious setup.js or intro.js scripts dropped
    by the compromised jscrambler npm package via preinstall hook. The scripts
    were added to the dist/ directory and executed as part of npm install.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
    - https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/
author: Actioner
date: 2026-07-14
tags:
    - attack.t1059.007
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'node'
            - 'jscrambler'
        CommandLine|contains:
            - 'dist/setup.js'
            - 'dist\\setup.js'
            - 'dist/intro.js'
            - 'dist\\intro.js'
    condition: selection
falsepositives:
    - Legitimate jscrambler package versions using different dist/ entry points (review version number)
level: high
```

<!-- VALIDATION AUDIT
- sigma check: failed (MITRE ATT&CK data fetch blocked by proxy 403 — not a rule syntax issue)
- sigma convert --without-pipeline -t splunk: PASS → CommandLine="*node*" CommandLine="*jscrambler*" CommandLine IN ("*dist/setup.js*", ...)
- sigma convert --without-pipeline -t log_scale: PASS
- Confidence: medium — legitimate jscrambler CLI invocations may include dist/ paths; version check needed to confirm malicious vs clean
-->

### Sigma: Jscrambler IronWorm Data Exfiltration via temp.sh

Detects HTTP PUT requests to temp.sh used for bulk credential exfiltration.
**Status:** compile check-splunk pass, compile check-logscale pass | confidence: **medium**

```yaml
title: Jscrambler IronWorm Data Exfiltration via temp.sh
id: 4d8f2e6a-1b3c-4a7e-9f5d-0c8b1a2e3d4f
status: experimental
description: >
    Detects HTTP PUT requests to temp.sh, a public file hosting service used
    by the IronWorm infostealer (from the compromised jscrambler npm package)
    for bulk exfiltration of harvested credentials and data.
references:
    - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
author: Actioner
date: 2026-07-14
tags:
    - attack.t1567.002
logsource:
    category: proxy
detection:
    selection_method:
        cs-method: 'PUT'
    selection_host_exact:
        r-dns: 'temp.sh'
    selection_host_sub:
        r-dns|endswith: '.temp.sh'
    condition: selection_method and (selection_host_exact or selection_host_sub)
falsepositives:
    - Developers legitimately using temp.sh for file sharing
level: high
```

<!-- VALIDATION AUDIT (revised v1.0)
- sigma convert --without-pipeline -t splunk: PASS → "cs-method"="PUT" "r-dns" IN ("temp.sh", "*.temp.sh")
- sigma convert --without-pipeline -t log_scale: PASS → "cs-method"=/^PUT$/i "r-dns"=/^temp\.sh$/i or "r-dns"=/\.temp\.sh$/i
- Fix applied: changed r-dns|contains to r-dns exact + r-dns|endswith to prevent substring false positives (e.g. "notemp.sh")
- Confidence: medium — temp.sh is a legitimate public file host; PUT method narrows scope but may still hit developer use
-->

### YARA: Jscrambler IronWorm Payload Detection

Matches the Rust infostealer binary via C2 infrastructure strings and exfiltration indicators.
**Status:** yarac compile pass | confidence: **medium**

```yara
rule Malware_Jscrambler_IronWorm_Payload
{
    meta:
        description = "Detects the IronWorm Rust-based infostealer payload delivered via the compromised jscrambler npm package (July 2026 supply-chain attack)"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        hash = "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903"
        hash = "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd"
        severity = "critical"
        confidence = "medium"
        tlp = "WHITE"

    strings:
        $c2_1 = "37.27.122.124" ascii
        $c2_2 = "57.128.246.79" ascii
        $exfil = "temp.sh" ascii
        $tor_1 = "check.torproject.org" ascii
        $tor_2 = "archive.torproject.org" ascii
        $rust_1 = "rustls" ascii
        $rust_2 = "chacha20" ascii nocase
        $rust_3 = "poly1305" ascii nocase

    condition:
        filesize < 50MB and
        (
            (2 of ($c2_*) and $exfil) or
            (1 of ($c2_*) and 2 of ($tor_*)) or
            (1 of ($c2_*) and 2 of ($rust_*) and $exfil)
        )
}
```

<!-- VALIDATION AUDIT (revised v1.0)
- yarac compile: PASS (exit 0)
- Confidence: downgraded high → medium — ChaCha20-Poly1305 per-string obfuscation means these strings may not appear in plaintext in real samples; rule targets the unobfuscated configuration layer and may miss encrypted variants
- C2 IPs + exfil service + Tor infrastructure is a distinctive combination when strings are visible
-->

### YARA: Jscrambler Malicious Dropper Scripts --- DROPPED

> **Dropped in revision v1.0:** The two YARA dropper-script rules (Malware_Jscrambler_SetupJS_Dropper, Malware_Jscrambler_IntroJS_Loader) searched for SHA-256 hash strings as file content, which would only match IOC reports or scan results containing those hashes --- not the actual malware files. These rules were useless for detection and have been removed. Use hash-based file scanning (e.g., `sha256sum` comparisons or EDR hash-match policies) against the IOC hashes listed in the IOC table above instead.

### Suricata: Jscrambler IronWorm C2 Outbound Connection

Alerts on established connections to known C2 IPs.
**Status:** suricata -T compile pass | confidence: **high**

```
alert ip $HOME_NET any -> 37.27.122.124 any (msg:"Actioner - Jscrambler IronWorm C2 Connection to 37.27.122.124"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-14; sid:2100100; rev:1;)

alert ip $HOME_NET any -> 57.128.246.79 any (msg:"Actioner - Jscrambler IronWorm C2 Connection to 57.128.246.79"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-14; sid:2100101; rev:1;)
```

<!-- VALIDATION AUDIT
- suricata -T: PASS — "Configuration provided was successfully loaded. Exiting."
- Confidence: high — dedicated attacker C2 infrastructure
-->

### Suricata: Jscrambler IronWorm Exfiltration via temp.sh

Alerts on HTTP PUT requests to temp.sh used for bulk data exfiltration.
**Status:** suricata -T compile pass | confidence: **medium**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Jscrambler IronWorm Exfiltration via temp.sh PUT"; flow:established,to_server; http.method; content:"PUT"; http.host; content:"temp.sh"; endswith; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created_at 2026-07-14; sid:2100102; rev:1;)
```

<!-- VALIDATION AUDIT
- suricata -T: PASS — "Configuration provided was successfully loaded. Exiting."
- Confidence: medium — temp.sh is a legitimate public file host; PUT method narrows but doesn't eliminate FPs
-->

### Suricata: Jscrambler IronWorm Self-Propagation via npm Registry --- DROPPED

> **Dropped in revision v1.0:** The Suricata rule alerting on HTTP PUT to registry.npmjs.org (sid:2100103) fires on every legitimate `npm publish` operation. The false-positive rate makes it unusable as a standalone detection. Monitor for self-propagation via npm audit logs and anomalous publishing patterns instead.

### Snort: Jscrambler IronWorm C2 Outbound Connection

Alerts on connections to the known C2 IP addresses.
**Status:** uncompiled (structural check only) | confidence: **high**

```
alert ip $HOME_NET any -> 37.27.122.124 any (msg:"Actioner - Jscrambler IronWorm C2 to 37.27.122.124"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created 2026-07-14; sid:2100104; rev:1;)

alert ip $HOME_NET any -> 57.128.246.79 any (msg:"Actioner - Jscrambler IronWorm C2 to 57.128.246.79"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html; metadata:author Actioner, created 2026-07-14; sid:2100105; rev:1;)
```

<!-- VALIDATION AUDIT (revised v1.0)
- snort: NOT INSTALLED — structural check only
- Fix applied: removed space in "flow:established, to_server" → "flow:established,to_server"
- Structure check: header uses ip protocol, flow:established,to_server; msg/sid/rev present; semicolons correct; no Suricata-only keywords
- Confidence: high — dedicated C2 IPs
-->

## Lessons Learned

1. **npm lifecycle hooks remain a critical attack surface.** Despite npm 12 disabling install scripts by default (released July 8, three days before this attack), the vast majority of the ecosystem has not yet upgraded. The attacker explicitly raced to exploit this closing window. Organizations should urgently adopt npm 12 or use `--ignore-scripts` with manual review of preinstall hooks.

2. **Credential scope determines blast radius.** The IronWorm payload's credential targeting breadth --- from cloud providers to AI tools to red-team frameworks --- demonstrates that a single compromised developer workstation can yield access to an organization's entire digital footprint. Secret management must enforce least-privilege scoping and short-lived tokens.

3. **Self-propagating supply chain attacks amplify impact.** The worm-like behavior (stealing npm tokens to republish other packages) means that even a quickly-contained incident can have cascading effects across the npm ecosystem. Package registries should implement anomaly detection on publishing patterns (rapid multi-package publishes, version-number gaps, new binary artifacts in historically pure-JS packages).

4. **Six-minute detection demonstrates the value of automated supply chain scanners.** Socket.dev's rapid detection limited the exposure window to approximately two hours and 1,479 downloads. Organizations without such tooling would have no visibility into this class of threat.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html) --- Primary technical coverage of the jscrambler supply chain attack with IOCs and timeline
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/) --- Coverage with download counts, credential targeting details, and ChaCha20-Poly1305 obfuscation details
- [SecurityWeek](https://www.securityweek.com/multiple-jscrambler-packages-impacted-by-supply-chain-attack/) --- Coverage of dependent package impact and execution chain details
- [Actioner: IronWorm npm Supply Chain Attack (2026-06-05)](/summaries/2026-06-05-npm-ironworm-supply-chain.md) --- Prior IronWorm/Shai-Hulud campaign analysis (Arweave/WeaveDB ecosystem)

---
*Report generated by Actioner*
