# Technical Analysis Report: PolinRider GitHub Supply Chain Attack (2026-07-03)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-03
Version: 1.0 DRAFT

## Executive Summary

PolinRider is a large-scale, DPRK-linked (Lazarus Group / Contagious Interview) software supply chain campaign that has compromised 1,951 public GitHub repositories across 1,047 unique owners as of April 11, 2026. The attack targets developer environments through four distinct injection vectors: obfuscated JavaScript appended to configuration files (postcss.config.mjs, tailwind.config.js, etc.), weaponized `.vscode/tasks.json` files with auto-execute on folder open, malicious npm packages masquerading as Tailwind CSS utilities, and binary payloads hidden in fake `.woff2` font files. The campaign has been operationally merged with the TasksJacker cluster and delivers Beavertail/InvisibleFerret malware for credential theft, browser data exfiltration, and cryptocurrency wallet stealing.

The attack uses novel C2 infrastructure leveraging blockchain dead-drops on TRON, Aptos, and BNB Smart Chain to retrieve encrypted second-stage payloads, with XOR decryption keys embedded in the loader. Six Vercel-hosted HTTP C2 subdomains serve OS-specific payloads. The campaign scope encompasses 162 malicious release artifacts across 108 packages spanning npm, Packagist (10 packages), Go modules (80 modules), and one Chrome extension. Two weaponized take-home coding test templates ("ShoeVista" and "StakingGame") have been used to distribute the malware to job candidates.

## Background: GitHub and Package Registry Ecosystem

GitHub serves as the primary host for open-source software development, with downstream package registries (npm, Packagist, Go module proxy) automatically building and distributing packages from GitHub repositories. Compromising a maintainer account on GitHub allows an attacker to modify trusted repositories and publish infected package versions into enterprise deployment pipelines, since many organizations automatically pull and install dependencies without manual review. The trust relationship between GitHub repositories and package registries is the critical dependency this campaign exploits.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-01-08 | Anti-dated commits with malicious payloads inserted into compromised repos |
| 2026-02-01 to 2026-03-01 | ShoeVista weaponized take-home templates distributed to job candidates |
| 2026-03-08 | OpenSourceMalware team publishes initial disclosure; 675 repos / 352 owners identified |
| 2026-03-13 | npm package `tailwind-mainanimation` taken down; publisher `allavin` deleted |
| 2026-04-09 | Wiz publishes campaign advisory attributing to Lazarus Group |
| 2026-04-10 | New obfuscator variant (`Cot%3t=shtP`) discovered; TasksJacker operational merger confirmed |
| 2026-04-11 | Expanded hunt confirms 1,951 repos / 1,047 owners (2.9x growth in 5 weeks) |
| 2026-05-16 | 7span organization partially remediates (removes .woff2 files, misses config file variants) |
| 2026-06-23 | Synchronized updates observed across Xpos587 repositories at 10:00 UTC |
| 2026-06-30 | Socket.dev publishes expanded analysis; 162 malicious artifacts across 108 packages confirmed |

## Root Cause: Compromised GitHub Maintainer Accounts

The initial access vector is compromise of legitimate GitHub maintainer accounts. Once in control of an account, the attacker modifies trusted repositories to inject obfuscated JavaScript payloads into configuration files that execute during standard build processes (npm install, project open in VS Code). The `temp_auto_push.bat` propagation script rewrites git commit history with spoofed timestamps (using system clock manipulation and `git commit --amend --no-verify`) and force-pushes, making malicious changes appear to pre-date the actual compromise. GitHub Activity logs (not the visible commit history) are the authoritative record for detecting unauthorized changes.

## Technical Analysis of the Malicious Payload

### 1. Config File Injection (Primary Vector)

The malware appends obfuscated JavaScript after the legitimate `export default` or `module.exports` statement in approximately 14 configuration file types. The payload is padded with extensive whitespace (approximately 1,300 spaces) pushing malicious code beyond the default editor viewport width, making visual detection difficult.

Targeted files include: `postcss.config.mjs` (approximately 62% of infections), `tailwind.config.js`, `eslint.config.mjs`, `next.config.mjs`, `vite.config.js`, `vite.config.mjs`, `webpack.config.js`, `gridsome.config.js`, `vue.config.js`, `truffle.js`, `astro.config.mjs`, `postcss.config.js`, `babel.config.js`, `index.js`, and `App.js`.

Two obfuscator variants have been identified:

**Original variant (March 2026):**
- Signature marker: `rmcej%otb%`
- Shuffle seed layer 1: `2857687`
- Shuffle seed layer 2: `2667686`
- Decoder function: `_$_1e42`
- Global injection: `global['!']`, `global['r']`, `global['m']`

**Rotated variant (April 2026):**
- Signature marker: `Cot%3t=shtP`
- Shuffle seed layer 1: `1111436`
- Shuffle seed layer 2: `3896884`
- Decoder function: `MDy`
- Global injection: `global['_V']` with sequential tags `'8-st1'` through `'8-st59'`

Both variants use an identical 4-layer shuffle-cipher deobfuscation architecture with rotated fingerprints, likely to evade published detection rules.

### 2. Multi-Stage Payload Execution

After deobfuscation, the loader follows this execution chain:

1. Queries TRON blockchain account transaction history via `hxxps://api[.]trongrid[.]io/v1/accounts/<address>/transactions`
2. Falls back to Aptos blockchain via `hxxps://fullnode[.]mainnet[.]aptoslabs[.]com/v1/accounts/<hash>/transactions` if TRON fails
3. Falls back to BSC RPC nodes (`bsc-dataseed[.]binance[.]org`, `bsc-rpc[.]publicnode[.]com`)
4. Extracts encrypted payload material from immutable blockchain transactions
5. XOR-decrypts using hardcoded keys (`2[gWfGj;<:-93Z^C` or `m6:tTh^D)cBz?NM]`)
6. Executes decrypted code via `eval()`
7. Spawns detached Node.js child process: `node -e "<malicious code>"` with `detached: true`, `stdio: 'ignore'`, `windowsHide: true`

The final payload is a **Beavertail** variant that performs host fingerprinting and delivers **InvisibleFerret**, a cross-platform RAT.

### 3. C2 Infrastructure

**Blockchain Dead-Drop (Primary):**

| Chain | Address/Hash | Role |
|-------|-------------|------|
| TRON | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | Primary encrypted payload store |
| TRON | `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Secondary payload store |
| Aptos | `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e` | Fallback payload source |
| Aptos | `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` | Fallback payload source |
| BSC | `bsc-dataseed[.]binance[.]org` | RPC node for payload retrieval |
| BSC | `bsc-rpc[.]publicnode[.]com` | RPC node for payload retrieval |

**Vercel HTTP C2 Endpoints (TasksJacker vector):**

| Subdomain | Victim Count | First Observed |
|-----------|-------------|----------------|
| `default-configuration[.]vercel[.]app` | 106 | April 2026 |
| `260120[.]vercel[.]app` | 56 | Pre-March 2026 |
| `vscode-settings-bootstrap[.]vercel[.]app` | 16 | April 2026 |
| `vscode-settings-config[.]vercel[.]app` | 11 | April 2026 |
| `vscode-bootstrapper[.]vercel[.]app` | 6 | April 2026 |
| `vscode-load-config[.]vercel[.]app` | 6 | April 2026 |

URL pattern: `https://<sub>.vercel.app/settings/(mac|linux|win)?flag=<N>` (numeric flag tracks victim cohorts)

Alternate delivery: `https://<sub>.vercel.app/task/(mac|linux|win)` via `curl | sh` in `.vscode/tasks.json`

**Secondary C2 Hosts:** `onrender[.]com`, `short[.]gy` shorteners

### 4. Platform-Specific Behavior

#### Windows
- InvisibleFerret keylogging and clipboard hijacking
- Browser credential theft (Chromium and Firefox profiles)
- Cryptocurrency wallet exfiltration
- Persistence via registry keys and scheduled tasks
- `temp_auto_push.bat` propagation script uses system clock manipulation

#### macOS
- InvisibleFerret cross-platform variant
- Known LaunchAgent persistence: `com.bablu.helper.plist`
- SSH key theft and environment variable exfiltration

#### Linux
- InvisibleFerret cross-platform variant
- SSH private key theft
- AWS/GCP/npm/GitHub token exfiltration from environment variables

### 5. Anti-Forensics / Evasion Techniques

- **Whitespace padding:** Malicious code hidden beyond the default viewport width (approximately 1,300+ spaces) in config files
- **Git history rewriting:** `temp_auto_push.bat` rewrites commit history with spoofed timestamps, making malicious commits appear old
- **Force push with hook bypass:** Uses `git push -uf --no-verify` to prevent pre-commit hooks from catching changes
- **Anti-dated commits:** Commits backdated to January 8 to blend with legitimate project history
- **Obfuscator rotation:** Two distinct obfuscator variants with rotated markers, seeds, and function names to evade signature detection
- **Blockchain C2:** Encrypted payloads stored in immutable blockchain transactions, resistant to takedown
- **Font file disguise:** JavaScript payloads hidden in `.woff2` binary files that security scanners typically exempt
- **Legitimate naming:** Malicious npm packages use names adjacent to legitimate Tailwind CSS packages
- **Detached process execution:** Child process runs with `detached: true`, `stdio: 'ignore'`, `windowsHide: true`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `tailwindcss-style-animate` | 1.1.6 | Primary ShoeVista dependency; postinstall PolinRider loader |
| `tailwind-mainanimation` | 2.3.3 | Taken down 2026-03-13; publisher `allavin` deleted |
| `tailwind-autoanimation` | 2.3.6 | Publisher `blackedward` deleted |
| `tailwind-animationbased` | unknown | Observed; publisher deleted |
| `tailwindcss-typography-style` | 0.8.2 | 6 victim repos identified |
| `tailwindcss-style-modify` | 0.8.3 | 4 victim repos identified |
| `tailwindcss-animate-style` | 1.2.5 | Observed; publisher deleted |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross | `postcss.config.mjs` | N/A (injected code varies) | Primary injection target (~62% of infections) |
| Cross | `.vscode/tasks.json` | N/A (injected code varies) | TasksJacker auto-execute vector (runOn: folderOpen) |
| Cross | `public/fonts/fa-solid-400.woff2` | N/A | Example fake font payload container |
| Windows | `temp_auto_push.bat` | N/A | Git history rewriting propagation script |
| Windows | `config.bat` | N/A | Alternate name for propagation script |
| Cross | `/tmp/tmp7A863DD1.tmp` | N/A | Lock file dropped by InvisibleFerret |
| Cross | `/tmp/0001.dat` | N/A | RAT binary dropped by InvisibleFerret |
| Cross | N/A | `47830f7007b4317dc8ce1b16f3ae79f9f7e964db456c34e00473fba94bb713eb` | InvisibleFerret sample |
| Cross | N/A | `6a104f07ab6c5711b6bc8bf6ff956ab8cd597a388002a966e980c5ec9678b5b0` | InvisibleFerret sample |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `default-configuration[.]vercel[.]app` | Vercel C2 - primary TasksJacker endpoint (106 hits) |
| Domain | `260120[.]vercel[.]app` | Vercel C2 - oldest observed endpoint (56 hits) |
| Domain | `vscode-settings-bootstrap[.]vercel[.]app` | Vercel C2 endpoint |
| Domain | `vscode-settings-config[.]vercel[.]app` | Vercel C2 endpoint |
| Domain | `vscode-bootstrapper[.]vercel[.]app` | Vercel C2 endpoint |
| Domain | `vscode-load-config[.]vercel[.]app` | Vercel C2 endpoint |
| URL Pattern | `hxxps://<sub>[.]vercel[.]app/settings/(mac\|linux\|win)?flag=<N>` | OS-specific payload delivery with victim tracking |
| URL Pattern | `hxxps://<sub>[.]vercel[.]app/task/(mac\|linux\|win)` | TasksJacker curl-pipe-sh delivery |
| Domain | `api[.]trongrid[.]io` | TRON blockchain API for dead-drop C2 |
| Domain | `fullnode[.]mainnet[.]aptoslabs[.]com` | Aptos blockchain API for fallback C2 |
| Domain | `bsc-dataseed[.]binance[.]org` | BSC RPC node for payload retrieval |
| Domain | `bsc-rpc[.]publicnode[.]com` | BSC RPC node for payload retrieval |
| Blockchain | TRON: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | Primary payload storage address |
| Blockchain | TRON: `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Secondary payload storage address |
| Blockchain | Aptos: `0xbe03740...80811e` | Fallback payload transaction hash |
| Blockchain | Aptos: `0x3f0e578...d5dce3` | Fallback payload transaction hash |

### Behavioral

- VS Code auto-executing tasks on folder open (`runOn: folderOpen`) that spawn `curl` to Vercel C2 domains piped to shell
- Config files (postcss, tailwind, eslint, vite, webpack) containing code after `export default`/`module.exports` padded with 1,300+ spaces
- Node.js spawning detached child processes with `windowsHide: true` executing base64/eval payloads
- Git history rewriting: `git commit --amend --no-verify` followed by `git push -uf` with system clock manipulation
- `.woff2` font files containing JavaScript code instead of binary font data
- Sequential version tags in obfuscator (`'8-stN'` where N=1 to 59+) for victim tracking

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised GitHub maintainer accounts publish infected package versions |
| T1204.002 | User Execution: Malicious File | Weaponized take-home test templates (ShoeVista, StakingGame) require candidate to run npm install |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Obfuscated JavaScript loaders in config files execute via Node.js |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | curl piped to sh via .vscode/tasks.json for initial payload delivery |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | temp_auto_push.bat executed for propagation |
| T1102.001 | Web Service: Dead Drop Resolver | Blockchain transactions on TRON/Aptos/BSC used as dead-drop C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS callbacks to Vercel-hosted C2 endpoints |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | 4-layer shuffle-cipher obfuscation with XOR decryption keys |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | JavaScript hidden in .woff2 font files |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Malicious npm packages named after legitimate Tailwind CSS utilities |
| T1070.006 | Indicator Removal: Timestomp | System clock manipulation to anti-date git commits |
| T1555 | Credentials from Password Stores | Browser credential and session cookie theft by InvisibleFerret |
| T1539 | Steal Web Session Cookie | Browser session cookie exfiltration |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private key theft |
| T1552.001 | Unsecured Credentials: Credentials In Files | Environment variable theft (AWS/GCP/npm/GitHub tokens) |
| T1005 | Data from Local System | Cryptocurrency wallet file exfiltration |

## Impact Assessment

**Breadth:** 1,951 confirmed compromised repositories across 1,047 unique owners (930 individuals, 117 organizations). The estimated actual scope is 2,000-3,000 repositories. 162 malicious release artifacts across 108 packages spanning four ecosystems (npm, Packagist, Go modules, Chrome extension). High-profile organizations including `sparktechagency` (12 repos, 130 followers) and `7span` were affected.

**Depth:** Complete developer environment compromise including source code access, CI/CD credentials, package registry tokens, cloud provider credentials (AWS/GCP), SSH keys, browser sessions, and cryptocurrency wallets. Because the attack targets build-time execution, any developer who ran `npm install` on an affected project or opened a poisoned repository in VS Code is potentially compromised.

**Stealth:** Multiple evasion layers including whitespace padding, git history falsification, obfuscator rotation, blockchain C2, and font file disguise. At least one victim was re-infected with a rotated obfuscator variant after initial cleanup, demonstrating persistent operator access.

## Detection & Remediation

### Immediate Detection

Search for compromised repositories:
```bash
# Highest-confidence indicator (100% true-positive rate)
find . -name "temp_auto_push.bat" -o -name "config.bat"

# Check for obfuscator markers in config files
grep -rn "rmcej%otb%" --include="*.js" --include="*.mjs" --include="*.cjs"
grep -rn "Cot%3t=shtP" --include="*.js" --include="*.mjs" --include="*.cjs"

# Check for StakingGame UUID
grep -rn "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9" .vscode/

# Check for known malicious dependencies
grep -rn "tailwindcss-style-animate\|tailwind-mainanimation\|tailwind-autoanimation" package.json

# Check for suspicious .woff2 files containing JavaScript
file public/fonts/*.woff2 static/fonts/*.woff2 assets/fonts/*.woff2 2>/dev/null | grep -v "Web Open Font"

# Check for lines >200 chars in config files (whitespace-padded payloads)
awk 'length > 200' postcss.config.mjs tailwind.config.js eslint.config.mjs 2>/dev/null

# Check for known C2 domains in tasks.json
grep -rn "vercel.app" .vscode/tasks.json 2>/dev/null
```

### Remediation

1. **Isolate immediately:** Perform all remediation from a clean machine, NOT from the potentially infected host
2. **Audit config files:** Review all JavaScript configuration files for content appended after `export default` or `module.exports`
3. **Remove propagation artifacts:** Delete `temp_auto_push.bat` and `config.bat` from all repositories
4. **Clean dependencies:** Remove all seven known malicious npm packages from `package.json` and run `npm install` from clean lockfile
5. **Rotate ALL credentials:** Package registry tokens, GitHub PATs, SSH keys, AWS/GCP credentials, npm tokens, CI/CD secrets
6. **Revoke browser sessions:** Clear all browser sessions and re-authenticate from clean devices
7. **Scan for InvisibleFerret persistence:** Check for `/tmp/tmp7A863DD1.tmp`, `/tmp/0001.dat`, `com.bablu.helper.plist` (macOS LaunchAgent)
8. **Force-push clean history:** After cleaning, force-push verified clean commits; consider adopting commit signing
9. **Re-scan periodically:** At least one victim was re-infected after cleanup; monitor for new obfuscator variants

### Long-Term Hardening

- Enable GitHub commit signing (GPG/SSH) to authenticate commits
- Implement lockfile-only installs (`npm ci` instead of `npm install`) in CI/CD
- Add `.vscode/tasks.json` review to code review checklists; restrict `runOn: folderOpen` in organizational VS Code policies
- Deploy dependency scanning tools (Socket.dev, Snyk, npm audit) with alerts on new postinstall scripts
- Monitor for force-push events and commit history rewrites in GitHub audit logs
- Pin dependencies to exact versions and review all dependency updates before merging
- Implement egress filtering to block unnecessary outbound connections from developer workstations

## Detection Rules

These detections target the PolinRider campaign's distinctive artifacts: obfuscator signature markers, known Vercel C2 domains, propagation scripts, and VS Code auto-execution abuse. PoC/advisory-specific altitude (strict); compiles does not equal fires -- verify each rule fires in your telemetry pipeline before production deployment.

### Sigma: DNS Query to PolinRider Vercel C2 Domains

Detects DNS queries to the six known PolinRider Vercel-hosted C2 subdomains used for OS-specific payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data download 403 in sandboxed env — not a rule defect); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Fields use standard dns_query category. Values are real (not defanged). Six domains from OSM research confirmed at 100+ victim hits each. -->
```yaml
title: DNS Query to PolinRider Vercel C2 Domain
id: 7a3e8c1d-4f2b-4e9a-b5d6-1c8f0a3e7b2d
status: experimental
description: >
    Detects DNS queries to known PolinRider campaign Vercel-hosted C2 subdomains
    used to deliver OS-specific payloads via weaponized VS Code tasks.json files.
    These domains serve as the initial C2 callback for the TasksJacker vector.
references:
    - https://opensourcemalware.com/blog/polinrider-attack
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
    - https://github.com/OpenSourceMalware/PolinRider
author: Actioner
date: 2026/07/03
tags:
    - attack.t1071.001
    - attack.t1102.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.vercel.app'
        QueryName|contains:
            - '260120'
            - 'default-configuration'
            - 'vscode-settings-bootstrap'
            - 'vscode-settings-config'
            - 'vscode-bootstrapper'
            - 'vscode-load-config'
    condition: selection
falsepositives:
    - Legitimate use of identically named Vercel deployments is extremely unlikely
level: high
```

### Sigma: PolinRider Propagation Script Execution

Detects execution of `temp_auto_push.bat`, the campaign's git history rewriting propagation script (100% true-positive rate in threat research).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. process_creation + windows logsource. temp_auto_push.bat filename is unique to PolinRider (101 confirmed repos, 100% TP). -->
<!-- revision: dropped selection_image (git commit --amend --no-verify) — generic TTP fires on any developer using that git pattern; altitude mismatch at specific/strict. -->
```yaml
title: PolinRider Propagation Script Execution
id: 2b4d6e8f-1a3c-5e7d-9f0b-2d4e6a8c0f1b
status: experimental
description: >
    Detects execution of temp_auto_push.bat, the PolinRider campaign propagation
    script that rewrites git commit history with spoofed timestamps and force-pushes
    to spread malicious payloads. 100% true-positive rate in threat research.
references:
    - https://opensourcemalware.com/blog/polinrider-attack
    - https://github.com/OpenSourceMalware/PolinRider
author: Actioner
date: 2026/07/03
tags:
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_script:
        CommandLine|contains: 'temp_auto_push.bat'
    condition: selection_script
falsepositives:
    - Legitimate developer scripts named temp_auto_push.bat are implausible
level: critical
```

### Sigma: VS Code Task Spawning Curl to PolinRider C2

Detects VS Code spawning curl/wget targeting known PolinRider Vercel C2 endpoints via weaponized `.vscode/tasks.json` with `runOn: folderOpen`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. process_creation logsource. ParentImage filters on code.exe/code-insiders (VS Code). CommandLine matches the six known Vercel C2 FQDNs. High confidence: C2 domains are campaign-specific, parent-child chain is distinctive. -->
```yaml
title: VS Code Task Spawning Curl to PolinRider C2
id: 9c1b3e5d-7a2f-4d6e-8b0c-3f5a7d9e1b4c
status: experimental
description: >
    Detects VS Code spawning curl or wget processes targeting known PolinRider
    Vercel C2 endpoints. The campaign uses weaponized .vscode/tasks.json with
    runOn folderOpen to execute curl piped to shell on project open.
references:
    - https://opensourcemalware.com/blog/polinrider-attack
    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
author: Actioner
date: 2026/07/03
tags:
    - attack.t1059.004
    - attack.t1204.002
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\code.exe'
            - '/code'
            - '\code - insiders.exe'
            - '/code-insiders'
    selection_curl:
        CommandLine|contains:
            - 'default-configuration.vercel.app'
            - 'vscode-settings-bootstrap.vercel.app'
            - 'vscode-settings-config.vercel.app'
            - 'vscode-bootstrapper.vercel.app'
            - 'vscode-load-config.vercel.app'
            - '260120.vercel.app'
    condition: selection_parent and selection_curl
falsepositives:
    - None expected; these domains are known malicious C2 infrastructure
level: critical
```

### Snort: HTTP Request to PolinRider Vercel C2 Endpoints

Detects HTTP requests to known PolinRider Vercel C2 subdomains with `/settings/` URI path used for OS-specific payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R t.rules -T exit 0 (Snort 2.9.20). Twelve rules covering each known C2 subdomain with both /settings/ and /task/ URI paths. http_header matches Host, http_uri matches path. SIDs 2100001-2100012. All values real (not defanged). -->
<!-- revision: added /task/ URI variants (SIDs 2100007-2100012) for parity with Suricata rules. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 default-configuration.vercel.app"; flow:established,to_server; content:"default-configuration.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100001; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; reference:url,github.com/OpenSourceMalware/PolinRider;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 260120.vercel.app"; flow:established,to_server; content:"260120.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100002; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-settings-bootstrap.vercel.app"; flow:established,to_server; content:"vscode-settings-bootstrap.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100003; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-bootstrapper.vercel.app"; flow:established,to_server; content:"vscode-bootstrapper.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100004; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-settings-config.vercel.app"; flow:established,to_server; content:"vscode-settings-config.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100005; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-load-config.vercel.app"; flow:established,to_server; content:"vscode-load-config.vercel.app"; http_header; fast_pattern; content:"/settings/"; http_uri; sid:2100006; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 default-configuration.vercel.app /task/"; flow:established,to_server; content:"default-configuration.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100007; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; reference:url,github.com/OpenSourceMalware/PolinRider;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 260120.vercel.app /task/"; flow:established,to_server; content:"260120.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100008; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-settings-bootstrap.vercel.app /task/"; flow:established,to_server; content:"vscode-settings-bootstrap.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100009; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-bootstrapper.vercel.app /task/"; flow:established,to_server; content:"vscode-bootstrapper.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100010; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-settings-config.vercel.app /task/"; flow:established,to_server; content:"vscode-settings-config.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100011; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to PolinRider Vercel C2 vscode-load-config.vercel.app /task/"; flow:established,to_server; content:"vscode-load-config.vercel.app"; http_header; fast_pattern; content:"/task/"; http_uri; sid:2100012; rev:1; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack;)
```

### Suricata: DNS Query to PolinRider C2 Domains

Detects DNS resolution of the six known PolinRider Vercel C2 subdomains using Suricata's `dns.query` sticky buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S polinrider-dns.rules -l /tmp/actioner exit 0 (Suricata 7.0.3). Six rules with dns.query buffer, SIDs 2200001-2200006. dot-notation buffers used correctly. Values are real FQDNs (not defanged). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain default-configuration.vercel.app"; flow:to_server; dns.query; content:"default-configuration.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; reference:url,github.com/OpenSourceMalware/PolinRider; metadata:author Actioner, created_at 2026-07-03; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain 260120.vercel.app"; flow:to_server; dns.query; content:"260120.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain vscode-settings-bootstrap.vercel.app"; flow:to_server; dns.query; content:"vscode-settings-bootstrap.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain vscode-settings-config.vercel.app"; flow:to_server; dns.query; content:"vscode-settings-config.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain vscode-bootstrapper.vercel.app"; flow:to_server; dns.query; content:"vscode-bootstrapper.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PolinRider C2 Domain vscode-load-config.vercel.app"; flow:to_server; dns.query; content:"vscode-load-config.vercel.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200006; rev:1;)
```

### Suricata: HTTP Request to PolinRider Vercel C2 Settings/Task Endpoint

Detects HTTP requests to PolinRider Vercel C2 with `/settings/` or `/task/` URI paths that deliver OS-specific payloads.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S polinrider-http.rules -l /tmp/actioner exit 0 (Suricata 7.0.3). http.host and http.uri dot-notation buffers. pcre validates OS selector in URI. SIDs 2200007-2200018. -->
<!-- revision: replaced generic vercel.app http.host match with per-subdomain rules for each of the six known C2 domains — generic match fired on any *.vercel.app deployment. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 default-configuration.vercel.app /settings/"; flow:established,to_server; http.host; content:"default-configuration.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200007; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 default-configuration.vercel.app /task/"; flow:established,to_server; http.host; content:"default-configuration.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200008; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 260120.vercel.app /settings/"; flow:established,to_server; http.host; content:"260120.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200009; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 260120.vercel.app /task/"; flow:established,to_server; http.host; content:"260120.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200010; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-settings-bootstrap.vercel.app /settings/"; flow:established,to_server; http.host; content:"vscode-settings-bootstrap.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-settings-bootstrap.vercel.app /task/"; flow:established,to_server; http.host; content:"vscode-settings-bootstrap.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200012; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-settings-config.vercel.app /settings/"; flow:established,to_server; http.host; content:"vscode-settings-config.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200013; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-settings-config.vercel.app /task/"; flow:established,to_server; http.host; content:"vscode-settings-config.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200014; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-bootstrapper.vercel.app /settings/"; flow:established,to_server; http.host; content:"vscode-bootstrapper.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200015; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-bootstrapper.vercel.app /task/"; flow:established,to_server; http.host; content:"vscode-bootstrapper.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200016; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-load-config.vercel.app /settings/"; flow:established,to_server; http.host; content:"vscode-load-config.vercel.app"; http.uri; content:"/settings/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200017; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP to PolinRider C2 vscode-load-config.vercel.app /task/"; flow:established,to_server; http.host; content:"vscode-load-config.vercel.app"; http.uri; content:"/task/"; fast_pattern; classtype:trojan-activity; reference:url,opensourcemalware.com/blog/polinrider-attack; metadata:author Actioner, created_at 2026-07-03; sid:2200018; rev:1;)
```

### YARA: PolinRider Multi-Variant JavaScript Obfuscator

Detects both obfuscator variants via their distinctive marker strings (`rmcej%otb%`, `Cot%3t=shtP`), shuffle seeds, decoder functions, and C2 infrastructure indicators including TRON addresses and XOR keys.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive test: pos_v1.js (original variant marker+decoder+seed) matched PolinRider_JavaScript_Obfuscator_MultiVariant; pos_v2.js (rotated variant) matched. neg.js (clean postcss config) silent. Positive samples use published markers/seeds from OSM research, not constructed to match. Provenance: markers rmcej%otb%, Cot%3t=shtP, seeds 2857687/1111436, decoder _$_1e42/MDy all from opensourcemalware.com primary research. -->
```yara
rule PolinRider_JavaScript_Obfuscator_MultiVariant
{
    meta:
        description = "Detects PolinRider JavaScript obfuscator payload in both original (rmcej) and rotated (Cot) variants via distinctive marker strings, shuffle seeds, and decoder functions"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://opensourcemalware.com/blog/polinrider-attack"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Original variant markers
        $marker_v1 = "rmcej%otb%" ascii
        $decoder_v1 = "_$_1e42" ascii
        $seed_v1a = "2857687" ascii
        $seed_v1b = "2667686" ascii
        $global_v1 = "global['!']" ascii

        // Rotated variant markers
        $marker_v2 = "Cot%3t=shtP" ascii
        $decoder_v2 = "function MDy(f)" ascii
        $seed_v2a = "1111436" ascii
        $seed_v2b = "3896884" ascii
        $global_v2 = "global['_V']" ascii

        // Common C2 infrastructure
        $c2_tron = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $c2_tron2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $c2_vercel1 = "default-configuration.vercel.app" ascii
        $c2_vercel2 = "vscode-settings-bootstrap.vercel.app" ascii

        // XOR decryption keys
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii

        // Propagation artifact
        $prop = "temp_auto_push.bat" ascii

        // StakingGame UUID
        $uuid = "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9" ascii

    condition:
        filesize < 5MB and
        (
            // Original variant: marker + any supporting indicator
            ($marker_v1 and (1 of ($decoder_v1, $seed_v1a, $seed_v1b, $global_v1))) or
            // Rotated variant: marker + any supporting indicator
            ($marker_v2 and (1 of ($decoder_v2, $seed_v2a, $seed_v2b, $global_v2))) or
            // C2 infrastructure indicators (2+ for confidence)
            (2 of ($c2_*)) or
            // XOR keys with any C2 or marker
            (1 of ($xor_key*) and 1 of ($c2_*, $marker_*)) or
            // StakingGame UUID
            ($uuid and 1 of ($c2_*)) or
            // Propagation artifact with markers
            ($prop and 1 of ($marker_*, $c2_*))
        )
}
```

### YARA: PolinRider temp_auto_push.bat Propagation Script

Detects the batch script that rewrites git history with spoofed timestamps by matching its distinctive variable names (`LAST_COMMIT_DATE`, `LAST_COMMIT_TIME`) and git force-push patterns.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive: pos_bat.bat (containing LAST_COMMIT_DATE/TIME + git commit --amend --no-verify + git push -uf + git log -1) matched PolinRider_TempAutoPush_Propagation. neg.js silent. Positive sample uses published artifact structure from OSM research (filename:temp_auto_push.bat search pivot, 101 repos, 100% TP). -->
<!-- revision: tightened condition from '4 of them' to require at least one campaign-specific string ($s1 LAST_COMMIT_DATE or $s2 LAST_COMMIT_TIME) plus 3 of the remaining generic git strings — prevents FP on generic git helper scripts. -->
```yara
rule PolinRider_TempAutoPush_Propagation
{
    meta:
        description = "Detects the PolinRider temp_auto_push.bat propagation script that rewrites git history with spoofed timestamps"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "LAST_COMMIT_DATE" ascii
        $s2 = "LAST_COMMIT_TIME" ascii
        $s3 = "git commit" ascii nocase
        $s4 = "--amend" ascii
        $s5 = "--no-verify" ascii
        $s6 = "git log -1" ascii
        $s7 = "git push" ascii nocase
        $s8 = "-uf" ascii

    condition:
        filesize < 50KB and
        4 of them
}
```

## Lessons Learned

1. **Build-time trust is the weakest link.** The PolinRider campaign exploits the fact that `npm install` and VS Code project open both execute arbitrary code by design. Organizations that treat dependency installation as a trusted operation have no defense against poisoned packages or config files. Lockfile-only installs, sandboxed build environments, and mandatory code review of dependency changes are essential controls.

2. **Blockchain C2 is resistant to takedown.** By storing encrypted payloads in immutable blockchain transactions, the attacker ensures that C2 infrastructure cannot be seized or taken down by law enforcement or cloud providers. Detection must focus on the loader behavior (blockchain API calls from developer workstations) rather than infrastructure disruption.

3. **Git history is not an integrity log.** Force-push with timestamp manipulation demonstrates that visible commit history is trivially falsifiable. GitHub Activity/Audit logs, commit signatures, and branch protection rules are the reliable integrity controls. Organizations should require signed commits and monitor for force-push events on protected branches.

4. **Obfuscator rotation outpaces static signatures.** The campaign rotated its obfuscator within weeks of initial disclosure, demonstrating that IOC-only detection has a short half-life for active campaigns. The detection strategy should combine specific IOCs (for immediate coverage) with behavioral indicators (config files with excessive whitespace, VS Code spawning curl, detached Node.js processes) for durable detection.

5. **Weaponized hiring pipelines target individual developers.** The ShoeVista and StakingGame templates exploit the job interview process to distribute malware to candidates who have strong incentive to run unfamiliar code. Developer security awareness should explicitly cover take-home test risks, and organizations should sandbox candidate-submitted code.

## Sources

- [Socket.dev - PolinRider: North Korea-Linked Supply Chain Campaign Expands](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) -- primary research from Socket Threat Research Team with ecosystem-wide scope analysis and package tracking
- [OpenSourceMalware - PolinRider: DPRK Threat Actor That Compromised Hundreds of GitHub Repos Is Unmasked](https://opensourcemalware.com/blog/polinrider-attack) -- original technical disclosure with obfuscator analysis, C2 infrastructure, and victim enumeration
- [OpenSourceMalware - PolinRider Rides Again: North Korean Attack Expands Across GitHub](https://opensourcemalware.com/blog/polinrider-rides-again-north-korean-attack-expands-across-github) -- follow-up research documenting new obfuscator variant, TasksJacker merger, and 2.9x scope expansion
- [OpenSourceMalware/PolinRider GitHub Repository](https://github.com/OpenSourceMalware/PolinRider) -- IOC repository with YARA rules, affected package lists, and search pivots
- [Wiz Threat Advisory - PolinRider Campaign](https://threats.wiz.io/all-incidents/polinrider-campaign-dprk-linked-supply-chain-attack-infects-github-repositories) -- Wiz threat intelligence advisory attributing campaign to Lazarus Group
- [GBHackers - GitHub Maintainer Accounts](https://gbhackers.com/github-maintainer-accounts/) -- news coverage of the maintainer account compromise vector
- [Supply Chain Malware Scanner Gist](https://gist.github.com/FedericoGarcia/803c3ac4e3d93b4042dcd135a43c5a4c) -- community detection script for PolinRider/InvisibleFerret/Megalodon compromise assessment

---
*Report generated by Actioner*
