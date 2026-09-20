# Technical Analysis Report: WeaselBiscuit npm Supply-Chain Attack (2026-09-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-20
Version: 1.0 (DRAFT)

## Executive Summary

Researchers at OpenSourceMalware discovered a cluster of 16 malicious npm packages distributing **WeaselBiscuit**, a previously undocumented JavaScript information stealer that harvests Chrome extension storage data across Windows, macOS, and Linux. The campaign uses Npoint.io JSON storage as a dead-drop to deliver its payload and resolve C2 configuration, with the primary C2 server located at `103[.]170[.]217[.]184:8787`. WeaselBiscuit exhibits functional overlaps with two DPRK-linked Contagious Interview campaign tools — BeaverTail and OtterCookie — but is deliberately stripped down: it lacks remote access, persistence, cryptocurrency wallet-draining code, and secondary payload delivery. When directed by C2, it can additionally log clipboard contents and keystrokes on Windows systems. The attack targeted the developer supply chain through typosquatting and scoped namespace packages published between September 12-16, 2026.

## Background

### Contagious Interview Campaign Context

The DPRK-linked Contagious Interview campaign (also tracked as DEV#POPPER, CL-STA-0240) has systematically targeted software developers in crypto/Web3 sectors through malicious npm packages since late 2023. The campaign's primary tools — BeaverTail (JavaScript stealer/loader) and OtterCookie (modular infostealer) — have evolved through multiple versions. WeaselBiscuit represents a new, minimized variant that borrows core functions from both but removes the heavier capabilities, suggesting operational specialization or a lower-tier operator within the same ecosystem.

### Discovery Timeline

| Date | Event |
|------|-------|
| 2026-09-12 | First malicious packages published under @biz44 scope |
| 2026-09-14 | Additional @biz44 utility packages published |
| 2026-09-15 | process-lhpm and process-tailwind published |
| 2026-09-16 | engin1, laycot, and process-mite published |
| 2026-09-16 | OpenSourceMalware team identifies and reports the cluster |
| 2026-09-18 | Public disclosure via The Hacker News and multiple outlets |

## Technical Analysis

### 1. Infection Chain

The attack follows a four-stage execution flow:

**Stage 1 — Package Import:** The malicious package's `index.js` calls an `initialize()` function on import.

**Stage 2 — Detached Loader:** The initializer spawns a detached background Node.js process running `loader.js`, writing a `.pid` file to track the process. The parent process exits normally, leaving the loader running independently.

**Stage 3 — Payload Retrieval:** The loader fetches a JSON document from a campaign-specific Npoint.io dead-drop URL. The JSON contains a `code` field with the main stealer payload Base64-encoded. The payload is decoded and executed in-memory via `new Function()` — never touching disk.

**Stage 4 — C2 Configuration:** The in-memory stealer resolves its C2 configuration from a separate Npoint.io URL (`https://api[.]npoint[.]io/37c0a0c68bf7a94ed731`), which points to the Express.js HTTP C2 at `103[.]170[.]217[.]184:8787`.

### 2. Campaign Identifiers

Numerical campaign IDs are embedded in package names and payloads to track installations: `10`, `12`, `44`, `79`, `95`, `99`. Each ID maps to a distinct Npoint dead-drop URL.

### 3. Host Reconnaissance

Upon execution, WeaselBiscuit collects and uploads via multipart POST to `/api/system-info`:
- Hostname, username, OS details, CPU model, total memory
- Home directory and temp directory paths
- Local network interface IP and MAC addresses
- Public IP (via `api[.]ipify[.]org`)
- Public IP geolocation (via `ip-api[.]com`)

### 4. Chrome Extension Storage Theft

The stealer's primary objective is harvesting Chrome extension Local Extension Settings — raw LevelDB key/value stores containing extension state data. It uploads every readable, nonempty file under the extension's `Local Extension Settings` directory via multipart POST to `/api/upload-local-extension-settings`.

**Target paths by platform:**
- **Windows:** `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\`
- **macOS:** `~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/`
- **Linux:** `~/.config/google-chrome/Default/Local Extension Settings/`

This capability is financially significant: it can expose wallet-extension state (e.g., MetaMask, Phantom), authentication tokens, and other sensitive extension-held data.

### 5. Optional Capabilities (Windows Only)

Based on C2 polling responses:

- **Clipboard Monitoring:** Polls `/api/clipboard-status/<hostname>` and, when enabled, exfiltrates clipboard contents via JSON POST to `/api/clipboard-data`.
- **Keystroke Logging:** Polls `/api/keyboard-mouse-status/<hostname>` and, when enabled, deploys a PowerShell-based keyboard monitor at `%TEMP%\kb-monitor\keyboard-monitor-*.ps1`, exfiltrating captured keystrokes to `/api/keyboard-mouse-data`.

### 6. Key Differences from BeaverTail/OtterCookie

| Capability | BeaverTail | OtterCookie | WeaselBiscuit |
|---|---|---|---|
| Remote access | Yes | Yes | No |
| Persistence | Yes | Yes | No |
| Crypto wallet draining | Yes | No | No |
| Secondary payloads (InvisibleFerret) | Yes | No | No |
| Chrome extension storage theft | Yes | Yes | Yes |
| Clipboard capture | No | Yes | Yes (Windows) |
| Keystroke logging | No | Yes | Yes (Windows) |

## Indicators of Compromise

### Malicious npm Packages

All packages should be considered malicious and removed immediately if found in any `node_modules` directory or `package.json`.

| Package | Version | Published |
|---------|---------|-----------|
| `@biz44/id10-client` | — | 2026-09-12 |
| `@biz44/id12-client` | — | 2026-09-12 |
| `@biz44/id44-client` | — | 2026-09-12 |
| `@biz44/id79-client` | — | 2026-09-12 |
| `@biz44/id95-client` | — | 2026-09-12 |
| `@biz44/id99-client` | — | 2026-09-12 |
| `@biz44/process-runtime-utils` | — | 2026-09-14 |
| `@biz44/runtime-utils` | — | 2026-09-14 |
| `@railone/image-utils` | — | Unknown |
| `@vibecheck-polid/process-runtime-utils` | — | Unknown |
| `engin1` | 1.3.99 | 2026-09-16 |
| `id79-client` | — | 2026-09-12 |
| `laycot` | 1.3.10 | 2026-09-16 |
| `process-lhpm` | — | 2026-09-15 |
| `process-mite` | — | 2026-09-16 |
| `process-tailwind` | 1.1.99 | 2026-09-15 |
| `swnwall` | 1.2.10 | Unknown |

### Network Indicators (Defanged)

**C2 Server:**
- `103[.]170[.]217[.]184:8787` (HTTP, Express.js)

**Npoint Dead-Drop URLs:**
- `hxxps://api[.]npoint[.]io/24c25d5f5fcbb0992a4f` (Campaign ID: 99)
- `hxxps://api[.]npoint[.]io/641d37178a880b1e8b8f` (Campaign ID: 10)
- `hxxps://api[.]npoint[.]io/33e8d008c334b060adad` (Campaign ID: 79)
- `hxxps://api[.]npoint[.]io/ddae72efbb6714fae922` (Campaign ID: 12)
- `hxxps://api[.]npoint[.]io/933a731a5e97f4b45249` (Campaign ID: 95)
- `hxxps://api[.]npoint[.]io/24c12c4b66a29747764f` (Campaign ID: 79, 404)
- `hxxps://api[.]npoint[.]io/37c0a0c68bf7a94ed731` (C2 config resolver)

**Reconnaissance Services:**
- `api[.]ipify[.]org` (public IP lookup)
- `ip-api[.]com` (geolocation)

### C2 API Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/system-info` | POST (multipart) | Host reconnaissance upload |
| `/api/upload-local-extension-settings` | POST (multipart) | Chrome extension data exfiltration |
| `/api/clipboard-status/<hostname>` | GET | Clipboard collection toggle |
| `/api/clipboard-data` | POST (JSON) | Clipboard data exfiltration |
| `/api/keyboard-mouse-status/<hostname>` | GET | Keylogger toggle |
| `/api/keyboard-mouse-data` | POST (JSON) | Keystroke data exfiltration |

### File Hashes

| Artifact | SHA-256 |
|----------|---------|
| Second-stage payload | `7b15605f23b131b3eeea57e031ae7cb32fc4b78c7bbb2025aa7a561ea5ae5159` |

### Host-Based Indicators

- PID marker file: `<package-directory>/.pid`
- Windows keylogger script: `%TEMP%\kb-monitor\keyboard-monitor-*.ps1`

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Usage |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages distributed through public registry |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Payload executed as JavaScript via `new Function()` |
| T1102.001 | Web Service: Dead Drop Resolver | Npoint.io used to host payload and C2 configuration |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication with Express.js server |
| T1005 | Data from Local System | Harvests Chrome extension LevelDB storage files |
| T1217 | Browser Information Discovery | Enumerates Chrome extension Local Extension Settings directories |
| T1115 | Clipboard Data | Clipboard monitoring and exfiltration (Windows) |
| T1056.004 | Input Capture: Credential API Hooking | PowerShell-based keystroke logging (Windows) |
| T1041 | Exfiltration Over C2 Channel | All stolen data exfiltrated via HTTP to C2 server |
| T1082 | System Information Discovery | Collects hostname, OS, CPU, memory, network interfaces |
| T1016 | System Network Configuration Discovery | Harvests local interface IPs and MAC addresses |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Package names mimic legitimate utilities |

## Detection and Remediation

### Immediate Actions

1. **Audit `package.json` and lockfiles** for any of the 17 malicious package names listed above.
2. **Search `node_modules`** directories for `@biz44/`, `@railone/`, `@vibecheck-polid/` scopes and the standalone packages.
3. **Block C2 IP** `103[.]170[.]217[.]184` at perimeter firewalls.
4. **Block Npoint URLs** or monitor for the specific dead-drop path identifiers listed above.
5. **Search for `.pid` files** in npm package directories that should not contain them.
6. **Check `%TEMP%\kb-monitor\`** on Windows systems for PowerShell keystroke monitor scripts.

### Longer-Term Measures

- Implement npm package allowlisting or use Socket.dev / Snyk to detect malicious packages before installation.
- Monitor for `node.exe`/`node` processes accessing Chrome extension storage directories.
- Enable DNS logging and alert on Node.js processes resolving `api[.]npoint[.]io`.
- Rotate any credentials or tokens stored in Chrome extensions on affected systems, particularly cryptocurrency wallet extensions.

## Detection Rules

### Sigma Rules

#### 1. WeaselBiscuit Malicious npm Package Installation
<!-- audit: advisory-specific rule keyed on exact malicious package names; high confidence for direct package installs -->

Detects npm install commands targeting known WeaselBiscuit malicious packages.

- **File:** `/tmp/actioner/weaselbiscuit_npm_install.yml`
- **Compile status:** Compiled (sigma convert to Splunk and LogScale exit 0)
- **Confidence:** High — advisory-specific package names with no legitimate use

#### 2. WeaselBiscuit Chrome Extension Storage Access by Node.js
<!-- audit: TTP/behavioral rule — node accessing Chrome extension LevelDB is suspicious but not unique to WeaselBiscuit; medium confidence -->

Detects Node.js processes accessing Chrome Local Extension Settings directories.

- **File:** `/tmp/actioner/weaselbiscuit_chrome_ext_access.yml`
- **Compile status:** Compiled (sigma convert to Splunk exit 0)
- **Confidence:** Medium — behavioral pattern also possible from legitimate browser extension development tools

#### 3. WeaselBiscuit Npoint Dead-Drop Resolver Communication
<!-- audit: TTP/behavioral — npoint.io is a legitimate service used by many developers; low-medium confidence without additional context -->

Detects Node.js DNS queries to api.npoint.io used as dead-drop resolver.

- **File:** `/tmp/actioner/weaselbiscuit_npoint_c2.yml`
- **Compile status:** Compiled (sigma convert to Splunk exit 0)
- **Confidence:** Low — npoint.io is a legitimate service; requires correlation with other indicators

### YARA Rules

#### 4. WeaselBiscuit_JS_Stealer
<!-- audit: targets C2 API endpoint strings, Npoint URLs, and stealer function patterns; high confidence when C2 IP or specific Npoint paths match -->

Detects WeaselBiscuit JavaScript stealer payload by C2 API endpoint strings, Npoint dead-drop identifiers, and Chrome extension targeting patterns.

- **File:** `/tmp/actioner/weaselbiscuit_stealer.yar`
- **Compile status:** Compiled (yarac exit 0)
- **Confidence:** High — combines advisory-specific C2 endpoints and Npoint path identifiers

#### 5. WeaselBiscuit_Loader
<!-- audit: targets the npm package loader component's code patterns; medium confidence due to generic string overlap with legitimate Node.js patterns -->

Detects the WeaselBiscuit loader component by its Npoint retrieval, dynamic execution, and detached process patterns.

- **File:** `/tmp/actioner/weaselbiscuit_stealer.yar` (second rule)
- **Compile status:** Compiled (yarac exit 0)
- **Confidence:** Medium — some strings individually common in Node.js; condition requires convergence

### Suricata Rules

#### 6-13. WeaselBiscuit C2 Communication Rules (8 rules)
<!-- audit: HTTP URI content matches on specific C2 API paths and known C2 IP; high confidence for endpoint-specific rules, medium for Npoint DNS -->

Eight Suricata rules detecting WeaselBiscuit C2 API endpoint communications, known C2 IP traffic, and Npoint dead-drop DNS resolution.

- **File:** `/tmp/actioner/weaselbiscuit_c2.rules`
- **Compile status:** Compiled (suricata -T exit 0)
- **Confidence:** High (SIDs 2026091801-2026091807 — specific C2 API paths and known IP); Low (SID 2026091808 — generic Npoint DNS, legitimate service)

### Snort Rules

The same rule file was tested with Snort but validation failed due to a Snort environment pidfile configuration issue unrelated to rule syntax. The rules use Suricata-compatible syntax.

- **File:** `/tmp/actioner/weaselbiscuit_c2.rules`
- **Compile status:** Uncompiled (Snort environment error, not rule syntax)

## Sources

- [The Hacker News — WeaselBiscuit Stealer Spreads via 13 npm Packages to Harvest Chrome Extension Storage](https://thehackernews.com/2026/09/weaselbiscuit-stealer-spreads-via-13.html)
- [OpenSourceMalware — WeaselBiscuit Strips BeaverTail and OtterCookie Down to Essentials](https://opensourcemalware.com/blog/introducing-weaselbiscuit)
- [GitHub — OpenSourceMalware/WeaselBiscuit Repository](https://github.com/OpenSourceMalware/WeaselBiscuit)
- [Mallory.ai — WeaselBiscuit npm Packages Steal Chrome Extension Storage](https://mallory.ai/stories/01a0b438-f5ed-7c0b-85ce-2a859ab4ebf3)
- [CySecurity News — WeaselBiscuit Stealer Found in 13 Malicious npm Packages](https://www.cysecurity.news/2026/09/weaselbiscuit-stealer-found-in-13.html)
