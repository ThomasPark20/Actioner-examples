# Technical Analysis Report: AmnesiaStealer -- macOS Infostealer with Live Browser Hijacking (2026-08-18)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-18
Version: 1.1 (REVISED)
<!-- revision: applied critic fixes — sid 2200103 scoped to allllowef.space via http.host; sids 2200101/2200102 dns.query content matches upgraded with endswith; YARA sample status corrected to "not tested (synthetic string validation only)" -->

## Executive Summary

AmnesiaStealer is a multi-stage, Rust-based macOS information stealer discovered by Jamf Threat Labs in mid-August 2026. Distributed via counterfeit GitHub download pages using ClickFix social engineering, the malware executes a three-stage infection chain: a self-deleting shell-script dropper, a Rust infostealer payload that harvests credentials from 16 Chromium-family browsers, the macOS Keychain, Apple Notes, Telegram, and cryptocurrency wallets, and an optional `stream_module` that provides operators with real-time, interactive remote control of the victim's browser sessions via Chrome DevTools Protocol (CDP).

What sets AmnesiaStealer apart from existing macOS stealers (Atomic/AMOS, MacSync, CrashStealer) is its combination of browser-profile cloning with CDP-based live remote control at approximately 3 fps, a cryptocurrency clipboard hijacker module, and its builder-driven configuration framework with Russian-language backend panels. The malware persists via a root LaunchDaemon impersonating Apple's CrashReporter (`com.apple.ReportCrash.plist`) and includes OS-version-branched logic to exploit CVE-2020-9771 for TCC bypass on older macOS versions. It exfiltrates data to `debug.allllowef[.]space` and uses `github.aoitour[.]com` as the initial delivery domain.

## Background: macOS Credential-Stealing Landscape

macOS infostealers have proliferated since 2023, with families like Atomic Stealer (AMOS), Poseidon, Banshee, and CrashStealer establishing the category. Most rely on AppleScript/osascript for password prompts and shell scripts for collection. AmnesiaStealer represents a significant evolution: a compiled Rust binary with encrypted configuration, builder-driven customization comparable to Windows infostealer-as-a-service toolkits, and the first documented macOS malware to combine browser-profile cloning with CDP-based live remote control. The shared distribution template (counterfeit GitHub pages with ClickFix) connects it to the broader AMOS/MacSync ecosystem, suggesting an organized operator network.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Early August 2026 | Counterfeit GitHub pages created on github.aoitour[.]com mimicking legitimate repositories |
| ~2026-08-11 | Initial distribution of AmnesiaStealer via ClickFix campaigns |
| 2026-08-13 | Jamf Threat Labs publishes initial technical analysis |
| 2026-08-13-14 | Coverage by BleepingComputer, The Hacker News, SecurityWeek, CSO Online |
| 2026-08-16 | Additional analysis and IOC publications from multiple security vendors |

## Root Cause: ClickFix Social Engineering via Counterfeit GitHub Pages

The initial access vector is social engineering through highly polished counterfeit GitHub download pages. These pages feature dark-theme branding mimicking GitHub's interface, fake "Verified Publisher" badges, and a "Download for macOS" call-to-action. Instead of delivering an application bundle, the landing page instructs victims to copy a Base64-encoded command and paste it into the macOS Terminal. This decoded command fetches a shell script from attacker infrastructure, which downloads a password-protected ZIP archive (password: `dulin`) containing the Mach-O payload. The same distribution template has been reused across AMOS (Atomic Stealer) and MacSync campaigns, indicating shared infrastructure or tooling.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 -- Shell Script Dropper

The decoded Base64 Terminal command retrieves a shell script from attacker infrastructure using the route `/d/command?t=<token>&b=<build>`. The dropper:

- Downloads a password-protected ZIP archive and extracts the Mach-O binary
- Removes the macOS quarantine extended attribute (`xattr -d com.apple.quarantine` / `xattr -cr`)
- Applies an ad-hoc code signature (`codesign --force --deep --sign -`)
- Extracts the binary to `/tmp/.com.apple.dt.<numeric_token>` (hidden, Apple-impersonating filename)
- Launches silently via `nohup` before deleting the executable from disk
- Clears shell history (`history -c`)

### 2. Stage 2 -- Rust Infostealer Core

The main payload is a universal Mach-O binary (Intel + Apple Silicon) written in Rust. Key SHA-256: `de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a`.

**Configuration:** An embedded 4,064-byte encrypted blob using a repeating XOR key (`4mn3s1a_2o26!xK`), structured as null-delimited `KEY\0VALUE\0` pairs. Configuration fields include `ENCRYPTION_KEY`, `CLIPPER_ENABLED`, and cryptocurrency wallet addresses.

**Credential Harvesting:**
- Presents a native-looking macOS password prompt, validated locally via `dscl . -authonly` before proceeding
- Stores cleartext password at `/tmp/pwd` and `~/.pwd`
- Unlocks the login keychain via `security unlock-keychain -p <password>`
- Collects keychain databases including `-wal` and `-shm` companions

**Browser Data Collection (16 Chromium-family browsers):**
Chrome, Brave, Arc, Microsoft Edge, Opera, Vivaldi, Chromium, and others. Per profile (`Default`, `Profile 1-3`):
- Cookies, Login Data, Login Data For Account, Web Data, History, Bookmarks
- Local State, Preferences, Extensions directory
- Chrome Safe Storage passwords via Keychain access

**Additional Data Targets:**
- Apple Notes (`NoteStore.sqlite` via privileged read; attachments capped at 12 MB)
- Telegram sessions (`tdata/key_datas` + account directories)
- Safari cookies via tiered strategy (direct read, Finder osascript, sudo cat, APFS snapshot mount via CVE-2020-9771)
- File grabber: `~/Desktop`, `~/Documents`, `~/Downloads` filtered on extensions (txt, pdf, rtf, doc, wallet, key, jpg, png, csv)
- System profiling: `sw_vers`, `whoami`, `ioreg`, `system_profiler`, `ls /Applications`
- IP geolocation via external API

**Cryptocurrency Clipper Module:**
Configurable via `CLIPPER_ENABLED` field (disabled in analyzed build). Targets: Bitcoin, Bitcoin Cash, Ethereum, TRON, Litecoin, Monero, Solana, Ripple, Cosmos (ATOM).

**Safe Storage Key Manipulation:**
When the Chrome Safe Storage key is unavailable (macOS 26+), the malware employs a "provision fallback (destructive)" strategy: it overwrites per-browser Safe Storage keys with a hardcoded password (`pqz8N3vKxRmY2aLcQ`), rendering existing cookies/passwords unreadable to the victim while enabling future attacker decryption.

### 3. Stage 3 -- Stream Module (Remote Browser Control)

A separate Rust binary (`stream_module`, SHA-256: `e853748ca8f9a5a9168263617409a9039ab09f4ffc7d860374c1e3b0b67b31a5`) fetched on operator command. Source files: `main.rs`, `relay.rs`, `cdp.rs`, `chrome.rs`, `cookies.rs`.

**Browser Hijacking Flow:**
1. Duplicates victim's browser profile to `~/.local/share/.stream/profiles/<browser>/`
2. Caches Safe Storage keys to `~/.local/share/.stream/.<browser>_key`
3. Launches a headless Chromium instance with flags: `--headless=old`, `--remote-debugging-port=`, `--remote-allow-origins=*`, plus hardening-off switches
4. Injects "stealth script" via `Page.addScriptToEvaluateOnNewDocument` to evade automation fingerprinting
5. Establishes WebSocket connection to relay: `ws://<relay-host>/ws/stream/<build_id>?t=<token>`
6. Sends JSON registration: `{"type":"register","build_id":"...","browser":"..."}`
7. Provides live screencast at ~3 fps with full input control

**Operator Commands:** `navigate`, `mouse_click`, `export_cookies`, tab management, keyboard/mouse/scroll interaction, cookie export in Netscape format via CDP `Network.getAllCookies`.

### 4. C2 Infrastructure

| Component | Value |
|-----------|-------|
| Delivery domain | github.aoitour[.]com |
| C2 backend | debug.allllowef[.]space |
| C2 panel | "Amnesia Panel" (Russian-language authentication) |
| Bot registration | `POST /api/bot/join` |
| Tasking poll | `GET /api/bot/actions?build_id=se&bot_id=<id>` |
| Data upload | `POST /send/` |
| WebSocket relay | `ws://<relay-host>/ws/stream/<build_id>?t=<token>` |
| API key | `86770e8759abf2dad9ae85f5e11a25e9` |
| Build ID | `b=se` |
| Build variant | `v3_shell_chrome` |

### 5. Persistence

The malware installs a root LaunchDaemon impersonating Apple's crash reporting service:

- **Plist path:** `/Library/LaunchDaemons/com.apple.ReportCrash.plist`
- **Settings:** `KeepAlive`, `RunAtLoad`, `SessionCreate` enabled; `UserName` overridden to console user
- Requires `sudo -S` (piped password from earlier capture) for installation

### 6. Anti-Forensics / Evasion Techniques

- Quarantine attribute removal on downloaded payloads
- Ad-hoc code signing to bypass validation
- Password-protected ZIP to complicate automated sandbox inspection
- Self-deletion of the initial executable after launch
- Shell history clearing (`history -c`)
- Hidden staging files with Apple-impersonating names (`.com.apple.dt.*`)
- Browser fingerprint API patching in headless sessions to avoid automation detection
- OS-version branching for macOS-specific bypass logic
- TCC database manipulation via `sqlite3` injection to bypass permissions
- Service restart (`killall tccd`) to apply TCC modifications

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| macOS | `/tmp/.com.apple.dt.<numeric>` | `de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a` | Stage 1 Mach-O infostealer payload |
| macOS | `stream_module` (fetched on demand) | `e853748ca8f9a5a9168263617409a9039ab09f4ffc7d860374c1e3b0b67b31a5` | Stage 3 browser control module |
| macOS | `/Library/LaunchDaemons/com.apple.ReportCrash.plist` | -- | Persistence LaunchDaemon (fake CrashReporter) |
| macOS | `/tmp/tempAppleScript.scpt` | -- | Fallback AppleScript |
| macOS | `/tmp/pwd`, `~/.pwd` | -- | Cleartext password cache |
| macOS | `/tmp/starter` | -- | LaunchDaemon plist staging file |
| macOS | `/tmp/.snap_read`, `/tmp/.snap_tcc` | -- | APFS snapshot access artifacts |
| macOS | `/tmp/.tcc_mod.db`, `/tmp/.tcc_bak.db` | -- | TCC database manipulation artifacts |
| macOS | `/tmp/mail_accounts_smoke` | -- | Mail account probing artifact |
| macOS | `/tmp/_notes_tmp_NoteStore.sqlite*` | -- | Apple Notes exfiltration staging |
| macOS | `/tmp/_sc_finder_tmp` | -- | Finder-related staging artifact |
| macOS | `/tmp/safari_cookies*` | -- | Safari cookie exfiltration staging |
| macOS | `~/.local/share/.stream/` | -- | Stream module profile/key cache |
| macOS | `~/tempFolder-32555443/` | -- | Staging directory (FileGrabber, Notes) |
| macOS | `BUILD_V3_MARKER.txt` | -- | Build variant marker file |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | github.aoitour[.]com | Counterfeit GitHub delivery domain |
| Domain | debug.allllowef[.]space | C2 backend (Amnesia Panel) |
| URL Pattern | `hxxps://github.aoitour[.]com/` | Initial ClickFix landing page |
| URL Pattern | `/d/command?t=<token>&b=<build>` | Shell script delivery route |
| URL Pattern | `/api/bot/join` | Bot registration endpoint |
| URL Pattern | `/api/bot/actions?build_id=se&bot_id=<id>` | Tasking poll endpoint |
| URL Pattern | `/send/` | Data exfiltration endpoint |
| URL Pattern | `ws://<relay>/ws/stream/<build_id>?t=<token>` | WebSocket relay for browser control |

### Behavioral

- Process execution of hidden Mach-O binaries from `/tmp/.com.apple.dt.*` paths
- `xattr -d com.apple.quarantine` or `xattr -cr` on downloaded binaries
- `codesign --force --deep --sign -` ad-hoc signing of extracted payloads
- `dscl . -authonly` for local password validation
- `security unlock-keychain -p` for keychain access
- `sudo -S` with piped password for privilege escalation
- `mount_apfs -o nobrowse` for APFS snapshot mounting (TCC bypass)
- `sqlite3` injection into TCC database paths
- `killall tccd` to restart TCC daemon
- Headless Chromium launch with `--remote-debugging-port` and `--remote-allow-origins=*`
- WebSocket connections carrying JSON with `"type":"register"` and `"type":"status"` messages
- File creation in `~/.local/share/.stream/` directory hierarchy

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Victim pastes Base64-decoded command into Terminal via ClickFix |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell script dropper downloads and executes payload |
| T1059.002 | Command and Scripting Interpreter: AppleScript | Fallback AppleScript (`tempAppleScript.scpt`) for credential prompts |
| T1543.004 | Create or Modify System Process: Launch Daemon | Persistence via `/Library/LaunchDaemons/com.apple.ReportCrash.plist` |
| T1036.005 | Masquerading: Match Legitimate Name or Location | LaunchDaemon impersonates Apple CrashReporter; binary uses `.com.apple.dt.*` naming |
| T1553.002 | Subvert Trust Controls: Code Signing | Ad-hoc code signing to bypass macOS validation |
| T1555.001 | Credentials from Password Stores: Keychain | Keychain unlock and data extraction via `security` CLI |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Harvests cookies, logins, and Safe Storage keys from 16 Chromium browsers |
| T1539 | Steal Web Session Cookie | Extracts browser cookies and exports via CDP `Network.getAllCookies` |
| T1056.002 | Input Capture: GUI Input Capture | Native-looking password prompt with local validation via `dscl` |
| T1074.001 | Data Staged: Local Data Staging | Files staged in `/tmp/` and `~/tempFolder-32555443/` before exfiltration |
| T1005 | Data from Local System | Collects Apple Notes, documents, system information |
| T1113 | Screen Capture | Live screencast at ~3 fps via headless browser |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTP/HTTPS and WebSocket |
| T1041 | Exfiltration Over C2 Channel | Data uploaded via POST to `/send/` endpoint |
| T1548.004 | Abuse Elevation Control Mechanism: Elevated Execution with Prompt | Uses captured password with `sudo -S` for LaunchDaemon installation |
| T1070.003 | Indicator Removal: Clear Command History | Clears shell history after execution |
| T1562.001 | Impair Defenses: Disable or Modify Tools | TCC database modification and tccd restart to bypass permissions |
| T1185 | Browser Session Hijacking | CDP-based live remote control of cloned browser sessions |
| T1115 | Clipboard Data | Cryptocurrency clipper module monitors and replaces wallet addresses |

## Impact Assessment

AmnesiaStealer represents a significant escalation in macOS infostealer capabilities. The combination of comprehensive credential harvesting (16 browsers, keychain, cryptocurrency wallets, password managers), live browser session hijacking via CDP, and a builder-driven configuration framework indicates a mature malware-as-a-service operation. The Russian-language C2 panel and shared distribution templates with AMOS/MacSync suggest an Eastern European operator ecosystem. The stream_module capability -- enabling attackers to interact with authenticated web sessions in real time -- poses particular risk for cryptocurrency exchanges, banking portals, and enterprise SaaS applications where session cookies provide full account access. The malware's OS-version-branched logic for exploiting CVE-2020-9771 demonstrates active maintenance and adaptation to Apple's evolving security controls.

## Detection & Remediation

### Immediate Detection

Check for the presence of AmnesiaStealer artifacts:

```bash
# Check for LaunchDaemon persistence
ls -la /Library/LaunchDaemons/com.apple.ReportCrash.plist

# Check for staging files in /tmp
ls -la /tmp/.com.apple.dt.* /tmp/tempAppleScript.scpt /tmp/.snap_* /tmp/.tcc_* /tmp/starter 2>/dev/null

# Check for cleartext password cache
ls -la ~/.pwd /tmp/pwd 2>/dev/null

# Check for stream module artifacts
ls -la ~/.local/share/.stream/ 2>/dev/null

# Check for staging directory
ls -la ~/tempFolder-32555443/ 2>/dev/null

# Check for build marker
find /tmp -name "BUILD_V3_MARKER.txt" 2>/dev/null

# Check DNS logs for C2 domains
# Look for queries to: allllowef.space, aoitour.com
```

### Remediation

1. **Containment:** Isolate affected systems from the network immediately; revoke all browser sessions and rotate passwords for any accounts accessed on the compromised system
2. **LaunchDaemon removal:** Remove `/Library/LaunchDaemons/com.apple.ReportCrash.plist` (verify it is not the legitimate Apple plist from `/System/Library/`)
3. **Artifact cleanup:** Remove all staging files from `/tmp/` (`.com.apple.dt.*`, `.snap_*`, `.tcc_*`, `tempAppleScript.scpt`, `starter`, `pwd`, `_notes_tmp_*`, `safari_cookies*`, `mail_accounts_smoke`)
4. **Credential rotation:** Reset macOS login password; rotate all passwords stored in the keychain and browsers; invalidate cryptocurrency wallet sessions; rotate Telegram session tokens
5. **Browser remediation:** Reset Chrome Safe Storage keys to Apple-managed values; clear and rebuild browser profiles if Safe Storage was overwritten with the attacker's key
6. **TCC database repair:** Restore TCC databases from backup or reset permissions via System Preferences
7. **Financial monitoring:** Monitor cryptocurrency wallets for unauthorized transactions; check clipboard-dependent transfers made during the compromise window

### Long-Term Hardening

- Deploy endpoint detection and response (EDR) with specific monitoring for LaunchDaemon creation by non-Apple processes
- Enforce macOS Sequoia/26 which limits TCC bypass techniques used by this malware
- Block known C2 domains at the DNS/proxy layer
- Implement browser policies to prevent headless Chromium launch with `--remote-debugging-port`
- Train users to recognize ClickFix social engineering (Terminal paste instructions)
- Monitor for ad-hoc code signing activity on endpoints (`codesign --force --deep --sign -`)

## Detection Rules

These detections target AmnesiaStealer's specific infrastructure, persistence mechanism, and staging artifacts. PoC/advisory-specific altitude (default, strict). Compiling does not prove a rule fires in your pipeline -- verify against your telemetry before promoting to production.

### Sigma: AmnesiaStealer LaunchDaemon Persistence

Detects creation of the specific LaunchDaemon plist impersonating Apple CrashReporter, the persistence mechanism documented by Jamf Threat Labs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch 403 (proxy/network issue, not rule error); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keyed on exact plist path /Library/LaunchDaemons/com.apple.ReportCrash.plist with filter for legitimate /System/ origin. FP risk: very low — legitimate CrashReporter plists live under /System/Library/LaunchDaemons/, not /Library/LaunchDaemons/. -->
```yaml
title: AmnesiaStealer macOS LaunchDaemon Persistence via Fake CrashReporter
id: 7e3a4b2c-9f1d-4e8a-b6c5-d3f2a1e09874
status: experimental
description: >
    Detects creation or modification of a LaunchDaemon plist impersonating Apple's
    CrashReporter service, as used by AmnesiaStealer for persistence on macOS.
references:
    - https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/
    - https://www.bleepingcomputer.com/news/security/new-amnesiastealer-macos-malware-hijacks-browser-sessions-via-remote-control/
author: Actioner
date: 2026/08/18
tags:
    - attack.t1543.004
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/Library/LaunchDaemons/com.apple.ReportCrash.plist'
    filter_apple:
        Image|startswith: '/System/'
    condition: selection and not filter_apple
falsepositives:
    - Legitimate Apple system updates touching this plist (filtered by System path)
level: high
```

### Sigma: AmnesiaStealer C2 Domain DNS Query

Detects DNS queries to known AmnesiaStealer C2 and delivery domains documented in the Jamf Threat Labs analysis.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch 403 (proxy/network issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keyed on two campaign-specific domains. FP risk: negligible — these are attacker-registered infrastructure. -->
```yaml
title: AmnesiaStealer C2 Domain DNS Query
id: 9c4e7f3a-1b2d-4a6e-8d5c-f0e3b7a29816
status: experimental
description: >
    Detects DNS queries to known AmnesiaStealer command-and-control domains
    used for data exfiltration and operator tasking.
references:
    - https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/
    - https://thehackernews.com/2026/08/amnesiastealer-hijacks-chromium.html
author: Actioner
date: 2026/08/18
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'allllowef.space'
            - 'aoitour.com'
    condition: selection
falsepositives:
    - Unlikely; these domains are infrastructure-specific to this campaign
level: critical
```

### Sigma: AmnesiaStealer Staging File Creation in /tmp

Detects creation of characteristic AmnesiaStealer temporary staging files including hidden Apple-impersonating executables and TCC manipulation artifacts.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch 403 (proxy/network issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. The .com.apple.dt prefix selection may overlap with legitimate Apple developer tools (Xcode Instruments, etc.) — medium confidence reflects this potential FP surface. Specific staging file paths (.snap_read, .tcc_mod.db, etc.) are highly distinctive. -->
```yaml
title: AmnesiaStealer Staging File Creation in /tmp
id: a1d2e3f4-5b6c-7d8e-9f0a-1b2c3d4e5f60
status: experimental
description: >
    Detects creation of characteristic AmnesiaStealer temporary staging files in /tmp,
    including hidden Apple-impersonating executables and credential cache files.
references:
    - https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/
    - https://www.bleepingcomputer.com/news/security/new-amnesiastealer-macos-malware-hijacks-browser-sessions-via-remote-control/
author: Actioner
date: 2026/08/18
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: macos
detection:
    selection_apple_dt:
        TargetFilename|startswith: '/tmp/.com.apple.dt.'
    selection_staging_files:
        TargetFilename:
            - '/tmp/tempAppleScript.scpt'
            - '/tmp/starter'
            - '/tmp/.snap_read'
            - '/tmp/.snap_tcc'
            - '/tmp/.tcc_mod.db'
            - '/tmp/.tcc_bak.db'
            - '/tmp/mail_accounts_smoke'
    condition: selection_apple_dt or selection_staging_files
falsepositives:
    - Apple developer tools may create files with com.apple.dt prefix; correlate with other AmnesiaStealer indicators
level: medium
```

### Suricata: AmnesiaStealer C2 DNS and HTTP Indicators

Detects DNS queries to campaign-specific C2/delivery domains and HTTP patterns matching the bot registration and exfiltration endpoints.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (rev 2). Four rules: sid 2200101-2200104. DNS rules (2200101/2200102) key on campaign-specific domains with endswith; for precision. HTTP sid 2200103 now scoped to allllowef.space via http.host (rev 2 fix). HTTP sid 2200104 already scoped to allllowef.space. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - AmnesiaStealer C2 DNS Query to allllowef.space"; flow:to_server; dns.query; content:"allllowef.space"; endswith; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/; metadata:author Actioner, created_at 2026-08-18; sid:2200101; rev:2;)

alert dns $HOME_NET any -> any any (msg:"Actioner - AmnesiaStealer Delivery Domain DNS Query to aoitour.com"; flow:to_server; dns.query; content:"aoitour.com"; endswith; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/; metadata:author Actioner, created_at 2026-08-18; sid:2200102; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AmnesiaStealer C2 Bot Registration POST"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/bot/join"; fast_pattern; http.host; content:"allllowef.space"; classtype:trojan-activity; reference:url,www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/; metadata:author Actioner, created_at 2026-08-18; sid:2200103; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AmnesiaStealer C2 Data Exfiltration POST"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/send/"; fast_pattern; http.host; content:"allllowef.space"; classtype:trojan-activity; reference:url,www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/; metadata:author Actioner, created_at 2026-08-18; sid:2200104; rev:1;)
```

### Snort: N/A

Snort 3 is not available in this environment for compile validation. The Suricata rules above cover the same network indicators (C2 DNS and HTTP patterns) and compile cleanly.

### YARA: AmnesiaStealer macOS Mach-O Strings

Detects AmnesiaStealer Mach-O binaries via the XOR key, hardcoded Safe Storage password, build markers, and C2 API paths embedded in analyzed samples.
**Status:** compile ✅ compiles · confidence: high · sample: not tested (synthetic string validation only)
<!-- audit: yarac exit 0. Positive test used a constructed file containing published strings, not a real malware sample — relabeled accordingly. Negative test: no match on benign file. Condition requires (xor_key AND safe_storage_pw) OR (build_marker AND build_variant) OR 4-of-13 campaign strings — multiple independent clusters reduce evasion surface. Confidence remains high: strings are campaign-unique per Jamf Threat Labs analysis. -->
```yara
rule Malware_AmnesiaStealer_macOS_Strings
{
    meta:
        description = "Detects AmnesiaStealer macOS infostealer via characteristic embedded strings and configuration markers"
        author = "Actioner"
        date = "2026-08-18"
        reference = "https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/"
        hash = "de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a"
        severity = "critical"

    strings:
        $xor_key = "4mn3s1a_2o26!xK" ascii
        $safe_storage_pw = "pqz8N3vKxRmY2aLcQ" ascii
        $build_marker = "BUILD_V3_MARKER.txt" ascii
        $build_variant = "v3_shell_chrome" ascii
        $debug_prefix = "[HYBRID_DEBUG]" ascii
        $config_clipper = "CLIPPER_ENABLED" ascii
        $config_encryption = "ENCRYPTION_KEY" ascii
        $module_stream = "stream_module" ascii
        $c2_path_join = "/api/bot/join" ascii
        $c2_path_actions = "/api/bot/actions" ascii
        $ws_register = "\"type\":\"register\"" ascii
        $tcc_msg = "Safari container fully protected by TCC" ascii
        $fallback_msg = "provision fallback (destructive)" ascii

    condition:
        filesize < 15MB and
        (
            ($xor_key and $safe_storage_pw) or
            ($build_marker and $build_variant) or
            (4 of ($c2_path*, $ws_register, $debug_prefix, $config_*, $module_stream)) or
            ($tcc_msg and $fallback_msg)
        )
}
```

## Lessons Learned

1. **ClickFix is becoming the dominant macOS social engineering vector.** The technique of instructing users to paste commands into Terminal bypasses all traditional download-based protections (Gatekeeper, notarization, XProtect). Organizations should consider blocking Terminal paste functionality or implementing EDR rules that alert on Base64-decoded execution from Terminal.

2. **Browser session hijacking via CDP is a new frontier for macOS malware.** AmnesiaStealer is the first documented macOS malware to combine profile cloning with live CDP-based remote control. This capability transforms a one-time credential theft into persistent, real-time account access -- particularly dangerous for cryptocurrency exchanges and banking portals. Defenders should monitor for headless Chromium processes with `--remote-debugging-port` flags.

3. **Builder-driven configuration indicates MaaS maturity.** The `v3_shell_chrome` build variant, encrypted configuration blobs, and Russian-language Amnesia Panel demonstrate that macOS infostealer toolkits have reached the same level of professionalization as their Windows counterparts. The shared distribution templates across AMOS, MacSync, and AmnesiaStealer suggest a common builder or operator ecosystem.

4. **macOS 26 is forcing stealer evolution.** The OS-version-branched logic and "provision fallback (destructive)" Safe Storage strategy show attackers actively adapting to Apple's tightening security controls. The fallback of overwriting Safe Storage keys with attacker-controlled values is a creative (if destructive) workaround that trading victim access for attacker access.

## Sources

- [Jamf Threat Labs Blog](https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/) — primary technical analysis with IOCs, hashes, and detailed behavioral breakdown
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-amnesiastealer-macos-malware-hijacks-browser-sessions-via-remote-control/) — initial coverage with C2 domain details and stream module description
- [The Hacker News](https://thehackernews.com/2026/08/amnesiastealer-hijacks-chromium.html) — coverage with file paths, persistence details, and cryptocurrency clipper information
- [SecurityWeek](https://www.securityweek.com/amnesiastealer-macos-malware-steals-data-controls-browser-sessions/) — analysis of CDP-based browser control and CVE-2020-9771 usage
- [CSO Online](https://www.csoonline.com/article/4210464/new-macos-malware-turns-stolen-browsers-into-attacker-controlled-sessions.html) — delivery mechanism details and universal binary analysis
- [Rescana](https://www.rescana.com/post/amnesiastealer-macos-malware-advanced-browser-session-hijacking-via-remote-control-and-github-supply-chain-attacks) — supply chain attack context and browser hijacking analysis
- [BrinzTech](https://www.brinztech.com/breach-alerts/brinztech-alert-amnesiastealer-multi-stage-rust-infostealer-targets-macos-users-via-counterfeit-github-pages) — XOR key details and builder framework analysis

---
*Report generated by Actioner*
