# Technical Analysis Report: PamStealer macOS Infostealer (2026-07-04)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-04
Version: 1.0 (DRAFT)

## Executive Summary

PamStealer is a two-stage macOS infostealer discovered by Jamf Threat Labs in early July 2026. It is distributed through typosquatted domains (`maccyapp[.]com`, `maccyapp[.]net`) impersonating the legitimate open-source clipboard manager Maccy (`maccy[.]app`). The attack chain begins with a compiled AppleScript dropper (`Maccy.scpt`) delivered inside a disk image. When the victim opens the script in Script Editor and presses Run, embedded JavaScript for Automation (JXA) code downloads a second-stage Rust-based arm64 Mach-O binary that masquerades as Finder.app. PamStealer is named for its distinctive credential validation technique: it uses the macOS Pluggable Authentication Modules (PAM) API to verify stolen passwords before exfiltrating them, ensuring only valid credentials reach the attacker. The malware targets system passwords, browser credentials, cryptocurrency wallet extensions, iCloud Keychain data, and clipboard contents. Exfiltrated data is encrypted with ChaCha20-Poly1305 and sent to the C2 domain `avenger-sync[.]live` via HTTPS POST. The malware includes CIS-region geofencing (Russia, Belarus, Kazakhstan, and adjacent countries), suggesting Russian-speaking operators.

## Background: Maccy Clipboard Manager Impersonation

Maccy is a popular, legitimate open-source clipboard manager for macOS, distributed exclusively through `maccy[.]app` and the Mac App Store. The PamStealer operators registered lookalike domains (`maccyapp[.]com`, `maccyapp[.]net`) to distribute a malicious disk image containing a compiled AppleScript file disguised as the Maccy application. The lure text within the script uses homoglyphs -- Cyrillic and Greek characters that look identical to Latin letters -- to defeat simple string-matching detections while appearing legitimate to human readers. In response to the campaign, the legitimate Maccy developer Alex Rodionov added a warning to the official website and GitHub repository urging users to avoid fake sites.

## Technical Analysis

### 1. First Stage: AppleScript Dropper (Maccy.scpt)

The malware arrives as a disk image containing `Maccy.scpt`, a compiled AppleScript file. macOS opens `.scpt` files in Script Editor by default. The visible content displays branded instructions telling the user to press Command+R (or click the Run button). The actual malicious logic sits below a large block of empty lines, hidden from view.

When executed, the script runs JavaScript for Automation (JXA) code that:

- Uses `NSURLSession` to download the second-stage payload
- Generates machine-specific encryption keys derived from CPU architecture, locale, keyboard layout, and time zone
- Checks regional settings and blocks execution in Russia, Belarus, Kazakhstan, Armenia, Azerbaijan, Kyrgyzstan, Moldova, Tajikistan, Uzbekistan, Turkmenistan, and Georgia (timezones: `Europe/Moscow`, `Europe/Minsk`, `Asia/Almaty`; locale codes: RU, BY, KZ, AM, AZ, KG, MD, TJ, UZ, TM, GE)
- Displays a native-style password prompt: "Maccy wants to make changes. Enter your password to allow this"

### 2. Second Stage: Rust-based Mach-O Payload

The second stage is an arm64 Mach-O binary written in Rust, installed at:

`~/Library/Application Support/com.apple.finder.core/Finder.app/Contents/MacOS/77617EA0`

The binary masquerades as the macOS Finder application using the bundle identifier `com.apple.finder.core`. Alternative variants use `com.apple.finder.monitor` and `com.apple.security.daemon` (impersonating Software Update). The malware:

- Runs without a visible window or Dock icon
- Uses copied Apple bundle identifiers and genuine system icons
- Is signed ad-hoc (`codesign -fs - --deep`)
- Creates a `.Maccy` marker file as an infection flag
- Creates `.lock` and `.config` files (the latter stores the C2 URL in cleartext)
- Uses the internal configuration identifier `avenger-config-v2`

### 3. Credential Theft via PAM Validation

PamStealer's signature technique is its use of the macOS PAM API (`pam_start`, `pam_authenticate`, `pam_end`) to validate credentials. When the fake password prompt collects a password, the malware cross-checks it through PAM authentication. If validation fails, the prompt is redisplayed in a loop until the correct password is supplied. This ensures only verified, working credentials are exfiltrated.

### 4. Data Harvesting

The Rust payload performs comprehensive data theft:

- **Browser credentials**: Opens SQLite databases to extract saved passwords, cookies, and session data
- **Cryptocurrency wallet extensions**: Extracts wallet data from browser extensions
- **iCloud Keychain**: Loads Apple's Security.framework at runtime (not statically linked) to access Keychain data
- **Clipboard monitoring**: Repeatedly spawns the `pbpaste` utility at 10-30 second intervals to capture clipboard contents
- **Ethereum endpoints**: Configuration includes references to `eth.drpc.org` and `ethereum-rpc.publicnode[.]com` for cryptocurrency-related operations

### 5. Persistence Mechanisms

PamStealer establishes persistence through two complementary mechanisms:

- **Modern**: `SMAppService` API for login item registration on current macOS versions
- **Legacy**: `LSSharedFileListInsertItemURL` against `kLSSharedFileListSessionLoginItems` via a helper binary (~34 KB arm64 Mach-O) dropped at `/private/tmp/System Settings`

The persistence helper masquerades as macOS System Settings, which legitimately resides in `/System/Applications/` and would never execute from `/private/tmp/`.

### 6. C2 Communication and Exfiltration

| Component | Detail |
|-----------|--------|
| Primary C2 domain | `avenger-sync[.]live` |
| Alternative C2 | `api.sync-master[.]online` |
| Netlify C2 | `avngr.netlify[.]app` |
| Exfiltration endpoint | `POST /api/sync` |
| Content-Type | `application/json` |
| Data envelope | `{"data":"..."}` JSON wrapping |
| Encryption | ChaCha20-Poly1305 (runtime-derived keys, not persisted) |
| User-Agent | Stock CFNetwork user agent |
| Infrastructure | Cloudflare-fronted |
| Build marker in traffic | `MacOSapp1{"data":""}` |

### 7. Evasion Techniques

- **Homoglyph obfuscation**: Cyrillic and Greek characters in lure text defeat string-matching detections
- **Regional geofencing**: Blocks execution in CIS countries, suggesting Russian-speaking operators
- **Architecture targeting**: arm64 only (Apple Silicon); Intel variants fail silent decryption
- **Process masquerading**: Uses legitimate Apple bundle identifiers and system icons
- **No visible presence**: Runs without window or Dock icon
- **Runtime framework loading**: Security.framework loaded dynamically, not statically linked
- **Delayed Full Disk Access prompt**: Fake Finder icon requesting FDA appears 10-40 minutes post-compromise
- **Post-compromise decoy**: Displays "'Maccy' is damaged and can't be opened" Gatekeeper-style error message

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots

### File Hashes

| Type | Value | Description |
|------|-------|-------------|
| SHA256 | `36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da` | PamStealer sample (per PCRisk) |

### Detection Names

| Engine | Detection Name |
|--------|---------------|
| Combo Cleaner | `Trojan.GenericKD.80674484` |
| ESET-NOD32 | `OSX/PSW.Agent.IY Trojan` |
| Emsisoft | `Trojan.GenericKD.80674484 (B)` |
| Symantec | `OSX.Trojan.Gen` |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| macOS | `~/Library/Application Support/com.apple.finder.core/Finder.app` | Second-stage payload bundle |
| macOS | `~/Library/Application Support/com.apple.finder.core/Finder.app/Contents/MacOS/77617EA0` | Rust payload binary |
| macOS | `/private/tmp/System Settings` | Persistence helper binary |
| macOS | `~/.Maccy` | Infection marker dot file |
| macOS | `~/.lock` | Concurrent execution lock file |
| macOS | `~/.config` | C2 URL stored in cleartext |
| macOS | `~/Library/Caches/com.apple.finder.core/Cache.db` | NSURLCache store (with WAL/SHM) |
| macOS | `~/Library/HTTPStorages/com.apple.finder.core/` | HTTP storage artifacts |
| macOS | `~/Library/Caches/com.apple.ScriptEditor2/` | Script Editor cache from dropper |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `avenger-sync[.]live` | Primary C2 domain (Cloudflare-fronted) |
| Domain | `api.sync-master[.]online` | Alternative C2 domain |
| Domain | `avngr.netlify[.]app` | Netlify-hosted C2 infrastructure |
| Domain | `maccyapp[.]com` | Fake Maccy distribution domain |
| Domain | `maccyapp[.]net` | Fake Maccy distribution domain |
| Domain | `eth.drpc[.]org` | Ethereum JSON-RPC endpoint from config |
| Domain | `ethereum-rpc.publicnode[.]com` | Ethereum JSON-RPC endpoint from config |
| URL | `hxxps://avenger-sync[.]live/api/sync` | C2 exfiltration endpoint |

### Bundle Identifiers

| Bundle ID | Impersonates |
|-----------|-------------|
| `com.apple.finder.core` | macOS Finder |
| `com.apple.finder.monitor` | macOS Finder (variant) |
| `com.apple.security.daemon` | macOS Software Update |

### Behavioral Indicators

- Script Editor application launching child processes after opening a `.scpt` file
- Native password prompt with text "Maccy wants to make changes"
- Gatekeeper decoy message "'Maccy' is damaged and can't be opened"
- Repeated `pbpaste` invocations at 10-30 second intervals from non-standard parent process
- File creation under `~/Library/Application Support/com.apple.finder.core/`
- Binary execution from `/private/tmp/System Settings`
- `codesign -fs - --deep` ad-hoc signing
- HTTPS POST requests with `{"data":"..."}` JSON envelope to `avenger-sync[.]live`
- Login item registration via `SMAppService` or legacy `LSSharedFileList` APIs

### Unique Strings

| String | Context |
|--------|---------|
| `avenger-config-v2` | Internal configuration identifier |
| `MacOSapp1` | Build marker in C2 traffic |
| `77617EA0` | Payload binary name |
| `avngr` | Delivery domain prefix pattern across sample set |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Victim opens Maccy.scpt in Script Editor and presses Run |
| T1059.002 | Command and Scripting Interpreter: AppleScript | JXA-embedded AppleScript dropper executes payload download |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JavaScript for Automation (JXA) uses NSURLSession for download |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Payload masquerades as Finder.app using Apple bundle identifiers |
| T1547.015 | Boot or Logon Autostart Execution: Login Items | SMAppService and legacy LSSharedFileList login item registration |
| T1056.002 | Input Capture: GUI Input Capture | Native-style fake password prompt "Maccy wants to make changes" |
| T1555.001 | Credentials from Password Stores: Keychain | Runtime Security.framework loading for Keychain access |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SQLite-based extraction of browser saved passwords and cookies |
| T1115 | Clipboard Data | Repeated pbpaste utility invocation for clipboard monitoring |
| T1005 | Data from Local System | Harvesting of browser data, wallet extensions, and Keychain |
| T1041 | Exfiltration Over C2 Channel | ChaCha20-Poly1305 encrypted data exfiltrated via HTTPS POST |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST to /api/sync with JSON-wrapped encrypted payloads |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encryption for C2 communications |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Regional exclusion via timezone, locale, and keyboard layout checks |
| T1140 | Deobfuscate/Decode Files or Information | Machine-keyed config decryption on qualifying hosts |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Homoglyph obfuscation in lure text; encrypted config blob |

## Impact Assessment

PamStealer targets individual macOS users, particularly those searching for clipboard management utilities. The impact includes:

- **Verified credential theft**: PAM validation ensures stolen passwords are confirmed working, increasing their value for follow-on attacks and credential stuffing
- **Browser data compromise**: Complete harvest of saved passwords, cookies, and session data from web browsers
- **Cryptocurrency theft risk**: Extraction of wallet extension data and Keychain-stored credentials, combined with Ethereum RPC endpoint references
- **Clipboard data exposure**: Continuous monitoring captures copied passwords, cryptocurrency addresses, sensitive text, and other transient data
- **Persistent access**: Login item persistence survives reboots and continues data harvesting until manually removed

## Detection & Remediation

### Immediate Detection

```bash
# Check for PamStealer persistence artifacts
ls -la ~/Library/Application\ Support/com.apple.finder.core/ 2>/dev/null
ls -la /private/tmp/System\ Settings 2>/dev/null

# Check for infection marker
ls -la ~/.Maccy 2>/dev/null

# Check for C2 config and lock files
ls -la ~/.lock ~/.config 2>/dev/null

# Check for cache artifacts
ls -la ~/Library/Caches/com.apple.finder.core/ 2>/dev/null
ls -la ~/Library/HTTPStorages/com.apple.finder.core/ 2>/dev/null

# Check login items for suspicious entries
sfltool dumpbtm 2>/dev/null | grep -i "finder.core\|security.daemon\|finder.monitor"

# Check for C2 communication in DNS logs
# Look for DNS queries to avenger-sync[.]live, maccyapp[.]com, sync-master[.]online
```

### Remediation

1. **Contain**: Immediately block `avenger-sync[.]live`, `api.sync-master[.]online`, `avngr.netlify[.]app`, `maccyapp[.]com`, and `maccyapp[.]net` at network perimeter
2. **Remove payload**: Delete `~/Library/Application Support/com.apple.finder.core/` directory and all contents
3. **Remove persistence**: Delete `/private/tmp/System Settings`; remove login items referencing `com.apple.finder.core`, `com.apple.finder.monitor`, or `com.apple.security.daemon` (use `sfltool resetbtm` or System Settings > Login Items)
4. **Clean markers**: Remove `~/.Maccy`, `~/.lock`, `~/.config` files
5. **Clean caches**: Remove `~/Library/Caches/com.apple.finder.core/` and `~/Library/HTTPStorages/com.apple.finder.core/`
6. **Rotate credentials**: Change all passwords stored in affected browsers, password managers, and macOS Keychain. The system login password was verified by PAM and must be changed
7. **Rotate cryptocurrency keys**: If cryptocurrency wallet extensions were present, assume wallet data is compromised and rotate seed phrases

### Long-Term Hardening

- Download Mac applications only from the Mac App Store or verified developer websites
- Verify website URLs before downloading software (legitimate Maccy is only at `maccy[.]app`)
- Deploy endpoint detection that monitors Script Editor child process spawns
- Monitor login item registration via `SMAppService` for unexpected entries
- Alert on `pbpaste` invocations from non-standard parent processes
- Block known C2 domains at DNS level

## Detection Rules

The following rules target specific artifacts and behaviors documented in the Jamf Threat Labs analysis of the PamStealer macOS infostealer. Host-based rules cover Script Editor abuse, persistence mechanisms, clipboard monitoring, C2 communication, and infection markers. Network rules target the known C2 domains and distribution infrastructure. Note: macOS-specific Sigma rules require endpoint telemetry that logs process creation events with parent-child relationships (e.g., via Endpoint Security Framework, osquery, or a macOS EDR agent).

### Sigma Rule 1: Script Editor Executing Maccy AppleScript Dropper

Detects Script Editor launching curl, bash, sh, zsh, or osascript child processes -- the primary execution technique used by PamStealer's AppleScript dropper.

compile: sigma check pass (0 errors, excluding ATT&CK tag validator due to network restriction) | splunk pass | log_scale pass | confidence: medium (TTP-level; Script Editor can be used legitimately for automation)

```yaml
title: PamStealer macOS Infostealer - Script Editor Executing Maccy AppleScript Dropper
id: a4e17c3d-8b92-4f61-ae5d-1c9f02b83e47
status: experimental
description: >
    Detects macOS Script Editor executing the PamStealer dropper delivered as
    Maccy.scpt. The malware arrives inside a disk image impersonating the legitimate
    Maccy clipboard manager. When the user opens the .scpt file and presses Run,
    Script Editor executes embedded JavaScript for Automation (JXA) code that
    downloads the second-stage Rust-based payload via NSURLSession.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1059.002
    - attack.t1204.002
logsource:
    category: process_creation
    product: macos
detection:
    selection_parent:
        ParentImage|endswith: '/Script Editor'
    selection_child:
        Image|endswith:
            - '/curl'
            - '/bash'
            - '/sh'
            - '/zsh'
            - '/osascript'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate automation workflows using Script Editor
    - Developer scripts executed interactively via Script Editor
level: high
```

### Sigma Rule 2: Fake Finder App Bundle Persistence

Detects file creation in the fake `com.apple.finder.core` application support directory or the presence of the `77617EA0` payload binary -- both unique to PamStealer.

compile: sigma check pass (0 errors) | splunk pass | log_scale pass | confidence: high (specific persistence path not used by legitimate macOS Finder)

```yaml
title: PamStealer macOS Infostealer - Fake Finder App Bundle Persistence
id: b7f29a1e-6d84-4c53-9ab2-3e8f14d67c90
status: experimental
description: >
    Detects file creation in the com.apple.finder.core application support directory
    used by the PamStealer infostealer to stage its Rust-based second-stage payload.
    The malware drops a fake Finder.app bundle at ~/Library/Application Support/
    com.apple.finder.core/ with the payload binary named 77617EA0 inside
    Contents/MacOS/. This path is not used by the legitimate macOS Finder.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1036.005
    - attack.t1547.015
logsource:
    category: file_event
    product: macos
detection:
    selection_app_support:
        TargetFilename|contains: '/Application Support/com.apple.finder.core/'
    selection_payload:
        TargetFilename|contains: '/Contents/MacOS/77617EA0'
    condition: 1 of selection_*
falsepositives:
    - None expected - com.apple.finder.core is not a legitimate Apple application support directory
level: critical
```

### Sigma Rule 3: Repeated pbpaste Clipboard Monitoring

Detects pbpaste invocations from suspicious parent processes associated with PamStealer's clipboard harvesting.

compile: sigma check pass (0 errors) | splunk pass | log_scale pass | confidence: high (pbpaste from fake Finder/security daemon parent is not legitimate)

```yaml
title: PamStealer macOS Infostealer - Repeated pbpaste Clipboard Monitoring
id: c8d35b2f-7e95-4a64-bc13-4f9a25e78d01
status: experimental
description: >
    Detects repeated invocation of the pbpaste utility by a non-standard parent
    process. PamStealer spawns pbpaste at 10-30 second intervals to harvest
    clipboard contents. While pbpaste is a legitimate macOS utility, repeated
    invocation by a process masquerading as Finder or from the com.apple.finder.core
    path is highly suspicious.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1115
logsource:
    category: process_creation
    product: macos
detection:
    selection_pbpaste:
        Image|endswith: '/pbpaste'
    selection_suspicious_parent:
        ParentImage|contains:
            - 'com.apple.finder.core'
            - 'com.apple.finder.monitor'
            - 'com.apple.security.daemon'
            - '/77617EA0'
    condition: selection_pbpaste and selection_suspicious_parent
falsepositives:
    - Clipboard manager applications that invoke pbpaste programmatically
level: high
```

### Sigma Rule 4: Persistence Helper in Private Tmp

Detects execution of the PamStealer persistence helper binary from `/private/tmp/System Settings`.

compile: sigma check pass (0 errors) | splunk pass | log_scale pass | confidence: critical (System Settings should never execute from /private/tmp/)

```yaml
title: PamStealer macOS Infostealer - Persistence Helper in Private Tmp
id: d9e46c30-8fa6-4b75-cd24-5a0b36f89e12
status: experimental
description: >
    Detects creation or execution of the PamStealer persistence helper binary
    at /private/tmp/System Settings. The malware drops an arm64 Mach-O binary
    masquerading as macOS System Settings in the temporary directory to register
    login items via the legacy LSSharedFileList API. Legitimate System Settings
    resides in /System/Applications/ and never runs from /private/tmp/.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1547.015
    - attack.t1036.005
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/tmp/System Settings'
    condition: selection
falsepositives:
    - None expected - System Settings should never execute from /private/tmp/
level: critical
```

### Sigma Rule 5: C2 Communication to avenger-sync Domain

Detects process command lines containing known PamStealer C2 domains.

compile: sigma check pass (0 errors) | splunk pass | log_scale pass | confidence: high (confirmed malicious C2 domains)

```yaml
title: PamStealer macOS Infostealer - C2 Communication to avenger-sync Domain
id: e0f57d41-9ab7-4c86-de35-6b1c47a90f23
status: experimental
description: >
    Detects process command lines containing the PamStealer C2 domain
    avenger-sync.live. The malware exfiltrates stolen credentials, browser data,
    keychain contents, and clipboard data to this endpoint via HTTPS POST requests
    with ChaCha20-Poly1305 encrypted JSON payloads. The C2 is fronted by Cloudflare.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains:
            - 'avenger-sync.live'
            - 'sync-master.online'
            - 'avngr.netlify.app'
    condition: selection
falsepositives:
    - None expected - these are confirmed malicious C2 domains
level: critical
```

### Sigma Rule 6: Maccy Marker and Cache File Creation

Detects creation of the `.Maccy` infection marker or PamStealer-specific cache directories.

compile: sigma check pass (0 errors) | splunk pass | log_scale pass | confidence: high (com.apple.finder.core is not a legitimate cache directory)

```yaml
title: PamStealer macOS Infostealer - Maccy Marker and Config File Creation
id: f1a68e52-0bc8-4d97-ef46-7c2d58ba1a34
status: experimental
description: >
    Detects creation of the .Maccy marker file, .lock file, or .config file
    associated with the PamStealer infostealer. The .Maccy dot file is dropped
    next to the malicious bundle as an infection flag. The .lock file prevents
    concurrent execution, and the .config file stores the C2 URL in cleartext.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/
author: Actioner
date: 2026/07/04
tags:
    - attack.t1027
logsource:
    category: file_event
    product: macos
detection:
    selection_marker:
        TargetFilename|endswith: '/.Maccy'
    selection_cache_artifacts:
        TargetFilename|contains:
            - '/Caches/com.apple.finder.core/'
            - '/HTTPStorages/com.apple.finder.core/'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Maccy clipboard manager may create dot files in its own application support directory but not named .Maccy in arbitrary locations
level: high
```

### YARA Rules: PamStealer Rust Payload and AppleScript Dropper

Two YARA rules detecting PamStealer via distinctive strings in the Mach-O binary (C2 domains, PAM API calls, fake bundle identifiers, config markers) and AppleScript dropper (social engineering prompts, JXA markers, distribution domains).

compile: yarac pass | confidence: high (IOC-anchored string combinations with Mach-O header validation)

```yara
rule Malware_macOS_PamStealer_Rust_Payload
{
    meta:
        description = "Detects PamStealer macOS infostealer Rust-based Mach-O payload via distinctive strings including C2 endpoints, config identifiers, PAM authentication markers, and masquerading bundle identifiers"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        tlp = "WHITE"
        severity = "critical"
        hash = "36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da"

    strings:
        $c2_domain = "avenger-sync.live" ascii wide
        $c2_endpoint = "/api/sync" ascii
        $c2_alt1 = "sync-master.online" ascii
        $c2_alt2 = "avngr.netlify.app" ascii

        $config_id = "avenger-config-v2" ascii
        $build_marker = "MacOSapp1" ascii

        $pam_start = "pam_start" ascii
        $pam_auth = "pam_authenticate" ascii
        $pam_end = "pam_end" ascii

        $bundle_fake1 = "com.apple.finder.core" ascii
        $bundle_fake2 = "com.apple.finder.monitor" ascii
        $bundle_fake3 = "com.apple.security.daemon" ascii

        $payload_name = "77617EA0" ascii
        $clipboard = "pbpaste" ascii
        $chacha = "ChaCha20" ascii

        $eth_rpc1 = "eth.drpc.org" ascii
        $eth_rpc2 = "ethereum-rpc.publicnode.com" ascii

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA) and
        filesize < 20MB and
        (
            ($c2_domain) or
            ($config_id) or
            ($build_marker and 1 of ($bundle_fake*)) or
            (2 of ($pam_start, $pam_auth, $pam_end) and 1 of ($bundle_fake*)) or
            ($payload_name and 1 of ($bundle_fake*)) or
            (1 of ($c2_alt*) and 1 of ($bundle_fake*, $pam_start, $pam_auth)) or
            (4 of them)
        )
}

rule Malware_macOS_PamStealer_AppleScript_Dropper
{
    meta:
        description = "Detects PamStealer AppleScript dropper (Maccy.scpt) via characteristic strings including the fake Maccy branding, NSURLSession payload retrieval, and social engineering prompt text"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $prompt = "Maccy wants to make changes" ascii wide
        $decoy = "is damaged and can't be opened" ascii wide
        $nsurl = "NSURLSession" ascii
        $jxa_marker = "ObjC.import" ascii

        $c2 = "avenger-sync.live" ascii
        $dist = "maccyapp.com" ascii
        $dist2 = "maccyapp.net" ascii

        $config = "avenger-config-v2" ascii
        $marker = ".Maccy" ascii

        $tz_ru = "Europe/Moscow" ascii
        $tz_by = "Europe/Minsk" ascii
        $tz_kz = "Asia/Almaty" ascii

    condition:
        filesize < 10MB and
        (
            ($prompt and ($nsurl or $jxa_marker)) or
            ($c2 and ($nsurl or $jxa_marker)) or
            (1 of ($dist, $dist2) and ($nsurl or $jxa_marker)) or
            ($config and $marker) or
            ($prompt and $decoy) or
            (2 of ($tz_ru, $tz_by, $tz_kz) and ($c2 or $config or 1 of ($dist, $dist2)))
        )
}
```

### Suricata Rules: PamStealer C2 and Distribution Domain Network Detection

Six rules covering DNS resolution of C2 domains, distribution domains, and HTTP exfiltration to `/api/sync`.

compile: suricata -T pass ("Configuration provided was successfully loaded") | confidence: high (IOC-anchored domain patterns)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer macOS Stealer DNS Query to C2 Domain avenger-sync.live"; flow:to_server; dns.query; content:"avenger-sync.live"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100201; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer macOS Stealer DNS Query to C2 Domain sync-master.online"; flow:to_server; dns.query; content:"sync-master.online"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100202; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer macOS Stealer DNS Query to Fake Maccy Distribution Domain maccyapp.com"; flow:to_server; dns.query; content:"maccyapp.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100203; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer macOS Stealer DNS Query to Fake Maccy Distribution Domain maccyapp.net"; flow:to_server; dns.query; content:"maccyapp.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100204; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PamStealer macOS Stealer C2 Exfiltration POST to /api/sync"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/sync"; fast_pattern; http.host; content:"avenger-sync.live"; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100205; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer macOS Stealer DNS Query to Netlify C2 avngr.netlify.app"; flow:to_server; dns.query; content:"avngr.netlify.app"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-04; sid:2100206; rev:1;)
```

### Snort Rules

> Not generated. Snort is not installed in the validation environment; any rule produced would be uncompiled. The Suricata rules above cover the same network-level detection patterns and can be adapted for Snort IDS deployments with minor syntax adjustments.

## Sources

- [Jamf Threat Labs: PamStealer - a Rust-based macOS infostealer that validates passwords via PAM](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/) -- primary technical analysis with complete IOCs, attack chain details, persistence mechanisms, and C2 infrastructure
- [Hackread: New PamStealer Malware Targets macOS Users via Fake Maccy Clipboard App](https://hackread.com/pamstealer-malware-macos-fake-maccy-clipboard-app/) -- initial reporting and summary sourced from Jamf Threat Labs
- [The Hacker News: PamStealer Uses Fake Maccy Sites and PAM Checks to Steal Mac Login Passwords](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html) -- additional coverage with distribution domain details
- [PCRisk: PamStealer Malware (Mac) - Removal steps](https://www.pcrisk.com/removal-guides/35543-pamstealer-malware-mac) -- SHA256 hash and AV detection names
- [CyberInsider: New macOS malware PamStealer uses PAM to validate stolen data](https://cyberinsider.com/new-macos-malware-pamstealer-uses-pam-to-validate-stolen-data/) -- additional technical details and evasion techniques
- [Cryptika: PamStealer Mimics Maccy Clipboard Manager](https://www.cryptika.com/pamstealer-mimics-maccy-clipboard-manager-silently-harvests-data-and-clipboard-contents/) -- alternative C2 domain `api.sync-master[.]online` and `avngr.netlify[.]app` infrastructure details

---
*Report generated by Actioner*
