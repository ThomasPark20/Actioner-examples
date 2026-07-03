# Technical Analysis Report: PamStealer macOS Infostealer (2026-07-03)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-03
Version: 1.1 (FINAL)

## Executive Summary

PamStealer is a macOS information stealer discovered by Jamf Threat Labs researcher Thijs Xhaflaire. It is distributed as a compiled AppleScript file (Maccy.scpt) inside disk images served from typosquatted domains impersonating Maccy, a legitimate open-source clipboard manager. The attack chain is two-stage: a JXA-based dropper executed within Script Editor downloads a Rust-compiled arm64 Mach-O binary that steals browser credentials, cryptocurrency wallet data, iCloud Keychain contents, and clipboard history. The stealer validates the victim's macOS login password locally through the PAM API, re-prompting until correct credentials are supplied. Exfiltration uses ChaCha20-Poly1305 encryption over HTTPS to a Cloudflare-fronted endpoint at avenger-sync[.]live.

The malware targets Apple Silicon Macs exclusively, uses environment fingerprinting (CPU architecture, locale, keyboard layout, timezone) to derive decryption keys for its configuration, and actively excludes hosts in Eastern European/CIS countries. It achieves persistence via dual login item registration and coerces Full Disk Access through a fake system alert. After completing data theft, it displays a counterfeit Gatekeeper alert telling the victim the application is damaged.

## Background: Maccy Clipboard Manager

Maccy (maccy[.]app) is a lightweight, open-source clipboard manager for macOS. Its popularity and simple utility-app profile make it an attractive lure for social engineering. The legitimate developer, Alex Rodionov, has added warnings to the official GitHub repository and website following disclosure. PamStealer exploits user trust in this well-known tool by registering lookalike domains (maccyapp[.]com, maccyapp[.]net) that serve trojanized disk images.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-2026-07-03 | Threat actors register maccyapp[.]com and maccyapp[.]net, hosting fake Maccy download pages |
| Pre-2026-07-03 | Jamf Threat Labs researcher Thijs Xhaflaire identifies and analyzes samples |
| 2026-07-03 | Jamf Threat Labs publishes technical analysis |
| 2026-07-03 | The Hacker News reports on the threat |
| 2026-07-03 | Maccy developer adds security warnings to official site and GitHub |

## Root Cause: Typosquatting and Social Engineering

PamStealer gains initial access through typosquatted domains mimicking the legitimate Maccy website. Users searching for "Maccy" or reaching the fake site via search engine results or social media links download a disk image containing the malicious Maccy.scpt file. The compiled AppleScript executes within Script Editor, which processes AppleScript files despite the com.apple.quarantine extended attribute. The lure text uses homoglyphs (Greek/Cyrillic characters mimicking Latin) and instructs the user to press Command+R or click the Run button.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: AppleScript/JXA Dropper (Maccy.scpt)

The initial payload is a compiled AppleScript file that wraps a JavaScript for Automation (JXA) payload. When executed in Script Editor, it performs the following:

**Environment fingerprinting and configuration decryption:**
- Derives a host fingerprint from CPU architecture, locale, keyboard layout, and timezone
- Uses this fingerprint as a decryption key for an integrity-checked configuration
- Configuration is keyed to Apple Silicon only; Intel hosts receive keys that fail decryption, silently terminating execution

**Region-based exclusion (three independent signals):**
- System timezone: `Europe/Moscow`, `Europe/Minsk`, `Asia/Almaty`
- Locale country codes: RU, BY, KZ, AM, AZ, KG, MD, TJ, UZ, TM, GE
- Keyboard layouts: Russian, Belarusian, Kazakh, and other regional layouts

**Anti-analysis measures:**
- Anti-debugging checks
- System Integrity Protection (SIP) status inspection
- Environment-aware config prevents execution in sandboxed/analysis environments

**Download and staging:**
- Uses NSURLSession (native Objective-C API via JXA bridge) rather than curl/osascript/zsh to download the second-stage payload
- Validates the response (checks for non-empty body) before writing
- Writes the Mach-O as an executable under `~/Library/Application Support/com.apple.finder.core/Finder.app/Contents/MacOS/`
- Copies genuine Finder.icns as the application icon
- Configures the bundle to run hidden (no window, no Dock presence)
- Ad-hoc signs the bundle: `codesign -fs - --deep`
- Exits early if payload is already present on disk

**Build variability:** Automated builder evidence shows cosmetic details (names, obfuscated values) change per build while core behaviors remain constant. Alternative bundle identifiers observed include `com.apple.finder.monitor` and `com.apple.security.daemon`, with alternative app names like "Software Update.app".

### 2. Stage 2: Rust-Based Infostealer

The second-stage payload is a stripped arm64 Mach-O binary compiled from Rust. Strings are decoded at runtime to minimize static analysis surface.

**Credential theft:**
- Bundles SQLite for direct database access to browser credential, cookie, and wallet-extension databases
- Loads Security.framework at runtime (not statically linked) to access Keychain data while hiding the import from static analysis

**Clipboard theft:**
- Spawns the `pbpaste` utility repeatedly at irregular intervals (under 10 seconds to ~90 seconds, typically 10-30 seconds)
- This is a continuous harvest, not a single snapshot

**PAM-based password capture:**
- Displays a native NSAlert with a secure text field styled to resemble a system authorization prompt
- Title: "Maccy wants to make changes"
- Message: "Enter your password to allow this"
- Account name is pre-filled
- Validates credentials locally via PAM API calls: `pam_start` -> `pam_authenticate` -> `pam_end`
- Re-prompts on validation failure; only continues when correct password is supplied
- No child processes are spawned for validation (no dscl, security, osascript)

**Persistence (dual login item registration):**
- Modern API: ServiceManagement (SMAppService)
- Legacy API: Shared file list (LSSharedFileListInsertItemURL against kLSSharedFileListSessionLoginItems)
- An embedded arm64 Mach-O helper (~34 KB) is dropped to `/private/tmp/System Settings`
- Made executable via chmod(), launched by parent with bundle path as argument
- Helper impersonates macOS System Settings, checks existing login items before registering to avoid duplicates

**Full Disk Access coercion:**
- After a variable delay (up to ~40 minutes), displays a counterfeit system alert styled with the Finder icon
- Claims "Finder has lost access to protected data" with an "Open Settings" button
- Opens System Settings directly to the Full Disk Access pane
- If granted, enables access to protected locations without further prompts

**Post-theft decoy:**
- Displays a fake Gatekeeper alert: "'Maccy' is damaged and can't be opened. You should move it to the Trash"
- Styled as a close copy of the genuine macOS message to create the impression of a corrupted download

### 3. C2 Infrastructure

**Primary exfiltration endpoint:** `hxxps://avenger-sync[.]live/api/sync`

**Communication details:**
- HTTP POST with `application/json` content type
- Stock CFNetwork user agent (not custom)
- Cloudflare-fronted infrastructure
- ChaCha20-Poly1305 encryption with keys derived at runtime (not persisted), distinct keys within a single run
- Payload wrapped in JSON envelope: `{"data":"..."}`
- Distinctive marker string: `MacOSapp1{"data":""}`
- Internal configuration identifier: `avenger-config-v2`

**Blockchain infrastructure integration:**
- Ethereum RPC endpoints found in decrypted config: `eth.drpc.org` and `ethereum-rpc.publicnode[.]com`
- The second-stage process (running as "Finder") connects to `ethereum-rpc.publicnode[.]com`
- Purpose unclear: potentially resilient C2 via on-chain data or cryptocurrency wallet reconnaissance

### 4. Platform-Specific Behavior

#### macOS (Apple Silicon only)

PamStealer is macOS-exclusive and specifically targets Apple Silicon (arm64) Macs. Intel-based systems cannot decrypt the configuration and execution terminates silently. No Windows or Linux variants have been observed.

### 5. Anti-Forensics / Evasion Techniques

- **Environment-keyed configuration:** Configuration decryption fails on non-matching hardware/locale, preventing analysis on Intel Macs or in many sandbox environments
- **Region exclusion:** Skips execution in CIS/Eastern European countries (common among financially motivated threat actors to avoid domestic law enforcement)
- **Anti-debugging:** Active anti-debugging checks in the dropper stage
- **SIP inspection:** Checks System Integrity Protection status
- **Runtime string decoding:** Rust binary strings decoded at runtime, not present as static artifacts
- **Dynamic framework loading:** Security.framework loaded at runtime rather than statically linked
- **Process-free credential validation:** PAM API called directly without spawning observable child processes
- **NSURLSession over shell tools:** Uses native Objective-C APIs for downloads instead of curl/wget, avoiding command-line logging
- **Homoglyph lure text:** Uses Greek/Cyrillic characters to mimic Latin in the lure instructions
- **Build polymorphism:** Automated builder changes cosmetic identifiers per build

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Maccy.scpt | N/A (compiled AppleScript) | Trojanized clipboard manager lure; compiled AppleScript wrapping JXA dropper |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| macOS | ~/Library/Application Support/com.apple.finder.core/Finder.app | Not published | Staged fake Finder bundle containing Rust stealer |
| macOS | ~/Library/Application Support/com.apple.finder.core/Finder.app/Contents/MacOS/77617EA0 | Not published | Second-stage Rust binary |
| macOS | /private/tmp/System Settings | Not published | Persistence helper (~34 KB arm64 Mach-O) |
| macOS | ~/Library/Caches/com.apple.finder.core/Cache.db | N/A | NSURLCache database; forensic artifact containing C2 metadata |
| macOS | .Maccy | N/A | Marker file alongside staged bundle |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | maccyapp[.]com | Fake Maccy distribution site |
| Domain | maccyapp[.]net | Alternative fake Maccy distribution site |
| Domain | avenger-sync[.]live | C2 exfiltration server (Cloudflare-fronted) |
| URL Pattern | hxxps://avenger-sync[.]live/api/sync | C2 exfiltration endpoint |
| Domain | eth[.]drpc[.]org | Ethereum JSON-RPC endpoint from decrypted config |
| Domain | ethereum-rpc[.]publicnode[.]com | Ethereum JSON-RPC endpoint, actively contacted by stealer |

### Behavioral

- Script Editor spawning `codesign` against a bundle inside `~/Library/Application Support/com.apple.finder.*`
- Process impersonating Finder running from `~/Library/Application Support/`, repeatedly spawning `pbpaste` at 10-30 second intervals
- NSURLCache artifacts under Script Editor profile (`~/Library/Caches/com.apple.ScriptEditor2/`)
- Executable named "System Settings" running from `/private/tmp/` and registering login items
- Native password prompt displayed by a non-system process invoking PAM API (pam_start, pam_authenticate, pam_end)
- Counterfeit Gatekeeper alert claiming application is damaged, displayed after data exfiltration
- ChaCha20-Poly1305 encrypted JSON payloads with `MacOSapp1` marker sent to external HTTPS endpoint
- Process connecting to Ethereum RPC endpoints from `~/Library/Application Support/` directory

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1583.001 | Acquire Infrastructure: Domains | Typosquatted domains maccyapp[.]com and maccyapp[.]net registered to impersonate legitimate maccy[.]app |
| T1204.002 | User Execution: Malicious File | User instructed to open Maccy.scpt in Script Editor and press Run |
| T1059.002 | Command and Scripting Interpreter: AppleScript | Compiled AppleScript wrapping JXA payload executed in Script Editor |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JXA (JavaScript for Automation) dropper using NSURLSession |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Fake Finder.app staged in com.apple.finder.core, helper as "System Settings" |
| T1553.002 | Subvert Trust Controls: Code Signing | Ad-hoc code signing (codesign -fs - --deep) of malicious bundle |
| T1547.015 | Boot or Logon Autostart Execution: Login Items | Dual persistence via SMAppService (modern) and LSSharedFileListInsertItemURL (legacy) |
| T1056.002 | Input Capture: GUI Input Capture | Native NSAlert password prompt styled as system authorization dialog |
<!-- revision: dropped T1556.003 — PamStealer calls PAM API to validate a captured password, it does not modify PAM modules or configuration. Credential capture is covered by T1056.002 (GUI Input Capture). -->
| T1115 | Clipboard Data | Repeated pbpaste spawning at 10-30 second intervals |
| T1555.001 | Credentials from Password Stores: Keychain | Security.framework loaded at runtime for Keychain access |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SQLite-based browser credential database access |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encrypted C2 exfiltration |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST to /api/sync with JSON envelope |
| T1132.001 | Data Encoding: Standard Encoding | JSON-wrapped encrypted payloads with MacOSapp1 marker |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Environment fingerprinting, anti-debug, SIP checks, sandbox detection |
| T1614.001 | System Location Discovery: System Language Discovery | Timezone, locale, and keyboard layout checks for CIS exclusion |

## Impact Assessment

PamStealer targets individual macOS users seeking free clipboard manager software. The stealer harvests a comprehensive set of credentials and sensitive data: browser passwords and cookies, cryptocurrency wallet extensions, iCloud Keychain credentials, clipboard contents (continuous), and the user's macOS login password (validated via PAM). If Full Disk Access is granted, the scope expands to Mail, Messages, Time Machine backups, and other protected data stores. The malware's Apple Silicon exclusivity limits its reach to Macs from late 2020 onward, but this covers the majority of actively used Macs. The CIS country exclusion and Cloudflare-fronted infrastructure suggest a financially motivated operation. No specific victim counts or telemetry have been published.

## Detection & Remediation

### Immediate Detection

Check for the presence of PamStealer filesystem artifacts:

```bash
# Check for fake Finder bundle in Application Support
ls -la ~/Library/Application\ Support/com.apple.finder.core/ 2>/dev/null
ls -la ~/Library/Application\ Support/com.apple.finder.monitor/ 2>/dev/null
ls -la ~/Library/Application\ Support/com.apple.security.daemon/ 2>/dev/null

# Check for persistence helper in /private/tmp
ls -la "/private/tmp/System Settings" 2>/dev/null

# Check for marker file
find ~ -maxdepth 3 -name ".Maccy" -type f 2>/dev/null

# Check for NSURLCache artifacts from the stealer
ls -la ~/Library/Caches/com.apple.finder.core/Cache.db 2>/dev/null

# Check for Script Editor network cache (dropper artifact)
ls -la ~/Library/Caches/com.apple.ScriptEditor2/ 2>/dev/null

# Check login items for suspicious entries
sfltool dumpbtm 2>/dev/null | grep -i "finder\|com.apple.finder.core\|com.apple.security.daemon"

# Check for active processes impersonating Finder from unusual locations
ps aux | grep -v "/System/Library" | grep "Finder"
```

### Remediation

1. **Kill malicious processes:** Terminate any process running as "Finder" from `~/Library/Application Support/` and any "System Settings" process from `/private/tmp/`
2. **Remove staged bundles:** Delete `~/Library/Application Support/com.apple.finder.core/`, `com.apple.finder.monitor/`, and `com.apple.security.daemon/` directories
3. **Remove persistence helper:** Delete `/private/tmp/System Settings`
4. **Remove login items:** Use System Settings > General > Login Items to remove any suspicious Finder or Software Update entries
5. **Clear caches:** Delete `~/Library/Caches/com.apple.finder.core/` and check `~/Library/HTTPStorages/com.apple.finder.core/`
6. **Rotate credentials:** Change macOS login password immediately; rotate all browser-saved passwords; revoke and regenerate cryptocurrency wallet keys; change iCloud password and enable/refresh 2FA
7. **Revoke Full Disk Access:** Review and remove any unrecognized entries in System Settings > Privacy & Security > Full Disk Access
8. **Check clipboard history:** Review any clipboard manager data for sensitive information that may have been exfiltrated

### Long-Term Hardening

- Configure endpoint security tools to alert on processes spawning from `~/Library/Application Support/` directories with Apple-mimicking bundle identifiers
- Block known malicious domains (maccyapp[.]com, maccyapp[.]net, avenger-sync[.]live) at the network perimeter
- Use application allowlisting to prevent execution of ad-hoc signed binaries from non-standard locations
- Educate users to verify software download sources, particularly for free utilities (maccy.app is the only legitimate Maccy domain)
- Deploy endpoint detection rules for Script Editor spawning codesign or network-accessing child processes
- Monitor for PAM API usage by non-system processes (unusual for standard macOS applications)

## Detection Rules

These detections target PamStealer's distinctive host-level behaviors and network C2 infrastructure. PoC/advisory-specific altitude (strict); all rules compile and convert cleanly. Note: no file hashes were published by Jamf, so YARA rules key on string artifacts from the analysis rather than sample hashes -- verify in your pipeline before production deployment.

### Sigma: PamStealer Fake Finder Spawning pbpaste

Detects a process impersonating Finder running from a `com.apple.finder` Application Support path and repeatedly spawning `pbpaste`, the stealer's clipboard theft mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK network fetch blocked, not a rule error); splunk convert exit 0; log_scale convert exit 0. Field names are macOS process_creation standard (ParentImage, Image). No pipeline available for macOS logsource. Values are real paths, not defanged. -->
```yaml
title: PamStealer macOS Fake Finder Process Spawning pbpaste
id: 7a3c1e9d-4f2b-48e6-a1d5-b8c6f3e20a74
status: experimental
description: >
    Detects a process impersonating Finder running from Application Support and
    repeatedly spawning pbpaste, consistent with PamStealer clipboard theft behavior.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html
author: Actioner
date: 2026/07/03
tags:
    - attack.t1115
    - attack.t1036.005
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|contains: '/Library/Application Support/com.apple.finder'
        Image|endswith: '/pbpaste'
    condition: selection
falsepositives:
    - Legitimate automation scripts running from Application Support directories
level: high
```

### Sigma: PamStealer Script Editor Spawning Codesign

Detects Script Editor spawning codesign to ad-hoc sign a bundle inside Application Support, a distinctive PamStealer dropper staging behavior.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK network fetch blocked, not a rule error); splunk convert exit 0; log_scale convert exit 0. Three-field conjunction (ParentImage, Image, CommandLine) provides high specificity. No macOS pipeline for schema mapping. -->
```yaml
title: PamStealer Script Editor Spawning Codesign for Application Support Bundle
id: 2d8a6f1c-5b3e-49d7-8c4a-e9f0d2a71b36
status: experimental
description: >
    Detects Script Editor spawning codesign to ad-hoc sign a bundle inside
    Application Support, consistent with PamStealer staging its fake Finder payload.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html
author: Actioner
date: 2026/07/03
tags:
    - attack.t1059.002
    - attack.t1553.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|endswith: '/Script Editor'
        Image|endswith: '/codesign'
        CommandLine|contains: '/Library/Application Support/'
    condition: selection
falsepositives:
    - Developers using Script Editor to sign legitimate scripts
level: high
```

### Sigma: PamStealer System Settings Helper in /private/tmp

Detects execution of a binary named "System Settings" from /private/tmp, the exact path where PamStealer drops its persistence registration helper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK network fetch blocked, not a rule error); splunk convert exit 0; log_scale convert exit 0. Exact path match provides maximum specificity with zero expected benign hits (legitimate System Settings runs from /System/Applications). -->
```yaml
title: PamStealer System Settings Helper in Private Tmp
id: 9e5b2c8a-1d4f-47a3-b6e9-c3d0f8a52e17
status: experimental
description: >
    Detects execution of a binary named System Settings from /private/tmp,
    consistent with PamStealer dropping its persistence helper to register login items.
references:
    - https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/
    - https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html
author: Actioner
date: 2026/07/03
tags:
    - attack.t1547.015
    - attack.t1036.005
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image: '/private/tmp/System Settings'
    condition: selection
falsepositives:
    - None expected - legitimate System Settings runs from /System/Applications
level: critical
```

### Snort: PamStealer C2 Exfiltration to avenger-sync.live

Detects HTTP traffic to the PamStealer C2 domain avenger-sync.live with the /api/sync exfiltration URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf (Snort 2.9.20) with rule in local.rules: "Snort successfully validated the configuration!" Host header + URI path conjunction; domain IOC is campaign-specific with no benign overlap. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PamStealer C2 Exfiltration to avenger-sync.live"; flow:established,to_server; content:"avenger-sync.live"; http_header; fast_pattern; content:"/api/sync"; http_uri; sid:2100010; rev:1; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/;)
```

### Suricata: PamStealer C2 Exfiltration to avenger-sync.live

Detects HTTP traffic to avenger-sync.live/api/sync using Suricata's dot-notation sticky buffers for precise host and URI matching.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0, Suricata 7.0.3. http.host + http.uri dot-notation buffers; campaign-specific domain IOC. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PamStealer C2 Exfiltration to avenger-sync.live"; flow:established,to_server; http.host; content:"avenger-sync.live"; http.uri; content:"/api/sync"; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-03; sid:2200010; rev:1;)
```

### Suricata: PamStealer DNS Query for Fake Maccy Site

Detects DNS queries for the fake Maccy distribution domain maccyapp.com used to deliver the PamStealer dropper.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0, Suricata 7.0.3. dns.query buffer with campaign-specific typosquat domain. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer DNS Query for Fake Maccy Distribution Site"; flow:to_server; dns.query; content:"maccyapp.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-03; sid:2200011; rev:1;)
```

### Suricata: PamStealer DNS Query for C2 Domain

Detects DNS queries for the PamStealer C2 domain avenger-sync.live.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0, Suricata 7.0.3. dns.query buffer with campaign-specific C2 domain. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - PamStealer DNS Query for C2 Domain avenger-sync.live"; flow:to_server; dns.query; content:"avenger-sync.live"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/; metadata:author Actioner, created_at 2026-07-03; sid:2200012; rev:1;)
```

### YARA: PamStealer macOS AppleScript Dropper

Detects PamStealer dropper or stealer binaries via distinctive string artifacts including the `MacOSapp1` C2 marker, `avenger-config-v2` config identifier, and PAM API strings combined with fake Apple bundle identifiers.
**Status:** compile ✅ compiles · confidence: medium · sample: fired (constructed positive from published strings)
<!-- audit: yarac exit 0. Two rules in file: PamStealer_macOS_AppleScript_Dropper (generic file, no Mach-O gate) and PamStealer_macOS_Rust_Stealer (Mach-O gated via magic bytes). Constructed positive test file containing published strings: fired on PamStealer_macOS_AppleScript_Dropper rule; quiet on negative. Confidence medium because no sample hashes published by Jamf, so string presence is inferred from analysis text rather than verified against a known sample. -->
```yara
rule PamStealer_macOS_AppleScript_Dropper
{
    meta:
        description = "Detects PamStealer compiled AppleScript dropper via distinctive strings and Mach-O markers"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        severity = "high"

    strings:
        $marker1 = "MacOSapp1" ascii
        $marker2 = "avenger-config-v2" ascii
        $marker3 = "avenger-sync" ascii
        $c2_path = "/api/sync" ascii
        $pam1 = "pam_start" ascii
        $pam2 = "pam_authenticate" ascii
        $pam3 = "pam_end" ascii
        $bundle1 = "com.apple.finder.core" ascii
        $bundle2 = "com.apple.finder.monitor" ascii
        $bundle3 = "com.apple.security.daemon" ascii
        $helper = "System Settings" ascii wide

    condition:
        filesize < 10MB and
        (
            ($marker1 and $c2_path) or
            ($marker2) or
            (2 of ($pam*) and 1 of ($bundle*)) or
            ($marker3 and 1 of ($bundle*)) or
            ($helper and 1 of ($bundle*))
        )
}

rule PamStealer_macOS_Rust_Stealer
{
    meta:
        description = "Detects PamStealer Rust-based macOS infostealer via PAM API usage combined with clipboard theft and C2 markers"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/"
        severity = "critical"

    strings:
        $pam1 = "pam_start" ascii
        $pam2 = "pam_authenticate" ascii
        $pam3 = "pam_end" ascii
        $clip = "pbpaste" ascii
        $c2_marker = "MacOSapp1" ascii
        $c2_config = "avenger-config-v2" ascii
        $c2_domain = "avenger-sync.live" ascii
        $bundle_path1 = "com.apple.finder.core" ascii
        $bundle_path2 = "com.apple.finder.monitor" ascii
        $prompt = "wants to make changes" ascii wide

    condition:
        (uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACF) and
        filesize < 10MB and
        (
            (all of ($pam*) and $clip) or
            ($c2_marker and $c2_config) or
            ($c2_domain and 1 of ($bundle_path*)) or
            ($prompt and 1 of ($pam*))
        )
}
```

## Lessons Learned

PamStealer demonstrates several concerning trends in macOS threat evolution. First, the use of compiled AppleScript as a delivery vector highlights a gap in macOS security: Script Editor processes AppleScript files despite quarantine attributes, providing a viable Gatekeeper bypass. Second, the direct PAM API invocation for password validation is a stealthier approach than spawning observable child processes (dscl, security) -- defenders monitoring process trees will miss this technique. Third, the build-polymorphism infrastructure suggests a mature operation capable of generating unique variants at scale, making hash-based detection unreliable (and notably, Jamf did not publish sample hashes). Fourth, the Ethereum RPC integration hints at potential on-chain C2 resilience or cryptocurrency-focused reconnaissance, an emerging pattern worth monitoring. Defenders should prioritize behavioral detection (process ancestry, file paths, clipboard access patterns) over static indicators given the polymorphic nature of the threat.

## Sources

- [Jamf Threat Labs Blog - PamStealer Analysis](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/) -- primary technical analysis by Thijs Xhaflaire; detailed attack chain, PAM abuse mechanism, and C2 protocol
- [The Hacker News - PamStealer Report](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html) -- secondary reporting with summary of Jamf findings
- [Maccy Official Site](https://maccy.app) -- legitimate clipboard manager being impersonated; confirms security warning added

---
*Report generated by Actioner*
