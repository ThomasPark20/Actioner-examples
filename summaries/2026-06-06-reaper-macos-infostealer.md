# Technical Analysis Report: Reaper (SHub) macOS Infostealer (2026-06-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-06
Version: 1.1 (FINAL)

## Executive Summary

Reaper is a new variant of the SHub macOS infostealer family, first documented by SentinelOne in May 2026. It impersonates Apple, Google, and Microsoft within a single multi-stage attack chain to steal browser credentials, cryptocurrency wallet data, macOS Keychain secrets, and high-value documents. What distinguishes Reaper from earlier SHub variants and other macOS stealers is its abuse of the native macOS Script Editor via the `applescript://` URL scheme, bypassing Terminal-based protections introduced in macOS Tahoe 26.4. The malware establishes persistence by masquerading as Google Software Update and maintains a 60-second C2 heartbeat beacon. Stolen data is exfiltrated in chunked ZIP archives via curl to an external C2 server. The malware includes a CIS-region block, suggesting the operators are Russian-speaking threat actors.

## Background: macOS Script Editor as an Attack Vector

macOS Script Editor is a built-in application for creating and running AppleScript automation scripts. Unlike Terminal, which Apple hardened in macOS Tahoe 26.4 with user confirmation prompts for pasted commands, Script Editor can be launched programmatically via the `applescript://` URL scheme with pre-populated code. Reaper exploits this gap: rather than requiring users to open Terminal and paste malicious commands (the "ClickFix" technique), it directly opens Script Editor with the payload hidden beneath extensive ASCII art and whitespace. When the user clicks "Run," the obfuscated AppleScript silently executes the attack chain.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05 (est.) | Reaper variant first observed by SentinelOne |
| 2026-05-18 | Moonlock publishes detailed analysis |
| 2026-05-19 | SentinelOne publishes primary technical blog post |
| 2026-05-19 | Multiple outlets report on the threat |

## Root Cause: Social Engineering via Fake Application Installers

The attack begins when a victim visits a fake installer website for popular applications such as WeChat or Miro. These sites are hosted on typo-squatted domains designed to impersonate legitimate vendors (e.g., `mlcrosoft[.]co[.]com` impersonating Microsoft, `mlroweb[.]com` impersonating Miro, `qq-0732gwh22[.]com` impersonating WeChat). The websites employ anti-analysis measures including a continuous debugger loop blocking F12, console function overriding, DevTools detection with a Russian-language "Access Denied" overlay, WebGL fingerprinting, and VPN/VM detection.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery via Script Editor Abuse

When the victim clicks the fake installer link, the site triggers the `applescript://` URL scheme, which launches macOS Script Editor pre-populated with the malicious payload. The malicious AppleScript commands are pushed far below the visible portion of the Script Editor window using extensive ASCII art and arbitrary whitespace injection. This obfuscation ensures the user sees only innocuous-looking content. When the user clicks "Run," the hidden script executes.

The AppleScript displays a fake dialog purporting to be an Apple XProtectRemediator security update, referencing the path `support[.]apple[.]com/downloads/xprotect-remediator-150.dmg`. While the user enters their login credentials in response to this prompt, the script silently executes curl commands to download the second-stage payload.

### 2. Second Stage: Shell Script Execution and Data Theft

The downloaded shell script performs comprehensive data harvesting:

**Browser credential theft**: Targets Chrome, Firefox, Brave, Edge, Opera, Vivaldi, Arc, and Orion browsers, extracting saved passwords, cookies, and session data.

**Browser extension harvesting**: Enumerates and extracts data from password managers and crypto wallet extensions including 1Password, Bitwarden, LastPass, MetaMask, and Phantom.

**macOS Keychain and iCloud**: Accesses stored credentials from the macOS Keychain and iCloud account data.

**Telegram session theft**: Extracts Telegram session data for account hijacking.

**Filegrabber module**: Searches the user's Desktop and Documents folders for files likely to contain business or financial value. Targeted extensions include: `.docx`, `.doc`, `.wallet`, `.key`, `.keys`, `.txt`, `.rtf`, `.csv`, `.xls`, `.xlsx`, `.json`, `.rdp`. Files under 2MB are collected; `.png` images under 6MB are included. Total collection is capped at 150MB.

### 3. Cryptocurrency Wallet Hijacking

Reaper goes beyond simple credential theft by actively hijacking desktop cryptocurrency wallet applications. It targets Exodus, Atomic Wallet, Ledger Wallet, Ledger Live, Electrum, and Trezor Suite. The malware:

1. Downloads modified `app.asar` files from the C2 (e.g., `exodus_asar.zip`)
2. Terminates the running wallet process
3. Replaces the application's internal code with the trojanized version
4. Clears quarantine attributes using `xattr -cr`
5. Applies ad hoc code signing to the modified application

This ensures continued theft of cryptocurrency funds even after the initial infection payload completes.

### 4. C2 Infrastructure

| Component | Detail |
|-----------|--------|
| Primary C2 domain | `hebsbsbzjsjshduxbs[.]xyz` |
| Exfiltration endpoint | `/gate/chunk` |
| Beacon endpoint | `/api/bot/heartbeat` |
| Telemetry endpoint | `/api/debug/event` |
| Beacon interval | 60 seconds |
| Exfil method | curl POST with chunked ZIP archives |
| Archive threshold | 85MB triggers splitting into 70MB chunks |
| Staging directory | `/tmp/shub_<random>/` |
| Split utility | `/tmp/shub_split.sh` |
| Archive naming | `/tmp/shub_mzip_*.zip` |

### 5. Persistence Mechanism

Reaper establishes persistence by creating a directory structure that mimics Google Software Update:

- **Backdoor binary**: `~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate` (Base64-encoded bash script)
- **LaunchAgent plist**: `~/Library/LaunchAgents/com.google.keystone.agent.plist`
- **Ephemeral script**: `/tmp/.c.sh`

The LaunchAgent executes the GoogleUpdate script every 60 seconds. This script functions as a beacon, sending system details to the C2's `/api/bot/heartbeat` endpoint and checking for additional command payloads.

### 6. Anti-Forensics / Evasion Techniques

- **CIS region block**: The stub script queries `~/Library/Preferences/com.apple.HIToolbox.plist` for Russian input sources. If detected, it sends a `cis_blocked` telemetry event to `/api/debug/event` and exits, indicating Russian-speaking operators.
- **Script Editor abuse**: Bypasses Terminal-based paste protections in macOS Tahoe 26.4.
- **ASCII art obfuscation**: Hides malicious AppleScript below the visible window area.
- **Brand impersonation**: Cycles through Apple (XProtectRemediator), Microsoft (typo-squatted domain), and Google (fake GoogleUpdate) disguises at different stages.
- **Anti-debugging websites**: F12 blocking, console override, DevTools detection, WebGL fingerprinting, VPN/VM detection.
- **Quarantine bypass**: Uses `xattr -cr` to strip quarantine attributes from modified wallet applications.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File Hashes

| Type | Value | Description |
|------|-------|-------------|
| Build ID (SHA256) | `6552824c59ddacb134073f24a4bd4724514a938a9dc59f1733503642faed3bd3` | Reaper build identifier |
| Build Hash (MD5) | `c917fcf8314228862571f80c9e4a871e` | Hardcoded build hash in payload |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| macOS | `~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate` | Persistence backdoor binary |
| macOS | `~/Library/LaunchAgents/com.google.keystone.agent.plist` | Persistence LaunchAgent |
| macOS | `/tmp/shub_<random>/` | Data staging directory |
| macOS | `/tmp/shub_split.sh` | Archive splitting script |
| macOS | `/tmp/shub_mzip_*.zip` | Chunked exfil archives |
| macOS | `/tmp/.c.sh` | Ephemeral backdoor script |
| macOS | `/tmp/*_asar.zip` | Downloaded wallet payloads |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `hebsbsbzjsjshduxbs[.]xyz` | Primary C2 server |
| Domain | `mlcrosoft[.]co[.]com` | Fake Microsoft typo-squatted lure domain |
| Domain | `mlroweb[.]com` | Fake Miro lure domain |
| Domain | `qq-0732gwh22[.]com` | Fake WeChat lure domain |
| URL Pattern | `hxxps://hebsbsbzjsjshduxbs[.]xyz/gate/chunk` | Data exfiltration endpoint |
| URL Pattern | `hxxps://hebsbsbzjsjshduxbs[.]xyz/api/bot/heartbeat` | Beacon check-in endpoint |
| URL Pattern | `hxxps://hebsbsbzjsjshduxbs[.]xyz/api/debug/event` | Telemetry/debugging endpoint |
| Spoofed URL | `support[.]apple[.]com/downloads/xprotect-remediator-150.dmg` | Fake Apple update dialog reference |

### Behavioral

- Script Editor application spawning curl, bash, or osascript child processes
- Files created under `/tmp/shub_*` directory tree
- LaunchAgent creation for `com.google.keystone.agent.plist` outside Chrome installation context
- Repeated HTTP POST requests to `/gate/chunk` at regular intervals
- 60-second interval HTTP requests to `/api/bot/heartbeat`
- `xattr -cr` executed against cryptocurrency wallet application paths
- Modified `app.asar` files in Exodus, Atomic, Ledger, or Trezor application directories

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.001 | User Execution: Malicious Link | Fake installer websites lure victims to click links triggering applescript:// URL scheme |
| T1059.002 | Command and Scripting Interpreter: AppleScript | Payload delivered and executed via Script Editor using applescript:// scheme |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Anti-analysis JavaScript on lure websites (debugger loops, DevTools detection) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell scripts downloaded and executed for data harvesting |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Persistence binary masquerades as Google Software Update |
| T1543.001 | Create or Modify System Process: Launch Agent | LaunchAgent com.google.keystone.agent.plist created for persistence |
| T1555.001 | Credentials from Password Stores: Keychain | macOS Keychain credentials accessed |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser saved passwords stolen from Chrome, Firefox, Brave, Edge, Opera, Vivaldi, Arc, Orion |
| T1005 | Data from Local System | Filegrabber searches Desktop and Documents for valuable files |
| T1074.001 | Data Staged: Local Data Staging | Data staged in /tmp/shub_* directory before exfiltration |
| T1560.001 | Archive Collected Data: Archive via Utility | Data compressed into chunked ZIP archives |
| T1041 | Exfiltration Over C2 Channel | ZIP archives uploaded via curl to C2 /gate/chunk endpoint |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for C2 heartbeat and data exfiltration |
| T1554 | Compromise Host Software Binary | Desktop crypto wallet applications modified with trojanized app.asar files post-compromise |
| T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | xattr -cr used to clear quarantine attributes on modified applications |

## Impact Assessment

Reaper targets individual macOS users, primarily those interested in cryptocurrency. The impact includes:

- **Credential theft**: Complete harvest of browser-stored credentials, password manager data, and macOS Keychain secrets across 8+ browsers
- **Cryptocurrency loss**: Active wallet hijacking ensures ongoing theft of funds even after initial infection cleanup, unless wallet applications are fully reinstalled
- **Document exfiltration**: Business and financial documents stolen from Desktop/Documents (up to 150MB)
- **Persistent backdoor**: 60-second beacon interval provides ongoing access for additional payload delivery
- **Session hijacking**: Telegram session data enables account takeover

## Detection & Remediation

### Immediate Detection

```bash
# Check for Reaper persistence artifacts
ls -la ~/Library/Application\ Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate
ls -la ~/Library/LaunchAgents/com.google.keystone.agent.plist

# Check for staging artifacts
ls -la /tmp/shub_* 2>/dev/null
ls -la /tmp/.c.sh 2>/dev/null
ls -la /tmp/*_asar.zip 2>/dev/null

# Check for C2 communication in network logs
# Look for DNS queries to hebsbsbzjsjshduxbs[.]xyz
# Look for HTTP POST to /gate/chunk or /api/bot/heartbeat

# Check LaunchAgent plist content - verify it points to GoogleUpdate path
plutil -p ~/Library/LaunchAgents/com.google.keystone.agent.plist 2>/dev/null
```

### Remediation

1. **Contain**: Immediately block `hebsbsbzjsjshduxbs[.]xyz`, `mlcrosoft[.]co[.]com`, `mlroweb[.]com`, and `qq-0732gwh22[.]com` at network perimeter
2. **Remove persistence**: Delete `~/Library/LaunchAgents/com.google.keystone.agent.plist` and `~/Library/Application Support/Google/GoogleUpdate.app/` (verify it is the malicious version, not a legitimate Google installation)
3. **Clean staging**: Remove `/tmp/shub_*`, `/tmp/.c.sh`, `/tmp/*_asar.zip`, `/tmp/shub_split.sh`
4. **Reinstall wallets**: Completely uninstall and reinstall any cryptocurrency wallet applications (Exodus, Atomic, Ledger Live, Trezor Suite, Electrum). Do NOT trust existing installations -- app.asar files may be trojanized
5. **Rotate credentials**: Change all passwords stored in affected browsers, password managers, and macOS Keychain. Revoke and regenerate cryptocurrency wallet seed phrases if wallet hijacking is confirmed
6. **Revoke sessions**: Terminate active Telegram sessions and re-authenticate

### Long-Term Hardening

- Disable the `applescript://` URL scheme if not required for business operations
- Deploy endpoint detection that monitors Script Editor child process spawns
- Monitor LaunchAgent creation in `~/Library/LaunchAgents/` for unexpected entries
- Implement network monitoring for large chunked uploads and connections to high-entropy .xyz domains
- Educate users about fake installer websites and the risk of running scripts from untrusted sources

## Detection Rules

The following rules target specific artifacts and behaviors documented in the SentinelOne and Moonlock analyses of the Reaper (SHub) macOS infostealer. Host-based rules cover Script Editor abuse, persistence mechanisms, staging directory creation, C2 communication, and wallet hijacking. Network rules target the known C2 domain and its endpoints, as well as lure domains. Note: macOS-specific Sigma rules require endpoint telemetry that logs process creation events with parent-child relationships (e.g., via Endpoint Security Framework, osquery, or a macOS EDR agent).

### Sigma Rule 1: Script Editor Spawning Suspicious Child Processes

Detects Script Editor launching curl, bash, sh, zsh, or osascript -- the primary execution technique used by Reaper to bypass Terminal protections.

compile: sigma check pass | splunk pass | log_scale pass | confidence: medium (TTP-level; Script Editor can be used legitimately for automation)

```yaml
title: Reaper macOS Stealer - Script Editor Spawning Suspicious Processes
id: 7bf778ef-1baf-420b-a9d3-d24e5d961572
status: experimental
description: >
    Detects macOS Script Editor launching curl or bash child processes, a technique
    used by the Reaper (SHub) infostealer to bypass Terminal-based protections
    introduced in macOS Tahoe 26.4. The malware uses the applescript:// URL scheme
    to pre-populate Script Editor with an obfuscated malicious payload.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
    - https://moonlock.com/mac-stealer-shub-reaper
author: Actioner
date: 2026-06-06
tags:
    - attack.t1059.002
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
    - Developer scripts executed via Script Editor
level: high
```

<!-- AUDIT: TTP-level detection for T1059.002 Script Editor abuse. Validated via sigma check (0 errors), sigma convert --without-pipeline -t splunk (valid SPL), sigma convert --without-pipeline -t log_scale (valid LogScale). Requires macOS EDR telemetry with parent process tracking. False positives possible from legitimate Script Editor automation; tune by excluding known automation users/scripts. Revision: removed attack.t1059.007 tag -- that technique covers JavaScript execution on lure sites, not host-side process creation detected by this rule. -->

### Sigma Rule 2: Fake Google Software Update Persistence Directory

Detects file creation in the fake Google Software Update directory used by Reaper for persistence backdoor installation.

compile: sigma check pass | splunk pass | log_scale pass | confidence: high (specific persistence path)

```yaml
title: Reaper macOS Stealer - Fake Google Software Update Persistence
id: 65212820-b536-4ec2-8707-5705c036bd59
status: experimental
description: >
    Detects creation of files in the fake Google Software Update directory used by
    the Reaper infostealer for persistence. The malware drops a Base64-encoded bash
    script named GoogleUpdate and registers a LaunchAgent to execute it every 60 seconds.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
    - https://moonlock.com/mac-stealer-shub-reaper
author: Actioner
date: 2026-06-06
tags:
    - attack.t1543.001
    - attack.t1036.005
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|contains|all:
            - '/Application Support/Google/GoogleUpdate.app/Contents/MacOS/'
            - 'GoogleUpdate'
    filter_legit:
        Image|contains:
            - '/Google/Chrome'
            - '/Google/GoogleUpdater'
            - '/ksinstall'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate Google Chrome or Google Software Update installations
level: high
```

<!-- AUDIT: Persistence detection for T1543.001 + T1036.005. Validated via sigma check (0 errors), splunk and log_scale backends. Revision: expanded filter_legit to include GoogleUpdater and ksinstall processes, matching the filter list in Sigma Rule 3 (LaunchAgent). The specific path "GoogleUpdate.app/Contents/MacOS/GoogleUpdate" narrows false positives significantly vs. generic GoogleUpdate detection. -->

### Sigma Rule 3: Malicious Google Keystone LaunchAgent

Detects creation of the `com.google.keystone.agent.plist` LaunchAgent outside standard Chrome installation context.

compile: sigma check pass | splunk pass | log_scale pass | confidence: medium (legitimate Google plist exists; filter required)

```yaml
title: Reaper macOS Stealer - Malicious Google Keystone LaunchAgent
id: a9509c8e-7fe9-4e03-8b91-4006b4961e7a
status: experimental
description: >
    Detects creation of the com.google.keystone.agent.plist LaunchAgent file
    outside of the standard Google Chrome installation flow. The Reaper infostealer
    uses this plist to maintain persistence by executing a beacon script every 60 seconds.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
    - https://moonlock.com/mac-stealer-shub-reaper
author: Actioner
date: 2026-06-06
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/com.google.keystone.agent.plist'
        TargetFilename|contains: '/LaunchAgents/'
    filter_chrome:
        Image|contains:
            - '/Google/Chrome'
            - '/Google/GoogleUpdater'
            - '/ksinstall'
    condition: selection and not filter_chrome
falsepositives:
    - Legitimate Google Chrome or Google Earth installations creating Keystone agent
level: medium
```

<!-- AUDIT: LaunchAgent persistence detection for T1543.001. Validated via sigma check, splunk, log_scale. Filters Chrome, GoogleUpdater, and ksinstall (the legitimate Keystone installer). Legitimate Google products do create this plist, so filter accuracy depends on Image path completeness in telemetry. -->

### Sigma Rule 4: SHub Staging Directory Activity

Detects file creation in the `/tmp/shub_*` staging directory -- a high-fidelity indicator specific to the SHub/Reaper malware family.

compile: sigma check pass | splunk pass | log_scale pass | confidence: high (unique malware artifact)

```yaml
title: Reaper macOS Stealer - SHub Staging Directory Activity
id: 60403fa7-1e6c-4798-a8b2-616dbae50046
status: experimental
description: >
    Detects file creation in the /tmp/shub_ staging directory or the presence of
    shub_split.sh and shub_mzip_ archive files used by the Reaper infostealer
    for data staging and chunked exfiltration.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
author: Actioner
date: 2026-06-06
tags:
    - attack.t1074.001
    - attack.t1560.001
logsource:
    category: file_event
    product: macos
detection:
    selection_staging:
        TargetFilename|contains: '/tmp/shub_'
    selection_split:
        TargetFilename|contains: '/tmp/shub_split.sh'
    selection_archive:
        TargetFilename|contains: '/tmp/shub_mzip_'
    condition: 1 of selection_*
falsepositives:
    - Unlikely - the shub_ prefix in /tmp is highly specific to this malware family
level: critical
```

<!-- AUDIT: High-fidelity IOC-based detection for T1074.001 + T1560.001. The "shub_" prefix is a distinctive malware artifact with no known legitimate use. Validated via sigma check, splunk, log_scale. -->

### Sigma Rule 5: C2 Exfiltration via Curl to Known Reaper Domain

Detects curl commands targeting the known Reaper C2 domain. The URI endpoints (/gate/chunk, /api/bot/heartbeat, /api/debug/event) are no longer matched independently because they can collide with legitimate APIs.

compile: sigma check pass | splunk pass | log_scale pass | confidence: high (known C2 domain IOC)

```yaml
title: Reaper macOS Stealer - C2 Exfiltration via Curl to Known Domain
id: 914441e5-9a7b-4122-95b8-49954921741e
status: experimental
description: >
    Detects curl commands targeting the known Reaper C2 domain hebsbsbzjsjshduxbs.xyz.
    The malware uses curl to upload chunked ZIP archives to /gate/chunk and maintain
    a 60-second beacon to /api/bot/heartbeat. URI endpoint paths are only matched
    when the C2 domain is also present in the command line to avoid false positives
    from legitimate APIs using similar paths.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
author: Actioner
date: 2026-06-06
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_curl:
        Image|endswith: '/curl'
    selection_c2_domain:
        CommandLine|contains: 'hebsbsbzjsjshduxbs.xyz'
    condition: selection_curl and selection_c2_domain
falsepositives:
    - None expected - hebsbsbzjsjshduxbs.xyz is a confirmed malicious C2 domain
    - Note: URI paths /gate/chunk, /api/bot/heartbeat, /api/debug/event were removed as standalone matches because they can appear in legitimate APIs
level: critical
```

<!-- AUDIT: Revision: removed standalone OR matching of URI paths /gate/chunk, /api/bot/heartbeat, /api/debug/event which could match legitimate APIs. Now requires the C2 domain hebsbsbzjsjshduxbs.xyz in the command line. Updated falsepositives to be honest about the URI path limitation. Validated via sigma check (0 errors), splunk, log_scale. -->

### Sigma Rule 6: Crypto Wallet Application Hijacking via xattr

Detects the combination of `xattr -cr` with cryptocurrency wallet application paths, indicating Reaper's wallet hijacking technique.

compile: sigma check pass | splunk pass | log_scale pass | confidence: medium (TTP-level; xattr -cr has legitimate uses)

```yaml
title: Reaper macOS Stealer - Crypto Wallet Application Hijacking
id: f03f9625-5016-4f4b-b59e-876e86d6b592
status: experimental
description: >
    Detects download of modified app.asar files and xattr -cr usage to clear
    quarantine attributes, a technique used by the Reaper infostealer to hijack
    desktop cryptocurrency wallet applications such as Exodus, Atomic, Ledger Live,
    and Trezor Suite.
references:
    - https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/
author: Actioner
date: 2026-06-06
tags:
    - attack.t1553.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_xattr:
        Image|endswith: '/xattr'
        CommandLine|contains: '-cr'
    selection_wallet_paths:
        CommandLine|contains:
            - 'Exodus'
            - 'Atomic Wallet'
            - 'Ledger Live'
            - 'Trezor Suite'
    condition: selection_xattr and selection_wallet_paths
falsepositives:
    - System administrators clearing quarantine attributes on legitimate wallet updates
level: high
```

<!-- AUDIT: Revision: removed attack.t1195.002 (Supply Chain Compromise) -- this is local post-compromise binary replacement, not supply chain. Retained T1553.001 (Gatekeeper Bypass via xattr -cr). Combines xattr quarantine bypass with wallet application paths. Validated via sigma check, splunk, log_scale. -->

### YARA Rule: Reaper SHub macOS Stealer Binary/Script Detection

Detects Reaper malware files (scripts, binaries, AppleScript payloads) via distinctive strings including C2 endpoints, staging paths, build identifiers, and brand impersonation artifacts.

compile: yarac pass | confidence: high (multiple IOC-anchored string combinations)

```yara
rule Malware_macOS_Reaper_SHub_Stealer
{
    meta:
        description = "Detects the Reaper (SHub) macOS infostealer via distinctive strings found in AppleScript payloads and shell scripts including staging paths, C2 endpoints, and build identifiers"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_domain = "hebsbsbzjsjshduxbs.xyz" ascii wide
        $c2_gate = "/gate/chunk" ascii
        $c2_heartbeat = "/api/bot/heartbeat" ascii
        $c2_debug = "/api/debug/event" ascii

        $staging_dir = "/tmp/shub_" ascii
        $split_script = "shub_split.sh" ascii
        $mzip = "shub_mzip_" ascii

        $build_hash = "c917fcf8314228862571f80c9e4a871e" ascii

        $persistence_path = "Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate" ascii
        $plist_name = "com.google.keystone.agent.plist" ascii

        $wallet_exodus = "exodus_asar.zip" ascii
        $wallet_inject = "_asar.zip" ascii

        $cis_check = "cis_blocked" ascii
        $hidden_script = "/tmp/.c.sh" ascii

        $lure_domain1 = "mlcrosoft.co.com" ascii
        $lure_domain2 = "mlroweb.com" ascii

    condition:
        filesize < 10MB and
        (
            ($c2_domain and 1 of ($c2_gate, $c2_heartbeat, $c2_debug)) or
            ($build_hash) or
            (2 of ($staging_dir, $split_script, $mzip)) or
            ($persistence_path and $plist_name) or
            (3 of them)
        )
}

rule Malware_macOS_Reaper_AppleScript_Payload
{
    meta:
        description = "Detects Reaper macOS stealer AppleScript payloads that use the applescript:// URL scheme with XProtectRemediator spoofing and obfuscated Script Editor content"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $scheme = "applescript://" ascii
        $xprotect_spoof = "XProtectRemediator" ascii nocase
        $script_editor = "Script Editor" ascii
        $curl_cmd = "curl" ascii
        $do_shell = "do shell script" ascii

        $c2 = "hebsbsbzjsjshduxbs.xyz" ascii
        $fake_apple = "support.apple.com/downloads/xprotect-remediator" ascii

    condition:
        filesize < 5MB and
        (
            ($scheme and $xprotect_spoof) or
            ($do_shell and $c2) or
            ($fake_apple and ($curl_cmd or $do_shell)) or
            ($scheme and $do_shell and $curl_cmd and 1 of ($c2, $fake_apple, $xprotect_spoof)) or
            ($script_editor and $do_shell and $xprotect_spoof)
        )
}
```

<!-- AUDIT: Two YARA rules. Rule 1 uses IOC-anchored strings (C2 domain, build hash, staging paths) with combinatorial conditions to reduce FPs. Rule 2 targets AppleScript payloads with scheme + spoof + execution string combinations. Both compiled cleanly with yarac (exit 0). Revision: the broad branch ($scheme and $do_shell and $curl_cmd) now requires at least one IOC-anchored string ($c2, $fake_apple, or $xprotect_spoof) to prevent matching any AppleScript that uses curl. The build_hash alone is sufficient for high-confidence match in Rule 1. The "3 of them" fallback catches variants that reuse multiple SHub infrastructure strings. -->

### Suricata Rules: Reaper C2 and Lure Domain Network Detection

Six rules covering DNS resolution of the C2 domain and lure domains, HTTP exfiltration to `/gate/chunk`, and heartbeat beaconing to `/api/bot/heartbeat`.

compile: suricata -T pass | confidence: high (IOC-anchored domain and URI patterns)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Reaper macOS Stealer DNS Query to C2 Domain"; flow:to_server; dns.query; content:"hebsbsbzjsjshduxbs.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Reaper macOS Stealer C2 Exfiltration to /gate/chunk"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/gate/chunk"; fast_pattern; http.host; content:"hebsbsbzjsjshduxbs.xyz"; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100102; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Reaper macOS Stealer C2 Heartbeat Beacon"; flow:established,to_server; http.uri; content:"/api/bot/heartbeat"; fast_pattern; http.host; content:"hebsbsbzjsjshduxbs.xyz"; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Reaper macOS Stealer DNS Query to Lure Domain mlcrosoft.co.com"; flow:to_server; dns.query; content:"mlcrosoft.co.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Reaper macOS Stealer DNS Query to Lure Domain mlroweb.com"; flow:to_server; dns.query; content:"mlroweb.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Reaper macOS Stealer DNS Query to Lure Domain qq-0732gwh22.com"; flow:to_server; dns.query; content:"qq-0732gwh22.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/; metadata:author Actioner, created_at 2026-06-06; sid:2100106; rev:1;)
```

<!-- AUDIT: Six Suricata rules validated with suricata -T (exit 0, "Configuration provided was successfully loaded"). Rules use dot-notation sticky buffers per Suricata syntax. DNS rules use dns.query for domain matching. Revision: HTTP exfil rule (sid:2100102) now includes http.host constraint for hebsbsbzjsjshduxbs.xyz (rev:2) to prevent firing on any POST to /gate/chunk. Heartbeat rule (sid:2100103) already combined URI + Host. All use classtype:trojan-activity. -->

### Snort Rules

> Not generated. Snort is not installed in the validation environment; any rule produced would be uncompiled.

## Lessons Learned

1. **Script Editor is the new Terminal**: Apple's hardening of Terminal in macOS Tahoe 26.4 successfully pushed attackers to find alternative execution paths. Script Editor via the `applescript://` URL scheme provides equivalent capability without the same user confirmation prompts. This gap should be addressed in future macOS security updates.

2. **Brand impersonation layering**: Reaper's multi-brand impersonation (Microsoft for delivery, Apple for credential harvesting, Google for persistence) makes it harder for users and defenders to track the attack chain as a single campaign. Each stage looks like a different vendor's component.

3. **Wallet hijacking outlasts infection cleanup**: Simply removing the malware and rotating passwords is insufficient. Trojanized wallet applications continue to intercept and divert cryptocurrency funds until the applications themselves are completely reinstalled from trusted sources.

4. **CIS region exclusion as attribution signal**: The deliberate blocking of CIS-region systems (checking for Russian keyboard input sources) combined with Russian-language anti-analysis messages on lure websites strongly suggests Russian-speaking operators, consistent with the broader macOS stealer ecosystem (AMOS, Banshee).

## Sources

- [SentinelOne Blog: SHub Reaper](https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/) -- primary technical analysis with IOCs, attack chain details, and persistence mechanisms
- [Moonlock Blog: Mac Stealer SHub Reaper](https://moonlock.com/mac-stealer-shub-reaper) -- detailed investigation of the Reaper variant and its data theft capabilities
- [Hackread: Reaper macOS Infostealer](https://hackread.com/reaper-macos-infostealer-script-editor-crypto-passwords/) -- initial reporting and summary of the threat
- [The Register: Do Fear the Reaper](https://www.theregister.com/security/2026/05/19/do-fear-the-reaper-stealer-swipes-macos-users-passwords-wallets-then-backdoors-them/5242258) -- additional coverage with persistence and beacon details
- [Help Net Security: SHub Reaper macOS Infostealer](https://www.helpnetsecurity.com/2026/05/19/shub-reaper-macos-infostealer-apple-google-microsoft/) -- additional reporting context
- [Security Online: SHub Reaper AppleScript Bypass](https://securityonline.info/shub-reaper-macos-infostealer-applescript-mitigation-bypass/) -- coverage of the AppleScript mitigation bypass technique

<!-- revision: v1.1 2026-06-06 | Applied critic NEEDS-REVISION fixes: (1) Sigma 1: removed attack.t1059.007 tag (wrong technique for host-side rule). (2) Sigma 2: expanded filter_legit to include GoogleUpdater and ksinstall. (3) Sigma 5: removed standalone URI path matching; now requires C2 domain in CommandLine; updated falsepositives. (4) Sigma 6: removed attack.t1195.002 (not supply chain); retained T1553.001. (5) YARA Rule 2: anchored broad branch to require IOC string. (6) Suricata sid:2100102: added http.host constraint for C2 domain (rev:2). (7) Report: fixed ATT&CK table T1195.002->T1554; defanged domain in bash script comment. All rules re-validated: sigma check 0 errors, yarac exit 0, suricata -T pass. -->

---
*Report generated by Actioner*
