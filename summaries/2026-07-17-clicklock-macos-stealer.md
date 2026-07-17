# Technical Analysis Report: ClickLock macOS Information Stealer (2026-07-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-17
Version: 1.0 (DRAFT)

## Executive Summary

ClickLock is a modular macOS information stealer discovered by Group-IB, first observed on VirusTotal on June 9, 2026, with zero detections at the time of upload. The malware is delivered via the ClickFix social engineering technique, where victims are tricked into pasting a malicious shell command into Terminal through a fake Cloudflare CAPTCHA verification page. ClickLock's signature technique is a coercive process-killing loop that terminates core macOS UI processes (Finder, Dock, SystemUIServer, NotificationCenter, Activity Monitor, browsers) every 210 milliseconds for up to 83 hours, leaving only a fake password dialog on an otherwise dead desktop. Once the user enters their login password, the malware validates it locally via `dscl`, then exfiltrates credentials, browser data, cryptocurrency wallet data, and Keychain contents via three Telegram bots.

The operation has targeted at least 100 victims across 33 countries since May 2026, with over 50% of victims in Europe. The malware uses compromised WordPress sites for payload hosting, installs a modified GSocket reverse-shell backdoor disguised as an iCloud process for persistent remote access, and self-deletes most components after execution to hinder forensic analysis.

## Background: macOS Credential Theft via ClickFix

ClickFix is a social engineering technique that has been increasingly adopted by macOS-targeting malware in 2026. It leverages fake verification pages (often mimicking Cloudflare) that instruct users to copy and paste a command into Terminal. Unlike traditional phishing that targets browser-based credentials, ClickFix achieves direct shell access on the victim's machine. ClickLock extends this approach with a novel "locker" component that renders the system unusable until the user complies with a fake password prompt, combining social engineering with denial-of-service pressure on the local machine.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| May 2026 | Earliest observed ClickLock activity begins |
| 2026-06-09 | Orchestrator shell script first uploaded to VirusTotal (zero detections) |
| 2026-07-16 | Group-IB publishes analysis of ClickLock Stealer |
| 2026-07-17 | Multiple security outlets report on the threat (BleepingComputer, The Hacker News, SecurityWeek, Infosecurity Magazine) |

## Root Cause: ClickFix Social Engineering via Fake Cloudflare Verification

The attack begins when a victim visits a ClickFix lure page, likely distributed via SEO poisoning, social media posts, or compromised websites. The page presents a fake Cloudflare "human verification" CAPTCHA that instructs the user to copy a malicious command and paste it into Terminal. When executed, the command triggers a fake verification progress bar animation while silently downloading and executing the orchestrator shell script. The script takes a `RAY_ID` parameter as its first argument, potentially used for campaign tracking.

## Technical Analysis of the Malicious Payload

### 1. Orchestrator Shell Script (Initial Loader)

The orchestrator script serves as the entry point. Upon execution it:

- Disables keyboard interrupts (trapping Ctrl+C)
- Hides the terminal cursor
- Displays a fake Cloudflare verification progress bar
- Suppresses NotificationCenter for approximately 6 hours to prevent Gatekeeper and security warnings
- Downloads four payload modules from compromised infrastructure

The four modules are downloaded from two compromised hosts:

- **Credential stealer** (`zsh.txt`) from `panalobet[.]ph/wp-content/upgrade/zsh.txt`
- **Keychain stealer** (`chromer.txt`) from `panalobet[.]ph/wp-content/themes/twentytwenty/assets/fonts/chromer.txt`
- **Crypto stealer** (`finderv2.jpg`) from `panalobet[.]ph/wp-content/themes/twentytwenty/assets/images/finderv2.jpg`
- **GSocket backdoor installer** (`goyim`) from `store.grafsynergy[.]com`

Payloads are downloaded using `curl` piped to `bash`, with files disguised using innocuous extensions (`.txt`, `.jpg`, `.css`).

### 2. Credential Stealer Module (zsh.txt)

The credential stealer uses `osascript` to launch a fake macOS password dialog styled with a downloaded Apple icon (stored in `/tmp/`) to appear indistinguishable from a legitimate system prompt. It displays the victim's real username to increase credibility. When the user enters their password, it is validated against the local directory service using:

```
dscl /Local/Default -authonly "$USER" "$PASS"
```

This ensures only the correct password is exfiltrated, preventing junk data from being sent to the operator. If the user cancels the dialog, the orchestrator installs two LaunchAgents (`com.authirity.plist` and `com.chromer.plist`) in `~/Library/LaunchAgents/` to relaunch the credential modules on the next login.

At the next login, the kill loop activates: `pkill` and `killall` bursts target Finder, Dock, Spotlight, Terminal, Activity Monitor, Console, System Settings, SystemUIServer, NotificationCenter, and web browsers every 210 milliseconds for up to 300,000 seconds (~83 hours). A secondary loop runs at 200ms intervals for up to 3,000,000 seconds (~34.7 days). This leaves only the fake password dialog visible on a dead desktop.

### 3. C2 Infrastructure

ClickLock uses no dedicated C2 infrastructure. Exfiltration runs entirely over Telegram via three bots. Files are split at 40MB boundaries for upload. The GSocket backdoor connects to a relay server at `gsnc[.]eu:67`.

Payload hosting relies on compromised legitimate domains:

- `panalobet[.]ph` — a compromised WordPress site hosting three payload modules
- `store.grafsynergy[.]com` — hosting the GSocket backdoor installer
- GSocket binary sourced from `gsocket[.]io`

### 4. Platform-Specific Behavior

#### macOS

**Data Theft Targets:**
- **8 browsers:** Chrome, Firefox, Brave, Edge, Opera, Vivaldi, Arc, Chromium (saved logins, cookies, autofill, bookmarks, local storage)
- **31 cryptocurrency wallet browser extensions** (including MetaMask, Phantom)
- **7 password manager extensions**
- **8 desktop wallet applications**
- **6 blockchain networks:** EVM, Bitcoin, Solana, TRON, TON, Stacks (cached addresses)
- **macOS Keychain:** Chrome Safe Storage AES key via `security find-generic-password`
- **FileZilla** FTP credentials
- **Shell histories**
- **System information and public IP**

**Persistence:**
- Two LaunchAgents: `~/Library/LaunchAgents/com.authirity.plist` and `~/Library/LaunchAgents/com.chromer.plist`
- Crontab entries
- Shell configuration file modifications
- GSocket backdoor permanent installation

**GSocket Backdoor (`goyim`):**
- Approximately 80% based on the public GSocket deploy script from The Hacker's Choice
- Binary pulled from `gsocket[.]io`
- Installed to `~/Library/Application Support/iCloudsync`
- Process masquerades as `SystemUIServerl` (note the trailing lowercase 'l', one character off from the legitimate `SystemUIServer`)
- Connects to relay at `gsnc[.]eu:67`

**Hidden Cache:**
- Working directory at `$HOME/.cacheb/`

### 5. Anti-Forensics / Evasion Techniques

- **Timestamp forging:** Modules forge timestamps using `~/Movies` directory metadata to break timeline analysis
- **Self-deletion:** All modules delete themselves after execution, except the GSocket backdoor which remains permanently installed
- **Persistence removal:** Modules remove their own persistence mechanisms after completing objectives
- **NotificationCenter suppression:** Killed continuously for ~6 hours to suppress Gatekeeper and security warnings
- **Keyboard interrupt suppression:** Terminal traps disabled to prevent Ctrl+C cancellation
- **Terminal cursor hidden:** Cursor hidden during fake verification sequence
- **Clean-reputation hosting:** Payloads hosted on compromised legitimate domains with good reputation scores
- **Zero VirusTotal detections:** Orchestrator had zero detections when first analyzed

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA1) | Description |
|----------|------|-------------|-------------|
| macOS | (downloaded as `zsh.txt`) | `8dda05168ea8610a2449419a47517bc32823d6ec` | Credential stealer module |
| macOS | (downloaded as `chromer.txt`) | `b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff` | Keychain stealer module |
| macOS | (downloaded as `finderv2.jpg`) | `0a1fb016bd10bac5455175c79aa4511e5ff1a330` | Crypto/infostealer module |
| macOS | `~/Library/LaunchAgents/com.authirity.plist` | — | Persistence for credential stealer |
| macOS | `~/Library/LaunchAgents/com.chromer.plist` | — | Persistence for Keychain stealer |
| macOS | `~/Library/Application Support/iCloudsync` | — | GSocket backdoor (disguised as iCloud) |
| macOS | `$HOME/.cacheb/` | — | Hidden working/cache directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `panalobet[.]ph` | Compromised WordPress site hosting payload modules |
| URL | `hxxps://panalobet[.]ph/wp-content/upgrade/zsh.txt` | Credential stealer download |
| URL | `hxxps://panalobet[.]ph/wp-content/themes/twentytwenty/assets/fonts/chromer.txt` | Keychain stealer download |
| URL | `hxxps://panalobet[.]ph/wp-content/themes/twentytwenty/assets/images/finderv2.jpg` | Crypto stealer download |
| Domain | `store.grafsynergy[.]com` | GSocket backdoor installer hosting |
| Domain | `gsnc[.]eu` | GSocket relay server |
| IP:Port | `gsnc[.]eu:67` | GSocket relay endpoint (non-standard port) |
| Domain | `gsocket[.]io` | Legitimate GSocket binary source |

### Behavioral

- **Process killing loop:** `pkill`/`killall` bursts against Finder, Dock, SystemUIServer, NotificationCenter, Spotlight, Terminal, Activity Monitor, Console, System Settings, and browsers every 210ms
- **Fake password dialog:** `osascript` launching AppleScript dialog with `display dialog`, `default answer`, `hidden answer` and Apple icon from `/tmp/`
- **Password validation:** `dscl /Local/Default -authonly` used to verify captured passwords
- **Keychain access:** `security find-generic-password` called from shell scripts
- **Download pattern:** `curl` piped to `bash` with URLs ending in `.jpg`, `.txt`, or `.css`
- **Process masquerading:** Process name `SystemUIServerl` (trailing 'l') mimicking legitimate `SystemUIServer`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Victim pastes malicious command into Terminal from ClickFix lure |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Orchestrator and modules are bash shell scripts |
| T1059.002 | Command and Scripting Interpreter: AppleScript | osascript used to display fake password dialog |
| T1056.002 | Input Capture: GUI Input Capture | Fake macOS password dialog captures login credentials |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | Two LaunchAgents installed for persistence |
| T1555.001 | Credentials from Password Stores: Keychain | Chrome Safe Storage AES key extracted from Keychain |
| T1005 | Data from Local System | Browser data, wallet data, shell history, FTP credentials harvested |
| T1105 | Ingress Tool Transfer | Payloads downloaded from compromised WordPress sites |
| T1036.004 | Masquerading: Masquerade Task or Service | GSocket backdoor masquerades as SystemUIServerl / iCloud |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Activity Monitor, NotificationCenter, and security-related processes killed |
| T1070.006 | Indicator Removal: Timestomp | Timestamps forged using ~/Movies directory metadata |
| T1070.004 | Indicator Removal: File Deletion | Modules self-delete after execution |
| T1567 | Exfiltration Over Web Service | Data exfiltrated via three Telegram bots |
| T1571 | Non-Standard Port | GSocket relay communicates on port 67 |

## Impact Assessment

ClickLock has compromised at least 100 systems across 33 countries within approximately two months of operation (May-July 2026), with over 50% of victims located in Europe. The comprehensive data theft scope -- spanning browser credentials, cryptocurrency wallets (31 extensions, 8 desktop apps, 6 blockchain networks), password managers (7 extensions), Keychain contents, and FTP credentials -- represents a significant risk of financial loss and account compromise. The persistent GSocket backdoor provides the operator with ongoing remote access even after credential theft is complete. Group-IB assesses the malware is still under active development.

## Detection & Remediation

### Immediate Detection

Check for ClickLock persistence artifacts:

```bash
# Check for ClickLock LaunchAgents
ls -la ~/Library/LaunchAgents/com.authirity.plist 2>/dev/null
ls -la ~/Library/LaunchAgents/com.chromer.plist 2>/dev/null

# Check for GSocket backdoor
ls -la ~/Library/Application\ Support/iCloudsync 2>/dev/null

# Check for hidden cache directory
ls -la ~/.cacheb/ 2>/dev/null

# Check for masquerading process
ps aux | grep -i "SystemUIServerl" | grep -v grep

# Check for suspicious LaunchAgents loaded
launchctl list | grep -E "authirity|chromer"

# Check crontab for suspicious entries
crontab -l 2>/dev/null

# Check for recent osascript invocations with password dialogs (requires endpoint telemetry)
log show --predicate 'process == "osascript"' --last 24h 2>/dev/null | head -50
```

### Remediation

1. **Contain:** Disconnect affected systems from the network immediately to stop active exfiltration via Telegram.
2. **Remove persistence:** Delete `~/Library/LaunchAgents/com.authirity.plist` and `~/Library/LaunchAgents/com.chromer.plist`. Remove any suspicious crontab entries. Check and clean shell configuration files (`.zshrc`, `.bashrc`, `.bash_profile`).
3. **Remove GSocket backdoor:** Delete `~/Library/Application Support/iCloudsync` directory. Kill any `SystemUIServerl` processes.
4. **Remove cache:** Delete `~/.cacheb/` directory.
5. **Rotate credentials:** Change the macOS login password. Rotate all browser-saved passwords. Revoke and regenerate any cryptocurrency wallet seeds/keys that were stored in targeted browser extensions or desktop wallets. Rotate FileZilla FTP credentials.
6. **Review Keychain:** The Chrome Safe Storage AES key was likely compromised; all Chrome-saved passwords should be considered exposed.
7. **Monitor Telegram:** While bot tokens are not published, monitor for unusual outbound traffic to `api.telegram.org`.

### Long-Term Hardening

- Block the ClickFix attack vector by deploying endpoint detection for `curl | bash` patterns and osascript-based password dialogs.
- macOS 26.4 introduces a paste warning for Terminal, but the "Paste Anyway" button leaves a residual exploitation window; user education remains critical.
- Monitor for process-killing loops targeting core macOS UI processes -- this behavior has no legitimate use case.
- Consider application allowlisting for LaunchAgents to detect unauthorized plist creation.

## Detection Rules

These detections target the ClickLock macOS stealer at the PoC/advisory-specific altitude, keying on distinctive artifacts: characteristic plist names, osascript password dialog patterns, dscl password validation, process-killing behavior, and known payload/C2 domains. Compiles does not equal fires -- verify each rule against your endpoint and network telemetry pipeline.

### Sigma: ClickLock Stealer - Fake macOS Password Dialog via osascript

Detects osascript executing AppleScript with `display dialog` / `hidden answer` to present a fake password prompt, the primary credential-harvesting mechanism of ClickLock.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy, not a rule issue); splunk convert exit 0; log_scale convert exit 0. osascript + display dialog + hidden answer is distinctive; false positives limited to IT admin scripts. -->
```yaml
title: ClickLock Stealer - Fake macOS Password Dialog via osascript
id: a3e7f1d2-4b8c-4a5e-9d6f-1c2b3a4e5f67
status: experimental
description: >
    Detects osascript executing AppleScript to display a fake password dialog,
    a technique used by the ClickLock macOS stealer to harvest user credentials
    by mimicking a legitimate system password prompt.
references:
    - https://www.group-ib.com/blog/clicklock-stealer-macos-malware/
    - https://www.bleepingcomputer.com/news/security/new-clicklock-macos-malware-traps-users-into-revealing-login-password/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1059.002
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection_binary:
        Image|endswith: '/osascript'
    selection_dialog:
        CommandLine|contains|all:
            - 'display dialog'
            - 'default answer'
            - 'hidden answer'
    condition: selection_binary and selection_dialog
falsepositives:
    - Legitimate system administration scripts using osascript password dialogs
    - Custom IT deployment tools requesting credentials via AppleScript
level: high
```

### Sigma: ClickLock Stealer - LaunchAgent Persistence via Characteristic Plist Names

Detects creation of `com.authirity.plist` or `com.chromer.plist` in LaunchAgents, the specific persistence files used by ClickLock.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale convert exit 0. Plist names are unique to ClickLock (typo "authirity" is distinctive). No known false positives. -->
```yaml
title: ClickLock Stealer - LaunchAgent Persistence via Characteristic Plist Names
id: b4f8a2e3-5c9d-4b6f-0e7a-2d3c4b5f6a78
status: experimental
description: >
    Detects creation of LaunchAgent plist files with names characteristic of the
    ClickLock macOS stealer (com.authirity.plist or com.chromer.plist), which are
    used to re-launch credential theft modules on login.
references:
    - https://www.group-ib.com/blog/clicklock-stealer-macos-malware/
    - https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1547.011
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith:
            - '/LaunchAgents/com.authirity.plist'
            - '/LaunchAgents/com.chromer.plist'
    condition: selection
falsepositives:
    - Unlikely - these plist names are distinctive to ClickLock stealer
level: critical
```

### Sigma: ClickLock Stealer - Password Validation via dscl authonly

Detects `dscl` invoked with `-authonly` against the local directory, used by ClickLock to validate captured passwords before exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk convert exit 0; log_scale convert exit 0. dscl -authonly from non-system parents is rare. Legitimate system auth services may trigger; scope to shell script parents if FP rate is high. -->
```yaml
title: ClickLock Stealer - Password Validation via dscl authonly
id: c5a9b3f4-6d0e-4c7a-1f8b-3e4d5c6a7b89
status: experimental
description: >
    Detects dscl being invoked with -authonly flag against the local directory,
    a technique used by the ClickLock macOS stealer to validate a captured
    password before exfiltration. Legitimate use of dscl -authonly from
    non-system parent processes is rare.
references:
    - https://www.group-ib.com/blog/clicklock-stealer-macos-malware/
    - https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html
author: Actioner
date: 2026/07/17
tags:
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - '/Local/Default'
            - '-authonly'
    condition: selection
falsepositives:
    - System authentication services validating credentials
    - IT administration scripts performing credential checks
level: high
```

### Sigma: ClickLock Stealer - Rapid macOS System Process Killing

Detects `pkill`/`killall` targeting core macOS UI processes (Finder, Dock, SystemUIServer, NotificationCenter), the coercive locker mechanism unique to ClickLock.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: splunk convert exit 0; log_scale convert exit 0. Individual kills are legitimate during maintenance/installs; confidence medium because a single event could be benign — the malicious signal is rapid repetition, which requires correlation or threshold logic not expressible in a single Sigma rule. Pair with osascript dialog rule for higher confidence. -->
```yaml
title: ClickLock Stealer - Rapid macOS System Process Killing
id: d6b0c4a5-7e1f-4d8b-2a9c-4f5e6d7a8b90
status: experimental
description: >
    Detects rapid use of pkill or killall targeting core macOS UI processes
    (Finder, Dock, SystemUIServer, NotificationCenter), a technique used by the
    ClickLock stealer to force users into entering their login password by
    rendering the desktop unusable.
references:
    - https://www.group-ib.com/blog/clicklock-stealer-macos-malware/
    - https://www.bleepingcomputer.com/news/security/new-clicklock-macos-malware-traps-users-into-revealing-login-password/
author: Actioner
date: 2026/07/17
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_tool:
        Image|endswith:
            - '/pkill'
            - '/killall'
    selection_target:
        CommandLine|contains:
            - 'Finder'
            - 'Dock'
            - 'SystemUIServer'
            - 'NotificationCenter'
    condition: selection_tool and selection_target
falsepositives:
    - System administrators restarting UI processes during maintenance
    - Software installers that restart Finder or Dock
level: high
```

### Snort: HTTP Request to ClickLock WordPress Payload Paths

Detects HTTP requests to the specific WordPress content paths used by ClickLock for payload staging on compromised host `panalobet[.]ph`. Snort is not installed -- structural check only.
**Status:** compile ⚠️ uncompiled (structural check only; Snort not installed) · confidence: high
<!-- audit: snort not on PATH; structural check: http service, http_uri sticky buffer, flow established,to_server, content with fast_pattern, sid/rev/classtype/reference present. Three rules covering zsh.txt, chromer.txt, finderv2.jpg payload paths. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock Payload Path zsh.txt"; flow:established, to_server; http_uri; content:"/wp-content/upgrade/zsh.txt", fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created 2026-07-17; sid:2100001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock Payload chromer.txt"; flow:established, to_server; http_uri; content:"/wp-content/themes/twentytwenty/assets/fonts/chromer.txt", fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created 2026-07-17; sid:2100002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock Payload finderv2.jpg"; flow:established, to_server; http_uri; content:"/wp-content/themes/twentytwenty/assets/images/finderv2.jpg", fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created 2026-07-17; sid:2100003; rev:1;)
```

### Suricata: DNS Queries to ClickLock Payload and C2 Domains

Detects DNS queries to the three known domains used by ClickLock for payload hosting (`panalobet[.]ph`, `store.grafsynergy[.]com`) and GSocket relay (`gsnc[.]eu`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 for all three rules. dns protocol, dns.query sticky buffer, nocase, fast_pattern. Domains are compromised infrastructure — may rotate, but current indicators are confirmed by Group-IB. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ClickLock Payload Domain panalobet.ph"; flow:to_server; dns.query; content:"panalobet.ph"; nocase; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ClickLock Payload Domain store.grafsynergy.com"; flow:to_server; dns.query; content:"store.grafsynergy.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ClickLock GSocket Relay gsnc.eu"; flow:to_server; dns.query; content:"gsnc.eu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200003; rev:1;)
```

### Suricata: HTTP Requests to ClickLock WordPress Payload Paths

Detects HTTP requests to the specific WordPress content paths used by ClickLock for payload delivery, including the credential stealer, Keychain stealer, and crypto stealer modules.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 for all three rules. http protocol, http.uri dot-notation sticky buffer, flow established,to_server, fast_pattern. Paths are specific enough to avoid false positives on legitimate WordPress sites. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock WordPress Payload Path zsh.txt"; flow:established,to_server; http.uri; content:"/wp-content/upgrade/zsh.txt"; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200004; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock WordPress Payload Path chromer.txt"; flow:established,to_server; http.uri; content:"/wp-content/themes/twentytwenty/assets/fonts/chromer.txt"; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200005; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to ClickLock WordPress Payload Path finderv2.jpg"; flow:established,to_server; http.uri; content:"/wp-content/themes/twentytwenty/assets/images/finderv2.jpg"; fast_pattern; classtype:trojan-activity; reference:url,group-ib.com/blog/clicklock-stealer-macos-malware/; metadata:author Actioner, created_at 2026-07-17; sid:2200006; rev:1;)
```

### YARA: ClickLock Orchestrator Shell Script

Detects the ClickLock orchestrator shell script via distinctive string combinations including the characteristic plist names (`com.authirity`, `com.chromer`), credential validation command (`dscl -authonly`), process kill targets, and backdoor artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt fired (Malware_ClickLock_Orchestrator_Script), neg.txt quiet. Positive sample constructed from published source strings (com.authirity.plist, com.chromer.plist, dscl /Local/Default -authonly, killall Dock/Finder, NotificationCenter, .cacheb, iCloudsync, goyim). Condition requires 3-of-6 distinctive strings AND at least one kill command — specific enough to avoid false positives on benign scripts. -->
```yara
rule Malware_ClickLock_Orchestrator_Script
{
    meta:
        description = "Detects the ClickLock macOS stealer orchestrator shell script via distinctive string combinations including plist names, process kill targets, and credential validation commands"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.group-ib.com/blog/clicklock-stealer-macos-malware/"
        severity = "high"

    strings:
        $plist1 = "com.authirity.plist" ascii
        $plist2 = "com.chromer.plist" ascii
        $dscl = "dscl /Local/Default -authonly" ascii
        $kill1 = "killall Dock" ascii
        $kill2 = "killall Finder" ascii
        $kill3 = "NotificationCenter" ascii
        $cache = ".cacheb" ascii
        $disguise = "iCloudsync" ascii
        $goyim = "goyim" ascii

    condition:
        filesize < 500KB and
        3 of ($plist1, $plist2, $dscl, $cache, $disguise, $goyim) and
        1 of ($kill*)
}
```

## Lessons Learned

1. **ClickFix evolves beyond credentials into coercion.** ClickLock demonstrates that the ClickFix social engineering technique is no longer limited to simple credential phishing -- it now enables full system compromise including persistent backdoor installation and coercive UI manipulation. The process-killing loop that forces password entry is a novel forced-interaction technique with no legitimate use case, making it a reliable detection signal.

2. **Compromised legitimate infrastructure remains the hosting weapon of choice.** All payload hosting used compromised WordPress sites and legitimate domains, providing clean reputation scores that bypass URL/domain blocklists. Network detection must focus on the specific payload paths and behavioral patterns, not just domain reputation.

3. **Telegram as exfiltration channel continues to grow.** ClickLock's use of three Telegram bots with 40MB file splitting for exfiltration, combined with no dedicated C2, makes network-level detection challenging since Telegram traffic is legitimate in most environments. Endpoint detection (osascript dialogs, dscl validation, process-killing loops, LaunchAgent creation) provides stronger detection coverage than network-only approaches.

## Sources

- [Group-IB Blog: ClickLock Stealer: Paste Once, Lose Everything](https://www.group-ib.com/blog/clicklock-stealer-macos-malware/) — primary technical analysis and original discovery
- [BleepingComputer: New ClickLock macOS malware traps users into revealing login password](https://www.bleepingcomputer.com/news/security/new-clicklock-macos-malware-traps-users-into-revealing-login-password/) — detailed coverage with IOCs and technical breakdown
- [The Hacker News: New ClickLock macOS Stealer Kills Apps Every 210ms Until Victims Type Their Password](https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html) — file hashes, payload paths, GSocket details
- [Infosecurity Magazine: Modular macOS Stealer Uses Kill Loops to Force Password Entry](https://www.infosecurity-magazine.com/news/clicklock-macos-stealer-clickfix/) — operational context and technique comparison
- [SecurityWeek: ClickLock Stealer Bypasses macOS Security With Social Engineering, Process Killing](https://www.securityweek.com/clicklock-stealer-bypasses-macos-security-with-social-engineering-process-killing/) — security bypass analysis
- [The Register: C'mon, just copy this text string and paste it into your macOS Terminal](https://www.theregister.com/cyber-crime/2026/07/16/cmon-just-copy-this-text-string-and-paste-it-into-your-macos-terminal-itll-fix-your-computer-honest/5273701) — additional coverage and GSocket details

---
*Report generated by Actioner*
