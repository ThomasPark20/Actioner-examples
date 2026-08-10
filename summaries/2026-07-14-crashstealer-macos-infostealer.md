# Technical Analysis Report: CrashStealer — macOS Infostealer Masquerading as Apple CrashReporter (2026-07-14)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-14
Version: 2 (REVISED)

<!-- revision: v2 2026-07-14 — Applied critic fixes: (1) Scoped Sigma dscl rule to CrashStealer process context (ParentImage|endswith '/veltod' OR Image|contains 'crashreporter') to eliminate altitude violation on generic dscl -authonly; elevated level to high; changed ATT&CK tag from T1078.003 to T1110.001. (2) Fixed Snort sid:2100201 comma-delimited content modifiers to semicolons. (3) Fixed Snort sid:2100202 DNS label length |10| to |0f| (endpoint-api-v1 = 15 chars) and comma-to-semicolon syntax. (4) Bumped Snort rev to 2 for both fixed rules. (5) Added YARA comment noting $exit45 byte pattern is x86_64 only (ARM64 uses different encoding). (6) Removed T1189 (Drive-by Compromise) from ATT&CK table — CrashStealer requires manual download+execute, not drive-by. -->

## Executive Summary

CrashStealer is a new C++-based macOS information-stealing malware that masquerades as Apple's built-in CrashReporter diagnostic tool. First reported by Jamf Threat Labs in July 2026, it is distributed via a fake productivity application called "Werkbit" delivered through a purpose-built website (werkbit[.]io) gated behind meeting PINs. The dropper is Apple-notarized and signed with a valid Developer ID (Emil Grigorov, WWB7JA7AQV), allowing it to bypass Gatekeeper entirely.

What distinguishes CrashStealer from typical macOS infostealers is its native C++ implementation (rather than the common AppleScript/shell approach), local password validation via `dscl -authonly` before exfiltration, AES-256-GCM encryption of collected data using PBKDF2-derived keys, and dual-layer anti-debugging via sysctl P_TRACED checks. The malware targets credentials from 5+ Chromium-family browsers, approximately 80 cryptocurrency wallet extensions, 14 password managers, and the macOS login keychain. Exfiltration uses libcurl to a C2 server at 179.43.166[.]242, with payload staging through endpoint-api-v1[.]com.

## Background: macOS Credential-Stealing Landscape

macOS infostealers have proliferated since 2023, with families like Atomic Stealer, Poseidon, and Banshee establishing the category. Most rely on AppleScript/osascript for password prompts and shell scripts for collection. CrashStealer represents an escalation in sophistication: compiled C++ with control-flow flattening, encrypted strings, and abuse of Apple's own notarization infrastructure to achieve implicit trust. The impersonation of Apple's CrashReporter — a legitimate system process users expect to see — is a particularly effective social engineering vector.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late June 2026 | Domain werkbit[.]io registered |
| Early July 2026 | GitHub repository mgothiclove/pkeys created to host staging payload (sys.cache) |
| ~2026-07-07 | Distribution begins via werkbit[.]io with meeting-PIN-gated downloads |
| 2026-07-10 | Jamf Threat Labs publishes initial analysis |
| 2026-07-13 | Coverage by The Hacker News, BleepingComputer, SecurityAffairs |

## Root Cause: Apple Notarization Trust Model Abuse

The initial access vector is social engineering: victims are directed to werkbit[.]io under the pretense of a legitimate productivity tool, with download access gated behind a "meeting PIN" to limit automated sandbox analysis. The dropper (Werkbit.app) passes Gatekeeper because it carries a valid Apple notarization ticket and Developer ID signature. Apple's notarization process checks for known malware signatures but does not perform deep behavioral analysis, creating a window for novel threats.

## Technical Analysis of the Malicious Payload

### 1. Dropper Stage — Werkbit.app

The dropper is distributed as a signed disk image ("Werkbit Setup"). Upon mounting and execution:

- The dropper is signed with Developer ID: **Emil Grigorov (WWB7JA7AQV)** and carries a valid Apple notarization ticket
- It fetches a shell script from the GitHub repository `mgothiclove/pkeys`, downloading a file named `sys.cache`
- The shell script stages the next payload and initiates the CrashReporter impersonation chain
- The multi-stage design isolates the dropper from the final payload, complicating attribution

### 2. Payload Stage — CrashReporter Impersonation

The main payload installs as `CrashReporter.app` with bundle identifier `com.apple.crashreporter`:

- **Binary name**: `veltod` (the actual Mach-O executable within the app bundle)
- **Installation path**: `~/Library/Caches/com.apple.crashreporter/CrashReporter.app`
- **Ad-hoc re-signing**: The payload re-signs itself at runtime, changing its hash to evade static signature-based detection while preserving execution validity
- **Anti-analysis**: Control-flow flattening, runtime string decryption from the `__const` section, and dual-layer anti-debugging via `sysctl` checking for `KERN_PROC`/`P_TRACED` (exits with code 45 on debugger detection)

### 3. Credential Harvesting

CrashStealer presents a fake macOS password prompt mimicking the system authentication dialog. The key innovation is **local password validation**:

- Uses `dscl . -authonly <username> <password>` (Directory Service command-line) to verify the password is correct before proceeding
- Invalid passwords trigger a re-prompt, ensuring only valid credentials reach the C2
- Once validated, the password is cached at `~/.cache/.sys_auth` with 600 permissions
- Uses the Apple `security` CLI tool to unlock the login keychain with the validated password

**Collection targets:**
- **Browsers**: Chrome, Brave, Edge, Opera, Vivaldi, Firefox (cookies, saved passwords, autofill data)
- **Cryptocurrency wallets**: ~80 extensions including MetaMask, Phantom, Coinbase, Trust Wallet, Rabby, Exodus
- **Password managers**: 14 including 1Password, Bitwarden, LastPass, Dashlane, KeePassXC
- **File system**: `~/Documents` and `~/Downloads` (excluding executables, disk images, archives, media files)
- **Keychain**: Full login keychain dump after unlock

### 4. C2 Infrastructure

| Component | Value |
|-----------|-------|
| C2 IP | 179.43.166[.]242 |
| Payload server | endpoint-api-v1[.]com |
| Distribution domain | werkbit[.]io |
| Associated domains | cohezo[.]io, cohezo[.]com, cordinex[.]io |
| GitHub staging | github[.]com/mgothiclove/pkeys |
| Download endpoint | hxxp://endpoint-api-v1[.]com/d/f1b24e/download |
| Protocol | libcurl over HTTPS |

### 5. Data Exfiltration

Collected data is encrypted and staged before exfiltration:

- **Encryption**: AES-256-GCM via Apple's CommonCrypto framework
- **Key derivation**: PBKDF2-HMAC-SHA256 with 10,000 iterations
- **Salt**: Hardcoded string `panel_salt_v1`
- **Staging**: Data packaged into hidden ZIP archives in `~/.cache/com.apple.crashreporter/`
- **Archive naming**: `.zx_` prefix followed by 8 random hex characters (e.g., `.zx_a3f7b1c2`)
- **Working directory**: `/tmp/.CrashReporter/` (hidden directory in tmp)
- **Upload**: libcurl POST to C2 at 179.43.166[.]242

### 6. Persistence

The malware establishes persistence via a macOS LaunchAgent:

- **Plist path**: `~/Library/LaunchAgents/com.apple.crashreporter.helper.plist`
- **Label**: `com.apple.crashreporter.helper`
- **Configuration**: `SuccessfulExit=false` (restarts on crash/non-zero exit)

### 7. Anti-Forensics / Evasion Techniques

- **Code signing abuse**: Valid Apple notarization + Developer ID bypasses Gatekeeper
- **Ad-hoc re-signing**: Runtime re-signing changes the binary hash per-install
- **Name impersonation**: `com.apple.crashreporter` mimics a legitimate Apple bundle ID
- **Control-flow flattening**: Obfuscates binary analysis
- **Encrypted strings**: Runtime decryption from `__const` section prevents static string extraction
- **Anti-debugging**: Dual-layer sysctl `KERN_PROC`/`P_TRACED` checks; exits with code 45
- **PIN-gated distribution**: Meeting PIN requirement limits automated sandbox analysis
- **Hidden staging**: Uses dot-prefixed directories (`/tmp/.CrashReporter/`, `.zx_` archives)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| macOS | `~/Library/LaunchAgents/com.apple.crashreporter.helper.plist` | n/a | Persistence LaunchAgent plist |
| macOS | `~/Library/Caches/com.apple.crashreporter/CrashReporter.app` | n/a (re-signed per install) | Main payload application bundle |
| macOS | `/tmp/.CrashReporter/` | n/a | Hidden staging/working directory |
| macOS | `~/.cache/com.apple.crashreporter/` | n/a | Encrypted archive staging directory |
| macOS | `~/.cache/.sys_auth` | n/a | Cached validated credentials (mode 600) |
| macOS | `.zx_[0-9a-f]{8}` files | n/a | Encrypted exfiltration archives |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 179.43.166[.]242 | Primary C2 server |
| Domain | werkbit[.]io | Dropper distribution site |
| Domain | endpoint-api-v1[.]com | Payload download server |
| Domain | cohezo[.]io | Associated infrastructure |
| Domain | cohezo[.]com | Associated infrastructure |
| Domain | cordinex[.]io | Associated infrastructure |
| URL Pattern | hxxp://endpoint-api-v1[.]com/d/f1b24e/download | Payload download endpoint |
| GitHub | github[.]com/mgothiclove/pkeys | Staging repository hosting sys.cache |

### Code Signing

| Attribute | Value |
|-----------|-------|
| Developer ID | Emil Grigorov (WWB7JA7AQV) |
| Bundle ID | com.apple.crashreporter |
| LaunchAgent Label | com.apple.crashreporter.helper |
| Notarization | Valid Apple notarization ticket |

### Behavioral

- Process named `CrashReporter` or `veltod` running from user-writable paths (not `/System/Library/CoreServices/`)
- `dscl . -authonly` executed by a non-system process (credential validation)
- `security unlock-keychain` executed shortly after `dscl -authonly` by the same parent
- File creation matching `.zx_[0-9a-f]{8}` pattern in `~/.cache/` directories
- Outbound connections to 179.43.166[.]242 from user-space processes
- LaunchAgent created with label `com.apple.crashreporter.helper` (Apple does not use this label)
- Hidden directory creation at `/tmp/.CrashReporter/`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | User must mount DMG and execute Werkbit.app |
| T1553.002 | Subvert Trust Controls: Code Signing | Dropper uses valid Developer ID + Apple notarization to bypass Gatekeeper |
| T1543.001 | Create or Modify System Process: Launch Agent | Persistence via com.apple.crashreporter.helper.plist LaunchAgent |
| T1056.002 | Input Capture: GUI Input Capture | Fake macOS password prompt captures user credentials |
| T1110.001 | Brute Force: Password Guessing | dscl -authonly validates harvested credentials locally |
| T1555.001 | Credentials from Password Stores: Keychain | Unlocks and dumps macOS login keychain |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Harvests saved passwords from Chromium and Firefox browsers |
| T1005 | Data from Local System | Collects files from ~/Documents and ~/Downloads |
| T1074.001 | Data Staged: Local Data Staging | Archives data in hidden directories before exfiltration |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encryption of exfiltrated data |
| T1041 | Exfiltration Over C2 Channel | Data uploaded to C2 server via libcurl |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Impersonates Apple CrashReporter process and bundle ID |
| T1622 | Debugger Evasion | Dual-layer sysctl P_TRACED anti-debugging checks |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Runtime string decryption from __const section |

## Impact Assessment

CrashStealer poses a significant risk to macOS users, particularly those in cryptocurrency and business environments. The Apple-notarized delivery mechanism means standard Gatekeeper and XProtect defenses are bypassed at the time of initial execution. The breadth of collection (browsers, wallets, password managers, keychain, documents) means a successful infection results in comprehensive credential and financial data compromise. The local password validation ensures only actionable credentials reach the attacker, increasing the operational value of each infection.

The meeting-PIN distribution model suggests targeted rather than mass-market deployment, potentially indicating a threat actor focused on high-value targets (cryptocurrency holders, business executives).

## Detection & Remediation

### Immediate Detection

Check for CrashStealer persistence artifacts:

```bash
# Check for the malicious LaunchAgent
ls -la ~/Library/LaunchAgents/com.apple.crashreporter.helper.plist

# Check for staging directories
ls -la /tmp/.CrashReporter/ 2>/dev/null
ls -la ~/.cache/com.apple.crashreporter/ 2>/dev/null

# Check for cached credentials
ls -la ~/.cache/.sys_auth 2>/dev/null

# Check for CrashReporter in unexpected locations
find ~/Library/Caches -name "CrashReporter.app" -type d 2>/dev/null

# Check for the malicious bundle ID in running processes
launchctl list | grep com.apple.crashreporter.helper

# Check for encrypted archives with .zx_ prefix
find ~/.cache -name ".zx_*" 2>/dev/null

# Verify the Developer ID (if the app is still present)
codesign -dvv ~/Library/Caches/com.apple.crashreporter/CrashReporter.app 2>&1 | grep "Developer ID"
```

### Remediation

1. **Containment**: Immediately disconnect the affected system from the network to halt C2 communication and ongoing exfiltration
2. **Remove persistence**: `launchctl unload ~/Library/LaunchAgents/com.apple.crashreporter.helper.plist` then delete the plist
3. **Remove payload**: Delete `~/Library/Caches/com.apple.crashreporter/` directory tree
4. **Clean staging**: Remove `/tmp/.CrashReporter/`, `~/.cache/com.apple.crashreporter/`, and `~/.cache/.sys_auth`
5. **Rotate all credentials**: Assume all browser-saved passwords, keychain entries, and password manager data are compromised; change all passwords starting with financial and email accounts
6. **Revoke browser sessions**: Sign out of all browser sessions and revoke OAuth tokens
7. **Cryptocurrency**: Transfer assets from any wallet whose extension was installed on the compromised system to new wallets generated on a clean device
8. **Report Developer ID**: Report Emil Grigorov (WWB7JA7AQV) to Apple for revocation via Apple's Developer ID revocation process
9. **Monitor**: Watch for unauthorized access to accounts using the compromised credentials

### Long-Term Hardening

- Deploy endpoint detection that monitors LaunchAgent creation in user directories, especially those mimicking Apple bundle IDs
- Block the identified C2 infrastructure at the network perimeter
- Consider application allowlisting beyond Gatekeeper (e.g., Santa by Google)
- Train users to be skeptical of "meeting software" downloads gated behind PINs
- Monitor for `dscl -authonly` invocations from non-system processes as a behavioral indicator

## Detection Rules

The following rules target CrashStealer-specific artifacts at the PoC/advisory-specific altitude. They cover persistence (LaunchAgent), credential validation (dscl), network infrastructure (C2 domains/IP), file system staging paths, and binary-level string patterns. Note that Sigma rules for macOS-specific log sources require appropriate endpoint telemetry (e.g., Jamf Protect, CrowdStrike Falcon, or similar macOS EDR).

### Sigma: CrashStealer macOS LaunchAgent Persistence

Detects creation of the CrashStealer persistence LaunchAgent plist.
**Status:** compile via sigma-convert to Splunk/LogScale -- passed | confidence: high

<!-- Validation: sigma convert --without-pipeline -t splunk passed (exit 0). sigma convert --without-pipeline -t log_scale passed (exit 0). sigma check failed due to network error fetching MITRE ATT&CK data (proxy 403), not a rule defect. Rule structure validated by successful backend conversion. -->

```yaml
title: CrashStealer macOS LaunchAgent Persistence
id: 7a3c1e2f-9b4d-4f8a-a5c6-d7e0f1b2c3d4
status: experimental
description: >
    Detects creation of a LaunchAgent plist file mimicking Apple's CrashReporter
    service, as used by the CrashStealer macOS infostealer for persistence.
    The malware installs com.apple.crashreporter.helper.plist in the user
    LaunchAgents directory to survive reboots.
references:
    - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
    - https://www.bleepingcomputer.com/news/security/new-crashstealer-malware-poses-as-apple-crash-reporting-tool/
    - https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html
author: Actioner
date: 2026-07-14
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith: '/Library/LaunchAgents/com.apple.crashreporter.helper.plist'
    condition: selection
falsepositives:
    - Legitimate Apple CrashReporter LaunchAgent updates (Apple does not use this exact plist name)
level: high
```

### Sigma: CrashStealer Credential Validation via dscl

Detects the use of `dscl -authonly` for local password validation in the context of CrashStealer process activity.
**Status:** compile via sigma-convert to Splunk/LogScale -- passed | confidence: high

<!-- Validation: sigma convert --without-pipeline -t splunk passed (exit 0): CommandLine="*dscl*" CommandLine="*-authonly*" ParentImage="*/veltod" OR Image="*crashreporter*". sigma convert --without-pipeline -t log_scale passed (exit 0). v2: Scoped to CrashStealer process context to eliminate altitude violation on generic dscl -authonly. Changed ATT&CK tag from T1078.003 to T1110.001. Elevated from medium to high confidence/level. -->

```yaml
title: CrashStealer Credential Validation via dscl
id: 8b4d2f3a-0c5e-4a9b-b6d7-e8f1a2c3d4e5
status: experimental
description: >
    Detects use of the macOS Directory Service command-line tool (dscl) with
    the -authonly flag in the context of CrashStealer activity. The malware
    locally validates harvested user credentials before exfiltration via
    dscl -authonly, avoiding sending invalid passwords to the C2 server.
    Scoped to CrashStealer process context (veltod binary or crashreporter
    parent) to avoid false positives from legitimate admin scripts.
references:
    - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
    - https://www.bleepingcomputer.com/news/security/new-crashstealer-malware-poses-as-apple-crash-reporting-tool/
    - https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html
author: Actioner
date: 2026-07-14
tags:
    - attack.t1110.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_cmd:
        CommandLine|contains|all:
            - 'dscl'
            - '-authonly'
    selection_context_parent:
        ParentImage|endswith: '/veltod'
    selection_context_image:
        Image|contains: 'crashreporter'
    condition: selection_cmd and (selection_context_parent or selection_context_image)
falsepositives:
    - Legitimate system administration scripts using dscl for authentication checks launched from a process path containing crashreporter
level: high
```

### Sigma: Network Connection to CrashStealer C2 Infrastructure

Detects outbound connections to known CrashStealer C2 IP and associated domains.
**Status:** compile via sigma-convert to Splunk/LogScale -- passed | confidence: high

<!-- Validation: sigma convert --without-pipeline -t splunk passed (exit 0). sigma convert --without-pipeline -t log_scale passed (exit 0). sigma check failed due to network error fetching MITRE ATT&CK data (proxy 403), not a rule defect. IOC-based rule; high confidence as indicators are confirmed malicious infrastructure. -->

```yaml
title: Network Connection to CrashStealer C2 Infrastructure
id: 9c5e3a4b-1d6f-4b0c-c7e8-f9a2b3d4e5f6
status: experimental
description: >
    Detects network connections to known CrashStealer command-and-control
    infrastructure, including the primary C2 IP address and associated
    distribution and payload domains.
references:
    - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
    - https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html
author: Actioner
date: 2026-07-14
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp: '179.43.166.242'
    selection_domains:
        DestinationHostname:
            - 'werkbit.io'
            - 'endpoint-api-v1.com'
            - 'cohezo.io'
            - 'cohezo.com'
            - 'cordinex.io'
    condition: selection_ip or selection_domains
falsepositives:
    - Unlikely - these are known malicious infrastructure indicators
level: critical
```

### Sigma: CrashStealer Staging Directory File Creation

Detects file creation in CrashStealer's known staging and credential-caching paths.
**Status:** compile via sigma-convert to Splunk/LogScale -- passed | confidence: high

<!-- Validation: sigma convert --without-pipeline -t splunk passed (exit 0). sigma convert --without-pipeline -t log_scale passed (exit 0). sigma check failed due to network error fetching MITRE ATT&CK data (proxy 403), not a rule defect. High confidence as these paths are CrashStealer-specific and not used by legitimate Apple CrashReporter. -->

```yaml
title: CrashStealer Staging Directory File Creation
id: 0d6f4b5c-2e7a-4c1d-d8f9-a0b3c4e5f6a7
status: experimental
description: >
    Detects file creation in directories used by CrashStealer for staging
    collected data before exfiltration. The malware uses /tmp/.CrashReporter/
    as a hidden working directory and ~/.cache/com.apple.crashreporter/ for
    encrypted archive storage.
references:
    - https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html
author: Actioner
date: 2026-07-14
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: macos
detection:
    selection_tmp:
        TargetFilename|contains: '/tmp/.CrashReporter/'
    selection_cache:
        TargetFilename|contains: '/.cache/com.apple.crashreporter/'
    selection_sysauth:
        TargetFilename|endswith: '/.cache/.sys_auth'
    condition: selection_tmp or selection_cache or selection_sysauth
falsepositives:
    - Legitimate Apple CrashReporter does not use these specific paths
level: high
```

### YARA: CrashStealer macOS Infostealer Binary Detection

Detects CrashStealer binaries via characteristic strings including the hardcoded encryption salt, staging paths, and credential validation commands.
**Status:** compile via yarac -- passed | confidence: high

<!-- Validation: yarac crashstealer_macos_infostealer.yar /dev/null returned exit code 0. Both rules in the file compile cleanly. -->

```yara
rule Malware_CrashStealer_macOS_Infostealer
{
    meta:
        description = "Detects CrashStealer macOS infostealer via characteristic strings found in the binary, including its hardcoded encryption salt, staging paths, credential validation command, and bundle identifier"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $salt = "panel_salt_v1" ascii
        $path1 = "/tmp/.CrashReporter/" ascii
        $path2 = ".cache/com.apple.crashreporter" ascii
        $path3 = ".cache/.sys_auth" ascii
        $bundle = "com.apple.crashreporter" ascii
        $plist = "com.apple.crashreporter.helper" ascii
        $dscl = "dscl" ascii
        $authonly = "-authonly" ascii
        $zx_prefix = ".zx_" ascii
        $c2_ip = "179.43.166.242" ascii
        $c2_domain = "endpoint-api-v1" ascii
        // NOTE: $exit45 matches the x86_64 encoding of 'mov eax, 45' (exit code
        // on debugger detection). ARM64 uses a different instruction encoding
        // (e.g., MOV W0, #0x2D / MOV X8, #0x1 / SVC #0) so this pattern will
        // NOT match ARM64 (Apple Silicon) builds of the malware.
        $exit45 = { B8 2D 00 00 00 }

    condition:
        filesize < 10MB and
        (
            ($salt and 2 of ($path*)) or
            ($bundle and $plist and 1 of ($path*)) or
            ($dscl and $authonly and 1 of ($path*)) or
            (4 of them)
        )
}

rule Malware_CrashStealer_Dropper_Werkbit
{
    meta:
        description = "Detects the Werkbit dropper used to deliver CrashStealer macOS infostealer, based on distribution infrastructure strings and staging behavior"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $werkbit = "werkbit" ascii nocase
        $veltod = "veltod" ascii
        $sys_cache = "sys.cache" ascii
        $github = "mgothiclove" ascii
        $endpoint = "endpoint-api-v1" ascii
        $c2 = "179.43.166.242" ascii

    condition:
        filesize < 20MB and
        (
            ($werkbit and ($veltod or $sys_cache)) or
            ($github and $sys_cache) or
            ($endpoint and 1 of ($werkbit, $veltod, $c2))
        )
}
```

### Suricata: DNS Queries to CrashStealer Infrastructure

Detects DNS lookups for known CrashStealer distribution, payload, and associated domains.
**Status:** compile via suricata -T -- passed | confidence: high

<!-- Validation: suricata -T -S crashstealer_dns_c2.rules -l /tmp/actioner-rules returned "Configuration provided was successfully loaded. Exiting." (exit 0). All 4 rules validated. -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CrashStealer Distribution Domain werkbit.io"; flow:to_server; dns.query; content:"werkbit.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/crashstealer-macos-malware-uses.html; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CrashStealer Payload Server endpoint-api-v1.com"; flow:to_server; dns.query; content:"endpoint-api-v1.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CrashStealer Associated Domain cohezo"; flow:to_server; dns.query; content:"cohezo."; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CrashStealer Associated Domain cordinex.io"; flow:to_server; dns.query; content:"cordinex.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100104; rev:1;)
```

### Suricata: HTTP Requests to CrashStealer Payload and C2

Detects HTTP connections to the CrashStealer payload download endpoint and primary C2 server.
**Status:** compile via suricata -T -- passed | confidence: high

<!-- Validation: suricata -T -S crashstealer_http_payload.rules -l /tmp/actioner-rules returned "Configuration provided was successfully loaded. Exiting." (exit 0). Both rules validated. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to CrashStealer Payload Download Endpoint"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/d/f1b24e/download"; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100105; rev:1;)

alert http $HOME_NET any -> 179.43.166.242 any (msg:"Actioner - HTTP Connection to CrashStealer C2 Server"; flow:established,to_server; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/crashstealer-macos-malware-uses.html; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created_at 2026-07-14; sid:2100106; rev:1;)
```

### Snort: DNS Queries to CrashStealer Domains

Detects DNS lookups for CrashStealer distribution and payload domains via DNS wire-format matching.
**Status:** uncompiled (structural check only) | confidence: high

<!-- Snort 3 is not installed in this environment. v2 fixes: (1) sid:2100201 — changed comma-delimited content modifiers to semicolons (Snort requires semicolons between keywords). (2) sid:2100202 — fixed DNS label length byte from |10| (decimal 16) to |0f| (decimal 15) for "endpoint-api-v1" (15 characters), and same comma-to-semicolon fix. Both rules bumped to rev:2. -->

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to CrashStealer Distribution Domain werkbit.io"; flow:to_server; content:"|07|werkbit|02|io|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/crashstealer-macos-malware-uses.html; metadata:author Actioner, created 2026-07-14; sid:2100201; rev:2;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to CrashStealer Payload Server endpoint-api-v1.com"; flow:to_server; content:"|0f|endpoint-api-v1|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html; metadata:author Actioner, created 2026-07-14; sid:2100202; rev:2;)
```

## Lessons Learned

1. **Apple notarization is not a security guarantee.** CrashStealer demonstrates that notarized and signed applications can still be malicious. Organizations should not rely on Gatekeeper alone and should deploy additional behavioral detection on macOS endpoints.

2. **C++ infostealers raise the bar for macOS defenders.** The shift from AppleScript/shell-based stealers to compiled C++ with control-flow flattening and encrypted strings significantly increases the cost of analysis and reduces the effectiveness of simple string-matching detection.

3. **Local credential validation is an emerging pattern.** By validating passwords locally before exfiltration, CrashStealer ensures only actionable data reaches the C2 — reducing noise for the operator and making the stolen data immediately usable. Defenders should monitor for `dscl -authonly` calls from non-system processes.

## Sources

- [The Hacker News](https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html) — Initial coverage of CrashStealer with technical details from Jamf Threat Labs research
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-crashstealer-malware-poses-as-apple-crash-reporting-tool/) — Coverage of credential validation technique and LaunchAgent persistence details
- [SecurityAffairs](https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html) — Most detailed IOC coverage including file paths, encryption parameters, network infrastructure, and MITRE ATT&CK mapping

---
*Report generated by Actioner*
