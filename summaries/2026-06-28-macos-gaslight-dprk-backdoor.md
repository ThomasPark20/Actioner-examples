# Technical Analysis Report: macOS.Gaslight (2026-06-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-28
Version: 1.0

## Executive Summary

macOS.Gaslight is a Rust-based macOS backdoor attributed to a DPRK-aligned threat cluster, discovered by SentinelLabs in June 2026. The implant uses Telegram Bot API for command-and-control, deploys an embedded Python credential stealer targeting browser data and macOS Keychain, and persists via a LaunchAgent masquerading as an Apple system service (`com.apple.system.services.activity`). Its most novel feature is a 3.5 KB Markdown-fenced payload containing 38 fabricated "system messages" designed to poison LLM-assisted malware analysis tools via prompt injection -- targeting analyst perception rather than sandbox evasion. The sample was uploaded to VirusTotal on May 22, 2026 and was undetected by static engines at the time of SentinelLabs' analysis. Apple's XProtect flagged a sibling sample under the rule `MACOS_BONZAI_COBUCH`, connecting it to known North Korean macOS activity.

## Background: macOS Threat Landscape and DPRK Activity

North Korea-linked groups have increasingly targeted macOS in recent years, leveraging the platform's growing enterprise adoption and historically lighter security tooling compared to Windows. macOS.Gaslight represents an evolution in this trend: beyond the standard credential theft and C2 implant functionality, it introduces a deliberate anti-analysis layer targeting AI-assisted reverse engineering workflows. The prompt injection payload is the first known instance of malware specifically designed to mislead LLM-based analysis tools, reflecting the adversary's awareness that automated AI triage is now part of the defender workflow.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-07-08 (BUILD_DATE) | Bash installer build date constant embedded in sample |
| 2026-05-22 | Sample uploaded to VirusTotal |
| Early June 2026 | Apple XProtect update surfaces sibling sample via `MACOS_BONZAI_COBUCH` rule |
| 2026-06-23 | SentinelLabs analysis date |
| 2026-06-28 | SentinelLabs public disclosure |

## Root Cause: Initial Access Vector

The initial access vector is not detailed in the available sources. Based on DPRK-attributed macOS campaigns, likely vectors include social engineering (fake job offers, trojanized applications) or supply chain compromise. The sample's ad-hoc code signing identifier (`endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`) and cross-architecture targeting (arm64 and x86_64) suggest distribution as a standalone binary rather than a signed application bundle.

## Technical Analysis of the Malicious Payload

### 1. Rust Implant Core

The primary implant is a Rust binary targeting macOS (arm64 and x86_64). Key implementation details:

- **Networking:** Built on the `reqwest`/`hyper` Rust HTTP stack with AES-GCM encryption (aes-gcm 0.10.3 crate)
- **Nonce generation:** Uses `CCRandomGenerateBytes` (macOS CommonCrypto)
- **Certificate pinning:** Custom trust anchor via `SecTrustSetAnchorCertificatesOnly`
- **Proxy awareness:** Reads host proxy settings via `SCDynamicStoreCopyProxies`
- **API resolution:** Dynamic resolution via `dlsym` at runtime
- **Path resolution:** Dynamic executable path via `__NSGetExecutablePath`
- **Power management:** `IOPMAssertionCreateWithName` assertion to prevent system sleep during operation
- **Ad-hoc signing identifier:** `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`

#### Embedded Configuration Schema (serde)

The implant deserializes its configuration via serde with these fields:
`tg_room_id`, `github_token`, `github_repo`, `github_polling_interval`, `main_upload_url`, `main_base_url`, `aes_key`, `payload_path_linux`, `payload_path_macos`, `persist_name_linux`, `persist_name_macos`, `persist_type_linux`, `persist_type_macos`, `init_python_enable`, `persist_enable`

#### Operator Commands

| Command | Function |
|---------|----------|
| `help` | Show command help |
| `id` | Identify implant |
| `shell` | Execute commands via `execvp` or `posix_spawnp` |
| `kill` | Terminate process by PID |
| `upload` | Exfiltrate file via Telegram multipart `attach://` |
| `stop` | Halt implant |
| `focus` | Unknown (partially recovered) |

### 2. Python Credential Stealer

A 6.6 KB base64-encoded Python script is embedded in the Rust binary. Rather than bundling a Python runtime (e.g., PyInstaller/Nuitka), the malware downloads a standalone CPython 3.10.18 interpreter from the `astral-sh/python-build-standalone` project at runtime -- a novel approach.

**Data targets:**
- Chrome, Brave, Firefox, Safari browser data (cookies, credentials, history)
- Terminal command histories
- Application listings
- Running processes (`ps aux`)
- System profile (`system_profiler`)
- Raw copy of `login.keychain-db` (macOS Keychain)

**Output:** `temp/collected_data.zip`

#### Bash Installer

A 2 KB base64-encoded Bash script handles CPython deployment:
- Runtime constants: `PY_VERSION=3.10.18`, `BUILD_DATE=20250708`
- Source: `astral-sh/python-build-standalone`
- Targets: arm64 and x86_64 macOS
- SentinelLabs notes "widespread use of emojis and strict adherence to comment headers" consistent with LLM-generated code

### 3. C2 Infrastructure

- **Protocol:** Telegram Bot API over HTTPS
- **Polling mechanism:** `getUpdates` long-polling loop
- **Data exfiltration:** Telegram multipart `attach://` file upload
- **Encryption:** AES-GCM with per-message nonce via `CCRandomGenerateBytes`
- **Conflict handling:** Detects `Conflict` response when two instances poll simultaneously, terminates the second copy
- **Error handling:** Handles `BotBlocked`, `InvalidToken`, `Conflict` error codes
- **Token redaction:** When URL path segment is the 4-byte literal `file`, the constructor substitutes the bot token with hardcoded placeholder `file/token:redacted`

The Telegram bot token is supplied at runtime (not hardcoded in the binary) and is self-redacted in runtime output. No specific bot tokens, chat IDs, or Telegram endpoints were disclosed in the public analysis.

### 4. Platform-Specific Behavior

#### macOS

- **Persistence:** LaunchAgent plist with label `com.apple.system.services.activity` (masquerades as Apple's namespace)
- **Anti-sleep:** `IOPMAssertionCreateWithName` power management assertion
- **Proxy support:** Reads system proxy via `SCDynamicStoreCopyProxies`
- **Architecture:** arm64 and x86_64

The configuration schema includes `payload_path_linux` and `persist_name_linux` fields, suggesting a Linux variant may exist or be planned, though none has been observed.

### 5. Anti-Forensics / Evasion Techniques

#### Prompt Injection Payload (Novel)

The most distinctive evasion feature is a 3.5 KB Markdown-fenced blob containing 38 fabricated "system" messages, delimited by `{{DATA}}` tokens. These messages are designed to mislead LLM-based malware analysis tools by simulating:

- Token expiry warnings
- Out-of-memory kill notifications
- Disk exhaustion errors
- Injection vulnerability flags
- Static-analysis false findings

This represents the first documented case of malware embedding prompt injection payloads specifically targeting AI analyst tools rather than traditional sandbox or AV evasion.

#### Traditional Evasion

- Runtime API resolution via `dlsym` (avoids static import table analysis)
- Dynamic executable path resolution via `__NSGetExecutablePath`
- Runtime token redaction to prevent credential leakage in forensic artifacts
- Certificate pinning to prevent TLS interception

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Standalone CPython | 3.10.18 | Downloaded from astral-sh/python-build-standalone for credential stealer execution |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| macOS | N/A (primary sample) | `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525` | macOS.Gaslight Rust backdoor (primary sample) |
| macOS | N/A (sibling BONZAI) | `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca` | Sibling sample caught by XProtect MACOS_BONZAI_COBUCH |
| macOS | N/A (Python payload) | `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239` | Embedded Python credential stealer (SHA256) |
| macOS | N/A (Bash installer) | `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394` | Bash installer for CPython deployment (SHA256) |
| macOS | `temp/collected_data.zip` | N/A | Exfiltration archive created by Python stealer |
| macOS | `~/Library/LaunchAgents/com.apple.system.services.activity.plist` | N/A | Persistence LaunchAgent plist |
| macOS | `login.keychain-db` | N/A | macOS Keychain targeted for raw copy |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `api[.]telegram[.]org` | Telegram Bot API C2 communication |
| URL Pattern | `hxxps://api[.]telegram[.]org/bot<token>/getUpdates` | C2 polling endpoint |
| URL Pattern | `hxxps://api[.]telegram[.]org/bot<token>/sendDocument` (attach://) | Data exfiltration via multipart upload |

### Behavioral

- **C2 Polling:** Persistent `getUpdates` loop to Telegram Bot API with AES-GCM encrypted payloads
- **Conflict Detection:** Second implant instance terminates upon receiving Telegram `Conflict` response
- **Token Redaction:** Bot token replaced with `file/token:redacted` when URL path contains literal `file`
- **Power Assertion:** `IOPMAssertionCreateWithName` prevents system sleep during implant operation
- **Process Execution:** Commands dispatched via `execvp` or `posix_spawnp`
- **Dynamic Resolution:** API calls resolved at runtime via `dlsym`; executable path via `__NSGetExecutablePath`

### Strings

The following distinctive strings are present in the binary:

- `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea` (ad-hoc signing identifier)
- `{{DATA}}` (prompt injection delimiter)
- `tg_room_id`, `github_token`, `github_polling_interval`, `main_upload_url`, `aes_key`, `payload_path_macos`, `persist_name_macos`, `init_python_enable` (configuration field names)
- `BotBlocked`, `InvalidToken`, `Conflict` (Telegram error handlers)
- `file/token:redacted` (token redaction placeholder)
- `com.apple.system.services.activity` (persistence label)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS communication to Telegram Bot API for C2 |
| T1102.002 | Web Service: Bidirectional Communication | Telegram used as bidirectional C2 channel (getUpdates + sendDocument) |
| T1543.001 | Create or Modify System Process: Launch Agent | Persistence via LaunchAgent `com.apple.system.services.activity` |
| T1059.006 | Command and Scripting Interpreter: Python | Credential stealer executed via standalone CPython runtime |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Bash installer for CPython deployment |
| T1555.001 | Credentials from Password Stores: Keychain | Raw copy of `login.keychain-db` |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Firefox, Safari data collection |
| T1005 | Data from Local System | Collection of terminal histories, app listings, system profiles |
| T1560.001 | Archive Collected Data: Archive via Utility | Data compressed into `collected_data.zip` |
| T1132.001 | Data Encoding: Standard Encoding | Base64-encoded Python stealer and Bash installer embedded in binary |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | Rust binary with base64-encoded Python stealer and Bash installer embedded as payloads |
| T1106 | Native API | Runtime API resolution via `dlsym` |
| T1057 | Process Discovery | `ps aux` enumeration |
| T1082 | System Information Discovery | `system_profiler` execution |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-GCM encryption for C2 communications |

## Impact Assessment

- **Breadth:** Unknown; sample was uploaded to VirusTotal on May 22, 2026, suggesting at least one target encountered it. Apple XProtect's MACOS_BONZAI_COBUCH rule and related AIRPIPE detection indicate Apple has observed this cluster in the wild.
- **Depth:** High -- full credential theft (browser data, macOS Keychain), arbitrary command execution, file exfiltration
- **Stealth:** Undetected by static engines at time of analysis; prompt injection payload may degrade AI-assisted triage quality
- **Attribution:** DPRK-aligned macOS activity cluster (SentinelLabs assessment)

## Detection & Remediation

### Immediate Detection

```bash
# Check for Gaslight LaunchAgent persistence
ls -la ~/Library/LaunchAgents/com.apple.system.services.activity.plist 2>/dev/null
launchctl list | grep com.apple.system.services.activity

# Check for standalone CPython download artifacts
find /tmp -name "cpython-3.10*" -type d 2>/dev/null
find / -name "collected_data.zip" 2>/dev/null

# Check for ad-hoc signed binary with known identifier
codesign -dvvv /path/to/suspect 2>&1 | grep "5555494492fc075f441637fb9d894913dde3a2ea"

# Check for Telegram C2 network activity
lsof -i -P | grep -i telegram
log show --predicate 'processImagePath contains "api.telegram.org"' --last 24h
```

### Remediation

1. **Contain:** Isolate affected systems from network; revoke any Telegram bot tokens if identified
2. **Eradicate:** Remove LaunchAgent plist (`com.apple.system.services.activity`); kill the implant process; remove the Rust binary and any CPython runtime artifacts
3. **Recover:** Rotate all credentials stored in macOS Keychain; reset browser passwords for Chrome, Brave, Firefox, Safari; invalidate active sessions
4. **Secret rotation:** Rotate any `github_token` values if the configuration was recoverable; assume all Keychain contents compromised

### Long-Term Hardening

- Deploy endpoint detection that monitors LaunchAgent creation in Apple's namespace (`com.apple.*`)
- Monitor for outbound connections to `api.telegram.org` from non-Telegram applications
- Implement application allowlisting to prevent execution of ad-hoc signed binaries
- Review AI analysis workflows for prompt injection resistance when processing untrusted binaries
- Ensure XProtect definitions are current (MACOS_BONZAI_COBUCH, AIRPIPE rules)

## Detection Rules

These detections target the macOS.Gaslight Rust backdoor at the PoC/advisory-specific altitude, covering LaunchAgent persistence, Python stealer execution, and file-level binary signatures. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment.

> **Network detection gap:** Three network-layer rules (Sigma network_connection, Snort, and Suricata) targeting Telegram Bot API traffic were drafted and subsequently dropped during review. The Sigma rule keyed on any process connecting to `api.telegram.org` -- generic activity not specific to Gaslight. The Snort and Suricata rules inspected raw TCP/HTTP for `/bot*/getUpdates` patterns, but Gaslight communicates over HTTPS; without TLS interception these rules would not fire, and even with interception they match any Telegram bot, not this threat specifically. Meaningful network-layer detection for Gaslight will require Gaslight-specific network artifacts (e.g., unique URI paths, JA4 fingerprints, or encrypted payload signatures) not yet available from public research.

### Sigma: Suspicious LaunchAgent Persistence

Detects creation of a LaunchAgent plist using the label `com.apple.system.services.activity`, the Gaslight persistence mechanism masquerading as an Apple system service.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. This specific LaunchAgent label is not used by legitimate Apple services; high confidence that any match is malicious. -->
```yaml
title: macOS Gaslight Backdoor - Suspicious LaunchAgent Persistence
id: 2d4e6f81-a3b5-4c7d-9e0f-1b2c3d4e5f67
status: experimental
description: >
    Detects creation of a LaunchAgent plist file using the label
    com.apple.system.services.activity, which is used by the macOS.Gaslight
    Rust backdoor for persistence. This label masquerades as a legitimate
    Apple system service.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/28
tags:
    - attack.t1543.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|contains: 'com.apple.system.services.activity'
        TargetFilename|endswith: '.plist'
    condition: selection
falsepositives:
    - Unlikely - this specific label is not used by legitimate Apple services
level: high
```

### Sigma: Python Credential Stealer via Standalone CPython

Detects execution of a standalone CPython 3.10 runtime with command-line indicators consistent with the Gaslight credential harvesting module. Both the CPython image path and stealer activity markers must match (AND logic) to avoid false positives from ubiquitous tools like `system_profiler`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Revised from OR to AND logic: selection_python is specific to cpython-3.10 standalone; selection_activity catches stealer artifacts. AND prevents selection_activity from firing alone on legitimate system_profiler usage. -->
```yaml
title: macOS Gaslight - Python Credential Stealer via Standalone CPython
id: 5c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: >
    Detects execution of a standalone CPython runtime (cpython-3.10.18) spawning
    processes consistent with the macOS.Gaslight credential harvesting module.
    The malware downloads a standalone Python interpreter from astral-sh/python-build-standalone
    to run its stealer script, which collects browser data, keychains, and terminal histories
    into collected_data.zip.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/28
tags:
    - attack.t1059.006
    - attack.t1555.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_python:
        Image|contains: 'cpython-3.10'
        Image|endswith: '/python3'
    selection_activity:
        CommandLine|contains:
            - 'collected_data.zip'
            - 'login.keychain-db'
            - 'system_profiler'
    condition: selection_python and selection_activity
falsepositives:
    - Developers using standalone CPython builds from astral-sh for legitimate purposes
level: medium
```

### Snort: Telegram Bot API C2 getUpdates Polling

Detects outbound HTTP traffic to `api.telegram.org` containing both `bot` and `getUpdates` URI patterns, consistent with the Gaslight C2 polling loop.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (rule appended to local.rules). Snort 2.9.20. Generic Telegram Bot API detection; legitimate bot traffic will match — deploy with source-process context. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - macOS.Gaslight Telegram Bot API C2 getUpdates Polling"; flow:established,to_server; content:"api.telegram.org"; fast_pattern; content:"getUpdates"; content:"bot"; sid:2100101; rev:1; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/;)
```

### Suricata: Telegram Bot API C2 getUpdates Polling

Detects HTTP requests to `api.telegram.org` with `/bot*/getUpdates` URI pattern using Suricata's HTTP sticky buffers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S exit 0, "Configuration provided was successfully loaded." Suricata 7.0.3. Uses http.host + http.uri dot-notation buffers. Same FP profile as Snort variant — legitimate Telegram bot traffic will match. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - macOS.Gaslight Telegram Bot API C2 getUpdates Polling"; flow:established,to_server; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; startswith; content:"/getUpdates"; fast_pattern; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/; metadata:author Actioner, created_at 2026-06-28; sid:2200101; rev:1;)
```

### YARA: macOS.Gaslight Rust Backdoor Binary

Detects the macOS.Gaslight Rust binary via its ad-hoc signing identifier, embedded serde configuration field names, prompt injection delimiters, and operator command error strings. Sample-tested against published indicators.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt = MATCH (fired on file containing published ad-hoc signing identifier + config fields). yara neg.txt = no match (quiet on benign file). Positive constructed from published strings in SentinelLabs report — not invented. $sign alone is sufficient (unique ad-hoc identifier); 4-of-$cfg condition catches variants that change signing identity. -->
```yara
rule DPRK_macOS_Gaslight_Rust_Backdoor
{
    meta:
        description = "Detects macOS.Gaslight Rust backdoor via embedded prompt injection markers, configuration field names, operator command strings, and ad-hoc signing identifier"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        severity = "critical"

    strings:
        // Ad-hoc signing identifier (unique to this sample)
        $sign = "endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea" ascii

        // Prompt injection delimiters
        $pi_delim = "{{DATA}}" ascii

        // Serde config field names (distinctive combination)
        $cfg1 = "tg_room_id" ascii
        $cfg2 = "github_token" ascii
        $cfg3 = "github_polling_interval" ascii
        $cfg4 = "main_upload_url" ascii
        $cfg5 = "aes_key" ascii
        $cfg6 = "payload_path_macos" ascii
        $cfg7 = "persist_name_macos" ascii
        $cfg8 = "init_python_enable" ascii

        // Operator command verbs
        $cmd1 = "BotBlocked" ascii
        $cmd2 = "InvalidToken" ascii
        $cmd3 = "file/token:redacted" ascii

        // Token redaction mechanism
        $redact = "token:redacted" ascii

        // LaunchAgent label
        $persist = "com.apple.system.services.activity" ascii

    condition:
        filesize < 15MB and
        (
            $sign or
            (4 of ($cfg*)) or
            ($pi_delim and 2 of ($cfg*)) or
            ($redact and 2 of ($cmd*) and $persist)
        )
}
```

## Lessons Learned

1. **AI-targeted evasion is here.** macOS.Gaslight is the first documented malware to embed prompt injection payloads specifically designed to mislead LLM-based analysis tools. As AI-assisted triage becomes standard in SOCs and malware analysis workflows, adversaries will increasingly target the AI layer itself. Defenders should treat LLM analysis output with the same skepticism as any other automated tool output and validate findings against raw artifacts.

2. **Telegram as C2 is a growing blind spot.** The use of Telegram Bot API for command-and-control provides the attacker with reliable, encrypted, and largely unmonitored infrastructure. Organizations should monitor for non-Telegram-app processes communicating with `api.telegram.org` and consider blocking Bot API access from endpoints where Telegram is not an approved application.

3. **DPRK groups continue to innovate on macOS.** The combination of Rust implementation, novel CPython stealer deployment (runtime download vs bundled interpreter), and prompt injection payloads demonstrates continued investment in macOS capabilities by DPRK-aligned actors. macOS endpoint detection maturity should be treated with the same urgency as Windows.

## Sources

- [SentinelLabs - macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/) -- primary technical analysis with IOCs, embedded string details, and architectural breakdown
- [The Hacker News - New Gaslight macOS Malware Uses Prompt Injection](https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html) -- secondary reporting with additional context on operator commands and Python stealer
- [Security Affairs - macOS Gaslight: North Korea-linked malware that tries to gaslight the analyst](https://securityaffairs.com/194256/malware/macos-gaslight-north-korea-linked-malware-that-tries-to-gaslight-the-analyst.html) -- secondary reporting confirming attribution and XProtect detection context

---
*Report generated by Actioner*
