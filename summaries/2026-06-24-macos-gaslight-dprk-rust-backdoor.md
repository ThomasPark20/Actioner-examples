# Technical Analysis Report: macOS.Gaslight DPRK Rust Backdoor (2026-06-24)

Prepared by: Actioner
Date: 2026-06-24

## Executive Summary

macOS.Gaslight is a Rust-based macOS backdoor assessed with high confidence as DPRK-aligned activity. The implant uses Telegram Bot API as its command-and-control channel, employing AES-GCM encryption with TLS certificate pinning for communications security. Its most novel feature is an embedded 3.5 KB prompt injection payload containing 38 fabricated system messages designed to mislead LLM-assisted malware analysis tools into aborting or misclassifying the sample -- targeting the analyst rather than the sandbox.

The backdoor supports remote shell execution, process killing, file exfiltration, and deploys an embedded Python stealer that harvests browser data (Chrome, Brave, Firefox, Safari), keychain credentials, terminal histories, and system profiles. Persistence is achieved via LaunchAgent masquerading under the Apple namespace (`com.apple.system.services.activity`). Apple has deployed XProtect detections under the rules `MACOS_BONZAI_COBUCH` and `AIRPIPE`.

## Background

This threat was publicly disclosed by SentinelLABS in their analysis of a DPRK-aligned macOS threat cluster. The malware family represents an evolution in North Korean macOS targeting capabilities, building on prior Rust and Go-based tooling such as RustBucket and KandyKorn. The campaign primarily targets cryptocurrency and Web3 organizations.

The "Gaslight" name reflects the implant's signature anti-analysis technique: embedding fabricated LLM system messages to gaslight automated analysis pipelines into producing false negatives. This represents a novel adaptation by threat actors to counter the growing use of AI-assisted security tooling.

## Technical Analysis of the Malicious Payload

### Stage 1: Rust Mach-O Implant

The primary payload is a 64-bit Mach-O binary compiled in Rust, ad-hoc signed with the identifier `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`. The binary contains a 15-field plaintext configuration schema deserialized via `serde`, including fields for Telegram C2 parameters, GitHub-based fallback infrastructure (not exercised in the analyzed sample), AES encryption keys, and per-platform persistence configuration.

**Configuration Schema Fields:**
`tg_room_id`, `main_upload_url`, `main_base_url`, `aes_key`, `github_token`, `github_repo`, `github_polling_interval`, `payload_path_linux`, `payload_path_macos`, `persist_name_linux`, `persist_name_macos`, `persist_type_linux`, `persist_type_macos`, `init_python_enable`, `persist_enable`

### Stage 2: C2 Communications

- **Protocol:** Telegram Bot API via `getUpdates` polling loop
- **Encryption:** AES-GCM (via Rust `aes-gcm` crate v0.10.3) with fresh nonces generated via `CCRandomGenerateBytes`
- **Transport Security:** TLS certificate pinning via `SecTrustSetAnchorCertificatesOnly`; proxy-aware via `SCDynamicStoreCopyProxies`
- **Exfiltration:** Telegram multipart file upload using `attach://` scheme
- **OPSEC:** Bot token self-redaction -- when URL path equals "file" (`0x656c6966` little-endian), the constructor replaces the token with `file/token:redacted`
- **Single-Instance Locking:** Telegram API conflict detection prevents duplicate implant instances

### Stage 3: Command Capabilities

| Command | Function |
|---------|----------|
| `help` | Display command menu |
| `id` | Identify implant to operator |
| `shell` | Execute commands via `execvp` or `posix_spawnp` |
| `kill` | Terminate process by PID |
| `upload` | Exfiltrate files via Telegram |
| `stop` | Halt the implant |
| `focus` | Unknown (unrecovered) |

### Stage 4: Embedded Python Stealer

A 6.6 KB base64-encoded Python script is deployed via a 2 KB bash installer that fetches a standalone `cpython-3.10.18` runtime from `astral-sh/python-build-standalone` (build date `20250708`), targeting both arm64 and x86_64 architectures. The stealer collects:

- Chrome, Brave, Firefox, and Safari browser data
- Terminal command histories
- Installed application listings
- Running process snapshot (`ps aux`)
- System hardware/software profile (`system_profiler`)
- Raw copy of `login.keychain-db`
- Output archived to `temp/collected_data.zip`

### Persistence

LaunchAgent persistence using the label `com.apple.system.services.activity`, masquerading under the Apple namespace. The implant also creates `IOPMAssertionCreateWithName` power management assertions to prevent system sleep and maintain C2 connectivity.

### Anti-Analysis: LLM Prompt Injection

The binary embeds a 3.5 KB Markdown-fenced blob containing 38 fabricated "system" messages delimited by `{{DATA}}` tokens. These messages mimic LLM harness scaffolding and include themes such as fake token expiry, out-of-memory kills, disk exhaustion, operation failures, and injection vulnerability warnings. The goal is to cause LLM-assisted analysis tools to abort, refuse analysis, or produce incorrect classifications.

### Additional Evasion

- Runtime API resolution via `dlsym` to avoid static symbol table entries
- Dynamic executable path resolution via `__NSGetExecutablePath`
- Minimal conventional sandbox evasion -- the focus is on analyst-layer deception

## Indicators of Compromise (IOCs)

### File Hashes

| Type | Hash | Description |
|------|------|-------------|
| SHA-256 | `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525` | Primary Gaslight Rust implant |
| SHA-256 | `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca` | Sibling BONZAI variant |
| SHA-256 | `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239` | Embedded Python stealer payload |
| SHA-256 | `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394` | Bash installer script |

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | api[.]telegram[.]org | C2 channel (Telegram Bot API) |
| URI Path | /bot\<TOKEN\>/getUpdates | C2 polling endpoint |
| URI Scheme | attach:// | Telegram file upload exfiltration |

### Host Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Code Signing ID | `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea` | Ad-hoc signing identifier |
| LaunchAgent Label | `com.apple.system.services.activity` | Persistence mechanism |
| File Path | `temp/collected_data.zip` | Stealer output archive |
| File Target | `login.keychain-db` | Credential theft target |
| String | `file/token:redacted` | Bot token redaction placeholder |
| String | `{{DATA}}` | Prompt injection delimiter |
| Build Artifact | `20250708` | Python installer build date |
| XProtect Rule | `MACOS_BONZAI_COBUCH` | Apple detection signature |
| XProtect Rule | `AIRPIPE` | Apple detection signature |

### Rust Crate / Dependency Indicators

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes-gcm` | 0.10.3 | Payload encryption |
| `serde` | -- | Configuration deserialization |
| `reqwest`/`hyper` | -- | HTTP networking stack |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1543.001 | Create or Modify System Process: Launch Agent | Persistence via `com.apple.system.services.activity` LaunchAgent |
| T1036.004 | Masquerading: Masquerade Task or Service | LaunchAgent label masquerades under Apple namespace |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 via Telegram Bot API over HTTPS |
| T1102.002 | Web Service: Bidirectional Communication | Telegram used as bidirectional C2 channel |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-GCM encryption of C2 payloads |
| T1553.002 | Subvert Trust Controls: Code Signing | Ad-hoc signed binary bypasses Gatekeeper |
| T1059.006 | Command and Scripting Interpreter: Python | Embedded Python stealer deployed at runtime |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell command execution via `execvp`/`posix_spawnp` |
| T1555.001 | Credentials from Password Stores: Keychain | Harvesting `login.keychain-db` |
| T1005 | Data from Local System | Collection of browser data, histories, app listings |
| T1082 | System Information Discovery | System profiling via `system_profiler` and `ps aux` |
| T1029 | Scheduled Transfer | Sleep prevention assertion to maintain C2 availability |
| T1041 | Exfiltration Over C2 Channel | File upload via Telegram `attach://` |
| T1027.009 | Obfuscated Files or Information: Embedded Payloads | Base64-encoded Python stealer and bash installer |
| T1106 | Native API | Runtime API resolution via `dlsym`; `IOPMAssertionCreateWithName` |
| T1140 | Deobfuscate/Decode Files or Information | Base64 decoding of embedded payloads at runtime |

## Detection & Remediation

### Immediate Detection

1. **Hash-based blocking:** Add all four SHA-256 hashes to endpoint detection blocklists and SIEM watchlists for immediate alerting.
2. **LaunchAgent monitoring:** Monitor for creation of plist files under `~/Library/LaunchAgents/` or `/Library/LaunchAgents/` with labels containing `com.apple.system.services.activity`.
3. **Network monitoring:** Alert on outbound HTTPS connections to `api[.]telegram[.]org` with URI paths matching `/bot*/getUpdates` from non-Telegram-client processes.
4. **Code signing validation:** Flag execution of ad-hoc signed Mach-O binaries with signing identifiers matching the `endpoint-macos-aarch64-*` pattern.
5. **Credential access monitoring:** Detect processes accessing `login.keychain-db` outside of expected system or user-initiated keychain operations.
6. **XProtect verification:** Ensure Apple XProtect definitions are current and include `MACOS_BONZAI_COBUCH` and `AIRPIPE` signatures.

### Remediation

1. Isolate affected hosts and preserve forensic images before remediation.
2. Remove the malicious LaunchAgent plist (`com.apple.system.services.activity`).
3. Identify and remove the Gaslight binary using the ad-hoc signing identifier or file hash.
4. Remove any staged Python runtime and `collected_data.zip` archives.
5. Rotate all credentials accessible from the compromised host, including keychain-stored passwords, browser-saved credentials, and any tokens/keys in terminal histories.
6. Review Telegram API access logs if corporate Telegram usage exists to identify any bot tokens that may have been created for C2.
7. Scan for lateral movement indicators given DPRK actors' focus on cryptocurrency infrastructure.

## Detection Rules

### Sigma: macOS.Gaslight LaunchAgent Persistence via Apple Namespace Masquerade

Detects creation of LaunchAgent plists using the `com.apple.system.services.activity` label associated with macOS.Gaslight persistence.

**Status:** ✅ compiles (sigma convert splunk exit 0, sigma convert log_scale exit 0) | **Confidence:** high

```yaml
title: macOS.Gaslight LaunchAgent Persistence via Apple Namespace Masquerade
id: 7a3e1d4f-8c2b-4e6a-9f01-3b5d7c8e2a14
status: experimental
description: Detects creation of a LaunchAgent plist masquerading as an Apple system service, consistent with macOS.Gaslight DPRK backdoor persistence using the label com.apple.system.services.activity.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1543.001
    - attack.t1036.004
logsource:
    category: file_event
    product: macos
detection:
    selection_path:
        TargetFilename|contains: '/LaunchAgents/'
    selection_label:
        TargetFilename|contains: 'com.apple.system.services.activity'
    condition: selection_path and selection_label
falsepositives:
    - Legitimate Apple system services (verify against known Apple LaunchAgent labels)
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to network error fetching MITRE STIX data (IncompleteRead), not a rule syntax issue -->

---

### Sigma: Potential Telegram Bot API C2 Communication

Detects outbound HTTP requests to the Telegram Bot API `getUpdates` endpoint used by macOS.Gaslight for C2 polling.

**Status:** ✅ compiles (sigma convert splunk exit 0, sigma convert log_scale exit 0) | **Confidence:** medium

```yaml
title: Potential Telegram Bot API C2 Communication from macOS Process
id: 9b2f4e7c-1a3d-4f8e-b6c5-2d9e8a7f3b01
status: experimental
description: Detects outbound HTTP requests to the Telegram Bot API getUpdates endpoint, which is used by macOS.Gaslight and other malware as a C2 polling mechanism.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: 'api.telegram.org'
    selection_endpoint:
        c-uri|contains: '/getUpdates'
    condition: selection_domain and selection_endpoint
falsepositives:
    - Legitimate Telegram bot integrations
    - Developer testing environments
level: medium
```

Caveat: Telegram Bot API is a legitimate service; tune for environments where Telegram bot usage is unexpected.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to network error (IncompleteRead) -->

---

### Sigma: macOS.Gaslight Python Stealer Data Collection Activity

Detects command patterns consistent with the macOS.Gaslight embedded Python stealer harvesting browser data, keychain, and system profiles.

**Status:** ✅ compiles (sigma convert splunk exit 0, sigma convert log_scale exit 0) | **Confidence:** medium

```yaml
title: macOS.Gaslight Python Stealer Data Collection Activity
id: 5d9f3e2b-8a4c-4b7e-c1d6-2f7e9a3b8c45
status: experimental
description: Detects command patterns consistent with the macOS.Gaslight embedded Python stealer that collects browser data, keychain, command histories, and system profiles.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1555.001
    - attack.t1005
    - attack.t1082
logsource:
    category: process_creation
    product: macos
detection:
    selection_keychain:
        CommandLine|contains: 'login.keychain-db'
    selection_profiler:
        CommandLine|contains: 'system_profiler'
    selection_collected:
        CommandLine|contains: 'collected_data.zip'
    condition: 1 of selection_*
falsepositives:
    - System administration scripts
    - Legitimate backup tools accessing keychain
    - IT asset management software running system_profiler
level: medium
```

Caveat: Individual selection criteria (especially `system_profiler`) are broad; consider correlating multiple selections in a single time window for higher fidelity.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to network error (IncompleteRead) -->

---

### Sigma: macOS Ad-hoc Signed Binary with Endpoint Identifier Pattern

Detects execution of ad-hoc signed binaries with signing identifiers matching the `endpoint-macos-aarch64-*` pattern used by macOS.Gaslight.

**Status:** ✅ compiles (sigma convert splunk exit 0, sigma convert log_scale exit 0) | **Confidence:** high

```yaml
title: macOS Ad-hoc Signed Binary with Endpoint Identifier Pattern
id: 6e0a4f3c-9b5d-4c8f-d2e7-3a8f1b4c9d56
status: experimental
description: Detects execution of ad-hoc signed macOS binaries with signing identifiers matching the pattern used by macOS.Gaslight (endpoint-macos-aarch64-*), indicating a potentially malicious unsigned Rust binary.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1553.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CodeSigningIdentifier|startswith: 'endpoint-macos-aarch64-'
    condition: selection
falsepositives:
    - Legitimate developer builds with similar naming convention
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to network error (IncompleteRead) -->

---

### Sigma: macOS Sleep Prevention via IOPMAssertionCreateWithName

Detects processes preventing system sleep, a technique used by macOS.Gaslight to maintain persistent C2 connectivity.

**Status:** ✅ compiles (sigma convert splunk exit 0, sigma convert log_scale exit 0) | **Confidence:** low

```yaml
title: macOS Sleep Prevention via IOPMAssertionCreateWithName
id: 4c8e2f1a-7b3d-4a9e-8d6f-1e5c3a2b7d90
status: experimental
description: Detects processes creating power management assertions to prevent system sleep, a technique used by macOS.Gaslight to maintain persistent C2 connectivity.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1029
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains: 'caffeinate'
    filter_known:
        Image|endswith:
            - '/caffeinate'
            - '/pmset'
    condition: selection and not filter_known
falsepositives:
    - Legitimate applications preventing sleep during long operations
    - Backup software
    - Media applications
level: low
```

Caveat: This rule uses a proxy indicator (`caffeinate` command line) since `IOPMAssertionCreateWithName` is an API call not typically visible in process creation logs; requires endpoint telemetry that captures API calls for direct detection.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to network error (IncompleteRead) -->

---

### YARA: macOS.Gaslight Rust Backdoor (3 rules)

Detects the primary Gaslight Mach-O implant, the embedded Python stealer payload, and the bash installer via distinctive string combinations and file structure.

**Status:** ✅ compiles (yarac exit 0) | **Confidence:** high (Mach-O rule), medium (Python stealer), medium (bash installer)

```yara
rule macOS_Gaslight_Rust_Backdoor
{
    meta:
        description = "Detects macOS.Gaslight DPRK Rust backdoor based on embedded configuration schema fields, prompt injection markers, and unique strings"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"

    strings:
        // Configuration schema fields (serde)
        $cfg_tg_room = "tg_room_id" ascii
        $cfg_main_upload = "main_upload_url" ascii
        $cfg_main_base = "main_base_url" ascii
        $cfg_aes_key = "aes_key" ascii
        $cfg_github_token = "github_token" ascii
        $cfg_github_repo = "github_repo" ascii
        $cfg_payload_macos = "payload_path_macos" ascii
        $cfg_persist_macos = "persist_name_macos" ascii
        $cfg_persist_type = "persist_type_macos" ascii
        $cfg_init_python = "init_python_enable" ascii
        $cfg_persist_enable = "persist_enable" ascii

        // Prompt injection markers
        $pi_marker = "{{DATA}}" ascii
        $pi_system = "[system]" ascii

        // Bot token redaction
        $redact = "file/token:redacted" ascii

        // Command verbs
        $cmd_shell = "shell" ascii
        $cmd_upload = "upload" ascii
        $cmd_kill = "kill" ascii
        $cmd_focus = "focus" ascii

        // Collection artifact path
        $collect_path = "collected_data.zip" ascii

        // LaunchAgent label
        $la_label = "com.apple.system.services.activity" ascii

        // Ad-hoc signing identifier prefix
        $signing_id = "endpoint-macos-aarch64-" ascii

        // Rust aes-gcm crate indicator
        $aes_gcm = "aes-gcm" ascii

    condition:
        uint32(0) == 0xFEEDFACF and  // Mach-O 64-bit magic
        (
            (5 of ($cfg_*)) or
            ($redact and 2 of ($cfg_*)) or
            ($la_label and $signing_id) or
            ($pi_marker and $pi_system and 2 of ($cfg_*)) or
            (8 of them)
        )
}

rule macOS_Gaslight_Python_Stealer
{
    meta:
        description = "Detects the embedded Python stealer payload associated with macOS.Gaslight that harvests browser data, keychain, and system information"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"

    strings:
        $browser_chrome = "Chrome" ascii
        $browser_brave = "Brave" ascii
        $browser_firefox = "Firefox" ascii
        $browser_safari = "Safari" ascii
        $keychain = "login.keychain-db" ascii
        $ps_aux = "ps aux" ascii
        $sys_prof = "system_profiler" ascii
        $collected = "collected_data.zip" ascii

    condition:
        filesize < 50KB and
        $keychain and
        $collected and
        3 of ($browser_*) and
        ($ps_aux or $sys_prof)
}

rule macOS_Gaslight_Bash_Installer
{
    meta:
        description = "Detects the Bash installer script used by macOS.Gaslight to deploy a standalone Python runtime for payload execution"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"

    strings:
        $python_standalone = "python-build-standalone" ascii
        $astral = "astral-sh" ascii
        $cpython = "cpython-3.10" ascii
        $build_date = "20250708" ascii

    condition:
        filesize < 10KB and
        3 of them
}
```

<!-- audit: yarac gaslight_macho.yar /dev/null exit 0; all three rules compile successfully -->

---

### Snort: macOS.Gaslight Telegram C2 Network Detection (2 rules)

Detects Telegram Bot API C2 polling and file upload exfiltration patterns associated with macOS.Gaslight network communications.

**Status:** ⚠️ uncompiled (structural check only) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram Bot API getUpdates C2 Polling"; flow:established,to_server; content:"api.telegram.org"; content:"/bot"; content:"/getUpdates"; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram File Upload Exfiltration"; flow:established,to_server; content:"api.telegram.org"; content:"attach://"; sid:2100002; rev:1; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/;)
```

Caveat: TLS inspection (SSL/TLS decryption) is required to inspect HTTPS traffic to `api[.]telegram[.]org`; without it, content matching will not fire.

<!-- audit: snort not installed; structural review only; rules follow standard Snort 2.x/3.x syntax with flow, content, sid, classtype, reference -->

---

### Suricata: macOS.Gaslight Telegram C2 Network Detection (2 rules)

Detects Telegram Bot API C2 polling and file upload exfiltration using Suricata dot-notation sticky buffers.

**Status:** ✅ compiles (suricata -T exit 0) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram Bot API getUpdates C2 Polling"; flow:established,to_server; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"/getUpdates"; sid:2200001; rev:1; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram File Upload Exfiltration"; flow:established,to_server; http.host; content:"api.telegram.org"; http.request_body; content:"attach://"; sid:2200002; rev:1; classtype:trojan-activity; reference:url,www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/; metadata: author Actioner;)
```

Caveat: Requires TLS decryption or JA3/JA4 fingerprinting for encrypted Telegram traffic; `http.host` may match via TLS SNI without decryption.

<!-- audit: suricata -T -S gaslight_telegram_c2_suricata.rules -l /tmp/actioner exit 0; "Configuration provided was successfully loaded. Exiting." -->

---

## Sources

- [SentinelLABS: macOS.Gaslight - Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/)
- [Malware.News: macOS.Gaslight Coverage](https://malware.news/t/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/108165)
- [SentinelOne: BlueNoroff macOS RustBucket Analysis](https://www.sentinelone.com/blog/bluenoroff-how-dprks-macos-rustbucket-seeks-to-evade-analysis-and-detection/)
- [SentinelOne: DPRK Crypto Theft - RustBucket to KandyKorn](https://www.sentinelone.com/blog/dprk-crypto-theft-macos-rustbucket-droppers-pivot-to-deliver-kandykorn-payloads/)
- [SentinelOne: macOS NimDoor - DPRK Targets Web3](https://www.sentinelone.com/labs/macos-nimdoor-dprk-threat-actors-target-web3-and-crypto-platforms-with-nim-based-malware/)

---

*Report generated by Actioner*
