# macOS.Gaslight -- DPRK Rust Backdoor with Prompt Injection

<!-- revision: 2026-06-27T1 — applied critic verdict NEEDS-REVISION; dropped 5 rules (Sigma #4, Suricata #10, Snort #15/#16/#17); fixed 9 rules; corrected MITRE ATT&CK T1608.001→T1105; normalized confidence labels to high/medium/low; fixed YARA #5 hash typo, #6 threshold+confidence, #8 confidence, #9 rewritten with hash module; relabeled Suricata #11/#12/#14 and Snort #18 to medium; tightened Sigma #2 with collected_data.zip anchor; final rule count: 13 -->

## Executive Summary

macOS.Gaslight is a Rust-compiled macOS backdoor attributed with high confidence to DPRK-aligned threat activity. Discovered by SentinelOne Labs and published on June 23, 2026, the malware is notable for embedding a 3.5 KB cascade of 38 fabricated "system" messages designed to deceive LLM-based analysis tools into aborting, truncating, or refusing analysis before reaching actionable content. The implant uses Telegram Bot API as its primary C2 channel, deploys a Python-based credential stealer targeting browser data and the macOS login keychain, and persists via a LaunchAgent masquerading within Apple's `com.apple.*` namespace. Apple's XProtect detects the sample under the rule `MACOS_BONZAI_COBUCH`. The binary was uploaded to VirusTotal on May 22, 2026, where it initially evaded all static engines.

---

## Background

The macOS.Gaslight backdoor was identified during SentinelLABS analysis of the BONZAI malware family, which Apple's XProtect associates with North Korean macOS threat activity. A sibling sample was also caught by the `AIRPIPE` XProtect rule, further solidifying the DPRK attribution. The malware represents an evolution in adversarial tactics: rather than targeting sandbox environments or automated analysis infrastructure, it specifically targets the growing adoption of LLM-assisted triage pipelines by embedding adversarial prompt injection payloads directly into the binary.

This is not the first documented instance of prompt injection in malware -- Check Point documented a Windows proof-of-concept in 2025, and supply-chain payloads like Hades and Shai-Hulud (which used an "Anthropic Magic String") employed simpler single-block injections. However, macOS.Gaslight represents the most sophisticated implementation observed to date, with a multi-message cascade designed to simulate a plausible system failure scenario.

---

## Technical Analysis

### Stage 1: Initial Execution

The primary binary is a Rust-compiled Mach-O executable supporting both aarch64 (ARM64) and x86_64 architectures. It carries an ad hoc code signing identifier with the prefix `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea`. At runtime, the binary resolves its own executable path via `__NSGetExecutablePath` and uses `dlsym` for dynamic API resolution to avoid populating the static symbol table.

### Stage 2: Configuration and C2 Initialization

The implant uses a 15-field configuration schema serialized via Rust's `serde` framework. The schema is baked into the binary as plaintext and includes fields for both macOS and Linux payloads, suggesting this is one component of a cross-platform toolset:

- `tg_room_id` -- Telegram chat ID for C2
- `github_token` / `github_repo` -- GitHub-based secondary infrastructure
- `github_polling_interval` -- Polling cadence
- `main_upload_url` / `main_base_url` -- Upload endpoints
- `aes_key` -- AES-GCM encryption key
- `payload_path_linux` / `payload_path_macos` -- Platform-specific payload paths
- `persist_name_linux` / `persist_name_macos` -- Persistence identifiers
- `persist_type_linux` / `persist_type_macos` -- Persistence mechanisms
- `init_python_enable` -- Python stealer activation flag
- `persist_enable` -- Persistence activation flag

### Stage 3: Telegram Bot API C2

Command and control runs over Telegram's Bot API in a polling loop using `getUpdates`. The implant handles three specific Telegram error codes: `BotBlocked`, `InvalidToken`, and `Conflict`. File exfiltration uses the multipart upload mechanism via the `attach://` URI scheme. The bot token is supplied at runtime through the configuration and is self-redacted as `file/token:redacted` in diagnostic output and crash artifacts, preventing recovery from forensic analysis.

**Transport Security:**
- AES-GCM encryption (via Rust `aes-gcm` 0.10.3 crate) with a fresh nonce per message generated via `CCRandomGenerateBytes`
- Custom TLS certificate pinning via `SecTrustSetAnchorCertificatesOnly`, rejecting standard proxy CAs
- System proxy awareness via `SCDynamicStoreCopyProxies`
- Networking via `reqwest`/`hyper` Rust stack

### Stage 4: Operator Commands

The implant supports seven operator commands:

| Command | Function |
|---------|----------|
| `help` | Display command help |
| `id` | Identify implant instance |
| `shell` | Execute shell commands via `execvp` or `posix_spawnp` |
| `kill` | Terminate process by PID |
| `upload` | Exfiltrate files via Telegram |
| `stop` | Halt implant |
| `focus` | Unknown (evidence present, details unrecovered) |

### Stage 5: Python Credential Stealer

When `init_python_enable` is set, the implant deploys a base64-encoded bash installer (2 KB) that stages a standalone `cpython-3.10.18` runtime fetched from the `astral-sh/python-build-standalone` project. The installer contains constants `PY_VERSION=3.10.18` and `BUILD_DATE=20250708`, and targets both arm64 and x86_64 architectures. SentinelOne notes the bash script exhibits "widespread use of emojis and strict adherence to comment headers," consistent with LLM-generated output.

The Python stealer module (6.6 KB, base64-encoded) harvests:
- Chrome browser data
- Brave browser data
- Firefox browser data
- Safari browser data
- Terminal command histories
- Installed application listings
- Running processes (via `ps aux`)
- System profile (via `system_profiler`)
- Raw copy of `login.keychain-db`

Collected data is packaged as `temp/collected_data.zip` and exfiltrated via Telegram file upload.

### Stage 6: Persistence

The implant establishes persistence via a macOS LaunchAgent with the label `com.apple.system.services.activity`, masquerading within Apple's legitimate `com.apple.*` namespace -- a well-documented North Korean macOS tactic. The executable path is resolved dynamically via `__NSGetExecutablePath`. Persistence is controlled by the `persist_enable` configuration field.

Additionally, the implant creates an `IOPMAssertionCreateWithName` power management assertion to prevent system sleep, keeping the C2 polling loop active during user idle periods.

### Prompt Injection Anti-Analysis Technique

The most distinctive feature is a 3.5 KB Markdown-fenced payload containing 38 fabricated "system" messages delimited by `{{DATA}}` tokens that mimic an LLM prompt triage scaffold. The messages simulate:

- Token expiry warnings
- Out-of-memory (OOM) kill notifications
- Disk exhaustion alerts
- Operation failure messages
- Injection vulnerability warnings
- Static-analysis flags
- Redis connection failures
- Build pipeline errors
- JSON parsing errors

The intent is to make an LLM-assisted triage agent "doubt its own session" and abort, truncate, or refuse analysis before reaching the actual malicious functionality. SentinelOne did not demonstrate successful bypass of actual AI malware analysis platforms, but the technique represents a credible and evolving threat to automated analysis pipelines.

---

## Indicators of Compromise (IOCs)

> All indicators are defanged for safe handling.

### File Hashes

| Type | Hash | Description |
|------|------|-------------|
| SHA256 | `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525` | Primary macOS.Gaslight sample |
| SHA256 | `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca` | Sibling BONZAI sample |
| SHA256 | `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239` | Python stealer payload script |
| SHA256 | `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394` | Bash installer script |

### Network Indicators

| Type | Indicator | Description |
|------|-----------|-------------|
| Domain | `api[.]telegram[.]org` | Telegram Bot API C2 endpoint |
| URL Pattern | `hxxps://api[.]telegram[.]org/bot<TOKEN>/getUpdates` | C2 polling endpoint |
| URL Pattern | `hxxps://api[.]telegram[.]org/bot<TOKEN>/sendDocument` | Data exfiltration endpoint |
| URL Pattern | `hxxps://github[.]com/astral-sh/python-build-standalone` | Python runtime staging source |

### Host Indicators

| Type | Indicator | Description |
|------|-----------|-------------|
| LaunchAgent Label | `com[.]apple[.]system[.]services[.]activity` | Persistence mechanism |
| File Path | `temp/collected_data.zip` | Credential theft staging archive |
| Code Signing ID | `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea` | Ad hoc signing identifier |
| XProtect Rule | `MACOS_BONZAI_COBUCH` | Apple detection signature |
| XProtect Rule | `AIRPIPE` | Related Apple detection signature |

### Embedded Strings

| String | Context |
|--------|---------|
| `{{DATA}}` | Prompt injection delimiter token |
| `token:redacted` | Bot token self-redaction pattern |
| `tg_room_id` | Configuration schema field |
| `BotBlocked` | Telegram error handler |
| `InvalidToken` | Telegram error handler |
| `PY_VERSION=3.10.18` | Bash installer constant |
| `BUILD_DATE=20250708` | Bash installer constant |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Implementation |
|--------|-------------|----------------|----------------|
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Standalone CPython runtime staged for credential stealer |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell command execution via `execvp`/`posix_spawnp` |
| Persistence | T1543.001 | Create or Modify System Process: Launch Agent | LaunchAgent with `com.apple.system.services.activity` label |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | LaunchAgent label impersonates Apple `com.apple.*` namespace |
| Defense Evasion | T1027.009 | Obfuscated Files or Information: Embedded Payloads | Base64-encoded Python stealer and bash installer |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Runtime decoding of base64-encoded payloads |
| Defense Evasion | T1553.002 | Subvert Trust Controls: Code Signing | Ad hoc code signing to avoid Gatekeeper |
| Credential Access | T1555.001 | Credentials from Password Stores: Keychain | Raw copy of `login.keychain-db` |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome, Brave, Firefox, Safari data harvesting |
| Discovery | T1057 | Process Discovery | Running processes via `ps aux` |
| Discovery | T1082 | System Information Discovery | System profile via `system_profiler` |
| Discovery | T1518 | Software Discovery | Installed applications listing |
| Collection | T1005 | Data from Local System | Terminal histories, application data |
| Collection | T1074.001 | Data Staged: Local Data Staging | `temp/collected_data.zip` staging |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Telegram Bot API polling loop |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS to Telegram API |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-GCM with per-message nonces |
| Command and Control | T1008 | Fallback Channels | GitHub-based secondary infrastructure |
| Exfiltration | T1567 | Exfiltration Over Web Service | Telegram `sendDocument` file upload |
| Resource Development | T1105 | Ingress Tool Transfer | Runtime Python staging from astral-sh repository |

<!-- revision: T1608.001 (Stage Capabilities: Upload Malware) corrected to T1105 (Ingress Tool Transfer) — the implant downloads a tool to the victim, not uploading malware to staging infrastructure -->

---

## Detection Rules

<!-- revision: 18 rules reduced to 13 after dropping 5 (Sigma #4, Suricata #10, Snort #15/#16/#17) and fixing 9 -->

### Sigma Rules

<!-- revision: Sigma #4 (Telegram Bot API C2 Communication) DROPPED — too broad, fires on any Telegram API usage, not Gaslight-specific (altitude violation) -->

#### 1. macOS.Gaslight LaunchAgent Persistence

**File:** `sigma_gaslight_launchagent.yml`
**Compile Status:** PASS (Splunk + LogScale conversion successful)
**Confidence:** high

```yaml
title: macOS.Gaslight DPRK Backdoor LaunchAgent Persistence
id: 9a3f7c1e-5b2d-4e8a-b1c3-d4e5f6a7b8c9
status: experimental
description: Detects creation of a LaunchAgent plist with the label com.apple.system.services.activity, used by the macOS.Gaslight DPRK-linked Rust backdoor for persistence.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.persistence
    - attack.t1543.001
    - attack.t1036.004
logsource:
    category: file_event
    product: macos
detection:
    selection_path:
        TargetFilename|contains: 'LaunchAgents'
    selection_label:
        TargetFilename|contains: 'com.apple.system.services.activity'
    condition: selection_path and selection_label
falsepositives:
    - Unlikely - this label masquerades as Apple but is not a legitimate Apple service
level: critical
```

#### 2. macOS.Gaslight Credential Theft via Python Stealer

<!-- revision: tightened OR logic — collected_data.zip is now mandatory anchor, plus at least one other indicator required; confidence downgraded from HIGH to medium -->

**File:** `sigma_gaslight_credential_theft.yml`
**Compile Status:** PASS (Splunk + LogScale conversion successful)
**Confidence:** medium

```yaml
title: macOS.Gaslight Credential Theft via Python Stealer Module
id: 2b4c8d3e-6f1a-4e9b-c2d3-e5f6a7b8c9d0
status: experimental
description: Detects the macOS.Gaslight Python stealer module accessing browser credential stores and keychain databases on macOS systems. Requires collected_data.zip as mandatory anchor artifact plus at least one other stealer indicator.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.credential_access
    - attack.t1555.001
    - attack.t1555.003
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: macos
detection:
    selection_python:
        Image|endswith:
            - '/python3'
            - '/python3.10'
            - '/python'
    selection_anchor:
        CommandLine|contains:
            - 'collected_data.zip'
    selection_indicators:
        CommandLine|contains:
            - 'login.keychain-db'
            - 'system_profiler'
    condition: selection_python and selection_anchor and selection_indicators
falsepositives:
    - Legitimate administrative scripts accessing keychain for backup purposes that also create collected_data.zip archives
level: high
```

#### 3. macOS.Gaslight Standalone Python Runtime Staging

<!-- revision: MITRE tag corrected from T1608.001 to T1105 -->

**File:** `sigma_gaslight_python_staging.yml`
**Compile Status:** PASS (Splunk + LogScale conversion successful)
**Confidence:** medium

```yaml
title: macOS.Gaslight Standalone Python Runtime Staging
id: 3c5d9e4f-7a2b-4f0c-d3e4-f6a7b8c9d0e1
status: experimental
description: Detects fetching of standalone CPython runtime from astral-sh/python-build-standalone, a technique used by macOS.Gaslight to stage its Python stealer module without relying on system Python.
references:
    - https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
author: Actioner CTI
date: 2026-06-27
tags:
    - attack.execution
    - attack.t1059.006
    - attack.resource_development
    - attack.t1105
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains:
            - 'python-build-standalone'
            - 'cpython-3.10.18'
    condition: selection
falsepositives:
    - Developers using astral-sh python-build-standalone for legitimate development purposes
level: medium
```

---

### YARA Rules

#### 5. macOS_Gaslight_Rust_Backdoor

<!-- revision: fixed hash typo in meta — removed extra "6a" (was 66 chars, now correct 64-char SHA256); severity downgraded from critical to high -->

**File:** `yara_gaslight.yar` (Rule 1 of 5)
**Compile Status:** PASS (`yarac` exit code 0)
**Confidence:** high

```yara
import "macho"
import "hash"

rule macOS_Gaslight_Rust_Backdoor
{
    meta:
        description = "Detects macOS.Gaslight DPRK-linked Rust backdoor with prompt injection capabilities"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        threat_actor = "DPRK"
        malware_family = "Gaslight"
        severity = "high"

    strings:
        $cmd_help = "help" ascii
        $cmd_id = "id" ascii
        $cmd_shell = "shell" ascii
        $cmd_kill = "kill" ascii
        $cmd_upload = "upload" ascii
        $cmd_stop = "stop" ascii
        $cmd_focus = "focus" ascii
        $cfg_tg_room = "tg_room_id" ascii
        $cfg_github_token = "github_token" ascii
        $cfg_github_repo = "github_repo" ascii
        $cfg_aes_key = "aes_key" ascii
        $cfg_payload_macos = "payload_path_macos" ascii
        $cfg_persist_macos = "persist_name_macos" ascii
        $cfg_persist_linux = "persist_name_linux" ascii
        $cfg_persist_enable = "persist_enable" ascii
        $cfg_init_python = "init_python_enable" ascii
        $cfg_main_upload = "main_upload_url" ascii
        $tg_api = "api.telegram.org" ascii
        $tg_getUpdates = "getUpdates" ascii
        $tg_botblocked = "BotBlocked" ascii
        $tg_invalidtoken = "InvalidToken" ascii
        $pi_marker = "{{DATA}}" ascii
        $persist_label = "com.apple.system.services.activity" ascii
        $signing_id = "endpoint-macos-aarch64-" ascii
        $redact = "token:redacted" ascii
        $rust_aes_gcm = "aes-gcm" ascii
        $rust_reqwest = "reqwest" ascii
        $rust_serde = "serde" ascii
        $fake_oom = "out-of-memory" ascii
        $fake_disk = "disk exhaustion" ascii
        $fake_token = "token expir" ascii
        $api_iopm = "IOPMAssertionCreateWithName" ascii
        $api_scdyn = "SCDynamicStoreCopyProxies" ascii
        $api_sectrust = "SecTrustSetAnchorCertificatesOnly" ascii
        $api_nsgetexec = "__NSGetExecutablePath" ascii

    condition:
        (macho.magic == macho.MH_MAGIC_64 or macho.magic == macho.MH_MAGIC) and
        (
            (3 of ($cfg_*) and $tg_api and $tg_getUpdates) or
            ($pi_marker and $persist_label) or
            (4 of ($cmd_*) and $signing_id) or
            (2 of ($fake_*) and 2 of ($api_*) and ($tg_botblocked or $tg_invalidtoken)) or
            (2 of ($rust_*) and $redact and $tg_api and $signing_id)
        )
}
```

#### 6. macOS_Gaslight_Prompt_Injection_Payload

<!-- revision: confidence downgraded from HIGH to medium; threshold raised from 3-of-6 to 4-of-6 fake strings -->

**File:** `yara_gaslight.yar` (Rule 2 of 5)
**Compile Status:** PASS
**Confidence:** medium

```yara
rule macOS_Gaslight_Prompt_Injection_Payload
{
    meta:
        description = "Detects the prompt injection payload embedded in macOS.Gaslight designed to confuse LLM analysis"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        severity = "medium"

    strings:
        $marker = "{{DATA}}" ascii
        $fake1 = "token expir" ascii nocase
        $fake2 = "out-of-memory" ascii nocase
        $fake3 = "disk exhaustion" ascii nocase
        $fake4 = "operation fail" ascii nocase
        $fake5 = "injection vulnerability" ascii nocase
        $fake6 = "static-analysis" ascii nocase

    condition:
        $marker and 4 of ($fake*) and filesize < 10MB
}
```

#### 7. macOS_Gaslight_Python_Stealer

**File:** `yara_gaslight.yar` (Rule 3 of 5)
**Compile Status:** PASS
**Confidence:** high

```yara
rule macOS_Gaslight_Python_Stealer
{
    meta:
        description = "Detects the Python stealer component used by macOS.Gaslight to harvest credentials"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"
        severity = "high"

    strings:
        $s1 = "login.keychain-db" ascii
        $s2 = "collected_data.zip" ascii
        $s3 = "system_profiler" ascii
        $s4 = "ps aux" ascii
        $browser1 = "Chrome" ascii
        $browser2 = "Brave" ascii
        $browser3 = "Firefox" ascii
        $browser4 = "Safari" ascii

    condition:
        $s1 and $s2 and $s3 and $s4 and 2 of ($browser*) and filesize < 100KB
}
```

#### 8. macOS_Gaslight_Bash_Installer

<!-- revision: confidence changed from CRITICAL to high; removed erroneous "(hash-anchored)" label — rule uses string matching not hash anchoring -->

**File:** `yara_gaslight.yar` (Rule 4 of 5)
**Compile Status:** PASS
**Confidence:** high

```yara
rule macOS_Gaslight_Bash_Installer
{
    meta:
        description = "Detects the bash installer script used by macOS.Gaslight to stage standalone Python runtime"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        hash = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"
        severity = "high"

    strings:
        $py_version = "PY_VERSION=3.10.18" ascii
        $build_date = "BUILD_DATE=20250708" ascii
        $astral = "python-build-standalone" ascii
        $arch1 = "arm64" ascii
        $arch2 = "x86_64" ascii

    condition:
        ($py_version or $build_date) and $astral and ($arch1 or $arch2) and filesize < 10KB
}
```

#### 9. macOS_Gaslight_SHA256_Hash

<!-- revision: REWRITTEN — original rule searched for hash bytes as strings in file content, which does not detect files with that SHA256 digest; now uses YARA hash module with hash.sha256(0, filesize) for correct hash-based detection; confidence changed from CRITICAL to high; expanded to cover all 4 known sample hashes -->

**File:** `yara_gaslight.yar` (Rule 5 of 5)
**Compile Status:** PASS
**Confidence:** high

```yara
rule macOS_Gaslight_SHA256_Hash
{
    meta:
        description = "Detects macOS.Gaslight primary sample and related artifacts by SHA256 hash"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"
        severity = "high"

    condition:
        hash.sha256(0, filesize) == "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525" or
        hash.sha256(0, filesize) == "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca" or
        hash.sha256(0, filesize) == "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239" or
        hash.sha256(0, filesize) == "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"
}
```

---

### Suricata Rules

<!-- revision: SID 2026062701 (Telegram Bot API TLS SNI) DROPPED — fires on ALL Telegram TLS traffic with no narrowing, massive false positive rate; all remaining rules relabeled from MEDIUM-HIGH to medium -->

**File:** `suricata_gaslight.rules`
**Compile Status:** PASS (`suricata -T` -- "Configuration provided was successfully loaded. Exiting.")
**Confidence:** medium

#### 11. Telegram Bot API getUpdates C2 Polling (SID 2026062702)

<!-- revision: confidence relabeled to medium; caveat added about FP with legitimate Telegram bots -->

> **Note:** This rule may fire on legitimate Telegram bot integrations. Investigate alerts by correlating with the source process -- non-browser, non-Telegram-client processes polling getUpdates warrant further investigation.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram Bot API getUpdates C2 Polling"; content:"api.telegram.org"; http_host; content:"/bot"; http_uri; content:"/getUpdates"; http_uri; flow:established,to_server; classtype:trojan-activity; sid:2026062702; rev:2;)
```

#### 12. Telegram sendDocument Data Exfiltration (SID 2026062703)

<!-- revision: confidence relabeled to medium -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram Bot API sendDocument Data Exfiltration"; content:"api.telegram.org"; http_host; content:"/bot"; http_uri; content:"/sendDocument"; http_uri; flow:established,to_server; classtype:trojan-activity; sid:2026062703; rev:2;)
```

#### 13. Standalone Python Runtime Download (SID 2026062704)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Standalone Python Runtime Download"; content:"python-build-standalone"; http_uri; content:"cpython-3.10"; http_uri; flow:established,to_server; classtype:trojan-activity; sid:2026062704; rev:1;)
```

#### 14. Telegram Multipart File Upload (SID 2026062705)

<!-- revision: confidence relabeled to medium -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE macOS.Gaslight Telegram Multipart File Upload via attach URI"; content:"api.telegram.org"; http_host; content:"attach://"; http_client_body; flow:established,to_server; classtype:trojan-activity; sid:2026062705; rev:2;)
```

---

### Snort Rules

<!-- revision: SIDs 2026270001, 2026270002, 2026270003 DROPPED — redundant with Suricata #11/#12 (lower fidelity, same detection logic) and Suricata #13 (Python download) respectively -->

**File:** `snort_gaslight.rules`
**Compile Status:** PASS ("Snort successfully validated the configuration!")
**Confidence:** medium

#### 18. collected_data.zip Exfiltration (SID 2026270004)

<!-- revision: confidence relabeled to medium; note added about content modifier limitations — Snort content matches are payload-level and require TLS inspection to be effective against HTTPS traffic -->

> **Note:** This rule's content matches operate at the payload level. Because macOS.Gaslight uses HTTPS with TLS certificate pinning, this rule is only effective when TLS inspection or HTTP proxy decryption is in place.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE macOS.Gaslight collected_data.zip Exfiltration"; content:"api.telegram.org"; nocase; content:"collected_data.zip"; nocase; sid:2026270004; rev:2; classtype:trojan-activity;)
```

---

## Remediation

### Immediate Actions

1. **Hash-based blocking**: Add all four SHA256 hashes to endpoint detection and EDR block lists
2. **XProtect verification**: Ensure Apple XProtect definitions are current; verify `MACOS_BONZAI_COBUCH` and `AIRPIPE` rules are active
3. **LaunchAgent audit**: Search all macOS endpoints for LaunchAgent plists containing the label `com.apple.system.services.activity` and remove any matches
4. **Network monitoring**: Deploy Suricata/Snort rules to detect Telegram Bot API C2 traffic, particularly `getUpdates` polling and `sendDocument` exfiltration
5. **Credential rotation**: If compromise is confirmed, rotate all browser-stored credentials, keychain passwords, and GitHub tokens

### Investigation Steps

1. Search for the ad hoc code signing identifier prefix `endpoint-macos-aarch64-` across managed endpoints
2. Review proxy logs for sustained polling to `api.telegram.org` from non-Telegram applications
3. Check for unexpected downloads from `astral-sh/python-build-standalone` on GitHub
4. Search for `temp/collected_data.zip` artifacts on disk
5. Review for `IOPMAssertionCreateWithName` assertions from unsigned or ad hoc signed binaries

### Long-term Mitigations

1. **LLM pipeline hardening**: Organizations using LLM-assisted malware triage should implement prompt injection defenses, including output sanitization and multi-pass analysis
2. **Certificate pinning detection**: Monitor for applications that reject standard proxy CAs, which may indicate TLS pinning for C2 evasion
3. **Python runtime monitoring**: Alert on standalone Python installations outside of standard package managers (Homebrew, system Python)
4. **Power assertion monitoring**: Track `IOPMAssertionCreateWithName` calls from non-standard applications to detect sleep prevention for C2 persistence

---

## Sources

1. [SentinelOne Labs -- macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/) -- Primary technical analysis by Phil Stokes, published June 23, 2026
2. [Security Affairs -- macOS Gaslight: North Korea-linked malware that tries to gaslight the analyst](https://securityaffairs.com/194256/malware/macos-gaslight-north-korea-linked-malware-that-tries-to-gaslight-the-analyst.html) -- Secondary coverage with attribution context
3. [BleepingComputer -- New macOS malware embeds fake errors to confuse AI analysis tools](https://www.bleepingcomputer.com/news/security/new-macos-malware-embeds-fake-errors-to-confuse-ai-analysis-tools/) -- Media coverage with prompt injection focus, published June 25, 2026

---

*Generated by Actioner -- 2026-06-27 | Revised: 2026-06-27T1*
