# macOS.Gaslight -- DPRK Rust Backdoor with LLM Prompt Injection Evasion

> **Status:** DRAFT -- Actioner CTI  
> **Date:** 2026-06-25  
> **TLP:** CLEAR  
> **Threat Actor:** DPRK-aligned activity cluster  
> **Malware Family:** macOS.Gaslight (also related: BONZAI)  
> **Platform:** macOS (arm64 / x86_64)

---

## Executive Summary

macOS.Gaslight is a Rust-based macOS backdoor attributed to a DPRK-aligned threat actor. Disclosed by [SentinelOne Labs](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/) on June 23, 2026, it uses Telegram Bot API for command and control, embeds a Python-based credential stealer, and notably includes a 3.5 KB prompt injection payload designed to deceive LLM-assisted malware analysis tools. The sample was uploaded on May 22, 2026 and surfaced in June 2026 via an Apple XProtect update. Apple detects it under the `MACOS_BONZAI_COBUCH` signature family. The backdoor uses AES-GCM encryption with certificate pinning for C2 transport, resolves APIs at runtime via `dlsym`, and self-redacts its Telegram bot token from logs and crash output.

---

## Sources

| Source | URL | Accessed |
|--------|-----|----------|
| SentinelOne Labs (primary) | [macOS.Gaslight: Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/) | 2026-06-25 |
| Infosecurity Magazine | [macOS.Gaslight Rust Backdoor](https://www.infosecurity-magazine.com/news/macos-gaslight-rust-backdoor/) | 2026-06-25 |

**Researcher:** Phil Stokes, Research Engineer, SentinelOne

---

## Indicators of Compromise

> IOCs below are **defanged** in prose. Detection rules use real (non-defanged) values.

### File Hashes (SHA256)

| SHA256 | Component |
|--------|-----------|
| `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525` | Main Rust backdoor sample |
| `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca` | Sibling BONZAI sample |
| `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239` | Embedded Python stealer payload |
| `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394` | Bash installer (Python runtime staging) |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `api[.]telegram[.]org` | Domain (C2) | Telegram Bot API used for C2 polling via `getUpdates` and file exfiltration via `sendDocument` with `attach://` |
| `github[.]com/astral-sh/python-build-standalone` | URL (staging) | Source for `cpython-3.10.18` standalone runtime download |

**Note:** No hardcoded Telegram bot tokens, IP addresses, or C2 domains were recovered from the sample. All C2 configuration (bot token, chat ID, AES key, GitHub credentials) is supplied at runtime via a 15-field `serde` configuration schema.

### Host-Based Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `com.apple.system.services.activity` | LaunchAgent Label | Persistence plist masquerading in Apple's `com.apple.*` namespace |
| `~/Library/LaunchAgents/com.apple.system.services.activity.plist` | File Path | Persistence mechanism |
| `temp/collected_data.zip` | File Path | Python stealer exfiltration staging archive |
| `endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea` | Signing ID | Code signing identifier |
| `file/token:redacted` | String | Bot token self-redaction placeholder |
| `BUILD_DATE=20250708` | String | Build date constant in bash installer |

### Configuration Schema Fields

The backdoor's 15-field `serde`-serialized config is embedded as plaintext in the binary:

```
tg_room_id, aes_key, github_token, github_repo, github_polling_interval,
main_upload_url, main_base_url, payload_path_linux, payload_path_macos,
persist_name_linux, persist_name_macos, persist_type_linux, persist_type_macos,
init_python_enable, persist_enable
```

### Operator Commands

Six verified verbs embedded in the binary: `help`, `id`, `shell`, `kill`, `upload`, `stop`. A seventh command `focus` was referenced but its handler was unrecovered.

---

## Kill Chain / Infection Flow

1. **Initial Access** -- Delivery mechanism not observed in source analysis; prior DPRK campaigns suggest social engineering via fraudulent job postings (Contagious Interview pattern)
2. **Execution** -- Rust Mach-O binary executes; resolves APIs at runtime via `dlsym` to avoid static symbol table exposure
3. **Persistence** -- Writes LaunchAgent plist to `~/Library/LaunchAgents/` using label `com.apple.system.services.activity`; resolves own path via `__NSGetExecutablePath`; creates `IOPMAssertionCreateWithName` to prevent system sleep
4. **C2 Establishment** -- Polls Telegram Bot API via `getUpdates` in a loop; encrypts traffic with AES-GCM (aes-gcm 0.10.3 crate); pins TLS certificates via `SecTrustSetAnchorCertificatesOnly`; honors system proxy via `SCDynamicStoreCopyProxies`; generates fresh nonce per message via `CCRandomGenerateBytes`
5. **Singleton Enforcement** -- Uses Telegram `Conflict` error code to prevent duplicate bot instances
6. **Credential Collection** -- Decodes embedded 6.6 KB base64 Python stealer; stages Python runtime from `astral-sh/python-build-standalone` via 2 KB bash installer; collects Chrome, Brave, Firefox, Safari data, terminal histories, installed apps, process snapshot (`ps aux`), system profile, and raw `login.keychain-db`
7. **Exfiltration** -- Archives collected data to `temp/collected_data.zip`; uploads via Telegram multipart `attach://` mechanism
8. **OPSEC** -- Self-redacts Telegram bot token from URL paths (replaces with `file/token:redacted` when URL path contains literal `file`); embeds 3.5 KB prompt injection payload to frustrate LLM-assisted analysis

---

## Prompt Injection / LLM Evasion (Novel Technique)

The sample contains a 3.5 KB Markdown-fenced blob with 38 fabricated "system" messages. This payload uses `{{DATA}}` tokens that mimic LLM triage harness scaffolding, blurring the boundary between untrusted sample data and trusted system instructions. The fabricated messages include:

- Token expiry warnings
- Out-of-memory kill notifications
- Disk exhaustion alerts
- Injection vulnerability warnings
- Static-analysis flag false positives

The goal is to compel LLM agents to abort, truncate, or refuse analysis of the sample. This represents a shift from traditional anti-analysis (sandbox evasion, VM detection) to adversarial attacks targeting AI-assisted SOC tooling.

**Prior Art:** Check Point (2025) documented analyst-targeting prompt injection; Socket's Hades supply-chain payload and the "Shai-Hulud" Anthropic Magic String are related techniques.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|--------|-----------|----|-------|
| Persistence | Create or Modify System Process: Launch Agent | T1543.001 | LaunchAgent plist with `com.apple.system.services.activity` label |
| Defense Evasion | Masquerading: Masquerade Task or Service | T1036.004 | Plist label masquerades as Apple system service |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Bot token self-redaction from logs/crash artifacts |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64-encoded Python stealer; runtime API resolution via `dlsym` |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | Stages standalone Python runtime; executes embedded stealer |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `shell` command via `execvp`/`posix_spawnp`; bash installer script |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Telegram Bot API for C2 |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 | AES-GCM encryption on C2 channel |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS to Telegram API |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | `collected_data.zip` staging |
| Collection | Data from Local System | T1005 | Browser data, keychain, terminal histories |
| Credential Access | Credentials from Password Stores: Keychain | T1555.001 | Raw `login.keychain-db` copy |
| Discovery | System Information Discovery | T1082 | `system_profiler` execution |
| Discovery | Process Discovery | T1057 | `ps aux` snapshot |
| Discovery | Software Discovery: Security Software Discovery | T1518.001 | Installed application enumeration |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | File upload via Telegram `sendDocument` |
| Resource Development | Stage Capabilities: Upload Malware | T1608.001 | Python runtime staged from GitHub |
| Impact | System Shutdown/Reboot | T1529 | Sleep prevention via IOPMAssertion (non-standard mapping -- prevents idle sleep) |

---

## Viability Gate Assessment

**PASS** -- This threat has concrete, distinctive artifacts suitable for detection:

- Four SHA256 hashes across distinct components
- Unique LaunchAgent label (`com.apple.system.services.activity`)
- Unique configuration schema field names baked into binary as plaintext
- Distinctive bot token redaction string (`file/token:redacted`)
- Unique signing identifier prefix (`endpoint-macos-aarch64`)
- Specific Python stealer output path (`temp/collected_data.zip`)
- Unique prompt injection scaffolding (`{{DATA}}` tokens with fabricated system messages)
- Telegram Bot API as C2 channel (detectable at network layer via SNI)

---

## Detection Rules

### Sigma Rules

Validated via `sigma convert --without-pipeline -t splunk` and `sigma convert --without-pipeline -t log_scale` (all 5 rules convert cleanly). `sigma check` could not complete due to MITRE ATT&CK data fetch timeout in this environment (not a rule syntax issue).

**File:** `rules/sigma/2026-06-25-macos-gaslight-rust-backdoor.yml`

#### 1. macOS.Gaslight -- LaunchAgent Persistence

Detects LaunchAgent plist creation with the `com.apple.system.services.activity` label. Caveat: requires file event telemetry on macOS (e.g., Endpoint Security Framework).

<!-- audit: sigma-convert-splunk=PASS, sigma-convert-logscale=PASS, sigma-check=SKIP(network timeout), splunk-output='TargetFilename="*/Library/LaunchAgents/*" TargetFilename="*com.apple.system.services.activity*"' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS (convert) |
| Confidence | **High** -- unique artifact-specific string, low false positive rate |

#### 2. macOS.Gaslight -- IOPMAssertion Sleep Prevention

Detects non-Apple processes calling IOPMAssertionCreateWithName. Caveat: behavioral rule; many legitimate apps prevent sleep; requires tuning per environment.

<!-- audit: sigma-convert-splunk=PASS, sigma-convert-logscale=PASS, sigma-check=SKIP(network timeout), splunk-output='CommandLine="*IOPMAssertionCreateWithName*" NOT Image="/System/*"' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS (convert) |
| Confidence | **Low** -- behavioral; high false positive potential from legitimate apps |

#### 3. macOS.Gaslight -- Python Stealer Data Collection Archive

Detects creation of `temp/collected_data.zip`. Caveat: filename is not globally unique; best paired with other Gaslight indicators.

<!-- audit: sigma-convert-splunk=PASS, sigma-convert-logscale=PASS, sigma-check=SKIP(network timeout), splunk-output='TargetFilename="*/temp/collected_data.zip"' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS (convert) |
| Confidence | **Medium** -- moderately specific file path; could match other archive tools |

#### 4. macOS.Gaslight -- Python Runtime Staging from astral-sh

Detects command lines referencing `astral-sh`, `python-build-standalone`, and `cpython-3.10` together. Caveat: legitimate developer use of astral-sh python-build-standalone will trigger this.

<!-- audit: sigma-convert-splunk=PASS, sigma-convert-logscale=PASS, sigma-check=SKIP(network timeout), splunk-output='CommandLine="*astral-sh*" CommandLine="*python-build-standalone*" CommandLine="*cpython-3.10*"' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS (convert) |
| Confidence | **Low** -- behavioral; legitimate developer activity will match |

#### 5. macOS.Gaslight -- Telegram Bot API C2 Communication

Detects command lines referencing both `api.telegram.org` and `getUpdates`. Caveat: legitimate Telegram bots on macOS will match; best used as a hunting query.

<!-- audit: sigma-convert-splunk=PASS, sigma-convert-logscale=PASS, sigma-check=SKIP(network timeout), splunk-output='CommandLine="*api.telegram.org*" CommandLine="*getUpdates*"' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS (convert) |
| Confidence | **Low** -- behavioral; Telegram bots are legitimate software |

---

### YARA Rules

Validated via `yarac` -- all 4 rules compile cleanly with exit code 0.

**File:** `rules/yara/2026-06-25-macos-gaslight-rust-backdoor.yar`

#### 1. macOS_Gaslight_Rust_Backdoor

Detects the Rust backdoor via Mach-O header + combination of serde config field names, persistence label, and bot token redaction string. Caveat: requires 5+ config fields or specific artifact combinations; tuned to minimize false positives on generic Rust binaries.

<!-- audit: yarac=PASS(exit 0), condition-logic='macho-header AND (5-of-cfg OR persist+redact OR persist+3cfg OR 4cfg+3cmd OR signid+2cfg)', imports=macho -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **High** -- artifact-specific strings unlikely in legitimate software |

#### 2. macOS_Gaslight_Python_Stealer

Detects the embedded Python stealer payload by matching collection targets and output archive. Caveat: small filesize constraint (<50KB) may miss variants; string combination is distinctive within constraint.

<!-- audit: yarac=PASS(exit 0), condition-logic='filesize<50KB AND collected_data.zip AND keychain AND 4-browsers AND (ps-aux OR profiler)' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **High** -- combination of specific collection targets + archive name within size constraint is distinctive |

#### 3. macOS_Gaslight_Prompt_Injection

Detects the LLM prompt injection payload via scaffolding tokens and fabricated system message strings. Caveat: the `{{DATA}}` token and markdown fences are common individually; the rule requires co-occurrence with 3+ fabricated error message patterns.

<!-- audit: yarac=PASS(exit 0), condition-logic='filesize<5MB AND scaffold AND md-fence AND 3-of-fakes' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Medium** -- novel detection category; false positive baseline unknown for prompt injection patterns |

#### 4. macOS_Gaslight_Bash_Installer

Detects the bash installer script that stages the Python runtime. Caveat: astral-sh/python-build-standalone is a legitimate open-source project; rule requires all three keywords plus architecture indicator within <10KB.

<!-- audit: yarac=PASS(exit 0), condition-logic='filesize<10KB AND python-build-standalone AND astral-sh AND cpython-3.10 AND (arm64 OR x86_64)' -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Medium** -- legitimate installer scripts for astral-sh could match, but size+keyword combination is rare |

---

### Suricata Rules

Validated via `suricata -T` -- configuration loaded successfully.

**File:** `rules/suricata/2026-06-25-macos-gaslight-rust-backdoor.rules`

#### 1. SID 2026062501 -- Telegram Bot API C2 getUpdates Polling

Detects TLS connections with SNI matching `api.telegram.org`. Caveat: will fire on any TLS connection to Telegram's API; requires additional context for triage.

<!-- audit: suricata-T=PASS, keyword=tls.sni, protocol=tls -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Low** -- behavioral; any Telegram API client will match |

#### 2. SID 2026062502 -- Telegram Bot API TLS Connection (Threshold)

Rate-limited variant (10+ connections in 60 seconds from same source) to detect polling behavior. Caveat: chatty Telegram bots or desktop clients may exceed this threshold.

<!-- audit: suricata-T=PASS, keyword=tls.sni+threshold, protocol=tls -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Low** -- behavioral; threshold helps but legitimate bots poll frequently |

#### 3. SID 2026062503 -- Python Runtime Staging Download

Detects TLS connections to `github.com` -- overly broad as written; included as a placeholder for environments that can correlate with endpoint process context. Caveat: extremely noisy; should be combined with endpoint telemetry or restricted to specific subnets.

<!-- audit: suricata-T=PASS, keyword=tls.sni, protocol=tls, note=BROAD-github.com-only -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Very Low** -- too broad for production use without additional filtering |

---

### Snort Rules

Validated via `snort -T` with minimal configuration -- configuration validated successfully.

**File:** `rules/snort/2026-06-25-macos-gaslight-rust-backdoor.rules`

#### 1. SID 2026062510 -- Telegram Bot API getUpdates C2 Polling

Detects HTTP requests to `api.telegram.org` with `/bot` and `getUpdates` in the URI. Caveat: only fires on unencrypted HTTP; Gaslight uses TLS with certificate pinning, so this rule targets degraded/intercepted scenarios only.

<!-- audit: snort-T=PASS(minimal-config), protocol=tcp, keywords=http_header+http_uri, note=HTTP-only-gaslight-uses-TLS -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Low** -- HTTP-only; malware uses HTTPS with cert pinning; useful only with TLS interception |

#### 2. SID 2026062511 -- Telegram Bot API File Exfiltration

Detects HTTP requests to Telegram API with `sendDocument` and `attach://` pattern. Caveat: same HTTP-only limitation as above.

<!-- audit: snort-T=PASS(minimal-config), protocol=tcp, keywords=http_header+http_uri+http_client_body, note=HTTP-only-gaslight-uses-TLS -->

| Property | Value |
|----------|-------|
| Compile Status | PASS |
| Confidence | **Low** -- HTTP-only; requires TLS interception to be effective |

---

## Apple XProtect Coverage

Apple has existing detection for related samples:
- **MACOS_BONZAI_COBUCH** -- hash-based XProtect rule covering the Gaslight sample family
- **AIRPIPE** -- XProtect rule that caught the sibling BONZAI sample

These are hash-based signatures and will not detect variants.

---

## Recommendations

1. **Deploy YARA rules** `macOS_Gaslight_Rust_Backdoor` and `macOS_Gaslight_Python_Stealer` to file scanning pipelines and EDR platforms -- these have the highest specificity
2. **Deploy Sigma rule** for LaunchAgent persistence with `com.apple.system.services.activity` label -- high confidence, low false positive
3. **Hunt** for Telegram Bot API polling from macOS endpoints using the Sigma/Suricata behavioral rules
4. **Verify XProtect** is current on macOS fleet (should include `MACOS_BONZAI_COBUCH`)
5. **Audit LLM-assisted analysis pipelines** to ensure sample content is treated as adversarial input, never as instructions -- implement input sanitization for `{{DATA}}` scaffolding tokens and markdown-fenced blocks before LLM processing
6. **Monitor** for `astral-sh/python-build-standalone` downloads from non-developer endpoints

---

## Rule Summary Table

| # | Type | Title | Compile Status | Confidence |
|---|------|-------|---------------|------------|
| 1 | Sigma | LaunchAgent Persistence | PASS (convert) | High |
| 2 | Sigma | IOPMAssertion Sleep Prevention | PASS (convert) | Low |
| 3 | Sigma | Python Stealer Data Collection Archive | PASS (convert) | Medium |
| 4 | Sigma | Python Runtime Staging from astral-sh | PASS (convert) | Low |
| 5 | Sigma | Telegram Bot API C2 Communication | PASS (convert) | Low |
| 6 | YARA | macOS_Gaslight_Rust_Backdoor | PASS | High |
| 7 | YARA | macOS_Gaslight_Python_Stealer | PASS | High |
| 8 | YARA | macOS_Gaslight_Prompt_Injection | PASS | Medium |
| 9 | YARA | macOS_Gaslight_Bash_Installer | PASS | Medium |
| 10 | Suricata | Telegram Bot API C2 getUpdates (SID 2026062501) | PASS | Low |
| 11 | Suricata | Telegram Bot API TLS Connection threshold (SID 2026062502) | PASS | Low |
| 12 | Suricata | Python Runtime Staging Download (SID 2026062503) | PASS | Very Low |
| 13 | Snort | Telegram Bot API getUpdates C2 Polling (SID 2026062510) | PASS | Low |
| 14 | Snort | Telegram Bot API File Exfiltration (SID 2026062511) | PASS | Low |

---

*This is a DRAFT report. All detection rules have been machine-validated but have not been tested against live samples or in production environments. Behavioral rules (confidence: Low) should be tuned per environment before deployment.*
