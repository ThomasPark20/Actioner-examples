<!-- revision: 2026-11-10 REVISE pass — dropped Sigma #5 (Chrome Headless; generic TTP, high FP in CI), dropped Suricata #11 (DNS for openrouter.ai; too broad). Fixed Sigma #3 (AND-condition for both filenames, downgraded to low). Fixed Sigma #6 (renamed to Netsh-specific, added proxy-detection caveat). Fixed YARA #8 severity critical->high. Moved Suricata SIDs to local 1000001-1000002 range; changed classtype to misc-activity. -->

# VOLTA Infostealer with AI-Driven Victim Prioritization

> **Status**: FINAL | **Date**: 2026-11-10 | **TLP**: CLEAR | **Analyst**: Actioner CTI

---

## Executive Summary

VOLTA is a self-deleting Windows infostealer that steals credentials, browser data, cryptocurrency wallets, cloud configurations, and application sessions, then sends the assembled victim profile to a large language model (LLM) for automated monetization assessment. The LLM ranks the victim's assets by value and evaluates their security posture, enabling operators to prioritize high-value targets. First observed in October 2026 and analyzed by Cisco Talos, VOLTA represents a significant evolution in infostealer operations by integrating AI-driven triage directly into the malware's execution chain. The malware is believed to be sold as a builder kit, with each operator receiving a uniquely compiled binary.

---

## Background

On October 31, 2026, Cisco Talos researcher Ryan Fetterman published a detailed analysis of VOLTA as part of Talos's [CAIRN initiative](https://blog.talosintelligence.com/introducing-cairn-frontier-tracking-for-ai-integrated-malware/) for tracking AI-integrated malware. VOLTA joins a growing class of threats that incorporate LLM capabilities, alongside previously reported tools such as [CLOSEDQUORUM](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/). Unlike prior AI-augmented malware that used LLMs for C2 or evasion, VOLTA uses AI specifically for post-collection victim appraisal -- an intelligence function traditionally performed manually by threat actors.

---

## Technical Analysis

### Stage 1: Collection

VOLTA performs broad credential and data harvesting across the victim system:

- **Browser Data**: Extracts passwords, cookies, autofill data, and stored credit cards from Chromium-based browsers and Firefox. Bypasses Chrome App-Bound Encryption (ABE) using headless Chrome techniques.
- **Messaging & Collaboration**: Steals sessions and tokens from Discord, Telegram, Slack, and Microsoft OAuth.
- **Email Clients**: Targets Thunderbird and Outlook stored credentials.
- **Gaming Platforms**: Harvests Steam, Battle.net, and Roblox account data.
- **Cloud & Network**: Extracts SSH private keys, gcloud credentials, OpenVPN configurations, and Hide.me VPN configs.
- **Wi-Fi Profiles**: Dumps all saved Wi-Fi passwords in plaintext via the `WlanGetProfileList` Windows API.
- **Cryptocurrency**: Steals wallet files and seed phrases; includes an embedded vault cracker (logs `WALLET VAULTS CRACKED` on success).
- **System Information**: Captures screenshots, document authorship metadata, and iPhone backup indicators.

A timestamped harvest log is written to `%APPDATA%\volta_debug.txt` recording what data was collected and whether subsequent stages succeeded.

### Stage 2: Enrichment

VOLTA actively leverages stolen sessions to enrich its victim profile:

- Queries Gmail for purchase receipts from Amazon, DoorDash, Uber Eats, Grubhub, Walmart, and PayPal.
- Pulls order history from Uber Eats and DoorDash using stolen session tokens.
- Reuses Discord tokens for account reconnaissance.
- Queries [Rolimons](https://rolimons[.]com) to appraise the victim's Roblox inventory value.

### Stage 3: Local Profiling

Collected data is serialized into a structured JSON victim profile written as `Identity_Report.txt`.

### Stage 4: AI-Driven Victim Prioritization

This is VOLTA's distinguishing capability. The malware:

1. Sends `Identity_Report.txt` contents to the [OpenRouter](https://openrouter[.]ai) API at the endpoint `/api/v1/chat/completions`.
2. Uses a hand-assembled JSON request (no SDK) with `User-Agent: "Mozilla/5.0"` and `temperature: 0.2`.
3. Instructs the LLM with a system prompt posing as "a forensic intelligence analyst drafting a target assessment" with directives to "Go deep, not wide... Be blunt, specific, accurate."
4. Requires the LLM to produce structured sections including **"WHAT THEY'RE WORTH"** (assets ranked low/medium/high) and **"THEIR OPSEC"** (security posture and password hygiene analysis).
5. Implements a model fallback chain:
   - Primary: `anthropic/claude-opus-4.6`
   - Fallback 1: `moonshotai/kimi-k2`
   - Fallback 2: `google/gemini-2.5-flash`
6. Includes refusal detection that scans LLM responses for phrases like "I can't" and "I'm not able" before failing over to the next model.
7. Writes the LLM response to `AI_Analysis.txt`.

The AI stage is optional -- if no OpenRouter API key is present in the build configuration, VOLTA proceeds without it.

### Stage 5: Exfiltration

VOLTA packages results into staged ZIP archives:

| Archive | Contents |
|---|---|
| `volta_log.zip` | First-stage raw collection data |
| `volta_dox.zip` | Victim profile (`Identity_Report.txt`) and AI assessment (`AI_Analysis.txt`) |
| `volta_doxnet.zip` | Network enrichment results (if available) |

Exfiltration is performed via **Telegram** to an operator-controlled channel. No traditional attacker-controlled C2 infrastructure was identified.

### Stage 6: Self-Deletion

The VOLTA executable deletes itself after completing its collection and exfiltration cycle. The specific self-deletion mechanism (API or command) was not detailed in the Talos report.

### Build Configuration

VOLTA is distributed as a builder, producing uniquely compiled binaries per operator. The build template contains six configurable slots (including Telegram channel, API keys, and settings) encrypted at build time using a SHA-256 key derived from two constants embedded in the binary.

---

## Indicators of Compromise

> All indicators are defanged per operational security best practices.

### File Hashes

| Type | Value |
|---|---|
| SHA-256 | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` |

### Known Filenames

| Filename | Context |
|---|---|
| `9BY0tjwOc3ut.exe` | VOLTA sample executable |
| `yLP9m5J3i2Aw.exe` | VOLTA sample executable (alternate name) |
| `Identity_Report.txt` | Local victim profile (JSON) |
| `AI_Analysis.txt` | LLM-generated victim assessment |
| `volta_debug.txt` | Timestamped harvest log (`%APPDATA%`) |
| `volta_log.zip` | First-stage exfiltration archive |
| `volta_dox.zip` | Profile + AI analysis archive |
| `volta_doxnet.zip` | Network enrichment archive |

### Network Indicators

| Indicator | Type | Context |
|---|---|---|
| `openrouter[.]ai` | Domain | LLM API endpoint for victim profiling |
| `openrouter[.]ai/api/v1/chat/completions` | URL Path | Specific API endpoint called |
| `rolimons[.]com` | Domain | Roblox inventory valuation (not attacker-owned) |

### PE Metadata

| Property | Value |
|---|---|
| File Type | PE32+ x86-64 |
| PE Timestamp | 2026-08-17 20:35 |
| First Seen (UTC) | 2026-10-11 12:46 |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | VOLTA Context |
|---|---|---|
| T1555.003 | Credentials from Web Browsers | Chromium and Firefox password, cookie, and card extraction |
| T1539 | Steal Web Session Cookie | Browser session theft for enrichment queries |
| T1528 | Steal Application Access Token | Discord, Slack, Telegram, Microsoft OAuth tokens |
| T1552.001 | Credentials in Files | SSH keys, gcloud configs, VPN configs |
| T1552.004 | Private Keys | SSH private key extraction |
| T1555 | Credentials from Password Stores | Wi-Fi profile passwords, wallet vaults |
| T1005 | Data from Local System | Broad local data collection |
| T1113 | Screen Capture | Screenshot collection |
| T1119 | Automated Collection | Programmatic mass data harvesting |
| T1016 | System Network Configuration Discovery | Wi-Fi profile enumeration via WlanGetProfileList |
| T1567 | Exfiltration Over Web Service | Telegram-based exfiltration |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion of executable |
| T1074.001 | Data Staged: Local Data Staging | ZIP archive staging before exfiltration |

---

## Detection & Remediation

### Detection Opportunities

1. **File System Monitoring**: Alert on creation of `volta_debug.txt` in `%APPDATA%`, and `volta_*.zip` or `Identity_Report.txt` / `AI_Analysis.txt` files on disk.
2. **Network Monitoring**: Monitor for connections to `openrouter[.]ai` from non-browser processes, especially POST requests to `/api/v1/chat/completions`.
3. **Wi-Fi Credential Access**: Detect `netsh wlan show profiles key=clear` or anomalous use of `WlanGetProfileList`.
4. **Telegram Exfiltration**: Monitor for outbound connections to Telegram API endpoints (`api.telegram.org`) from non-Telegram processes, particularly carrying ZIP attachments.

### Remediation

- Rotate all browser-stored credentials, session tokens, and API keys on impacted systems.
- Revoke and regenerate SSH keys, cloud credentials (gcloud), and VPN configurations.
- Invalidate Discord, Slack, Telegram, and Microsoft OAuth tokens.
- Check cryptocurrency wallets for unauthorized access and transfer funds to new wallets with fresh seed phrases.
- Review Wi-Fi network credentials and rotate shared passwords.
- Conduct full forensic triage given VOLTA's self-deletion behavior -- artifacts may be limited to `volta_debug.txt` and staged ZIP files if the executable removed itself.

---

## Detection Rules

### Dropped Rules

- **Sigma: Chrome Headless Launch From Suspicious Parent** -- dropped; generic infostealer TTP not VOLTA-specific, high false-positive rate in development and CI/CD environments.
- **Suricata: DNS Query for openrouter.ai** -- dropped; fires on any DNS resolution of a legitimate AI API gateway, too broad for production deployment.

### Sigma Rules

#### 1. VOLTA Debug Log File Creation

Detects creation of `volta_debug.txt` in the user's AppData Roaming directory, a VOLTA-specific harvest log.

- **Confidence**: High (IOC-specific filename and path)
- **Caveat**: IOC-anchored; the filename is unique to this malware family. Very low false positive rate expected.

```yaml
title: VOLTA Infostealer Debug Log File Creation
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
    Detects creation of volta_debug.txt in the user's AppData Roaming directory,
    a timestamped harvest log written by the VOLTA infostealer during credential
    collection and LLM analysis stages.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI (DRAFT)
date: 2026-11-10
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\volta_debug.txt'
        TargetFilename|contains: '\AppData\Roaming\'
    condition: selection
falsepositives:
    - Unlikely - distinctive filename tied to VOLTA malware family
level: high
```

#### 2. VOLTA Staging Archive Creation

Detects creation of VOLTA-specific ZIP archive files used for staging stolen data prior to exfiltration.

- **Confidence**: High (IOC-specific filenames)
- **Caveat**: IOC-anchored; the `volta_log.zip`, `volta_dox.zip`, and `volta_doxnet.zip` filenames are unique to VOLTA.

```yaml
title: VOLTA Infostealer Staging Archive Creation
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
    Detects creation of VOLTA-specific ZIP archive files used for staging
    stolen data prior to exfiltration. VOLTA creates volta_log.zip (first stage),
    volta_dox.zip (profile and AI analysis), and volta_doxnet.zip (network enrichment).
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI (DRAFT)
date: 2026-11-10
tags:
    - attack.collection
    - attack.t1074.001
    - attack.exfiltration
    - attack.t1567
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\volta_log.zip'
            - '\volta_dox.zip'
            - '\volta_doxnet.zip'
    condition: selection
falsepositives:
    - Unlikely - distinctive filenames specific to VOLTA infostealer
level: high
```

#### 3. VOLTA Identity Report and AI Analysis File Creation

Detects co-occurrence of both `Identity_Report.txt` and `AI_Analysis.txt` file creation events, requiring both files to be present to reduce false positives from the individually generic filenames.

- **Confidence**: Low (both filenames are individually generic; AND condition raises fidelity but correlation window depends on SIEM configuration)
- **Caveat**: `AI_Analysis.txt` alone is too generic to alert on. This rule requires both filenames in the same detection window. Recommend correlating with other VOLTA indicators.

```yaml
title: VOLTA Infostealer Identity Report and AI Analysis File Creation
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
    Detects simultaneous creation of both Identity_Report.txt and AI_Analysis.txt
    files, the victim profiling artifacts generated by the VOLTA infostealer.
    Requiring both filenames reduces false positives from generic naming.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI (DRAFT)
date: 2026-11-10
tags:
    - attack.collection
    - attack.t1005
    - attack.t1119
logsource:
    category: file_event
    product: windows
detection:
    selection_identity:
        TargetFilename|endswith: '\Identity_Report.txt'
    selection_ai:
        TargetFilename|endswith: '\AI_Analysis.txt'
    condition: selection_identity and selection_ai
falsepositives:
    - Legitimate software that happens to create files with both of these generic names in the same event window
    - AI_Analysis.txt is a generic filename; this rule requires co-occurrence of both files to reduce noise
level: low
```

#### 4. Suspicious OpenRouter AI API Connection From Non-Browser Process

Detects network connections to the OpenRouter AI API from non-browser processes, the endpoint VOLTA uses for LLM-based victim prioritization.

- **Confidence**: Medium (TTP-based; legitimate AI tool usage will trigger this rule)
- **Caveat**: OpenRouter is a legitimate AI API gateway. This rule will produce false positives in environments using OpenRouter for development or production AI features. Tune per environment.

```yaml
title: Suspicious OpenRouter AI API Connection From Non-Browser Process
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: >
    Detects network connections to the OpenRouter AI API endpoint from processes
    that are not web browsers. VOLTA infostealer sends stolen victim data to
    openrouter.ai/api/v1/chat/completions for LLM-based victim prioritization.
    This rule is TTP-based and may fire on legitimate AI tool usage.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI (DRAFT)
date: 2026-11-10
tags:
    - attack.exfiltration
    - attack.t1567
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|endswith: 'openrouter.ai'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\firefox.exe'
            - '\brave.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    condition: selection and not filter_browsers
falsepositives:
    - Legitimate AI development tools and scripts using OpenRouter API
    - IDE plugins with AI assistants configured to use OpenRouter
level: medium
```

#### 5. Wi-Fi Credential Dumping via Netsh

Detects Wi-Fi credential harvesting via `netsh wlan show profiles key=clear`, a proxy detection for infostealers that dump saved Wi-Fi passwords.

- **Confidence**: Medium (TTP-based; legitimate admin activity can trigger)
- **Caveat**: This is a proxy detection. VOLTA itself uses the `WlanGetProfileList` API rather than netsh; this rule covers the netsh-based variant of the same TTP, which is more commonly logged by endpoint telemetry.

```yaml
title: Wi-Fi Credential Dumping via Netsh
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: experimental
description: >
    Detects Wi-Fi credential harvesting through netsh wlan show profiles
    with key=clear. This is a proxy detection for infostealers such as VOLTA
    that dump saved Wi-Fi passwords. Note: VOLTA itself uses the WlanGetProfileList
    API rather than netsh; this rule covers the netsh-based variant of the same TTP,
    which is more commonly logged by endpoint telemetry.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI (DRAFT)
date: 2026-11-10
tags:
    - attack.credential_access
    - attack.t1555
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'netsh'
            - 'wlan'
            - 'show'
            - 'profiles'
        CommandLine|contains: 'key=clear'
    condition: selection
falsepositives:
    - System administrators auditing Wi-Fi configurations
    - Network troubleshooting scripts
level: medium
```

### YARA Rules

#### 6. VOLTA Infostealer Artifact Strings

Detects VOLTA infostealer samples based on combinations of distinctive strings found in the binary, including output filenames, LLM API endpoints, model identifiers, and prompt directives.

- **Confidence**: High (requires multiple co-occurring VOLTA-specific strings in a PE file)
- **Caveat**: Multi-string combinatorial rule requiring at least 3 of 6 VOLTA-branded filenames, or correlated API/model/prompt indicators. Will not match builds that strip or obfuscate these strings.

#### 7. VOLTA Infostealer Known Hash

Detects the known VOLTA sample by SHA-256 hash.

- **Confidence**: High (exact hash match)
- **Caveat**: Hash-based rule. Will only match the exact known sample. Will not detect variants or recompiled builds.

```yara
import "hash"

rule VOLTA_Infostealer_Artifacts
{
    meta:
        description = "Detects VOLTA infostealer based on distinctive strings found in samples"
        author = "Actioner CTI (DRAFT)"
        date = "2026-11-10"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "high"

    strings:
        $file1 = "volta_debug.txt" ascii wide
        $file2 = "volta_log.zip" ascii wide
        $file3 = "volta_dox.zip" ascii wide
        $file4 = "volta_doxnet.zip" ascii wide
        $file5 = "Identity_Report.txt" ascii wide
        $file6 = "AI_Analysis.txt" ascii wide
        $log1 = "WALLET VAULTS CRACKED" ascii wide
        $api1 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $api2 = "openrouter.ai" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $model3 = "google/gemini-2.5-flash" ascii wide
        $prompt1 = "WHAT THEY'RE WORTH" ascii wide
        $prompt2 = "THEIR OPSEC" ascii wide
        $prompt3 = "forensic intelligence analyst" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($file*)) or
            ($log1 and 1 of ($file*)) or
            ($api1 and 1 of ($model*)) or
            ($api2 and 2 of ($prompt*)) or
            (2 of ($model*) and 1 of ($prompt*))
        )
}

rule VOLTA_Infostealer_Hash
{
    meta:
        description = "Detects known VOLTA infostealer sample by SHA256 hash"
        author = "Actioner CTI (DRAFT)"
        date = "2026-11-10"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "high"

    condition:
        hash.sha256(0, filesize) == "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
}
```

### Suricata Rules

#### 8-9. VOLTA Network Detection (OpenRouter TLS/HTTP)

Two Suricata rules detecting network-level indicators of VOLTA's LLM API communication: TLS SNI matching and HTTP POST to the chat completions endpoint (requires TLS inspection).

- **Confidence**: Medium (the domain is a legitimate service; rules are TTP-level)
- **Caveat**: These rules target a legitimate third-party service and use `misc-activity` classtype accordingly. They will produce false positives in environments where OpenRouter is used for authorized AI development. Deploy with appropriate suppression for known AI development hosts. SIDs are in the local range (1000001-1000002).

```
# Suricata rules for VOLTA infostealer network indicators
# Status: structurally reviewed (suricata not available in validation environment)
# SIDs in local range 1000000-1999999

# Detects HTTPS TLS SNI to openrouter.ai which VOLTA uses for LLM victim analysis
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"VOLTA Infostealer - OpenRouter AI API TLS SNI"; tls.sni; content:"openrouter.ai"; nocase; classtype:misc-activity; sid:1000001; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)

# Detects HTTP POST to OpenRouter chat completions endpoint (if TLS inspection is enabled)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"VOLTA Infostealer - OpenRouter Chat Completions API POST"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; nocase; http.uri; content:"/api/v1/chat/completions"; classtype:misc-activity; sid:1000002; rev:1; metadata:created_at 2026_11_10, updated_at 2026_11_10;)
```

---

## Validation Summary

| Rule Type | Rule | Splunk | LogScale | yarac | Notes |
|---|---|---|---|---|---|
| Sigma #1 | VOLTA Debug Log | Pass | Pass | -- | Unchanged |
| Sigma #2 | VOLTA Staging Archives | Pass | Pass | -- | Unchanged |
| Sigma #3 | Identity Report + AI Analysis | Pass | Pass | -- | Fixed: AND condition, level lowered to low |
| Sigma #4 | OpenRouter Non-Browser | Pass | Pass | -- | Unchanged |
| Sigma #5 | Wi-Fi Credential Dumping via Netsh | Pass | Pass | -- | Fixed: renamed, proxy-detection caveat added |
| YARA #6 | VOLTA Artifact Strings | -- | -- | Pass (exit 0) | Unchanged |
| YARA #7 | VOLTA Known Hash | -- | -- | Pass (exit 0) | Fixed: severity critical -> high |
| Suricata #8 | OpenRouter TLS SNI | -- | -- | -- | Fixed: SID 1000001, classtype misc-activity |
| Suricata #9 | OpenRouter HTTP POST | -- | -- | -- | Fixed: SID 1000002, classtype misc-activity |

Suricata rules were structurally reviewed only; `suricata` is not installed in the validation environment.

---

## Sources

- [Cisco Talos: Appraisal by AI: Model-Driven Victim Prioritization in the VOLTA Infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) (2026-10-31)
- [Cisco Talos: Introducing CAIRN - Frontier Tracking for AI-Integrated Malware](https://blog.talosintelligence.com/introducing-cairn-frontier-tracking-for-ai-integrated-malware/)
- [Cisco Talos: The Closed Quorum - Inside the First Reported Autonomous AI C2 Implant](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/)

---

*This report has been revised per editorial review. All detection rules require environmental tuning and validation before production deployment.*
