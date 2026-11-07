# VOLTA Infostealer (VOLTA-AUTODOXER) -- Technical Analysis

| Field | Value |
|---|---|
| **Report Status** | FINAL |
| **Date** | 2026-11-07 |
| **Threat** | VOLTA / VOLTA-AUTODOXER Infostealer |
| **Severity** | High |
| **Disclosed By** | Cisco Talos (CAIRN team) |
| **Disclosure Date** | 2026-10-31 |
| **TLP** | CLEAR |

---

## Executive Summary

VOLTA (also tracked as VOLTA-AUTODOXER) is a Windows x86-64 infostealer that harvests credentials, browser data, cryptocurrency wallets, application sessions, and Wi-Fi profiles, then sends a structured victim dossier to a large language model (LLM) via the OpenRouter API for automated monetization assessment. The LLM ranks the victim's assets by resale value and evaluates their security posture, relieving the operator of manual triage. First observed on October 11, 2026, and disclosed by Cisco Talos on October 31, 2026, VOLTA represents a novel integration of AI-driven victim prioritization into the commodity infostealer ecosystem. The malware self-deletes after execution, operates without attacker-owned infrastructure (relying entirely on third-party APIs), and is distributed via a builder model with six configurable slots, suggesting it is sold as a service.

---

## Background

Cisco Talos's CAIRN (Counter AI Research Nexus) team identified VOLTA during their tracking of AI-integrated malware. VOLTA is the second AI-enabled implant publicly documented by Talos, following their earlier work on CLOSEDQUORUM. While CLOSEDQUORUM used AI for operational decision-making, VOLTA applies LLM capabilities specifically to post-collection victim triage -- an approach Talos describes as shifting human-intensive analytical work to model calls.

The malware operates as a builder-based service. Each build is compiled with six configurable slots (including Telegram channel, API keys, and operational settings), meaning different operators will produce samples with different hashes but identical core functionality.

---

## Attack Timeline

| Date | Event |
|---|---|
| 2026-08-17 20:35 UTC | PE compile timestamp of the analyzed sample |
| 2026-10-11 12:46 UTC | First observed in the wild |
| 2026-10-31 | Cisco Talos publishes analysis |
| 2026-11-07 | This report drafted |

---

## Root Cause

The initial access vector for VOLTA is **unknown**. Talos did not identify the delivery mechanism. The builder model suggests distribution through typical infostealer channels (cracked software, malvertising, phishing, or social engineering on messaging platforms). No confirmed victim counts or follow-on compromises using AI assessment results have been reported.

---

## Technical Analysis

### Stage 1: Collection

VOLTA performs comprehensive credential and data harvesting across multiple categories:

**Browser Data:**
- Chromium-family browsers: passwords, cookies, saved payment cards, autofill data
- Firefox and Thunderbird: stored credentials and session data
- Outlook profiles
- App-Bound Encryption (ABE) bypass via headless Chrome launch (`chrome.exe --headless`) to extract protected Chromium credentials

**Application Sessions and Tokens:**
- Discord tokens (later reused for profile enrichment)
- Telegram session files
- Steam and Roblox sessions
- Microsoft OAuth tokens
- Slack sessions
- SSH keys and cloud provider configuration files

**System Data:**
- Wi-Fi profiles and plaintext passwords via `WlanGetProfileList` API
- Screenshots
- Geolocation data
- Host system information

**Cryptocurrency:**
- Wallet files and seed phrases
- Inline vault cracking (logged as "WALLET VAULTS CRACKED")

### Stage 2: Local Enrichment (Session Reuse)

VOLTA reuses stolen sessions and tokens for active enrichment:

- **Gmail:** Searches for purchase receipts from Amazon, DoorDash, Uber Eats, Grubhub, Walmart, and PayPal to confirm physical addresses and spending patterns
- **Uber Eats / DoorDash:** Queries order history directly using stolen sessions
- **Discord:** Enriches victim profile using the stolen token
- **Roblox / Rolimons:** Values the victim's Roblox inventory through the Rolimons live valuation service

### Stage 3: Structuring

Collected and enriched data is assembled into `Identity_Report.txt`, a structured JSON victim dossier containing all harvested artifacts, enrichment results, and metadata.

### Stage 4: AI Assessment

The JSON dossier is sent to an LLM via the OpenRouter Chat Completions API:

- **Endpoint:** `openrouter[.]ai/api/v1/chat/completions` (HTTP POST, JSON body)
- **User-Agent:** `Mozilla/5.0`
- **Temperature:** 0.2
- **Default model:** `anthropic/claude-opus-4.6`
- **Fallback chain:** `moonshotai/kimi-k2` -> `google/gemini-2.5-flash`
- **Refusal handling:** Response is checked for refusal phrases ("I can't", "I'm not able"); on detection, the next model in the chain is tried (up to 3 attempts)
- **Persona:** The system prompt instructs the model to act as "a forensic intelligence analyst drafting a target assessment"
- **Prompt guidance:** "Go deep, not wide... Be blunt, specific, accurate."
- **Output sections:**
  - **"WHAT THEY'RE WORTH"** -- Assets ranked by monetization ease into low, medium, and high tiers
  - **"THEIR OPSEC"** -- Assessment of the victim's password hygiene and security posture, linking sparse data points (names, addresses, universities) to password patterns

The model response is saved as `AI_Analysis.txt`.

### Stage 5: Staged Exfiltration

Data is exfiltrated in staged ZIP archives:

1. **`volta_log.zip`** -- Sent after initial collection (raw stolen data)
2. **`volta_dox.zip`** -- Sent after AI processing (contains `Identity_Report.txt` and `AI_Analysis.txt`)
3. **`volta_doxnet.zip`** -- Sent conditionally when network enrichment returns additional data

Exfiltration is performed to a Telegram channel (configured at build time).

### Stage 6: Self-Deletion

The executable deletes itself after completing all stages, removing the primary forensic artifact. However, `%APPDATA%\volta_debug.txt` (a timestamped harvest log) may survive self-deletion.

### Obfuscation

Build-time secrets (API keys, Telegram channel, etc.) are encrypted using a key derived via SHA-256 from two constants embedded in the binary. Talos describes this as weak protection that can be recovered through reverse engineering.

### Infrastructure

VOLTA uses **no attacker-owned infrastructure**. All C2 and exfiltration flows through legitimate third-party services:
- OpenRouter (AI API)
- Telegram (data exfiltration)
- Various SaaS platforms (enrichment)

---

## Indicators of Compromise

> All network indicators are defanged per standard practice.

### File Hashes

| Type | Value | Note |
|---|---|---|
| SHA-256 | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | Primary analyzed sample |

**Note:** VOLTA uses a builder model. Other builds will have different hashes. Behavioral detection should supplement hash-based IOCs.

### File Names

| Filename | Context |
|---|---|
| `9BY0tjwOc3ut.exe` | Observed VOLTA executable name |
| `yLP9m5J3i2Aw.exe` | Observed VOLTA executable name |
| `volta_debug.txt` | Timestamped harvest log (`%APPDATA%`) |
| `Identity_Report.txt` | Structured victim dossier (JSON) |
| `AI_Analysis.txt` | LLM assessment output |
| `volta_log.zip` | Stage 1 exfil archive |
| `volta_dox.zip` | Stage 2 exfil archive (post-AI) |
| `volta_doxnet.zip` | Stage 3 exfil archive (network enrichment) |

### Network Indicators

| Indicator | Type | Context |
|---|---|---|
| `openrouter[.]ai` | Domain | LLM API endpoint for victim assessment |
| `openrouter[.]ai/api/v1/chat/completions` | URL | Chat completions API endpoint |
| `rolimons[.]com` | Domain | Roblox inventory valuation |

**Caution:** Both openrouter[.]ai and rolimons[.]com serve legitimate users. These domains should NOT be blocked outright; instead, correlate with process-level telemetry and other behavioral indicators.

### Strings and Artifacts

| String / Artifact | Context |
|---|---|
| `WALLET VAULTS CRACKED` | Report section logged during crypto wallet extraction |
| `WHAT THEY'RE WORTH` | AI assessment output section header |
| `THEIR OPSEC` | AI assessment output section header |
| `forensic intelligence analyst` | System prompt persona fragment |
| `Go deep, not wide` | Prompt guidance fragment |
| `anthropic/claude-opus-4.6` | Default LLM model string |
| `moonshotai/kimi-k2` | First fallback model string |
| `google/gemini-2.5-flash` | Second fallback model string |
| `I can't` | Refusal detection string |
| `I'm not able` | Refusal detection string |
| `Mozilla/5.0` | User-Agent used for API calls |

### Host Artifacts

| Path | Description |
|---|---|
| `%APPDATA%\volta_debug.txt` | Harvest log -- **preserve during IR** |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | VOLTA Behavior | Confidence |
|---|---|---|---|
| T1555.003 | Credentials from Web Browsers | Chromium/Firefox credential extraction, ABE bypass | High |
| T1539 | Steal Web Session Cookie | Browser cookie extraction | High |
| T1528 | Steal Application Access Token | Discord, Telegram, Steam, OAuth, Slack tokens | High |
| T1552.001 | Credentials in Files | SSH keys, cloud configs, Wi-Fi passwords | High |
| T1552.004 | Private Keys | SSH private key harvesting | High |
| T1005 | Data from Local System | Wallet files, documents, screenshots | High |
| T1113 | Screen Capture | Screenshots of victim desktop | High |
| T1114.002 | Remote Email Collection | Gmail receipt search via stolen tokens | High |
| T1016 | System Network Configuration Discovery | Wi-Fi profile enumeration via WlanGetProfileList | Medium |
| T1614 | System Location Discovery | Geolocation data collection | Medium |
| T1560.001 | Archive Collected Data: Archive via Utility | Staged ZIP archives (volta_log/dox/doxnet.zip) | High |
| T1567 | Exfiltration Over Web Service | Data sent to Telegram and OpenRouter | High |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion of executable | High |
| T1027 | Obfuscated Files or Information | Encrypted config with SHA-256 derived key | Medium |

---

## Impact Assessment

### Scope of Compromise

A VOLTA infection should be treated as a **full credential and session compromise** across all applications present on the victim host. The impact includes:

1. **Credential Exposure:** All browser-stored passwords, payment cards, and autofill data
2. **Session Hijacking:** Active sessions for Discord, Telegram, Steam, Roblox, Gmail, Slack, and Microsoft services
3. **Cryptocurrency Theft:** Wallet seed phrases and vault contents
4. **Physical Identity Exposure:** The AI assessment correlates stolen data to build a real-world identity profile, including address confirmation via delivery service order history
5. **Wi-Fi Network Compromise:** Plaintext Wi-Fi passwords exposed
6. **SSH/Cloud Access:** Private keys and cloud configuration files enabling lateral movement

### Novel Risk: AI-Driven Prioritization

The LLM integration allows operators to efficiently triage large volumes of stolen data, focusing manual follow-up on high-value victims. This reduces the operator's time-to-exploitation for high-worth targets and may indicate a trend toward AI-augmented cybercrime at scale.

---

## Detection & Remediation

### Detection Priorities

1. **Headless Chrome from non-standard parents:** Alert on `chrome.exe --headless` launched by processes other than Chrome itself or Chrome updater
2. **VOLTA file artifacts:** Hunt for `volta_debug.txt`, `volta_*.zip`, `Identity_Report.txt`, `AI_Analysis.txt` on endpoints
3. **OpenRouter API traffic from non-browser processes:** Correlate DNS queries or TLS connections to `openrouter[.]ai` with process telemetry
4. **Known sample hash:** Deploy SHA-256 `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279`
5. **Self-deleting executables:** Monitor for processes that delete their own binary after execution

### Remediation Steps

1. **Preserve `%APPDATA%\volta_debug.txt`** before it is overwritten or deleted -- it contains timestamped harvest records
2. **Revoke all sessions and tokens** (not just passwords) for every application on the affected host: Discord, Telegram, Steam, Gmail, Microsoft, Slack, Roblox, and any cloud provider
3. **Rotate all passwords** that were stored in browsers or password managers on the host
4. **Migrate cryptocurrency** from any wallet whose seed phrase was stored in plaintext or on the affected system
5. **Revoke and regenerate SSH keys** and cloud API credentials
6. **Change Wi-Fi passwords** for all networks the affected host connected to
7. **Implement application control** to block unknown executables and restrict headless Chrome launches (where supported by endpoint tooling)
8. **Deploy egress monitoring** tied to process identity to detect unauthorized API calls to AI services and messaging platforms (where supported by endpoint tooling)

---

## Detection Rules

These detections target VOLTA-specific file artifacts, binary strings, and network exfiltration patterns at PoC/advisory-specific altitude. All HTTP-content network rules require TLS inspection; without it, only DNS-based detection applies (none retained -- see dropped-rule notes). Compiles does not equal fires -- verify in your pipeline.

<!-- revision: 9 rules dropped (2 Sigma, 4 Snort, 3 Suricata) for excessive FP on legitimate services or TTP-level breadth. Remaining rules tightened per critic verdict. -->

### Sigma Rules

<!-- revision: dropped Sigma #1 "Headless Chrome ABE Bypass" -- behavioral/TTP, fires on any headless Chrome from non-standard parent (Selenium, Puppeteer, CI/CD); not artifact-specific at strict altitude. -->
<!-- revision: dropped Sigma #2 "Suspicious OpenRouter API Connection" -- DNS query to legitimate public API; any dev tool or AI app calling OpenRouter fires this; filter excludes only five browsers. -->

#### Rule 1: VOLTA Infostealer -- Debug Log and Exfil Archive Creation
Detects creation of VOLTA-prefixed file artifacts (`volta_debug.txt`, `volta_*.zip`); generic report names fire only when co-occurring with a volta-prefixed file.
**Status:** compile ✅ compiles (Splunk + LogScale convert exit 0) · confidence: high (volta-prefixed filenames)
<!-- audit: sigma check fails on MITRE ATT&CK network fetch (403), not rule syntax. splunk/log_scale convert exit 0. Level lowered critical->high. selection_reports now conjunctive with selection_debug|selection_archives to prevent generic-name-only firing. -->
- **File:** `rules/sigma/2026-11-07-volta-infostealer-1.yml`

```yaml
title: VOLTA Infostealer - Debug Log and Exfil Archive Creation
id: c3e5f0a4-9b6d-4c1f-d8e3-4f0a7b2c5d9e
status: experimental
description: >
    Detects creation of files matching VOLTA infostealer artifact naming
    conventions, including its debug log (volta_debug.txt) and staged
    exfiltration archives (volta_log.zip, volta_dox.zip, volta_doxnet.zip).
    Generic report filenames (Identity_Report.txt, AI_Analysis.txt) fire only
    when co-occurring with a volta-prefixed artifact.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI
date: 2026-11-07
tags:
    - attack.t1560.001
    - attack.t1567
logsource:
    category: file_event
    product: windows
detection:
    selection_debug:
        TargetFilename|endswith: '\volta_debug.txt'
    selection_archives:
        TargetFilename|endswith:
            - '\volta_log.zip'
            - '\volta_dox.zip'
            - '\volta_doxnet.zip'
    selection_reports:
        TargetFilename|endswith:
            - '\Identity_Report.txt'
            - '\AI_Analysis.txt'
    condition: selection_debug or selection_archives or (selection_reports and (selection_debug or selection_archives))
falsepositives:
    - Unlikely for volta-prefixed filenames; generic report names require co-occurrence
level: high
```

#### Rule 2: VOLTA Infostealer -- Known Sample Filename Deletion
Detects deletion of two known VOLTA sample filenames; builder randomizes names so future-build coverage is near-zero.
**Status:** compile ✅ compiles (Splunk + LogScale convert exit 0) · confidence: low
<!-- audit: sigma check fails on MITRE ATT&CK network fetch (403), not rule syntax. splunk/log_scale convert exit 0. Retitled from "Process Self-Deletion After Credential Harvest" (rule does not verify self-deletion). Level critical->high. Confidence low -- exact IOC with no future-build coverage. -->
- **File:** `rules/sigma/2026-11-07-volta-infostealer-2.yml`

```yaml
title: VOLTA Infostealer - Known Sample Filename Deletion
id: d4f6a1b5-0c7e-4d2a-e9f4-5a1b8c3d6e0f
status: experimental
description: >
    Detects deletion of files matching known VOLTA infostealer sample names.
    Coverage is limited to two observed filenames; the builder randomizes names
    per build, so future samples will not match.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner CTI
date: 2026-11-07
tags:
    - attack.t1070.004
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\9BY0tjwOc3ut.exe'
            - '\yLP9m5J3i2Aw.exe'
    condition: selection
falsepositives:
    - Unlikely; these filenames are unique to known VOLTA samples
level: high
```

### YARA Rules

#### Rule 1: VOLTA_Infostealer_Strings
Detects VOLTA by characteristic artifact names and report section headers in PE binaries.
**Status:** compile ✅ compiles (`yarac` exit 0) · confidence: high
<!-- audit: yarac exit 0. PE header + filesize cap. "WALLET VAULTS CRACKED" alone is high-confidence. No changes from draft. -->

#### Rule 2: VOLTA_Infostealer_APIConfig
Detects VOLTA by OpenRouter API config and LLM model strings; `$api_endpoint` now requires co-occurrence with a model or persona string.
**Status:** compile ✅ compiles (`yarac` exit 0) · confidence: high
<!-- audit: yarac exit 0. Fixed: $api_endpoint alone previously matched any binary embedding the OpenRouter SDK. Now requires co-occurrence with $model* or $persona. Audit comment "unlikely to match legitimate software" corrected. -->
<!-- revision: condition tightened -- $api_endpoint requires 1 of ($model*, $persona) to co-occur -->

#### Rule 3: VOLTA_Infostealer_WiFiHarvest
Detects VOLTA Wi-Fi harvesting by WlanGetProfileList co-occurring with volta-prefixed strings.
**Status:** compile ✅ compiles (`yarac` exit 0) · confidence: medium
<!-- audit: yarac exit 0. WlanGetProfileList used by legitimate Wi-Fi tools; volta-string co-occurrence reduces FP. No changes from draft. -->

All YARA rules in: `rules/yara/2026-11-07-volta-infostealer.yar`

### Snort Rules

> **TLS caveat:** VOLTA exfiltrates to Telegram over HTTPS. All HTTP-content Snort rules below require TLS inspection to be effective; without it they will not fire on encrypted exfiltration traffic.

<!-- revision: dropped SID 2026110701 "OpenRouter API Chat Completions" -- generic OpenRouter detection; any app using the service fires it; TLS blind. -->
<!-- revision: dropped SID 2026110702 "LLM Model Identifier in HTTP Body" -- not VOLTA-exclusive; legitimate OpenRouter users specify the same model; TLS blind. -->

#### Rule 1: VOLTA -- AI Assessment Output Markers (SID 2026110703)
Detects VOLTA's unique assessment section headers ("WHAT THEY'RE WORTH" + "THEIR OPSEC") co-occurring in outbound traffic. Requires TLS inspection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: Snort 2.9.20. Content match on two VOLTA-specific section headers. Downgraded from high to medium: rule is VOLTA-specific but non-functional without TLS inspection (Telegram HTTPS). -->
<!-- revision: confidence high->medium (TLS blindness caveat) -->

#### Rule 2: VOLTA -- Exfiltration Archive Name (SID 2026110704)
Detects "volta_dox.zip" in outbound HTTP traffic. Requires TLS inspection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: Snort 2.9.20. Highly specific filename. Downgraded from high to medium: non-functional without TLS inspection. -->
<!-- revision: confidence high->medium (TLS blindness caveat) -->

All Snort rules in: `rules/snort/2026-11-07-volta-infostealer.rules`

### Suricata Rules

> **TLS caveat:** VOLTA exfiltrates to Telegram over HTTPS. All HTTP-content Suricata rules below require TLS inspection to be effective.

<!-- revision: dropped SID 2026110801 "OpenRouter API Chat Completions" -- generic OpenRouter detection; not VOLTA-specific. -->
<!-- revision: dropped SID 2026110802 "LLM Model String in Request Body" -- not VOLTA-exclusive; legitimate OpenRouter users specify the same model. -->
<!-- revision: dropped SID 2026110804 "DNS Query for OpenRouter" -- bare DNS query to legitimate service; misclassified as trojan-activity. -->

#### Rule 1: VOLTA -- Exfiltration Archive volta_dox.zip in Upload (SID 2026110803)
Detects "volta_dox.zip" in HTTP POST request body. Requires TLS inspection.
**Status:** compile ✅ compiles (Suricata 7.0.3 exit 0) · confidence: medium
<!-- audit: suricata -T exit 0. VOLTA-specific filename. Downgraded from high to medium: non-functional without TLS inspection (Telegram HTTPS). -->
<!-- revision: confidence high->medium (TLS blindness caveat); msg prefix corrected to "Actioner - " per spec -->

#### Rule 2: VOLTA -- Staged Exfil Archive volta_log.zip (SID 2026110805)
Detects "volta_log.zip" in HTTP POST request body. Requires TLS inspection.
**Status:** compile ✅ compiles (Suricata 7.0.3 exit 0) · confidence: medium
<!-- audit: suricata -T exit 0. VOLTA-specific initial exfil archive name. Downgraded from high to medium: non-functional without TLS inspection. -->
<!-- revision: confidence high->medium (TLS blindness caveat); msg prefix corrected to "Actioner - " per spec -->

All Suricata rules in: `rules/suricata/2026-11-07-volta-infostealer.rules`

---

## Sources

- [Cisco Talos -- Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/)
- [DEV Community -- VOLTA: Infostealer Uses LLMs to Assess Stolen Data](https://dev.to/anoymask/volta-infostealer-uses-llms-to-assess-stolen-data-and-prioritize-high-value-victims-2ock)
- [Brandefense -- VOLTA Infostealer: AI Victim Ranking](https://brandefense.io/security-news/volta-infostealer-ai-victim-ranking/)
- [AICYBR -- VOLTA-AUTODOXER: AI-Powered Victim Profiling, Credential Theft and Detection](https://aicybr.com/blog/volta-autodoxer-ai-victim-profiling-infostealer-detection-response)
- [GIGAZINE -- Malware discovered that uses AI to analyze stolen personal information](https://gigazine.net/gsc_news/en/20261102-ai-model-driven-victim-prioritization/)
- [InsideAI -- Volta-Autodoxer: AI-Enhanced Malware Profiles Victims for Hackers](https://insideai.news/news/cybersecurity-ai/volta-autodoxer-ai-malware/14302/)
- [AI Chat Daily -- Talos finds VOLTA infostealer using Claude to rank victims](https://www.aichatdaily.com/ai-security/talos-finds-volta-infostealer-using-claude-rank-victims)
- [DataStudios -- VOLTA infostealer uses Claude, Kimi and Gemini via OpenRouter](https://www.datastudios.org/post/cisco-talos-volta-infostealer-claude-kimi-gemini-openrouter-victim-profiling)
- [NetManageIT -- VOLTA Infostealer: AI Victim Prioritization](https://blog.netmanageit.com/volta-infostealer-ai-victim-prioritization/)

---

*Report generated 2026-11-07 by Actioner CTI pipeline. Revised 2026-11-07 after peer review.*
