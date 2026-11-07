# VOLTA Infostealer (VOLTA-AUTODOXER) -- DRAFT Technical Analysis

| Field | Value |
|---|---|
| **Report Status** | DRAFT |
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
3. **OpenRouter API traffic from non-browser processes:** Correlate DNS queries or TLS connections to `openrouter.ai` with process telemetry
4. **Known sample hash:** Deploy SHA-256 `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279`
5. **Self-deleting executables:** Monitor for processes that delete their own binary after execution

### Remediation Steps

1. **Preserve `%APPDATA%\volta_debug.txt`** before it is overwritten or deleted -- it contains timestamped harvest records
2. **Revoke all sessions and tokens** (not just passwords) for every application on the affected host: Discord, Telegram, Steam, Gmail, Microsoft, Slack, Roblox, and any cloud provider
3. **Rotate all passwords** that were stored in browsers or password managers on the host
4. **Migrate cryptocurrency** from any wallet whose seed phrase was stored in plaintext or on the affected system
5. **Revoke and regenerate SSH keys** and cloud API credentials
6. **Change Wi-Fi passwords** for all networks the affected host connected to
7. **Implement application control** to block unknown executables and restrict headless Chrome launches
8. **Deploy egress monitoring** tied to process identity to detect unauthorized API calls to AI services and messaging platforms

---

## Detection Rules

### Sigma Rules

#### Rule 1: VOLTA Infostealer -- Headless Chrome ABE Bypass
- **File:** `rules/sigma/2026-11-07-volta-infostealer-1.yml`
- **Compile Status:** ✅ Compiles (converts to Splunk and LogScale; `sigma check` failed due to network connectivity to MITRE ATT&CK, not rule syntax)
- **Confidence:** High
- **MITRE:** T1555.003
- **Audit Comment:** Behavioral rule. May fire on legitimate browser automation (Selenium, Puppeteer). Tune `filter_main_parent` to include approved testing frameworks.

```yaml
detection:
    selection:
        Image|endswith: '\chrome.exe'
        CommandLine|contains: '--headless'
    filter_main_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\GoogleUpdate.exe'
            - '\setup.exe'
    condition: selection and not filter_main_parent
```

#### Rule 2: VOLTA Infostealer -- Suspicious OpenRouter API Connection
- **File:** `rules/sigma/2026-11-07-volta-infostealer-2.yml`
- **Compile Status:** ✅ Compiles
- **Confidence:** Medium
- **MITRE:** T1567
- **Audit Comment:** DNS-based rule. OpenRouter is a legitimate service; this rule will fire on non-browser processes querying the domain. Correlate with other VOLTA indicators before escalating. Consider allowlisting known AI-powered applications.

```yaml
detection:
    selection:
        QueryName|endswith: 'openrouter.ai'
    filter_main_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\brave.exe'
            - '\opera.exe'
    condition: selection and not filter_main_browser
```

#### Rule 3: VOLTA Infostealer -- Debug Log and Exfil Archive Creation
- **File:** `rules/sigma/2026-11-07-volta-infostealer-3.yml`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **MITRE:** T1560.001, T1567
- **Audit Comment:** Advisory-specific filenames with very low false positive potential. The `volta_debug.txt` artifact is distinctive. The `Identity_Report.txt` and `AI_Analysis.txt` names are more generic; consider requiring co-occurrence with other VOLTA indicators in production.

#### Rule 4: VOLTA Infostealer -- Known Sample Filename Deletion
- **File:** `rules/sigma/2026-11-07-volta-infostealer-4.yml`
- **Compile Status:** ✅ Compiles
- **Confidence:** High (for known samples); Low (coverage of future builds)
- **MITRE:** T1070.004
- **Audit Comment:** Targets only the two known VOLTA filenames. Builder-generated samples will use different names. Supplement with behavioral rules.

### YARA Rules

#### Rule 1: VOLTA_Infostealer_Strings
- **File:** `rules/yara/2026-11-07-volta-infostealer.yar`
- **Compile Status:** ✅ Compiles (`yarac` exit 0)
- **Confidence:** High
- **Audit Comment:** Matches on VOLTA-specific artifact names and report section headers. PE header check (`MZ`) and filesize cap reduce false positives. The "WALLET VAULTS CRACKED" string alone is high-confidence.

#### Rule 2: VOLTA_Infostealer_APIConfig
- **File:** `rules/yara/2026-11-07-volta-infostealer.yar`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **Audit Comment:** Matches on OpenRouter API endpoint and LLM model identifier strings specific to VOLTA's fallback chain. Unlikely to match legitimate software. The combination of 2+ model strings with refusal detection phrases is distinctive.

#### Rule 3: VOLTA_Infostealer_WiFiHarvest
- **File:** `rules/yara/2026-11-07-volta-infostealer.yar`
- **Compile Status:** ✅ Compiles
- **Confidence:** Medium
- **Audit Comment:** WlanGetProfileList is used by legitimate Wi-Fi management tools. This rule requires co-occurrence with VOLTA-specific strings to reduce false positives. Medium confidence due to the broader use of the API.

### Snort Rules

#### Rule 1: VOLTA -- OpenRouter API Chat Completions Request (SID 2026110701)
- **File:** `rules/snort/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles (Snort 2.9.20 validation passed)
- **Confidence:** Medium
- **Audit Comment:** Detects POST to OpenRouter chat completions. Will fire on any application using the OpenRouter API. Best deployed as a hunt/alert rule, not a block. Correlate with other VOLTA network indicators.

#### Rule 2: VOLTA -- LLM Model Identifier in HTTP Body (SID 2026110702)
- **File:** `rules/snort/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** Medium
- **Audit Comment:** Requires both the "anthropic/claude-opus" model string in the body and "openrouter.ai" in headers. Higher specificity than Rule 1, but legitimate OpenRouter users may also specify this model.

#### Rule 3: VOLTA -- AI Assessment Output Markers (SID 2026110703)
- **File:** `rules/snort/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **Audit Comment:** Matches VOLTA's unique assessment section headers in traffic. Very low false positive rate. Note: if VOLTA uses TLS (likely), this rule requires TLS inspection or will only catch unencrypted exfil.

#### Rule 4: VOLTA -- Exfiltration Archive Name (SID 2026110704)
- **File:** `rules/snort/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **Audit Comment:** Matches "volta_dox.zip" in outbound traffic. Highly specific. Requires TLS inspection for encrypted exfil channels.

### Suricata Rules

#### Rule 1: VOLTA -- OpenRouter API Chat Completions (SID 2026110801)
- **File:** `rules/suricata/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles (Suricata 7.0.3 validation passed)
- **Confidence:** Medium
- **Audit Comment:** Uses Suricata HTTP sticky buffers. Same correlation caveat as Snort Rule 1.

#### Rule 2: VOLTA -- LLM Model String in Request Body (SID 2026110802)
- **File:** `rules/suricata/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** Medium
- **Audit Comment:** Matches model identifier in HTTP request body via sticky buffer. Higher fidelity than DNS-only detection.

#### Rule 3: VOLTA -- Exfiltration Archive in Upload (SID 2026110803)
- **File:** `rules/suricata/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **Audit Comment:** Matches "volta_dox.zip" in HTTP request body. Highly specific to VOLTA exfiltration.

#### Rule 4: VOLTA -- DNS Query for OpenRouter (SID 2026110804)
- **File:** `rules/suricata/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** Low
- **Audit Comment:** Broad DNS-level detection. OpenRouter is a legitimate service. Use as a hunt signal, not a detection. Must be correlated with endpoint telemetry.

#### Rule 5: VOLTA -- Staged Exfil Archive volta_log.zip (SID 2026110805)
- **File:** `rules/suricata/2026-11-07-volta-infostealer.rules`
- **Compile Status:** ✅ Compiles
- **Confidence:** High
- **Audit Comment:** Matches the initial exfiltration archive name. Same TLS inspection requirement applies.

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

*Report generated 2026-11-07 by Actioner CTI pipeline. DRAFT -- pending peer review.*
