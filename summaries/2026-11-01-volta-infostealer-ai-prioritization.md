# VOLTA Infostealer: Self-Deleting Windows Infostealer with LLM-Based Victim Prioritization

**Status:** DRAFT | **TLP:** CLEAR | **Date:** 2026-11-01 | **Author:** CTI Research Team

---

## Executive Summary

VOLTA (also tracked as VOLTA-AUTODOXER) is a novel Windows infostealer discovered through Cisco Talos' CAIRN research effort and publicly disclosed on October 31, 2026. Its distinguishing capability is a post-collection stage that sends harvested victim data to a large language model (LLM) via the OpenRouter API, which then ranks the victim's assets by monetization value and assesses their security posture. The malware harvests credentials, sessions, crypto wallets, and personal data from over a dozen application categories, performs live enrichment using stolen sessions, and self-deletes after exfiltration. No in-the-wild attacks have been confirmed; Talos describes VOLTA as a likely builder-model product where the author sells access and customers supply configuration values at compile time.

---

## Background

VOLTA was identified through Talos' CAIRN research initiative, which also produced work on CLOSEDQUORUM and NIK C2. The malware is a PE32+ (x86-64) executable distributed as a custom-compiled binary per buyer. It uses no attacker-owned infrastructure -- all endpoints are third-party services (OpenRouter for LLM inference, Telegram for exfiltration, Rolimons for Roblox valuation). The AI-driven triage represents a significant evolution in infostealer tradecraft: rather than dumping all data and leaving prioritization to the operator, VOLTA automates victim appraisal using commercial LLM APIs.

---

## Attack Timeline

| Date | Event |
|------|-------|
| 2026-08-17 | PE compilation timestamp (20:35 UTC) |
| 2026-10-11 | First observed in the wild (12:46 UTC) |
| 2026-10-31 | Cisco Talos publishes analysis |

---

## Root Cause

Initial access vector is not described in the Talos report. The binary is delivered as a standalone PE executable. The builder model suggests distribution likely varies per customer (e.g., phishing, drive-by download, cracked software bundles). No persistence mechanism is documented -- the malware executes, collects, exfiltrates, and self-deletes.

---

## Technical Analysis

### Execution Chain

1. **Execution** -- Victim runs the PE binary (e.g., `9BY0tjwOc3ut.exe` or `yLP9m5J3i2Aw.exe`)
2. **Credential & Data Harvesting** -- Broad collection across browsers, messaging apps, cloud configs, wallets, Wi-Fi profiles, and screenshots
3. **Wallet Cracking** -- Embedded cracker runs against wallet vaults inline
4. **Stage 1 Exfiltration** -- `volta_log.zip` sent to operator's Telegram channel
5. **Live Enrichment** -- Stolen sessions used to query Gmail receipts, food delivery order history, Discord profiles, and Roblox inventory valuation
6. **Identity Report Assembly** -- `Identity_Report.txt` compiled as serialized JSON with geolocation, employer, inferred birth year, card last-4, Slack workspaces, document metadata, iPhone backup indicators, and Roblox valuation
7. **LLM Appraisal** -- Identity report POSTed to OpenRouter API; LLM returns `AI_Analysis.txt` with asset ranking and security posture assessment
8. **Stage 2 Exfiltration** -- `volta_dox.zip` (containing Identity_Report.txt and AI_Analysis.txt)
9. **Stage 3 Exfiltration** -- `volta_doxnet.zip` (if network enrichment yields results)
10. **Self-Deletion** -- Main executable removes itself (mechanism not disclosed)

### Data Collection Targets

| Category | Targets |
|----------|---------|
| **Browsers** | Chromium (passwords, cookies, saved cards), Firefox, Thunderbird |
| **Email** | Outlook profiles, Gmail (via stolen sessions) |
| **Messaging** | Discord, Telegram, Slack sessions |
| **Gaming** | Steam, Battle.net, Roblox (with inventory valuation via Rolimons) |
| **Crypto** | Wallet vaults (with inline cracking) |
| **Cloud/SSH** | SSH keys, gcloud, OpenVPN, Hide.me configs |
| **Auth Tokens** | Microsoft OAuth tokens, Discord tokens |
| **Wi-Fi** | All saved Wi-Fi passwords via `WlanGetProfileList` (dumped in plaintext) |
| **Screenshots** | Desktop capture |
| **Delivery Apps** | Uber Eats and DoorDash order history (via stolen sessions) |

### Chrome App-Bound Encryption (ABE) Bypass

VOLTA bypasses Chrome's App-Bound Encryption by launching Chrome with the `--headless` flag from its own process. This allows extraction of cookies and credentials that would otherwise be protected by ABE.

### LLM Victim Prioritization

- **Endpoint:** `hxxps://openrouter[.]ai/api/v1/chat/completions`
- **Method:** POST with hand-assembled JSON (no SDK)
- **User-Agent:** `Mozilla/5.0`
- **Temperature:** 0.2
- **Default Model:** `anthropic/claude-opus-4.6`
- **Fallback Chain:** `moonshotai/kimi-k2` --> `google/gemini-2.5-flash`
- **Refusal Detection:** Scans response for phrases like "I can't" and "I'm not able"; falls back to next model on match
- **System Prompt Role:** "forensic intelligence analyst drafting a target assessment"
- **Directive:** "Go deep, not wide... Be blunt, specific, accurate."
- **Required Output Sections:**
  - "WHAT THEY'RE WORTH" -- assets ranked low/medium/high by monetization potential
  - "THEIR OPSEC" -- password hygiene and security posture assessment
- **Optional:** The LLM stage is skipped if no API key is present in the build config

### Configuration

Six build-time template slots covering: Telegram channel, API keys, and settings. Values are encrypted with a SHA-256 key derived from two constants stored in the same binary -- offering effectively no protection against reverse engineering.

### Exfiltration

All exfiltration goes to a Telegram channel configured at build time. No attacker-owned C2 infrastructure is used.

---

## Indicators of Compromise

### File Hashes

| Type | Hash | Note |
|------|------|------|
| SHA-256 | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | Primary sample analyzed by Talos |

### File Names

| Filename | Description |
|----------|-------------|
| `9BY0tjwOc3ut.exe` | Sample executable name |
| `yLP9m5J3i2Aw.exe` | Alternate sample executable name |
| `volta_debug.txt` | Timestamped harvest log |
| `Identity_Report.txt` | Victim profile (serialized JSON) |
| `AI_Analysis.txt` | LLM-generated victim appraisal |
| `volta_log.zip` | Stage 1 exfil archive |
| `volta_dox.zip` | Stage 2 exfil archive (identity + AI analysis) |
| `volta_doxnet.zip` | Stage 3 exfil archive (network enrichment) |

### File Paths

| Path | Description |
|------|-------------|
| `%APPDATA%\volta_debug.txt` | Harvest log with timestamps |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `openrouter[.]ai` | Domain | LLM API endpoint for victim profiling |
| `hxxps://openrouter[.]ai/api/v1/chat/completions` | URL | POST target for LLM inference |
| `rolimons[.]com` | Domain | Roblox inventory valuation (legitimate service) |

**Note:** Both `openrouter[.]ai` and `rolimons[.]com` are legitimate third-party services. Detection should focus on non-browser processes making connections to these endpoints, not blanket blocking.

### Strings of Interest

| String | Context |
|--------|---------|
| `WALLET VAULTS CRACKED` | Report section header |
| `WHAT THEY'RE WORTH` | LLM output section |
| `THEIR OPSEC` | LLM output section |
| `Go deep, not wide` | System prompt fragment |
| `forensic intelligence analyst` | System prompt role |
| `anthropic/claude-opus-4.6` | Default LLM model ID |
| `moonshotai/kimi-k2` | Fallback LLM model ID |
| `google/gemini-2.5-flash` | Fallback LLM model ID |
| `VOLTA-AUTODOXER` | Self-identifier |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | VOLTA Behavior |
|-------------|----------------|----------------|
| T1204.002 | User Execution: Malicious File | Victim executes PE binary |
| T1555.003 | Credentials from Web Browsers | Chromium/Firefox password and cookie theft |
| T1539 | Steal Web Session Cookie | Browser cookie harvesting |
| T1528 | Steal Application Access Token | Discord, Microsoft OAuth token theft |
| T1552.001 | Credentials in Files | Cloud config and SSH key harvesting |
| T1552.004 | Private Keys | SSH private key collection |
| T1555 | Credentials from Password Stores | Wi-Fi passwords via WlanGetProfileList, wallet vaults |
| T1005 | Data from Local System | Screenshots, local file collection |
| T1113 | Screen Capture | Desktop screenshot capture |
| T1114.002 | Remote Email Collection | Gmail receipt search via stolen sessions |
| T1119 | Automated Collection | Automated broad-spectrum data harvesting |
| T1560.002 | Archive Collected Data: Archive via Library | Packaging into volta_log/dox/doxnet.zip |
| T1027 | Obfuscated Files or Information | SHA-256-encrypted config slots |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion after exfiltration |
| T1567 | Exfiltration Over Web Service | Telegram channel exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Data sent to Telegram and OpenRouter |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS to OpenRouter API |

---

## Impact

- **Credential Compromise:** Broad credential theft across browsers, email, messaging, gaming, cloud, and cryptocurrency wallets
- **Financial Risk:** Crypto wallet vault cracking with inline password recovery; stolen payment card data
- **Identity Theft:** Comprehensive victim profiling including inferred home address, employer, birth year, and spending patterns
- **Privacy Violation:** AI-generated victim dossier ranks personal assets by monetization value
- **Operational Security Exposure:** LLM assesses victim's password hygiene and security posture, enabling targeted follow-on attacks

---

## Detection & Remediation

### Detection Priorities

1. **File artifacts** -- Monitor for creation of `volta_debug.txt`, `Identity_Report.txt`, `AI_Analysis.txt`, or ZIP files prefixed with `volta_` in `%APPDATA%` and temp directories
2. **Headless Chrome abuse** -- Alert on `chrome.exe` or `msedge.exe` launched with `--headless` by non-browser parent processes
3. **Anomalous AI API traffic** -- Non-browser processes making HTTPS POST requests to `openrouter[.]ai`
4. **Wi-Fi credential dumping** -- Processes calling `WlanGetProfileList` API to enumerate saved Wi-Fi profiles and extract plaintext passwords
5. **Telegram exfiltration** -- Non-browser processes making API calls to `api.telegram.org`

### Remediation

- Preserve `%APPDATA%\volta_debug.txt` for forensic analysis before cleanup
- Rotate all credentials stored in browsers, messaging apps, cloud configs, and SSH keys
- Revoke and regenerate crypto wallet seeds if any wallet files were present
- Review Telegram, Discord, and email sessions for unauthorized access
- Implement application control policies restricting `--headless` Chrome launches to approved automation tools
- Monitor for unauthorized OpenRouter API usage from enterprise networks (**Note:** blocking `openrouter[.]ai` or `api.telegram.org` is an interim measure only -- VOLTA's builder model means operators can substitute different exfiltration endpoints in new builds)

---

## Detection Rules

### Sigma Rules

#### 1. VOLTA -- Headless Chrome Launch for ABE Bypass

**File:** `/tmp/actioner/volta-proc-headless-chrome.yml`

Detects Chrome/Edge launched with `--headless` by a non-browser parent, indicating potential ABE bypass for cookie/credential theft. Caveat: legitimate browser automation tools (Puppeteer, Playwright, Selenium) may trigger this rule.

**Validation:**
- `sigma check -x attacktag`: 0 errors, 0 condition errors, 0 issues
- `sigma convert --without-pipeline -t splunk`: `Image IN ("*\\chrome.exe", "*\\msedge.exe") CommandLine="*--headless*" NOT (ParentImage IN (...))`
- `sigma convert --without-pipeline -t log_scale`: Converts successfully

```yaml
title: VOLTA Infostealer - Headless Chrome Launch for ABE Bypass
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects Chrome being launched with --headless flag by a non-browser parent,
  indicative of VOLTA ABE bypass technique.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: CTI Research Team
date: 2026-11-01
tags:
    - attack.credential_access
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
        CommandLine|contains: '--headless'
    filter_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\devenv.exe'
            - '\code.exe'
            - '\node.exe'
            - '\python.exe'
            - '\java.exe'
    condition: selection and not filter_parent
falsepositives:
    - Legitimate browser automation or testing frameworks
    - Developer tools using headless Chrome
level: medium
```

#### 2. VOLTA -- Characteristic File Artifacts

**File:** `/tmp/actioner/volta-file-artifacts.yml`

Detects creation of VOLTA-specific files including debug logs, identity reports, AI analysis output, and staged exfiltration archives. Low false-positive rate due to highly specific file names.

**Validation:**
- `sigma check -x attacktag`: 0 errors, 0 condition errors, 0 issues
- `sigma convert --without-pipeline -t splunk`: `TargetFilename="*\\volta_debug.txt" OR TargetFilename IN ("*\\Identity_Report.txt", "*\\AI_Analysis.txt") OR ...`
- `sigma convert --without-pipeline -t log_scale`: Converts successfully

```yaml
title: VOLTA Infostealer - Characteristic File Artifacts
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects creation of files characteristic of VOLTA infostealer activity
  including debug logs, report files, and exfiltration archives.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: CTI Research Team
date: 2026-11-01
tags:
    - attack.collection
    - attack.t1005
    - attack.exfiltration
    - attack.t1567
logsource:
    category: file_event
    product: windows
detection:
    selection_debug:
        TargetFilename|endswith: '\volta_debug.txt'
    selection_reports:
        TargetFilename|endswith:
            - '\Identity_Report.txt'
            - '\AI_Analysis.txt'
    selection_archives:
        TargetFilename|endswith:
            - '\volta_log.zip'
            - '\volta_dox.zip'
            - '\volta_doxnet.zip'
    condition: selection_debug or selection_reports or selection_archives
falsepositives:
    - Unlikely
level: high
```

#### 3. VOLTA -- Outbound DNS Query to OpenRouter AI API

**File:** `/tmp/actioner/volta-network-openrouter.yml`

Detects non-browser processes resolving `openrouter.ai`, which VOLTA uses for LLM-based victim profiling. Caveat: legitimate AI developer tools may trigger; tune filter for environment.

**Validation:**
- `sigma check -x attacktag`: 0 errors, 0 condition errors, 0 issues
- `sigma convert --without-pipeline -t splunk`: `QueryName="*.openrouter.ai" NOT (Image IN (...))`
- `sigma convert --without-pipeline -t log_scale`: Converts successfully

```yaml
title: VOLTA Infostealer - Outbound Connection to OpenRouter AI API
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
  Detects non-browser processes making outbound connections to OpenRouter AI API,
  which VOLTA uses for LLM-based victim profiling.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: CTI Research Team
date: 2026-11-01
tags:
    - attack.exfiltration
    - attack.t1567
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith: '.openrouter.ai'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\firefox.exe'
            - '\brave.exe'
    condition: selection and not filter_browsers
falsepositives:
    - Legitimate developer tools or AI applications using OpenRouter API
level: medium
```

#### 4. VOLTA -- Wi-Fi Credential Harvesting via netsh

**File:** `/tmp/actioner/volta-wifi-credential-dump.yml`

Detects `netsh wlan show profile` with `key=clear` which dumps Wi-Fi passwords in plaintext, matching VOLTA's Wi-Fi credential harvesting behavior. Caveat: network administrators may legitimately run this command.

**Validation:**
- `sigma check -x attacktag`: 0 errors, 0 condition errors, 0 issues
- `sigma convert --without-pipeline -t splunk`: `CommandLine="*wlan*" CommandLine="*show*" CommandLine="*profile*" CommandLine="*key=clear*"`
- `sigma convert --without-pipeline -t log_scale`: Converts successfully

```yaml
title: VOLTA Infostealer - WLAN Profile Enumeration via WlanGetProfileList
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: >
  Detects non-system processes calling netsh wlan show profiles or accessing
  WLAN profile data, indicative of VOLTA Wi-Fi credential harvesting.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: CTI Research Team
date: 2026-11-01
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
            - 'wlan'
            - 'show'
            - 'profile'
        CommandLine|contains: 'key=clear'
    condition: selection
falsepositives:
    - Network administrators performing wireless audits
level: medium
```

### YARA Rules

#### 5. VOLTA Infostealer Strings (Binary Detection)

**File:** `/tmp/actioner/volta-infostealer.yar`

Detects VOLTA infostealer PE binaries based on characteristic strings including report headers, file artifact names, LLM model identifiers, and API endpoints. Contains two rules: one for PE binary detection and one for configuration/output file detection.

**Validation:**
- `yarac volta-infostealer.yar /dev/null`: Compiles successfully (exit code 0)

```yara
rule VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA/VOLTA-AUTODOXER infostealer based on characteristic strings"
        author = "CTI Research Team"
        date = "2026-11-01"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "high"

    strings:
        $s1 = "WALLET VAULTS CRACKED" ascii wide
        $s2 = "volta_debug.txt" ascii wide
        $s3 = "Identity_Report.txt" ascii wide
        $s4 = "AI_Analysis.txt" ascii wide
        $s5 = "volta_log.zip" ascii wide
        $s6 = "volta_dox.zip" ascii wide
        $s7 = "volta_doxnet.zip" ascii wide
        $s8 = "WHAT THEY'RE WORTH" ascii wide
        $s9 = "THEIR OPSEC" ascii wide
        $s10 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $s11 = "Go deep, not wide" ascii wide
        $s12 = "forensic intelligence analyst" ascii wide

        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $model3 = "google/gemini-2.5-flash" ascii wide

        $api1 = "WlanGetProfileList" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($s*)) or
            (2 of ($model*) and 1 of ($s*)) or
            ($api1 and 2 of ($s*))
        )
}

rule VOLTA_Infostealer_Config
{
    meta:
        description = "Detects VOLTA infostealer configuration artifacts or output files"
        author = "CTI Research Team"
        date = "2026-11-01"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "high"

    strings:
        $header1 = "WHAT THEY'RE WORTH" ascii wide
        $header2 = "THEIR OPSEC" ascii wide
        $volta1 = "volta_dox" ascii wide
        $volta2 = "volta_log" ascii wide
        $volta3 = "volta_debug" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide

    condition:
        ($header1 and $header2) or
        (2 of ($volta*) and $wallet)
}
```

### Suricata Rules

#### 6. VOLTA -- OpenRouter API Chat Completions Request

**File:** `/tmp/actioner/volta-network.rules`

Detects HTTP POST requests to the OpenRouter chat completions API endpoint, which VOLTA uses for LLM inference. Second rule additionally matches the system prompt keyword "forensic intelligence analyst" in the request body.

> :warning: **uncompiled (structural check only)** -- These rules follow Suricata syntax but have not been compiled with `suricata -T`. Validate in your environment before deployment.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"VOLTA Infostealer - OpenRouter API Chat Completions Request";
  flow:established,to_server;
  http.method; content:"POST";
  http.host; content:"openrouter.ai";
  http.uri; content:"/api/v1/chat/completions";
  classtype:trojan-activity;
  sid:1000001; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"VOLTA Infostealer - LLM Prompt Forensic Analyst Keyword";
  flow:established,to_server;
  http.method; content:"POST";
  http.request_body; content:"forensic intelligence analyst";
  http.host; content:"openrouter.ai";
  classtype:trojan-activity;
  sid:1000002; rev:1;
)
```

---

## Sources

- [Cisco Talos - Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) (PRIMARY)
- [NetManageIT - VOLTA Infostealer Uses AI to Rank Stolen Victims](https://blog.netmanageit.com/volta-infostealer-ai-victim-prioritization/)
- [Startup Fortune - Malware called Volta-Autodoxer uses AI to build a dossier on its victims](https://startupfortune.com/malware-called-volta-autodoxer-uses-ai-to-build-a-dossier-on-its-victims/)
- [Mallory.ai - VOLTA Infostealer Uses AI to Profile Victims and Prioritize Stolen Assets](https://mallory.ai/stories/01a191e4-d855-7034-acc9-955e625a7810)
- [SuperPowerDaily - Cisco Talos finds malware that uses AI to rank victims' stolen assets](https://superpowerdaily.com/posts/cisco-talos-finds-malware-that-uses-ai-to-rank-victims-stolen-assets)
- [Artiverse - VOLTA Infostealer Turns Stolen Data Into AI-Ranked Victim Dossiers](https://www.artiverse.ca/volta-infostealer-turns-stolen-data-into-ai-ranked-victim-dossiers/)
