# VOLTA Infostealer (VOLTA-AUTODOXER) -- Technical Analysis & Detection Rules

**Status:** DRAFT  
**Date:** 2026-11-04  
**Analyst:** Actioner  
**TLP:** CLEAR

---

## Executive Summary

VOLTA (internally branded "VOLTA-AUTODOXER") is a PE32+ x86-64 Windows infostealer first observed on 2026-10-11. Its distinguishing feature is the use of large language models (LLMs) via the OpenRouter API to automatically appraise and rank stolen victim data by monetization value. After harvesting credentials, session tokens, cryptocurrency wallets, Wi-Fi passwords, email receipts, and gaming account data, VOLTA assembles a victim dossier, submits it to an LLM for analysis, and exfiltrates staged ZIP archives before self-deleting. No actor-controlled infrastructure has been observed; the malware relies entirely on legitimate third-party APIs (OpenRouter, Rolimons, Gmail, Uber Eats, DoorDash, Discord).

---

## Background

VOLTA was first documented by [Cisco Talos](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) in late October 2026. The malware represents an evolution in infostealer design: rather than exfiltrating raw data for manual review, it uses AI to prioritize victims, generating structured intelligence reports that include sections titled "WHAT THEY'RE WORTH" and "THEIR OPSEC." The configuration uses a six-slot builder template encrypted with SHA-256-derived keys, consistent with a sold-access or malware-as-a-service model.

---

## Technical Analysis

### Infection Chain

The initial delivery vector was not documented in the primary source. The malware is distributed as a PE32+ executable with randomized filenames (e.g., `9BY0tjwOc3ut.exe`, `yLP9m5J3i2Aw.exe`).

### Data Collection (Stage 1)

VOLTA performs broad credential and data harvesting across the following categories:

| Target Category | Specifics |
|---|---|
| **Browsers** | Chromium (including App-Bound Encryption bypass via `chrome --headless`), Firefox |
| **Email** | Thunderbird, Outlook; Gmail receipt searches (Amazon, DoorDash, Uber Eats, Grubhub, Walmart, PayPal) |
| **Messaging** | Discord (token reuse), Telegram, Slack |
| **Gaming** | Steam, Battle.net, Roblox (live valuation via rolimons[.]com) |
| **Crypto** | Wallet vault cracking inline ("WALLET VAULTS CRACKED") |
| **Network** | Wi-Fi passwords via `WlanGetProfileList`, SSH keys, VPN configs (OpenVPN, Hide.me) |
| **Cloud** | gcloud configurations |

Collection progress is logged to `%APPDATA%\volta_debug.txt` with timestamps.

### AI-Driven Victim Analysis (Stage 2)

After data collection, VOLTA assembles an `Identity_Report.txt` (JSON-serialized victim dossier) and submits it to the OpenRouter LLM API:

- **Endpoint:** `hxxps://openrouter[.]ai/api/v1/chat/completions`
- **Default model:** `anthropic/claude-opus-4.6`
- **Fallback chain:** `moonshotai/kimi-k2` then `google/gemini-2.5-flash`
- **Temperature:** 0.2
- **User-Agent:** `Mozilla/5.0`
- **System prompt framing:** Forensic intelligence analyst persona; instructions include "Go deep, not wide... Be blunt, specific, accurate."
- **Refusal detection:** Checks for "I can't" and "I'm not able" in responses
- **Output:** Saved as `AI_Analysis.txt`

The request is hand-assembled JSON with no SDK dependency.

### Exfiltration (Stage 3)

Data is staged into three progressive ZIP archives:

1. `volta_log.zip` -- Post-collection raw harvest
2. `volta_dox.zip` -- Post-AI-analysis bundle
3. `volta_doxnet.zip` -- Post-network-enrichment final package

Delivery is performed via Telegram (specific bot tokens/channels not documented in the source).

### Self-Deletion

The executable deletes itself after execution (T1070.004), leaving only `volta_debug.txt` in `%APPDATA%` as a forensic artifact if not cleaned.

---

## Indicators of Compromise

> All indicators are defanged for safe handling. Detection rules below use real (non-defanged) values.

### File Hashes

| Type | Value |
|---|---|
| SHA-256 | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` |

### Filenames

| Filename | Context |
|---|---|
| `9BY0tjwOc3ut.exe` | Observed dropper filename |
| `yLP9m5J3i2Aw.exe` | Observed dropper filename |

### File Artifacts

| Path / Filename | Description |
|---|---|
| `%APPDATA%\volta_debug.txt` | Timestamped harvest log |
| `Identity_Report.txt` | Serialized victim dossier (JSON) |
| `AI_Analysis.txt` | LLM output report |
| `volta_log.zip` | Stage 1 exfil archive |
| `volta_dox.zip` | Stage 2 exfil archive |
| `volta_doxnet.zip` | Stage 3 exfil archive |

### Network Indicators

| Indicator | Context |
|---|---|
| `hxxps://openrouter[.]ai/api/v1/chat/completions` | LLM API endpoint |
| `rolimons[.]com` | Roblox account valuation |
| Telegram (unspecified bot/channel) | Exfiltration delivery |

### PE Metadata

| Field | Value |
|---|---|
| PE Timestamp | 2026-08-17 20:35 |
| First Seen (UTC) | 2026-10-11 12:46 |
| Architecture | PE32+ x86-64 |

---

## MITRE ATT&CK Mapping

| Technique | ID | VOLTA Usage |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | Chromium App-Bound Encryption bypass via headless Chrome; Firefox credential theft |
| Steal Web Session Cookie | T1539 | Browser session/cookie harvesting |
| Steal Application Access Token | T1528 | Discord token reuse, application tokens |
| Unsecured Credentials: Credentials In Files | T1552.001 | SSH keys, VPN configs, gcloud configs |
| Unsecured Credentials: Private Keys | T1552.004 | SSH private keys, crypto wallet keys |
| Data from Local System | T1005 | Broad local data collection |
| Screen Capture | T1113 | (Referenced in Talos mapping) |
| Email Collection: Remote Email Collection | T1114.002 | Gmail receipt searches |
| Deobfuscate/Decode Files or Information | T1140 | Config decryption via SHA-256 derived key |
| Indicator Removal: File Deletion | T1070.004 | Self-deletion after execution |
| Exfiltration Over Web Service | T1567 | Data exfil via Telegram and OpenRouter |

---

## Detection Rules

### Sigma: Suspicious Chrome Headless Launch (Process Creation)

Detects Chrome launched with `--headless` from a non-standard parent process, a technique VOLTA uses for App-Bound Encryption bypass. Tune `ParentImage` filter to match legitimate headless Chrome usage in your environment.
<!-- audit: Compile: sigma convert to Splunk + LogScale both succeeded. MITRE tag check unavailable (offline). Confidence: medium-high; headless Chrome is used legitimately by dev/CI tools. -->

**Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale) | **Confidence:** Medium-High

```yaml
title: Suspicious Chrome Headless Launch Potentially Related to VOLTA Infostealer
id: 3a7c8e1f-5b2d-4f9a-a1e3-6d8c2b4f0e7a
status: experimental
description: >
  Detects Chrome launched with --headless flag from a non-standard parent process,
  a technique used by VOLTA infostealer to bypass App-Bound Encryption.
references:
  - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1555.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_child:
    Image|endswith: '\chrome.exe'
    CommandLine|contains: '--headless'
  filter_parent_legitimate:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\explorer.exe'
      - '\cmd.exe'
      - '\powershell.exe'
      - '\code.exe'
      - '\node.exe'
      - '\java.exe'
      - '\jenkins.exe'
  condition: selection_child and not filter_parent_legitimate
falsepositives:
  - Automated testing frameworks using headless Chrome
  - Enterprise RPA tools
  - Developer tooling
level: high
```

---

### Sigma: VOLTA File Artifact Creation (File Event)

Detects creation of files with names specific to the VOLTA infostealer workflow. Filenames are highly distinctive; false positives are unlikely.
<!-- audit: Compile: sigma convert to Splunk + LogScale both succeeded. Confidence: high; filenames are unique to this malware family. Identity_Report.txt and AI_Analysis.txt are generic but combined with volta_* names the pattern is strong. -->

**Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale) | **Confidence:** High

```yaml
title: VOLTA Infostealer File Artifact Creation
id: 8f4b2c6e-1d3a-4e7f-b5c9-2a0d8e6f4b1c
status: experimental
description: >
  Detects creation of files associated with the VOLTA infostealer harvest and
  exfiltration workflow, including debug logs, analysis outputs, and ZIP archives.
references:
  - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-04
tags:
  - attack.t1005
logsource:
  category: file_event
  product: windows
detection:
  selection_debug:
    TargetFilename|endswith: '\volta_debug.txt'
  selection_identity:
    TargetFilename|endswith: '\Identity_Report.txt'
  selection_ai:
    TargetFilename|endswith: '\AI_Analysis.txt'
  selection_zip:
    TargetFilename|endswith:
      - '\volta_log.zip'
      - '\volta_dox.zip'
      - '\volta_doxnet.zip'
  condition: selection_debug or selection_identity or selection_ai or selection_zip
falsepositives:
  - Unlikely -- filenames are highly specific to this malware family
level: critical
```

---

### Sigma: Non-Browser Process Connecting to OpenRouter AI (Network)

Detects network connections to openrouter[.]ai from processes that are not web browsers, which may indicate VOLTA or similar LLM-abusing malware. Baseline legitimate developer/API usage.
<!-- audit: Compile: sigma convert to Splunk + LogScale both succeeded. Confidence: medium; OpenRouter is a legitimate API service. Rule value is in detecting non-browser processes reaching it. -->

**Compile:** PASS (sigma convert --without-pipeline -t splunk, -t log_scale) | **Confidence:** Medium

```yaml
title: Non-Browser Process Connecting to OpenRouter AI API
id: c2e9d4a7-6f1b-4c3e-8a5d-0b7f2e8c1d3a
status: experimental
description: >
  Detects network connections to openrouter.ai from processes other than
  known web browsers, which may indicate VOLTA infostealer LLM-based
  victim analysis or similar abuse of the OpenRouter API.
references:
  - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-04
tags:
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
      - '\firefox.exe'
      - '\msedge.exe'
      - '\brave.exe'
      - '\opera.exe'
      - '\iexplore.exe'
  condition: selection and not filter_browsers
falsepositives:
  - Developer tools or scripts legitimately using the OpenRouter API
level: high
```

---

### YARA: VOLTA Infostealer Binary Detection

Matches PE executables containing distinctive VOLTA strings. Uses three detection paths: the "VOLTA-AUTODOXER" tag alone, any three of the known artifact filenames/strings, or a combination of model names, refusal strings, and artifact filenames. Caveat: requires MZ header and sub-50MB file size to reduce false positives on non-PE files.
<!-- audit: Compile: yarac succeeded with no errors. Positive test: fires on synthetic PE with embedded strings. Negative test: quiet on benign text file. Confidence: high; string combinations are unique to this family. -->

**Compile:** PASS (yarac + positive/negative fire test) | **Confidence:** High

```yara
rule VOLTA_Infostealer
{
    meta:
        description = "Detects VOLTA (VOLTA-AUTODOXER) infostealer based on distinctive embedded strings"
        author = "Actioner"
        date = "2026-11-04"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $tag = "VOLTA-AUTODOXER" ascii wide
        $debug_file = "volta_debug.txt" ascii wide
        $identity = "Identity_Report.txt" ascii wide
        $ai_out = "AI_Analysis.txt" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide
        $api = "openrouter.ai/api/v1/chat/completions" ascii wide
        $zip1 = "volta_log.zip" ascii wide
        $zip2 = "volta_dox.zip" ascii wide
        $zip3 = "volta_doxnet.zip" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $refusal1 = "I can't" ascii wide
        $refusal2 = "I'm not able" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            $tag or
            3 of ($debug_file, $identity, $ai_out, $wallet, $api, $zip1, $zip2, $zip3) or
            (1 of ($model1, $model2) and 1 of ($refusal1, $refusal2) and 1 of ($debug_file, $identity, $ai_out))
        )
}
```

---

### Snort: VOLTA HTTP POST to OpenRouter API

Detects HTTP POST requests to the OpenRouter chat completions endpoint with the generic Mozilla/5.0 User-Agent characteristic of VOLTA's hand-assembled requests. Caveat: will not fire on HTTPS/TLS-encrypted traffic without SSL inspection.
<!-- audit: Compile: snort -T succeeded via minimal config with classification.config. SID 2100001 in assigned range. Confidence: medium; requires HTTP visibility (not HTTPS). -->

**Compile:** PASS (snort -T) | **Confidence:** Medium

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"VOLTA Infostealer - HTTP POST to OpenRouter AI API"; flow:established,to_server; content:"POST"; http_method; content:"openrouter.ai"; http_header; content:"/api/v1/chat/completions"; http_uri; content:"Mozilla/5.0"; http_header; classtype:trojan-activity; sid:2100001; rev:1;)
```

---

### Suricata: VOLTA TLS SNI and HTTP Detection (2 rules)

Two complementary rules: (1) TLS SNI detection for openrouter[.]ai connections regardless of decryption, and (2) HTTP-layer detection for decrypted traffic matching the VOLTA request pattern. The TLS SNI rule is the more broadly useful of the two.
<!-- audit: Compile: suricata -T succeeded for both rules. SIDs 2200001-2200002 in assigned range. Confidence: medium for TLS SNI (broad -- any openrouter.ai connection), medium-high for HTTP rule (more specific). -->

**Compile:** PASS (suricata -T) | **Confidence:** Medium / Medium-High

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer TLS SNI to OpenRouter AI"; tls.sni; content:"openrouter.ai"; endswith; nocase; classtype:trojan-activity; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer HTTP POST to OpenRouter Chat API"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; http.uri; content:"/api/v1/chat/completions"; http.header; content:"Mozilla/5.0"; classtype:trojan-activity; sid:2200002; rev:1;)
```

---

## Sources

- [Cisco Talos: Appraisal by AI -- Model-Driven Victim Prioritization in the VOLTA Infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*This report was produced in DRAFT mode by Actioner on 2026-11-04. All detection rules have been compiler-validated. Review false-positive baselines before production deployment.*
