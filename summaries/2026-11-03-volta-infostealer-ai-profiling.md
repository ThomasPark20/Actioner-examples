# Technical Analysis Report: VOLTA Infostealer (VOLTA-AUTODOXER) (2026-11-03)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-03
Version: DRAFT 1.0

## Executive Summary

VOLTA (also called VOLTA-AUTODOXER) is a novel Windows infostealer that introduces an unprecedented AI-driven victim triage mechanism. After harvesting a comprehensive set of credentials, session tokens, crypto wallets, and personal data, the malware serializes the stolen bundle and submits it to a large language model (LLM) through the OpenRouter API for automated profiling. The LLM is instructed to act as a "forensic intelligence analyst," rank each stolen asset by monetization potential (low/medium/high), and assess the victim's security posture and password hygiene. The default model is Anthropic Claude Opus 4.6, with fallback to Moonshot AI Kimi K2 and Google Gemini 2.5 Flash when refusals are detected. Exfiltration occurs over Telegram in three staged archives. The malware uses no attacker-owned infrastructure, relying entirely on third-party services, making network-based blocking more difficult. A single PE64 sample (SHA256: `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279`) has been observed, with a PE timestamp of 2026-08-17 and first seen on 2026-10-11. The builder-style template with six configurable slots suggests this may be sold as a kit.

## Background: AI-Augmented Infostealers

VOLTA represents an evolution in the infostealer landscape where threat actors leverage LLMs not for generating malware code, but for post-collection intelligence analysis. Traditional infostealers dump credentials and logs to operators who manually sift through them; VOLTA automates the triage step, delivering a ranked victim assessment that tells the operator exactly which accounts are most valuable and how easy the victim is to exploit further. This commoditizes victim prioritization, lowering the skill threshold for downstream fraud. The malware was discovered by Cisco Talos as part of its CAIRN research effort, alongside a related implant called CLOSEDQUORUM.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-17 | PE compilation timestamp of the observed VOLTA sample |
| 2026-10-11 12:46 | First sample observed (VirusTotal first seen) |
| 2026-10-31 | Cisco Talos publishes technical analysis |
| 2026-11-01 to 2026-11-02 | Secondary media coverage (The Hacker News, SecurityAffairs, Help Net Security) |

## Root Cause: Initial Access Vector

The Cisco Talos report does not describe a specific initial access vector for VOLTA. Given the builder-style template with configurable fields, distribution likely varies by operator. Common infostealer delivery mechanisms include trojanized software downloads, phishing with malicious attachments, drive-by downloads, and cracked-software lures. The malware is a standalone PE64 executable (filenames: `9BY0tjwOc3ut.exe`, `yLP9m5J3i2Aw.exe`), suggesting randomized naming consistent with automated delivery.

## Technical Analysis of the Malicious Payload

### 1. Collection Stage (Credential and Data Harvesting)

VOLTA performs broad credential and data harvesting across multiple application categories:

- **Browsers:** Chromium-based browser passwords, cookies, saved payment cards, and autofill data. Includes an App-Bound Encryption bypass to extract tokens protected by Chrome's newer credential protection mechanism. Firefox and Thunderbird data are also targeted.
- **Email clients:** Outlook data and Gmail access via stolen session tokens, with targeted searches for purchase receipts from Amazon, DoorDash, Uber Eats, Grubhub, Walmart, and PayPal to corroborate home address.
- **Messaging:** Discord, Telegram, and Slack session tokens and workspace data.
- **Gaming:** Steam, Battle.net, and Roblox sessions. Roblox inventory is valued via Rolimons.com.
- **Crypto wallets:** Wallet seed phrases copied, plus an embedded cracker that attempts to break wallet passwords on-device.
- **Cloud and developer credentials:** SSH keys, cloud-provider credentials, Microsoft OAuth tokens.
- **System data:** Wi-Fi passwords (via `WlanGetProfileList`), screenshots, device location, signs of iPhone backups.
- **Delivery platform enrichment:** Uses stolen sessions to pull order histories from DoorDash and Uber Eats.

### 2. AI Profiling Stage (LLM-Driven Victim Assessment)

The defining feature of VOLTA is its AI profiling pipeline:

- **Endpoint:** `POST` to `openrouter.ai/api/v1/chat/completions` using hand-built JSON (no SDK).
- **Model chain:** Default `anthropic/claude-opus-4.6`, fallback `moonshotai/kimi-k2`, then `google/gemini-2.5-flash`.
- **Refusal detection:** Scans LLM responses for phrases like "I can't" and "I'm not able" to trigger fallback.
- **Temperature:** 0.2 (deterministic, consistent output).
- **System prompt (~240 words):** Casts the model as a "forensic intelligence analyst" drafting a target assessment. Instructs: "Go deep, not wide... Be blunt, specific, accurate."
- **Required output sections:** "WALLET VAULTS CRACKED" (cracked wallet results), "WHAT THEY'RE WORTH" (valuables ranked low/medium/high monetization tiers), and "THEIR OPSEC" (security posture assessment, password hygiene).
- **API key source:** Embedded in the build config. If absent, the malware searches the victim's environment variables for `OPENAI_API_KEY` and uses it.
- **Offline fallback:** If no API key is available at all, the malware skips the AI stage and proceeds with raw data exfiltration.

### 3. Exfiltration (Staged Over Telegram)

Exfiltration occurs in three stages via a Telegram channel configured at build time:

1. **`volta_log.zip`** (immediate): Browser credentials, cookies, cards, wallets, Discord/Steam/Roblox tokens, Wi-Fi passwords, and screenshots.
2. **`volta_dox.zip`** (after AI call): The `Identity_Report.txt` victim profile and `AI_Analysis.txt` LLM response.
3. **`volta_doxnet.zip`** (after enrichment): Gmail receipts and delivery-platform order histories, sent only if network enrichment yields data.

### 4. Build and Configuration

VOLTA uses a template with six build-time configurable slots covering:
- Telegram exfiltration channel
- API keys (OpenRouter/LLM)
- Other operational settings

The config is encrypted, but the key is the SHA-256 of two constants embedded in the binary -- effectively recoverable by anyone who reverse engineers the sample. This builder model suggests the author sells a kit or compiles custom binaries per customer.

### 5. Anti-Forensics / Evasion Techniques

- **Self-deletion:** The malware deletes itself after execution.
- **No attacker-owned infrastructure:** All endpoints are legitimate third-party services (OpenRouter, Telegram, Rolimons), complicating network-level blocking.
- **Debug log:** Writes `%APPDATA%\volta_debug.txt` with timestamped collection status and AI call results. While useful for the operator, this is a high-fidelity forensic artifact for defenders.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Windows | 9BY0tjwOc3ut.exe / yLP9m5J3i2Aw.exe | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | VOLTA PE64 binary |
| Windows | %APPDATA%\volta_debug.txt | -- | Timestamped harvest log (forensic artifact) |
| Windows | Identity_Report.txt | -- | Locally assembled victim profile (JSON) |
| Windows | AI_Analysis.txt | -- | LLM profiling response |
| Windows | volta_log.zip | -- | Stage 1 exfil archive (credentials) |
| Windows | volta_dox.zip | -- | Stage 2 exfil archive (AI analysis + profile) |
| Windows | volta_doxnet.zip | -- | Stage 3 exfil archive (network enrichment) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | openrouter[.]ai | LLM API endpoint for victim profiling |
| URL Pattern | hxxps://openrouter[.]ai/api/v1/chat/completions | LLM API POST endpoint |
| Domain | rolimons[.]com | Roblox inventory valuation lookup |
| Service | Telegram (channel configured per build) | Exfiltration channel |

### Behavioral

- Writes `volta_debug.txt` to `%APPDATA%` with timestamped harvest status
- Creates `Identity_Report.txt` and `AI_Analysis.txt` in working directory
- Creates ZIP archives with `volta_` prefix for staged exfiltration
- Calls `WlanGetProfileList` API to dump saved Wi-Fi passwords
- Launches Chrome with `--headless` flag from unexpected parent processes (App-Bound Encryption bypass)
- Searches Gmail via stolen session for receipt keywords from Amazon, DoorDash, Uber Eats, Grubhub, Walmart, PayPal
- HTTP POST to OpenRouter API with JSON body containing model identifier and victim data bundle
- Checks LLM response text for refusal phrases ("I can't", "I'm not able") and chains to alternate models

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1555.003 | Credentials from Web Browsers | Chromium password, cookie, and payment card extraction with App-Bound Encryption bypass |
| T1539 | Steal Web Session Cookie | Browser cookies, Discord/Telegram/Steam/Roblox session tokens |
| T1528 | Steal Application Access Token | Microsoft OAuth tokens, Slack workspace tokens, cloud API keys |
| T1552.001 | Unsecured Credentials: Credentials In Files | Wi-Fi passwords via WlanGetProfileList, SSH keys, cloud credentials |
| T1552.004 | Unsecured Credentials: Private Keys | SSH key theft |
| T1005 | Data from Local System | Crypto wallets, screenshots, device data, iPhone backup artifacts |
| T1119 | Automated Collection | Systematic harvesting across all targeted application categories |
| T1560 | Archive Collected Data | ZIP packaging into volta_log.zip, volta_dox.zip, volta_doxnet.zip |
| T1567 | Exfiltration Over Web Service | Data sent via Telegram channel and OpenRouter API |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion after execution |

## Impact Assessment

VOLTA's AI-driven triage mechanism significantly increases the efficiency of credential monetization. Rather than forcing operators to manually review large credential dumps, each victim receives an automated assessment of their financial value and security weaknesses. This could enable faster account takeover for high-value targets, reduce time-to-fraud for cryptocurrency theft (with the embedded wallet cracker), and allow less sophisticated operators to conduct effective attacks. The builder model suggests multiple independent operators may deploy VOLTA, potentially expanding its reach. The use of legitimate third-party infrastructure (OpenRouter, Telegram) and self-deletion after execution complicates traditional network blocking and host forensics.

## Detection & Remediation

### Immediate Detection

- **File artifact search:** Look for `volta_debug.txt` in `%APPDATA%` directories across all endpoints. Its presence indicates active or recent VOLTA compromise.
- **Network monitoring:** Alert on outbound HTTPS POST requests to `openrouter.ai/api/v1/chat/completions`, particularly from non-development endpoints.
- **Process monitoring:** Alert on Chrome launched with `--headless` from unexpected parent processes.
- **Archive detection:** Monitor for creation of files named `volta_log.zip`, `volta_dox.zip`, or `volta_doxnet.zip`.

### Remediation

1. **Contain:** Isolate the compromised system immediately.
2. **Preserve evidence:** Copy `%APPDATA%\volta_debug.txt` before remediation -- it documents exactly what was stolen.
3. **Credential rotation:** Rotate ALL credentials from targeted browsers, email clients, messaging apps, and cloud services.
4. **Token revocation:** Revoke Discord, Telegram, Steam, Roblox, Slack, and Microsoft OAuth tokens.
5. **Crypto wallet migration:** Move any wallet whose seed phrase was stored in plaintext to a new wallet generated on an air-gapped device.
6. **Wi-Fi password rotation:** Change all Wi-Fi passwords that were saved on the compromised system.
7. **Monitor for fraud:** Watch for unauthorized access to delivery service accounts, email, and financial services.

### Long-Term Hardening

- Deploy application control policies restricting which processes can launch Chrome with `--headless`.
- Store credentials in hardware-backed keystores (TPM, hardware security keys) rather than browser password managers.
- Enable phishing-resistant MFA on all high-value accounts.
- Monitor for environment variable enumeration of `OPENAI_API_KEY` and similar API key patterns.
- Consider DNS-level blocking of `openrouter.ai` on non-development endpoints.

## Detection Rules

These detections target VOLTA infostealer file artifacts, network communication with the OpenRouter LLM API, and binary-level strings. PoC/advisory-specific altitude (strict); Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify each rule in your pipeline.

### Sigma: VOLTA Infostealer File Artifacts on Disk

Detects VOLTA infostealer file artifacts (debug log, victim profile, AI analysis, and staged exfiltration archives) written to disk.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0; splunk_windows pipeline convert exit 0 (schema-mapped). File names are unique to VOLTA; no known benign overlap. -->
```yaml
title: VOLTA Infostealer File Artifacts on Disk
id: 8c3e1d7a-4f2b-49e6-a5c8-0d1b3e6f9a72
status: experimental
description: >
    Detects VOLTA infostealer file artifacts written to disk, including its debug log,
    victim profile report, AI analysis output, and characteristic exfiltration archives.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/03
tags:
    - attack.t1005
    - attack.t1119
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
    - Unlikely - file names are highly specific to the VOLTA malware family
level: high
```

### Sigma: VOLTA Infostealer Debug Log in AppData

Detects creation of the VOLTA debug log at its known %APPDATA% path, the highest-fidelity single-file indicator of compromise.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Path + filename combination is unique to VOLTA. -->
```yaml
title: VOLTA Infostealer Debug Log in AppData
id: 5d9c2e8a-1b3f-47a6-d0e4-9f6a8c2d5b71
status: experimental
description: >
    Detects creation of the VOLTA infostealer debug log at its known path in the user
    AppData Roaming directory, a high-fidelity indicator of active compromise.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/03
tags:
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - '\AppData\Roaming\'
            - 'volta_debug.txt'
    condition: selection
falsepositives:
    - Unlikely - highly specific file name and path combination
level: critical
```

### Sigma: VOLTA Infostealer OpenRouter LLM API Call

Detects proxy/web log traffic to the OpenRouter LLM chat completions endpoint, used by VOLTA for AI-driven victim profiling. Scope to non-development endpoints to reduce false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Legitimate developer use of OpenRouter is a known FP source; scoping guidance provided. -->
```yaml
title: VOLTA Infostealer OpenRouter LLM API Call
id: 2a4f8e6c-91d3-4b7a-c5e0-7f2d1a3b8c94
status: experimental
description: >
    Detects network connections to the OpenRouter API endpoint used by VOLTA infostealer
    to submit stolen victim data for AI-driven profiling and prioritization.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/03
tags:
    - attack.t1567
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/api/v1/chat/completions'
        r-dns|contains: 'openrouter.ai'
    condition: selection
falsepositives:
    - Legitimate use of the OpenRouter LLM API service by developers or applications
level: medium
```

### Snort: VOLTA Infostealer OpenRouter LLM API POST

Detects HTTP POST to the OpenRouter chat completions endpoint carrying the VOLTA default model identifier (`anthropic/claude-opus-4.6`) in the request body.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: medium
<!-- audit: snort binary not available in this environment. Structural check: correct http service, sticky buffers (http_method, http_uri, http_header, http_client_body), flow, sid 2100001, all semicolons present. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer OpenRouter LLM API POST"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/api/v1/chat/completions", fast_pattern; http_header; content:"openrouter.ai"; http_client_body; content:"anthropic/claude-opus-4.6"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created 2026-11-03; sid:2100001; rev:1;)
```

### Snort: VOLTA Infostealer LLM Victim Profiling Request

Detects HTTP POST to any chat completions API carrying the VOLTA report header string "WALLET VAULTS CRACKED" in the request body.
**Status:** compile ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: snort binary not available. Structural check: correct http service, sticky buffers (http_method, http_uri, http_client_body), flow, sid 2100002, all semicolons present. "WALLET VAULTS CRACKED" is highly distinctive and specific to VOLTA's LLM prompt template. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer LLM Victim Profiling Request"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/api/v1/chat/completions"; http_client_body; content:"WALLET VAULTS CRACKED", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created 2026-11-03; sid:2100002; rev:1;)
```

### Suricata: VOLTA Infostealer OpenRouter LLM API POST

Detects HTTP POST to `openrouter.ai` at the chat completions endpoint with the VOLTA default model identifier in the request body.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0. Uses dot-notation sticky buffers (http.method, http.host, http.uri, http.request_body). Legitimate developer OpenRouter use is a known FP; model identifier in body adds specificity. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer OpenRouter LLM API POST"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; http.uri; content:"/api/v1/chat/completions"; fast_pattern; http.request_body; content:"anthropic/claude-opus-4.6"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created_at 2026-11-03; sid:2200001; rev:1;)
```

### Suricata: VOLTA Infostealer LLM Victim Profiling Request

Detects HTTP POST to any chat completions endpoint carrying the distinctive VOLTA prompt string "WALLET VAULTS CRACKED" in the request body.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. "WALLET VAULTS CRACKED" is a hardcoded report header unique to VOLTA's LLM system prompt. No known benign use of this string in HTTP request bodies. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer LLM Victim Profiling Request"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/chat/completions"; http.request_body; content:"WALLET VAULTS CRACKED"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created_at 2026-11-03; sid:2200002; rev:1;)
```

### YARA: VOLTA Infostealer Binary Strings

Detects the VOLTA infostealer PE binary via characteristic report headers, LLM prompt fragments, file artifacts, API endpoint, and model identifiers.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. yara positive test: fired on constructed sample carrying source-published strings (WALLET VAULTS CRACKED, WHAT THEY'RE WORTH, THEIR OPSEC, volta_debug.txt, Identity_Report.txt, AI_Analysis.txt, openrouter.ai endpoint). Negative test: quiet on benign file. Condition requires PE header + filesize < 50MB + threshold combination of distinctive string groups. Strings sourced from Cisco Talos blog. -->
```yara
rule Malware_VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer (VOLTA-AUTODOXER) via characteristic strings found in the PE binary"
        author = "Actioner"
        date = "2026-11-03"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $report1 = "WALLET VAULTS CRACKED" ascii wide
        $report2 = "WHAT THEY'RE WORTH" ascii wide
        $report3 = "THEIR OPSEC" ascii wide
        $prompt1 = "Go deep, not wide" ascii wide
        $prompt2 = "Be blunt, specific, accurate" ascii wide
        $file1 = "volta_debug.txt" ascii wide
        $file2 = "Identity_Report.txt" ascii wide
        $file3 = "AI_Analysis.txt" ascii wide
        $file4 = "volta_dox.zip" ascii wide
        $file5 = "volta_log.zip" ascii wide
        $file6 = "volta_doxnet.zip" ascii wide
        $api1 = "openrouter.ai/api/v1/chat/completions" ascii wide
        $refusal1 = "I can't" ascii wide
        $refusal2 = "I'm not able" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii wide
        $model2 = "moonshotai/kimi-k2" ascii wide
        $model3 = "google/gemini-2.5-flash" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            3 of ($report*) or
            (2 of ($file*) and 1 of ($api*)) or
            (1 of ($prompt*) and 1 of ($model*)) or
            (2 of ($model*) and 1 of ($refusal*))
        )
}
```

## Lessons Learned

1. **LLMs as post-exploitation triage tools:** VOLTA demonstrates that threat actors are now integrating LLMs into the operational pipeline not for code generation, but for automated intelligence analysis of stolen data. This reduces the human effort required to monetize credential dumps and lowers the bar for less sophisticated operators.

2. **Third-party infrastructure complicates blocking:** VOLTA uses no attacker-owned C2 infrastructure. All communication flows through legitimate services (OpenRouter, Telegram, Rolimons). Network defenders cannot simply blocklist an IP or domain without potentially disrupting legitimate business tools. Detection must shift from infrastructure IOCs to behavioral patterns and file artifacts.

3. **Defensive value of malware debug logs:** The `volta_debug.txt` file is both the attacker's operational log and the defender's forensic goldmine. It records exactly what was harvested and whether the AI call succeeded. Incident responders should prioritize preserving this file during triage, as it provides a precise scope of compromise without requiring full reverse engineering.

4. **API key hygiene matters:** VOLTA's fallback to scanning environment variables for `OPENAI_API_KEY` highlights that API keys stored in plaintext on workstations are a target. Organizations should enforce secrets management practices and avoid storing API keys in environment variables on end-user machines.

## Sources

- [Cisco Talos Blog: Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) -- primary technical analysis, source of all IOCs and TTP details
- [The Hacker News: New VOLTA Infostealer Uses Claude, Gemini, and Kimi AI to Rank Victims by Financial Value](https://thehackernews.com/2026/11/new-volta-infostealer-uses-claude.html) -- secondary coverage with additional context on the 240-word system prompt and NIK C2 relationship
- [SecurityAffairs: VOLTA, the infostealer that asks an AI which victims are worth the effort](https://securityaffairs.com/202281/malware/volta-the-infostealer-that-asks-an-ai-which-victims-are-worth-the-effort.html) -- secondary coverage with forensic preservation recommendations and CLOSEDQUORUM linkage
- [Help Net Security: AI-powered infostealer picks out the most profitable parts of your stolen data](https://www.helpnetsecurity.com/2026/11/02/ai-powered-infostealer-volta-victim-profiling/) -- secondary coverage confirming builder model and API key theft behavior
- [Security Boulevard: Volta Infostealer Uses AI Model to Assess the Worth of Victims](https://securityboulevard.com/2026/11/volta-infostealer-uses-ai-model-to-assess-the-worth-of-victims/) -- secondary coverage

---
*Report generated by Actioner*
