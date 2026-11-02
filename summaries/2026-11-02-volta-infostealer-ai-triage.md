# Technical Analysis Report: VOLTA Infostealer with AI-Driven Victim Prioritization (2026-11-02)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-02
Version: 1.0

## Executive Summary

VOLTA is a Windows infostealer first observed on 2026-10-11 that harvests credentials, cryptocurrency wallets, session tokens, and Wi-Fi profiles from compromised hosts, then submits the victim profile to the OpenRouter LLM API for AI-driven triage and prioritization. The malware sends stolen data to large language models (Claude, Kimi K2, Gemini Flash) with a system prompt that frames the LLM as a "forensic intelligence analyst" and requests a target assessment including sections titled "WHAT THEY'RE WORTH" and "THEIR OPSEC." The AI output guides the operator's decision on which victims to exploit further through staged enrichment (Gmail receipts, Uber Eats/DoorDash orders, Discord profiles). VOLTA uses Chrome's `--headless` flag to bypass App-Bound Encryption for cookie theft, calls `WlanGetProfileList` for Wi-Fi harvesting, and self-deletes after execution. The stolen data is exfiltrated in three staged ZIP archives (`volta_log.zip`, `volta_dox.zip`, `volta_doxnet.zip`).

## Background: OpenRouter LLM API Abuse

OpenRouter is a legitimate LLM routing API that provides access to multiple AI models (Anthropic Claude, Google Gemini, Moonshot Kimi) through a single endpoint. VOLTA abuses this service as an automated triage engine: rather than maintaining operator-side infrastructure to evaluate victims, the malware outsources the analysis to commercial LLMs. This represents a novel use of AI APIs in commodity malware — shifting from manual victim selection to AI-assisted prioritization at scale. No actor-owned C2 infrastructure was identified; all network traffic goes to legitimate third-party services.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-17 20:35 | PE timestamp of analyzed VOLTA sample |
| 2026-10-11 12:46 | First observed submission (VirusTotal) |
| 2026-10-30 | Cisco Talos publishes technical analysis |

## Root Cause: Initial Access

Initial access vector is not documented in the Talos report. Distribution is likely through social engineering or malware-as-a-service (MaaS) channels given the commodity infostealer design pattern and build-time configuration templating (six encrypted template slots per binary).

## Technical Analysis of the Malicious Payload

### 1. Credential and Session Harvesting

VOLTA collects a broad set of victim data on first execution:

- Chromium browser credentials, cookies, and saved payment cards (ABE bypass via `--headless`)
- Firefox, Thunderbird, and Outlook profiles
- Slack workspace tokens, Discord tokens, Telegram session files
- Steam and Battle.net sessions
- Roblox accounts (with Rolimons.com inventory valuation lookups)
- Microsoft OAuth tokens
- SSH keys and configs (including gcloud, OpenVPN, Hide.me)
- Cryptocurrency wallets and seed phrases (embedded cracker for wallet vaults)
- Saved Wi-Fi profiles (via `WlanGetProfileList` API)
- Screenshots and iPhone backup indicators

The harvest log is written to `%APPDATA%\volta_debug.txt` with timestamps.

### 2. AI-Driven Victim Triage

After initial collection, VOLTA assembles an `Identity_Report.txt` containing the victim profile and submits it to `openrouter.ai/api/v1/chat/completions` via hand-assembled JSON (no SDK). The system prompt frames the LLM as a "forensic intelligence analyst drafting a target assessment" and requires section headers "WHAT THEY'RE WORTH" and "THEIR OPSEC." The LLM response is saved as `AI_Analysis.txt`.

- **Default model:** `anthropic/claude-opus-4.6`
- **Fallback chain:** `moonshotai/kimi-k2` → `google/gemini-2.5-flash`
- **Temperature:** 0.2
- **Refusal detection:** Responses are checked for phrases like "I can't" and "I'm not able"; on refusal the next model in the chain is tried
- **User-Agent:** `Mozilla/5.0`

### 3. Staged Exfiltration

Exfiltration occurs in three ZIP archives:

| Stage | Archive | Contents |
|-------|---------|----------|
| 1 | `volta_log.zip` | Initial harvest: credentials, wallets, sessions |
| 2 | `volta_dox.zip` | Post-LLM enrichment: Gmail receipts, delivery orders, Discord profile |
| 3 | `volta_doxnet.zip` | Network enrichment: Wi-Fi data, further recon results |

The log string "WALLET VAULTS CRACKED" appears when the embedded cryptocurrency wallet cracker succeeds.

### 4. Anti-Forensics / Evasion Techniques

- Self-deletion of the main executable after execution
- Embedded configuration encrypted with SHA-256-derived key from two binary constants
- Build-time templating with six encrypted configuration slots
- No actor-owned infrastructure — all traffic to legitimate third-party APIs

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|------------|---------------|-------------|
| Windows | 9BY0tjwOc3ut.exe / yLP9m5J3i2Aw.exe | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | VOLTA main executable (PE32+ x86-64, PE timestamp 2026-08-17) |
| Windows | `%APPDATA%\volta_debug.txt` | — | Timestamped harvest log |
| Windows | Identity_Report.txt | — | Assembled victim profile sent to LLM |
| Windows | AI_Analysis.txt | — | LLM-generated target assessment |
| Windows | volta_log.zip | — | Stage 1 exfil archive |
| Windows | volta_dox.zip | — | Stage 2 exfil archive |
| Windows | volta_doxnet.zip | — | Stage 3 exfil archive |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | openrouter[.]ai | LLM API for victim triage |
| URL | hxxps://openrouter[.]ai/api/v1/chat/completions | LLM inference endpoint |
| Domain | rolimons[.]com | Roblox inventory valuation lookup |

### Behavioral

- Chrome/Chromium launched with `--headless` from non-browser parent process (ABE bypass)
- `WlanGetProfileList` API call for Wi-Fi profile enumeration
- Hand-assembled JSON POST to OpenRouter API with model field containing `anthropic/claude-opus-4.6`, `moonshotai/kimi-k2`, or `google/gemini-2.5-flash`
- Self-deletion of PE executable after harvest completion

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1005 | Data from Local System | Harvest of browser credentials, wallets, session tokens, Wi-Fi profiles |
| T1119 | Automated Collection | Scripted multi-stage collection across browser, messaging, and crypto applications |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome ABE bypass via `--headless` flag |
| T1560.001 | Archive Collected Data: Archive via Utility | Three-stage ZIP exfiltration (volta_log/dox/doxnet.zip) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST to OpenRouter API |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Build-time encrypted configuration with SHA-256-derived key |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion of main executable |

## Impact Assessment

VOLTA targets Windows users with cryptocurrency holdings, gaming accounts (Roblox, Steam, Battle.net), and cloud credentials. The AI triage component allows the operator to scale victim prioritization without manual review, focusing exploitation efforts on high-value targets. The breadth of collected data (browser credentials, session tokens, Wi-Fi profiles, wallet seeds) enables account takeover, financial theft, and identity exploitation. The absence of actor-owned C2 makes network-level blocking more challenging since all traffic goes to legitimate services.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for VOLTA debug log
Get-ChildItem -Path "$env:APPDATA\volta_debug.txt" -ErrorAction SilentlyContinue

# Check for VOLTA exfil archives
Get-ChildItem -Recurse -Filter "volta_*.zip" -ErrorAction SilentlyContinue

# Check for Identity_Report.txt and AI_Analysis.txt
Get-ChildItem -Path $env:TEMP, $env:APPDATA -Include "Identity_Report.txt","AI_Analysis.txt" -Recurse -ErrorAction SilentlyContinue
```

### Remediation

1. **Contain**: Isolate affected hosts from the network
2. **Eradicate**: Remove VOLTA artifacts (`volta_debug.txt`, `Identity_Report.txt`, `AI_Analysis.txt`, `volta_*.zip`)
3. **Rotate credentials**: All browser-saved passwords, session tokens, OAuth tokens, SSH keys
4. **Revoke tokens**: Discord, Slack, Telegram, Steam, Battle.net, Roblox sessions
5. **Migrate wallets**: Move cryptocurrency from any wallet whose seed phrase was stored on the compromised host
6. **Rotate Wi-Fi**: Change passwords for all Wi-Fi networks whose profiles were saved on the host

### Long-Term Hardening

- Deploy application control policies restricting which processes may launch Chrome with `--headless`
- Use hardware-backed credential storage (FIDO2/WebAuthn) to reduce value of stolen passwords
- Monitor for non-browser processes resolving `openrouter.ai` via DNS query logging
- Alert on creation of files matching `volta_*.zip` or `volta_debug.txt` patterns

## Detection Rules

Four Sigma rules, one YARA rule (two sub-rules), one Suricata rule, and one Snort rule cover the observable artifacts.

<!-- VALIDATION AUDIT: All four Sigma rules convert cleanly to both Splunk (--without-pipeline -t splunk) and CrowdStrike LogScale (--without-pipeline -t log_scale). sigma check fails due to egress proxy blocking MITRE ATT&CK data download (HTTP 403) — environment limitation, not rule defect. YARA rule compiles with yarac (import "hash" for SHA256 sub-rule). Suricata rule passes suricata -T. Snort rule is structurally valid but uncompiled (no snort binary available in environment). All Sigma field names match Windows Sysmon/EVTX schemas. Detection values use real (non-defanged) indicators as required. -->

### Sigma: VOLTA Debug Log File Creation

Detects creation of `volta_debug.txt` in the user's AppData directory.

compile ✅ (Splunk + LogScale) × confidence **high**

```yaml
title: VOLTA Infostealer Debug Log File Creation
id: b3e7a1c4-9f2d-4e8a-b6c1-5d0e3f8a2b7c
status: experimental
description: >
    Detects creation of volta_debug.txt in the user's AppData\Roaming directory,
    a timestamped harvest log written by the VOLTA infostealer during credential
    and session theft operations.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-02
tags:
    - attack.t1005
    - attack.t1119
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\AppData\Roaming\volta_debug.txt'
    condition: selection
falsepositives:
    - Legitimate software named Volta (e.g., the Volta JavaScript tool manager) does not write to this path
level: high
```

### Sigma: VOLTA Chrome Headless ABE Bypass

Detects Chrome launched with `--headless` by a non-browser parent process.

compile ✅ (Splunk + LogScale) × confidence **medium**

```yaml
title: VOLTA Infostealer Chrome Headless ABE Bypass
id: a4d8f2e5-1c3b-4a9f-8e7d-6b2c0f9a3d1e
status: experimental
description: >
    Detects Chrome or Chromium launched with --headless by a non-browser parent
    process, a technique used by VOLTA to bypass App-Bound Encryption and
    extract cookies and saved credentials from Chromium-based browsers.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-02
tags:
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\chromium.exe'
            - '\brave.exe'
    selection_headless:
        CommandLine|contains: '--headless'
    filter_browser_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\chromium.exe'
            - '\brave.exe'
            - '\setup.exe'
            - '\update.exe'
            - '\GoogleUpdate.exe'
            - '\MicrosoftEdgeUpdate.exe'
    condition: selection_binary and selection_headless and not filter_browser_parent
falsepositives:
    - Automated browser testing frameworks (Selenium, Puppeteer, Playwright)
    - CI/CD pipelines running headless browser tests
    - Developers running headless Chrome for screenshot or PDF generation
level: medium
```

### Sigma: VOLTA Staged Exfiltration Archives

Detects creation of VOLTA's three-stage exfil ZIP archives.

compile ✅ (Splunk + LogScale) × confidence **high**

```yaml
title: VOLTA Infostealer Staged Exfiltration Archives
id: c5e9f3a6-2d4c-4b0a-9f8e-7c3d1a0b4e2f
status: experimental
description: >
    Detects creation of ZIP archives with names matching VOLTA's three-stage
    exfiltration pattern (volta_log.zip, volta_dox.zip, volta_doxnet.zip)
    used to package stolen credentials, victim profiles, and network
    enrichment data.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-02
tags:
    - attack.t1560.001
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
    - Unlikely; these file names are specific to the VOLTA infostealer
level: critical
```

### Sigma: VOLTA OpenRouter DNS Query

Detects DNS queries to `openrouter.ai` from non-browser processes.

compile ✅ (Splunk + LogScale) × confidence **medium**

```yaml
title: VOLTA Infostealer OpenRouter API DNS Query
id: d6f0a4b7-3e5d-4c1b-a0f9-8d4e2b1c5f3a
status: experimental
description: >
    Detects DNS queries to openrouter.ai from non-browser processes. VOLTA
    sends stolen victim data to the OpenRouter LLM API for AI-driven triage
    and prioritization. Legitimate developer use of the OpenRouter API exists
    but is uncommon outside AI/ML tooling.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026-11-02
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'openrouter.ai'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\firefox.exe'
            - '\brave.exe'
    condition: selection and not filter_browsers
falsepositives:
    - AI/ML development tools and IDE plugins that use the OpenRouter API
    - Python or Node.js scripts making legitimate OpenRouter API calls
level: medium
```

### YARA: VOLTA Infostealer Strings and Hash

Two YARA sub-rules: one matching distinctive strings (debug log, exfil archives, LLM prompt markers), one matching the known sample hash.

compile ✅ × confidence **high**

```yara
import "hash"

rule VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer by distinctive strings"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        severity = "critical"

    strings:
        $debug_log    = "volta_debug.txt" ascii wide
        $exfil1       = "volta_log.zip" ascii wide
        $exfil2       = "volta_dox.zip" ascii wide
        $exfil3       = "volta_doxnet.zip" ascii wide
        $report_id    = "Identity_Report.txt" ascii wide
        $ai_output    = "AI_Analysis.txt" ascii wide
        $api_endpoint = "openrouter.ai/api/v1/chat/completions" ascii wide
        $prompt_worth = "WHAT THEY'RE WORTH" ascii wide
        $prompt_opsec = "THEIR OPSEC" ascii wide
        $wallet_crack = "WALLET VAULTS CRACKED" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        (($debug_log and 2 of ($exfil*)) or
         ($api_endpoint and ($prompt_worth or $prompt_opsec)) or
         (4 of them))
}

rule VOLTA_Infostealer_Hash
{
    meta:
        description = "Detects known VOLTA infostealer sample by SHA256 hash"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        severity = "critical"

    condition:
        hash.sha256(0, filesize) == "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
}
```

### Suricata: VOLTA OpenRouter Exfiltration

Detects HTTPS POST to the OpenRouter chat completions API.

compile ✅ × confidence **high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"VOLTA Infostealer - HTTPS POST to OpenRouter LLM API for victim triage"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; http.uri; content:"/api/v1/chat/completions"; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; classtype:trojan-activity; sid:2026110201; rev:1;)
```

### Snort: VOLTA OpenRouter Exfiltration

⚠️ uncompiled (structural check only) × confidence **high**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"VOLTA Infostealer - HTTPS POST to OpenRouter LLM API for victim triage"; flow:established,to_server; content:"POST"; http_method; content:"openrouter.ai"; http_header; content:"/api/v1/chat/completions"; http_uri; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; classtype:trojan-activity; sid:2026110201; rev:1;)
```

## Lessons Learned

VOLTA demonstrates the emerging pattern of commodity malware integrating AI APIs to automate operator workflows — in this case, victim triage. The use of legitimate third-party services (OpenRouter, Gmail, Uber Eats, Discord) as both collection targets and infrastructure complicates network-based detection since there are no actor-controlled domains or IPs to block. Detection must focus on host-level artifacts (distinctive file names, Chrome ABE bypass technique) and the unusual pattern of non-browser processes communicating with LLM APIs. The refusal-detection and model-fallback logic shows operators anticipating AI safety measures as an obstacle to overcome.

## Sources

- [Cisco Talos Blog](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) — Primary technical analysis of VOLTA infostealer

---
*Report generated by Actioner*
