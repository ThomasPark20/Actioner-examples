# Technical Analysis Report: VOLTA Infostealer (2026/11/11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026/11/11
Version: 1.0

## Executive Summary

VOLTA (aka VOLTA-AUTODOXER) is a novel Windows infostealer that differentiates itself from the commodity stealer landscape by integrating large language model (LLM) API calls to rank and prioritize victims by the monetization value of their stolen assets. After harvesting credentials, sessions, cryptocurrency wallets, and personal data from an infected host, VOLTA assembles a structured victim dossier and submits it to an LLM via the OpenRouter API. The model is instructed to act as a forensic intelligence analyst, producing a "target assessment" that classifies stolen assets into low, medium, and high tiers and evaluates the victim's security posture. The malware uses a model fallback chain (Claude Opus 4.6, Kimi K2, Gemini 2.5 Flash) with refusal detection logic, and self-deletes after execution.

First observed on 2026-10-11, VOLTA appears to be distributed as a builder-based crimeware service with a six-slot build configuration template. It was surfaced through the CAIRN research effort by Cisco Talos researcher Ryan Fetterman. The malware uses exclusively third-party infrastructure (OpenRouter, Telegram, Gmail, delivery service APIs) with no attacker-owned C2 servers identified. This makes traditional network IOC blocking less effective; detection must focus on endpoint behavioral indicators and the distinctive file artifacts the malware creates.

## Background: AI-Augmented Infostealers

VOLTA represents an emerging trend in crimeware where threat actors leverage generalist AI models to automate victim triage. Rather than exfiltrating all stolen data to a human operator for manual review, VOLTA offloads the assessment to an LLM, which produces a concise, structured appraisal of a victim's financial worth and exploitability. This reduces operator workload and allows faster monetization of high-value targets. The technique is notable because it abuses legitimate AI API services, not attacker-hosted models, making infrastructure takedown difficult.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-17 20:35 | PE compilation timestamp of analyzed sample |
| 2026-10-11 12:46 | First observed in the wild (VirusTotal first submission) |
| 2026-11-11 | Cisco Talos publishes analysis of VOLTA infostealer |

## Root Cause: Initial Access Vector

The initial access vector for VOLTA is not detailed in the Talos report. The builder-based distribution model suggests it is delivered through typical commodity stealer channels such as phishing, malvertising, cracked software downloads, or social engineering via Discord/Telegram. The binary names (`9BY0tjwOc3ut.exe`, `yLP9m5J3i2Aw.exe`) suggest randomized filenames consistent with automated delivery infrastructure.

## Technical Analysis of the Malicious Payload

### 1. Credential and Data Harvesting

VOLTA performs broad credential and session harvesting across multiple applications:

- **Browser data**: Passwords, cookies, and saved payment cards from Chromium-based browsers; Firefox profiles
- **Email clients**: Thunderbird and Outlook profiles; Microsoft OAuth tokens
- **Messaging/Gaming**: Discord tokens, Telegram sessions, Slack workspaces, Steam, Battle.net, Roblox sessions
- **SSH/Cloud**: SSH private keys, gcloud configs, OpenVPN configs, Hide.me profiles
- **Cryptocurrency**: Wallet files, with inline cracking capabilities
- **System data**: Wi-Fi profiles (via `WlanGetProfileList` API), screenshots, iPhone backup indicators, document metadata

Chrome App-Bound Encryption (ABE) bypass is performed by launching Chrome with the `--headless` flag from the stealer process, which is a detectable behavioral indicator.

### 2. Victim Enrichment

VOLTA uses stolen session tokens to actively enrich the victim profile:

- **Gmail**: Searches for receipts from Amazon, DoorDash, Uber Eats, Grubhub, Walmart, and PayPal to confirm spending habits and home address
- **Food delivery**: Pulls order history from Uber Eats and DoorDash APIs
- **Roblox**: Queries `rolimons[.]com` to value the victim's Roblox inventory
- **Discord**: Enriches profile data using the stolen Discord token

### 3. LLM-Driven Victim Prioritization

The assembled data is structured into `Identity_Report.txt` (JSON-serialized victim dossier) and submitted to an LLM via HTTPS POST to `openrouter[.]ai/api/v1/chat/completions`. Key configuration:

- **Default model**: `anthropic/claude-opus-4.6`
- **Fallback chain**: `moonshotai/kimi-k2` then `google/gemini-2.5-flash`
- **Temperature**: 0.2 (deterministic output)
- **User-Agent**: `Mozilla/5.0`
- **Request format**: Hand-assembled JSON (no SDK)

The system prompt instructs the model to act as a "forensic intelligence analyst" producing a "target assessment" with sections including:
- **"WHAT THEY'RE WORTH"**: Ranks monetizable assets into low/medium/high tiers
- **"THEIR OPSEC"**: Evaluates victim's security posture and password hygiene
- **"WALLET VAULTS CRACKED"**: Reports on compromised cryptocurrency wallets

**Refusal detection**: The malware scans LLM responses for phrases like "I can't" and "I'm not able" before falling back to the next model in the chain. If no API key is configured, the AI stage is skipped entirely.

The model's response is saved to `AI_Analysis.txt`.

### 4. Staged Exfiltration

Data is exfiltrated in up to three staged ZIP archives:

| Stage | Archive | Contents |
|-------|---------|----------|
| 1 | `volta_log.zip` | Raw stolen credentials and session data |
| 2 | `volta_dox.zip` | `Identity_Report.txt` + `AI_Analysis.txt` |
| 3 | `volta_doxnet.zip` | Network enrichment results (if available) |

The final dossier is delivered to the operator via a Telegram channel configured at build time.

### 5. C2 Infrastructure

VOLTA uses no attacker-owned infrastructure. All observed communication endpoints are legitimate third-party services:

- **OpenRouter API** (`openrouter[.]ai`): LLM victim assessment
- **Telegram Bot API**: Exfiltration delivery channel
- **Gmail API**: Victim email search using stolen OAuth tokens
- **rolimons[.]com**: Roblox inventory valuation
- **Uber Eats / DoorDash APIs**: Order history enrichment

### 6. Anti-Forensics / Evasion Techniques

- **Self-deletion**: The main executable deletes itself after execution (mechanism not specified in report)
- **Timestamped debug log**: `%APPDATA%\volta_debug.txt` records harvesting operations and LLM call status
- **Weak encryption**: Build-time configuration values (Telegram channel, API keys) are encrypted with SHA-256 derived from two constants embedded in the binary
- **Builder-based polymorphism**: Six-slot build template produces unique binaries per customer, varying hashes across deployments

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Windows | `9BY0tjwOc3ut.exe` / `yLP9m5J3i2Aw.exe` | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | VOLTA main executable (PE32+ x86-64) |
| Windows | `%APPDATA%\volta_debug.txt` | N/A | Timestamped harvest log |
| Windows | `Identity_Report.txt` | N/A | JSON victim dossier sent to LLM |
| Windows | `AI_Analysis.txt` | N/A | LLM-generated victim assessment |
| Windows | `volta_log.zip` | N/A | Stage 1 exfiltration archive |
| Windows | `volta_dox.zip` | N/A | Stage 2 exfiltration archive (dossier) |
| Windows | `volta_doxnet.zip` | N/A | Stage 3 exfiltration archive (network enrichment) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `openrouter[.]ai` | LLM API for victim assessment (legitimate service abused) |
| URL Pattern | `hxxps://openrouter[.]ai/api/v1/chat/completions` | LLM API endpoint |
| Domain | `rolimons[.]com` | Roblox inventory valuation (legitimate service queried) |

### Behavioral

- Non-browser process launching `chrome.exe --headless` (ABE bypass)
- Process creating files matching `volta_*.zip` or `volta_debug.txt`
- Process creating `Identity_Report.txt` and `AI_Analysis.txt` in sequence
- Non-browser HTTPS POST to `openrouter[.]ai` with JSON body containing model identifiers
- Wi-Fi profile enumeration via `WlanGetProfileList` API
- Gmail API searches for receipt keywords (Amazon, DoorDash, Uber Eats, Grubhub, Walmart, PayPal)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1555.003 | Credentials from Web Browsers | Harvests passwords, cookies, payment cards from Chromium and Firefox browsers; bypasses Chrome ABE via --headless |
| T1539 | Steal Web Session Cookie | Steals session cookies from browsers for account access |
| T1528 | Steal Application Access Token | Steals Discord tokens, Microsoft OAuth tokens, Telegram sessions |
| T1552.004 | Unsecured Credentials: Private Keys | Harvests SSH private keys and cloud configuration files |
| T1552.001 | Unsecured Credentials: Credentials In Files | Extracts credentials from application config files (gcloud, OpenVPN, Hide.me) |
| T1005 | Data from Local System | Collects screenshots, document metadata, Wi-Fi profiles, iPhone backup indicators |
| T1113 | Screen Capture | Takes screenshots of victim desktop |
| T1119 | Automated Collection | Automatically assembles structured victim dossier from multiple data sources |
| T1074.001 | Data Staged: Local Data Staging | Stages collected data into three ZIP archives before exfiltration |
| T1567 | Exfiltration Over Web Service | Exfiltrates data via Telegram Bot API and submits to OpenRouter LLM API |
| T1071.001 | Application Layer Protocol: Web Protocols | All C2 and exfiltration over HTTPS to legitimate web services |
| T1070.004 | Indicator Removal: File Deletion | Self-deletes main executable after execution |

## Impact Assessment

VOLTA targets individual users broadly and opportunistically. Its impact is amplified by the LLM-driven triage, which allows operators to quickly identify and prioritize high-value victims for manual exploitation. The combination of credential theft, session hijacking, cryptocurrency wallet cracking, and active enrichment via stolen tokens (Gmail, food delivery, gaming) means a successful infection can lead to:

- Financial account compromise and fraudulent transactions
- Cryptocurrency theft from cracked wallets
- Identity theft using assembled personal dossiers
- Secondary account compromises via stolen sessions and tokens
- Physical security risks from address and spending pattern exposure

The builder-based distribution model suggests multiple operators may be deploying VOLTA, each with unique binaries and exfiltration channels, making hash-based detection alone insufficient.

## Detection & Remediation

### Immediate Detection

```bash
# Check for VOLTA debug log (Windows)
dir /s /b "%APPDATA%\volta_debug.txt" 2>nul

# Check for VOLTA exfiltration archives
dir /s /b "%USERPROFILE%\volta_log.zip" "%USERPROFILE%\volta_dox.zip" "%USERPROFILE%\volta_doxnet.zip" 2>nul

# Check for dossier files
dir /s /b "%USERPROFILE%\Identity_Report.txt" "%USERPROFILE%\AI_Analysis.txt" 2>nul

# Check for Chrome headless launches from non-browser parents (Sysmon EventID 1 in PowerShell)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='CommandLine'] and contains(Data, '--headless')] and EventData[Data[@Name='Image'] and contains(Data, 'chrome.exe')]]" -MaxEvents 50
```

### Remediation

1. **Preserve evidence**: Before remediation, collect `%APPDATA%\volta_debug.txt` for forensic analysis of what was stolen
2. **Revoke all tokens**: Invalidate Discord, Microsoft OAuth, Google, Telegram, Slack, Steam, and all other application sessions
3. **Change all passwords**: Reset every password stored in the browser, prioritizing financial accounts
4. **Cryptocurrency wallets**: Move any wallet whose seed phrase or private key was stored in plaintext to a new wallet generated on an air-gapped device
5. **Enable MFA**: Deploy hardware-backed MFA on all critical accounts
6. **Monitor for abuse**: Watch for unauthorized access using stolen sessions, especially on Gmail, Discord, and food delivery accounts
7. **Notify financial institutions**: Alert banks and payment providers of potential credential compromise

### Long-Term Hardening

- Restrict which processes can launch Chrome with `--headless` via application whitelisting
- Deploy hardware-backed credential stores (e.g., Windows Hello, hardware security keys)
- Monitor for non-browser processes making HTTPS connections to AI API services
- Implement DNS monitoring for unexpected queries to `openrouter[.]ai` from endpoint systems
- Use browser-based credential managers with biometric unlock rather than plaintext-accessible stores

## Detection Rules

This section provides detection rules (five Sigma, two Suricata network rules, and two YARA file rules) targeting VOLTA's distinctive file artifacts, behavioral patterns, and network indicators. All rules are advisory-specific and tuned for high precision; the primary caveat is that the builder-based distribution model means file hashes will vary across deployments, making behavioral and string-based detection essential.

### Sigma: Chrome Headless Launch from Unusual Parent

Detects Chrome or Edge launched with `--headless` from a non-standard parent process, targeting the App-Bound Encryption bypass technique used by VOLTA.  Legitimate headless browser usage by testing frameworks will generate false positives.

<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); sigma convert --without-pipeline -t splunk and -t log_scale both succeed; rule parses and converts cleanly; FP from Selenium/Puppeteer/Playwright is expected and noted -->

**Compile**: ✅ | **Confidence**: medium

```yaml
title: Chrome Launched With Headless Flag By Unusual Parent
id: 7a3e2d1f-9c4b-4e8a-b5d6-0f1a2c3e4d5b
status: experimental
description: >
    Detects Chrome being launched with the --headless flag from a non-standard
    parent process, which may indicate App-Bound Encryption bypass as observed
    in the VOLTA infostealer.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/11
tags:
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '--headless'
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
    filter_browser_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\explorer.exe'
            - '\svchost.exe'
            - '\services.exe'
            - '\GoogleUpdate.exe'
            - '\MicrosoftEdgeUpdate.exe'
    condition: selection and not filter_browser_parent
falsepositives:
    - Automated testing frameworks (Selenium, Puppeteer, Playwright)
    - CI/CD pipelines running headless browser tests
    - Node.js, Python, Java, or PowerShell processes using headless Chrome for PDF rendering
level: medium
```

### Sigma: VOLTA Debug Log File Creation

Detects creation of the `volta_debug.txt` file in the AppData directory, a timestamped harvest log unique to the VOLTA infostealer.

<!-- audit: sigma check blocked by proxy; sigma convert -t splunk produces: TargetFilename="*\\volta_debug.txt"; sigma convert -t log_scale succeeds; filename is highly specific to VOLTA -->

**Compile**: ✅ | **Confidence**: high

```yaml
title: VOLTA Infostealer Debug Log File Creation
id: 8b4f3e2a-0d5c-4f9b-a6e7-1a2b3c4d5e6f
status: experimental
description: >
    Detects creation of volta_debug.txt in the AppData\Roaming directory,
    a timestamped harvest log written by the VOLTA infostealer during
    credential collection.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/11
tags:
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\volta_debug.txt'
    condition: selection
falsepositives:
    - Unlikely - highly specific filename associated with VOLTA malware
level: critical
```

### Sigma: VOLTA Exfiltration Archive Creation

Detects creation of ZIP archives matching VOLTA's staged exfiltration naming convention (`volta_log.zip`, `volta_dox.zip`, `volta_doxnet.zip`).

<!-- audit: sigma check blocked by proxy; sigma convert -t splunk produces: TargetFilename IN ("*\\volta_log.zip", "*\\volta_dox.zip", "*\\volta_doxnet.zip"); log_scale conversion succeeds; filenames are unique to VOLTA -->

**Compile**: ✅ | **Confidence**: high

```yaml
title: VOLTA Infostealer Exfiltration Archive Creation
id: 9c5a4b3d-1e6f-4a0b-b7c8-2d3e4f5a6b7c
status: experimental
description: >
    Detects creation of ZIP archives matching VOLTA infostealer exfiltration
    naming convention (volta_log.zip, volta_dox.zip, volta_doxnet.zip) used
    for staged data exfiltration.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/11
tags:
    - attack.t1074.001
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
    - Unlikely - highly specific filenames associated with VOLTA malware
level: critical
```

### Sigma: VOLTA Victim Dossier File Creation

Detects creation of `Identity_Report.txt` or `AI_Analysis.txt`, the victim dossier and LLM response files generated by VOLTA.  Generic filenames carry a slightly elevated false-positive risk from security assessment tools.

<!-- audit: sigma check blocked by proxy; sigma convert -t splunk produces: TargetFilename IN ("*\\Identity_Report.txt", "*\\AI_Analysis.txt"); log_scale conversion succeeds; filenames are moderately specific -->

**Compile**: ✅ | **Confidence**: medium

```yaml
title: VOLTA Infostealer Victim Dossier File Creation
id: 2a1b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects creation of Identity_Report.txt or AI_Analysis.txt files used by
    the VOLTA infostealer to assemble victim dossiers and store LLM-generated
    assessments of victim asset value.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/11
tags:
    - attack.t1005
    - attack.t1119
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\Identity_Report.txt'
            - '\AI_Analysis.txt'
    condition: selection
falsepositives:
    - Security assessment tools that generate similarly named reports
    - AI-powered tools that create analysis or identity report files
level: medium
```

### Sigma: Non-Browser DNS Query to OpenRouter AI

Detects DNS queries to `openrouter[.]ai` from non-browser processes, which may indicate an infostealer using the OpenRouter API for LLM-driven victim assessment.  Legitimate AI development tools using OpenRouter from command-line processes will generate false positives.

<!-- audit: sigma check blocked by proxy; sigma convert -t splunk produces: QueryName="*openrouter.ai" NOT (Image IN (...)); log_scale conversion succeeds; openrouter.ai queries from non-browser processes are suspicious but legitimate developer tooling is possible -->

**Compile**: ✅ | **Confidence**: medium

```yaml
title: Connection to OpenRouter AI API From Non-Browser Process
id: 3b2c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects network connections to the OpenRouter AI API (openrouter.ai) from
    processes that are not web browsers, as observed in the VOLTA infostealer
    which uses OpenRouter to submit stolen data for LLM-driven victim
    prioritization.
references:
    - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
author: Actioner
date: 2026/11/11
tags:
    - attack.t1567
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith: 'openrouter.ai'
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
    - Legitimate AI development tools or IDE plugins using OpenRouter API
    - Python or Node.js scripts using OpenRouter for AI tasks
level: medium
```

### Suricata: VOLTA OpenRouter LLM Exfiltration

Two Suricata rules detecting: (1) OpenRouter API POST with VOLTA-specific system prompt keywords in the request body, and (2) OpenRouter API POST with forensic analyst role assignment. Both require TLS decryption or proxy inspection to match HTTPS POST body content.

<!-- audit: suricata -T -S <file> -l /tmp/actioner exits 0; both rules pass syntax validation; SIDs 2200004-2200005 in assigned range; dot-notation sticky buffers used correctly -->
<!-- revision: Dropped SID 2200003 (rolimons.com DNS) per critic — fires on every Roblox player or trader visiting rolimons.com; not remotely specific to VOLTA at strict leniency. -->

**Compile**: ✅ | **Confidence**: medium (requires TLS inspection)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer OpenRouter API LLM Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; fast_pattern; http.uri; content:"/api/v1/chat/completions"; http.request_body; content:"WHAT THEY"; content:"WORTH"; distance:0; within:30; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created_at 2026-11-11; sid:2200004; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - VOLTA Infostealer OpenRouter API Request With Stealer Model Chain"; flow:established,to_server; http.method; content:"POST"; http.host; content:"openrouter.ai"; http.uri; content:"/api/v1/chat/completions"; http.request_body; content:"forensic"; content:"target assessment"; distance:0; within:200; classtype:trojan-activity; reference:url,blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/; metadata:author Actioner, created_at 2026-11-11; sid:2200005; rev:1;)
```

### YARA: VOLTA Infostealer Binary Detection

Two rules: (1) String-based detection matching VOLTA's characteristic filenames, LLM model identifiers, API endpoints, and output section headers, and (2) a broader rule matching PE64 binaries containing two or more VOLTA-prefixed artifact names.  The string-based rule is designed to survive builder variations by requiring only a subset of indicators.

<!-- audit: yarac /tmp/actioner/rules/yara_volta_infostealer.yar /dev/null exits 0; both rules compile cleanly; PE module imported correctly; condition logic uses OR branches for flexibility across builder variants; hash of known sample included in meta -->
<!-- revision: Renamed rule 2 from Malware_VOLTA_Infostealer_Hash to Malware_VOLTA_Infostealer_Artifacts_Broad — it detects by strings, not hash. Tightened condition from `any of ($volta*)` to `2 of ($volta*)` to reduce FP from unrelated projects using a single "volta_log" or "volta_dox" string. -->

**Compile**: ✅ | **Confidence**: high (rule 1 with 3+ string matches), medium (rule 2 broader catch)

```yara
import "pe"

rule Malware_VOLTA_Infostealer_Strings
{
    meta:
        description = "Detects VOLTA infostealer based on characteristic strings including debug log paths, dossier filenames, exfiltration archive names, and LLM model fallback chain identifiers"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $debug = "volta_debug.txt" ascii wide
        $report = "Identity_Report.txt" ascii wide
        $analysis = "AI_Analysis.txt" ascii wide
        $zip1 = "volta_log.zip" ascii wide
        $zip2 = "volta_dox.zip" ascii wide
        $zip3 = "volta_doxnet.zip" ascii wide
        $model1 = "anthropic/claude-opus-4.6" ascii
        $model2 = "moonshotai/kimi-k2" ascii
        $model3 = "google/gemini-2.5-flash" ascii
        $api = "/api/v1/chat/completions" ascii
        $openrouter = "openrouter.ai" ascii
        $worth = "WHAT THEY'RE WORTH" ascii wide
        $opsec = "THEIR OPSEC" ascii wide
        $wallet = "WALLET VAULTS CRACKED" ascii wide
        $refusal1 = "I can't" ascii wide
        $refusal2 = "I'm not able" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($debug, $report, $analysis, $zip1, $zip2, $zip3)) or
            (2 of ($model1, $model2, $model3) and $api) or
            ($openrouter and $api and 1 of ($worth, $opsec, $wallet)) or
            (4 of them)
        )
}

rule Malware_VOLTA_Infostealer_Artifacts_Broad
{
    meta:
        description = "Broadly detects VOLTA infostealer variants by matching PE64 binaries containing two or more VOLTA-prefixed artifact name strings (volta_debug, volta_log, volta_dox)"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/"
        hash = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279"
        tlp = "WHITE"
        severity = "high"

    strings:
        $volta1 = "volta_debug" ascii wide
        $volta2 = "volta_log" ascii wide
        $volta3 = "volta_dox" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        2 of ($volta*)
}
```

## Lessons Learned

1. **AI as a force multiplier for crimeware**: VOLTA demonstrates that LLM integration in malware is no longer theoretical. By automating victim triage, operators can process more victims faster and prioritize high-value targets without manual review. Defenders should anticipate more infostealers adopting similar techniques.

2. **Legitimate infrastructure abuse complicates detection**: VOLTA uses exclusively third-party services (OpenRouter, Telegram, Gmail, food delivery APIs) with no attacker-owned C2. Traditional network IOC blocking and domain reputation lists are insufficient. Detection must pivot to endpoint behavioral indicators: unusual process trees, distinctive file artifacts, and anomalous API access patterns.

3. **Active enrichment raises the stakes**: Unlike passive infostealers that simply dump credentials, VOLTA actively uses stolen tokens to search email, query delivery services, and value gaming inventories. This means a compromised machine is not just a data source but an active reconnaissance platform, and the window for damage extends beyond the initial infection.

4. **Builder-based distribution demands behavioral detection**: The six-slot build template produces unique binaries per customer. SHA-256 hash matching will only catch the exact analyzed sample. Detection strategies must focus on behavioral patterns (file naming conventions, API call sequences, Chrome headless abuse) that persist across builder variants.

## Sources

- [Cisco Talos: Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/) — primary technical analysis by Ryan Fetterman detailing VOLTA's LLM integration, credential harvesting, and exfiltration workflow
- [MITRE ATT&CK Framework](https://attack.mitre.org/) — technique and sub-technique mappings for observed TTPs

---
*Report generated by Actioner*
