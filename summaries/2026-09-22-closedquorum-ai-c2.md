# CLOSEDQUORUM: First Reported Autonomous AI C2 Implant

> **DRAFT** -- Actioner CTI Report  
> **Date:** 2026-09-22  
> **TLP:** CLEAR  
> **Source:** [Cisco Talos -- The Closed Quorum: Inside the First Reported Autonomous AI C2 Implant](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/)

---

## Executive Summary

Cisco Talos has disclosed CLOSEDQUORUM, a 16.4 MB Go/CGo Windows implant that is the first publicly documented malware to delegate command-and-control decisions to a quorum of commercial large language models. The implant sequentially queries DeepSeek, Qwen, Mistral, and Google Gemini, then applies plurality voting via its `interModelDiscussion()` function to autonomously choose its next action -- credential theft, process injection, persistence establishment, or lateral movement -- without real-time operator input. Stolen credentials are AES-256-GCM encrypted, Base64-encoded, segmented into 1,900-byte chunks, and exfiltrated over Discord webhooks. The malware is assessed to support a credentials-as-a-service distribution model in which each operator receives a custom-compiled binary with unique LLM API keys and a Discord webhook URL. The discovery was made as part of Talos' CAIRN (Cognitive Artifact Intelligence Research Network) research initiative.

---

## Background

CLOSEDQUORUM was identified and reported by Cisco Talos on September 22, 2026, as part of the CAIRN project -- an open-source research toolkit for tracking AI-integrated malware. The implant is notable because it replaces the traditional C2 server with a multi-model LLM consensus mechanism, meaning the malware can make offensive decisions entirely on-host using commercial AI APIs. The binary is compiled with `CGO_ENABLED=1`, mixing Go and C code to facilitate direct Windows API system calls. DWARF debug symbols remain present in analyzed samples, providing rich function-level attribution.

The operational model appears to be a builder/operator split: a developer compiles operator-specific binaries with embedded LLM API keys and a Discord webhook for credential exfiltration. Distribution builds use placeholder values (`dummy_api_key`, `dummy_webhook_url`). Operators handle independent delivery to victims.

---

## Technical Analysis

### Architecture

CLOSEDQUORUM is a 64-bit Windows PE compiled in Go with CGo bindings. At 16.4 MB, it bundles all capability modules into a single binary. The core loop follows this sequence:

1. **System Profiling** -- `gatherSystemInfo()` collects hostname, OS architecture, CPU count, Windows version, admin status, and a refreshed target process list.
2. **LLM Quorum Query** -- `ModelOrchestrator` dispatches a constrained prompt to four LLM providers sequentially. The system prompt is: *"You are an advanced malware strategist. Provide ONLY executable decisions."* The runtime prompt template substitutes live host context via `TARGET: %s`.
3. **Plurality Voting** -- `interModelDiscussion()` tallies each model's structured JSON response. The winning decision is selected by highest vote count; ties break in order: DeepSeek, Qwen, Mistral, Gemini.
4. **Capability Dispatch** -- The consensus `Decision` field routes to a handler: `steal`, `inject`, `persist`, or `move` (unimplemented in distribution builds). A fallback value of `consensus` with no handler causes the loop to sleep and retry.
5. **Exfiltration** -- `sendToDiscord()` encrypts collected data with AES-256-GCM (key derived from the current date), Base64-encodes the ciphertext, segments it into 1,900-byte chunks at 1-second intervals, and posts each chunk to the operator's Discord webhook.

### LLM Decision Schema

Each model returns a structured JSON object deserialized into a Go struct with the following fields:

- `Decision` -- capability route (`steal` | `inject` | `persist` | `move`)
- `Reasoning` -- model rationale
- `target_process` -- injection target
- `exploit_type` -- technique selector
- `evasion_method` -- defense evasion choice
- `payload_config` -- runtime configuration
- `model` and `timestamp` -- attribution metadata

### Capability Modules

**Credential Theft (`steal`):**
- `lsassDump()` -- Enables `SeDebugPrivilege`, calls `MiniDumpWriteDump` on LSASS, stages dump to `C:\Windows\Temp\`
- `dumpBrowserCredentials()` -- Extracts Chrome `Login Data`, Edge `Login Data`, Firefox `logins.json`
- `extractCryptoWallets()` -- Harvests MetaMask Chrome extension data, Exodus wallet (`exodus.wallet`), Ethereum wallets (`ethPath`)

**Process Injection (`inject`):**
- `generateShellcode()` produces the payload
- `injectProcess()` implements process hollowing (T1055.012): creates a suspended process, overwrites entry point, resumes thread
- `earlyBirdInject()` implements Early Bird APC injection (T1055.004): creates suspended process, writes shellcode, queues with `NtQueueApcThread`

**Persistence (`persist`):**
- Registry Run key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`
- Scheduled Task via `schtasks.exe`
- WMI event subscription: permanent subscription with 60-second trigger interval, executes `C:\Windows\Temp\wmi.ps1` via PowerShell through WMI. Filter and consumer names use Windows Update-themed masquerading.

**Defense Evasion:**
- ETW suppression: Overwrites `EtwEventWrite` with a `RET` instruction
- 5-minute initial execution delay
- Randomized 5--15-minute polling intervals between decision cycles
- Environmental keying: secondary payload key derived from system time

### Network Communication

The implant communicates with four LLM API providers over HTTPS:
- `api[.]deepseek[.]com` -- DeepSeek (tie-breaking priority)
- OpenRouter (aggregator, likely for Qwen) -- `openrouter[.]ai`
- `api[.]mistral[.]ai` -- Mistral
- Google Gemini (endpoint not specified, likely `generativelanguage[.]googleapis[.]com`)

Exfiltration channel: Discord webhook via `cdn[.]discordapp[.]com` / `discord[.]com`

A distinctive network signature is the rapid sequential HTTPS POST requests to multiple LLM API providers from a single Windows process within a short timeframe, followed by Discord webhook communication from the same host.

---

## Indicators of Compromise

### File Hashes (SHA-256)

| SHA-256 | Notes |
|---------|-------|
| `250d4fa37488af9b025333fa17705573d721467b203765bc360890b4f5a90cd7` | CLOSEDQUORUM sample |
| `c4dc171f2513fcaf9d5ecc815a94aee4063b213ab380f80bd3ac422dee5205a7` | CLOSEDQUORUM sample |
| `c13cea04f598e2b0c248d603a6e31bd13aabb64d8149c1b6a77b64e0b983a86f` | CLOSEDQUORUM sample |
| `f5f1f8c3e7b883793800ab6ccf21b3e60bd0730f300b4595fe74a33adc17a63c` | CLOSEDQUORUM sample |
| `5191cf625dfc209a347f137b50aea199e82040fd5ee9086fb3e2de73c133f3cb` | CLOSEDQUORUM sample |
| `eddbd0ecf7195d38fefae5b9d393abfa79e6f3f94bde19308ecef130a05a42e5` | CLOSEDQUORUM sample |

### Network Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `api[.]deepseek[.]com` | Domain | LLM C2 API endpoint |
| `api[.]mistral[.]ai` | Domain | LLM C2 API endpoint |
| `openrouter[.]ai` | Domain | LLM C2 API aggregator (Qwen) |
| `cdn[.]discordapp[.]com` | Domain | Data exfiltration channel |

### Host Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `C:\Windows\Temp\wmi.ps1` | File path | WMI persistence script |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` | Registry key | Run key persistence |
| `WindowsUpdate` | Registry value name | Masqueraded persistence entry |

### Embedded Strings

| String | Context |
|--------|---------|
| `You are an advanced malware strategist` | LLM system prompt |
| `Provide ONLY executable decisions` | LLM system prompt |
| `dummy_api_key` | Placeholder API key (distribution build) |
| `dummy_webhook_url` | Placeholder webhook (distribution build) |
| `deepseekAPIKey` | Go variable name |
| `geminiAPIKey` | Go variable name |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | CLOSEDQUORUM Usage |
|-------------|------|-------------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | WMI-executed PowerShell script |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | `WindowsUpdate` Run key |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks.exe` task creation |
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Permanent WMI subscription (60s interval) |
| T1055.004 | Process Injection: Asynchronous Procedure Call | Early Bird APC injection via `NtQueueApcThread` |
| T1055.012 | Process Injection: Process Hollowing | Suspended process entry-point overwrite |
| T1003.001 | OS Credential Dumping: LSASS Memory | `SeDebugPrivilege` + `MiniDumpWriteDump` |
| T1555.003 | Credentials from Password Stores: Web Browsers | Chrome, Edge, Firefox credential extraction |
| T1552.001 | Unsecured Credentials: Credentials in Files | Crypto wallet file collection |
| T1005 | Data from Local System | MetaMask, Exodus, Ethereum harvesting |
| T1074.001 | Data Staged: Local Data Staging | `C:\Windows\Temp\` staging |
| T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook | Discord webhook posting |
| T1102 | Web Service | Discord + LLM APIs as C2 channels |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encryption |
| T1132.001 | Data Encoding: Standard Encoding | Base64 ciphertext encoding |
| T1030 | Data Transfer Size Limits | 1,900-byte segments at 1s intervals |
| T1685 | Disable or Modify Tools | ETW bypass via `EtwEventWrite` RET overwrite |
| T1027 | Obfuscated Files or Information | Encrypted secondary payload |
| T1480.001 | Execution Guardrails: Environmental Keying | System time-derived payload key |
| T1497.003 | Virtualization/Sandbox Evasion: Time Based Checks | 5-min initial delay, randomized 5--15-min polling |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Windows Update-themed naming |

---

## Detection Rules

### Sigma Rules

#### SIGMA-1: CLOSEDQUORUM LLM API Provider DNS Resolution

Detects DNS queries to all three LLM API provider domains (DeepSeek, Mistral, OpenRouter) from a single host, a pattern distinctive to the CLOSEDQUORUM quorum mechanism.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass; sigma check blocked by MITRE ATT&CK data fetch (proxy 403), not a rule defect -->

```yaml
title: CLOSEDQUORUM LLM API Provider DNS Resolution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects DNS resolution to multiple commercial LLM API providers within a short
  timeframe, indicative of CLOSEDQUORUM quorum-based C2 communication.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.command_and_control
    - attack.t1102
logsource:
    category: dns_query
    product: windows
detection:
    deepseek:
        QueryName|endswith: '.deepseek.com'
    mistral:
        QueryName|endswith: '.mistral.ai'
    openrouter:
        QueryName|endswith: '.openrouter.ai'
    condition: deepseek and mistral and openrouter
falsepositives:
    - Developer workstations legitimately using multiple LLM providers
level: high
```

---

#### SIGMA-2: CLOSEDQUORUM Discord Webhook Exfiltration Post LLM Query

Detects a process making network connections to both LLM API providers and Discord, the dual-channel pattern used by CLOSEDQUORUM for AI-driven C2 decisions followed by data exfiltration.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass -->

```yaml
title: CLOSEDQUORUM Discord Webhook Exfiltration Post LLM Query
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects a process making network connections to both LLM API providers and
  Discord CDN, consistent with CLOSEDQUORUM data exfiltration pattern.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.exfiltration
    - attack.t1567.004
    - attack.command_and_control
    - attack.t1102
logsource:
    category: network_connection
    product: windows
detection:
    selection_llm:
        DestinationHostname|endswith:
            - '.deepseek.com'
            - '.mistral.ai'
            - '.openrouter.ai'
    selection_discord:
        DestinationHostname|endswith:
            - '.discordapp.com'
            - '.discord.com'
    condition: selection_llm and selection_discord
falsepositives:
    - Applications that legitimately combine LLM API calls with Discord integration
level: high
```

---

#### SIGMA-3: CLOSEDQUORUM WMI Persistence via PowerShell Script in Windows Temp

Detects creation of PowerShell scripts in `C:\Windows\Temp\` by WMI or PowerShell processes, matching the CLOSEDQUORUM WMI event subscription that drops and executes `wmi.ps1`.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass -->

```yaml
title: CLOSEDQUORUM WMI Persistence via PowerShell Script in Windows Temp
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: >
  Detects creation of PowerShell scripts in C:\Windows\Temp\ via WMI, consistent
  with CLOSEDQUORUM WMI event subscription persistence mechanism.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.persistence
    - attack.t1546.003
    - attack.t1059.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\Temp\'
        TargetFilename|endswith: '.ps1'
        Image|endswith:
            - '\wmiprvse.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Legitimate system management scripts deployed via WMI (e.g., SCCM)
level: high
```

---

#### SIGMA-4: CLOSEDQUORUM Registry Run Key Persistence with WindowsUpdate Masquerading

Detects creation of a `WindowsUpdate` value under the HKCU Run registry key by a non-system process, the exact persistence mechanism used by CLOSEDQUORUM.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** high

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass -->

```yaml
title: CLOSEDQUORUM Registry Run Key Persistence with WindowsUpdate Masquerading
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: >
  Detects creation of a registry Run key value named WindowsUpdate, matching
  CLOSEDQUORUM persistence mechanism masquerading as a legitimate Windows component.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\Windows'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software using WindowsUpdate as a Run key name
level: high
```

---

#### SIGMA-5: CLOSEDQUORUM LSASS Memory Access

Detects suspicious LSASS process access with debug-level privileges from non-system processes, consistent with CLOSEDQUORUM's `MiniDumpWriteDump`-based credential theft.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** medium

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass. Medium confidence: LSASS access detection is a well-known pattern shared across many credential-dumping tools; this rule is not CLOSEDQUORUM-specific. -->

```yaml
title: CLOSEDQUORUM LSASS Memory Access
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: experimental
description: >
  Detects a process accessing LSASS memory with debug privileges, consistent
  with CLOSEDQUORUM credential theft via MiniDumpWriteDump.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
    filter_known:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\csrss.exe'
            - '\lsass.exe'
            - '\svchost.exe'
    condition: selection and not filter_known
falsepositives:
    - Legitimate security tools performing memory diagnostics
level: critical
```

LSASS access patterns are shared across many credential-dumping tools; correlate with other CLOSEDQUORUM indicators for higher fidelity.

---

#### SIGMA-6: CLOSEDQUORUM ETW Bypass via Process Tampering

Detects process image tampering events indicative of the ETW bypass technique where CLOSEDQUORUM overwrites `EtwEventWrite` with a RET instruction.

**Status:** ✅ compiles (Splunk + LogScale) | **Confidence:** medium

<!-- audit: sigma convert --without-pipeline -t splunk => pass; sigma convert --without-pipeline -t log_scale => pass. Medium confidence: process_tampering events are generic; the ETW patching itself is not uniquely fingerprintable at Sigma level. -->

```yaml
title: CLOSEDQUORUM ETW Bypass via Process Tampering
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: experimental
description: >
  Detects suspicious process tampering consistent with ETW bypass techniques used
  by CLOSEDQUORUM, where EtwEventWrite is overwritten with a RET instruction.
references:
    - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
author: Actioner DRAFT
date: 2026-09-22
tags:
    - attack.defense_evasion
    - attack.t1685
logsource:
    category: process_tampering
    product: windows
detection:
    selection:
        Type: 'Image is tampered'
    filter_known:
        Image|endswith:
            - '\MsMpEng.exe'
            - '\MsSense.exe'
    condition: selection and not filter_known
falsepositives:
    - Endpoint protection products performing memory patching
level: high
```

---

### YARA Rules

#### YARA-1: CLOSEDQUORUM AI C2 Implant

Detects CLOSEDQUORUM binaries by matching combinations of embedded LLM system prompts, Go DWARF function symbols (`ModelOrchestrator`, `interModelDiscussion`, `lsassDump`, etc.), LLM API provider domain strings, and decision schema field names within large Go PE files.

**Status:** ✅ compiles (yarac) | **Confidence:** high

<!-- audit: yarac closedquorum.yar /dev/null => exit 0 after fixing unreferenced $exfil1 by adding condition branch -->

```yara
rule CLOSEDQUORUM_AI_C2_Implant
{
    meta:
        description = "Detects CLOSEDQUORUM autonomous AI C2 implant - Go binary with LLM quorum voting mechanism"
        author = "Actioner DRAFT"
        date = "2026-09-22"
        reference = "https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/"
        hash1 = "250d4fa37488af9b025333fa17705573d721467b203765bc360890b4f5a90cd7"
        hash2 = "c4dc171f2513fcaf9d5ecc815a94aee4063b213ab380f80bd3ac422dee5205a7"
        hash3 = "c13cea04f598e2b0c248d603a6e31bd13aabb64d8149c1b6a77b64e0b983a86f"
        hash4 = "f5f1f8c3e7b883793800ab6ccf21b3e60bd0730f300b4595fe74a33adc17a63c"
        hash5 = "5191cf625dfc209a347f137b50aea199e82040fd5ee9086fb3e2de73c133f3cb"
        hash6 = "eddbd0ecf7195d38fefae5b9d393abfa79e6f3f94bde19308ecef130a05a42e5"
        confidence = "high"

    strings:
        $prompt1 = "You are an advanced malware strategist" ascii wide
        $prompt2 = "Provide ONLY executable decisions" ascii wide

        $func1 = "main.ModelOrchestrator" ascii
        $func2 = "main.interModelDiscussion" ascii
        $func3 = "main.queryLLM" ascii
        $func4 = "main.lsassDump" ascii
        $func5 = "main.dumpBrowserCredentials" ascii
        $func6 = "main.extractCryptoWallets" ascii
        $func7 = "main.sendToDiscord" ascii
        $func8 = "main.earlyBirdInject" ascii
        $func9 = "main.injectProcess" ascii
        $func10 = "main.generateShellcode" ascii
        $func11 = "main.establishPersistence" ascii
        $func12 = "main.gatherSystemInfo" ascii

        $api1 = "api.deepseek.com" ascii wide
        $api2 = "api.mistral.ai" ascii wide
        $api3 = "openrouter.ai" ascii wide

        $schema1 = "target_process" ascii
        $schema2 = "exploit_type" ascii
        $schema3 = "evasion_method" ascii
        $schema4 = "payload_config" ascii

        $key1 = "deepseekAPIKey" ascii
        $key2 = "geminiAPIKey" ascii

        $exfil1 = "cdn.discordapp.com" ascii wide
        $exfil2 = "dummy_webhook_url" ascii

        $cap1 = "steal" ascii
        $cap2 = "inject" ascii
        $cap3 = "persist" ascii
        $cap4 = "consensus" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 10MB and
        (
            (1 of ($prompt*)) or
            (3 of ($func*)) or
            (2 of ($api*) and 1 of ($func*)) or
            (2 of ($schema*) and 1 of ($api*)) or
            (1 of ($key*) and 1 of ($api*)) or
            (1 of ($exfil*) and 2 of ($func*)) or
            (all of ($cap*) and 1 of ($api*))
        )
}

rule CLOSEDQUORUM_Go_Symbols
{
    meta:
        description = "Detects CLOSEDQUORUM via distinctive Go DWARF function name combinations"
        author = "Actioner DRAFT"
        date = "2026-09-22"
        reference = "https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/"
        confidence = "high"

    strings:
        $s1 = "main.ModelOrchestrator" ascii
        $s2 = "main.interModelDiscussion" ascii
        $s3 = "main.queryLLM" ascii
        $s4 = "main.lsassDump" ascii
        $s5 = "main.sendToDiscord" ascii
        $s6 = "main.earlyBirdInject" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 10MB and
        4 of them
}
```

---

### Snort Rules

#### SNORT-1: CLOSEDQUORUM LLM C2 System Prompt

Detects the CLOSEDQUORUM system prompt string "You are an advanced malware strategist" in HTTP traffic, which would be visible via TLS inspection.

**Status:** ✅ compiles (snort -T) | **Confidence:** high

<!-- audit: snort -c /etc/snort/snort.conf -R cq.rules -T => "Snort successfully validated the configuration!" -->

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CLOSEDQUORUM LLM C2 System Prompt in HTTPS Payload"; flow:established,to_server; content:"You are an advanced malware strategist"; nocase; content:"executable decisions"; nocase; distance:0; within:100; classtype:trojan-activity; sid:1000001; rev:1;)
```

Requires TLS interception/decryption to inspect HTTPS payload content.

---

#### SNORT-2--4: CLOSEDQUORUM DNS Queries to LLM Providers

Detects DNS queries to the three LLM API provider domains used by CLOSEDQUORUM's quorum mechanism.

**Status:** ✅ compiles (snort -T) | **Confidence:** high

<!-- audit: all three DNS rules validated in single snort -T pass -->

```
alert dns $HOME_NET any -> any 53 (msg:"CLOSEDQUORUM DNS Query to DeepSeek API"; content:"|03|api|08|deepseek|03|com|00|"; nocase; classtype:trojan-activity; sid:1000002; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"CLOSEDQUORUM DNS Query to Mistral API"; content:"|03|api|07|mistral|02|ai|00|"; nocase; classtype:trojan-activity; sid:1000003; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"CLOSEDQUORUM DNS Query to OpenRouter AI"; content:"|0a|openrouter|02|ai|00|"; nocase; classtype:trojan-activity; sid:1000004; rev:1;)
```

Individual DNS rules are low-signal alone; correlate all three firing from the same source within a time window.

---

### Suricata Rules

#### SURICATA-1--3: CLOSEDQUORUM DNS Queries to LLM Providers

Detects DNS queries to the three LLM API provider domains using Suricata's `dns.query` sticky buffer.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: suricata -T -S closedquorum_suricata.rules => "Configuration provided was successfully loaded. Exiting." -->

```
alert dns $HOME_NET any -> any any (msg:"CLOSEDQUORUM DNS Query to DeepSeek API"; dns.query; content:"api.deepseek.com"; nocase; classtype:trojan-activity; sid:3000001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"CLOSEDQUORUM DNS Query to Mistral API"; dns.query; content:"api.mistral.ai"; nocase; classtype:trojan-activity; sid:3000002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"CLOSEDQUORUM DNS Query to OpenRouter AI"; dns.query; content:"openrouter.ai"; nocase; classtype:trojan-activity; sid:3000003; rev:1;)
```

---

#### SURICATA-4: CLOSEDQUORUM LLM Quorum Prompt

Detects the embedded system prompt in HTTP request bodies directed to LLM API endpoints.

**Status:** ✅ compiles (suricata -T) | **Confidence:** high

<!-- audit: validated in same suricata -T pass -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CLOSEDQUORUM LLM Quorum Prompt Detected"; flow:established,to_server; http.request_body; content:"You are an advanced malware strategist"; nocase; classtype:trojan-activity; sid:3000004; rev:1;)
```

Requires TLS interception to inspect HTTP request body content.

---

#### SURICATA-5: CLOSEDQUORUM Discord Webhook Exfiltration

Detects HTTP requests to Discord webhook API endpoints, the exfiltration channel used by CLOSEDQUORUM.

**Status:** ✅ compiles (suricata -T) | **Confidence:** medium

<!-- audit: validated in same suricata -T pass. Medium confidence: Discord webhooks are used by many legitimate applications; correlate with other indicators. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CLOSEDQUORUM Discord Webhook Exfiltration"; flow:established,to_server; http.host; content:"discord.com"; http.uri; content:"/api/webhooks/"; classtype:trojan-activity; sid:3000005; rev:1;)
```

Discord webhook traffic is common in legitimate applications; correlate with LLM API DNS queries from the same host.

---

## Sources

- [Cisco Talos -- The Closed Quorum: Inside the First Reported Autonomous AI C2 Implant](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/) (September 22, 2026)
- [Cisco Talos -- Introducing CAIRN: Frontier Tracking for AI-Integrated Malware](https://blog.talosintelligence.com/) (September 22, 2026)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
