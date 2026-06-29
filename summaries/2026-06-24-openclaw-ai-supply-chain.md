<!-- revision: 2026-06-24T2 — (1) Sigma Rule 1: renamed filter_main to selection_ioc per Sigma naming convention (filter_ prefix reserved for exclusions); (2) Sigma Rule 3: added caveat that FileSize|gte requires custom field mapping (not official Sigma spec), marked compile status as warning; (3) Sigma Rule 5: removed 'node' from ParentImage|contains to reduce false positives in Node.js environments; (4) YARA Rule 1: tightened condition from 'any of them' to require curl+bash combo or 2+ domain IOC strings; (5) YARA Rule 3: changed 'any of them' to '2 of them' to prevent single-IOC matches in threat intel documents; (6) added this revision comment. -->
# Technical Analysis Report: OpenClaw AI Supply Chain (2026-06-24)
Prepared by: Actioner
Date: 2026-06-24

## Executive Summary

Malicious skills published to ClawHub, the official marketplace for the OpenClaw AI agent framework, have been weaponized to distribute macOS infostealers (AMOS, cluw), conduct affiliate injection fraud, and orchestrate coordinated cryptocurrency front-running schemes. Unit 42 researchers identified five distinct malicious skills that evaded both VirusTotal and ClawScan security controls using techniques including 22 MB file-padding evasion, paste-site redirect lures, base64-encoded curl-pipe-bash droppers, and semantic instruction hijacking. The campaign is part of the broader "ClawHavoc" operation, which has grown from 341 to over 824 confirmed malicious skills across 10,700+ entries in the ClawHub registry. The AMOS C2 infrastructure at `91.92.242[.]30` remained active for more than three months after initial public disclosure, indicating persistent threat actor operations. An estimated 26,000 agents were affected, including agents on corporate accounts.

## Background

OpenClaw is an open-source AI agent framework whose third-party skills are distributed through ClawHub, a dedicated marketplace. Skills are markdown-driven packages with broad local system access, making ClawHub a critical supply chain link in the agentic software ecosystem. Unlike traditional package supply chain attacks (e.g., npm/PyPI typosquatting), OpenClaw's attack surface is unique: malicious skills exploit semantic instruction hijacking -- manipulating the AI agent's natural language interpretation rather than conventional code-level exploits -- to bypass runtime isolation assumptions.

In February 2026, Koi Security audited all 2,857 ClawHub skills and identified 341 malicious entries; Bitdefender independently estimated approximately 17% of analyzed skills carried malicious payloads. Despite ClawHub deploying VirusTotal integration (early February) and ClawScan code analysis (mid-February), five skills remained unblocked through May 2026 by exploiting detection gaps.

The Hacker News separately reported a related campaign where a skill named `brand-landingpage` was merged into a popular repository, inheriting its trust signals (~36,000 stars), then used post-installation payload swapping via external documentation links to redirect agents to malicious endpoints. The attacker (tracked as "AIR") claimed approximately 26,000 compromised agents including corporate deployments.

## Technical Analysis of the Malicious Payload

### Threat Category 1: Infostealers (cluw / AMOS)

Two skills (`ai-tradingview-assistant-for-macos`, `tradingview-ai-indicator-assistant`) delivered the **cluw** macOS infostealer through a multi-stage delivery chain:

1. **Prerequisite Block Lure**: The malicious skill contains a fake "prerequisite installation" section directing the AI agent to visit paste-site URLs.
2. **Paste-Site Redirect**: Intermediary sites (`rentry[.]co/openclaw-code`, `glot[.]io/snippets/hfd3x9ueu5`) serve terminal commands that the agent copies and executes.
3. **Curl-Pipe-Bash Dropper**: Base64-encoded `curl | bash` commands fetch payloads from `2.26.75[.]16`.
4. **C2 Communication**: Stolen credentials (browser passwords, keychain data, cryptocurrency wallets, SSH keys, API tokens) are exfiltrated to `91.92.242[.]30` (known AMOS infrastructure).
5. **Persistence**: Cron jobs are registered to maintain C2 channels even after skill removal.

The `omnicogg` skill uses an additional evasion technique: a 22 MB padding block of null/whitespace characters appended to README.md, inflating file size beyond content-analysis pipeline processing thresholds to evade scanner detection.

**Platform-specific delivery**:
- **macOS**: Base64-encoded shell commands from glot[.]io executed in Terminal
- **Windows**: Password-protected ZIP archives hosted on GitHub (bypassing AV scanning)

### Threat Category 2: Affiliate Injection

The `money-radar` skill performs runtime affiliate injection:

1. Skill fetches referral link configuration from `laosji[.]net/referrals.json` at runtime.
2. The AI agent's recommendations are dynamically manipulated to include attacker-controlled affiliate links.
3. The agent provides financially incentivized product/service recommendations to unsuspecting users.

### Threat Category 3: Front-Running Financial Fraud

The `letssendit` skill orchestrates coordinated cryptocurrency front-running:

1. The agent joins a coordination pool at `letssendit[.]fun`.
2. SOL (Solana) is pooled from multiple compromised agents.
3. The operator front-runs meme token launches on `pump[.]fun`.
4. Artificial demand is created, followed by rug-pull execution.

### Threat Category 4: Credential Exfiltration

Malicious skills target `~/.clawdbot/.env` (OpenClaw bot credentials file) for exfiltration to webhook services and Telegram Bot API endpoints for cryptocurrency private key theft.

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| IP | `91.92.242[.]30` | AMOS C2 infrastructure (persistent) |
| IP | `2.26.75[.]16` | cluw infostealer payload delivery server |
| Domain | `laosji[.]net` | Affiliate injection payload source |
| Domain | `letssendit[.]fun` | Front-running scheme coordination |
| Domain | `download.setup-service[.]com` | Malware distribution |
| Domain | `install.app-distribution[.]net` | Malware distribution |
| Domain | `openclawcli.vercel[.]app` | Distribution endpoint |
| URL | `rentry[.]co/openclaw-code` | Paste-site redirect lure |
| URL | `glot[.]io/snippets/hfd3x9ueu5` | Paste-site intermediary |
| URL | `github[.]com/Ddoy233/openclawcli` | Malicious repository |

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7` | cluw macOS infostealer |
| `881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7` | Associated payload |
| `b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2` | omnicogg (AMOS dropper with padding) |
| `b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007` | ai-tradingview-assistant-for-macos |
| `ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d` | money-radar affiliate injection |
| `f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e` | letssendit front-running |

### Malicious Skill Names

| Skill Name | Category |
|------------|----------|
| `ai-tradingview-assistant-for-macos` | Infostealer (cluw) |
| `tradingview-ai-indicator-assistant` | Infostealer (cluw) |
| `omnicogg` | AMOS dropper (padded evasion) |
| `money-radar` | Affiliate injection |
| `letssendit` | Front-running fraud |
| `santi-text-game` | Suspected malicious |
| `pdfcheck` | Suspected malicious |
| `update` | Suspected malicious |
| `wistec-core` | Suspected malicious |
| `brand-landingpage` | Post-install payload swap |

### Host Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| File Path | `~/.clawdbot/.env` | Targeted credential file |
| Behavior | Cron job creation by OpenClaw-spawned processes | Persistence mechanism |
| Behavior | README.md files exceeding 20 MB | Scanner evasion padding |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|--------------|----------------|---------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious skills in ClawHub marketplace |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Curl-pipe-bash dropper execution |
| T1140 | Deobfuscate/Decode Files or Information | Base64-encoded dropper payloads |
| T1027.001 | Obfuscated Files or Information: Binary Padding | 22 MB padding in README.md |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication |
| T1552.001 | Unsecured Credentials: Credentials in Files | Targeting ~/.clawdbot/.env |
| T1053.003 | Scheduled Task/Job: Cron | Persistence via cron job registration |
| T1567 | Exfiltration Over Web Service | Data exfiltration via Telegram Bot API |
| T1185 | Browser Session Hijacking | Affiliate link injection at runtime |
| T1565.003 | Data Manipulation: Runtime Data Manipulation | Semantic instruction hijacking of agent responses |

## Detection & Remediation

### Detection Opportunities

1. **Network Monitoring**: Alert on connections to known C2 IPs (`91.92.242[.]30`, `2.26.75[.]16`) and malicious domains.
2. **Process Monitoring**: Detect curl-pipe-bash execution patterns originating from OpenClaw agent processes.
3. **File Monitoring**: Flag README.md files exceeding 20 MB (padding evasion) and unauthorized access to `~/.clawdbot/.env`.
4. **Scheduled Task Monitoring**: Detect cron job creation by processes in the OpenClaw process tree.

### Remediation Steps

1. Audit all installed OpenClaw skills against the malicious skill name list.
2. Remove any identified malicious skills and verify no cron job persistence remains.
3. Rotate all credentials stored in `~/.clawdbot/.env` and any browser-stored passwords.
4. Block IOC domains/IPs at network perimeter.
5. Review Solana wallet activity if `letssendit` skill was installed.
6. Monitor for post-removal C2 callbacks from persisted cron jobs.

## Detection Rules

### Sigma Rule 1: OpenClaw Curl-Pipe-Bash Dropper Execution

Detects the curl-pipe-bash dropper pattern with specific OpenClaw campaign IOCs in command line arguments.

**Compile Status**: ✅ Compiles (Splunk, LogScale) | **Confidence**: High (IOC-specific)

```yaml
title: OpenClaw Malicious Skill - Curl Pipe Bash Dropper Execution
id: ce5e1b37-30a4-4b4b-94cb-91e65ba0a8eb
status: experimental
description: Detects curl-pipe-bash dropper pattern associated with OpenClaw ClawHub malicious skills delivering AMOS and cluw infostealers via paste-site intermediaries.
references:
    - https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
author: Actioner
date: 2026/06/24
tags:
    - attack.execution
    - attack.t1059.004
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: macos
detection:
    selection_curl_bash:
        CommandLine|contains|all:
            - 'curl'
            - 'bash'
    selection_ioc:
        CommandLine|contains:
            - 'glot.io/snippets'
            - 'rentry.co/openclaw'
            - '91.92.242.30'
            - '2.26.75.16'
    condition: selection_curl_bash and selection_ioc
falsepositives:
    - Legitimate developer scripts fetching from paste sites (unlikely with these specific indicators)
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; sigma check failed due to MITRE STIX data download timeout (IncompleteRead), not a rule syntax issue -->

---

### Sigma Rule 2: OpenClaw AMOS Infostealer C2 Communication

Detects network connections to known C2 infrastructure IPs and malicious domains associated with the OpenClaw campaign.

**Compile Status**: ✅ Compiles (Splunk, LogScale) | **Confidence**: High (IOC-specific)

```yaml
title: OpenClaw AMOS Infostealer C2 Communication
id: dee7a844-559b-465e-92da-164957ce555d
status: experimental
description: Detects network connections to known C2 infrastructure associated with the OpenClaw ClawHub supply chain attack delivering AMOS and cluw infostealers.
references:
    - https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
author: Actioner
date: 2026/06/24
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: network_connection
    product: macos
detection:
    selection_c2_ip:
        DestinationIp:
            - '91.92.242.30'
            - '2.26.75.16'
    selection_c2_domain:
        DestinationHostname|endswith:
            - 'laosji.net'
            - 'letssendit.fun'
            - 'setup-service.com'
            - 'app-distribution.net'
    condition: selection_c2_ip or selection_c2_domain
falsepositives:
    - Unlikely
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; sigma check failed due to MITRE STIX data download timeout, not a rule syntax issue -->

---

### Sigma Rule 3: OpenClaw Oversized README Evasion Technique

Detects creation of README.md files exceeding 20 MB, consistent with the padding evasion technique used by the omnicogg AMOS dropper.

**Compile Status**: ⚠️ Compiles (Splunk, LogScale) but requires custom field mapping | **Confidence**: Medium (TTP-based; legitimate large README files are rare but possible)

> **Caveat**: The `FileSize|gte` modifier is not part of the official Sigma specification. This rule requires a custom field mapping for `FileSize` in your SIEM pipeline. Most file-event log sources (Sysmon EventID 11, macOS Endpoint Security Framework) do not natively populate a `FileSize` field. Implementers must enrich file-event telemetry with file size data or use a SIEM-native approach (e.g., Splunk `eval` on indexed metadata) and adapt the detection logic accordingly.

```yaml
title: OpenClaw Oversized README Evasion Technique
id: 8394d205-1880-4f8e-84e7-bdb11efa23f1
status: experimental
description: Detects creation of abnormally large README files used by OpenClaw malicious skills to evade scanner processing thresholds via 22MB+ padding.
references:
    - https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
author: Actioner
date: 2026/06/24
tags:
    - attack.defense_evasion
    - attack.t1027.001
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|endswith:
            - '/README.md'
        FileSize|gte: 20000000
    condition: selection
falsepositives:
    - Legitimate large README files in data-heavy repositories (rare at 20MB+)
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; TTP-based rule capped at medium confidence; FileSize|gte is NOT an official Sigma modifier -- requires custom field mapping; FileSize field availability depends on log source -->

---

### Sigma Rule 4: OpenClaw Bot Credentials File Access

Detects unauthorized access to the OpenClaw bot credentials file targeted for exfiltration by malicious skills.

**Compile Status**: ✅ Compiles (Splunk, LogScale) | **Confidence**: Medium (TTP-based; requires file access monitoring)

```yaml
title: OpenClaw Bot Credentials File Access
id: 99809c9b-a35e-478e-a9e2-1e852e59c8e1
status: experimental
description: Detects unauthorized access to OpenClaw bot credentials file (.clawdbot/.env) which is targeted by malicious skills for exfiltration.
references:
    - https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
    - https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/
author: Actioner
date: 2026/06/24
tags:
    - attack.credential_access
    - attack.t1552.001
logsource:
    category: file_access
    product: macos
detection:
    selection:
        TargetFilename|contains: '.clawdbot/.env'
    filter_legitimate:
        Image|endswith:
            - '/openclaw'
            - '/claw'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate OpenClaw configuration reads by the official client
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; TTP-based rule capped at medium; requires endpoint file access telemetry (e.g., Sysmon for macOS / Endpoint Security Framework) -->

---

### Sigma Rule 5: OpenClaw Malicious Skill Cron Job Persistence

Detects cron job creation by processes in the OpenClaw process tree, used for maintaining C2 channels after skill removal.

**Compile Status**: ✅ Compiles (Splunk, LogScale) | **Confidence**: Medium (TTP-based; legitimate auto-updater skills may trigger)

```yaml
title: OpenClaw Malicious Skill Cron Job Persistence
id: e7fcacee-bb63-4979-b057-374e25a1e6b5
status: experimental
description: Detects cron job creation by processes associated with OpenClaw skill execution, used by malicious skills for persistence and maintaining C2 channels.
references:
    - https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
author: Actioner
date: 2026/06/24
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    category: process_creation
    product: macos
detection:
    selection_crontab:
        Image|endswith: '/crontab'
        CommandLine|contains: '-'
    selection_parent:
        ParentImage|contains:
            - 'openclaw'
            - 'claw'
    condition: selection_crontab and selection_parent
falsepositives:
    - Legitimate OpenClaw auto-updater skills creating scheduled tasks
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk EXIT:0; sigma convert --without-pipeline -t log_scale EXIT:0; TTP-based rule capped at medium; removed 'node' from ParentImage filter to reduce false positives in Node.js environments -->

---

### YARA Rule 1: OpenClaw AMOS Dropper with Padding Evasion

Detects Mach-O files with oversized padding characteristic of the omnicogg AMOS dropper, or files containing known OpenClaw campaign IOC strings.

**Compile Status**: ✅ Compiles (yarac) | **Confidence**: High (hash-anchored + IOC-specific)

```yara
rule OpenClaw_AMOS_Dropper_Padded {
    meta:
        description = "Detects AMOS dropper with padding evasion technique used in OpenClaw ClawHub supply chain attack"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2"

    strings:
        $curl_bash = "curl" ascii wide
        $pipe_bash = "| bash" ascii wide
        $glot = "glot.io/snippets" ascii wide
        $rentry = "rentry.co/openclaw" ascii wide
        $setup_service = "setup-service.com" ascii wide
        $app_dist = "app-distribution.net" ascii wide

    condition:
        filesize > 20MB and (($curl_bash and $pipe_bash) or 2 of ($glot*, $rentry*, $setup_service*, $app_dist*))
}
```

<!-- audit: yarac /tmp/actioner/openclaw_amos_dropper.yar /dev/null EXIT:0; tightened condition from 'any of them' to require curl+bash combo or 2+ domain/URL IOC strings to reduce false positives on large benign files -->

---

### YARA Rule 2: OpenClaw Cluw Infostealer

Detects macOS Mach-O binaries containing multiple C2/distribution domain indicators associated with the cluw infostealer.

**Compile Status**: ✅ Compiles (yarac) | **Confidence**: High (hash-anchored + multi-IOC condition)

```yara
rule OpenClaw_Cluw_Infostealer {
    meta:
        description = "Detects cluw macOS infostealer payload distributed via OpenClaw ClawHub malicious skills"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7"

    strings:
        $c2_ip1 = "2.26.75.16" ascii wide
        $c2_ip2 = "91.92.242.30" ascii wide
        $domain1 = "laosji.net" ascii wide
        $domain2 = "letssendit.fun" ascii wide
        $domain3 = "setup-service.com" ascii wide
        $domain4 = "app-distribution.net" ascii wide
        $ua = "openclawcli" ascii wide

    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and
        (2 of ($c2_ip*, $domain*) or $ua)
}
```

<!-- audit: yarac /tmp/actioner/openclaw_amos_dropper.yar /dev/null EXIT:0; Mach-O magic bytes condition limits scope to macOS binaries -->

---

### YARA Rule 3: OpenClaw Malicious Skill IOC Indicators

Broad sweep rule matching any known IOC string from the OpenClaw campaign in arbitrary files (skills, scripts, configs).

**Compile Status**: ✅ Compiles (yarac) | **Confidence**: High (IOC-specific strings)

```yara
rule OpenClaw_Malicious_Skill_Indicators {
    meta:
        description = "Detects OpenClaw malicious skill files containing known IOC patterns from the ClawHub supply chain attack"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/"
        hash = "ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d"

    strings:
        $glot_snippet = "glot.io/snippets/hfd3x9ueu5" ascii wide
        $rentry_lure = "rentry.co/openclaw-code" ascii wide
        $c2_1 = "91.92.242.30" ascii wide
        $c2_2 = "2.26.75.16" ascii wide
        $dropper_domain1 = "download.setup-service.com" ascii wide
        $dropper_domain2 = "install.app-distribution.net" ascii wide
        $laosji = "laosji.net" ascii wide
        $letssendit = "letssendit.fun" ascii wide
        $vercel = "openclawcli.vercel.app" ascii wide

    condition:
        2 of them
}
```

<!-- audit: yarac /tmp/actioner/openclaw_amos_dropper.yar /dev/null EXIT:0; changed from 'any of them' to '2 of them' to prevent single-IOC-string matches in threat intel documents -->

---

### Snort Rules: OpenClaw C2 and Malware Distribution

Six Snort rules covering C2 IP communication, affiliate injection domains, paste-site dropper URLs, and malware distribution domains.

**Compile Status**: ⚠️ Uncompiled (structural check only -- no Snort compiler available) | **Confidence**: High (IOC-specific)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw AMOS Infostealer C2 Communication to 91.92.242.30"; content:"91.92.242.30"; sid:2100001; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Cluw Infostealer Payload Server 2.26.75.16"; content:"2.26.75.16"; sid:2100002; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE OpenClaw Affiliate Injection Domain laosji.net"; content:"laosji.net"; http_header; nocase; sid:2100003; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE OpenClaw Front-Running Coordination Domain letssendit.fun"; content:"letssendit.fun"; http_header; nocase; sid:2100004; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE OpenClaw Paste-Site Dropper via glot.io"; content:"glot.io"; content:"/snippets/hfd3x9ueu5"; distance:0; http_uri; sid:2100005; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE OpenClaw Malware Distribution Domain setup-service.com"; content:"setup-service.com"; http_header; nocase; sid:2100006; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/;)
```

<!-- audit: no Snort compiler available in environment; rules follow standard Snort 2.x/3.x syntax with proper sid/rev/classtype/reference fields; structural review only -->

---

### Suricata Rules: OpenClaw C2 and Malware Distribution

Nine Suricata rules using dot-notation sticky buffers for HTTP host/URI matching, plus IP-based rules for direct C2 detection.

**Compile Status**: ✅ Compiles (suricata -T) | **Confidence**: High (IOC-specific)

```
alert ip $HOME_NET any -> 91.92.242.30 any (msg:"MALWARE OpenClaw AMOS C2 to 91.92.242.30"; sid:2200001; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert ip $HOME_NET any -> 2.26.75.16 any (msg:"MALWARE OpenClaw Cluw Payload Server 2.26.75.16"; sid:2200002; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Affiliate Injection to laosji.net"; http.host; content:"laosji.net"; sid:2200003; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Front-Running Coordination letssendit.fun"; http.host; content:"letssendit.fun"; sid:2200004; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Dropper Paste-Site glot.io Snippet"; http.host; content:"glot.io"; http.uri; content:"/snippets/hfd3x9ueu5"; sid:2200005; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Malware Distribution setup-service.com"; http.host; content:"setup-service.com"; sid:2200006; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Malware Distribution app-distribution.net"; http.host; content:"app-distribution.net"; sid:2200007; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Vercel Distribution Endpoint"; http.host; content:"openclawcli.vercel.app"; sid:2200008; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE OpenClaw Rentry Paste-Site Lure"; http.host; content:"rentry.co"; http.uri; content:"/openclaw-code"; sid:2200009; rev:1; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/; metadata: author Actioner;)
```

<!-- audit: suricata -T -S /tmp/actioner/openclaw_c2_suricata.rules -l /tmp/actioner EXIT:0; initial version used invalid 'dst_ip' keyword, fixed to use destination IP in rule header; all 9 rules validated successfully -->

## Sources

- [Unit 42 - OpenClaw's Skill Marketplace and the Emerging AI Supply Chain Threat](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/)
- [The Hacker News - Fake AI Agent Skill Passed Security](https://thehackernews.com/2026/06/fake-ai-agent-skill-passed-security.html)
- [eSecurity Planet - Hundreds of Malicious Skills Found in OpenClaw's ClawHub](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)
- [Sangfor - OpenClaw Security Risks: From Vulnerabilities to Supply Chain Abuse](https://www.sangfor.com/blog/cybersecurity/openclaw-ai-agent-security-risks-2026)
- [Hive Security - OpenClaw: How the Viral AI Agent Became 2026's First Major Security Crisis](https://hivesecurity.gitlab.io/blog/openclaw-ai-agent-security-crisis-2026/)
- [PointGuard AI - OpenClaw ClawHub Malicious Skills Supply Chain Attack](https://www.pointguardai.com/ai-security-incidents/openclaw-clawhub-malicious-skills-supply-chain-attack)

---
*Report generated by Actioner*
