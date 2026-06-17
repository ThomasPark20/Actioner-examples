# Malicious JetBrains Marketplace Plugins Stealing AI API Keys

<!-- revision: 2026-06-17 REVISE pass — applied all critic fixes:
     1. Sigma Rule 1: cs-uri → c-uri, cs-User-Agent → c-useragent in fields; condition tightened to AND all three selections; ATT&CK tag corrected to attack.t1552
     2. Sigma Rule 2: level elevated to critical for consistency with Rule 3
     3. Sigma Rule 3: T1555 → T1552, T1176 → T1554
     4. ATT&CK table: T1555 → T1552 (Unsecured Credentials); T1176 → T1554 (Compromise Client Software Binary), kept T1176 only for PromptSnatcher
     5. YARA Rule 1: added filesize < 50MB; first branch now requires $auth_token; removed $key_length_check (dead weight in compiled JARs); last branch uses $auth_token instead of $key_length_check
     6. Remediation: defanged IP 39.107.60.51 → 39.107.60[.]51
     7. Suricata note added re: live IPs in rules
     8. Sigma tactic tags fixed to hyphenated form (attack.credential-access, attack.command-and-control)
     Re-validation: sigma check 0 errors/0 issues; sigma convert splunk PASS; sigma convert log_scale PASS; yarac PASS; suricata -T PASS
-->

**Date:** 2026-06-17
**Status:** FINAL
**TLP:** CLEAR
**Severity:** HIGH

---

## Executive Summary

A coordinated supply-chain campaign deployed at least 15 malicious plugins on the JetBrains Marketplace across seven vendor accounts, accumulating approximately 70,000 installations. The plugins masquerade as AI coding assistants leveraging DeepSeek, OpenAI, and SiliconFlow APIs. When developers enter their API keys into the plugin settings, credentials are silently exfiltrated via plaintext HTTP POST requests to a hardcoded command-and-control server at `39.107.60[.]51`. The operation, discovered by Aikido Security, ran from late October 2025 through at least June 10, 2026, and includes a monetization layer where stolen keys from non-paying users are redistributed to paying users.

A related but distinct campaign, tracked as "PromptSnatcher" (Panel 231), was disclosed concurrently involving two Chrome ad-blocker extensions that intercept AI chatbot conversations from ChatGPT, Claude, Gemini, and other platforms.

---

## Background

JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, etc.) support a plugin marketplace where third-party developers publish extensions. As AI-assisted coding tools have surged in popularity, developers routinely install marketplace plugins that integrate with large language model providers. These plugins typically require the user to input API keys for OpenAI, DeepSeek, or SiliconFlow services. This trust model creates an attractive attack surface: a malicious plugin that provides legitimate AI functionality can silently harvest credentials with no security prompts or consent dialogs.

---

## Timeline

| Date | Event |
|------|-------|
| 2025-10-31 | First malicious plugin ("DeepSeek Junit Test") published |
| 2025-11 to 2026-01 | Eight additional plugins published across multiple vendor accounts |
| 2026-01-15 | "DeepSeek Coder AI" published, achieving 3,498 downloads |
| 2026-04-18 | "DeepSeek Code Review" published |
| 2026-06-09 | "CodeGPT AI Assistant" published (25,571 downloads) |
| 2026-06-10 | "DeepSeek AI Assist" published (27,727 downloads) |
| 2026-06-17 | Aikido Security publishes disclosure; reporting by BleepingComputer, The Hacker News, Hackread, and others |

---

## Root Cause Analysis

The root cause is insufficient vetting of JetBrains Marketplace plugin submissions combined with the inherent trust developers place in marketplace-distributed extensions. The plugins passed marketplace review because they provided legitimate AI coding functionality while concealing credential exfiltration logic within the standard settings `apply()` handler -- a code path that appears benign during review. There is no runtime permission model in JetBrains IDEs that would prompt users before a plugin makes outbound HTTP connections, and the exfiltration uses plaintext HTTP rather than HTTPS, making the credential theft invisible to both the user and most certificate-based inspection tools.

---

## Technical Analysis

### Attack Flow

1. **Distribution:** Plugins published on the official JetBrains Marketplace under seven different vendor accounts to avoid single-account takedown risk.
2. **Installation:** Developers install plugins expecting AI-powered code review, commit message generation, bug finding, or chat functionality.
3. **Credential Entry:** Users enter API keys for OpenAI (`sk-...`), DeepSeek, or SiliconFlow into the plugin's settings dialog.
4. **Exfiltration Trigger:** When the user clicks "Apply" to save settings, the plugin's `apply()` method fires. A filter checks if the key is non-null, starts with `sk-`, and is exactly 51 characters long.
5. **Data Exfiltration:** The key is transmitted via an unencrypted HTTP POST to `http://39.107.60[.]51/api/software/` with a static authentication header `X-Api-Key: F48D2AA7CF341F782C1D`. No user consent prompt or visual indicator accompanies this transmission.
6. **Monetization:** Paying users receive functional API keys from the C2 server (likely keys stolen from other victims), creating a dual-revenue credential resale model.

### Key Code Pattern

The exfiltration filter logic:
```
if (key != null && key.startsWith("sk-") && ks.add(key) && StringUtils.length(key) == 51)
```

### Plugin Distribution Strategy

The attacker used seven vendor accounts (CodePilot, StackSmith, CodeCrafter, CodeWeaver, JetCode, DailyCode, ZenCoder) to distribute plugins, reducing the risk of a single takedown disrupting the operation. Plugin names deliberately reference popular AI brands (DeepSeek, CodeGPT) to attract downloads.

### Related Activity: PromptSnatcher Chrome Extensions

Two Chrome extensions ("Smart Adblocker" and "Adblock for Browser") were disclosed in the same reporting cycle. Tracked as Panel 231 / PromptSnatcher, these extensions intercept AI chatbot conversations from ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Grok, and Meta AI by injecting `shared-page-capture.js` and patching `fetch`, `XMLHttpRequest`, and `WebSocket` APIs. Over 90,000 users were affected.

---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| IPv4 | `39.107.60[.]51` | C2 server (Alibaba Cloud) |
| URI Path | `/api/software/` | Exfiltration endpoint |
| HTTP Header | `X-Api-Key: F48D2AA7CF341F782C1D` | Static C2 authentication token |
| Protocol | HTTP (plaintext, not HTTPS) | Transmission method |

### Malicious Plugin Package IDs

| Plugin Name | Package ID | Downloads |
|---|---|---|
| DeepSeek Junit Test | `org.sm.yms.toolkit` | 1,121 |
| DeepSeek Git Commit | `com.json.simple.kit` | 1,894 |
| DeepSeek FindBugs | `org.bug.find.tools` | 1,485 |
| DeepSeek AI Chat | `org.translate.ai.simple` | 1,317 |
| DeepSeek Dev AI | `com.yy.test.ai.simple` | 740 |
| DeepSeek AI Coding | `com.dev.ai.toolkit` | 450 |
| AI FindBugs | `com.json.view.simple` | 623 |
| AI Git Commitor | `com.my.git.ai.kit` | 301 |
| AI Coder Review | `org.check.ai.ds` | 735 |
| DeepSeek Coder AI | `com.review.tool.code` | 3,498 |
| AI Coder Assistant | `org.code.assist.dev.tool` | 319 |
| DeepSeek Code Review | `com.coder.ai.dpt` | 278 |
| CodeGPT AI Assistant | `com.my.code.tools` | 25,571 |
| DeepSeek AI Assist | `ord.cp.code.ai.kit` | 27,727 |
| Coding Simple Tool | `com.dp.git.ai.tool` | 3,931 |

### Vendor Accounts

| Display Name | Account ID |
|---|---|
| CodePilot | mycode |
| StackSmith | misshewei |
| CodeCrafter | keteme |
| CodeWeaver | simpledev |
| JetCode | skyblue |
| DailyCode | dialycode |
| ZenCoder | 947cb4c8-5db1-4cf0-8182-0aae7c433bb3 |

### Related PromptSnatcher Chrome Extension IOCs

| Extension Name | Chrome Extension ID | Users |
|---|---|---|
| Smart Adblocker | `iojpcjjdfhlcbgjnpngcmaojmlokmeii` | ~90,000 |
| Adblock for Browser | `jcbjcocinigpbgfpnhlpagidbmlngnnn` | ~10,000 |

---

## MITRE ATT&CK Mapping

<!-- revision: T1555 replaced with T1552 (API keys are unsecured credentials, not password-store creds);
     T1176 replaced with T1554 for JetBrains plugins (not browser extensions); T1176 retained only for PromptSnatcher Chrome extensions -->

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Resource Development | Compromise Software Supply Chain | T1195.002 | Malicious plugins published to official JetBrains Marketplace |
| Persistence | Compromise Client Software Binary | T1554 | Malicious plugins persist in JetBrains IDE plugin directories |
| Persistence | Browser Extensions | T1176 | PromptSnatcher Chrome extensions persist in browser (related campaign only) |
| Credential Access | Unsecured Credentials | T1552 | API keys harvested from IDE plugin settings where they are stored without protection |
| Credential Access | Input Capture | T1056 | Key capture via settings apply() handler |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen keys transmitted to C2 via HTTP POST |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST to C2 endpoint |
| Defense Evasion | Masquerading | T1036 | Plugins impersonate legitimate AI tools (DeepSeek, CodeGPT) |

---

## Impact Assessment

- **~70,000 developer installations** across 15 plugins, with potential for API key theft from each installation where credentials were entered.
- **Financial impact:** Stolen API keys incur usage charges to legitimate key owners; attackers monetize through credential resale.
- **Scope of affected services:** OpenAI, DeepSeek, and SiliconFlow API keys targeted.
- **Organizational risk:** Developer workstations with these plugins may have provided API keys linked to corporate accounts with significant usage limits or billing.
- **Supply chain trust:** Erodes confidence in JetBrains Marketplace as a trusted distribution channel.

---

## Detection & Remediation

### Immediate Actions

1. **Audit installed plugins:** Search all JetBrains IDE installations for the 15 malicious package IDs listed above. Check plugin directories typically located at:
   - Windows: `%APPDATA%\JetBrains\<IDE><version>\plugins\`
   - macOS: `~/Library/Application Support/JetBrains/<IDE><version>/plugins/`
   - Linux: `~/.local/share/JetBrains/<IDE><version>/plugins/`
2. **Revoke and rotate API keys:** Any OpenAI, DeepSeek, or SiliconFlow API keys that were entered into affected plugins must be revoked immediately and new keys issued.
3. **Review API usage logs:** Check for unauthorized usage of potentially compromised API keys, particularly from unfamiliar IP ranges.
4. **Block C2 IP:** Add `39.107.60[.]51` to network blocklists (firewall, proxy, DNS sinkhole).
5. **Uninstall malicious plugins** and clear IDE caches.

<!-- revision: defanged IP in remediation step 4 (was fanged 39.107.60.51, now 39.107.60[.]51) -->

### Detection Opportunities

- Monitor proxy/firewall logs for HTTP POST connections to `39.107.60[.]51` or URI path `/api/software/`.
- Alert on JetBrains IDE processes making outbound HTTP (non-HTTPS) connections to non-JetBrains infrastructure.
- Use file integrity monitoring to detect the presence of known malicious package IDs in plugin directories.
- For the PromptSnatcher campaign, audit Chrome extensions for IDs `iojpcjjdfhlcbgjnpngcmaojmlokmeii` and `jcbjcocinigpbgfpnhlpagidbmlngnnn`.

---

## Detection Rules

### Sigma Rule 1: Proxy Log Detection of C2 Communication

<!-- revision: field names corrected (cs-uri → c-uri, cs-User-Agent → c-useragent); condition tightened from
     "selection_dest and (selection_method or selection_uri)" to "selection_dest and selection_method and selection_uri"
     to prevent POST-to-C2-on-any-URI false positives; ATT&CK tag corrected from T1555 to T1552 -->

Detects outbound HTTP POST connections to the known C2 server and exfiltration endpoint used by the malicious plugins. **Status: PASS** (sigma check: 0 errors, 0 condition errors, 0 issues; sigma convert to splunk: PASS; sigma convert to log_scale: PASS).

```yaml
title: Suspicious JetBrains Plugin API Key Exfiltration to Known C2
id: 8e3a7f12-c4d1-4b9e-a3f7-1d2e5c8b9a4f
status: experimental
description: >
    Detects outbound HTTP POST connections from JetBrains IDE processes to the
    known C2 server (39.107.60.51) used by malicious JetBrains Marketplace plugins
    that steal AI API keys (DeepSeek, OpenAI, SiliconFlow). The plugins exfiltrate
    credentials via plaintext HTTP to /api/software/ with a static X-Api-Key header.
references:
    - https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys
    - https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html
author: CTI Analyst (Automated Draft)
date: 2026-06-17
tags:
    - attack.credential-access
    - attack.t1552
    - attack.exfiltration
    - attack.t1041
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_dest:
        dst_ip: '39.107.60.51'
    selection_method:
        cs-method: 'POST'
    selection_uri:
        c-uri|contains: '/api/software/'
    condition: selection_dest and selection_method and selection_uri
fields:
    - src_ip
    - dst_ip
    - c-uri
    - cs-method
    - c-useragent
falsepositives:
    - Legitimate services hosted on 39.107.60.51 (unlikely given Alibaba Cloud IP)
level: high
```

### Sigma Rule 2: Endpoint Detection of JetBrains IDE to C2

<!-- revision: level elevated from high to critical for consistency with Rule 3 (both are high-confidence IOC-based detections) -->

Detects network connections from JetBrains IDE processes to the known C2 IP, useful for Sysmon-based endpoint detection. **Status: PASS** (sigma check: 0 errors, 0 condition errors, 0 issues; sigma convert to splunk: PASS; sigma convert to log_scale: PASS).

```yaml
title: JetBrains IDE Process HTTP Connection to Suspicious Alibaba Cloud IP
id: 2f7b8d3e-a1c5-49f0-b6d8-3e9a7c2f1d5b
status: experimental
description: >
    Detects network connections from JetBrains IDE processes (IntelliJ, PyCharm,
    WebStorm, etc.) to the known C2 IP 39.107.60.51 associated with malicious
    marketplace plugins stealing AI API keys.
references:
    - https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys
    - https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/
author: CTI Analyst (Automated Draft)
date: 2026-06-17
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\idea64.exe'
            - '\idea.exe'
            - '\pycharm64.exe'
            - '\pycharm.exe'
            - '\webstorm64.exe'
            - '\webstorm.exe'
            - '\phpstorm64.exe'
            - '\phpstorm.exe'
            - '\goland64.exe'
            - '\goland.exe'
            - '\clion64.exe'
            - '\clion.exe'
            - '\rider64.exe'
            - '\rider.exe'
            - '\rubymine64.exe'
            - '\rubymine.exe'
            - '\datagrip64.exe'
            - '\datagrip.exe'
    selection_dest:
        DestinationIp: '39.107.60.51'
    condition: selection_process and selection_dest
fields:
    - Image
    - DestinationIp
    - DestinationPort
    - User
falsepositives:
    - Legitimate connections to this specific IP from JetBrains IDEs are highly unlikely
level: critical
```

### Sigma Rule 3: File-Based Detection of Malicious Plugin Package IDs

<!-- revision: ATT&CK tags corrected from T1555 → T1552, T1176 → T1554 -->

Detects the presence of known malicious plugin package IDs in the filesystem, indicating installation of compromised plugins. **Status: PASS** (sigma check: 0 errors, 0 condition errors, 0 issues; sigma convert to splunk: PASS; sigma convert to log_scale: PASS).

```yaml
title: Malicious JetBrains Plugin Package ID in Plugin Directory
id: 4a9c1e6f-d3b2-48a7-9e5c-7f1a3b8d2c6e
status: experimental
description: >
    Detects the presence of known malicious JetBrains plugin package IDs on disk,
    indicating a compromised IDE installation with plugins that exfiltrate AI API keys.
references:
    - https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys
    - https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html
author: CTI Analyst (Automated Draft)
date: 2026-06-17
tags:
    - attack.credential-access
    - attack.t1552
    - attack.persistence
    - attack.t1554
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - 'org.sm.yms.toolkit'
            - 'com.json.simple.kit'
            - 'org.bug.find.tools'
            - 'org.translate.ai.simple'
            - 'com.yy.test.ai.simple'
            - 'com.dev.ai.toolkit'
            - 'com.json.view.simple'
            - 'com.my.git.ai.kit'
            - 'org.check.ai.ds'
            - 'com.review.tool.code'
            - 'org.code.assist.dev.tool'
            - 'com.coder.ai.dpt'
            - 'com.my.code.tools'
            - 'ord.cp.code.ai.kit'
            - 'com.dp.git.ai.tool'
    condition: selection
fields:
    - TargetFilename
    - Image
    - User
falsepositives:
    - None expected; these are known malicious plugin identifiers
level: critical
```

### YARA Rule: Malicious Plugin Binary Detection

<!-- revision: (1) added filesize < 50MB constraint; (2) first condition branch now requires $auth_token
     (was "$c2_ip and $c2_endpoint" alone — overly loose); (3) removed $key_length_check string
     ("StringUtils.length(key) == 51") — Java source won't appear in compiled JARs, dead weight;
     (4) last branch replaced $key_length_check with $auth_token -->

Identifies malicious JetBrains plugin binaries by matching the C2 IP, exfiltration endpoint, and static authentication token embedded in the plugin JAR files. **Status: PASS** (yarac compile: exit code 0).

```yara
rule JetBrains_Malicious_Plugin_APIKeyTheft
{
    meta:
        description = "Detects malicious JetBrains plugins that exfiltrate AI API keys to C2 server 39.107.60.51"
        author = "CTI Analyst (Automated Draft)"
        date = "2026-06-17"
        reference = "https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys"
        severity = "high"

    strings:
        $c2_ip = "39.107.60.51" ascii wide
        $c2_endpoint = "/api/software/" ascii wide
        $auth_token = "F48D2AA7CF341F782C1D" ascii wide
        $header_key = "X-Api-Key" ascii wide
        $sk_prefix = "sk-" ascii

        $pkg_id1 = "org.sm.yms.toolkit" ascii
        $pkg_id2 = "com.json.simple.kit" ascii
        $pkg_id3 = "org.bug.find.tools" ascii
        $pkg_id4 = "org.translate.ai.simple" ascii
        $pkg_id5 = "com.yy.test.ai.simple" ascii
        $pkg_id6 = "com.dev.ai.toolkit" ascii
        $pkg_id7 = "com.json.view.simple" ascii
        $pkg_id8 = "com.my.git.ai.kit" ascii
        $pkg_id9 = "org.check.ai.ds" ascii
        $pkg_id10 = "com.review.tool.code" ascii
        $pkg_id11 = "org.code.assist.dev.tool" ascii
        $pkg_id12 = "com.coder.ai.dpt" ascii
        $pkg_id13 = "com.my.code.tools" ascii
        $pkg_id14 = "ord.cp.code.ai.kit" ascii
        $pkg_id15 = "com.dp.git.ai.tool" ascii

    condition:
        filesize < 50MB and (
            ($c2_ip and $c2_endpoint and $auth_token) or
            ($auth_token and $header_key) or
            ($c2_ip and $auth_token) or
            (any of ($pkg_id*) and ($c2_ip or $auth_token or $c2_endpoint)) or
            ($sk_prefix and $c2_ip and $auth_token)
        )
}

rule JetBrains_Plugin_C2_AuthToken
{
    meta:
        description = "Detects the static C2 authentication token used by malicious JetBrains AI plugins"
        author = "CTI Analyst (Automated Draft)"
        date = "2026-06-17"
        reference = "https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys"
        severity = "critical"

    strings:
        $token = "F48D2AA7CF341F782C1D" ascii wide nocase
        $endpoint = "/api/software/" ascii wide

    condition:
        all of them
}
```

### Suricata Rules: Network-Based C2 Detection

<!-- revision: note added — Suricata rules use live (non-defanged) IPs, which is correct and required for Suricata syntax -->

Detects HTTP POST traffic to the C2 endpoint with the static authentication token, covering both the known C2 IP and any rotated infrastructure using the same exfiltration pattern. Note: Suricata rules use live (non-defanged) IP addresses as required by Suricata syntax. **Status: PASS** (suricata -T: configuration successfully loaded, exit code 0).

```
alert http $HOME_NET any -> 39.107.60.51 any (msg:"MALWARE JetBrains Malicious Plugin C2 - API Key Exfiltration POST to /api/software/"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/software/"; http.header; content:"X-Api-Key"; content:"F48D2AA7CF341F782C1D"; reference:url,www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys; classtype:trojan-activity; sid:2026061701; rev:1;)

alert http $HOME_NET any -> 39.107.60.51 any (msg:"MALWARE JetBrains Malicious Plugin C2 - Static Auth Token Detected"; flow:established,to_server; http.header; content:"F48D2AA7CF341F782C1D"; reference:url,www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys; classtype:trojan-activity; sid:2026061702; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE JetBrains Malicious Plugin C2 - Exfil Pattern POST with X-Api-Key Token"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/software/"; http.header; content:"X-Api-Key"; content:"F48D2AA7CF341F782C1D"; reference:url,www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys; classtype:trojan-activity; sid:2026061703; rev:1;)
```

---

## Sources

- [Aikido Security - Multiple JetBrains IDE plugins caught stealing AI keys](https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys)
- [The Hacker News - Malicious JetBrains Plugins Steal AI API Keys as Chrome Extensions Capture Chatbot Chats](https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html)
- [BleepingComputer - Malicious JetBrains Marketplace plugins steal AI API keys from developers](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/)
- [Hackread - Malicious JetBrains Plugins Steal DeepSeek & OpenAI API Keys](https://hackread.com/malicious-jetbrains-plugins-steal-deepseek-openai-api-keys/)
- [GBHackers - JetBrains Plugin Security Alert: 70,000+ Installs Linked to AI Key Theft](https://gbhackers.com/jetbrains-plugin-security-alert/)
- [CyberPress - Malicious JetBrains Plugins Caught Harvesting AI API Keys from Developers](https://cyberpress.org/malicious-jetbrains-plugins/)
