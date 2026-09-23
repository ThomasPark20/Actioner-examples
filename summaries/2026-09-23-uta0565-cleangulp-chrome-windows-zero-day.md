# Technical Analysis Report: UTA0565 CLEANGULP Chrome-Windows Zero-Day Chain (2026-09-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-23
Version: 1.0 (DRAFT)

## Executive Summary

On September 3-4, 2026, a third Chinese threat actor tracked by Volexity as UTA0565 exploited the same three-vulnerability zero-day chain (CVE-2026-85046, CVE-2026-87491, CVE-2026-85880) previously attributed to UTA0560 and JungleBamboo/APT31 to deploy a previously undocumented malware family dubbed CLEANGULP. Unlike the earlier campaigns that relied on spear-phishing from compromised/spoofed email accounts, UTA0565 constructed multiple fake websites that cloned legitimate news, NGO, and business sites to lure Asian government targets. The CLEANGULP payload is a C-based Windows backdoor compiled with MSVC, obfuscated with control flow flattening, and capable of command execution, process enumeration, file transfer, and Beacon Object File (BOF) execution. It communicates over HTTP using AES-256-GCM encryption with a custom Base64 alphabet to its typosquatted C2 domain `thecovnresation[.]com`. Volexity published its analysis on September 21, 2026, in "Mind the (Patch) Gap, Part 2."

## Background: Shared Exploit Kit, Third Threat Actor

This report covers the UTA0565/CLEANGULP campaign, which is **distinct** from the UTA0560/GRIMWEDGE and JungleBamboo/LONGTALE campaigns documented in the September 15 report. All three threat actors exploited the same BlueMoon exploit kit chaining CVE-2026-85046 (Chrome V8 type confusion), CVE-2026-87491 (Chrome V8 sandbox escape), and CVE-2026-85880 (Windows ALPC privilege escalation). Volexity assesses that this widespread adoption across multiple Chinese threat actors "suggests a coordinated effort within the Chinese computer network exploitation (CNE) community, where the core kit was likely shared, customized, and weaponized by multiple groups." The shared exploit chain but divergent post-exploitation tooling and infrastructure reinforce the assessment of a centralized exploit supply chain serving multiple Chinese state-aligned operators.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-02 | UTA0565 registers spoofed domains: outsourcingwise[.]net, halal-navi[.]net, halaltak[.]net |
| 2026-09-03 | UTA0565 registers borneobulletins[.]top; begins exploitation campaign |
| 2026-09-04 | UTA0565 registers thecovnresation[.]com and thecovnresation[.]net; exploitation continues |
| 2026-09-04 | Google patches CVE-2026-85046 in Chrome stable release |
| 2026-09-08 | Microsoft discloses and patches CVE-2026-85880 |
| 2026-09-21 | Volexity publishes "Mind the (Patch) Gap, Part 2" analysis |

## Root Cause: Fake Websites with Cloned Content

UTA0565 used a distinct initial access approach: rather than spear-phishing from compromised email accounts (as UTA0560 did), UTA0565 created multiple fake websites that cloned content from legitimate organizations. Phishing emails in Chinese referenced the sentencing of Hong Kong activist Chow Hang-tung and urged recipients to publicly support her, directing victims to the cloned sites. The fake sites contained a hidden iframe loading `/config.html`, which triggered the BlueMoon exploit chain.

Spoofed domains impersonated:

- **China Digital Times** (chinadigitaltimes.net) via `chinadigitaltimes[.]top`
- **Center for American Progress** (americanprogress.org) via `americanprgoress[.]top`
- **The Conversation** (theconversation.com) via `thecovnresation[.]com` / `thecovnresation[.]net`
- **Borneo Bulletin** (borneobulletin.com.bn) via `borneobulletins[.]top`
- **OutsourcingWise** (outsourcingwise.com) via `outsourcingwise[.]net`
- **Halal Navi** (halal-navi.com) via `halal-navi[.]net`
- **HalalKetak** (halalketak.net) via `halaltak[.]net`

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (BlueMoon Chain)

The exploit delivery mechanism reused the shared BlueMoon exploit kit documented in the UTA0560/GRIMWEDGE report. When a victim visited a spoofed website, a hidden iframe loaded `/config.html`, which initiated the three-stage exploit chain:

1. **CVE-2026-85046** — Chrome V8 type confusion for initial code execution in the renderer
2. **CVE-2026-87491** — Chrome V8 sandbox escape to break out of the renderer sandbox
3. **CVE-2026-85880** — Windows ALPC local privilege escalation for kernel-level access

The `pp` shellcode (post-exploitation stage) downloaded `chrome_cleanup.exe` from attacker infrastructure (e.g., `hxxps://americanprgoress[.]top/chrome_cleanup.exe`), removed the Mark-of-the-Web (MOTW) attribute from the file, and executed it via Windows COM shell.

### 2. CLEANGULP Backdoor

**CLEANGULP** is a previously undocumented malware family written in C and compiled with the Microsoft Visual C Compiler. The binary employs control flow flattening with indirect calls to hinder analysis.

- **File:** chrome_cleanup.exe (delivery name) / MicrosoftIME.exe (persistence name)
- **SHA256:** `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb`
- **SHA1:** `668aa5551315ab26b67118fbb29f8e4560a1e1af`
- **MD5:** `177652713dad3c128bd9195abf2b7603`
- **Size:** 914,432 bytes

Upon execution, CLEANGULP copies itself to `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` and creates a scheduled task named **"MicrosoftIME"** for persistence.

**CLEANGULP Commands:**

| Command | Function |
|---------|----------|
| shell | Execute arbitrary commands |
| ps | Enumerate running processes |
| upload | Exfiltrate files to C2 |
| download | Download files from C2 to disk |
| bof | Execute Beacon Object Files (Cobalt Strike compatible) |

The BOF execution capability is notable as it indicates the malware is designed to integrate with the broader Cobalt Strike ecosystem, enabling operators to extend functionality through modular post-exploitation modules.

### 3. C2 Infrastructure

**C2 Domain:** `thecovnresation[.]com` (typosquat of theconversation.com — note the transposed 'n' and 'r' in "conversation")

**Protocol:** HTTP POST to `/beacon/pre-register`

**Encryption:** AES-256-GCM with Base64 encoding
- **AES Key:** Derived as the SHA256 hash of a custom alphabet string, yielding: `cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21`
- **Custom Base64 Alphabet:** `3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopqrstuvwxyzABCDEWXYZ12V56789a+e`

**User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`

**Session Identifier:** Non-RFC 9562 compliant time-based UUID format

**Hosting IP:** `96[.]9[.]125[.]52` (observed hosting chinadigitaltimes[.]top spoof)

### 4. Platform-Specific Behavior

#### Windows

CLEANGULP targets Windows exclusively. The exploit chain requires Chrome on Windows (the BlueMoon JavaScript loader gates on User-Agent). The malware persists via:

- **Installation path:** `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` — masquerades as a Microsoft Input Method Editor component
- **Scheduled task:** "MicrosoftIME" — executes the implant on a recurring basis
- **MOTW removal:** The exploit chain strips the Mark-of-the-Web before execution to bypass SmartScreen and other MOTW-aware defenses

### 5. Anti-Forensics / Evasion Techniques

- **Control flow flattening:** CLEANGULP binary uses control flow flattening with indirect calls to obstruct static and dynamic analysis
- **Custom encryption:** AES-256-GCM with a non-standard Base64 alphabet makes C2 traffic harder to decode without knowledge of the custom alphabet
- **Typosquatting:** C2 domain closely mimics a legitimate media site (theconversation.com), making DNS-level detection harder without exact-match rules
- **MOTW stripping:** Removes Mark-of-the-Web before execution to avoid SmartScreen prompts
- **Legitimate path masquerading:** Installation path under Microsoft\IME\ mimics legitimate Windows component directories

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | chrome_cleanup.exe | `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb` | CLEANGULP initial payload |
| Windows | %LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe | `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb` | CLEANGULP persisted binary |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | thecovnresation[.]com | CLEANGULP C2 server |
| Domain | thecovnresation[.]net | CLEANGULP C2 alternate |
| Domain | chinadigitaltimes[.]top | Spoofed China Digital Times |
| Domain | americanprgoress[.]top | Spoofed Center for American Progress |
| Domain | borneobulletins[.]top | Spoofed Borneo Bulletin |
| Domain | outsourcingwise[.]net | Spoofed OutsourcingWise |
| Domain | halal-navi[.]net | Spoofed Halal Navi |
| Domain | halaltak[.]net | Spoofed HalalKetak |
| Domain | personclouds[.]com | UTA0565 infrastructure |
| IP | 96[.]9[.]125[.]52 | Hosts chinadigitaltimes[.]top spoof |
| URL | hxxps://americanprgoress[.]top/chrome_cleanup.exe | CLEANGULP payload download |
| URI Pattern | /beacon/pre-register | CLEANGULP C2 beacon endpoint |
| URI Pattern | /config.html | Exploit delivery iframe |

### Behavioral

- **Scheduled task** named "MicrosoftIME" for persistence
- **File creation** at `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe`
- **Mark-of-the-Web removal** on downloaded executable before COM-based execution
- **HTTP POST** to `/beacon/pre-register` with AES-256-GCM encrypted body using custom Base64 alphabet
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` (truncated/non-standard)
- **BOF execution** capability indicating Cobalt Strike ecosystem integration

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Spearphishing Link | Phishing emails with links to cloned fake websites |
| T1189 | Drive-by Compromise | Hidden iframe on fake sites triggers exploit chain |
| T1203 | Exploitation for Client Execution | CVE-2026-85046 (V8 type confusion) and CVE-2026-87491 (V8 sandbox escape) |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-85880 (Windows ALPC LPE) |
| T1059.003 | Windows Command Shell | CLEANGULP "shell" command executes arbitrary commands |
| T1053.005 | Scheduled Task | "MicrosoftIME" scheduled task for persistence |
| T1036.005 | Match Legitimate Name or Location | Installation as MicrosoftIME.exe in Microsoft\IME\ directory |
| T1105 | Ingress Tool Transfer | Download of chrome_cleanup.exe payload from spoofed domain |
| T1071.001 | Web Protocols | C2 communication via HTTP POST to /beacon/pre-register |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encryption of C2 traffic |
| T1027.001 | Obfuscated Files or Information: Binary Padding | Control flow flattening obfuscation of CLEANGULP binary |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | MOTW stripped before execution |
| T1082 | System Information Discovery | Process enumeration via "ps" command |
| T1057 | Process Discovery | CLEANGULP "ps" command lists running processes |
| T1041 | Exfiltration Over C2 Channel | CLEANGULP "upload" command exfiltrates files over HTTP C2 |

## Impact Assessment

**Breadth:** UTA0565 targeted Asian government entities through at least nine spoofed domains impersonating organizations across multiple sectors (media, NGOs, business services, restaurants). The breadth of spoofed sites suggests wide targeting across Southeast and East Asian government audiences.

**Depth:** Full system compromise via kernel-level exploitation. CLEANGULP provides complete remote access with command execution, file transfer, and extensibility via BOF execution. The BOF capability allows operators to load additional post-exploitation tools without dropping them to disk.

**Stealth:** CLEANGULP employs multiple evasion layers: control flow flattening against reverse engineering, custom encryption for C2 traffic, typosquat C2 domain, MOTW bypass, and masquerading as a legitimate Windows IME component.

**Broader Threat:** This is the third confirmed Chinese threat actor using the identical exploit chain within a one-week window, confirming a centralized exploit supply chain. Volexity also identified additional clusters (UNK_LateNight, UNK_DoubleCheck, UNK_QuietRacket) using the same kit, indicating even wider adoption.

## Detection & Remediation

### Immediate Detection

1. **Search for scheduled task:** `schtasks /query /tn "MicrosoftIME"` -- presence indicates CLEANGULP persistence
2. **Search for file:** Check `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` across endpoints; hash against `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb`
3. **Search DNS logs** for queries to `thecovnresation.com`, `thecovnresation.net`, `chinadigitaltimes.top`, `americanprgoress.top`, `borneobulletins.top`
4. **Search proxy/web logs** for HTTP POST requests to `/beacon/pre-register`
5. **Search proxy/firewall logs** for connections to `96.9.125.52`
6. **Search for file hash** `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb` in endpoint telemetry

### Remediation

1. **Immediately update Chrome** to the latest stable release (patches CVE-2026-85046 and CVE-2026-87491)
2. **Apply Windows security updates** addressing CVE-2026-85880 (patched September 8, 2026)
3. **Isolate compromised hosts** and collect forensic images
4. **Remove** the "MicrosoftIME" scheduled task on confirmed compromised systems
5. **Delete** `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe`
6. **Block** all IOC domains and IPs at the network perimeter
7. **Reset credentials** for any users on compromised systems
8. **Hunt for BOF artifacts** -- the BOF execution capability suggests operators may have deployed additional tools

### Long-Term Hardening

1. **Reduce patch gap exposure:** Enable Chrome automatic updates and enforce rapid update policies via Chrome Enterprise
2. **DNS monitoring:** Deploy DNS monitoring with alerting on newly registered domains that typosquat known legitimate domains
3. **MOTW enforcement:** Consider application control policies that block execution of binaries without valid MOTW or code signatures
4. **Network segmentation:** Restrict outbound HTTP/HTTPS from workstations to known-good destinations where feasible
5. **Scheduled task auditing:** Monitor for creation of new scheduled tasks, particularly those executing from user-writable directories

## Detection Rules

These detections target campaign-specific artifacts from the UTA0565 CLEANGULP operation. PoC/advisory-specific altitude (default); Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: UTA0565 CLEANGULP Scheduled Task Persistence

Detects creation of the "MicrosoftIME" scheduled task used by CLEANGULP for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Task name "MicrosoftIME" combined with schtasks.exe is campaign-specific. FP risk: legitimate Microsoft IME task operations exist but would not typically involve schtasks.exe command-line creation with this exact name in user context. -->

```yaml
title: UTA0565 CLEANGULP Scheduled Task Persistence
id: 3a1e7c9d-8f2b-4d6a-b5e4-0c9f1d3a7e2b
status: experimental
description: >
    Detects creation of the "MicrosoftIME" scheduled task used by CLEANGULP malware
    for persistence, as deployed by Chinese threat actor UTA0565.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/23
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'MicrosoftIME'
    condition: selection
falsepositives:
    - Legitimate Microsoft IME-related scheduled tasks (verify task action path points to %LOCALAPPDATA%\Microsoft\IME\)
level: high
```

### Sigma: UTA0565 CLEANGULP Installation to IME Directory

Detects file creation of MicrosoftIME.exe in the user AppData Microsoft IME directory, consistent with CLEANGULP installation.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. File path \Microsoft\IME\MicrosoftIME.exe under user AppData is not a standard Windows-delivered location for executables. FP: theoretically possible if a legitimate IME installer places an exe at this exact path, but unlikely. -->

```yaml
title: UTA0565 CLEANGULP Installation to IME Directory
id: 5b2f8d4e-1c3a-4e7b-9a6d-2f0e8c5b7d1a
status: experimental
description: >
    Detects file creation of MicrosoftIME.exe in the user's AppData\Local\Microsoft\IME
    directory, consistent with CLEANGULP malware installation by UTA0565.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/23
tags:
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\Microsoft\IME\MicrosoftIME.exe'
    condition: selection
falsepositives:
    - Legitimate Microsoft IME executable updates (rare; verify file hash against known CLEANGULP hash)
level: high
```

### Sigma: UTA0565 CLEANGULP Known Campaign Domain DNS Query

Detects DNS queries to known UTA0565 campaign infrastructure including the CLEANGULP C2 domain and spoofed phishing domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. All domains are typosquats or campaign-specific. No benign use known. -->

```yaml
title: UTA0565 CLEANGULP Known Campaign Domain DNS Query
id: 9e4f2a1b-7c3d-4b8e-a6f5-1d0c3e2b4a7f
status: experimental
description: >
    Detects DNS queries to known UTA0565 campaign infrastructure including the CLEANGULP
    C2 domain thecovnresation.com and spoofed phishing domains.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/23
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'thecovnresation.com'
            - 'thecovnresation.net'
            - 'chinadigitaltimes.top'
            - 'americanprgoress.top'
            - 'borneobulletins.top'
            - 'outsourcingwise.net'
            - 'halal-navi.net'
            - 'halaltak.net'
            - 'personclouds.com'
    condition: selection
falsepositives:
    - Unlikely - domains are typosquats and campaign-specific infrastructure
level: critical
```

### Snort: UTA0565 CLEANGULP C2 and Infrastructure Domain Detection

Detects TLS ClientHello traffic containing UTA0565 campaign domain strings in the payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0. Content match on distinctive domain labels "thecovnresation", "chinadigitaltimes", "americanprgoress" in raw TCP payload for TLS SNI detection. Campaign-specific domains; no benign overlap. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0565 CLEANGULP C2 Domain in TLS ClientHello"; flow:established,to_server; content:"thecovnresation"; fast_pattern; content:".com"; distance:0; within:5; sid:2100010; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0565 Spoofed Domain chinadigitaltimes.top in TLS ClientHello"; flow:established,to_server; content:"chinadigitaltimes"; fast_pattern; content:".top"; distance:0; within:5; sid:2100011; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0565 Spoofed Domain americanprgoress.top in TLS ClientHello"; flow:established,to_server; content:"americanprgoress"; fast_pattern; content:".top"; distance:0; within:5; sid:2100012; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)
```

### Suricata: UTA0565 CLEANGULP C2 and Infrastructure

Detects TLS connections, DNS queries, and HTTP C2 beacons to known UTA0565 campaign domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Seven rules covering TLS SNI, DNS, and HTTP C2 beacon URI. Campaign-specific infrastructure; no benign overlap. The HTTP C2 beacon rule on /beacon/pre-register is medium confidence standalone but combined with other indicators is high. -->

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to CLEANGULP C2 Domain thecovnresation.com"; flow:established,to_server; tls.sni; content:"thecovnresation.com"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200010; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to UTA0565 Spoofed Domain chinadigitaltimes.top"; flow:established,to_server; tls.sni; content:"chinadigitaltimes.top"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200011; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to UTA0565 Spoofed Domain americanprgoress.top"; flow:established,to_server; tls.sni; content:"americanprgoress.top"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200012; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CLEANGULP C2 Domain thecovnresation.com"; flow:to_server; dns.query; content:"thecovnresation.com"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200013; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UTA0565 Spoofed Domain chinadigitaltimes.top"; flow:to_server; dns.query; content:"chinadigitaltimes.top"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200014; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UTA0565 Spoofed Domain americanprgoress.top"; flow:to_server; dns.query; content:"americanprgoress.top"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200015; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CLEANGULP HTTP C2 Beacon to /beacon/pre-register"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/beacon/pre-register"; fast_pattern; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-23; sid:2200016; rev:1;)
```

### YARA: UTA0565 CLEANGULP Backdoor

Detects the CLEANGULP Windows PE backdoor via its distinctive C2 domain, beacon URI, or custom Base64 alphabet.
**Status:** compile ✅ compiles · confidence: medium · sample: constructed
<!-- audit: yarac exit 0. Positive sample constructed (MZ header + C2 domain string); negative sample (benign text) did not match. C2 domain and custom base64 alphabet are highly distinctive. Condition is OR across four strings: any single match is sufficient. Medium confidence because individual strings like /beacon/pre-register could theoretically appear in benign contexts, but the PE gate + size limit + any-of-four logic provides reasonable specificity. The AES key hash and custom Base64 alphabet are near-unique identifiers. -->

```yara
rule UTA0565_CLEANGULP_Backdoor
{
    meta:
        description = "Detects CLEANGULP backdoor deployed by UTA0565 via distinctive C2 domain, beacon URI, and custom Base64 alphabet"
        author = "Actioner"
        date = "2026-09-23"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $c2 = "thecovnresation.com" ascii wide
        $beacon_uri = "/beacon/pre-register" ascii wide
        $custom_b64 = "3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq" ascii
        $aes_key = "cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            $c2 or
            $beacon_uri or
            $custom_b64 or
            $aes_key
        )
}
```

## Lessons Learned

1. **Centralized exploit supply chain confirmed.** UTA0565 is the third distinct Chinese threat actor confirmed using the identical BlueMoon exploit chain within the same week as UTA0560 and JungleBamboo. Additional unnamed clusters (UNK_LateNight, UNK_DoubleCheck, UNK_QuietRacket) suggest even broader distribution, reinforcing Volexity's assessment of a centralized exploit development or procurement capability serving multiple Chinese CNE operators.

2. **Fake website approach widens the attack surface.** Where UTA0560 relied on spear-phishing emails with direct links, UTA0565's use of cloned legitimate websites creates a more convincing and harder-to-detect lure. The variety of impersonated organizations (media, NGOs, business services, restaurants) suggests targeting of diverse government-adjacent audiences across Southeast and East Asia.

3. **BOF execution indicates mature operational capability.** CLEANGULP's ability to execute Beacon Object Files represents a significant step up from GRIMWEDGE's simple JScript backdoor. This indicates UTA0565 may be a more sophisticated operator with deeper integration into Cobalt Strike's post-exploitation ecosystem.

4. **Custom C2 encryption complicates network detection.** The use of AES-256-GCM with a custom Base64 alphabet makes passive traffic analysis infeasible. Detection must key on network indicators (domains, URIs) rather than payload content.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Volexity Blog - Mind the (Patch) Gap, Part 2](https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/) — primary technical analysis with full IOCs, exploit chain details, and CLEANGULP malware analysis
- [The Hacker News - Chinese Hackers Exploit Chrome-Windows Zero-Day Chain to Deploy CLEANGULP Malware](https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html) — secondary reporting summarizing Volexity's findings with additional context
- [CyberScoop - Volexity spots another China-aligned threat group exploiting Chrome and Microsoft defects](https://cyberscoop.com/volexity-uta0565-china-exploit-chain-chrome-microsoft/) — supplementary reporting on UTA0565 campaign and broader threat landscape implications

---
*Report generated by Actioner (DRAFT v1.0)*
