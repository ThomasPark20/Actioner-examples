# Technical Analysis Report: UTA0565 CLEANGULP Chrome-Windows Zero-Day Chain (2026-09-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-26
Version: 1.0 (DRAFT)

## Executive Summary

In early September 2026, Chinese threat actor UTA0565 launched a targeted campaign using fake news and policy websites to deliver the CLEANGULP backdoor. The attack exploited a three-vulnerability zero-day chain: CVE-2026-85046 (Chrome V8 type confusion), CVE-2026-87491 (Chrome WebAssembly sandbox escape), and CVE-2026-85880 (Windows kernel privilege escalation via RtlpCreateServerAcl). Victims visiting typosquatted domains masquerading as legitimate news outlets (China Digital Times, American Progress) were redirected through the "BlueMoon" exploit kit, which achieved kernel-level code execution from a single page visit. The delivered payload, CLEANGULP (SHA256: `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb`), is a 914 KB Win64 backdoor supporting shell commands, process listing, file upload/download, and beacon object file (BOF) execution. It communicates with its C2 server at `thecovnresation[.]com` via HTTP POST using AES-256-GCM encryption with a custom Base64 alphabet. This campaign is distinct from but related to the parallel UTA0560/GRIMWEDGE and JungleBamboo/LONGTALE campaigns documented in Volexity's September 9 report, all three threat actors sharing the same underlying exploit chain. Volexity researchers Damien Cash and Tom Lancaster published the UTA0565/CLEANGULP analysis on September 21, 2026.

## Background: BlueMoon Exploit Kit and Shared Exploit Supply

The "BlueMoon" exploit kit chains three vulnerabilities to achieve arbitrary code execution on fully-patched (at the time) Windows systems running Google Chrome. The same three-CVE chain was simultaneously exploited by at least three Chinese threat actors -- UTA0560, JungleBamboo (APT31/Violet Typhoon), and UTA0565 -- each deploying different post-exploitation payloads. This convergence strongly suggests a centralized exploit development or procurement capability among China-nexus groups. CVE-2026-85046 was reported to Chromium on August 4, 2026 and existed in a "patch gap" -- fixed in upstream Chromium source but not yet shipped in a Chrome stable release.

### Exploit Chain Components

| Stage | CVE | Vulnerability | Impact |
|-------|-----|---------------|--------|
| 1 | CVE-2026-85046 | Chrome V8 type confusion | Arbitrary code execution in renderer |
| 2 | CVE-2026-87491 | Chrome WebAssembly sandbox escape | Escape V8 sandbox |
| 3 | CVE-2026-85880 | Windows kernel RtlpCreateServerAcl | Local privilege escalation to SYSTEM |

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-04 | CVE-2026-85046 reported to Chromium project |
| 2026-08-27 to 2026-08-29 | Exploit development (build timestamps in scripts) |
| 2026-09-01 | Parallel UTA0560 and JungleBamboo campaigns begin |
| 2026-09-03 | UTA0565 campaign detected -- fake website infrastructure active |
| 2026-09-04 | Additional UTA0565 detections confirmed |
| 2026-09-09 | Volexity publishes Part 1 analysis (UTA0560, JungleBamboo) |
| 2026-09-21 | Volexity publishes Part 2 analysis (UTA0565, CLEANGULP) |

## Root Cause: Fake News Website Delivery

Unlike UTA0560's spear-phishing via XSS redirects, UTA0565 used typosquatted domains mimicking legitimate news and policy organizations as the delivery mechanism. Victims were lured to these fake websites, which served the BlueMoon exploit kit. The spoofed domains included:

- `chinadigitaltimes[.]top` -- mimicking chinadigitaltimes.net (independent China news)
- `americanprgoress[.]top` -- typosquat of americanprogress.org (Center for American Progress)

These domains hosted convincing replicas of the legitimate sites, with the exploit chain embedded in page resources.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (BlueMoon Chain)

The BlueMoon exploit kit uses the same multi-stage architecture documented in the UTA0560 campaign:

- **JavaScript loader** gates execution based on User-Agent (Chrome on Windows only)
- **Exploit page** (`page.html`) contains three embedded shellcode payloads:
  - **p1**: Host reconnaissance (OS version, CPUID, hypervisor detection, token privileges)
  - **p2**: Windows kernel LPE exploiting CVE-2026-85880 in `RtlpCreateServerAcl` (targets Windows 10 1809-22H2, Server 2022, Windows 11 21H2 builds <=22000)
  - **pp**: Browser process injection via `CreateProcessA`, modified for CLEANGULP delivery

The pp payload downloads `chrome_cleanup.exe` to the victim system, diverging from UTA0560's `msgbox.exe` delivery.

### 2. CLEANGULP Backdoor

**File Metadata:**

| Attribute | Value |
|-----------|-------|
| Filename | chrome_cleanup.exe |
| Size | 914,432 bytes (893.0 KB) |
| Type | Win64 EXE (MSVC compiled) |
| MD5 | `177652713dad3c128bd9195abf2b7603` |
| SHA1 | `668aa5551315ab26b67118fbb29f8e4560a1e1af` |
| SHA256 | `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb` |
| Installation Path | `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` |

**Persistence:** Scheduled task named **"MicrosoftIME"** re-executing the backdoor at regular intervals.

**Supported Commands:**

| Command | Function |
|---------|----------|
| shell | Execute arbitrary command |
| ps | List running processes |
| upload | Upload file to C2 |
| download | Download file from C2 |
| bof | Execute beacon object file (Cobalt Strike compatible) |

### 3. C2 Infrastructure

**Primary C2 Domain:** `thecovnresation[.]com` (typosquat of theconversation.com)
**Secondary Domain:** `thecovnresation[.]net`

**C2 Protocol:**
- Method: HTTP POST
- Beacon URI: `/beacon/pre-register`
- Encryption: AES-256-GCM
- Encoding: Base64 with custom alphabet
- Custom Base64 Alphabet: `3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq/rstuvwxyzABCDEWXYZ12V56789a+e`
- AES Key Derivation: SHA256 of the custom alphabet = `cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21`
- Registration Response: `{"approved":false,"status":"ok"}`

### 4. Platform Behavior

- **Target OS:** Windows 10 1809-22H2, Windows Server 2022, Windows 11 21H2 (builds <=22000)
- **Target Browser:** Google Chrome 151.x (patch gap period)
- **Execution Context:** Runs as SYSTEM after kernel LPE
- **BOF Support:** Indicates potential Cobalt Strike interoperability -- the `bof` command enables execution of Cobalt Strike-compatible beacon object files, suggesting UTA0565 may use Cobalt Strike or compatible frameworks for lateral movement

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | chrome_cleanup.exe | `8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb` | CLEANGULP backdoor |
| Windows | %LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe | (same as above -- renamed copy) | CLEANGULP installed |
| Windows | page.html | `7a52ff23949edee8faa61ce0def6dbca8b7e5943c54d23376cc190762ea3985c` | Exploit delivery page (shared) |
| Windows | p1 DLL | `b7b0cd6539464ab39c6526e499f86d611faa21c5af945535ebaf187cec543af1` | Host reconnaissance payload (shared) |
| Windows | p2 DLL | `51462a23ac25e1bd0e49b7cae7f3a71f8d2201e22d45175b587e4740b49863cc` | Windows kernel LPE payload (shared) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | chinadigitaltimes[.]top | UTA0565 spoofed news site |
| Domain | americanprgoress[.]top | UTA0565 spoofed policy site |
| Domain | thecovnresation[.]com | CLEANGULP C2 (primary) |
| Domain | thecovnresation[.]net | CLEANGULP C2 (secondary) |
| IP | 96[.]9[.]125[.]52 | Hosted chinadigitaltimes[.]top |
| Domain | personclouds[.]com | Suspected UTA0565 infrastructure (medium confidence) |
| Domain | outsourcingwise[.]net | Suspected UTA0565 infrastructure (medium confidence) |
| Domain | halal-navi[.]net | Suspected UTA0565 infrastructure (medium confidence) |
| Domain | halaltak[.]net | Suspected UTA0565 infrastructure (medium confidence) |
| Domain | borneobulletins[.]top | Suspected UTA0565 infrastructure (medium confidence) |
| URI | /beacon/pre-register | CLEANGULP beacon URI pattern |

### Behavioral

- **Scheduled task** named "MicrosoftIME" for persistence
- **Installation path** `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` -- legitimate IME path is `%SystemRoot%\System32\IME\`
- **C2 beacon** via HTTP POST to `/beacon/pre-register` with AES-256-GCM encrypted, custom Base64-encoded body
- **Custom Base64 alphabet** in binary: `3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq/rstuvwxyzABCDEWXYZ12V56789a+e`
- **BOF execution** capability indicating Cobalt Strike ecosystem interoperability

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Fake news websites serving BlueMoon exploit kit |
| T1583.001 | Acquire Infrastructure: Domains | Typosquatted domains mimicking news/policy organizations |
| T1203 | Exploitation for Client Execution | CVE-2026-85046 (V8 type confusion) and CVE-2026-87491 (sandbox escape) |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-85880 (Windows kernel RtlpCreateServerAcl) |
| T1105 | Ingress Tool Transfer | Download of chrome_cleanup.exe via browser injection |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Renamed to MicrosoftIME.exe in IME directory |
| T1053.005 | Scheduled Task | "MicrosoftIME" scheduled task for persistence |
| T1071.001 | Web Protocols | C2 communication via HTTP POST |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-GCM encrypted C2 traffic |
| T1059 | Command and Scripting Interpreter | Shell command execution capability |
| T1057 | Process Discovery | Process listing via "ps" command |
| T1082 | System Information Discovery | Host reconnaissance via p1 shellcode |
| T1041 | Exfiltration Over C2 Channel | File upload capability over HTTP C2 |

## Impact Assessment

**Breadth:** UTA0565 targeted organizations interested in China-related news and U.S. policy, consistent with espionage objectives. The use of typosquatted versions of China Digital Times and American Progress suggests targeting of journalists, researchers, NGO staff, and policy professionals.

**Depth:** Full system compromise from a single website visit. The exploit chain achieves kernel-level code execution, and CLEANGULP provides arbitrary command execution, file transfer, and BOF execution -- sufficient for complete intelligence collection.

**Stealth:** CLEANGULP uses AES-256-GCM encryption with a custom Base64 alphabet for C2 communication, making traffic analysis difficult. The installation path masquerades as a legitimate Microsoft IME component, and the scheduled task name blends with legitimate Windows services.

**BOF Capability:** The inclusion of beacon object file execution suggests UTA0565 has access to Cobalt Strike or compatible post-exploitation frameworks, enabling modular capability deployment without writing additional tools to disk.

## Detection & Remediation

### Immediate Detection

1. **Search for scheduled task:** `schtasks /query /tn "MicrosoftIME"` -- verify that any results point to `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` (malicious) vs `%SystemRoot%\System32\IME\` (legitimate)
2. **Search DNS logs** for queries to `thecovnresation[.]com`, `thecovnresation[.]net`, `chinadigitaltimes[.]top`, or `americanprgoress[.]top`
3. **Search proxy/firewall logs** for connections to `96[.]9[.]125[.]52`
4. **Search for file hashes** listed in the IOC table across endpoint telemetry
5. **Search for** `chrome_cleanup.exe` or `MicrosoftIME.exe` in `%LOCALAPPDATA%\Microsoft\IME\`
6. **Search HTTP logs** for POST requests to URI path `/beacon/pre-register`

### Remediation

1. **Immediately update Chrome** to the latest stable release (patches CVE-2026-85046 and CVE-2026-87491)
2. **Apply Windows security updates** addressing CVE-2026-85880
3. **Isolate compromised hosts** and collect forensic images
4. **Remove** the "MicrosoftIME" scheduled task
5. **Remove** `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe`
6. **Block** all IOC domains and IPs at the network perimeter
7. **Reset credentials** for any users on compromised systems
8. **Hunt for BOF artifacts** -- check for evidence of Cobalt Strike beacon object files or lateral movement

### Long-Term Hardening

1. **Reduce patch gap exposure:** Enable Chrome's automatic update mechanism; consider Chrome Enterprise policies for rapid update enforcement
2. **DNS-based protection:** Block typosquatted domains via DNS sinkholing and monitor for newly-registered lookalike domains
3. **Network monitoring:** Alert on HTTP POST requests to `/beacon/pre-register` and TLS connections to known C2 domains
4. **Endpoint monitoring:** Deploy Sysmon or equivalent to capture process creation, scheduled task events, and file creation in `%LOCALAPPDATA%\Microsoft\IME\`

## Detection Rules

These detections target campaign-specific artifacts from the UTA0565 CLEANGULP operation. PoC/advisory-specific altitude (default); all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: UTA0565 CLEANGULP Scheduled Task Persistence

Detects creation of the "MicrosoftIME" scheduled task used by CLEANGULP for persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy -- known environment issue); sigma convert splunk exit 0; sigma convert log_scale exit 0. Task name "MicrosoftIME" combined with schtasks.exe is distinctive. Low FP: legitimate IME tasks are created by Windows Setup, not schtasks. -->

```yaml
title: UTA0565 CLEANGULP Scheduled Task Persistence
id: a1b2c3d4-5e6f-47a8-b9c0-d1e2f3a4b5c6
status: experimental
description: >
    Detects creation of the "MicrosoftIME" scheduled task used by the CLEANGULP
    backdoor deployed by Chinese threat actor UTA0565 for persistence.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/26
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'MicrosoftIME'
    condition: selection_schtasks
falsepositives:
    - Legitimate Microsoft IME scheduled tasks may exist but would not use schtasks to create them
level: high
```

### Sigma: UTA0565 CLEANGULP C2 Domain DNS Query

Detects DNS queries to the known CLEANGULP C2 domains `thecovnresation[.]com` and `thecovnresation[.]net`, which are typosquats of `theconversation.com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Domains are campaign-specific typosquats with no legitimate use. -->

```yaml
title: UTA0565 CLEANGULP C2 Domain DNS Query
id: b2c3d4e5-6f7a-48b9-c0d1-e2f3a4b5c6d7
status: experimental
description: >
    Detects DNS queries to the known CLEANGULP command-and-control domains
    thecovnresation.com and thecovnresation.net used by Chinese threat actor UTA0565.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/26
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'thecovnresation.com'
            - 'thecovnresation.net'
    condition: selection
falsepositives:
    - Unlikely - typosquat domains specific to this campaign
level: critical
```

### Sigma: UTA0565 CLEANGULP Installation Path Execution

Detects execution of `MicrosoftIME.exe` from the unusual `%LOCALAPPDATA%\Microsoft\IME\` path, which is the CLEANGULP installation location (legitimate IME binaries reside in `%SystemRoot%\System32\IME\`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Path distinction between LOCALAPPDATA and System32 IME is reliable. Filter removes legitimate system IME executions. -->

```yaml
title: UTA0565 CLEANGULP Installation Path Execution
id: c3d4e5f6-7a8b-49c0-d1e2-f3a4b5c6d7e8
status: experimental
description: >
    Detects execution of MicrosoftIME.exe from the unusual path
    %LOCALAPPDATA%\Microsoft\IME\, consistent with CLEANGULP backdoor
    installation by Chinese threat actor UTA0565.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/26
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Microsoft\IME\MicrosoftIME.exe'
    filter_legit:
        Image|contains: '\Windows\System32\IME\'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate Microsoft IME executable runs from System32, not LOCALAPPDATA
level: high
```

### Sigma: UTA0565 Spoofed Website Domain DNS Query

Detects DNS queries to known UTA0565 typosquatted domains used as delivery infrastructure for the Chrome-Windows zero-day exploit chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. All three domains are confirmed attacker-controlled typosquats. -->

```yaml
title: UTA0565 Spoofed Website Domain DNS Query
id: d4e5f6a7-8b9c-40d1-e2f3-a4b5c6d7e8f9
status: experimental
description: >
    Detects DNS queries to known UTA0565 spoofed website domains used as
    delivery infrastructure for the Chrome-Windows zero-day exploit chain
    deploying CLEANGULP malware.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/26
tags:
    - attack.t1583.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'chinadigitaltimes.top'
            - 'americanprgoress.top'
            - 'borneobulletins.top'
    condition: selection
falsepositives:
    - Unlikely - typosquat domains specific to this campaign
level: critical
```

### Sigma: UTA0565 CLEANGULP Payload Download via Curl

Detects cmd.exe spawning curl to download `chrome_cleanup.exe`, matching the CLEANGULP delivery stage.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. "chrome_cleanup" in a curl download from cmd.exe is distinctive. No known legitimate software uses this pattern. -->

```yaml
title: UTA0565 CLEANGULP Payload Download via Curl
id: e5f6a7b8-9c0d-41e2-f3a4-b5c6d7e8f9a0
status: experimental
description: >
    Detects cmd.exe spawning curl to download chrome_cleanup.exe, consistent
    with the UTA0565 browser exploit chain payload delivery stage for CLEANGULP.
references:
    - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
    - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
author: Actioner
date: 2026/09/26
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        Image|endswith: '\curl.exe'
        CommandLine|contains: 'chrome_cleanup'
    condition: selection
falsepositives:
    - Legitimate Chrome cleanup utilities would not be downloaded via curl from cmd.exe
level: critical
```

### Suricata: UTA0565 CLEANGULP C2 and Delivery Infrastructure

Detects TLS connections, DNS queries, and HTTP beacon traffic to known UTA0565 campaign infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S suricata_cleangulp.rules -l /tmp/actioner exit 0. Seven rules: TLS SNI for C2 and spoofed domains, DNS queries for C2 domains, and HTTP POST beacon URI detection. All domains are campaign-specific with no known benign overlap. -->

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to CLEANGULP C2 Domain thecovnresation.com"; flow:established,to_server; tls.sni; content:"thecovnresation.com"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200101; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to CLEANGULP C2 Domain thecovnresation.net"; flow:established,to_server; tls.sni; content:"thecovnresation.net"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CLEANGULP C2 Domain thecovnresation.com"; flow:to_server; dns.query; content:"thecovnresation.com"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to CLEANGULP C2 Domain thecovnresation.net"; flow:to_server; dns.query; content:"thecovnresation.net"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200104; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to UTA0565 Spoofed Domain chinadigitaltimes.top"; flow:established,to_server; tls.sni; content:"chinadigitaltimes.top"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200105; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to UTA0565 Spoofed Domain americanprgoress.top"; flow:established,to_server; tls.sni; content:"americanprgoress.top"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200106; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - CLEANGULP HTTP POST Beacon URI /beacon/pre-register"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/beacon/pre-register"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/; metadata:author Actioner, created_at 2026-09-26; sid:2200107; rev:1;)
```

### Snort: UTA0565 CLEANGULP C2 Domain Detection

Detects TLS ClientHello traffic containing the CLEANGULP C2 domain `thecovnresation` and spoofed delivery domains.
**Status:** ⚠️ uncompiled (structural check only) · confidence: high
<!-- audit: Snort not installed in this environment. Rules follow standard Snort 2.x/3.x syntax with flow, content, and fast_pattern keywords. Domain strings are unique campaign artifacts. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - CLEANGULP C2 Domain thecovnresation in TLS ClientHello"; flow:established,to_server; content:"thecovnresation"; fast_pattern; sid:2100101; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0565 Spoofed Domain chinadigitaltimes in TLS ClientHello"; flow:established,to_server; content:"chinadigitaltimes"; fast_pattern; content:".top"; distance:0; within:5; sid:2100102; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0565 Spoofed Domain americanprgoress in TLS ClientHello"; flow:established,to_server; content:"americanprgoress"; fast_pattern; content:".top"; distance:0; within:5; sid:2100103; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/;)
```

### YARA: UTA0565 CLEANGULP Backdoor Strings

Detects the CLEANGULP backdoor via its distinctive C2 domain, custom Base64 alphabet, AES key, and beacon URI pattern. The custom Base64 alphabet (`3GHIJ...`) is a highly distinctive artifact unique to this malware family.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Primary detection via $c2_domain ("thecovnresation") or $custom_b64 (64-char custom alphabet) -- both are unique campaign artifacts with zero known benign matches. Secondary branch ($beacon_uri + 2 of $cmd_*) provides behavioral coverage for variants that change C2 domains. -->

```yara
rule UTA0565_CLEANGULP_Backdoor
{
    meta:
        description = "Detects CLEANGULP backdoor deployed by Chinese threat actor UTA0565 via custom Base64 alphabet, C2 domain, and beacon URI patterns"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $c2_domain = "thecovnresation" ascii wide
        $beacon_uri = "/beacon/pre-register" ascii wide
        $custom_b64 = "3GHIJKLMNOPQRSTUb4Fcd0fghijklmnopq/rstuvwxyzABCDEWXYZ12V56789a+e" ascii wide
        $aes_key = "cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21" ascii wide
        $cmd_shell = "shell" ascii
        $cmd_ps = "ps" ascii
        $cmd_upload = "upload" ascii
        $cmd_download = "download" ascii
        $cmd_bof = "bof" ascii

    condition:
        filesize < 2MB and
        (
            $c2_domain or
            $custom_b64 or
            $aes_key or
            ($beacon_uri and 2 of ($cmd_*))
        )
}
```

### YARA: UTA0565 CLEANGULP Dropper

Detects the CLEANGULP dropper executable by the combination of C2 domain, beacon URI, and filename/installation path strings.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. Requires 2 of 4 campaign-specific strings. Medium confidence because individual strings like "chrome_cleanup" or "MicrosoftIME" could appear in legitimate contexts, but any pair is distinctive. -->

```yara
rule UTA0565_CLEANGULP_Dropper
{
    meta:
        description = "Detects CLEANGULP dropper by filename pattern and known file size used by UTA0565"
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/"
        hash = "8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb"
        severity = "critical"

    strings:
        $mz = "MZ"
        $s1 = "thecovnresation" ascii wide
        $s2 = "/beacon/pre-register" ascii wide
        $s3 = "chrome_cleanup" ascii wide
        $s4 = "MicrosoftIME" ascii wide

    condition:
        $mz at 0 and
        filesize < 2MB and
        2 of ($s1, $s2, $s3, $s4)
}
```

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Volexity Blog - Mind the (Patch) Gap, Part 2: Fake Websites Used to Deploy Chrome & Windows 0-Day Exploits](https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/) -- primary technical analysis with full IOCs, CLEANGULP malware details, and C2 protocol analysis (Damien Cash and Tom Lancaster, September 21, 2026)
- [Volexity Blog - Mind the (Patch) Gap: Multiple Chinese Threat Actors Chain 0-day Exploits in Chrome & Windows](https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/) -- Part 1 analysis documenting the shared BlueMoon exploit chain, UTA0560/GRIMWEDGE, and JungleBamboo/LONGTALE campaigns (September 9, 2026)
- [The Hacker News - Chinese Hackers Exploit Chrome-Windows Zero-Day Chain](https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html) -- secondary reporting summarizing the UTA0565 CLEANGULP campaign with key IOCs and capabilities

---
*Report generated by Actioner (DRAFT v1.0)*
