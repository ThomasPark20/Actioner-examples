# Technical Analysis Report: Chaos Ransomware msaRAT (2026-07-27)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-27
Version: 1.0

## Executive Summary

Cisco Talos has identified a novel Rust-based remote access trojan dubbed "msaRAT," attributed to the Chaos ransomware-as-a-service (RaaS) group. The RAT implements a browser-native command-and-control channel by hijacking Chrome or Edge via the Chrome DevTools Protocol (CDP), establishing WebRTC data channels that route through Cloudflare Workers and Twilio TURN servers. This architecture means all C2 traffic originates from a legitimate browser process and traverses trusted cloud infrastructure, rendering conventional network-based detection largely ineffective. The malware was discovered during incident response to a Chaos ransomware intrusion observed in February 2025. The Chaos group, which emerged in early 2025 (distinct from the older Chaos ransomware builder), has been linked to the Iranian-linked MuddyWater APT as a cover for espionage operations disguised as financially motivated ransomware.

msaRAT is delivered as an MSI installer (update_ms.msi) masquerading as a Windows update, dropped to `C:\ProgramData` via curl.exe from a staging server at 172.86.126[.]18:443. The embedded DLL (lib.dll) exports a `RUN` function invoked by an MSI custom action, launching the Tokio async runtime. The RAT locates Chrome or Edge on the system, starts it in headless mode with remote debugging enabled (`--headless=new --remote-debugging-port`), connects via CDP WebSocket, injects JavaScript to establish a WebRTC DataChannel through Cloudflare Workers signaling, and routes all data through Twilio TURN relays. The channel is double-encrypted: DTLS at the transport layer (browser-handled) and ChaCha20-Poly1305 with ECDH key exchange at the application layer.

## Background: Chrome DevTools Protocol as an Attack Surface

The Chrome DevTools Protocol (CDP) is a debugging API built into all Chromium-based browsers (Chrome, Edge, Brave, etc.) that allows programmatic control of browser sessions. When a browser is launched with `--remote-debugging-port`, it exposes a WebSocket interface on localhost that enables full control: navigating pages, injecting JavaScript, bypassing Content Security Policy, and intercepting network traffic. Legitimate uses include automated testing (Puppeteer, Playwright, Selenium) and development debugging.

msaRAT abuses CDP as a "living off the browser" technique -- the RAT never directly touches the network. Instead, it puppets a headless browser instance to perform all external communications, making traffic appear to originate from a standard browser process connecting to legitimate cloud services. This represents an evolution beyond traditional LOLBin techniques, leveraging the browser itself as a trusted network proxy.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Early 2025 | Chaos RaaS group emerges; initial operations observed |
| February 2025 | msaRAT first observed in incident response engagement |
| 2025 (ongoing) | MuddyWater reportedly uses Chaos for espionage cover |
| 2026-07-22 | Cisco Talos publishes detailed technical analysis |

## Root Cause: Social Engineering and RMM Tool Abuse

Initial access is achieved through spam emails and voice-based social engineering (vishing). The operators convince victims to install remote management and monitoring (RMM) tools, establishing persistent remote access. From this foothold, attackers download the msaRAT payload using curl.exe, fetching update_ms.msi from the staging server at 172.86.126[.]18:443 and writing it to `C:\ProgramData\update_ms.msi`.

## Technical Analysis of the Malicious Payload

### 1. MSI Installer Delivery and DLL Execution

The payload arrives as `update_ms.msi`, an MSI installer whose metadata is crafted to impersonate a legitimate Windows update. The installer contains an embedded binary named `Bin_lib_EA2AEBC3` (lib.dll) stored in the MSI Binary table. A custom action `CA_Run_EA2AEBC3` is triggered during `InstallFinalize`, loading the DLL directly into memory without writing it to disk. The DLL exports a `RUN` function designed for MSI custom action invocation.

The download uses curl.exe to perform an HTTP GET on port 443 -- notably using plain HTTP despite the typical HTTPS port designation, a deliberate evasion technique to bypass protocol-based inspection that assumes port 443 traffic is TLS-encrypted.

### 2. Rust Runtime and Browser Discovery

msaRAT is implemented in Rust using the Tokio asynchronous runtime. The binary spawns OS threads via the CreateThread API, with the thread count determined by the `TOKIO_WORKER_THREADS` environment variable or the CPU count from GetSystemInfo (minimum 1). Characteristic strings in the binary include `TOKIO_WORKER_THREADS` and `the number of hardware threads is not known`.

The RAT discovers installed browsers using a priority-ordered search:

1. `%ProgramFiles%\Google\Chrome\Application\chrome.exe`
2. `%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe`
3. `%ProgramFiles%\Microsoft\Edge\Application\msedge.exe`
4. `%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe`
5. Windows Registry fallback for Chrome-specific keys

### 3. C2 Infrastructure

**Browser Hijacking via CDP:**

The RAT launches the discovered browser with `--headless=new`, `--remote-debugging-port`, and `--user-data-dir` (pointing to a fresh profile directory to avoid conflicts and bypass Chrome 136's remote debugging restrictions on default profiles). It then:

1. Issues an HTTP GET to `/json/list/` on the debugging port to enumerate debuggable targets
2. Establishes a WebSocket connection via the returned `webSocketDebuggerUrl`
3. Executes sequential CDP commands: `Target.createTarget`, `Page.enable`, `Runtime.enable`
4. Disables Content Security Policy with `Page.setBypassCSP`
5. Registers five JavaScript callback bindings via `Runtime.addBinding`: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
6. Injects JavaScript payload via `Runtime.evaluate` (stored as plaintext in the binary's `.rdata` section)

**WebRTC Channel Establishment:**

The injected JavaScript establishes the C2 data channel:

1. GET request to `/token/v1/{UID}` on the Cloudflare Worker (`is-01-ast[.]ols-img-12[.]workers[.]dev`) retrieves ICE server configuration containing STUN/TURN credentials
2. Creates an RTCPeerConnection with a randomly named DataChannel (5-20 alphanumeric characters)
3. Generates an SDP Offer with ICE candidate gathering (5-second timeout)
4. POST to `/token/v1/{UID}` sends the SDP Offer and receives the SDP Answer
5. The Answer deliberately omits ICE candidates, forcing all traffic through Twilio TURN relays (`global[.]turn[.]twilio[.]com`) rather than allowing direct P2P connections
6. Google STUN server (`stun2[.]l[.]google[.]com`) is used for initial connectivity probing

**Encryption:**

- Layer 1: DTLS (browser-handled, automatic for WebRTC)
- Layer 2: ChaCha20-Poly1305 with ECDH key exchange, initiated when the RAT receives a Handshake frame (0xFE) from the C2

**Flow Control:**

Data is Base64-encoded for passage through CDP string channels, converted back to ArrayBuffer via a `Base64ToArrayBuffer` function. Send buffer management dequeues data when the buffer drops below 24KB.

### 4. Platform-Specific Behavior

#### Windows

msaRAT exclusively targets Windows. Command execution uses `cmd.exe /e:ON /v:OFF /d /c <command>`, which enables command extensions, disables delayed variable expansion, ignores registry AutoRun entries, and executes the specified command. Output is returned through the same WebRTC channel.

### 5. Anti-Forensics / Evasion Techniques

- **Browser-as-proxy:** All network traffic originates from a legitimate browser process (chrome.exe or msedge.exe), not the RAT binary
- **Plain HTTP over port 443:** Initial payload download uses HTTP on port 443 to evade protocol inspection
- **CSP bypass:** `Page.setBypassCSP` disables Content Security Policy in the injected page
- **Separate user profile:** Uses `--user-data-dir` to avoid interfering with the user's browser session and to bypass Chrome 136 debugging restrictions
- **Legitimate infrastructure:** C2 signaling through Cloudflare Workers, data relay through Twilio TURN, connectivity probing via Google STUN
- **Double encryption:** DTLS + ChaCha20-Poly1305 makes traffic inspection infeasible even if intercepted
- **Memory-only DLL:** lib.dll is loaded directly from the MSI Binary table into memory without disk write
- **Headless execution:** `--headless=new` flag prevents any visible browser window
- **HeadlessChrome User-Agent:** The browser sends a HeadlessChrome User-Agent string, and Origin/Referer headers are spoofed as Microsoft's official website

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | C:\ProgramData\update_ms.msi | N/A (not published by Talos) | MSI installer masquerading as Windows update |
| Windows | (in-memory) lib.dll | N/A (not published by Talos) | msaRAT DLL payload with RUN export |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 172[.]86[.]126[.]18:443 | Staging server for MSI payload download |
| Domain | is-01-ast[.]ols-img-12[.]workers[.]dev | Cloudflare Worker C2 signaling endpoint |
| Domain | global[.]turn[.]twilio[.]com | TURN relay for WebRTC data channel |
| Domain | stun2[.]l[.]google[.]com | STUN server for connectivity probing |
| URL Pattern | /token/v1/{UID} | WebRTC SDP offer/answer exchange endpoint |
| URL Pattern | /json/list/ | CDP debuggable targets enumeration (loopback) |

### Behavioral

- Chrome or Edge launched with `--headless=new --remote-debugging-port --user-data-dir` by a non-interactive parent process (MSI installer, service, or RMM tool)
- Non-browser process (lib.dll loaded via msiexec) making loopback HTTP connections to CDP debugging port
- `cmd.exe /e:ON /v:OFF /d /c` spawned from a process tree rooted in msiexec or an RMM tool
- HeadlessChrome User-Agent with spoofed Microsoft Origin/Referer headers
- WebRTC traffic to Twilio TURN servers from a headless browser instance
- MSI custom action `CA_Run_EA2AEBC3` executing embedded binary `Bin_lib_EA2AEBC3`

### Detection Signatures (Vendor)

| Vendor | Signature |
|--------|-----------|
| ClamAV | Win.Downloader.ChaosRaas-10060321-0 |
| Snort 2 | SID 1:66839, 1:66840, 1:66841 |
| Snort 3 | SID 1:66839, 1:301587 |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566 | Phishing | Spam emails used for initial contact with victims |
| T1204.002 | User Execution: Malicious File | Victim executes MSI installer disguised as Windows update |
| T1219 | Remote Access Software | RMM tools installed for persistent access during initial compromise |
| T1105 | Ingress Tool Transfer | curl.exe downloads update_ms.msi from staging IP |
| T1036.005 | Masquerading: Match Legitimate Name | MSI installer metadata impersonates a Windows update |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe /e:ON /v:OFF /d /c used for command execution |
| T1218.007 | System Binary Proxy Execution: Msiexec | MSI custom action loads DLL payload |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 signaling via HTTP/HTTPS to Cloudflare Workers |
| T1102.002 | Web Service: Bidirectional Communication | Cloudflare Workers used for SDP offer/answer exchange |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | ECDH key exchange for ChaCha20-Poly1305 encryption |
| T1572 | Protocol Tunneling | WebRTC DataChannel tunneled through Twilio TURN |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Page.setBypassCSP enables arbitrary JavaScript injection via CDP |

## Impact Assessment

msaRAT represents a significant evolution in C2 evasion. By routing all communications through a legitimate browser process and trusted cloud infrastructure (Cloudflare, Twilio, Google), the RAT's traffic is effectively invisible to traditional network security controls. The double-encrypted WebRTC channel further prevents content inspection. Organizations relying solely on network-based detection (IDS/IPS, proxy, DNS monitoring) will miss this threat unless they specifically monitor for Chrome DevTools Protocol abuse patterns and anomalous browser launching behavior.

The Chaos RaaS group operates a double-extortion model, meaning successful deployment of msaRAT precedes both data exfiltration (via legitimate file-sharing software) and ransomware encryption. The association with MuddyWater suggests state-level resources may be behind some Chaos operations, increasing the sophistication and persistence of campaigns.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for headless browsers with remote debugging
Get-WmiObject Win32_Process | Where-Object {
    ($_.Name -match 'chrome|msedge') -and
    ($_.CommandLine -match '--headless') -and
    ($_.CommandLine -match '--remote-debugging-port')
} | Select-Object ProcessId, Name, CommandLine, ParentProcessId

# Check for MSI payloads in ProgramData
Get-ChildItem -Path "C:\ProgramData" -Filter "*.msi" -Recurse | Select-Object FullName, LastWriteTime, Length

# Check for suspicious cmd.exe invocations
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='CommandLine'] and contains(Data,'/e:ON') and contains(Data,'/v:OFF')]]" -MaxEvents 50
```

### Remediation

1. **Immediate:** Kill any headless browser processes launched with `--remote-debugging-port` by non-interactive parent processes
2. **Block** network access to 172[.]86[.]126[.]18 and is-01-ast[.]ols-img-12[.]workers[.]dev at firewall/proxy
3. **Scan** all endpoints for update_ms.msi in C:\ProgramData and lib.dll loaded via MSI custom actions
4. **Audit** RMM tool installations across the environment; remove unauthorized tools
5. **Rotate** credentials for any accounts accessible from compromised systems
6. **Review** MSI installation logs for custom action CA_Run_EA2AEBC3

### Long-Term Hardening

- Deploy application control policies restricting which processes can launch browsers with debugging flags
- Monitor for Chrome/Edge processes spawned by non-standard parent processes (msiexec, services, RMM agents)
- Implement Sysmon with process creation (EID 1) and network connection (EID 3) logging targeting browser processes
- Consider blocking `--remote-debugging-port` via endpoint protection rules for non-development systems
- Monitor DNS queries to `*.workers.dev` domains from non-browser processes as a generic indicator of Cloudflare Worker abuse

## Detection Rules

These rules target the distinctive artifacts of msaRAT's browser-based C2 mechanism: headless browser launching with CDP debugging, the specific Cloudflare Worker C2 domain, the MSI delivery pattern, and the characteristic command execution flags. IOC-based rules (staging IP, C2 domain) will require updates as infrastructure rotates; behavioral rules (headless browser + debugging port, CDP loopback queries) offer longer-term detection value. All rules validated against their respective toolchains.

### Sigma: Headless Browser Launch with Remote Debugging Port

Detects Chrome or Edge launched with `--headless` and `--remote-debugging-port`, the core technique msaRAT uses to establish its CDP-based C2 channel; no parent process filter is applied to maximize catch rate.

<!-- audit: sigma convert --without-pipeline -t splunk passed; sigma convert --without-pipeline -t log_scale passed; fields: process_creation standard (Image, CommandLine); no defanged values in detection; technique tags only (T1219, T1071.001); confidence downgraded from high to medium due to Selenium/Puppeteer/Playwright FP surface -->

`compile: pass | confidence: medium`

```yaml
title: Headless Browser Launch with Remote Debugging Port
id: 7a3b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects Chrome or Edge launched in headless mode with remote debugging port enabled,
    a technique used by msaRAT to establish covert C2 channels via Chrome DevTools Protocol.
    The RAT launches the browser with --headless=new and --remote-debugging-port flags.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026-07-27
tags:
    - attack.t1219
    - attack.t1071.001
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
    - CI/CD pipelines using headless browsers
    - Web scraping tools launched by scheduled tasks
level: high
```

> **Caveat:** Filter by ParentImage to reduce false positives from legitimate test automation; the rule intentionally omits parent filtering to catch msaRAT regardless of the process chain.

### Sigma: Curl Download of MSI from Known msaRAT Staging Server

Detects curl.exe fetching a payload from the known msaRAT staging IP 172[.]86[.]126[.]18.

<!-- audit: sigma convert --without-pipeline -t splunk passed; sigma convert --without-pipeline -t log_scale passed; IOC-specific rule keying on staging IP; detection value uses real IP (not defanged) -->

`compile: pass | confidence: high`

```yaml
title: Curl Download of MSI from Known msaRAT Staging Server
id: 8b4c2d5e-6f7a-4b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects curl.exe downloading an MSI installer from the known msaRAT staging
    IP address 172.86.126.18 on port 443 using plain HTTP. The Chaos ransomware
    group uses this technique to deliver the msaRAT payload disguised as a
    Windows update (update_ms.msi).
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026-07-27
tags:
    - attack.t1105
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
    selection_target:
        CommandLine|contains: '172.86.126.18'
    condition: selection_curl and selection_target
falsepositives:
    - Unlikely - this is a known malicious staging IP
level: critical
```

### Sigma: MSI File Written to ProgramData Masquerading as Windows Update

Detects the specific file drop pattern used by msaRAT's delivery chain.

<!-- audit: sigma convert --without-pipeline -t splunk passed; sigma convert --without-pipeline -t log_scale passed; file_event category; TargetFilename field standard for Sysmon EID 11 -->

`compile: pass | confidence: high`

```yaml
title: MSI File Written to ProgramData Masquerading as Windows Update
id: 9c5d3e6f-7a8b-4c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: >
    Detects an MSI file named update_ms.msi being created in C:\ProgramData,
    matching the msaRAT delivery mechanism where the Chaos ransomware group
    drops the payload to this location before execution.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026-07-27
tags:
    - attack.t1036.005
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\update_ms.msi'
        TargetFilename|startswith: 'C:\ProgramData'
    condition: selection
falsepositives:
    - Legitimate software update mechanisms writing MSI files to ProgramData
level: high
```

### Sigma: Command Execution via msaRAT Shell Pattern

Detects the specific `cmd.exe /e:ON /v:OFF /d /c` flag combination used by msaRAT for command execution.

<!-- audit: sigma convert --without-pipeline -t splunk passed; sigma convert --without-pipeline -t log_scale passed; contains|all ensures all four flags present; process_creation standard; confidence downgraded from medium to low -- /e:ON /v:OFF /d /c is not unique to msaRAT -->

`compile: pass | confidence: low`

```yaml
title: Command Execution via msaRAT Shell Pattern
id: 1e7f5a8b-9c0d-4e2f-3a4b-5c6d7e8f0a1b
status: experimental
description: >
    Detects cmd.exe execution with the specific flag combination used by msaRAT
    for command execution: /e:ON /v:OFF /d /c. This pattern enables command
    extensions, disables delayed variable expansion, ignores registry AutoRun
    entries, and executes the specified command.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026-07-27
tags:
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_flags:
        CommandLine|contains|all:
            - '/e:ON'
            - '/v:OFF'
            - '/d'
            - '/c'
    condition: selection_cmd and selection_flags
falsepositives:
    - Administrative scripts using this exact combination of cmd.exe flags
    - Software installers invoking cmd.exe with similar parameters
level: medium
```

> **Caveat:** The `/d` and `/c` flags individually are common; the four-flag combination is less common but not exclusively malicious. Correlate with parent process (msiexec, browser, RMM tool) for higher confidence.

### Sigma: DNS Query to msaRAT Cloudflare Worker C2 Domain

Detects DNS resolution of the known msaRAT C2 signaling domain on Cloudflare Workers.

<!-- audit: sigma convert --without-pipeline -t splunk passed; sigma convert --without-pipeline -t log_scale passed; dns_query category; real domain in detection value -->

`compile: pass | confidence: high`

```yaml
title: DNS Query to msaRAT Cloudflare Worker C2 Domain
id: 2f8a6b9c-0d1e-4f3a-4b5c-6d7e8f0a1b2c
status: experimental
description: >
    Detects DNS resolution of the known msaRAT C2 signaling domain hosted
    on Cloudflare Workers infrastructure. The domain is-01-ast.ols-img-12.workers.dev
    is used for SDP offer/answer exchange during WebRTC C2 channel establishment.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026-07-27
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|contains: 'is-01-ast.ols-img-12.workers.dev'
    condition: selection
falsepositives:
    - Unlikely - this is a known malicious C2 domain
level: critical
```

**DROPPED: Sigma Non-Browser Process Initiating Loopback Connection (CDP Abuse)** -- Fires on any non-browser process connecting to 127.0.0.1 with no port filter, producing millions of events/day; description contradicted detection logic.

### YARA: msaRAT Rust RAT Binary Detection

Detects the msaRAT binary via its characteristic CDP binding names, Tokio runtime strings, and CDP command patterns embedded in the PE.

<!-- audit: yarac /tmp/actioner/yara_msarat.yar /dev/null exit code 0; condition requires PE header + size < 10MB + multiple string clusters; binding names (msaOpen, msaClose, etc.) are highly specific to msaRAT -->

`compile: pass | confidence: high`

```yara
import "pe"

rule Malware_Chaos_msaRAT_Rust_RAT
{
    meta:
        description = "Detects msaRAT Rust-based RAT used by Chaos ransomware group via Chrome DevTools Protocol binding names, Tokio runtime strings, and CDP command patterns embedded in the binary"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $binding1 = "msaOpen" ascii
        $binding2 = "msaClose" ascii
        $binding3 = "msaError" ascii
        $binding4 = "msaMessage" ascii
        $binding5 = "dataAck" ascii

        $tokio1 = "TOKIO_WORKER_THREADS" ascii
        $tokio2 = "the number of hardware threads is not known" ascii

        $cdp1 = "Runtime.addBinding" ascii
        $cdp2 = "Runtime.evaluate" ascii
        $cdp3 = "Page.setBypassCSP" ascii
        $cdp4 = "Target.createTarget" ascii
        $cdp5 = "Page.enable" ascii
        $cdp6 = "Runtime.enable" ascii

        $js1 = "Base64ToArrayBuffer" ascii
        $js2 = "RTCPeerConnection" ascii
        $js3 = "createDataChannel" ascii

        $crypto1 = "chacha20" ascii nocase
        $crypto2 = "poly1305" ascii nocase

        $export = "RUN" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($binding*)) or
            (2 of ($binding*) and 2 of ($cdp*)) or
            (2 of ($binding*) and 1 of ($tokio*) and $export) or
            (all of ($cdp*) and 2 of ($js*) and 1 of ($crypto*))
        )
}
```

### Suricata: msaRAT Cloudflare Worker C2 Signaling

Detects HTTP connections to the known msaRAT C2 signaling domain on Cloudflare Workers.

<!-- audit: suricata -T -S /tmp/actioner/suricata_msarat.rules -l /tmp/actioner exit code 0; http protocol with http.host buffer; dot-notation buffers; all required fields present -->

`compile: pass | confidence: high`

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - msaRAT Cloudflare Worker C2 Signaling Domain"; flow:established,to_server; http.host; content:"is-01-ast.ols-img-12.workers.dev"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-27; sid:2100101; rev:1;)
```

### Suricata: msaRAT CDP JSON List Endpoint Query

Detects HTTP requests to the `/json/list/` CDP endpoint on loopback, indicating a process enumerating debuggable browser targets.

<!-- audit: suricata -T validated; http.uri + http.host buffers; loopback host match; confidence downgraded from medium to low -- legitimate test automation (Selenium/Puppeteer/Playwright) queries this same endpoint -->

`compile: pass | confidence: low`

```
alert http $HOME_NET any -> any any (msg:"Actioner - msaRAT CDP JSON List Endpoint Query"; flow:established,to_server; http.uri; content:"/json/list/"; fast_pattern; http.host; content:"127.0.0.1"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-27; sid:2100102; rev:1;)
```

> **Caveat:** Legitimate test automation (Selenium, Puppeteer, Playwright) queries `/json/list/` routinely; requires loopback interface monitoring.

### Suricata: DNS Query for msaRAT C2 Domain

Detects DNS resolution of the known msaRAT C2 domain using Suricata's native dns.query buffer.

<!-- audit: suricata -T validated; dns protocol with dns.query buffer; nocase for case-insensitive matching -->

`compile: pass | confidence: high`

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query for msaRAT Cloudflare Worker C2 Domain"; flow:to_server; dns.query; content:"is-01-ast.ols-img-12.workers.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-27; sid:2100103; rev:1;)
```

### Suricata: msaRAT WebRTC SDP Token Exchange via Workers

Detects HTTP requests to `/token/v1/` on Cloudflare Workers domains, matching the msaRAT SDP offer/answer exchange pattern.

<!-- audit: suricata -T validated; http.uri + http.host buffers; .workers.dev suffix match; confidence downgraded from high to medium -- /token/v1/ on ANY .workers.dev domain matches thousands of legitimate Cloudflare Worker applications -->

`compile: pass | confidence: medium`

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - msaRAT WebRTC SDP Token Exchange via Workers"; flow:established,to_server; http.uri; content:"/token/v1/"; fast_pattern; http.host; content:".workers.dev"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created_at 2026-07-27; sid:2100104; rev:1;)
```

> **Caveat:** The `/token/v1/` path on `.workers.dev` matches thousands of legitimate Cloudflare Worker applications; use only as a correlative indicator alongside other msaRAT signals.

### Snort: msaRAT Plain HTTP Payload Download over Port 443

Detects plain HTTP traffic on port 443 targeting the msaRAT staging IP requesting the MSI payload.

<!-- audit: snort -c /etc/snort/snort.conf -R msa.rules -T validated; tcp protocol on port 443; content matches for staging IP and payload filename -->

`compile: pass | confidence: high`

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - msaRAT Plain HTTP over Port 443 to Staging IP"; flow:established,to_server; content:"GET"; depth:3; content:"172.86.126.18"; content:"update_ms.msi"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created 2026-07-27; sid:2100201; rev:1;)
```

### Snort: msaRAT CDP JSON List Endpoint on Loopback

Detects HTTP requests to the `/json/list/` CDP endpoint on a loopback host, indicating CDP target enumeration.

<!-- audit: snort syntax fixed (comma -> semicolon after content:"/json/list/"); confidence downgraded from medium to low -- legitimate test automation queries this endpoint -->

`compile: pass | confidence: low`

```
alert http $HOME_NET any -> any any (msg:"Actioner - msaRAT CDP JSON List Endpoint on Loopback"; flow:established,to_server; http_uri; content:"/json/list/"; fast_pattern; http_header; content:"Host|3A| 127.0.0.1"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/; metadata:author Actioner, created 2026-07-27; sid:2100202; rev:1;)
```

> **Caveat:** Legitimate test automation queries `/json/list/` routinely; requires Snort on loopback/host-level traffic.

## Lessons Learned

msaRAT demonstrates the growing trend of "living off the browser" -- a natural evolution from living-off-the-land techniques that exploit trusted system binaries. By using the browser as a network proxy and routing C2 through legitimate cloud infrastructure, the Chaos group has created a communication channel that is effectively invisible to traditional network monitoring. Defenders must expand process-level telemetry to cover browser launching patterns (especially headless mode with debugging ports), monitor CDP-related loopback communications, and develop detection logic for anomalous browser parent-child process relationships. The WebRTC-via-TURN pattern -- where the SDP answer deliberately omits ICE candidates to force relay routing -- is a particularly clever technique that may see broader adoption by other threat actors.

## Sources

- [Cisco Talos Blog - Chaos ransomware's msaRAT](https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/) -- primary technical analysis and discovery report
- [Cisco Talos IOCs GitHub](https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/chaos-msarat.txt) -- official indicator of compromise repository
- [BleepingComputer - New msaRAT malware uses Chrome, Edge browsers](https://www.bleepingcomputer.com/news/security/new-msarat-malware-uses-chrome-edge-browsers-to-route-c2-traffic/) -- additional technical reporting and context
- [The Hacker News - Chaos Ransomware Uses msaRAT](https://thehackernews.com/2026/07/chaos-ransomware-uses-msarat-to-route.html) -- supplementary analysis with browser flag details and shell command patterns
- [Help Net Security - Chaos ransomware msaRAT](https://www.helpnetsecurity.com/2026/07/23/cisco-talos-chaos-ransomware-msarat/) -- summary reporting
- [GridinSoft - msaRAT Hides C2 in Chrome and Edge](https://blog.gridinsoft.com/msarat-chrome-edge-browser-c2/) -- detection guidance and Chrome 136 debugging restrictions context

<!-- revision: DROPPED Sigma Non-Browser Loopback rule (no port filter, millions of events/day). FIXED Sigma Headless Browser (removed "Non-Interactive Parent" from title, downgraded high->medium). FIXED Sigma Shell Pattern (downgraded medium->low). FIXED Suricata CDP JSON (downgraded medium->low). FIXED Suricata WebRTC SDP (downgraded high->medium). FIXED Snort CDP JSON (comma->semicolon syntax fix, downgraded medium->low). Removed T1539 (CSP bypass is JS injection not cookie theft, replaced with T1059.007). Removed T1055 (MSI DLL loading already covered by T1218.007). -->

---
*Report generated by Actioner*
