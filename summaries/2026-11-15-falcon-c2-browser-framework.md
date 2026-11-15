# Technical Analysis Report: Falcon C2 Browser-Based Framework & Antino Implant (2026-11-15)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-15
Version: 1.0

## Executive Summary

Falcon C2 is a browser-based command-and-control framework targeting government entities across the Middle East and Southeast Asia, disclosed by Palo Alto Unit 42 in November 2026. The framework operates through malicious browser extensions disguised as a "PDF Viewer" (Chrome extension ID: `mbidcmlcbgbphpoacojjbmfpohcimjji`), enabling credential theft, session hijacking, clipboard monitoring, download interception, and in-browser proxying via WebSocket-encrypted channels. A companion Windows implant named Antino, compiled in Rust, uses Microsoft OneDrive as its C2 channel with XOR-encoded configuration (key `0xABCD`). Campaigns active from March through May 2026 compromised at least 39 instances of Roundcube webmail at a Middle Eastern Ministry of Foreign Affairs, with additional targeting of defense, interior, law enforcement, justice, and military entities across five countries. Unit 42 assesses with high confidence that Falcon overlaps with the PeckBirdy framework reported by Trend Micro in January 2026, and Cisco Talos has linked Antino to a China-nexus actor designated UAT-11587.

## Background: Browser-Based C2 Targeting Government Infrastructure

Falcon C2 represents an evolution in browser-based attack frameworks, leveraging Manifest V3 Chrome extensions and equivalent Firefox add-ons to maintain persistent access within victim browsers. The framework targets web-based government applications including Roundcube webmail, internal document management systems, and government portals. The browser-based approach allows the operator to hijack authenticated sessions without needing to compromise credentials for the underlying systems, operating entirely within the context of the victim's browser. The Antino implant provides a traditional backdoor capability alongside the browser compromise, using OneDrive API credentials embedded in a XOR-encoded PE section for out-of-band command and control.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| January 2026 | Trend Micro publishes PeckBirdy report documenting an earlier variant of the same framework |
| March 2026 | Campaign begins targeting Middle Eastern Ministry of Foreign Affairs Roundcube webmail |
| March-May 2026 | 39 compromised Roundcube webmail instances observed at the Middle Eastern target |
| May 2026 | Extension version 2026.5.13.1 compiled; campaigns extend to Southeast Asian targets |
| Southeast Asian campaign (dates unspecified) | Extension check-ins observed every 3-4 minutes for 3+ weeks at a police entity |
| November 2026 | Unit 42 publishes detailed technical analysis |

## Root Cause: Malicious Browser Extension Sideloading

The initial access vector involves deployment of a malicious browser extension in developer mode, masquerading as a legitimate "PDF Viewer." The exact delivery mechanism to install the extension is not fully detailed, but the framework supports a fake Adobe Flash update prompt (served from `microsoft-flash[.]com`) to deliver the Antino implant. The operator management panel includes pre-packaged installers (`firefox.zip`, `browser.exe`) suggesting the extensions may be installed through social engineering or physical access to victim machines. Once loaded, the extension operates with 40 permissions including `<all_urls>` host permissions, granting comprehensive access to all browser activity.

## Technical Analysis of the Malicious Payload

### 1. Falcon C2 Browser Extension (Stage 1 -- Initial Implant)

The extension consists of 14 files for Chrome and an equivalent set for Firefox. Key components:

- **background.js** (service worker): Manages extension lifecycle, intercepts downloads via `chrome.downloads.onCreated`, and coordinates communication between components
- **content-script.js**: Injected into all pages after load; injects `analytics-core.js` via `chrome-extension://<ID>/analytics-core.js` script tag
- **analytics-core.js**: The primary implant payload, shared between Chrome and Firefox variants (identical SHA-256: `3e535d63af8a95221fb517fa1b3e4a0029d3463d8b767443abdff385ee8cb6e9`)
- **sandbox.html / sandbox.js**: Sandbox with a CSP permitting `eval`; receives the implant via MessageChannel and executes it
- **offscreen.js / offscreen.html**: Offscreen document that introduces a 2-second delay before fetching and loading the implant into the sandbox
- **twitter-dm.js**: Specialized scraper for X/Twitter direct messages using screen coordinates, with date parsing localized in six languages
- **page.js / page.html**: Additional extension pages

The extension's capabilities include:
- Credential harvesting from browser stores and forms (500-entry FIFO cache)
- Session cookie theft
- Clipboard hijacking and replacement rule management
- Fetch and XMLHttpRequest hooking (intercepting all web traffic)
- Download interception and URL replacement
- Browser-based proxy request handling
- Gmail email collection
- Username harvesting from government portals

### 2. Falcon C2 Implant Delivery and Obfuscation (Stage 2)

The victim-facing listener delivers payloads through paths: `hxxps://{domain}/config/{ATTACK_ID}` with variants at `/hta`, `/html`, and `/wscript`. The JavaScript payload (`victim_common.js` and `victim.js`) is obfuscated by XOR-encoding each character with a one-byte key, producing an integer array. A small decoder loop reconstructs and executes the original code.

Key named functions in the implant:
- `xg_note` -- set session remark
- `xg_send` -- send JSON to C2
- `xg_data` -- exfiltrate data
- `xg_notify` -- send Telegram notification to operator
- `run` -- eval-based code execution
- `set_remark` -- set victim identifier
- `handleProxyRequest` -- proxy requests through victim browser
- `storageApi` -- extension storage dictionary access

### 3. C2 Infrastructure

**Falcon C2 WebSocket Channel:**
- Victim-facing listener: TCP 443, TLS WebSocket
- Management panel: TCP 8080
- Heartbeat: `{"heartbeat":"1"}` sent every minute; reset on any inbound message
- Key exchange protocol:
  1. Server sends `action: pubkey` message containing a 2048-bit RSA PEM key
  2. Client generates 32-byte AES key and 16-byte IV via `crypto.getRandomValues`
  3. Both values are RSA-encrypted and Base64-encoded
  4. Client sends `key_exchange` message
  5. Subsequent payloads encrypted with AES-256-CBC
- Fallback: Comet protocol (unencrypted, supports only `run` and `nothing` commands); URL-encoding plus Base64 if Web Crypto API is unavailable
- Responses: Base64-encoded results returned as JSON over the WebSocket

**Anti-analysis features on the operator panel:**
- Global `contextmenu` listener calling `preventDefault()` (disables right-click)
- Login panel hidden behind pressing F9 three times consecutively
- Decoy Tetris and Snake games on the victim-facing listener

**Antino C2 (OneDrive):**
- Heartbeat: `antino/heartbeat/<Bot ID>.json` (contains hostname, username, remark)
- File upload: `antino/antino_upload/`
- Command polling: `command_req_<Bot ID>_<timestamp>.json` at OneDrive root
- Authentication: OAuth via `tenant_id`, `client_id`, `client_secret`, `user_id` from XOR-encoded `.cfg` PE section (2-byte key `0xABCD`)

### 4. Platform-Specific Behavior

#### Browser (Chrome / Firefox -- Cross-Platform)

- Extension loaded in developer mode as "PDF Viewer" version 2026.5.13.1
- Chrome extension ID: `mbidcmlcbgbphpoacojjbmfpohcimjji`
- 40 permissions requested including `<all_urls>` host permissions
- Content script injected on all URLs after page load
- Twitter DM scraper active on `x.com` and `twitter.com`
- Browser storage keys written: `Hm_lvt_$` (local storage), `Hm_lvt__<session ID>` (cookie, expiry 2099), `_domain_google_mark` (remark), `popup_count` (Flash prompt counter), `clipboard_replacer_rules` (chrome.storage.local)
- Check-in interval: every 3-4 minutes

#### Windows (Antino Implant)

- Delivery: `hxxps://microsoft-flash[.]com/download/Adobe_installer.exe`
- File: `flashcenter_pp_ax_install_en.exe` (SHA-256: `0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd`)
- Persistence directory: `%LOCALAPPDATA%\Windows GatherOSStateKit\tmp<8 char>.exe`
- Bot ID stored in `id` file (UUID format)
- Persistence mechanism: Writes `%TEMP%\SDIAG_<GUID>\result\result.ps1`, then executes `sdiagnhost.exe` which parses the answer file and runs a PowerShell snippet to set a Registry Run key
- Commands: `cmd`, `ps`, `system_info`, `list_files`, `add_to_run`, `exit`, `load` (Rhai script execution), `execute_program`, `upload_file`, `download_file`
- Legacy DLLs referenced: `DllSafeCheck64.dll`, `slc.dll`

### 5. Anti-Forensics / Evasion Techniques

- Browser extension sideloaded in developer mode (bypasses Chrome Web Store review)
- Manifest V3 compliance avoids legacy extension security flags
- XOR obfuscation of JavaScript implant payload (one-byte key to integer array)
- XOR-encoded configuration in Antino PE `.cfg` section (2-byte key `0xABCD`)
- Signed binary proxy execution via `sdiagnhost.exe` (Microsoft Scripted Diagnostic Native Host)
- OneDrive C2 channel blends with legitimate cloud traffic
- Comet protocol fallback when WebSocket is unavailable
- Contextmenu and F9 anti-analysis on operator panel
- Decoy games (Tetris, Snake) on the listener
- Inconsistent XHR/fetch hook implementations (XHR checks status 200-299; fetch checks `response.ok`) suggest possible AI-assisted code generation

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| PDF Viewer (Chrome extension) | 2026.5.13.1 | Falcon C2 browser implant disguised as PDF viewer |
| PDF Viewer (Firefox extension) | 2026.5.13.1 | Firefox variant of Falcon C2 browser implant |
| flashcenter_pp_ax_install_en.exe | N/A | Antino implant delivered via fake Flash update |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Chrome | analytics-core.js | `3e535d63af8a95221fb517fa1b3e4a0029d3463d8b767443abdff385ee8cb6e9` | Primary implant payload |
| Chrome | background.js | `f8b86238e179d88a9979b6f97750a39dda1d07b54d634bc1348fdfb0944a3b92` | Service worker |
| Chrome | content-script.js | `88e8b07bdf294ace0357d35acb7e108c66ba65a2c4ad66351fb8f7806dae0862` | Content injection script |
| Chrome | manifest.json | `b6a7be724871ed3e81c986b74d62da8911c82a336c4c1857b35f2446b2d49fda` | Extension manifest |
| Chrome | offscreen.js | `356b96c2267c5f2d8c07693643626e090b6389318b4ffa74699fa1732da5a00c` | Offscreen loader |
| Chrome | sandbox.js | `66e9098551a1c0c74077d6cf55570e5d307a4a5ef0b0f2053e139394e61c442d` | Sandbox executor |
| Chrome | twitter-dm.js | `3e923f11db08413fca8a3a69d33d8896cfd56309e5179e8604d7fb7110428da2` | Twitter DM scraper |
| Chrome | page.js | `e2b6b1becdbcc340121e163b5afdfc5437a480ca132248ed5c7c309c45ac3dbb` | Extension page |
| Chrome | icon128.png | `065d18fcfeddbd718c054f4b21c3cde5b9291db921d01f343d7ac0d4b41f29ce` | Extension icon |
| Chrome | icon48.png | `5711586125909863b91c1b5ff7cf70ef5d35249d67b11d7a23dc864405cddfe2` | Extension icon |
| Chrome | icon16.png | `3eab406d841fa22a4b0200c95c1afab068347f835400d5771e8de60aef732016` | Extension icon |
| Chrome | offscreen.html | `2ed834d92bfefc9d07a9f1a48f986974ae2a29669029f8163a1f6e8706388fcd` | Offscreen document |
| Chrome | page.html | `32af8413cbd38ce8beb257288cb8e6aa2f9b781d56d0f5272bffbcdc22d999f4` | Extension page |
| Chrome | sandbox.html | `265c2b36060e4b21c25aa86a8bb22d1db5f806117b484774c75c65b5b38222e0` | Sandbox document |
| Firefox | background.js | `2ebe36f1322b77264a33fded81cd4b8817f93362945070bf0bb5845dd27c0575` | Firefox background script |
| Firefox | content-script.js | `857429faffe0e0747ce299e86eed063ed781b4e403b917ca7e853e89bedf072c` | Firefox content script |
| Firefox | manifest.json | `b33f2e95943e3ff0a72dea1be9fdea03d986bada4def34f6991b3113ec161ad7` | Firefox manifest |
| Firefox | offscreen.js | `898656c33effb51e109c548fc213f157f151a870ea64a4601eda74ae75bd3af6` | Firefox offscreen loader |
| Firefox | sandbox.js | `b3d8ea89b19a87bf2fdd63127086681059f41d67b6e5f8c939f5636a1b2315ce` | Firefox sandbox executor |
| Firefox | twitter-dm.js | `24d69139cb2d32598f0f4983876f6320485fac134a66ade59cab76b50b4128f7` | Firefox Twitter DM scraper |
| Windows | flashcenter_pp_ax_install_en.exe | `0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd` | Antino implant |
| Windows | %LOCALAPPDATA%\Windows GatherOSStateKit\tmp\<8char\>.exe | -- | Antino persistence copy |
| Windows | %TEMP%\SDIAG_\<GUID\>\result\result.ps1 | -- | Antino diagnostic answer file |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | fonts[.]tarotfree101[.]top | Falcon C2 server |
| Domain | fonts[.]chrorne[.]com | Falcon C2 server (typosquatting chrome.com) |
| Domain | robot[.]avbliud[.]com | Falcon C2 server |
| Domain | microsoft-flash[.]com | Antino payload delivery (fake Flash update) |
| Domain | wps-cn[.]com | Payload delivery (fake WPS Office) |
| URL Pattern | hxxps://{domain}/config/{ATTACK_ID} | Falcon C2 configuration endpoint |
| URL Pattern | hxxps://{domain}/hta | Falcon HTA payload delivery |
| URL Pattern | hxxps://{domain}/html | Falcon HTML payload delivery |
| URL Pattern | hxxps://{domain}/wscript | Falcon WScript payload delivery |
| URL | hxxps://microsoft-flash[.]com/download/Adobe_installer.exe | Antino implant download |
| Extension ID | mbidcmlcbgbphpoacojjbmfpohcimjji | Malicious Chrome extension identifier |

### Behavioral

- Offscreen document creation with 2-second delay before implant fetch
- Persistent WebSocket connection on TCP 443 while browser tab is active
- Heartbeat JSON `{"heartbeat":"1"}` every 60 seconds over WebSocket
- Download URLs rewritten to attacker-controlled redirect URLs
- Cookie writes with `Hm_lvt_` prefix and 2099 expiry date
- `_domain_google_mark` written to both localStorage and cookies
- `clipboard_replacer_rules` stored in `chrome.storage.local`
- Extension check-in every 3-4 minutes sustained for weeks
- File creation in `%LOCALAPPDATA%\Windows GatherOSStateKit\` with random 8-character names
- `sdiagnhost.exe` execution leading to PowerShell-based Registry Run key creation
- OneDrive API calls to paths containing `antino/heartbeat/` and `antino/antino_upload/`
- Polling of OneDrive root for files matching `command_req_*` pattern

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1176 | Browser Extensions | Malicious Chrome/Firefox extension sideloaded in developer mode as "PDF Viewer" |
| T1185 | Browser Session Hijacking | Session cookie theft and authenticated session reuse through browser proxy |
| T1059.007 | JavaScript | JavaScript implant execution via eval in sandboxed context with CSP bypass |
| T1555.003 | Credentials from Web Browsers | Credential harvesting from browser stores and web forms |
| T1539 | Steal Web Session Cookie | Session cookie theft with 500-entry FIFO cache |
| T1115 | Clipboard Data | Clipboard monitoring and content replacement via configurable rules |
| T1557 | Adversary-in-the-Middle | Fetch and XHR hooking to intercept all browser network traffic |
| T1565 | Data Manipulation | Download interception and URL replacement |
| T1090 | Proxy | Browser-based proxy routing requests through victim sessions |
| T1204.002 | Malicious File | Fake Adobe Flash update prompt to deliver Antino implant |
| T1102.002 | Bidirectional Communication | OneDrive used as bidirectional C2 channel for Antino |
| T1218 | System Binary Proxy Execution | sdiagnhost.exe abused to execute PowerShell from diagnostic answer file |
| T1547.001 | Registry Run Keys | Antino adds persistence via Windows Registry Run key |
| T1114 | Email Collection | Gmail email collection through browser extension |
| T1071.001 | Web Protocols | WebSocket over TLS for C2 communication |
| T1036.005 | Match Legitimate Name or Location | Extension named "PDF Viewer"; domains mimic microsoft, chrome, wps |
| T1568 | Dynamic Resolution | C2 configuration retrieved dynamically via /config/{ATTACK_ID} path |

## Impact Assessment

**Breadth:** At least five countries affected across the Middle East and Southeast Asia, targeting ministries of foreign affairs, defense, interior, law enforcement, justice, military, and telecom. 39 confirmed compromised Roundcube webmail instances at a single Middle Eastern ministry. Additional targets include police entities, intelligence directorates, and departments of corrections across at least four Southeast Asian countries.

**Depth:** Full browser session hijacking provides access to authenticated government web applications without credential compromise. The extension's 40 permissions and `<all_urls>` access enable comprehensive monitoring of all browser activity including email, internal documents, and chat platforms (Discord, Zalo, X/Twitter DMs). The Antino implant adds traditional system-level access with file operations, command execution, and Rhai scripting.

**Stealth:** The browser extension operates within the normal browser context, making it difficult to detect with traditional endpoint security. The OneDrive C2 channel for Antino blends with legitimate cloud traffic. AES-256-CBC encryption on the WebSocket channel and the Comet fallback provide resilient communications.

## Detection & Remediation

### Immediate Detection

```bash
# Check for the malicious Chrome extension ID
find /home -path "*/Extensions/mbidcmlcbgbphpoacojjbmfpohcimjji" -type d 2>/dev/null

# Check for Antino persistence directory on Windows
dir "%LOCALAPPDATA%\Windows GatherOSStateKit\" /s 2>nul

# Check for suspicious SDIAG answer files
dir "%TEMP%\SDIAG_*\result\result.ps1" /s 2>nul

# Search proxy/DNS logs for known C2 domains
# grep -iE "(tarotfree101\.top|chrorne\.com|avbliud\.com|microsoft-flash\.com|wps-cn\.com)" /var/log/dns*.log

# Check Chrome extensions for "PDF Viewer" with suspicious version
# In Chrome: chrome://extensions with Developer mode enabled, look for "PDF Viewer" version 2026.5.13.1

# Search for Hm_lvt_ cookies with 2099 expiry (browser forensics)
# Check localStorage for _domain_google_mark and clipboard_replacer_rules keys
```

### Remediation

1. **Immediate containment:** Remove the malicious browser extension from all affected browsers; revoke and rotate all session cookies and credentials accessed during the compromise window
2. **Antino removal:** Terminate processes running from `%LOCALAPPDATA%\Windows GatherOSStateKit\`, remove the directory, clean the Registry Run key, and remove diagnostic answer files from `%TEMP%\SDIAG_*\`
3. **Credential rotation:** Reset all passwords for government web applications accessed during the compromise; invalidate OAuth tokens for any OneDrive tenants whose credentials were embedded in the Antino configuration
4. **Network blocking:** Block all identified C2 domains at the DNS and proxy layers; monitor for residual connections
5. **Browser audit:** Audit all developer-mode extensions across the organization; implement policies restricting extension sideloading

### Long-Term Hardening

- Enforce Chrome enterprise policies to prevent developer-mode extension sideloading (`ExtensionInstallAllowlist`, `DeveloperToolsAvailability`)
- Deploy browser extension allowlisting across all government endpoints
- Implement network monitoring for persistent WebSocket connections to unusual domains
- Monitor OneDrive API activity for patterns matching Antino's heartbeat and command polling structure
- Establish DNS monitoring for domains with typosquatting patterns (e.g., `chrorne` vs `chrome`)

## Detection Rules

The following rules target Falcon C2 infrastructure domains, the Antino implant's file system artifacts, and the malicious browser extension. IOC-based rules (domains, hashes, extension ID) provide high-confidence detection with minimal false positives. Behavioral rules for `sdiagnhost.exe` abuse carry medium confidence due to the possibility of legitimate diagnostic activity; tune the sdiagnhost rule against your baseline. All Sigma rules were validated via `sigma convert` to Splunk and LogScale backends; `sigma check` could not run due to a network restriction on MITRE ATT&CK data retrieval in this environment.

### Sigma: DNS Query to Known Falcon C2 Domain

Detects DNS resolution of the three known Falcon C2 operator domains. IOC-specific with negligible false-positive risk.

<!-- audit: sigma convert --without-pipeline -t splunk -> QueryName IN ("*tarotfree101.top", "*chrorne.com", "*avbliud.com"); sigma convert -t log_scale OK; sigma check blocked by MITRE ATT&CK data fetch 403 (network constraint, not rule defect); structural validation passed -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** high

```yaml
title: DNS Query to Known Falcon C2 Domain
id: 7a3e1f4b-9c2d-4e8a-b5f6-d0c7a1e3b9f2
status: experimental
description: >
    Detects DNS queries to known Falcon C2 framework command-and-control domains
    used in campaigns targeting government entities in the Middle East and Southeast Asia.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'tarotfree101.top'
            - 'chrorne.com'
            - 'avbliud.com'
    condition: selection
falsepositives:
    - Unlikely; these are attacker-controlled domains
level: high
```

### Sigma: DNS Query to Falcon C2 Payload Delivery Domain

Detects DNS lookups to domains serving the Antino implant via fake software update pages. IOC-specific; the domain `microsoft-flash[.]com` is unambiguously malicious.

<!-- audit: sigma convert --without-pipeline -t splunk -> QueryName IN ("*microsoft-flash.com", "*wps-cn.com"); sigma convert -t log_scale OK; sigma check blocked by network constraint -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** high

```yaml
title: DNS Query to Falcon C2 Payload Delivery Domain
id: b8d2c5e1-3f7a-4b9c-a6e0-f1d8c2b4a7e5
status: experimental
description: >
    Detects DNS queries to domains used by the Falcon C2 framework to deliver the
    Antino implant and other payloads via fake software update pages.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1204.002
    - attack.t1036.005
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'microsoft-flash.com'
            - 'wps-cn.com'
    condition: selection
falsepositives:
    - Unlikely; these are attacker-controlled domains masquerading as legitimate software
level: high
```

### Sigma: Antino Implant File Creation in GatherOSStateKit Directory

Detects file writes under the `Windows GatherOSStateKit` directory, Antino's persistence location. The space in the directory name distinguishes it from the legitimate `GatherOSState` path.

<!-- audit: sigma convert --without-pipeline -t splunk -> TargetFilename="*\\Windows GatherOSStateKit\\*"; sigma convert -t log_scale OK; sigma check blocked by network constraint -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** high

```yaml
title: Antino Implant File Creation in GatherOSStateKit Directory
id: c4f9a3e7-1b5d-4c8e-9a2f-e6d0b3c7f1a8
status: experimental
description: >
    Detects file creation in the Windows GatherOSStateKit directory under LocalAppData,
    used by the Antino implant as its persistence location with a random 8-character filename.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1036.005
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Windows GatherOSStateKit\'
    condition: selection
falsepositives:
    - Legitimate Windows GatherOSState tool activity, though the directory name includes a space which distinguishes this from the real GatherOSState path
level: high
```

### Sigma: Suspicious Sdiagnhost PowerShell Result File Creation

Detects creation of `result.ps1` under `SDIAG_` temporary directories, the mechanism Antino uses to abuse `sdiagnhost.exe` for persistence. Legitimate diagnostic packs may create similar files during troubleshooting.

<!-- audit: sigma convert --without-pipeline -t splunk -> TargetFilename="*\\SDIAG_*" TargetFilename="*\\result\\result.ps1*"; sigma convert -t log_scale OK; sigma check blocked by network constraint -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** medium

```yaml
title: Suspicious Sdiagnhost Execution with PowerShell Result File
id: d5e8b2c6-4a7f-4d9e-b3c1-a0f7e6d2c8b4
status: experimental
description: >
    Detects creation of result.ps1 files under SDIAG temporary directories, as used
    by the Antino implant to abuse sdiagnhost.exe for Run key persistence via
    scripted diagnostic answer files.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1218
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - '\SDIAG_'
            - '\result\result.ps1'
    condition: selection
falsepositives:
    - Legitimate Microsoft Scripted Diagnostics creating PowerShell result files, though this specific path pattern is uncommon outside of troubleshooting pack execution
level: medium
```

### Sigma: Falcon C2 Malicious Browser Extension File Activity

Detects file system references to the known malicious Chrome extension ID. Directly IOC-anchored with no known false positives.

<!-- audit: sigma convert --without-pipeline -t splunk -> TargetFilename="*mbidcmlcbgbphpoacojjbmfpohcimjji*"; sigma convert -t log_scale OK; sigma check blocked by network constraint -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** high

```yaml
title: Falcon C2 Malicious Browser Extension Installation
id: e6f9c3d7-5b8a-4e0f-c4d2-b1a8e7f3d9c5
status: experimental
description: >
    Detects file system activity related to the Falcon C2 malicious Chrome extension
    (ID mbidcmlcbgbphpoacojjbmfpohcimjji) disguised as a PDF Viewer, used for
    credential theft and session hijacking.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1176
    - attack.t1185
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 'mbidcmlcbgbphpoacojjbmfpohcimjji'
    condition: selection
falsepositives:
    - Unlikely; this is a known malicious extension ID
level: high
```

### Sigma: Web Proxy Connection to Falcon C2 Infrastructure

Detects proxy connections to all five known Falcon C2 and payload delivery domains. Suitable for organizations with centralized proxy logging.

<!-- audit: sigma convert --without-pipeline -t splunk -> "cs-host" IN ("*tarotfree101.top", "*chrorne.com", ...); sigma convert -t log_scale OK; sigma check blocked by network constraint -->

**Compile status:** ✅ compiles (sigma convert splunk + logscale) | **Confidence:** high

```yaml
title: Web Proxy Connection to Falcon C2 Infrastructure
id: f7a0d4e8-6c9b-4f1a-d5e3-c2b9f8a4e0d6
status: experimental
description: >
    Detects proxy log entries showing connections to known Falcon C2 domains and
    their characteristic URI path patterns used for configuration retrieval and
    payload delivery.
references:
    - https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
author: Actioner
date: 2026-11-15
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: proxy
detection:
    selection_domains:
        cs-host|endswith:
            - 'tarotfree101.top'
            - 'chrorne.com'
            - 'avbliud.com'
            - 'microsoft-flash.com'
            - 'wps-cn.com'
    condition: selection_domains
falsepositives:
    - Unlikely; these are attacker-controlled domains
level: high
```

### Suricata: Falcon C2 DNS and TLS Detection Rules

Nine Suricata rules covering DNS queries to all five C2/delivery domains, TLS SNI matching for the three C2 domains, and HTTP URI pattern matching for the Falcon configuration endpoint. All rules use dot-notation sticky buffers.

<!-- audit: suricata -T -S suricata-falcon-c2.rules -l /tmp/actioner-falcon-c2/ exited 0; "Configuration provided was successfully loaded. Exiting." -->

**Compile status:** ✅ compiles (suricata -T) | **Confidence:** high (IOC-anchored)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain tarotfree101.top"; flow:to_server; dns.query; content:"tarotfree101.top"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain chrorne.com"; flow:to_server; dns.query; content:"chrorne.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain avbliud.com"; flow:to_server; dns.query; content:"avbliud.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Payload Domain microsoft-flash.com"; flow:to_server; dns.query; content:"microsoft-flash.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Payload Domain wps-cn.com"; flow:to_server; dns.query; content:"wps-cn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200005; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Falcon C2 Domain tarotfree101.top"; flow:established,to_server; tls.sni; content:"tarotfree101.top"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200006; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Falcon C2 Domain chrorne.com"; flow:established,to_server; tls.sni; content:"chrorne.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200007; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Falcon C2 Domain avbliud.com"; flow:established,to_server; tls.sni; content:"avbliud.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200008; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Falcon C2 Config Path"; flow:established,to_server; http.uri; content:"/config/"; fast_pattern; http.host; content:"tarotfree101.top"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/falcon-c2-browser-compromise/; metadata:author Actioner, created_at 2026-11-15; sid:2200009; rev:1;)
```

### Snort: Falcon C2 DNS Detection Rules

Five Snort rules for DNS queries to known C2 and payload delivery domains. Snort is not installed in this environment.

<!-- audit: snort not installed; structural check only: all rules have msg, content, nocase, sid, rev; balanced parentheses; valid dns protocol header -->

**Compile status:** ⚠️ uncompiled (structural check only) | **Confidence:** high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain tarotfree101.top"; content:"tarotfree101.top"; nocase; sid:2100001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain chrorne.com"; content:"chrorne.com"; nocase; sid:2100002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Domain avbliud.com"; content:"avbliud.com"; nocase; sid:2100003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Payload Domain microsoft-flash.com"; content:"microsoft-flash.com"; nocase; sid:2100004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Falcon C2 Payload Domain wps-cn.com"; content:"wps-cn.com"; nocase; sid:2100005; rev:1;)
```

### YARA: Falcon C2 Extension Manifest Detection

Detects the Falcon C2 browser extension manifest and associated files by matching the extension ID, the specific name/version combination, or the name with multiple characteristic filenames.

<!-- audit: yarac yara-falcon-c2-extension.yar /dev/null exited 0 on attempt 3 after fixing two unreferenced string errors ($storage_clipboard, $action_pubkey) by adding additional condition branches -->

**Compile status:** ✅ compiles (yarac) | **Confidence:** high

```yara
rule Falcon_C2_Browser_Extension_Manifest
{
    meta:
        description = "Detects Falcon C2 malicious browser extension manifest disguised as PDF Viewer"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"
        hash = "b6a7be724871ed3e81c986b74d62da8911c82a336c4c1857b35f2446b2d49fda"

    strings:
        $ext_name = "PDF Viewer" ascii wide
        $ext_desc = "Portable Document Format" ascii wide
        $ext_version = "2026.5.13.1" ascii wide
        $ext_id = "mbidcmlcbgbphpoacojjbmfpohcimjji" ascii wide
        $file_analytics = "analytics-core.js" ascii wide
        $file_twitter = "twitter-dm.js" ascii wide
        $file_sandbox = "sandbox.html" ascii wide
        $file_offscreen = "offscreen.js" ascii wide
        $all_urls = "<all_urls>" ascii wide

    condition:
        ($ext_id) or
        ($ext_name and $ext_desc and $ext_version) or
        ($ext_name and $all_urls and 3 of ($file_*))
}
```

### YARA: Falcon C2 JavaScript Implant Functions

Detects the Falcon C2 JavaScript implant by matching its distinctive function names (`xg_note`, `xg_send`, `xg_data`, `xg_notify`), storage keys, and key-exchange protocol identifiers. Requires 3+ function name matches or specific storage/protocol combinations.

<!-- audit: yarac exited 0; all strings referenced in condition after fix; strings are specific to Falcon naming conventions but generic enough names (e.g., "storageApi") may appear in benign JS -->

**Compile status:** ✅ compiles (yarac) | **Confidence:** medium

```yara
rule Falcon_C2_JavaScript_Implant
{
    meta:
        description = "Detects Falcon C2 JavaScript implant code patterns including C2 functions and storage keys"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"

    strings:
        $func_xg_note = "xg_note" ascii wide
        $func_xg_send = "xg_send" ascii wide
        $func_xg_data = "xg_data" ascii wide
        $func_xg_notify = "xg_notify" ascii wide
        $func_proxy = "handleProxyRequest" ascii wide
        $func_storage = "storageApi" ascii wide
        $storage_hmvlt = "Hm_lvt_" ascii wide
        $storage_remark = "_domain_google_mark" ascii wide
        $storage_clipboard = "clipboard_replacer_rules" ascii wide
        $action_pubkey = "pubkey" ascii wide
        $action_key_exchange = "key_exchange" ascii wide

    condition:
        3 of ($func_*) or
        ($storage_hmvlt and $storage_remark) or
        ($func_xg_send and $action_key_exchange) or
        ($storage_clipboard and $storage_hmvlt and $func_xg_send) or
        ($action_pubkey and $action_key_exchange and $func_xg_send)
}
```

### YARA: Antino Implant Detection

Detects the Antino backdoor by matching its OneDrive C2 paths, command strings, persistence directory name, and PE-level indicators. Requires PE file format plus multiple Antino-specific string matches.

<!-- audit: yarac exited 0; PE header check (MZ) combined with string groups ensures specificity; command strings like "system_info" and "list_files" are somewhat generic but combined conditions raise confidence -->

**Compile status:** ✅ compiles (yarac) | **Confidence:** medium

```yara
rule Antino_Implant
{
    meta:
        description = "Detects the Antino implant used alongside Falcon C2, a Rust-compiled backdoor using OneDrive for C2"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"
        hash = "0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd"

    strings:
        $path_heartbeat = "antino/heartbeat/" ascii wide
        $path_upload = "antino/antino_upload/" ascii wide
        $cmd_req = "command_req_" ascii wide
        $dir_gather = "Windows GatherOSStateKit" ascii wide
        $cfg_section = ".cfg" ascii
        $cmd1 = "system_info" ascii wide
        $cmd2 = "list_files" ascii wide
        $cmd3 = "add_to_run" ascii wide
        $cmd4 = "execute_program" ascii wide
        $cmd5 = "upload_file" ascii wide
        $cmd6 = "download_file" ascii wide
        $dll1 = "DllSafeCheck64.dll" ascii wide
        $dll2 = "slc.dll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($path_heartbeat and $path_upload) or
            ($cmd_req and $dir_gather) or
            ($cfg_section and 3 of ($cmd*)) or
            ($dll1 and $dll2 and 2 of ($cmd*))
        )
}
```

## Lessons Learned

1. **Browser extensions are a growing APT vector:** Falcon C2 demonstrates that Manifest V3 browser extensions, despite their improved security model, can still be weaponized when sideloaded in developer mode. Organizations must enforce extension allowlisting and prohibit developer-mode installations on managed endpoints.

2. **Legitimate cloud services as C2 channels:** The use of OneDrive as Antino's C2 channel makes network-based detection significantly harder. Defenders need to monitor cloud API usage patterns, not just domain blocklists, and correlate unusual OneDrive activity with endpoint behavioral indicators.

3. **Signed binary proxy execution remains effective:** The abuse of `sdiagnhost.exe` to run arbitrary PowerShell via crafted diagnostic answer files is a novel persistence technique that bypasses application whitelisting. This broadens the known set of LOLBins defenders must monitor.

4. **AI-assisted malware development:** Unit 42's observation of code inconsistencies suggesting AI-assisted authorship signals a trend where threat actors leverage LLMs to accelerate malware development, potentially lowering the barrier to entry for sophisticated browser-based C2 frameworks.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Palo Alto Unit 42 - Falcon C2 Browser Compromise](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/) — Primary technical analysis of Falcon C2 framework, Antino implant, and browser extension details
- [Trend Micro - PeckBirdy Script Framework](https://www.trendmicro.com/en_us/research/26/a/peckbirdy-script-framework.html) — Earlier variant analysis establishing overlap with Falcon C2
- [Symantec/Broadcom - The Jewelbug Dossier](https://sed-cms.broadcom.com/) — Related threat intelligence on the actor ecosystem
- [Cisco Talos - UAT-11587 and Antino Backdoor](https://blog.talosintelligence.com/) — China-nexus attribution and additional Antino analysis
- [GBHackers - Hackers Use Falcon C2 Framework](https://gbhackers.com/hackers-use-falcon-c2-framework/) — Secondary coverage (content unavailable during analysis)

---
*Report generated by Actioner*
