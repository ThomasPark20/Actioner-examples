# Technical Analysis Report: UAT-11587 Antino Rust Backdoor Campaign (2026-10-01)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-01
Version: 1.0 (DRAFT)

## Executive Summary

UAT-11587 is a China-nexus threat actor conducting a sustained espionage campaign targeting government, defense, legislative, and policy organizations across at least eight Asian countries. Cisco Talos assesses with high confidence that UAT-11587 is China-nexus, based on converging development artifacts (Simplified Chinese metadata, +08:00 timestamps, use of the rsproxy.cn Rust crate mirror), infrastructure patterns, and geopolitical targeting aligned with PRC strategic interests. The campaign has compromised approximately 350 endpoints across at least 10 confirmed and 5 probable institutional environments between September 2025 and July 2026.

The actor deploys a custom Rust backdoor called "Antino" through a five-stage infection chain: spear-phishing emails with cloned Gmail attachment widgets lead to HTA or WSF stagers hosted on Cloudflare Pages, which load JScript downloaders, trigger .NET BinaryFormatter deserialization chains in-memory, and ultimately deploy the Antino backdoor via DLL sideloading through a legitimate Microsoft-signed binary (GatherOsState.exe). Antino communicates with its operators exclusively through Microsoft 365 services --- OneDrive for heartbeats and file transfer, Outlook email for command-and-control --- using OAuth 2.0 client-credentials flow against the Microsoft Graph API, blending C2 traffic with legitimate enterprise Microsoft 365 synchronization.

## Background: Targeted Organizations

UAT-11587 targets government and policy organizations across Asia with a focus on entities relevant to PRC strategic and geopolitical interests. Confirmed target countries include Taiwan (primary), India (largest single wave: ~57 endpoints on June 8-9, 2026), the Philippines, Cambodia, Pakistan, Thailand, Myanmar, and Syria. Targeted sectors span defense and military, executive government, foreign affairs, justice and law enforcement, legislative institutions, government IT services, think tanks, universities, and civil society organizations. The campaign uses politically themed lure documents tailored to each target --- cross-strait issues, ASEAN maritime disputes, bilateral summit proceedings, and legislative affairs --- consistent with intelligence collection requirements of a state-level sponsor.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-09 to 2025-11 | Initial Philippines-themed lures; direct email attachment delivery; Antino Gen1 builds observed |
| 2025-12 to 2026-01 | Antino Gen2 development (AntinoApp manifest, random UUID sessions, OneDrive heartbeats) |
| 2026-01 | Philippines-focused HTA campaigns begin; broader policy lures; standalone fake-installer delivery via microsoft-flash[.]com and wps-cn[.]com |
| 2026-03 to 2026-06 | Campaign acceleration; Philippines, Taiwan, Cambodia, Myanmar, Syria, Pakistan, Thailand targeting |
| 2026-06-08 to 2026-06-09 | Largest concentrated wave targeting India (~57 newly observed endpoints) |
| 2026-07 | Talos investigation completion |
| 2026-09-30 | Cisco Talos public disclosure |

## Root Cause: Spear-Phishing with Sender-Domain Misalignment

Initial access is achieved through spear-phishing emails sent via the Migadu email service using the attacker-controlled domain osc-cdn[.]com as the RFC 5321 envelope sender while spoofing trusted organizational identities in the RFC 5322 From header. Victim organizations with non-enforcing DMARC policies (p=none) accept these messages despite DMARC alignment failures. The email HTML body contains a pixel-perfect clone of the Gmail attachment preview widget, constructed from four inline Base64-encoded PNG images, wrapped in an anchor tag pointing to a Cloudflare Pages URL with protocol-relative notation (`//my-<project>.pages.dev/...`). A `?m=` query parameter encodes a per-recipient identifier for delivery tracking.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 --- HTA/WSF Stager (mshta.exe / wscript.exe)

The victim clicks the cloned Gmail widget link, which downloads an HTA or WSF file from Cloudflare Pages (e.g., `my-662ylt3w[.]pages[.]dev`). The HTA variant executes under mshta.exe: it hides and resizes its window, sends a tracking beacon to the fixed Cloudflare Pages hostname `oisadjfoinsiduhfnoisdnfosdnoifnsoid[.]pages[.]dev` (with the lure title in the URL path and a `?track` query parameter), then imports a Stage 2 JScript from Cloudflare R2 or Amazon CloudFront. The WSF variant sends an HTTP HEAD request to the same tracking hostname and similarly loads Stage 2 JavaScript.

### 2. Stage 2 --- JScript Downloader (In-Process)

Delivered from Cloudflare R2, the JScript runs in-process within mshta.exe. It downloads three encrypted resources: (1) an encrypted JavaScript orchestrator (.js), (2) an encrypted .NET serialized gadget resource (.txt), and (3) a second encrypted .NET serialized gadget resource (.txt). These payloads are decoded with custom Base64 and decrypted with RC4 using an embedded key. The decrypted JScript orchestrator is executed in-memory.

### 3. Stage 3 --- .NET BinaryFormatter Deserialization Chain

The orchestrator instantiates COM-visible .NET classes and passes attacker-controlled serialized data into `BinaryFormatter`. A two-stage deserialization process occurs: stage_1 attempts to disable `ActivitySurrogateSelector`-based gadget chain protections; stage_2 uses `System.Windows.Forms.AxHost+State` with the `ActivitySurrogateSelector` gadget to load an embedded PE (TestAssembly.dll, GUID `b2b3adb0-1669-4b94-86cb-6dd682ddbea3`) directly into mshta.exe memory. Try/catch wrapping ensures compatibility across .NET versions and patches.

### 4. Stage 4 --- TestAssembly.dll Downloader

TestAssembly.dll is a small .NET downloader that operates within the mshta.exe process. It downloads a lure-specific decoy PDF (displayed to the victim to maintain the social engineering pretext), then downloads a three-file DLL-sideloading bundle from cloud infrastructure (Cloudflare R2). The bundle is written to `%LOCALAPPDATA%\Windows GatherOSStateKit\` and consists of:
- **GatherOsState.exe** --- legitimate Microsoft-signed Windows ADK binary
- **slc.dll** --- the Antino Rust backdoor payload
- **OsGather.dat / OsState.dat** --- encrypted configuration data

TestAssembly.dll then launches GatherOsState.exe, which sideloads slc.dll from the local directory and calls its `SLOpen` export to initialize the Antino backdoor.

### 5. Stage 5 --- Antino Rust Backdoor (slc.dll via DLL Sideloading)

Antino is a custom Rust backdoor compiled for x86_64-pc-windows-msvc (Gen2 also targets i686-pc-windows-msvc). Configuration is stored in a custom PE section named `.cfg`, encrypted with an alternating XOR key (0xAB, 0xCD) after a four-byte little-endian JSON length header.

**Antino Gen2 capabilities (December 2025 -- January 2026 builds):**

| Command | Description |
|---------|-------------|
| `system_info` | Collect host and process context telemetry |
| `cmd` | Execute `cmd.exe /C` with output capture |
| `powershell` | Execute `powershell.exe -Command` (optionally proxied through sdiagnhost.exe) |
| `list_files` | Enumerate directory contents |
| `upload_file` | Transfer file from operator's OneDrive to compromised host |
| `download_file` | Exfiltrate file from endpoint to operator's OneDrive |
| `execute_program` | Run operator-supplied program via Windows Scripted Diagnostics |
| `load_shellcode` | Execute Base64-encoded shellcode in-memory with optional sleep masking |
| `add_to_run` | Create HKCU Registry Run key for persistence |
| `exit` | Terminate the Antino runtime |

### 6. C2 Infrastructure --- Microsoft 365 Graph API

Antino authenticates to Microsoft 365 via OAuth 2.0 client-credentials flow (no interactive sign-in) through `login.microsoftonline.com`, using a registered Entra ID application. All C2 communication transits the Microsoft Graph API (`graph.microsoft.com`):

**OneDrive channel (file-based dead-drop):**
- `/antino/heartbeats/{session_id}.json` --- implant registration and 60-second heartbeat (JSON: session ID, timestamp, machine name, username, platform, campaign code)
- `/antino_downloads/{file}` --- exfiltrated files from victim
- `/antino_uploads/{file}` --- operator-staged tools for delivery to victim

**Outlook email channel (command polling every 10 seconds):**
- Subject: `command_req_[session_id]` (operator-to-implant commands)
- Subject: `command_res_[session_id]` (implant-to-operator responses)
- JSON body: `{"command_type": "<command>", "command_data": {...}, "request_id": "<id>"}`

### 7. Persistence --- Windows Scripted Diagnostics Abuse

Antino's `add_to_run` command creates persistence through a process proxy chain: it initializes COM, creates a `CScriptedDiag` instance (CLSID `{1F3D8AA5-9EBF-4EE4-85C2-EA40379AEDE8}`, implemented by sdiageng.dll), initializes with the Program Compatibility Wizard package and a blank Answers XML, creates a temporary working copy in `C:\Windows\Temp\SDIAG_<GUID>`, writes an attacker PowerShell script to the directory, and delegates execution through `%windir%\SysWOW64\sdiagnhost.exe -Embedding`. The PowerShell script creates an HKCU Run value pointing to the Antino executable for persistence across user sign-in.

### 8. Defense Evasion

- **In-memory execution:** Stages 1--4 run entirely in-memory within mshta.exe before any file is written to disk
- **Sleep masking (load_shellcode):** Hooks Sleep and VirtualAlloc, registers a vectored exception handler; tracked memory regions are set to PAGE_READWRITE and encrypted during Sleep; access violations on wake trigger decryption and re-protection
- **Process proxy:** PowerShell execution proxied through sdiagnhost.exe via Windows Scripted Diagnostics, complicating behavioral attribution
- **Cloud service blending:** C2 traffic terminates at graph.microsoft.com and login.microsoftonline.com, widely trusted and commonly allowed in enterprise environments
- **Dead-drop file model:** OneDrive file-based polling decouples operator activity from implant network behavior
- **Nonstandard file extensions:** Sideloading bundle files use randomized extensions (.luy, .pzs, .syk, .lzj, .iwq, .ael, etc.) during transit

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\GatherOsState.exe` | (legitimate Microsoft binary, various hashes) | Sideloading host --- Microsoft-signed Windows ADK binary |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | 09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff | Antino Gen2 backdoor (slc.dll) |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | 0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd | Antino Gen2 backdoor variant |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | e2eb7703047b37b28dc34e6990205d758a2454b39bc655b460606745fadcb530 | Antino Gen2 backdoor variant |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | e7e3b0bcd6798634adf8b49d305f3a7b7682e4b76db549682a183c5a186df4bb | Antino Gen2 backdoor variant |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | fdbd047031c13a17c9f491c9355f44d587584ebe2b8927be8482e6c236c8e1c1 | Antino Gen2 backdoor variant |
| Windows | `%LOCALAPPDATA%\Windows GatherOSStateKit\OsGather.dat` | (various) | Encrypted configuration data |
| Windows | TestAssembly.dll (in-memory) | d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf | Stage 4 .NET downloader |
| Windows | `C:\Windows\Temp\SDIAG_<GUID>\result.ps1` | (dynamic) | Attacker PowerShell script for persistence |

**Standalone fake-installer hashes (Antino bundled as fake Flash/WPS installer):**

| SHA256 | Description |
|--------|-------------|
| 971cb2448b5d67dcc1f5eaa10d12e77f213035ad31230dc2ac7a510610a2059d | Fake installer (flashcenter_pp_ax_install_en.exe) |
| 9b7df409c9a89f7536d3ba7b6d43fb6dbac618c8bb52615ba34cc971ad71bbf3 | Fake installer variant |
| b90a4e770869c28fd2140acb3ebdc50c113bb6f096b4bbdb9ac87c349c70e85e | Fake installer variant |

**Antino Gen1 backdoor hashes:**

| SHA256 | Description |
|--------|-------------|
| 1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da | Antino Gen1 |
| 40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d | Antino Gen1 |
| 5c5c060b272cd4a5c3767edc0e9478bd35b7e1756e183d0446a5491bd65519cb | Antino Gen1 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | osc-cdn[.]com | Attacker-controlled sender domain (spear-phishing envelope sender) |
| Domain | oisadjfoinsiduhfnoisdnfosdnoifnsoid[.]pages[.]dev | Execution tracking beacon (Cloudflare Pages) |
| Domain | my-3lyt6wcp[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-qc39r814[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-662ylt3w[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-6g16qsfe[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-goq6xmbm[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-h3qli6kq[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-sv7c1fzs[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-u0up9qri[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-vtsdod2n[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | my-wgoxp32b[.]pages[.]dev | HTA/WSF stager delivery (Cloudflare Pages) |
| Domain | pub-abfa7742e315485a98a5fafd6dbfb68e[.]r2[.]dev | Stage 2/payload staging (Cloudflare R2) |
| Domain | pub-0173d1566dcd4fd49fa25f11f14bfe4c[.]r2[.]dev | Stage 2/payload staging (Cloudflare R2) |
| Domain | d2nq35tel3ucuo[.]cloudfront[.]net | Stage 2 staging (Amazon CloudFront) |
| Domain | microsoft-flash[.]com | Standalone fake-installer delivery |
| Domain | wps-cn[.]com | Standalone fake-installer delivery |
| IP | 103[.]27[.]110[.]220 | Historical serving IP for wps-cn[.]com |
| URL | hxxps://microsoft-flash[.]com/download/flashcenter_pp_ax_install_en.exe | Fake Flash installer (Antino) |
| URL | hxxps://www[.]wps-cn[.]com/downloads/flashcenter_pp_ax_install_en.exe | Fake WPS installer (Antino) |

### Behavioral

- mshta.exe spawning network connections to `*.pages.dev` domains and subsequently loading .NET assemblies via BinaryFormatter deserialization
- GatherOsState.exe executing from `%LOCALAPPDATA%\Windows GatherOSStateKit\` (outside its legitimate Windows ADK installation path)
- sdiagnhost.exe spawning powershell.exe as a child process (Antino's process proxy for command execution and persistence)
- HKCU Registry Run key creation pointing to GatherOsState.exe or Antino executable path
- Outbound HTTPS to graph.microsoft.com with OneDrive file operations under paths containing `/antino/heartbeats/`, `/antino_downloads/`, or `/antino_uploads/`
- Outlook email activity with subject lines matching `command_req_*` or `command_res_*` patterns (Antino C2 command channel)
- Files written to `%LOCALAPPDATA%\Windows GatherOSStateKit\` with names slc.dll, OsGather.dat, or OsState.dat

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Spear-phishing emails with cloned Gmail attachment widget linking to Cloudflare Pages |
| T1204.001 | User Execution: Malicious Link | Victim clicks fake Gmail attachment preview to download HTA/WSF stager |
| T1218.005 | System Binary Proxy Execution: Mshta | HTA stager and Stages 2--4 execute in-memory within mshta.exe |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JScript downloaders and orchestrators executed in HTA/WSF context |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Antino executes powershell.exe for commands and persistence via sdiagnhost.exe proxy |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | slc.dll sideloaded by legitimate GatherOsState.exe from local directory |
| T1036.005 | Masquerading: Match Legitimate Name or Location | slc.dll and GatherOsState.exe names match legitimate Windows ADK components |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | HKCU Run key persistence via add_to_run command |
| T1027 | Obfuscated Files or Information | RC4-encrypted payloads, custom Base64, XOR-encrypted .cfg PE section |
| T1140 | Deobfuscate/Decode Files or Information | Custom Base64 + RC4 decryption of staged payloads; XOR decryption of configuration |
| T1055 | Process Injection | .NET BinaryFormatter deserialization chain loads PE into mshta.exe memory |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 via Microsoft Graph API (HTTPS to graph.microsoft.com) |
| T1102.002 | Web Service: Bidirectional Communication | OneDrive and Outlook used as bidirectional C2 channels |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Files exfiltrated to operator-controlled OneDrive under /antino_downloads/ |
| T1082 | System Information Discovery | system_info command collects host context |
| T1083 | File and Directory Discovery | list_files command enumerates directory contents |
| T1105 | Ingress Tool Transfer | upload_file delivers tools from operator OneDrive to victim |

## Impact Assessment

The campaign has compromised approximately 350 endpoints across at least 15 institutional environments in eight countries. The primary targets are government organizations handling national security, foreign affairs, defense, and legislative functions --- entities whose compromise would yield significant intelligence value. The Antino backdoor's full capability set (file exfiltration, command execution, shellcode injection, persistence) combined with its M365-based C2 channel (which blends with legitimate enterprise traffic and is difficult to inspect or block without disrupting business operations) makes detection and remediation particularly challenging. The sustained 10-month campaign duration and progressive expansion in targeting scope suggest an active, well-resourced operation.

## Detection & Remediation

### Immediate Detection

```
# Check for Antino sideloading directory
dir "%LOCALAPPDATA%\Windows GatherOSStateKit\" /s 2>nul

# Check for GatherOsState.exe running outside its legitimate ADK path
wmic process where "name='GatherOsState.exe'" get ExecutablePath,ProcessId

# Check HKCU Run keys for suspicious GatherOsState entries
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s | findstr /i "GatherOsState"

# Check for sdiagnhost.exe spawning PowerShell
wmic process where "name='powershell.exe'" get ParentProcessId,CommandLine | findstr /v "findstr"

# Check for slc.dll in non-standard locations
dir "%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll" 2>nul
```

### Remediation

1. **Containment:** Isolate endpoints where GatherOsState.exe is found running from `%LOCALAPPDATA%\Windows GatherOSStateKit\`. Block outbound HTTPS to the identified staging domains at the proxy/firewall level.
2. **Eradication:** Remove the `%LOCALAPPDATA%\Windows GatherOSStateKit\` directory and all contents. Remove any HKCU Run key entries pointing to GatherOsState.exe outside its legitimate ADK path. Kill any running GatherOsState.exe process from the sideloading directory.
3. **Credential rotation:** Rotate credentials for any accounts that were active on compromised endpoints. Review Microsoft 365 Entra ID application registrations for unauthorized OAuth applications with Graph API permissions to OneDrive and Outlook.
4. **Email security:** Enforce DMARC at p=reject or p=quarantine for organizational domains. Review email gateway logs for messages from osc-cdn[.]com.

### Long-Term Hardening

- Enforce strict DMARC policies (p=reject) to prevent sender-domain misalignment attacks
- Block or alert on mshta.exe and wscript.exe execution for non-administrative users via application control policies
- Monitor for DLL sideloading from user-writable directories (GatherOsState.exe loading slc.dll from AppData)
- Audit Entra ID application registrations for OAuth applications with Mail.Read/Mail.Send and Files.ReadWrite.All permissions
- Deploy conditional access policies requiring managed device compliance for Graph API access

## Detection Rules

These detections target the UAT-11587 Antino backdoor campaign at the PoC/advisory-specific altitude, keying on distinctive artifacts from the infection chain: the GatherOsState.exe sideloading path, Antino-specific strings, known staging domains, and the sdiagnhost.exe process proxy. Compiles does not equal fires --- verify each rule against your telemetry pipeline before promoting to production.

### Sigma: GatherOsState DLL Sideloading from AppData

Detects GatherOsState.exe executing from the user's AppData directory, outside its legitimate Windows ADK installation path --- the distinctive sideloading vector used by Antino.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE ATT&CK data fetch blocked by proxy, not a rule issue). sigma convert --without-pipeline splunk exit 0; log_scale exit 0. Distinctive: GatherOsState.exe in AppData is not a legitimate deployment pattern. No known FP. -->
```yaml
title: UAT-11587 Antino Backdoor - GatherOsState DLL Sideloading from AppData
id: 7c4e1a2b-3d5f-4e8a-9b6c-0d1e2f3a4b5c
status: experimental
description: >
    Detects GatherOsState.exe executing from the user's AppData directory, consistent with
    UAT-11587 Antino backdoor deployment via DLL sideloading. Legitimate GatherOsState.exe
    resides in Windows ADK installation paths, not user-writable AppData directories.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
    - https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.txt
author: Actioner
date: 2026-10-01
tags:
    - attack.t1574.002
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GatherOsState.exe'
        Image|contains: '\AppData\Local\'
    condition: selection
falsepositives:
    - Legitimate Windows ADK tools relocated to AppData by administrators (unlikely)
level: high
```

### Sigma: Sdiagnhost Spawning PowerShell (Antino Process Proxy)

Detects sdiagnhost.exe spawning powershell.exe, consistent with Antino's use of Windows Scripted Diagnostics as a process execution proxy. Legitimate troubleshooting packs may trigger this; scope to endpoints of interest.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk exit 0; log_scale exit 0. Behavioral overlap: legitimate Windows troubleshooting packs can invoke PowerShell, but this is uncommon in enterprise environments. Medium confidence due to benign-overlap risk. -->
```yaml
title: UAT-11587 Antino Backdoor - Sdiagnhost Spawning PowerShell
id: 8d5f2b3c-4e6a-5f9b-0c7d-1e2f3a4b5c6d
status: experimental
description: >
    Detects sdiagnhost.exe spawning powershell.exe, consistent with UAT-11587 Antino backdoor
    using Windows Scripted Diagnostics as a process execution proxy to complicate behavioral
    attribution. Antino proxies PowerShell commands and persistence through this framework.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026-10-01
tags:
    - attack.t1059.001
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sdiagnhost.exe'
        Image|endswith: '\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate Windows troubleshooting packs executing PowerShell remediation scripts
level: medium
```

### Sigma: Mshta Loading HTA from Cloudflare Pages

Detects mshta.exe executing content from a Cloudflare Pages domain (*.pages.dev), consistent with UAT-11587's initial HTA stager delivery mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; log_scale exit 0. Highly distinctive: mshta.exe loading from .pages.dev is not a legitimate enterprise pattern. Low FP risk in corporate environments. -->
```yaml
title: UAT-11587 Antino Backdoor - Mshta Loading HTA from Cloudflare Pages
id: 9e6a3c4d-5f7b-6a0c-1d8e-2f3a4b5c6d7e
status: experimental
description: >
    Detects mshta.exe executing an HTA file downloaded from a Cloudflare Pages domain
    (*.pages.dev), consistent with UAT-11587 initial access via spear-phishing links
    delivering HTA stagers from attacker-controlled Cloudflare Pages projects.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026-10-01
tags:
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains: '.pages.dev'
    condition: selection
falsepositives:
    - Legitimate HTA applications hosted on Cloudflare Pages (rare in enterprise environments)
level: high
```

### Sigma: Registry Run Key Persistence for GatherOsState

Detects creation of an HKCU Run key entry containing "GatherOsState", consistent with Antino's `add_to_run` persistence command.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk exit 0; log_scale exit 0. Distinctive: GatherOsState is a Windows ADK binary that has no legitimate reason to be in a Run key. No known FP. -->
```yaml
title: UAT-11587 Antino Backdoor - Registry Run Key Persistence for GatherOsState
id: 0f7b4d5e-6a8c-7b1d-2e9f-3a4b5c6d7e8f
status: experimental
description: >
    Detects creation of a Registry Run key entry containing GatherOsState, consistent with
    UAT-11587 Antino backdoor add_to_run persistence command that creates an HKCU Run value
    to launch the sideloading host on user sign-in.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026-10-01
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\'
        Details|contains: 'GatherOsState'
    condition: selection
falsepositives:
    - Legitimate Windows ADK tools configured to start at logon (unlikely via Run key)
level: high
```

### Snort: UAT-11587 Antino Tracking Beacon and Fake Installer Download

Detects outbound HTTP traffic containing the Antino tracking beacon hostname or the known fake Flash installer download URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R exit 0 (pidfile suffix warning is cosmetic, not a rule error). Two rules: (1) tracking beacon hostname oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev; (2) fake installer URI path. Both are IOC-specific, low FP. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11587 Antino Tracking Beacon to Cloudflare Pages"; flow:established,to_server; content:"oisadjfoinsiduhfnoisdnfosdnoifnsoid"; nocase; content:".pages.dev"; nocase; distance:0; within:15; content:"?track"; sid:2100101; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - UAT-11587 Antino Fake Flash Installer Download"; flow:established,to_server; content:"/download/flashcenter_pp_ax_install_en.exe"; fast_pattern; sid:2100102; rev:1; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/;)
```

### Suricata: UAT-11587 Antino DNS and HTTP IOCs

Detects DNS queries for the Antino tracking beacon domain, known C2 delivery domains (microsoft-flash[.]com, wps-cn[.]com), and the fake installer download URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Four rules targeting distinct IOCs: tracking beacon DNS, two delivery domain DNS queries, and the fake installer HTTP URI. All IOC-specific, high precision. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino Tracking Beacon DNS Query"; flow:to_server; dns.query; content:"oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-10-01; sid:2200101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino C2 Domain microsoft-flash"; flow:to_server; dns.query; content:"microsoft-flash.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-10-01; sid:2200102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino C2 Domain wps-cn"; flow:to_server; dns.query; content:"wps-cn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-10-01; sid:2200103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11587 Antino Fake Flash Installer Download URI"; flow:established,to_server; http.uri; content:"/download/flashcenter_pp_ax_install_en.exe"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-10-01; sid:2200104; rev:1;)
```

### YARA: Antino Rust Backdoor and TestAssembly Downloader

Detects the Antino Rust backdoor via distinctive PDB paths (`\antino\antino\target\`), application manifest string ("AntinoApp"), C2 path strings (`/antino/heartbeats/`), and the TestAssembly.dll GUID.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive test fired on constructed sample containing published PDB path + C2 path strings; negative (benign MZ with unrelated content) silent. Two rules: APT_UAT11587_Antino_Backdoor (keys on PDB paths, manifest + C2 paths, source paths + .cfg section, or TestAssembly GUID), APT_UAT11587_TestAssembly_Downloader (keys on GUID + file names). Strings sourced from Talos-published PDB paths and C2 folder names. -->
```yara
rule APT_UAT11587_Antino_Backdoor
{
    meta:
        description = "Detects UAT-11587 Antino Rust backdoor via distinctive PDB paths, application manifest, and C2 path strings"
        author = "Actioner"
        date = "2026-10-01"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff"
        severity = "critical"

    strings:
        $pdb1 = "\\antino\\antino\\target\\" ascii
        $pdb2 = "slc_template.pdb" ascii
        $pdb3 = "antino_client_template.pdb" ascii

        $manifest = "AntinoApp" ascii wide

        $c2path1 = "/antino/heartbeats/" ascii
        $c2path2 = "antino_downloads" ascii
        $c2path3 = "antino_uploads" ascii

        $cmd1 = "command_req_" ascii
        $cmd2 = "command_res_" ascii

        $src1 = "artillery\\run.rs" ascii
        $src2 = "signaller\\mod.rs" ascii

        $cfg_section = ".cfg" ascii fullword

        $guid = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            any of ($pdb*) or
            ($manifest and 2 of ($c2path*)) or
            (3 of ($c2path*, $cmd*)) or
            (any of ($src*) and $cfg_section) or
            $guid
        )
}

rule APT_UAT11587_TestAssembly_Downloader
{
    meta:
        description = "Detects UAT-11587 TestAssembly.dll .NET downloader used in Stage 4 of the Antino infection chain"
        author = "Actioner"
        date = "2026-10-01"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf"
        severity = "high"

    strings:
        $guid = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase
        $name = "TestAssembly" ascii wide
        $path1 = "GatherOsState.exe" ascii wide
        $path2 = "slc.dll" ascii wide
        $path3 = "Windows GatherOSStateKit" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $guid and
        ($name or 2 of ($path*))
}
```

## Lessons Learned

This campaign demonstrates several trends in China-nexus operations: (1) the shift to cloud-native C2 channels (Microsoft 365 Graph API) that blend with legitimate enterprise traffic and resist traditional network inspection; (2) sophisticated multi-stage, in-memory infection chains that minimize disk artifacts; (3) exploitation of email authentication gaps (non-enforcing DMARC) as an initial access vector against government organizations; and (4) abuse of legitimate Microsoft-signed binaries for DLL sideloading to evade application whitelisting. Organizations should prioritize DMARC enforcement, application control for script hosts (mshta.exe, wscript.exe), and behavioral monitoring for DLL sideloading from user-writable directories.

## Sources

- [Cisco Talos: China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) --- primary technical analysis (published 2026-09-30)
- [Cisco Talos IOC Repository: uat-11587-targets-gov.txt](https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.txt) --- comprehensive IOC list (SHA256 hashes, domains, URLs)

---
*Report generated by Actioner*
