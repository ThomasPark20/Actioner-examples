# Technical Analysis Report: UAT-11587 Antino Backdoor — China-Nexus Espionage Targeting Asian Government Entities (2026-09-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-30
Version: 2 (FINAL)

## Executive Summary

UAT-11587 is a China-nexus threat actor conducting sustained cyber espionage operations against government, defense, diplomatic, and policy organizations across at least eight Asian countries. Active since at least September 2025, the campaign delivers a previously undocumented Rust-compiled Windows backdoor called "Antino" through a five-stage infection chain combining spear-phishing emails, HTA/WSF stagers, .NET BinaryFormatter deserialization gadget chains, and DLL sideloading via a legitimate Microsoft ADK binary (GatherOsState.exe). Antino uses Microsoft 365 infrastructure (Outlook and OneDrive via the Microsoft Graph API) as its command-and-control channel, blending C2 traffic with legitimate enterprise Microsoft 365 activity. As of July 2026, Cisco Talos assesses with moderate confidence that the campaign constitutes an intelligence-gathering operation impacting approximately 350 endpoints across 16 institutional environments in Taiwan, India, the Philippines, Cambodia, Pakistan, Thailand, Myanmar, and Syria.

## Background: Targeted Entities and Strategic Context

UAT-11587 targets institutions at the intersection of national security, foreign policy, and governance across the Indo-Pacific and South/Southeast Asia. Victim sectors include defense and military, central government, foreign affairs, legislative bodies, justice and law enforcement, government IT services, think tanks, universities, and civil society organizations. The tailored lure themes -- Taiwan legislative proceedings, Indian government cabinet agendas, Philippine maritime sovereignty disputes, and regional diplomatic summits -- indicate collection requirements aligned with Chinese strategic interests in the region.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| September 2025 | First observed activity; Philippines-themed lures delivered as direct email attachments |
| October 2025 | Antino Gen 1 compiled (earliest known build based on PDB timestamps) |
| November 2025 | Continued Philippines-targeted operations |
| December 2025 - January 2026 | Antino Gen 2 development; expanded infrastructure; introduction of fake installer delivery branch |
| January 2026 | Two additional Philippines HTA campaigns; broader geopolitical lures deployed |
| March - Early June 2026 | Acceleration: closely timed Taiwan and Philippines operations; activity targeting Cambodia, Myanmar, Syria, Pakistan, Thailand |
| June 8-9, 2026 | Largest concentrated wave: ~57 newly observed India endpoints compromised |
| July 2026 | Most recent observed activity (16 institutional environments, ~350 endpoints total) |
| September 30, 2026 | Cisco Talos publishes technical analysis |

## Root Cause: Spear-Phishing with Spoofed Email and Cloned Gmail UI

Initial access relies on spear-phishing emails exploiting a DMARC policy gap. The attacker sends email through the Migadu mail service using the attacker-controlled domain osc-cdn[.]com as the RFC 5321 envelope sender (passing SPF) while spoofing a trusted organization in the RFC 5322 From header. Because the impersonated organization's DMARC policy is set to `p=none` (monitoring only), the receiving mail gateway accepts the message despite DMARC alignment failure.

The email body clones the Gmail attachment card UI using four inline Base64-encoded PNG images wrapped in anchor tags with protocol-relative URLs (`//my-<project>[.]pages[.]dev/File_download?m=<target-id>`). This visually reproduces Gmail's native file-attachment preview, tricking the recipient into clicking what appears to be a legitimate attachment. The `?m=` query parameter provides per-recipient tracking.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: HTA/WSF Stager

The fake attachment link directs to a Cloudflare Pages URL serving either an HTA or WSF file. Both formats are served in parallel (A/B testing or redundancy).

**HTA variant:** Executes via `mshta.exe`. Hides and resizes the window, then emits a tracking beacon to the hardcoded Cloudflare Pages domain `oisadjfoinsiduhfnoisdnfosdnoifnsoid[.]pages[.]dev` with the lure title in the URL path and a `?track` query parameter. It then imports the Stage 2 JScript payload from a Cloudflare R2 or Amazon CloudFront URL.

**WSF variant:** Executes via `wscript.exe` or `cscript.exe`. Sends an HTTP HEAD request to the same tracking hostname with the lure title in the path, then loads Stage 2 JScript from Cloudflare R2.

Decoy document lure themes observed:
- Taiwan information warfare workshop / 2025 TikTok study
- Taiwan legislative tax expense rulings (reproducing Ministry of Finance documents)
- CSIS Indo-Pacific Forecast 2026 event agenda
- Philippine maritime sovereignty (Bajo de Masinloc resolution)
- Indian government cabinet meeting agenda; C-DAC research
- Tehran bilateral summit proceedings
- Cross-border repression seminar
- Trump/Russia/Venezuela geopolitical news summaries

### 2. Stage 2: JScript Downloader and Decryptor

Running in-process within `mshta.exe`, the Stage 2 JScript downloads three encrypted resources from Cloudflare R2 or CloudFront:
1. An encrypted JavaScript orchestrator (`.js` file)
2. An encrypted .NET serialized gadget resource (`.txt` file) -- "stage_1"
3. An encrypted .NET serialized gadget resource (`.txt` file) -- "stage_2"

Each resource is decoded with a custom Base64 variant, then decrypted with RC4 using an embedded key. The decrypted orchestrator is executed in-memory.

### 3. Stage 3: .NET BinaryFormatter Deserialization Chain

The decrypted orchestrator instantiates COM-visible .NET classes from JScript to trigger BinaryFormatter deserialization. This uses a two-stage gadget chain:

**Stage 3a (stage_1 resource):** Targets .NET security checks that block ActivitySurrogateSelector gadgets. Wrapped in try/catch for compatibility across .NET versions and patch levels. Two sequential deserialization calls handle different .NET configurations.

**Stage 3b (stage_2 resource):** The primary gadget chain using `System.Windows.Forms.AxHost+State` deserialization combined with ActivitySurrogateSelector. Surrogate object substitution during deserialization loads the embedded PE "TestAssembly.dll" directly into `mshta.exe` process memory without writing to disk.

### 4. Stage 4: TestAssembly.dll Downloader and Launcher

TestAssembly.dll is a .NET assembly executing in-memory within `mshta.exe`. All observed variants share the AssemblyAttribute GUID `b2b3adb0-1669-4b94-86cb-6dd682ddbea3` (a strong detection marker).

It performs:
1. Downloads the lure-specific decoy PDF document and opens it (user-visible cover)
2. Downloads a three-file DLL sideloading bundle from Cloudflare R2 using nonstandard file extensions (`.luy`, `.pzs`, `.syk`, `.lzj`, `.iwq`, `.ael`, `.thl`, `.czh`, `.mxb`, `.mtm`, `.fsc`, `.pgy`)
3. Writes the bundle to `%LOCALAPPDATA%\Windows GatherOSStateKit\`
4. Launches the legitimate Microsoft-signed `GatherOsState.exe`

### 5. Stage 5: DLL Sideloading and Antino Execution

`GatherOsState.exe` is a legitimate Microsoft Assessment and Deployment Kit (ADK) binary with a valid Microsoft digital signature. When executed from the staging directory, its DLL search order loads the attacker-supplied `slc.dll` (Antino backdoor) instead of the legitimate Software Licensing Client DLL. `GatherOsState.exe` calls the `SLOpen` export, transferring execution to Antino.

### 6. Antino Backdoor Capabilities

Antino is compiled in Rust for both 32-bit and 64-bit Windows. Two generations have been identified: Gen 1 (October 2025) and Gen 2 (December 2025 - January 2026).

**Configuration:** Stored in a custom `.cfg` PE section. The JSON configuration is XOR-encrypted with alternating key bytes `0xAB, 0xCD`, prefixed by a 4-byte little-endian length. Configuration includes Entra ID application credentials, target OneDrive/Outlook details, persistence mode (`run` boolean), and launch mode (`exe`, `raw`, or `dll`).

**Command handlers:**

| Command | Description |
|---------|-------------|
| `cmd` | Execute `cmd.exe /C` commands, capture output |
| `powershell` | Execute `powershell.exe -Command` scripts |
| `system_info` | Collect host/process reconnaissance |
| `execute_program` | Run operator-supplied executables |
| `list_files` | Directory enumeration |
| `upload_file` | Transfer file from OneDrive to victim |
| `download_file` | Exfiltrate file from victim to OneDrive |
| `load_shellcode` | In-memory shellcode injection with optional sleep mask |
| `add_to_run` | Create HKCU Run key for persistence |
| `exit` | Terminate Antino |

**Sleep mask evasion (load_shellcode):** When `use_sleep_mask` is enabled, Antino hooks `Sleep()` and `VirtualAlloc()`, registers a Vectored Exception Handler, and tracks allocated regions. When shellcode calls `Sleep()`, the hook XOR-encrypts the region and changes protection to `PAGE_READWRITE`. On wake, the access violation triggers the VEH, which decrypts and restores `PAGE_EXECUTE_READ`, reducing the time window for memory scanners to detect executable payload bytes.

**Windows Scripted Diagnostics abuse (execute_program / add_to_run):** Antino instantiates CLSID `{1F3D8AA5-9EBF-4EE4-85C2-EA40379AEDE8}` (`CScriptedDiag` from `sdiageng.dll`), initializes the PCW troubleshooting package, writes an attacker-controlled PowerShell script into the temporary directory `C:\Windows\Temp\SDIAG_<GUID>`, then resumes the diagnostic workflow. The diagnostic engine delegates to `sdiagnhost.exe`, which executes the PowerShell script, proxying execution through Microsoft-signed binaries.

### 7. C2 Infrastructure: Microsoft 365 Dead-Drop

Antino authenticates to Microsoft 365 using OAuth 2.0 client-credentials flow with operator-registered Entra ID application credentials, requiring no interactive user sign-in.

**Mechanism 1 -- OneDrive file-based communication:**

| OneDrive Path | Direction | Purpose |
|---------------|-----------|---------|
| `/antino/heartbeats/{session_id}.json` | Implant to Operator | Heartbeat (system info, session ID, campaign code) |
| `/antino_downloads/{file}` | Implant to Operator | Exfiltrated data |
| `/antino_uploads/{file}` | Operator to Implant | Toolkit delivery |

**Mechanism 2 -- Outlook email command channel:**

Commands are polled every 10 seconds via Microsoft Graph API. Email subjects use the format `command_req_[session_id]` (inbound) and `command_res_[session_id]` (outbound). Command and response bodies are JSON objects containing `command_type`, `command_data`/`result`, `request_id`, `success`, and `error` fields.

**Network endpoints:** All C2 traffic goes to `graph.microsoft.com` and `login.microsoftonline.com`, blending with legitimate Microsoft 365 application traffic.

### 8. Standalone Delivery Branch

A parallel delivery method bypasses the HTA chain entirely: spear-phishing emails link to fake installer executables hosted on attacker-registered domains:
- `hxxps://microsoft-flash[.]com/download/flashcenter_pp_ax_install_en.exe`
- `hxxps://www[.]wps-cn[.]com/downloads/flashcenter_pp_ax_install_en.exe`

These deliver standalone Antino payloads configured for direct execution.

### 9. Anti-Forensics / Evasion Techniques

- **Protocol-relative URLs** (`//domain/path`) in phishing emails may evade URL extraction tools expecting fully qualified HTTP/HTTPS URLs
- **Nonstandard file extensions** (`.luy`, `.pzs`, `.syk`, etc.) bypass extension-based security controls
- **In-memory payload execution** via BinaryFormatter deserialization avoids disk writes for intermediate stages
- **Legitimate binary sideloading** (GatherOsState.exe with valid Microsoft signature) evades application whitelisting
- **Sleep mask technique** for shellcode memory obfuscation
- **Scripted Diagnostics framework abuse** proxies PowerShell/registry operations through Microsoft-signed `sdiagnhost.exe`
- **M365 C2 channel** blends with legitimate enterprise traffic to `graph.microsoft.com`
- **DMARC p=none exploitation** for email delivery

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### File Hashes (SHA256) -- Antino Backdoor

| SHA256 | Variant |
|--------|---------|
| `09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff` | Gen 2 slc.dll |
| `0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd` | Gen 2 standalone |
| `1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da` | Gen 1 slc.dll |
| `40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d` | Gen 1 standalone |
| `5c5c060b272cd4a5c3767edc0e9478bd35b7e1756e183d0446a5491bd65519cb` | Configured standalone |
| `971cb2448b5d67dcc1f5eaa10d12e77f213035ad31230dc2ac7a510610a2059d` | Gen 2 standalone |
| `9b7df409c9a89f7536d3ba7b6d43fb6dbac618c8bb52615ba34cc971ad71bbf3` | Gen 2 standalone |
| `b90a4e770869c28fd2140acb3ebdc50c113bb6f096b4bbdb9ac87c349c70e85e` | Gen 2 standalone |
| `ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800` | Memory image |
| `e2eb7703047b37b28dc34e6990205d758a2454b39bc655b460606745fadcb530` | Gen 2 slc.dll |
| `e7e3b0bcd6798634adf8b49d305f3a7b7682e4b76db549682a183c5a186df4bb` | Gen 2 slc.dll |
| `fdbd047031c13a17c9f491c9355f44d587584ebe2b8927be8482e6c236c8e1c1` | Gen 2 slc.dll |

### File Hashes (SHA256) -- TestAssembly.dll

| SHA256 | Description |
|--------|-------------|
| `d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf` | TestAssembly.dll variant |
| `133a46ba41136ca21c93fb08c28446826d8c0d9b7923a16f2d152d595a710098` | TestAssembly.dll variant |
| `9fc50cf28f86201fda8306926817b1ede41fdd993202515905dd072f6803542f` | TestAssembly.dll variant |
| `d4cb2f5df16ec9b9c5b796ae55848534e15d4f8b8806f0431108fc7a99a2548a` | TestAssembly.dll variant |
| `131ac3e0df777910e0a32e43d5744bccb0490750d4c2adc359da41d76d383c46` | TestAssembly.dll variant |

### File Hashes (SHA256) -- HTA/WSF Stagers (Selected)

| SHA256 | Description |
|--------|-------------|
| `e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34` | HTA stager |
| `e6ff096a0562c0042b09d250bd60272ffcd8d72bd95c563842acf765a8dc8bcf` | HTA stager |
| `4d0fdce4c098635fe9b296c3a82c74645f9885eb5e383aa44a0fe7e50da3ca3f` | HTA stager |
| `f1ef5fe4c0cdcff13cc750c867728b89719f81437bdc49041edd1ae1f3edb4e8` | HTA stager |
| `01b5c6acb20e41799a0e96d9d1d6e1c44791883706b6285e874fcb15cc93b31a` | HTA stager |

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| Domain | `osc-cdn[.]com` | SMTP envelope sender domain (attacker-controlled, Migadu) |
| Domain | `oisadjfoinsiduhfnoisdnfosdnoifnsoid[.]pages[.]dev` | Execution-tracking beacon |
| Domain | `my-3lyt6wcp[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-qc39r814[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-662ylt3w[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-6g16qsfe[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-goq6xmbm[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-h3qli6kq[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-sv7c1fzs[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-u0up9qri[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-vtsdod2n[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `my-wgoxp32b[.]pages[.]dev` | Cloudflare Pages HTA hosting |
| Domain | `pub-abfa7742e315485a98a5fafd6dbfb68e[.]r2[.]dev` | Cloudflare R2 payload staging |
| Domain | `pub-0173d1566dcd4fd49fa25f11f14bfe4c[.]r2[.]dev` | Cloudflare R2 payload staging |
| Domain | `d2nq35tel3ucuo[.]cloudfront[.]net` | Amazon CloudFront payload staging |
| Domain | `d32tpl7xt7175h[.]cloudfront[.]net` | Amazon CloudFront payload staging (infrastructure overlap noted by Talos, no confirmed UNC6384 attribution) |
| Domain | `microsoft-flash[.]com` | Standalone backdoor delivery |
| Domain | `wps-cn[.]com` | Standalone backdoor delivery (Chinese-language targeting) |
| IP | `103[.]27[.]110[.]220` | Historical serving IP for wps-cn[.]com |

### File System Artifacts

| Path | Description |
|------|-------------|
| `%LOCALAPPDATA%\Windows GatherOSStateKit\GatherOsState.exe` | Legitimate Microsoft ADK binary (sideload host) |
| `%LOCALAPPDATA%\Windows GatherOSStateKit\slc.dll` | Antino backdoor DLL |
| `%LOCALAPPDATA%\Windows GatherOSStateKit\OsGather.dat` | Calculator PE decoy |
| `C:\Windows\Temp\SDIAG_<GUID>\` | Scripted Diagnostics temp directory |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence registry key (add_to_run command) |

### Behavioral Indicators

- `mshta.exe` making HTTPS connections to `*.pages[.]dev` or `*.r2[.]dev` domains
- `GatherOsState.exe` executing from `%LOCALAPPDATA%\Windows GatherOSStateKit\` (not the standard ADK install path)
- `GatherOsState.exe` loading `slc.dll` from its own directory rather than from `System32`
- `sdiagnhost.exe` launching PowerShell scripts not associated with legitimate diagnostic workflows
- HTTPS traffic to `graph.microsoft.com` from non-browser, non-Office processes (e.g., from `GatherOsState.exe`)
- Email subjects matching patterns `command_req_*` or `command_res_*` in Microsoft 365 mailbox audit logs
- OneDrive folder creation with paths `/antino/heartbeats/` or `/antino_downloads/` or `/antino_uploads/`

### Development Artifacts

| Artifact | Value |
|----------|-------|
| PDB path | `D:\\a\\antino\\antino\\target\\x86_64-pc-windows-msvc\\release\\deps\\slc_template.pdb` |
| PDB path | `D:\\a\\antino\\antino\\target\\x86_64-pc-windows-msvc\\release\\deps\\antino_client_template.pdb` |
| PE manifest | `AntinoApp` |
| AssemblyAttribute GUID | `b2b3adb0-1669-4b94-86cb-6dd682ddbea3` (TestAssembly.dll -- all variants) |
| Rust mirror | `rsproxy.cn` (China-focused Cargo package mirror in 10 builds) |
| Build system | GitHub Actions Windows runners (inferred from `D:\a\` path prefix) |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Tailored emails with cloned Gmail attachment UI containing protocol-relative URLs linking to HTA/WSF stagers |
| T1218.005 | System Binary Proxy Execution: Mshta | HTA stager executed via mshta.exe |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JScript downloader/decryptor and orchestrator stages |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Antino powershell command handler; sdiagnhost.exe PowerShell execution |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Antino cmd handler executing cmd.exe /C |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | GatherOsState.exe loading attacker-supplied slc.dll |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Fake installer names (flashcenter_pp_ax_install_en.exe); staging in GatherOSStateKit directory |
| T1027 | Obfuscated Files or Information | RC4 encryption + custom Base64 encoding of payloads; XOR-encrypted .cfg section |
| T1140 | Deobfuscate/Decode Files or Information | RC4 decryption and custom Base64 decoding of JScript orchestrator and gadget resources |
| T1055 | Process Injection | In-memory shellcode loading via load_shellcode command |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | add_to_run command creates HKCU Run key persistence |
| T1082 | System Information Discovery | system_info command handler |
| T1083 | File and Directory Discovery | list_files command handler |
| T1005 | Data from Local System | download_file command exfiltrates local files |
| T1105 | Ingress Tool Transfer | upload_file command delivers payloads from OneDrive |
| T1102 | Web Service | Microsoft 365 Outlook/OneDrive used as C2 dead-drop |
| T1567 | Exfiltration Over Web Service | Data exfiltrated to OneDrive via Microsoft Graph API |
| T1218 | System Binary Proxy Execution | Execution proxied through sdiagnhost.exe via Scripted Diagnostics framework |
<!-- revision: T1553.002 dropped — abusing already-signed binary is T1574.002 (DLL Side-Loading), already mapped above -->

## Impact Assessment

As of July 2026, UAT-11587 has compromised approximately 350 endpoints across 16 institutional environments in eight countries. The campaign's sustained 10-month operational tempo, tailored lures matching collection requirements, and post-compromise capabilities (shell execution, file exfiltration, shellcode injection, persistence) indicate a professional intelligence-gathering operation. The use of Microsoft 365 infrastructure for C2 significantly complicates network-based detection in enterprise environments that rely on M365 for daily operations, as C2 traffic is indistinguishable from legitimate Graph API calls at the network layer. The DLL sideloading of a Microsoft-signed binary and in-memory execution chain further challenge endpoint detection.

## Detection & Remediation

### Immediate Detection

1. **Search for staging directory:** Look for `%LOCALAPPDATA%\Windows GatherOSStateKit\` on all endpoints
2. **Hunt for GatherOsState.exe outside ADK paths:** Any instance of `GatherOsState.exe` running from a user-writable directory is suspicious
3. **Check HKCU Run keys:** Search for Run values pointing to paths containing `GatherOSStateKit` or `slc.exe`
4. **Audit M365 application registrations:** Review Entra ID for unrecognized OAuth application registrations with Mail.Read/Mail.Send and Files.ReadWrite.All permissions
5. **Search email logs:** Look for SMTP envelope senders from `osc-cdn[.]com` or emails containing protocol-relative URLs to `*.pages[.]dev`
6. **OneDrive audit:** Search unified audit logs for folder creation events matching `/antino/` path patterns

### Remediation

1. **Isolate** affected endpoints immediately
2. **Revoke** any unrecognized Entra ID application registrations and rotate associated credentials
3. **Remove** the staging directory (`%LOCALAPPDATA%\Windows GatherOSStateKit\`) and associated Run key entries
4. **Block** known IOC domains at the proxy/DNS level (see Network IOCs above)
5. **Re-image** confirmed compromised endpoints -- Antino's shellcode injection and persistence capabilities warrant full re-imaging over manual cleanup
6. **Review** DMARC policies for organizational domains; upgrade from `p=none` to `p=quarantine` or `p=reject`

### Long-Term Hardening

- Enforce DMARC `p=reject` on all organizational email domains
- Implement application control policies preventing `mshta.exe` and `wscript.exe` execution for standard users
- Monitor Entra ID application registrations for excessive Graph API permissions
- Deploy Sysmon with image-load monitoring for `slc.dll` loaded by non-system processes
- Implement DLL load-order hardening for known-abused Microsoft binaries
- Block Cloudflare Pages/R2 URLs at the proxy if not business-required

## Detection Rules

The rules below target Antino-specific artifacts: the DLL sideloading pattern, HTA stager beacon behavior, Antino binary strings, staging directory creation, and Scripted Diagnostics abuse. All rules are advisory-specific (strict) and keyed on artifacts unique to this campaign. Network rules target the hardcoded tracking beacon domain and known C2-adjacent patterns. YARA rules detect Antino binary artifacts including PDB paths, configuration section, and Rust source path strings.

<!-- VALIDATION LOG (v2 — REVISE pass)
sigma check: blocked by proxy (MITRE ATT&CK data fetch 403); fallback to sigma convert
sigma convert --without-pipeline -t splunk: all 6 Sigma rules converted successfully (re-validated rules 2,3,4 after revision)
sigma convert --without-pipeline -t log_scale: all 6 Sigma rules converted successfully (re-validated rules 2,3,4 after revision)
yarac: all 3 YARA rules compiled successfully
suricata -T -S: all 6 Suricata rules passed syntax validation (added wps-cn.com rule)
snort -c /etc/snort/snort.conf -R: both Snort rules passed validation (fixed DNS label length |24|→|23| in rule 1)

REVISION CHANGES:
- Sigma 2: scoped DestinationHostname from generic *.pages.dev to 11 campaign-specific subdomains
- Sigma 3: added Image|endswith '\GatherOsState.exe' to tie to specific sideloading pair
- Sigma 4: added CommandLine|contains 'SDIAG_' scoping; strengthened FP field; downgraded level to medium
- Suricata 2b: added new rule for wps-cn.com delivery domain
- Snort 1: fixed DNS label length byte |24|→|23| (35 chars = 0x23)
- MITRE: dropped T1566.001 (delivery is link not attachment), fixed T1218.011→T1218, dropped T1057 (no ps handler), dropped T1553.002 (covered by T1574.002)
- Clarified UNC6384 attribution on CloudFront domain
-->

### Sigma Rules

#### Sigma Rule 1: GatherOsState.exe DLL Sideloading from User-Writable Directory

Detects execution of the legitimate Microsoft ADK binary GatherOsState.exe from a user-writable staging directory, consistent with UAT-11587 Antino DLL sideloading.
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. Keys on specific binary in anomalous path with ADK filter. -->

**Status:** compile ✅ compiles · confidence: high

```yaml
title: UAT-11587 Antino - GatherOsState.exe Sideload from User Directory
id: f7a2c1e4-8b3d-4e5f-9a6c-2d1b0e8f7a3b
status: experimental
description: >
    Detects GatherOsState.exe executing from a user-writable directory such as
    AppData\Local, which is consistent with UAT-11587 Antino backdoor DLL
    sideloading. The legitimate binary normally resides in the Windows ADK
    installation directory under Program Files.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1574.002
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\GatherOsState.exe'
    selection_path:
        Image|contains:
            - '\AppData\Local\'
            - '\AppData\Roaming\'
            - '\Users\'
    filter_adk:
        Image|contains:
            - '\Windows Kits\'
            - '\Assessment and Deployment Kit\'
    condition: selection_image and selection_path and not filter_adk
falsepositives:
    - Legitimate Windows ADK tools copied to user directories for testing
level: high
```

#### Sigma Rule 2: Mshta.exe Connecting to UAT-11587 Cloudflare Pages Subdomains

Detects mshta.exe initiating network connections to the specific Cloudflare Pages subdomains used by UAT-11587 for HTA stager hosting and tracking beacons.
<!-- revision: scoped DestinationHostname from generic *.pages.dev to the 11 campaign-specific subdomains per critic verdict; keeps high confidence -->
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. Scoped to artifact-specific subdomains from Talos IOC table. -->

**Status:** compile ✅ compiles · confidence: high

```yaml
title: UAT-11587 Antino - Mshta Connecting to Campaign Cloudflare Pages
id: a3b5c7d9-1e2f-4a6b-8c0d-3e5f7a9b1c2d
status: experimental
description: >
    Detects mshta.exe making network connections to specific Cloudflare Pages
    subdomains used by UAT-11587 for HTA stager hosting and execution-tracking
    beacons. Each subdomain is a known IOC from the campaign.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1218.005
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        DestinationHostname|endswith:
            - 'oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev'
            - 'my-3lyt6wcp.pages.dev'
            - 'my-qc39r814.pages.dev'
            - 'my-662ylt3w.pages.dev'
            - 'my-6g16qsfe.pages.dev'
            - 'my-goq6xmbm.pages.dev'
            - 'my-h3qli6kq.pages.dev'
            - 'my-sv7c1fzs.pages.dev'
            - 'my-u0up9qri.pages.dev'
            - 'my-vtsdod2n.pages.dev'
            - 'my-wgoxp32b.pages.dev'
    condition: selection
falsepositives:
    - None known; these subdomains are attacker-controlled infrastructure
level: critical
```

#### Sigma Rule 3: Slc.dll Loaded by GatherOsState.exe from Non-System Path

Detects GatherOsState.exe loading slc.dll from outside System32, the specific sideloading pair used by UAT-11587 Antino.
<!-- revision: added Image|endswith '\GatherOsState.exe' to tie to the specific sideloading pair per critic verdict; keeps high confidence -->
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. Scoped to GatherOsState.exe + slc.dll pair. -->

**Status:** compile ✅ compiles · confidence: high

```yaml
title: UAT-11587 Antino - Slc.dll Loaded by GatherOsState.exe from Non-System Path
id: b4c6d8e0-2f3a-4b7c-9d1e-4f6a8b0c2d3e
status: experimental
description: >
    Detects GatherOsState.exe loading slc.dll from outside the Windows System32
    directory. UAT-11587 places a malicious slc.dll (Antino backdoor) alongside
    GatherOsState.exe in a user-writable directory for DLL sideloading.
    Scoped to the specific GatherOsState.exe + slc.dll sideloading pair.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\GatherOsState.exe'
        ImageLoaded|endswith: '\slc.dll'
    filter_system:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_system
falsepositives:
    - Legitimate Windows ADK GatherOsState.exe loading slc.dll from a non-standard ADK directory (extremely rare)
level: high
```

#### Sigma Rule 4: Sdiagnhost.exe Spawning PowerShell from SDIAG Temp Directory

Detects sdiagnhost.exe launching PowerShell with a command line referencing the SDIAG_ temp directory pattern, consistent with UAT-11587 Antino's Scripted Diagnostics abuse. Legitimate troubleshooting packages can trigger sdiagnhost-to-PowerShell; the SDIAG_ path scoping reduces false positives.
<!-- revision: added CommandLine|contains 'SDIAG_' to scope to Scripted Diagnostics temp directory pattern per critic verdict; strengthened FP field; downgraded level to medium -->
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. sdiagnhost→powershell is legitimate in troubleshooting scenarios; SDIAG_ path narrows to programmatic abuse. -->

**Status:** compile ✅ compiles · confidence: medium

```yaml
title: UAT-11587 Antino - Sdiagnhost Spawning PowerShell from SDIAG Directory
id: c5d7e9f1-3a4b-4c8d-0e2f-5a7b9c1d3e4f
status: experimental
description: >
    Detects sdiagnhost.exe (Scripted Diagnostics Native Host) spawning
    PowerShell with a command line referencing the SDIAG_ temporary directory.
    UAT-11587 Antino abuses the Windows Scripted Diagnostics framework by
    writing malicious PowerShell scripts into C:\Windows\Temp\SDIAG_<GUID>\
    and triggering execution via sdiagnhost.exe.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1059.001
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sdiagnhost.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains: 'SDIAG_'
    condition: selection
falsepositives:
    - Legitimate Windows troubleshooting packages that run PowerShell remediation scripts from SDIAG temp directories (e.g., Windows Update Troubleshooter, Network Diagnostics)
    - SCCM/Intune remediation scripts invoked through the diagnostics framework
level: medium
```

#### Sigma Rule 5: File Creation in Windows GatherOSStateKit Directory

Detects file creation under the Antino staging directory path.
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. "Windows GatherOSStateKit" is campaign-unique. -->

**Status:** compile ✅ compiles · confidence: high

```yaml
title: UAT-11587 Antino - File Creation in GatherOSStateKit Staging Directory
id: d6e8f0a2-4b5c-4d9e-1f3a-6b8c0d2e4f5a
status: experimental
description: >
    Detects file creation in the %LOCALAPPDATA%\Windows GatherOSStateKit\
    directory, which UAT-11587 uses as the staging directory for the Antino
    DLL sideloading bundle (GatherOsState.exe, slc.dll, OsGather.dat).
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Windows GatherOSStateKit\'
    condition: selection
falsepositives:
    - Legitimate use of a directory named "Windows GatherOSStateKit" (none known)
level: critical
```

#### Sigma Rule 6: Registry Run Key Referencing GatherOSStateKit

Detects creation of a Run key entry pointing to the Antino staging directory.
<!-- audit: sigma convert --without-pipeline -t splunk 0; -t log_scale 0. Run key value data containing "GatherOSStateKit" is campaign-specific. -->

**Status:** compile ✅ compiles · confidence: high

```yaml
title: UAT-11587 Antino - Registry Run Key Persistence via GatherOSStateKit
id: e7f9a1b3-5c6d-4e0f-2a4b-7c9d1e3f5a6b
status: experimental
description: >
    Detects registry Run key entries referencing the Windows GatherOSStateKit
    directory. UAT-11587 Antino's add_to_run command creates HKCU Run key
    entries pointing to the sideloaded payload in this staging directory
    for persistence across user logons.
references:
    - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
author: Actioner
date: 2026/09/30
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
        Details|contains: 'GatherOSStateKit'
    condition: selection
falsepositives:
    - None known
level: critical
```

### YARA Rules

#### YARA Rule 1: Antino Backdoor Binary Detection

Detects the Antino backdoor via PDB paths, PE export name, manifest ID, and Rust source path artifacts compiled into the binary.
<!-- audit: yarac 0. Well-structured with PDB paths, Rust source paths, manifest ID, C2 folder names. -->

**Status:** compile ✅ compiles · confidence: high

```yara
import "pe"

rule APT_UAT11587_Antino_Backdoor
{
    meta:
        description = "Detects UAT-11587 Antino Rust backdoor via PDB paths, PE export, manifest ID, and source path artifacts"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $pdb1 = "antino\\target\\" ascii
        $pdb2 = "slc_template.pdb" ascii
        $pdb3 = "antino_client_template.pdb" ascii

        $src1 = "antino\\client\\src\\core.rs" ascii
        $src2 = "antino\\shared\\src\\command_client.rs" ascii
        $src3 = "antino\\shared\\src\\command\\add_to_run.rs" ascii
        $src4 = "antino\\client\\src\\artillery\\run.rs" ascii
        $src5 = "antino\\client\\src\\signaller\\mod.rs" ascii
        $src6 = "antino\\shared\\src\\command\\load.rs" ascii

        $manifest = "AntinoApp" ascii wide

        $cmd1 = "command_req_" ascii wide
        $cmd2 = "command_res_" ascii wide
        $cmd3 = "antino_downloads" ascii wide
        $cmd4 = "antino_uploads" ascii wide
        $cmd5 = "/antino/heartbeats/" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            any of ($pdb*) or
            2 of ($src*) or
            ($manifest and 1 of ($cmd*)) or
            (pe.exports("SLOpen") and 2 of ($cmd*)) or
            3 of ($cmd*)
        )
}
```

#### YARA Rule 2: TestAssembly.dll Downloader (GUID Marker)

Detects the TestAssembly.dll .NET downloader component via its invariant AssemblyAttribute GUID present across all observed variants.
<!-- audit: yarac 0. Invariant GUID across all 5 observed variants is extremely strong marker. -->

**Status:** compile ✅ compiles · confidence: high

```yara
rule APT_UAT11587_TestAssembly_Downloader
{
    meta:
        description = "Detects UAT-11587 TestAssembly.dll downloader via invariant AssemblyAttribute GUID b2b3adb0-1669-4b94-86cb-6dd682ddbea3"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf"
        tlp = "WHITE"
        severity = "high"

    strings:
        $guid_ascii = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase
        $guid_wide = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" wide nocase

        $dotnet1 = "TestAssembly" ascii wide
        $dotnet2 = "GatherOsState" ascii wide
        $dotnet3 = "GatherOSStateKit" ascii wide

    condition:
        ($guid_ascii or $guid_wide) and 1 of ($dotnet*)
}
```

#### YARA Rule 3: Antino HTA Stager

Detects HTA files containing the UAT-11587 tracking beacon domain and Cloudflare R2 payload sourcing patterns.
<!-- audit: yarac 0. 35-character random beacon domain string is unique. -->

**Status:** compile ✅ compiles · confidence: high

```yara
rule APT_UAT11587_HTA_Stager
{
    meta:
        description = "Detects UAT-11587 HTA stager via hardcoded tracking beacon domain and Cloudflare infrastructure patterns"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34"
        tlp = "WHITE"
        severity = "high"

    strings:
        $beacon = "oisadjfoinsiduhfnoisdnfosdnoifnsoid" ascii nocase
        $track = "?track" ascii
        $r2 = ".r2.dev" ascii nocase
        $cf_pages = ".pages.dev" ascii nocase
        $hta_marker1 = "<HTA:APPLICATION" ascii nocase
        $hta_marker2 = "mshta" ascii nocase

    condition:
        filesize < 1MB and
        $beacon and
        ($track or $r2 or $cf_pages) and
        (1 of ($hta_marker*))
}
```

### Suricata Rules

#### Suricata Rule 1: DNS Query to UAT-11587 Tracking Beacon Domain

Detects DNS queries to the hardcoded Antino HTA execution-tracking beacon domain.
<!-- audit: suricata -T -S 0. Hardcoded attacker domain. No FP possible. -->

**Status:** compile ✅ compiles · confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino HTA Tracking Beacon DNS Query"; flow:to_server; dns.query; content:"oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100101; rev:1;)
```

#### Suricata Rule 2a: DNS Query to UAT-11587 Standalone Delivery Domain (microsoft-flash.com)

Detects DNS queries to the attacker-registered standalone backdoor delivery domain microsoft-flash[.]com.

**Status:** compile ✅ compiles · confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino Standalone Delivery Domain microsoft-flash.com"; flow:to_server; dns.query; content:"microsoft-flash.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100102; rev:1;)
```

#### Suricata Rule 2b: DNS Query to UAT-11587 Standalone Delivery Domain (wps-cn.com)

Detects DNS queries to the attacker-registered standalone backdoor delivery domain wps-cn[.]com.
<!-- revision: added per critic verdict — wps-cn.com was documented as second delivery domain but had no rule -->
<!-- audit: suricata -T -S 0. Hardcoded attacker domain. -->

**Status:** compile ✅ compiles · confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino Standalone Delivery Domain wps-cn.com"; flow:to_server; dns.query; content:"wps-cn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100106; rev:1;)
```

#### Suricata Rule 3: DNS Query to UAT-11587 Spoofed Sender Domain

Detects DNS queries to the attacker-controlled SMTP envelope sender domain.
<!-- audit: suricata -T -S 0. Attacker-controlled domain. Specific. -->

**Status:** compile ✅ compiles · confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAT-11587 Antino SMTP Sender Domain osc-cdn.com DNS Query"; flow:to_server; dns.query; content:"osc-cdn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100103; rev:1;)
```

#### Suricata Rule 4: HTTP Request to UAT-11587 Cloudflare R2 Payload Staging

Detects HTTP requests to known UAT-11587 Cloudflare R2 payload staging buckets.
<!-- audit: suricata -T -S 0. Specific R2 bucket subdomain. -->

**Status:** compile ✅ compiles · confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11587 Antino Cloudflare R2 Payload Staging Bucket"; flow:established,to_server; http.host; content:"pub-abfa7742e315485a98a5fafd6dbfb68e.r2.dev"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100104; rev:1;)
```

#### Suricata Rule 5: HTTP Request to UAT-11587 Second Cloudflare R2 Bucket

Detects HTTP requests to the second known UAT-11587 Cloudflare R2 payload staging bucket.
<!-- audit: suricata -T -S 0. Specific R2 bucket subdomain. -->

**Status:** compile ✅ compiles · confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11587 Antino Cloudflare R2 Payload Staging Bucket 2"; flow:established,to_server; http.host; content:"pub-0173d1566dcd4fd49fa25f11f14bfe4c.r2.dev"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created_at 2026-09-30; sid:2100105; rev:1;)
```

### Snort 3 Rules

#### Snort Rule 1: DNS Query to UAT-11587 Tracking Beacon

Detects DNS queries to the hardcoded UAT-11587 HTA tracking beacon domain via DNS payload inspection.
<!-- revision: fixed DNS label length byte from |24| (0x24=36) to |23| (0x23=35) to match the 35-character subdomain -->
<!-- audit: snort -c /etc/snort/snort.conf -R 0. Wire-format: "oisadjfoinsiduhfnoisdnfosdnoifnsoid" is 35 chars = 0x23. -->

**Status:** compile ✅ compiles · confidence: high

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAT-11587 Antino HTA Tracking Beacon DNS Query"; flow:to_server; content:"|23|oisadjfoinsiduhfnoisdnfosdnoifnsoid|05|pages|03|dev|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created 2026-09-30; sid:2100201; rev:1;)
```

#### Snort Rule 2: HTTP Request to UAT-11587 Standalone Delivery Domain

Detects HTTP traffic to the attacker-registered microsoft-flash[.]com domain.
<!-- audit: snort -c /etc/snort/snort.conf -R 0. Specific attacker domain. -->

**Status:** compile ✅ compiles · confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAT-11587 Antino Standalone Delivery Domain microsoft-flash.com"; flow:established, to_server; http_header; content:"microsoft-flash.com", fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/; metadata:author Actioner, created 2026-09-30; sid:2100202; rev:1;)
```

## Lessons Learned

1. **DMARC enforcement is critical.** UAT-11587's email delivery relies entirely on the impersonated organization having a non-enforcing DMARC policy (`p=none`). Organizations that enforce `p=reject` would have blocked the initial delivery vector. This is a systemic gap across many government entities in the targeted region.

2. **Legitimate cloud infrastructure as attack infrastructure.** The campaign's exclusive use of Cloudflare Pages, Cloudflare R2, Amazon CloudFront, and Microsoft 365 for delivery, staging, and C2 means that domain-based blocking is insufficient. Defenders must pair network IOCs with behavioral detection (e.g., `mshta.exe` connecting to `*.pages.dev`, `GatherOsState.exe` outside ADK paths making Graph API calls).

3. **DLL sideloading of signed binaries remains effective.** The abuse of Microsoft-signed `GatherOsState.exe` and the Windows Scripted Diagnostics framework demonstrates that signed binary trust is a persistent defensive blind spot. Application control policies must go beyond signature verification to include path-based restrictions and parent-child process relationship monitoring.

4. **Rust adoption by Chinese-nexus actors continues.** The Antino backdoor joins a growing set of Rust-compiled implants from Chinese-nexus groups, suggesting increased investment in less-commonly-analyzed compiled languages to hinder reverse engineering and reduce detection by legacy signature-based tools.

## Sources

- [Cisco Talos: China-nexus UAT-11587 targets government and policy organizations across Asia with Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) -- primary technical analysis, IOCs, and TTPs
- [OffSeq Threat Radar: UAT-11587 Antino Backdoor Tracking](https://radar.offseq.com/threat/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor-c9030f900b59c0b1) -- threat intelligence aggregation and tracking

---
*Report generated by Actioner*
