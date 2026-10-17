# Technical Analysis Report: AOMEI Backupper Supply Chain Attack — UNC7017 (2026-10-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-17
Version: 1.0 DRAFT

## Executive Summary

Between May and July 2026, a threat actor tracked as UNC7017 repeatedly tampered with AOMEI Backupper's update servers in brief windows of five to ten minutes, replacing legitimate configuration files (`down_html.ini` and `Notifycfg.ini`) with malicious versions that directed the software's update mechanism to download and execute a backdoor. The attack exploited the absence of cryptographic signature verification in AOMEI's update process: the checksum intended to validate the update package was stored in the same unsigned file that named it, allowing the attacker to substitute both the package URL and its checksum simultaneously.

Clients that polled for updates during these windows received the CROSSROAD downloader (`upgrade-now.exe`), which established persistence via a scheduled task and installed the SHINYROAD backdoor through DLL side-loading of a signed Famatech (Radmin) binary. On some hosts, the open-source Adaptix C2 framework was deployed as follow-on tooling, disguised as Nitro PDF software. A secondary technique leveraged an invisible 1x1 WebDAV pop-up to coerce NetNTLMv2 authentication and capture credentials. Affected organizations span IT services, telecommunications, and higher education across 11 countries. The campaign was independently discovered by ManageEngine METAL and confirmed by Google Threat Intelligence Group (GTIG) and Mandiant. AOMEI reported corrective server-side action on July 29, 2026, but server fixes do not remediate already-compromised endpoints.

## Background: AOMEI Backupper

AOMEI Backupper is a widely used Windows backup and disaster recovery utility developed by AOMEI International Network Limited. It provides system backup, disk cloning, file synchronization, and restore capabilities. The software periodically polls AOMEI's servers over HTTPS for update packages and promotional pop-up content using two configuration files: `down_html.ini` (controls the update package URL and checksum) and `Notifycfg.ini` (controls pop-up notifications and can trigger execution of local files). Neither file is cryptographically signed. AOMEI's AnyViewer remote desktop product uses the same update infrastructure and was also identified as a target. Version 8.3.0 was the version examined by researchers; the current release 8.5.0 (October 9, 2026) shows no change to update verification in AOMEI's changelog.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~April 2026 | Earliest possible tampering activity per GTIG; staging via `serv.oss-cn-hongkong[.]aliyuncs[.]com` (Alibaba Cloud OSS bucket) |
| 2026-05-28, 05:40-05:50 | First confirmed tampering window (10 min); ManageEngine METAL detects Radmin Server installation on two unrelated customers |
| 2026-06-07 | Customer reports anomaly; ManageEngine notifies AOMEI |
| 2026-06-22 | Allowlist IP `96[.]126[.]191[.]98` configured in `whitelist.ini` at staging domain |
| 2026-07-16, 08:33-08:39 | Second confirmed tampering window (6 min); `down_html.ini` redirected to `promotion[.]storage-data[.]com`; `Notifycfg.ini` bloated with 35,000+ dummy sections |
| 2026-07-17 | Mandiant notifies AOMEI and shares indicators |
| 2026-07-20, 10:35-10:40 | Third confirmed tampering window (5 min); update staged on Google Cloud Storage; WebDAV NetNTLMv2 coercion introduced via invisible 1x1 pop-up |
| 2026-07-29 | AOMEI reports corrective server-side action |
| 2026-10-16 | Public disclosure by GTIG/Mandiant and ManageEngine METAL |

## Root Cause: Unsigned Update Configuration

The attacker gained write access to AOMEI's update servers (method undisclosed) and replaced two unsigned configuration files during brief windows. The fundamental weakness is the absence of cryptographic verification: `down_html.ini` contains both the update package URL and its MD5 checksum, but neither the file nor the package is signed. An attacker who controls the server can substitute both the package and its expected checksum simultaneously, causing the client to validate the malicious package as legitimate. The attacker restored clean files after each window, making the tampering ephemeral and difficult to detect through server-side monitoring alone.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 — Configuration Tampering and Package Delivery

During each tampering window, the attacker modified two files on AOMEI's servers:

**down_html.ini** — Redirected the update package URL and replaced the MD5 checksum:
- July 16: URL changed from `https://www2.aomeisoftware.com/download/abpopup/upgrade-now.zip` to `https://promotion.storage-data.com/download/abpopup/upgrade-now.zip`; `thrid` incremented from 5 to 6; MD5 changed to `31323E7E738230FA6A8DEEF2B7894666`
- July 20: URL changed to `https://storage.googleapis.com/aomeiupdate/upgrade-now.zip`; `thrid` set to 7; MD5 changed to `BF73C4391B58CA95220CE3AE03F66DCF`

**Notifycfg.ini** — July 16: Injected 35,000+ `[dummy_XXXXXX]` sections to bloat the config and force an update-and-execute cycle. July 20: Replaced a legitimate 400x380 promotional banner with a 1x1 invisible pop-up pointing to `file://8.210.84.56/DavWWWRoot/campaign/24hour-flash-sale.html`, coercing WebDAV/SMB authentication to capture NetNTLMv2 hashes.

The AOMEI process chain `ABService.exe` -> `Backupper.exe` -> `ABNotify.exe` downloaded the tampered config, fetched the malicious `upgrade-now.zip`, extracted it to the `Tmphtml\` staging directory, and moved it to the `html\` rendering directory for execution.

### 2. Stage 2 — CROSSROAD Downloader

`upgrade-now.exe` is a 64-bit Windows PE written in C with fabricated metadata: ProductName `AOMEI Update Compent` (misspelled), company `AOMEI International Network Limited`, version `8.2.5.0`. Key behaviors:

- **Path validation:** Checks if its path contains `AOMEI`; if not, attempts self-deletion but continues
- **Geolocation guardrail:** Resolves public IP via DNS (`myip.opendns.com`, `o-o.myaddr.l.google.com`) and HTTP (`checkip.amazonaws.com`, `api.ipify.org`, `ifconfig.me/ip`, `icanhazip.com`) using User-Agents `Anyviewer-loader/1.0` and `Anyviewer-ipcheck/1.0`. Aborts if the country code is `CN`
- **Mutex:** `Global\{F9E6E3C0-E11A-4F85-9944-AF4AD6E05883}`
- **Config reversion:** Parses `down_html.ini`, resets `thrid` to 5 and URL to the legitimate AOMEI server, making the compromise self-hiding
- **Payload staging:** Downloads `component.zip` (or `en.zip`) from `promotion.storage-data.com` to `%TEMP%\svc<random_hex>.tmp`, unpacks to `%LOCALAPPDATA%\Radmin\`
- **Persistence:** Creates scheduled task `\RadminComponentRuntime` running `FamItrfc.exe --runtimechk` every 3 hours
- **Self-deletion:** Copies to `%TEMP%`, relaunches with `--nitrod`, passing parent PID in env var `NITRODP` and original path in `NITRODT`. The child renames the original file's `$DATA` ADS to `:wtfbbq` and marks it for deletion via `SetFileInformationByHandle`
- **Timestomping:** May 20 sample had fabricated 2024 PE compile timestamps

### 3. Stage 3 — SHINYROAD Backdoor

Loading chain: Scheduled task -> `FamItrfc.exe --runtimechk` -> hijacked `BlkScrDl.dll` (search-order) -> registers COM CLSID `{21191641-0D7F-4CD9-9572-01AAE6E7851B}` (AppID `{9AD3E98A-4C7E-4F37-982D-D73D41E4F91B}`) -> `dllhost.exe` loads `csvc\RuntimeComponent.dll` -> decrypts `metadata.dat` (ChaCha20, HMAC-SHA256-derived key/IV) -> runs compiled Python bytecode in embedded PocketPy VM

**C2 Protocol:**
- Initial C2: `8[.]218[.]65[.]184:443` (raw TCP)
- Earlier variant: `8[.]218[.]65[.]184:41397`
- Handshake string: `mct3-handshake-v1`
- Session crypto: Symmetric encryption keyed from agent ID derived from hostname/username fingerprinting
- Traffic chaffing: Random junk packets (config keys: `JAM_BURST_PACKETS_MIN`, `JAM_MIN_MS`, `JAM_MAX_BYTES`)
- **Capabilities:** Interactive shell via `os.system`, in-memory extension loading via PocketPy `WorkPool` thread manager

### 4. Follow-On Tooling — Adaptix C2 (ADAPTAGENT)

Deployed from early July 2026 onward on select hosts:
- Sideloaded via signed `Nitro_Scan2PDFApp.exe` loading malicious `Eztwain4.dll` from `%LOCALAPPDATA%\Nitro Pro\`
- Launched by `NitroPromotion.exe` through scheduled task `\NitroRuntime` via `powershell -Command "Start-Process ... -WindowStyle Hidden"`
- Beacons every 2 minutes to `8[.]210[.]84[.]56:6800` over HTTP
- Pipe pattern: `\\.\pipe\%08lx`
- Mutex: `Global\{8d00c640-48d8-4440-a8e1-660fd37f572a}`
- Strings: `13ConnectorHTTP`, `9Connector`, `Adaptix Crash Analyzer v1.0`

### 5. Anti-Forensics / Evasion Techniques

- **Config reversion:** CROSSROAD restores `down_html.ini` to legitimate values after staging, making the compromised machine appear normal
- **Ephemeral tampering:** Server-side changes reverted after 5-10 minute windows
- **Self-deletion via ADS manipulation:** Renames `$DATA` stream to `:wtfbbq` and marks for deletion
- **Timestomping:** Fabricated PE compile timestamps
- **Geofencing:** Aborts if host resolves to China
- **Security agent detection:** Checks for and halts if specific endpoint security agents are present
- **Runtime-only decryption:** C2 address produced only by runtime decryption of `metadata.dat`
- **Signed binary abuse:** All execution hosts (FamItrfc.exe, Nitro_Scan2PDFApp.exe) are legitimately signed, evading signature-based controls
- **COM surrogate abuse:** SHINYROAD runs inside `dllhost.exe`, a trusted Windows process

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| AOMEI Backupper | 8.3.0 (examined) | Update config files tampered on server; no code-level modification to the installer |
| AOMEI AnyViewer | Unknown | Same update infrastructure targeted; specific versions not disclosed |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Windows | upgrade-now.zip (May 20) | 6670ab3f0434a42f33416f8354150b1701e7615f3cfa2f1635e54f8df0f6eec7 | CROSSROAD archive |
| Windows | upgrade-now.exe (May 20) | 11e576df44e9c9eef72b9f5b699291bcdb200a19130778ec231e5b0987b913ad | CROSSROAD loader |
| Windows | upgrade-now.exe (Jul 16) | 9a58e8f49edf5644e5728f74cf36f560d3d486fa51db4db69d927963c7aca450 | CROSSROAD loader |
| Windows | upgrade-now.exe (Jul 20) | b360b6db0c2b668317edc1504a7c39ef047f0d925c8f113b521f6724c157ae21 | CROSSROAD loader |
| Windows | upgrade-now.zip (Jul 20) | 9ed503c6a9a3a493fb859401e9ed469eed77ab9927341964d6dbfbfa6255aeba | CROSSROAD archive |
| Windows | upgrade-now.exe (May 28 endpoint) | 130c3970f1c900191615b99d8be522d6a488a3d3b73938896ed937092007d96a | CROSSROAD from ManageEngine METAL |
| Windows | component.zip / en.zip | d167bc898e856da8a4003cb4dfc7de55fea109eee3cd64fc8999710314109464 | SHINYROAD package |
| Windows | BlkScrDl.dll | 5837bc26a73cfb46ffd466cf889f03ce2f6a48f1f3fd42ec8be22189d51cab1e | Malicious DLL (DLL side-loading) |
| Windows | RuntimeComponent.dll | 8fbaa74b27dc1e89abfc694e834378746f0ad37a688098c5f8f511410157c8b8 | Custom PocketPy engine (SHINYROAD) |
| Windows | config.zip | 4c0a75e0f62ddc0bb350c224fe996f3b2ab08dcb0d288231c61ffe9406c7045b | Python bytecode archive |
| Windows | metadata.dat | 4b4d25b3501519476f9a62a88a781e4f446f669280eb5e98c6b96eb6d3743431 | ChaCha20-encrypted payload |
| Windows | NitroPromotion.exe | 14b31918075e6130b9123158743db0a81e2d7bfcf6d39731ee7d9200a98cd591 | ADAPTAGENT launcher |
| Windows | Eztwain4.dll | 8c8090aca8ddb1cf968d2b810457e0cfce97c03cd721f70d2eca7f37f2681fc4 | ADAPTAGENT helper DLL |
| Windows | WNTestdll.dll | 100657d3e205bfd0e96f1c088ae1739b50657592a696201467b4c65b7d36289a | PocketPy execution artifact |
| Windows | abe.exe | 7b252be444dee2fb2a57043a823dc5b5e1fae970aea91ee2c8339aa70329969d | Secondary payload |
| Windows | down_html.ini (Jul 16) | 924ad92d89dde577d5858b2ebc5703a485467842d78e98b75019b2e2e0ac3fe6 | Tampered config |
| Windows | Notifycfg.ini (Jul 16) | d2f9ef2429312667f0512504b6a19ba4a9cc5514f1b2933923dd42f75a1c5934 | Tampered notification config |
| Windows | Notifycfg.ini (Jul 20) | 286e0d8c7bdfaa7c251a3e8f0f2fefbe25c67586c0149d39b1095c89dc6023c8 | WebDAV coercion config |
| Windows | down_html.ini (Jul 20) | f2a7d0a4c8613a9cdd31ede6131b27040c0571ca97970b245a710191806d7ac4 | Tampered config |
| Windows | down_html.ini (ManageEngine) | a984fdb0830760446d2b599b263506e01fcf1e560a31a057c3bbe7b3f8ac155d | Tampered config (May 28) |
| Windows | Notifycfg.ini (ManageEngine) | 2e3b4bfb86224f079b8762ce78bb7ff10afdbf8421b08b23e96429f2e1ee7b50 | Tampered notification config (May 28) |

**Key file paths:**
- `%PROGRAMFILES(X86)%\AOMEI\*\Tmphtml\` — Staging directory for downloaded update packages
- `%PROGRAMFILES(X86)%\AOMEI\*\html\` — Rendering directory; CROSSROAD executed from here
- `%LOCALAPPDATA%\Radmin\` — SHINYROAD components (BlkScrDl.dll, config.zip, metadata.dat)
- `%LOCALAPPDATA%\Radmin\csvc\RuntimeComponent.dll` — PocketPy engine
- `%LOCALAPPDATA%\Radmin\FamItrfc.exe` — Signed Radmin binary (side-loading host)
- `%LOCALAPPDATA%\Nitro Pro\` — ADAPTAGENT components (Eztwain4.dll, NitroPromotion.exe, Nitro_Scan2PDFApp.exe)
- `%TEMP%\svc*.tmp` — CROSSROAD staging artifacts
- Shared memory: `Local\963d3c60-d406-4ad6-aa1e-dc8e45061ccf`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | storage-data[.]com | Threat actor domain (parent) |
| Domain | promotion[.]storage-data[.]com | Stage-2 dropper and Stage-3 payload staging |
| Domain | aomei[.]storage-data[.]com | Threat actor infrastructure |
| Domain | serv[.]oss-cn-hongkong[.]aliyuncs[.]com | Alibaba Cloud OSS bucket (April/May staging) |
| IP | 8[.]210[.]84[.]56 | WebDAV NTLM target; Adaptix C2 (TCP 6800) |
| IP | 8[.]218[.]65[.]184 | SHINYROAD C2 (TCP 41397 and 443) |
| IP | 47[.]239[.]60[.]117 | Secondary infrastructure |
| IP | 96[.]126[.]191[.]98 | Allowlist IP in whitelist.ini (June 22) |
| URL | hxxps://promotion[.]storage-data[.]com/download/abpopup/upgrade-now[.]zip | Stage-2 dropper download (Jul 16) |
| URL | hxxps://promotion[.]storage-data[.]com/config/component[.]zip | SHINYROAD payload |
| URL | hxxps://promotion[.]storage-data[.]com/config/en[.]zip | SHINYROAD payload (alternate name) |
| URL | hxxps://promotion[.]storage-data[.]com/config/whitelist[.]ini | Target allowlist endpoint |
| URL | hxxps://storage[.]googleapis[.]com/aomeiupdate/upgrade-now[.]zip | Jul 20 GCS staging |
| URL | hxxps://storage[.]googleapis[.]com/aomeiupdate/component[.]zip | Jul 20 GCS component |
| URL | `file://8[.]210[.]84[.]56/DavWWWRoot/campaign/24hour-flash-sale[.]html` | WebDAV NTLM coercion |
| User-Agent | Anyviewer-loader/1.0 | CROSSROAD IP check |
| User-Agent | Anyviewer-ipcheck/1.0 | CROSSROAD IP check |

### Behavioral

- **Scheduled tasks:** `\RadminComponentRuntime` (runs `FamItrfc.exe --runtimechk` every 3 hours); `\NitroRuntime` (runs `powershell -Command "Start-Process ... -WindowStyle Hidden"`)
- **Mutexes:** `Global\{F9E6E3C0-E11A-4F85-9944-AF4AD6E05883}` (CROSSROAD); `Global\{8d00c640-48d8-4440-a8e1-660fd37f572a}` (ADAPTAGENT)
- **COM artifacts:** CLSID `{21191641-0D7F-4CD9-9572-01AAE6E7851B}`, AppID `{9AD3E98A-4C7E-4F37-982D-D73D41E4F91B}`
- **Registry:** `\REGISTRY\MACHINE\SYSTEM\Software\Microsoft\TIP\AggregateResults\data` (unusual binary blobs)
- **ADS abuse:** `:wtfbbq` stream rename during self-deletion
- **Env vars:** `NITRODP` (parent PID), `NITRODT` (original path) during `--nitrod` self-deletion
- **CROSSROAD metadata typo:** `AOMEI Update Compent` (misspelled "Component")
- **ADAPTAGENT named pipe:** `\\.\pipe\%08lx`
- **SHINYROAD handshake:** `mct3-handshake-v1`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Tampered AOMEI update server configs to deliver malicious packages |
| T1053.005 | Scheduled Task/Job: Scheduled Task | RadminComponentRuntime and NitroRuntime tasks for persistence |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Signed FamItrfc.exe loads attacker-placed BlkScrDl.dll |
| T1559.001 | Inter-Process Communication: Component Object Model | BlkScrDl.dll registers COM server loaded by dllhost.exe |
| T1059.006 | Command and Scripting Interpreter: Python | SHINYROAD executes compiled PocketPy bytecode |
| T1059.001 | Command and Scripting Interpreter: PowerShell | NitroRuntime task uses PowerShell with -WindowStyle Hidden |
| T1187 | Forced Authentication | WebDAV pop-up coerces NetNTLMv2 authentication to attacker server |
| T1105 | Ingress Tool Transfer | CROSSROAD downloads SHINYROAD and Adaptix from staging infrastructure |
| T1070.004 | Indicator Removal: File Deletion | CROSSROAD self-deletes via ADS rename and SetFileInformationByHandle |
| T1564.004 | Hide Artifacts: NTFS File Attributes | ADS manipulation (`:wtfbbq` rename) during self-deletion |
| T1036.005 | Masquerading: Match Legitimate Name or Location | CROSSROAD uses AOMEI metadata; ADAPTAGENT disguised as Nitro PDF |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | SHINYROAD payload encrypted with ChaCha20, HMAC-SHA256-derived keys |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decryption of metadata.dat to PocketPy bytecode |
| T1016 | System Network Configuration Discovery | CROSSROAD queries multiple IP-check services for geolocation |
| T1614 | System Location Discovery | Geolocation check to exclude Chinese IPs |
| T1082 | System Information Discovery | Hostname/username fingerprinting for agent ID |
| T1033 | System Owner/User Discovery | Username collection for agent ID derivation |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | SHINYROAD session crypto after handshake |
| T1571 | Non-Standard Port | C2 on TCP 41397 and 6800 |
| T1001.001 | Data Obfuscation: Junk Data | SHINYROAD traffic chaffing with random packets |
| T1480 | Execution Guardrails | Geolocation and security-agent checks before payload delivery |
| T1219.002 | Remote Access Tools: Remote Desktop Software | Radmin Server installed as RMM tooling |
| T1583.001 | Acquire Infrastructure: Domains | storage-data.com and subdomains |
| T1583.006 | Acquire Infrastructure: Web Services | Google Cloud Storage bucket for payload staging |
| T1608.001 | Stage Capabilities: Upload Malware | Payloads staged on attacker domains and GCS |

## Impact Assessment

GTIG identified victims across IT services, telecommunications, and higher education in 11 countries: Australia, Brazil, India, Pakistan, Portugal, Singapore, South Africa, Spain, Switzerland, Turkiye, and the United States. The true number of affected organizations is likely higher given that unobserved tampering windows probably occurred. Each window was brief (5-10 minutes), but any client polling during that time received the malicious payload. The CROSSROAD downloader's config-reversion feature makes retrospective detection on endpoints difficult unless forensic artifacts are preserved. Remediation is required on all endpoints that polled AOMEI servers during the April-July 2026 window, as server-side fixes do not clean already-compromised machines.

## Detection & Remediation

### Immediate Detection

Check for the following on Windows endpoints:

```
# Scheduled tasks
schtasks /query /tn "\RadminComponentRuntime"
schtasks /query /tn "\NitroRuntime"

# File system artifacts
dir "%LOCALAPPDATA%\Radmin\" /s
dir "%LOCALAPPDATA%\Nitro Pro\" /s
dir "%TEMP%\svc*.tmp"

# AOMEI staging directories — check for upgrade-now.exe or unexpected executables
dir "%PROGRAMFILES(X86)%\AOMEI\*\Tmphtml\" /s
dir "%PROGRAMFILES(X86)%\AOMEI\*\html\" /s

# Registry check
reg query "HKLM\SYSTEM\Software\Microsoft\TIP\AggregateResults" /v data
```

### Remediation

1. **Isolate** any endpoint with confirmed indicators and preserve forensic evidence, especially cached `.ini` files in `Tmphtml\`
2. **Delete** scheduled tasks `\RadminComponentRuntime` and `\NitroRuntime`
3. **Remove** `%LOCALAPPDATA%\Radmin\` and `%LOCALAPPDATA%\Nitro Pro\` directories entirely
4. **Block** the following at the network perimeter: `storage-data[.]com` and all subdomains; IPs `8[.]210[.]84[.]56`, `8[.]218[.]65[.]184`, `47[.]239[.]60[.]117`; outbound SMB (TCP 445) and WebDAV to external addresses
5. **Rotate credentials** for any account whose NetNTLMv2 hash may have been captured (any host showing WebDAV coercion indicators)
6. **Hunt retrospectively** across proxy/firewall logs for April-July 2026, looking for connections to the listed domains and IPs, and for the `Anyviewer-loader/1.0` and `Anyviewer-ipcheck/1.0` User-Agent strings
7. **Do not rely** on checking AOMEI's live update URLs — the server returns clean content outside tampering windows

### Long-Term Hardening

- Require cryptographic code signing verification on all software update channels; checksum-only validation is insufficient
- Block outbound SMB/WebDAV to external IP addresses at the firewall
- Deploy application allowlisting or DLL-load policies that restrict side-loading from user-writable directories (particularly `%LOCALAPPDATA%`)
- Monitor for COM server registrations from non-standard paths, especially under `%LOCALAPPDATA%`
- Evaluate whether AOMEI Backupper's update mechanism has been hardened before re-enabling automatic updates

## Detection Rules

These detections target specific artifacts from the UNC7017 AOMEI Backupper supply chain attack at PoC/advisory-specific altitude. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: AOMEI Supply Chain - RadminComponentRuntime Scheduled Task Creation
Detects `schtasks.exe` creating the `RadminComponentRuntime` task with `FamItrfc` in the command line, a distinctive persistence artifact of CROSSROAD.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK fetch 403); splunk convert exit 0; log_scale convert exit 0. Distinctive task name + binary combo; no known benign overlap. -->
```yaml
title: AOMEI Supply Chain - RadminComponentRuntime Scheduled Task Creation
id: 8c4e1a2b-3d5f-4e6a-9b7c-2d1e8f0a4c3b
status: experimental
description: >
    Detects creation of the RadminComponentRuntime scheduled task used by
    CROSSROAD downloader in the AOMEI Backupper supply chain compromise
    (UNC7017). The task runs FamItrfc.exe with --runtimechk every 3 hours
    to trigger DLL side-loading of the SHINYROAD backdoor.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
    - https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html
author: Actioner
date: 2026/10/17
tags:
    - attack.t1053.005
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'RadminComponentRuntime'
            - 'FamItrfc'
    condition: selection_schtasks
falsepositives:
    - Legitimate Radmin Server installations creating similarly named tasks (unlikely in most environments)
level: high
```

### Sigma: AOMEI ABNotify Spawning Executable From Rendering Directory
Detects `ABNotify.exe` launching any `.exe` from the AOMEI `html\` directory tree, the mechanism through which the tampered `Notifycfg.ini` triggered CROSSROAD execution.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. ABNotify should never launch executables from html dir in normal operation. -->
```yaml
title: AOMEI ABNotify Spawning Executable From Rendering Directory
id: 3768e7d0-ba38-48fa-a630-d25bb50438de
status: experimental
description: >
    Detects ABNotify.exe launching an executable from the AOMEI Backupper
    html rendering directory. In the UNC7017 supply chain attack, the tampered
    Notifycfg.ini caused ABNotify to execute the malicious upgrade-now.exe
    dropper from the html subdirectory.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
    - https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html
author: Actioner
date: 2026/10/17
tags:
    - attack.t1195.002
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\ABNotify.exe'
        Image|contains: '\html\'
        Image|endswith: '.exe'
    condition: selection
falsepositives:
    - Legitimate AOMEI promotional content launching a browser (rare, and should not launch .exe from html directory)
level: high
```

### Sigma: AOMEI Supply Chain - CROSSROAD Self-Deletion via Nitrod Flag
Detects the `--nitrod` command-line argument unique to CROSSROAD's self-deletion mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. The --nitrod flag is a distinctive, campaign-specific artifact with no known legitimate use. -->
```yaml
title: AOMEI Supply Chain - CROSSROAD Self-Deletion via Nitrod Flag
id: a2b3c4d5-e6f7-8901-abcd-ef2345678901
status: experimental
description: >
    Detects the CROSSROAD downloader's self-deletion mechanism where it
    copies itself to TEMP and relaunches with the --nitrod argument.
    This is a distinctive artifact of the UNC7017 AOMEI supply chain attack.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
author: Actioner
date: 2026/10/17
tags:
    - attack.t1070.004
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '--nitrod'
    condition: selection
falsepositives:
    - Unknown legitimate use of --nitrod flag
level: high
```

### Sigma: AOMEI Supply Chain - SHINYROAD COM Server in Non-Standard Path
Detects `dllhost.exe` loading `RuntimeComponent.dll` from a `Radmin` directory, indicating the SHINYROAD COM surrogate abuse chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Requires Sysmon EID 7 (image_load). RuntimeComponent.dll from Radmin under LocalAppData is highly distinctive. -->
```yaml
title: AOMEI Supply Chain - SHINYROAD COM Server Registration in Non-Standard Path
id: b3c4d5e6-f7a8-9012-bcde-f34567890123
status: experimental
description: >
    Detects dllhost.exe hosting the RuntimeComponent.dll COM server from
    the Radmin application directory under LocalAppData. The SHINYROAD
    backdoor registers a COM object that causes dllhost.exe to load the
    malicious DLL from a non-standard path.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
    - https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html
author: Actioner
date: 2026/10/17
tags:
    - attack.t1559.001
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\dllhost.exe'
        ImageLoaded|contains: '\Radmin\'
        ImageLoaded|endswith: '\RuntimeComponent.dll'
    condition: selection
falsepositives:
    - Legitimate Radmin Server components loaded by COM (unlikely from LocalAppData)
level: high
```

### Sigma: AOMEI Supply Chain - CROSSROAD IP Check User-Agent
Detects the `Anyviewer-loader/1.0` or `Anyviewer-ipcheck/1.0` User-Agent strings used by CROSSROAD for geolocation checks in proxy logs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert exit 0; log_scale convert exit 0. Campaign-specific UAs; note field name is proxy-logsource-specific (c-useragent). -->
```yaml
title: AOMEI Supply Chain - CROSSROAD IP Check User-Agent
id: c4d5e6f7-a8b9-0123-cdef-456789012345
status: experimental
description: >
    Detects the distinctive User-Agent strings used by the CROSSROAD
    downloader for public IP geolocation checks. The malware uses
    Anyviewer-loader/1.0 and Anyviewer-ipcheck/1.0 to determine whether
    the victim is in China before proceeding with payload delivery.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
author: Actioner
date: 2026/10/17
tags:
    - attack.t1016
    - attack.t1614
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains:
            - 'Anyviewer-loader/1.0'
            - 'Anyviewer-ipcheck/1.0'
    condition: selection
falsepositives:
    - Legitimate AnyViewer software using similar User-Agent strings (verify context)
level: high
```

### Snort: AOMEI Supply Chain DNS and User-Agent Detection
Detects DNS queries to the `storage-data[.]com` C2 domain and the CROSSROAD-specific User-Agent strings in HTTP traffic.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (Snort 2.9.20). DNS rule uses label-length encoding for storage-data.com. HTTP rules use http_header sticky buffer on tcp/$HTTP_PORTS. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to AOMEI Supply Chain C2 Domain storage-data.com"; flow:to_server; content:"|0c|storage-data|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created 2026-10-17; sid:2100001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - AOMEI CROSSROAD User-Agent Anyviewer-loader"; flow:established,to_server; content:"Anyviewer-loader/1.0"; http_header; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created 2026-10-17; sid:2100002; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - AOMEI CROSSROAD User-Agent Anyviewer-ipcheck"; flow:established,to_server; content:"Anyviewer-ipcheck/1.0"; http_header; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created 2026-10-17; sid:2100003; rev:1;)
```

### Suricata: AOMEI Supply Chain DNS and User-Agent Detection
Detects DNS queries to the `storage-data[.]com` C2 domain and subdomains, plus the CROSSROAD-specific User-Agent strings.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Uses dns.query and http.user_agent dot-notation sticky buffers. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to AOMEI Supply Chain C2 Domain storage-data.com"; flow:to_server; dns.query; content:"storage-data.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created_at 2026-10-17; sid:2200001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to AOMEI Supply Chain Staging Domain promotion.storage-data.com"; flow:to_server; dns.query; content:"promotion.storage-data.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created_at 2026-10-17; sid:2200002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AOMEI CROSSROAD User-Agent Anyviewer-loader"; flow:established,to_server; http.user_agent; content:"Anyviewer-loader/1.0"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created_at 2026-10-17; sid:2200003; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - AOMEI CROSSROAD User-Agent Anyviewer-ipcheck"; flow:established,to_server; http.user_agent; content:"Anyviewer-ipcheck/1.0"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering; metadata:author Actioner, created_at 2026-10-17; sid:2200004; rev:1;)
```

### YARA: CROSSROAD Downloader
Detects the CROSSROAD downloader via distinctive metadata typo (`AOMEI Update Compent`), self-deletion artifacts (`--nitrod`, `:wtfbbq`), mutex, and scheduled task name.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on pos (published strings from GTIG), quiet on neg. Keys on 3+ distinctive campaign strings; PE header check + filesize cap reduce FP risk. -->
```yara
rule Malware_CROSSROAD_Downloader
{
    meta:
        description = "Detects CROSSROAD downloader from AOMEI Backupper supply chain attack (UNC7017). Keys on distinctive metadata typo, self-deletion flag, and scheduled task name."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "11e576df44e9c9eef72b9f5b699291bcdb200a19130778ec231e5b0987b913ad"
        severity = "high"

    strings:
        $meta_typo = "AOMEI Update Compent" ascii wide
        $nitrod = "--nitrod" ascii
        $nitrodp = "NITRODP" ascii
        $nitrodt = "NITRODT" ascii
        $task = "RadminComponentRuntime" ascii wide
        $runtimechk = "--runtimechk" ascii
        $mutex = "{F9E6E3C0-E11A-4F85-9944-AF4AD6E05883}" ascii wide
        $wtfbbq = ":wtfbbq" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($meta_typo and 2 of ($nitrod, $nitrodp, $nitrodt, $task, $runtimechk)) or
            ($mutex and $task) or
            ($wtfbbq and $nitrod and $task)
        )
}
```

### YARA: SHINYROAD Backdoor
Detects SHINYROAD backdoor components via the PocketPy bootstrap script name, handshake string, traffic chaffing config keys, and shared memory GUID.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on highly campaign-specific strings (mct3-handshake-v1, bootstrap_tcp_slim_v2_call_min.py, JAM_* chaffing keys). No PE header check needed as SHINYROAD components include DLLs and bytecode archives. -->
```yara
rule Malware_SHINYROAD_Backdoor
{
    meta:
        description = "Detects SHINYROAD backdoor components from AOMEI Backupper supply chain attack (UNC7017). Keys on PocketPy bootstrap script name, handshake string, and traffic chaffing config."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "8fbaa74b27dc1e89abfc694e834378746f0ad37a688098c5f8f511410157c8b8"
        severity = "high"

    strings:
        $handshake = "mct3-handshake-v1" ascii
        $bootstrap = "bootstrap_tcp_slim_v2_call_min.py" ascii
        $jam1 = "JAM_BURST_PACKETS_MIN" ascii
        $jam2 = "JAM_MIN_MS" ascii
        $jam3 = "JAM_MAX_BYTES" ascii
        $pyio1 = "_pyio_compat" ascii
        $pyio2 = "_pyio_struct" ascii
        $shm = "963d3c60-d406-4ad6-aa1e-dc8e45061ccf" ascii

    condition:
        filesize < 10MB and
        (
            ($handshake and $bootstrap) or
            ($handshake and 2 of ($jam*)) or
            (2 of ($pyio*) and $shm) or
            (3 of them)
        )
}
```

### YARA: ADAPTAGENT Loader (Adaptix C2)
Detects the ADAPTAGENT loader masquerading as Nitro PDF software, keying on Adaptix framework strings, mutex, and Nitro naming artifacts.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on Adaptix-specific strings (crash analyzer version, connector class names) combined with Nitro naming and mutex. PE header check constrains to executables. -->
```yara
rule Malware_ADAPTAGENT_Loader
{
    meta:
        description = "Detects ADAPTAGENT (Adaptix C2) loader masquerading as Nitro PDF software, used as follow-on tooling in the AOMEI Backupper supply chain attack."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "14b31918075e6130b9123158743db0a81e2d7bfcf6d39731ee7d9200a98cd591"
        severity = "high"

    strings:
        $s1 = "NitroPromotion.exe" ascii wide
        $s2 = "Adaptix Crash Analyzer v1.0" ascii wide
        $s3 = "13ConnectorHTTP" ascii
        $s4 = "9Connector" ascii
        $mutex = "{8d00c640-48d8-4440-a8e1-660fd37f572a}" ascii wide
        $pipe = "\\\\.\\pipe\\%08lx" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s2 and ($s3 or $s4)) or
            ($mutex and $s1) or
            (3 of them)
        )
}
```

## Lessons Learned

This attack demonstrates that software update mechanisms relying solely on checksums co-located with the package metadata provide no real integrity guarantee. When the checksum and the URL it validates reside in the same unsigned file, an attacker who compromises the server can replace both atomically. The ephemeral nature of the tampering -- five to ten minute windows, followed by restoration of legitimate content -- shows that attackers are adapting to make supply chain compromises harder to detect through continuous monitoring of server-side artifacts.

The case also highlights the persistent risk of DLL side-loading through signed binaries: once CROSSROAD placed `BlkScrDl.dll` alongside a signed Famatech executable, the entire SHINYROAD backdoor chain ran under the guise of trusted processes, including `dllhost.exe` as a COM surrogate. Defenders should monitor for COM server registrations from non-standard paths and restrict DLL loading from user-writable directories, even when the host executable is legitimately signed.

The fact that AOMEI's server-side remediation does not clean already-compromised endpoints, combined with the attacker's self-cleaning behavior (CROSSROAD restoring the original config values), means that many affected organizations may not realize they were compromised. Retrospective hunting across the April-July 2026 window is essential for organizations that ran AOMEI Backupper or AnyViewer during that period.

## Sources

- [Google Threat Intelligence Group (GTIG/Mandiant)](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering) — Primary technical analysis with full IOC tables, YARA rules, and MITRE ATT&CK mapping
- [ManageEngine Threat Analysis Lab (METAL)](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html) — Independent discovery report with process execution chain analysis and Sigma rules
- [The Hacker News](https://thehackernews.com/2026/10/attackers-tampered-with-aomei.html) — News coverage consolidating findings from both research groups
- [AOMEI Backupper Changelog](https://www.ubackup.com/changelog.html) — Vendor changelog showing no update verification changes as of v8.5.0

---
*Report generated by Actioner*
