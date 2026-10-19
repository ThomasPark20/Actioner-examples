# Technical Analysis Report: MALFEX npm Supply-Chain Attack via `imgdecode` (2026-10-19)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-19
Version: FINAL 1.0

## Executive Summary

The MALFEX campaign is a multi-year npm software supply-chain attack (active since August 2023) attributed to a likely lone Brazilian-speaking threat actor. The latest evolution uses the `imgdecode` npm package to deliver a compiled 64-bit Windows DLL disguised as a Node.js native addon (`.node` file). When a developer imports the package on a Windows console, the addon downloads an AES-256-CBC-encrypted payload from GitHub (`cavecrew/proj`), decrypts it using the passphrase `nif-runtime-2027`, and injects the resulting shellcode into a suspended `dllhost.exe` process via classic process injection (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread). The campaign has delivered the Overlord RAT and a comprehensive Node.js credential stealer ("movinlike") targeting browsers, Discord, Telegram, crypto wallets, and gaming platforms. As of October 2026, eight malicious packages across five npm publisher accounts accumulated over 40,700 downloads; `imgdecode` alone had 979 downloads. The C2 infrastructure operates from IP `104.234.65[.]75` (AS265919, Brazil) on ports 700 and 7007.

## Background: npm Native Addon Attack Surface

Node.js native addons (`.node` files) are compiled shared libraries loaded via `require()` or `process.dlopen()`. Unlike JavaScript-based npm malware that typically uses lifecycle hooks (`postinstall`), native addons execute compiled code during module initialization without triggering install-time script audits. The `imgdecode` package exploits this by placing a malicious MSVC-compiled DLL at `prebuilds/win32-x64/imgdecode.node` that runs its payload in the `napi_register_module_v1` export -- the addon's entry point. The package contains no `binding.gyp` or native source code, meaning the DLL was pre-built and committed directly. This technique bypasses common npm security scanners that focus on JavaScript analysis and lifecycle hook inspection.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2023-08-06 | Earliest known MALFEX npm activity (campaign-wide) |
| 2024-07 | `function-flag` first published (37,419 downloads by Oct 2026) |
| 2026-09-26 | `cdn-img-fetch`, `img-to-native`, `native-runner` v1.0.0 published |
| 2026-09-28 16:06 | npm removes `native-runner` and `img-to-native` |
| 2026-09-30 03:29 | `imgbundle` v1.0.0 published (decrypt role, replaces `img-to-native`) |
| 2026-09-30 03:37 | `runhelper` v1.0.0 published (shellcode executor via Koffi FFI) |
| 2026-09-30 16:13 | `runhelper` unpublished |
| 2026-09-30 22:32 | `imgdecode` v1.0.0 published (~6 hours after `runhelper` removal) |
| 2026-09-30 23:07 | `imgdecode` v1.0.1 (addon now fetches, decrypts, and injects) |
| 2026-10-01 17:48 | `imgdecode` v1.0.2 published |
| 2026-10-05 | Checkmarx publishes initial MALFEX campaign analysis |
| 2026-10-07 23:06 | npm removes `imgbundle` |
| 2026-10-08 13:03 | npm removes `cdn-img-fetch` |
| 2026-10-11 22:09 | `imgdecode` v1.0.3 published (drops `imgbundle` dependency, standalone) |
| 2026-10-13 | SafeDep publishes detailed `imgdecode` native addon analysis |
| 2026-10-17 | The Hacker News covers `imgdecode` shellcode loader |

## Root Cause: Malicious npm Package with Native Addon

The attack vector is a trojanized npm package that bypasses install-time security checks by embedding its payload in a pre-compiled Windows DLL rather than using JavaScript lifecycle hooks. The malicious code executes at `require()` time via the `napi_register_module_v1` export, which Node.js calls during module initialization. The package further evades analysis by checking whether stdout is an interactive Windows console (via `GetStdHandle`/`GetConsoleMode`), preventing execution in CI runners, redirected-output environments, and many sandboxes.

## Technical Analysis of the Malicious Payload

### 1. Package Structure and Initial Loader

The `imgdecode` npm package is minimal: a ~9-line `index.js` that calls `require()` on the native addon at `prebuilds/win32-x64/imgdecode.node`. The `.node` file is a 64-bit MSVC-compiled DLL with `node-addon-api` exports. The PDB path embedded in the binary is `C:\Users\Administrator\Desktop\npm\imgdecode\build\Release\imgdecode.pdb`. The package has no `binding.gyp` despite the registry metadata listing `node-gyp rebuild` as the install command.

**String obfuscation:** Strings in the DLL are encoded with a single-byte XOR key `0x37`. Long strings sit in `.rdata` as 16-byte blocks decoded with `xorps` (SIMD); short strings are built on the stack.

**Console gate:** The DLL calls `GetStdHandle(STD_OUTPUT_HANDLE)` and `GetConsoleMode()`. If stdout is not a live Windows console, the DLL exits silently -- this targets developer terminals and avoids CI/CD and sandbox environments.

### 2. Payload Download and Decryption

The addon downloads an encrypted payload from GitHub using WinINet APIs:

- **URL:** `hxxps://raw[.]githubusercontent[.]com/cavecrew/proj/main/banner.jpg`
- **User-Agent:** `Mozilla/5.0`
- **Flags:** `INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE` (`0x80800000`)

Decryption uses Windows CNG (`bcrypt.dll`):

- **Algorithm:** AES-256-CBC
- **Key derivation:** SHA-256 hash of the passphrase `nif-runtime-2027`
- **IV:** First 16 bytes of the response
- **Ciphertext:** Remaining bytes after the IV
- **Minimum size check:** Responses of 32 bytes or fewer are rejected

**Kill-switch:** If the decrypted plaintext starts with JPEG (`FF D8`) or PNG (`89 50 4E 47`) magic bytes, the loader stops. This allows the operator to disable the loader by serving a valid image.

### 3. Shellcode Injection into dllhost.exe

1. `GetSystemDirectoryW` resolves `%SystemRoot%\System32\`
2. `CreateProcessW` starts `dllhost.exe` with flags: `CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, window style `SW_HIDE`
3. `VirtualAllocEx` allocates memory with `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE`
4. `WriteProcessMemory` copies the decrypted shellcode; byte count is verified
5. `VirtualProtectEx` changes protection to `PAGE_EXECUTE_READ`
6. `CreateRemoteThread` starts execution at offset zero of the buffer
7. Handles are closed and `Sleep(800)` is called

**Fallback:** If injection into `dllhost.exe` fails, the addon falls back to in-process execution within `node.exe` using `VirtualAlloc`, `RtlMoveMemory`, `VirtualProtect`, and `CreateThread`.

**Resolved APIs (via `GetProcAddress`):** `CreateProcessW`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`, `ResumeThread`, `TerminateProcess`, `GetSystemDirectoryW`, `CloseHandle`, `Sleep`

### 4. Earlier Infection Chains

**Chain 1 (Sep 26):** `cdn-img-fetch` downloads `banner.png` from GitHub `cavecrew/proj`, which is a 1x1 PNG with an appended 4-byte big-endian length and base64 payload. `img-to-native` decrypts with key `malfexteam2027` and writes a Go executable. `native-runner` executes the Go binary (`downloader` module, Go 1.27.1, built with `-H windowsgui`), which downloads the stealer from `hxxp://104.234.65[.]75:700/setup.exe` and saves it as `%TEMP%\svc_update.exe`.

**Chain 2 (Sep 30, short-lived):** `imgbundle` decrypts `cdn-img-fetch/.runtime/rt.jpg` into shellcode. `runhelper` copies the shellcode to executable memory and runs it via Koffi, a Node.js FFI library, calling `VirtualAlloc`, `RtlMoveMemory`, and `CreateThread` from JavaScript.

**Chain 3 (Overlord RAT):** `tlxbnhd`, `tldriver`, `mxdriver` use lifecycle hooks to download and run a Windows executable delivering the Overlord RAT (Go-based, open-source), which uses Solana blockchain transactions to retrieve its C2 address.

**Chain 4 (function-flag):** The postinstall script runs `example.js`, which calls an ASCII art function with a specific font that triggers a hidden routine. It downloads `node.exe` from `cdnzona.discloud[.]app` and saves to `%APPDATA%\node.exe`.

### 5. Stage 3: movinlike Stealer

The final payload `setup.exe` (SHA-256: `8d50cb1b...`) is a 71.5 MB Node.js 18 application packed with `pkg`, internal name `movinlike`. Its `.env` configuration contains:

- `NPM_API=hxxp://104.234.65[.]75:7007`
- `NPM_LICENSE=MALFEX-89BEE69BB61967AF1C3B07C9`
- `NPM_RAT=1`

**Capabilities:**

- **Anti-analysis:** VM/sandbox detection; checks for `x64dbg`, `procmon`, `wireshark`
- **Browser data:** Chromium passwords and cookies; app-bound key recovery via SYSTEM scheduled task running PowerShell with Chrome `IElevator` COM interface
- **Discord:** Token theft; patches `discord_desktop_core/index.js` with webhook injection
- **Crypto wallets:** Browser and desktop wallet data extraction
- **Gaming:** Steam, Epic Games, Riot, Battle.net, Minecraft, Ubisoft
- **Telegram:** Desktop session theft
- **File collection:** Filenames matching `seed`, `mnemonic`, `wallet`, `secret`, `token`, `senha`; extensions `.kdbx`, `.pem`, `.ppk`, `.env`
- **RAT:** Shell execution, file transfer, process control, clipboard access, screenshots, mouse/keyboard input
- **C2 protocol:** WebSocket to `ws://104.234.65[.]75:7007/agent?license=...`
- **API paths:** `/about/sendRouter`, `/about/discord`
- **Upload format:** `malfex.zip`

### 6. C2 Infrastructure

- **IP:** `104.234.65[.]75` (AS265919, BB Host LTDA, Sao Paulo, Brazil)
- **Port 700:** HTTP, stage-2 download (`/setup.exe`)
- **Port 7007:** HTTP API and WebSocket C2
- **GitHub:** `cavecrew/proj` repository (account now inaccessible; `banner.jpg` returns HTTP 404)
- **Alternate hosting:** `cdnzona.discloud[.]app` (function-flag chain)

### 7. Anti-Forensics / Evasion Techniques

- **Console-only execution:** The native addon exits if stdout is not a Windows console, evading CI/sandboxes
- **String obfuscation:** Single-byte XOR (key `0x37`) with SIMD decoding
- **Image signature kill-switch:** The operator can disable the loader by serving a real image
- **No install hooks:** Execution at `require()` time bypasses npm install-time audits
- **Pre-compiled DLL:** Avoids JavaScript-level static analysis
- **Dynamic API resolution:** Uses `GetProcAddress` for injection APIs to evade IAT-based detection
- **EVTX tampering:** The stealer edits Security and Sysmon event log records, recalculates checksums, and deletes PowerShell history
- **Rapid package replacement:** New packages published within hours of takedowns

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `104.234.65[.]75`)

### Package / Software Level

| Package / Component | Malicious Version(s) | npm Account | Description |
|---------------------|----------------------|-------------|-------------|
| imgdecode | 1.0.0, 1.0.1, 1.0.2, 1.0.3 | malfexteste8 | Native addon shellcode loader (primary focus) |
| cdn-img-fetch | 1.0.0 | -- | Downloads encrypted payload from GitHub |
| img-to-native | 1.0.0 | -- | Decrypts and writes Go executable |
| native-runner | 1.0.0 | -- | Executes Go downloader |
| imgbundle | 1.0.0 - 1.0.2 | -- | Replacement decryptor for img-to-native |
| runhelper | 1.0.0 | -- | Shellcode executor via Koffi FFI |
| function-flag | multiple (since Jul 2024) | -- | Postinstall hook downloader (37,419 downloads) |
| tlxbnhd, tldriver, mxdriver | -- | -- | Overlord RAT loaders |

**Publisher accounts:** malfexkkj, malfex_user, malfexteste2, malfexteste3, malfexteste4, malfexteste8

**Publisher email:** trelicas.flexionar_4q[at]icloud[.]com

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|---------------|-------------|
| Windows | `prebuilds/win32-x64/imgdecode.node` (v1.0.0) | `d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714` | Native addon DLL v1.0.0 |
| Windows | `prebuilds/win32-x64/imgdecode.node` (v1.0.1) | `54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85` | Native addon DLL v1.0.1 |
| Windows | `prebuilds/win32-x64/imgdecode.node` (v1.0.2/1.0.3) | `a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1` | Native addon DLL v1.0.2-1.0.3 |
| -- | `banner.png` (GitHub carrier) | `4f4f7d64139bde6d458a061c7fb7dd247f70f60a1ab47d87fd3634656586c106` | 1x1 PNG with appended encrypted payload |
| Windows | Stage-2 Go downloader | `2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b` | Go 1.27.1 downloader module |
| Windows | `setup.exe` (movinlike stealer) | `8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6` | 71.5 MB Node.js 18 app packed with pkg |
| Windows | `%TEMP%\svc_update.exe` | -- | Stage-2 download location |
| Windows | `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` | -- | Stealer persistence copy |
| Windows | `%SystemRoot%\System32\dllhost.exe` | -- | Injection target (legitimate binary, started suspended) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `104.234.65[.]75:700` | Stage-2 download server (`/setup.exe`) |
| IP | `104.234.65[.]75:7007` | Stealer C2 API and WebSocket |
| URL Pattern | `hxxps://raw[.]githubusercontent[.]com/cavecrew/proj/main/banner.jpg` | Encrypted shellcode download |
| URL Pattern | `hxxp://104.234.65[.]75:700/setup.exe` | Stage-2 stealer download |
| URL Pattern | `ws://104.234.65[.]75:7007/agent?license=...` | WebSocket C2 connection |
| Domain | `cdnzona.discloud[.]app` | function-flag payload hosting |
| API Path | `/about/sendRouter` | Stealer C2 endpoint |
| API Path | `/about/discord` | Stealer C2 endpoint |
| GitHub | `cavecrew/proj` | Payload hosting (now inaccessible) |

### Behavioral

- `node.exe` spawning `dllhost.exe` without `/Processid:` argument (shellcode injection)
- `node.exe` connecting to `raw.githubusercontent[.]com` followed by `dllhost.exe` connecting to an unknown external host
- Scheduled task `MicrosoftEdgeUpdateService` pointing to non-standard Edge binary path
- Registry Run key `MicrosoftEdgeUpdateService` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- EVTX log file tampering (Security and Sysmon logs modified, checksums recalculated)
- PowerShell history deletion
- File collection targeting `.kdbx`, `.pem`, `.ppk`, `.env` extensions and seed phrase filenames

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages published to public registry |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Node.js native addon loaded via `require()` |
| T1055 | Process Injection | Shellcode injected into suspended dllhost.exe via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread |
| T1027 | Obfuscated Files or Information | XOR-encoded strings (key 0x37), AES-256-CBC encrypted payloads |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decryption of payload using nif-runtime-2027 passphrase |
| T1105 | Ingress Tool Transfer | Downloads encrypted payload from GitHub and stealer from C2 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MicrosoftEdgeUpdateService Run key for persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | MicrosoftEdgeUpdateService scheduled task |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Persistence binary named MicrosoftEdgeUpdate.exe in EdgeUpdate directory |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/WebSocket C2 communication |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium password and cookie extraction |
| T1539 | Steal Web Session Cookie | Browser cookie theft and Discord token theft |
| T1005 | Data from Local System | Collection of seed phrases, keys, and wallet files |
| T1113 | Screen Capture | Screenshot capability in RAT module |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | EVTX log tampering and PowerShell history deletion |
| T1497 | Virtualization/Sandbox Evasion | Console-mode check; VM/sandbox/debugger detection |
| T1106 | Native API | GetProcAddress for dynamic API resolution |

## Impact Assessment

- **Breadth:** 8 malicious packages with 40,767+ combined downloads; `imgdecode` alone had 979 downloads. No public GitHub projects or deps.dev dependents were found importing these packages, suggesting most downloads were direct installs, mirrors, or scanner activity.
- **Depth:** Full system compromise -- credential theft (browsers, Discord, Telegram, crypto wallets, gaming platforms), remote access (shell, file transfer, screenshots, input control), and persistent backdoor.
- **Stealth:** High -- native addon bypasses JavaScript analysis; console check evades CI/sandboxes; EVTX tampering removes forensic evidence; dynamic API resolution and XOR obfuscation hinder static analysis.
- **Attribution:** Linguistic indicators (Portuguese package descriptions, -0300 timezone in git commits) suggest a Brazilian actor. CloudSEK stresses this is linguistic attribution only. The `MALFEX` license key system suggests a possible malware-as-a-service component.

## Detection & Remediation

### Immediate Detection

```bash
# Check if imgdecode or related MALFEX packages are installed
npm ls imgdecode cdn-img-fetch img-to-native native-runner imgbundle runhelper function-flag 2>/dev/null
npm ls -g imgdecode cdn-img-fetch img-to-native native-runner imgbundle runhelper function-flag 2>/dev/null

# Search for the package in node_modules across the filesystem
find / -path "*/node_modules/imgdecode" -o -path "*/node_modules/cdn-img-fetch" \
  -o -path "*/node_modules/runhelper" -o -path "*/node_modules/function-flag" 2>/dev/null

# Check for persistence artifacts (Windows - PowerShell)
# Get-ScheduledTask | Where-Object {$_.TaskName -eq "MicrosoftEdgeUpdateService"}
# Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object MicrosoftEdgeUpdateService
# Test-Path "$env:APPDATA\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
# Test-Path "$env:TEMP\svc_update.exe"
```

### Remediation

1. **Isolate** affected systems immediately; capture memory before rebooting (shellcode runs in-memory)
2. **Remove** malicious packages: `npm uninstall imgdecode cdn-img-fetch img-to-native native-runner imgbundle runhelper function-flag`
3. **Delete** persistence: remove the `MicrosoftEdgeUpdateService` scheduled task and Run key, and delete `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`
4. **Rotate all credentials:** browser passwords, Discord tokens, npm/GitHub tokens, SSH keys, cloud API keys, and any `.env` file contents
5. **Move crypto funds** to new wallets if seed phrases, mnemonics, or wallet files were stored on the affected system
6. **Compare local logs** with centralized/external logs -- the stealer tampers with local Security and Sysmon EVTX records
7. **Block** C2 IP `104.234.65[.]75` at the network perimeter

### Long-Term Hardening

- **Audit native addons:** Flag npm packages containing pre-built `.node` files in `prebuilds/` without corresponding native source code or `binding.gyp`
- **Use lockfiles and integrity checks:** `npm ci` with `package-lock.json` and `--ignore-scripts` where possible
- **Deploy npm audit tooling:** Socket.dev, Snyk, or similar supply-chain security scanners
- **Monitor process genealogy:** Alert on `node.exe` spawning unexpected child processes (`dllhost.exe`, `cmd.exe`, `powershell.exe`)
- **Restrict outbound access:** Limit developer workstation access to known-good registries and repositories

## Detection Rules

These detections target the MALFEX `imgdecode` shellcode injection chain and associated persistence/C2 indicators at PoC/advisory-specific altitude. Four Sigma rules cover host-level behavior and network indicators; three YARA rules target the malicious DLL, Go downloader, and stealer binaries; Snort and Suricata rules cover the known C2 IP and payload download patterns. Note: compiles does not equal fires -- verify each rule in your pipeline against available telemetry.

### Sigma: Node.js Spawns Suspended dllhost.exe (MALFEX Injection)

Detects `node.exe` spawning `dllhost.exe` without the legitimate `/Processid:` COM surrogate argument, the distinctive marker of the `imgdecode` shellcode injection.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, network issue, not a rule error); splunk convert exit 0; log_scale convert exit 0. Console-only execution means this fires only when the developer terminal trigger activates. FP: no known legitimate case of node.exe spawning dllhost.exe without /Processid:. -->

```yaml
title: Node.js Spawns Suspended dllhost.exe - MALFEX imgdecode Shellcode Injection
id: 7a1b3c4d-9e2f-4a6b-8d7c-1e5f0a3b2c4d
status: experimental
description: >
    Detects node.exe spawning dllhost.exe, indicative of the MALFEX imgdecode
    native addon injecting shellcode into a suspended dllhost.exe process.
    The addon creates dllhost.exe with CREATE_SUSPENDED and injects shellcode
    via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
    - https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html
author: Actioner
date: 2026/10/19
tags:
    - attack.t1055
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\node.exe'
        Image|endswith: '\dllhost.exe'
    filter_com:
        CommandLine|contains: '/Processid:'
    condition: selection and not filter_com
falsepositives:
    - Legitimate Node.js applications that spawn COM surrogate processes (unlikely without /Processid:)
level: high
```

### Sigma: Outbound Connection to MALFEX C2 IP 104.234.65.75

Detects any network connection to the known MALFEX C2 IP `104.234.65[.]75`. No process filter -- fires for any image.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Single-IP rule; will need updates if actor rotates infrastructure. No known legitimate services at this IP. Title renamed from "Node.js Connects" to match detection logic (no Image filter). -->

```yaml
title: Outbound Connection to MALFEX C2 IP 104.234.65.75
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects outbound network connections to the known MALFEX campaign
    C2 server at 104.234.65.75, used for payload download (port 700) and
    stealer C2/WebSocket communication (port 7007). No process image filter;
    fires for any process connecting to this IP.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
    - https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html
author: Actioner
date: 2026/10/19
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '104.234.65.75'
    condition: selection
falsepositives:
    - None expected - this is a known malicious IP
level: critical
```

### Sigma: MALFEX Persistence via MicrosoftEdgeUpdateService

Detects the MALFEX stealer creating persistence via a scheduled task or registry Run key named `MicrosoftEdgeUpdateService`.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Requires process_creation logging (Sysmon EID 1 or 4688 with command-line). The stealer likely uses direct registry/task API calls rather than reg.exe/schtasks.exe command lines, so this rule may miss -- supplement with registry_set monitoring. Downgraded from high to medium per critic review. -->

```yaml
title: MALFEX Stealer Persistence via MicrosoftEdgeUpdateService
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: >
    Detects the MALFEX movinlike stealer creating persistence via a scheduled
    task or registry Run key named MicrosoftEdgeUpdateService, which masquerades
    as a legitimate Microsoft Edge update service.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
    - https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html
author: Actioner
date: 2026/10/19
tags:
    - attack.t1053.005
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'MicrosoftEdgeUpdateService'
            - '/create'
    selection_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'MicrosoftEdgeUpdateService'
            - 'CurrentVersion\Run'
    condition: selection_schtasks or selection_reg
falsepositives:
    - Legitimate Microsoft Edge update service installations (verify the binary path points to the official Edge updater)
level: medium
```

### Sigma: MALFEX Stealer Drops Masquerading EdgeUpdate Binary

Detects file creation of `MicrosoftEdgeUpdate.exe` in the AppData EdgeUpdate directory by a non-standard process.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403); splunk convert exit 0; log_scale convert exit 0. Requires file_event logging (Sysmon EID 11). Filter excludes legitimate Edge updater writes. -->

```yaml
title: MALFEX Stealer Drops Masquerading EdgeUpdate Binary
id: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a
status: experimental
description: >
    Detects creation of MicrosoftEdgeUpdate.exe in the AppData EdgeUpdate
    directory by a non-standard process, consistent with the MALFEX movinlike
    stealer establishing persistence with a masquerading binary name.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
    - https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html
author: Actioner
date: 2026/10/19
tags:
    - attack.t1036.005
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - '\AppData\Roaming\Microsoft\EdgeUpdate\'
            - 'MicrosoftEdgeUpdate.exe'
    filter_legit:
        Image|contains: '\Microsoft\EdgeUpdate\'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate Microsoft Edge update self-updates
level: high
```

### Snort: MALFEX C2 IP Outbound Connection and Stage-2 Download

Detects outbound TCP connections to the MALFEX C2 IP `104.234.65[.]75` on any port, with specific rules for the `/setup.exe` download (port 700) and WebSocket C2 (port 7007).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R m.rules -T exit 0 (Snort 2.9.20). IP-specific rules; will age out if the actor rotates infrastructure. -->

```snort
alert tcp $HOME_NET any -> 104.234.65.75 700 (msg:"Actioner - MALFEX C2 Stage-2 Download from 104.234.65.75:700"; flow:established,to_server; content:"GET"; depth:3; content:"/setup.exe"; distance:1; sid:2100001; rev:2; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/;)

alert tcp $HOME_NET any -> 104.234.65.75 7007 (msg:"Actioner - MALFEX Stealer WebSocket C2 to 104.234.65.75:7007"; flow:established,to_server; content:"Upgrade|3a 20|websocket"; nocase; fast_pattern; sid:2100002; rev:1; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/;)

alert tcp $HOME_NET any -> 104.234.65.75 any (msg:"Actioner - MALFEX Known C2 IP 104.234.65.75 Outbound Connection"; flow:established,to_server; sid:2100003; rev:1; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/;)
```

### Suricata: MALFEX GitHub Payload Download and C2 Communication

Detects HTTP requests to the `cavecrew/proj` GitHub repository used for encrypted shellcode delivery, and outbound connections to the MALFEX C2 IP.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0 (Suricata 7.0.3). GitHub URL rule depends on the cavecrew account remaining the payload source; C2 IP rules will age out on infrastructure rotation. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - MALFEX imgdecode Payload Download from GitHub cavecrew/proj"; flow:established,to_server; http.host; content:"raw.githubusercontent.com"; http.uri; content:"/cavecrew/proj/"; fast_pattern; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/; metadata:author Actioner, created_at 2026-10-19; sid:2200001; rev:1;)

alert tcp $HOME_NET any -> 104.234.65.75 7007 (msg:"Actioner - MALFEX Stealer WebSocket C2 to 104.234.65.75:7007"; flow:established,to_server; content:"Upgrade:"; nocase; content:"websocket"; nocase; distance:0; within:20; fast_pattern; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/; metadata:author Actioner, created_at 2026-10-19; sid:2200002; rev:1;)

alert tcp $HOME_NET any -> 104.234.65.75 any (msg:"Actioner - MALFEX Known C2 IP 104.234.65.75 Any Port"; flow:established,to_server; classtype:trojan-activity; reference:url,safedep.io/malfex-imgdecode-npm-native-addon-loader/; metadata:author Actioner, created_at 2026-10-19; sid:2200003; rev:1;)
```

### YARA: MALFEX imgdecode Native Addon DLL

Detects the MALFEX `imgdecode` malicious Node.js native addon via PDB path, decryption passphrase, XOR key, and process injection API imports. Covers all three known DLL builds.
**Status:** compile ✅ compiles · confidence: high · sample: constructed
<!-- audit: yarac exit 0. yara pos.txt matched Malware_MALFEX_Imgdecode_Native_Addon; neg.txt quiet. Positive constructed from published PDB path and passphrase strings, not an upstream sample. Condition uses OR branches: $pdb alone is sufficient; alternatively $passphrase + 2 injection APIs; or $export + $passphrase. -->

```yara
rule Malware_MALFEX_Imgdecode_Native_Addon
{
    meta:
        description = "Detects the MALFEX imgdecode malicious Node.js native addon (.node DLL) via PDB path, XOR key, decryption passphrase, and injection API chain"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1"
        hash = "d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714"
        hash = "54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85"
        severity = "critical"

    strings:
        $pdb = "imgdecode\\build\\Release\\imgdecode.pdb" ascii
        $passphrase = "nif-runtime-2027" ascii wide
        $export = "napi_register_module_v1" ascii
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "CreateRemoteThread" ascii fullword
        $api4 = "VirtualProtectEx" ascii fullword
        $api5 = "CreateProcessW" ascii fullword
        $target = "dllhost.exe" ascii wide
        $ua = "Mozilla/5.0" ascii
        $key = "malfexteam2027" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $pdb or
            ($passphrase and 2 of ($api*)) or
            ($export and $passphrase) or
            ($key and 1 of ($api*)) or
            ($target and $passphrase and $ua)
        )
}
```

### YARA: MALFEX Go Downloader

Detects the MALFEX Go-based stage-2 downloader that retrieves `setup.exe` from the C2 server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Keys on the hardcoded C2 IP 104.234.65.75 combined with the downloader module name, svc_update.exe path, or Go build string. -->

```yara
rule Malware_MALFEX_Go_Downloader
{
    meta:
        description = "Detects the MALFEX Go-based stage-2 downloader that fetches setup.exe from the C2 server"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b"
        severity = "high"

    strings:
        $mod = "downloader" ascii fullword
        $c2_1 = "104.234.65.75" ascii
        $c2_2 = "setup.exe" ascii
        $path1 = "svc_update.exe" ascii
        $go = "Go build" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $c2_1 and
        ($go or 1 of ($mod, $path1, $c2_2))
}
```

### YARA: MALFEX movinlike Stealer

Detects the MALFEX `movinlike` Node.js stealer packed with `pkg`, via its `.env` config strings, MALFEX license key pattern, and C2 IP.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: yarac exit 0. The 100MB filesize is intentional (pkg-packed Node.js apps are large; the known sample is 71.5 MB). Condition requires C2 IP plus env config, or MALFEX license plus name/IP. Added uint16(0) == 0x5A4D PE header check per critic review to prevent matching on reports/blog posts containing "MALFEX-" and "movinlike". Downgraded from high/critical to medium. -->

```yara
rule Malware_MALFEX_Movinlike_Stealer
{
    meta:
        description = "Detects the MALFEX movinlike Node.js stealer packed with pkg, via config strings and license key pattern"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6"
        severity = "high"

    strings:
        $license = "MALFEX-" ascii
        $env1 = "NPM_API=" ascii
        $env2 = "NPM_LICENSE=" ascii
        $env3 = "NPM_RAT=" ascii
        $name = "movinlike" ascii fullword
        $c2 = "104.234.65.75" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100MB and
        (
            (2 of ($env*) and $c2) or
            ($license and $name) or
            ($license and $c2)
        )
}
```

## Lessons Learned

1. **Native addons are an under-monitored attack surface.** Most npm security tools focus on JavaScript analysis and lifecycle hook inspection. Pre-compiled `.node` files in `prebuilds/` directories bypass these checks entirely, making them an attractive vector for advanced adversaries.

2. **Rapid replacement defeats point-in-time takedowns.** The MALFEX operator published replacement packages within hours of each takedown, demonstrating that reactive removal alone is insufficient. Defenders need behavioral detection (e.g., `node.exe` spawning `dllhost.exe`) alongside IOC-based blocking.

3. **Console-gating is an effective sandbox evasion technique.** By checking whether stdout is an interactive console, the addon avoids detonation in most automated analysis environments, which typically redirect output. This is a novel evasion technique for npm malware.

4. **Supply-chain attacks are increasingly targeting the build-time and require-time execution model** rather than install-time hooks. Organizations should audit `require()` chains and native addon imports, not just `postinstall` scripts.

## Sources

- [SafeDep - MALFEX Moves Its npm Loader into a Native Windows DLL](https://safedep.io/malfex-imgdecode-npm-native-addon-loader/) -- primary technical analysis of `imgdecode` native addon, injection chain, and stealer capabilities
- [The Hacker News - MALFEX npm Package 'imgdecode' Hides Shellcode Loader](https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html) -- detailed timeline and campaign overview
- [The Hacker News - Eight Malicious npm Packages Downloaded 40,767 Times](https://thehackernews.com/2026/10/eight-malicious-npm-packages-downloaded.html) -- broader MALFEX campaign coverage (Checkmarx/CloudSEK findings)
- [Socket.dev - imgdecode package files](https://socket.dev/npm/package/imgdecode/files/1.0.0/index.js) -- package structure analysis
- [npm - imgdecode versions](https://www.npmjs.com/package/imgdecode?activeTab=versions) -- package version history
- [Checkmarx - MALFEX Campaign Analysis](https://checkmarx.com/blog/malfex-npm-supply-chain-attack/) -- initial MALFEX campaign discovery and analysis
- [CloudSEK - MALFEX Threat Actor Attribution](https://cloudsek.com/blog/malfex-npm-supply-chain-campaign/) -- linguistic attribution and campaign tracking
- [OSV Advisory MAL-2026-17320](https://osv.dev/vulnerability/MAL-2026-17320) -- `imgdecode` advisory

<!-- revision: FINAL 1.0 — Sigma dllhost rule: T1055.001→T1055 (shellcode injection, not DLL injection). Sigma C2 IP rule: renamed from "Node.js Connects" to "Outbound Connection" (no Image filter in detection). Sigma persistence rule: downgraded high→medium (stealer likely uses API calls, not schtasks/reg.exe CLIs). Snort sid:2100001: $EXTERNAL_NET→104.234.65.75 (specific C2 IP). YARA imgdecode: sample label fired✓→constructed. YARA movinlike: added uint16(0)==0x5A4D PE check, downgraded to medium. ATT&CK table: removed T1055.012 (not process hollowing), corrected T1055.001→T1055. Defanged bare IP in Remediation §7. Fixed OSV link to specific advisory. Added Checkmarx and CloudSEK source URLs. -->

---
*Report generated by Actioner*
