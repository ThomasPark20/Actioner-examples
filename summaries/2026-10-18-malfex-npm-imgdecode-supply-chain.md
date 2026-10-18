# Technical Analysis Report

**DRAFT** | **TLP:CLEAR** | **Date:** 2026-10-18 | **Analyst:** Actioner CTI

## Executive Summary

The MALFEX campaign is a multi-stage npm supply chain attack centered on the `imgdecode` package (979 downloads), which embeds a Windows-only shellcode loader inside a prebuilt native Node.js addon (`imgdecode.node`). The addon decrypts a remotely hosted payload using AES-256-CBC (key derived from SHA-256 of "nif-runtime-2027"), then injects the resulting shellcode into a suspended `dllhost.exe` process. The final payload is a Node.js-based stealer/RAT ("MALFEX") capable of harvesting browser credentials, cryptocurrency wallets, Discord tokens, and establishing persistent WebSocket-based remote access. At least eight npm packages published by five accounts since September 2026 are attributed to this operator, with a broader campaign dating to August 2023. The operator is assessed to be Portuguese-speaking, likely Brazil-based, operating under the "Malfex team" / "Murizada" identity.

## Background

The MALFEX npm supply chain attack was publicly disclosed on October 17, 2026, following coordinated analysis by SafeDep, Checkmarx, CloudSEK, and Socket. The campaign exploits the npm ecosystem's trust model by publishing packages with innocuous names (`imgdecode`, `imgbundle`, `cdn-img-fetch`) that conceal native Windows DLLs carrying an obfuscated shellcode loader. The attack specifically targets Windows developer workstations, with anti-analysis features to detect debugger and sandbox environments.

The campaign is notable for its use of prebuilt native addons rather than postinstall scripts, bypassing many existing supply chain security controls that focus on lifecycle hook abuse.

## Attack Timeline

| Date (UTC) | Event |
|---|---|
| 2023-08-06 | Earliest known MALFEX campaign activity begins |
| 2026-09-26 | `cdn-img-fetch`, `img-to-native`, `native-runner` 1.0.0 published to npm |
| 2026-09-28 16:06 | npm removes `native-runner` and `img-to-native` |
| 2026-09-30 03:29 | `imgbundle` 1.0.0 published (replacement for `img-to-native`) |
| 2026-09-30 03:37 | `runhelper` 1.0.0 published (replacement for `native-runner`) |
| 2026-09-30 16:13 | `runhelper` unpublished by author |
| 2026-09-30 22:32 | `imgdecode` 1.0.0 published -- native addon approach begins |
| 2026-09-30 23:07 | `imgdecode` 1.0.1 published |
| 2026-10-01 17:48 | `imgdecode` 1.0.2 published |
| 2026-10-06 | Internet Archive captures GitHub-hosted Go downloader image |
| 2026-10-07 23:06 | npm removes `imgbundle` |
| 2026-10-08 13:03 | npm removes `cdn-img-fetch` |
| 2026-10-11 22:09 | `imgdecode` 1.0.3 published (removes `imgbundle` dependency, self-contained) |
| 2026-10-17 | Public disclosure via The Hacker News |

## Root Cause

The attack exploits the npm package registry's permissive publishing model, where any user can publish packages containing prebuilt native binaries. Unlike postinstall scripts, native addon `.node` files (which are DLLs on Windows) are loaded via `require()` during normal module resolution without triggering lifecycle hook auditing. The nine-line JavaScript wrapper in `imgdecode` simply calls `require('./prebuilds/win32-x64/imgdecode.node')`, which loads and executes the malicious DLL through the N-API `napi_register_module_v1` entry point.

## Technical Analysis

### Stage 0: Initial Access via npm Package

The `imgdecode` package is published with a prebuilt native addon at `prebuilds/win32-x64/imgdecode.node`. A minimal JavaScript wrapper loads this addon via `require()`. The addon is a 64-bit MSVC-compiled DLL that registers through the standard N-API entry point `napi_register_module_v1`.

### Stage 1: Native Addon Loader (imgdecode.node)

The DLL employs single-byte XOR obfuscation (key `0x37`) for all sensitive strings, stored as 16-byte blocks in the `.rdata` section. On execution, the loader:

1. **Environment check**: Calls `GetStdHandle(STD_OUTPUT_HANDLE)` and `GetConsoleMode` to determine if it is running in a developer terminal
2. **Payload download**: Uses WinINet (`InternetOpenA`, `InternetOpenUrlA` with flags `0x80800000`) to fetch an encrypted payload from `https://raw.githubusercontent[.]com/cavecrew/proj/main/banner.jpg`
3. **Decryption**: Derives an AES-256-CBC key via SHA-256 of "nif-runtime-2027" using Windows CNG (`bcrypt.dll`). The ciphertext layout is IV (first 16 bytes) followed by PKCS#7-padded ciphertext
4. **Kill-switch check**: Inspects decrypted plaintext for JPEG (`FF D8`) or PNG (`89 50 4E 47`) magic bytes; if matched, execution halts (operator-controlled disable mechanism)
5. **Process injection**: Creates a suspended `dllhost.exe` process (`CreateProcessW` with flags `0x0800020C` = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_SUSPENDED), allocates memory via `VirtualAllocEx` (MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE), writes shellcode with `WriteProcessMemory`, changes protection to PAGE_EXECUTE_READ via `VirtualProtectEx`, and starts execution with `CreateRemoteThread`
6. **Fallback**: If remote injection fails, falls back to in-process execution via `VirtualAlloc` / `RtlMoveMemory` / `VirtualProtect` / `CreateThread`

### Stage 2: Go Downloader (svc_update.exe)

The injected shellcode bootstraps a Go executable (compiled with Go 1.27.1, `-ldflags="-s -w -H windowsgui"`). This downloader fetches `setup.exe` from `http://104.234.65[.]75:700/setup.exe` and writes it to `%TEMP%\svc_update.exe`.

### Stage 3: MALFEX Stealer/RAT (setup.exe / "movinlike")

The final payload is a Node.js application packaged with `pkg`. It reads configuration from a `.env` file containing:
- `NPM_API=http://104.234.65[.]75:7007`
- `NPM_LICENSE=MALFEX-89BEE69BB61967AF1C3B07C9`
- `NPM_RAT=1`

**Stealer capabilities:**
- Browser credential harvesting (Chromium passwords, cookies, app-bound key recovery)
- Cryptocurrency wallet file collection (`.kdbx`, `.pem`, `.ppk`, seed/mnemonic files)
- Discord token theft via `discord_desktop_core/index.js` patching
- Telegram session data theft
- Clipboard monitoring
- Screen capture
- File collection targeting `.env`, files matching patterns: seed, mnemonic, wallet, secret, token, senha

**RAT capabilities:**
- WebSocket-based C2: `ws://104.234.65[.]75:7007/agent?license=...`
- HTTP API endpoints: `/about/sendRouter`, `/about/discord`
- Exfiltration via `malfex.zip` archive upload

**Persistence:**
- Copies to `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`
- Registry Run key value: `MicrosoftEdgeUpdateService`
- Scheduled task: `MicrosoftEdgeUpdateService`

**Anti-forensics:**
- Windows Security and Sysmon EVTX log tampering with checksum recalculation
- PowerShell history file deletion
- Anti-analysis checks for `x64dbg`, `procmon`, `wireshark`
- Sandbox username detection

### Earlier Variants

Prior to the native addon approach, the campaign used JavaScript-based loaders:
- **runhelper**: Used the Koffi FFI module to call `VirtualAlloc` / `RtlMoveMemory` / `CreateThread` for in-process shellcode execution from a JPG file
- **img-to-native**: Decrypted a Go executable using key "malfexteam2027" and dropped it to `%APPDATA%\Microsoft\Windows\node_runtime_helper.exe`
- **cdn-img-fetch**: Extracted encrypted blobs from a PNG file (`banner.png`)

## Indicators of Compromise (IOCs)

> All indicators are defanged per reporting standards. Detection rules use live values.

### Malicious npm Packages

| Package | Versions | Advisory ID |
|---|---|---|
| imgdecode | 1.0.0, 1.0.1, 1.0.2, 1.0.3 | -- |
| imgbundle | 1.0.0, 1.0.1, 1.0.2 | MAL-2026-17330 |
| runhelper | 1.0.0 | MAL-2026-17332 |
| cdn-img-fetch | 1.0.0 | MAL-2026-17320 |
| img-to-native | 1.0.0 | MAL-2026-17216 |
| native-runner | 1.0.0 | MAL-2026-17218 |

### File Hashes (SHA-256)

| Artifact | SHA-256 |
|---|---|
| imgdecode.node v1.0.0 | `d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714` |
| imgdecode.node v1.0.1 | `54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85` |
| imgdecode.node v1.0.2/1.0.3 | `a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1` |
| banner.png (JS-era carrier) | `4f4f7d64139bde6d458a061c7fb7dd247f70f60a1ab47d87fd3634656586c106` |
| Stage 2 Go downloader | `2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b` |
| Stage 3 MALFEX stealer/RAT | `8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6` |

### Network Indicators

| Indicator | Context |
|---|---|
| `104.234.65[.]75` | C2 server (AS265919, BB Host LTDA, Sao Paulo, Brazil) |
| `http://104.234.65[.]75:700/setup[.]exe` | Stage 2 download URL |
| `http://104.234.65[.]75:7007` | Stealer/RAT C2 API |
| `ws://104.234.65[.]75:7007/agent?license=` | RAT WebSocket endpoint |
| `hxxps://raw.githubusercontent[.]com/cavecrew/proj/main/banner.jpg` | Encrypted shellcode payload |
| `hxxps://raw.githubusercontent[.]com/cavecrew/proj/main/banner.png` | JS-era encrypted payload |
| `cdnzona.discloud[.]app` | function-flag payload host |

### Host Indicators

| Indicator | Type |
|---|---|
| `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` | Persistence binary path |
| `%APPDATA%\Microsoft\Windows\node_runtime_helper.exe` | Earlier variant persistence path |
| `%TEMP%\svc_update.exe` | Stage 2 drop path |
| `MicrosoftEdgeUpdateService` (Run key value) | Registry persistence |
| `MicrosoftEdgeUpdateService` (scheduled task) | Task scheduler persistence |
| `MALFEX-89BEE69BB61967AF1C3B07C9` | License key in .env |
| `C:\Users\Administrator\Desktop\npm\imgdecode\build\Release\imgdecode.pdb` | PDB path |

### Publisher Accounts

| npm Handle | Email |
|---|---|
| malfexteste8 | trelicas.flexionar_4q@icloud[.]com |
| malfexkkj | -- |
| malfex_user | -- |
| malfexteste2 | -- |
| malfexteste3 | -- |
| malfexteste4 | -- |

### Encryption Keys

| Key Material | Usage |
|---|---|
| `nif-runtime-2027` | SHA-256 to derive AES-256-CBC key (native addon) |
| `malfexteam2027` | AES key for img-to-native variant |
| `0x37` | XOR byte for string obfuscation in imgdecode.node |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observable |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm packages published to public registry |
| T1204.002 | User Execution: Malicious File | `require()` of imgdecode triggers native addon load |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JS wrapper loads native addon; earlier variants used Koffi FFI |
| T1027 | Obfuscated Files or Information | XOR 0x37 string encoding in .rdata section |
| T1140 | Deobfuscate/Decode Files or Information | AES-256-CBC decryption of downloaded payload at runtime |
| T1105 | Ingress Tool Transfer | Download of encrypted shellcode and setup.exe from remote hosts |
| T1620 | Reflective Code Loading | In-memory shellcode execution via VirtualAlloc/CreateThread fallback |
| T1055 | Process Injection | Shellcode injection into suspended dllhost.exe via CreateRemoteThread |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MicrosoftEdgeUpdateService Run key value |
| T1053.005 | Scheduled Task/Job: Scheduled Task | MicrosoftEdgeUpdateService scheduled task |
| T1036 | Masquerading | Persistence artifacts named to resemble Microsoft Edge updater |
| T1497 | Virtualization/Sandbox Evasion | VM and sandbox environment checks |
| T1622 | Debugger Evasion | Detection of x64dbg, procmon, wireshark |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium password/cookie harvesting |
| T1005 | Data from Local System | Wallet, key, and credential file collection |
| T1115 | Clipboard Data | Clipboard monitoring in RAT mode |
| T1113 | Screen Capture | Screenshot capability |
| T1219 | Remote Access Software | WebSocket-based RAT |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP and WebSocket C2 communication |
| T1041 | Exfiltration Over C2 Channel | malfex.zip archive upload to C2 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | EVTX tampering with checksum recalculation |

## Impact Assessment

- **Scope:** 979 downloads of `imgdecode`; approximately 40,767 combined downloads across the broader eight-package campaign (dominated by `function-flag` at 37,419)
- **Platform:** Windows x64 only (the native addon is a 64-bit MSVC DLL; non-Windows systems are unaffected)
- **Severity:** CRITICAL -- full system compromise including credential theft, cryptocurrency wallet extraction, persistent remote access, and anti-forensic log tampering
- **Affected parties:** Developers who installed any version of the listed packages on Windows systems
- **Financial risk:** Direct cryptocurrency theft via wallet seed phrase and key file exfiltration
- **Credential exposure:** Browser passwords, Discord tokens, Telegram sessions, SSH/PGP keys

## Detection & Remediation

### Immediate Actions

1. **Audit dependencies:** Search all projects for any of the listed package names in `package.json` and `package-lock.json`
2. **Isolate affected systems:** Any Windows machine that installed these packages should be treated as compromised
3. **Check persistence:** Look for the `MicrosoftEdgeUpdateService` scheduled task and Run key value; check for `MicrosoftEdgeUpdate.exe` in `%APPDATA%\Microsoft\EdgeUpdate\`
4. **Rotate credentials:** All browser-stored passwords, Discord tokens, SSH keys, and API tokens on affected systems
5. **Move crypto assets:** If seed phrases, wallet files, or private keys were stored on the affected machine, transfer funds to new wallets immediately
6. **Review logs:** Check for outbound connections to `104.234.65[.]75` on ports 700 and 7007

### Long-term Mitigations

- Enable npm audit and use lockfile-only installs (`npm ci`)
- Deploy package allowlisting or use tools like Socket, Snyk, or SafeDep to screen new dependencies
- Monitor for native addon files (`.node`) in npm packages, which are less commonly audited than JavaScript
- Implement process creation monitoring for `node.exe` spawning unexpected child processes

## Detection Rules

### Sigma: Node.js Spawns dllhost.exe Without COM Activation (Confidence: high)

Detects the specific process injection pattern where node.exe creates a dllhost.exe child process without the standard /Processid: COM argument.

**File:** `rules/sigma/malfex-npm-imgdecode-node-spawns-dllhost.yml`

### Sigma: MALFEX Scheduled Task Persistence (Confidence: high)

Detects schtasks.exe creating the MicrosoftEdgeUpdateService task name used by MALFEX for persistence.

**File:** `rules/sigma/malfex-npm-imgdecode-scheduled-task.yml`

### Sigma: MALFEX Fake EdgeUpdate Binary Drop (Confidence: high)

Detects file creation of MicrosoftEdgeUpdate.exe in the AppData\Roaming EdgeUpdate path, which is not a legitimate Edge updater location.

**File:** `rules/sigma/malfex-npm-imgdecode-persistence-path.yml`

### Sigma: MALFEX Registry Run Key Persistence (Confidence: high)

Detects registry set operations creating the MicrosoftEdgeUpdateService value under a Run key.

**File:** `rules/sigma/malfex-npm-imgdecode-run-key.yml`

### YARA: MALFEX imgdecode Native Addon (Confidence: high)

Detects the malicious imgdecode.node DLL via XOR-0x37 encoded strings for the decryption key, GitHub URL, WriteProcessMemory, and CreateRemoteThread, plus the characteristic PDB path.

**File:** `rules/yara/malfex-npm-imgdecode.yar`

### YARA: MALFEX Stage 2 Go Downloader (Confidence: medium)

Detects the Go-compiled downloader that fetches setup.exe from the MALFEX C2 server.

**File:** `rules/yara/malfex-npm-imgdecode.yar` (rule: `MALFEX_Stage2_Go_Downloader`)

### Suricata: MALFEX C2 Network Indicators (Confidence: high)

Four rules covering Stage 2 download (setup.exe on port 700), stealer API endpoints (/about/sendRouter, /about/discord), and RAT WebSocket registration.

> **Non-standard port caveat:** Rules targeting ports 700 and 7007 require HTTP application-layer detection on those ports. Suricata 7+ automatic protocol detection handles this by default; older versions need explicit `app-layer.protocols.http.detection-ports` configuration for ports 700 and 7007.

**File:** `rules/suricata/malfex-npm-imgdecode.rules`

## Sources

- [The Hacker News - MALFEX npm Package imgdecode Hides Shellcode Loader](https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html)
- [SafeDep - MALFEX imgdecode npm Native Addon Loader Analysis](https://safedep.io/malfex-imgdecode-npm-native-addon-loader/)
- [The Hacker News - Eight Malicious npm Packages Downloaded 40K+ Times](https://thehackernews.com/2026/10/eight-malicious-npm-packages-downloaded.html)
- [Socket - runhelper 1.0.0 Source](https://socket.dev/npm/package/runhelper/files/1.0.0/index.js)
- [Socket - imgdecode 1.0.0 Source](https://socket.dev/npm/package/imgdecode/files/1.0.0/index.js)
- [npm - imgdecode Versions](https://www.npmjs.com/package/imgdecode?activeTab=versions)
- [npm-stat - imgdecode Download Statistics](https://npm-stat.com/charts.html?package=imgdecode)
- [Koffi - FFI Module for Node.js](https://koffi.dev/)
