# 13 Malicious NuGet Packages -- Fake .NET Job Assessment Supply Chain Attack

**Date:** 2026-11-26
**Status:** FINAL
**TLP:** WHITE
**Researcher:** Socket (Kush Pandya)

---

## Executive Summary

A coordinated software supply-chain attack used 13 malicious NuGet packages disguised as WinUI 3 and WPF button controls to target Windows .NET developers through fake take-home job assessments. Active from July 23 through November 2026, the campaign delivered multiple payloads including DLL sideloading stagers, credential stealers, reconnaissance tools, and C2 loaders -- all leveraging GitHub repositories as infrastructure. The operation spans NuGet and npm registries across four NuGet publisher accounts and three npm accounts, totaling 28 package versions. Socket researchers disclosed the campaign on November 23, 2026, and NuGet has since removed the packages.

---

## Background

The campaign targets .NET developers through a social engineering lure: a fake take-home coding assessment requiring candidates to enhance a FileButton control and implement exception handling in a WinUI 3 project. The assessment repository (`stevenleedig-ux/WinUI3_Home_Assessment`) ships pre-built malicious `.nupkg` files in a local `Packages` folder and configures NuGet restore to pull from that folder. Building the solution triggers the infection chain automatically via MSBuild targets.

The attacker also ran a parallel campaign via npm (six packages in July 2026), maintained a ClickFix social engineering page on GitHub Pages, and posted a job listing on the LaborX freelance marketplace advertising an $8,500--10,000 C# WPF developer position for a "Crypto Wallet Analyzer" application, which was itself trojanized.

Socket noted similarities to North Korean "Contagious Interview" and Iranian recruitment-themed campaigns but found no shared indicators or code, and has not attributed the campaign to a named threat actor. The attacker persona's X account metadata indicates Korea, while the persona claimed a Miami, Florida base.

---

## Technical Analysis

### Stage 0: Social Engineering Lure

- **Lure repository:** `stevenleedig-ux/WinUI3_Home_Assessment` (created Nov 3, 2026)
- **Mechanism:** A "Home Assessment" with a 3--4 hour time limit, requiring candidates to build the project (which triggers NuGet restore from a local packages folder)
- **Local feed:** `RestoreAdditionalProjectSources` in the `.csproj` points to a committed `Packages` folder containing the trojanized `.nupkg` files
- **Setting:** `DisableFastUpToDateCheck=true` ensures the malicious MSBuild target runs on every build
- **Additional lure:** A LaborX job posting (Nov 7, 2026) for a "Crypto Wallet Analyzer" application
- **ClickFix page:** A fake reCAPTCHA "Security Handshake Error" page at `figma-share[.]github[.]io` (created Sep 3, 2026) that tricks users into pasting a PowerShell command into the Windows Run dialog

### Stage 1: MSBuild Build-Time Execution

The `VS_Builder.MSBuildAnalyzer` / `HappyOne.MSBuildAnalyzer` packages ship a `.targets` file in their `build/` directory that MSBuild automatically imports:

- **Targets file:** `build/VS_Builder.MsBuildAnalyzer.targets` (or `HappyOne.MsBuildAnalyzer.targets`)
- **Framework gate:** Only executes if the target framework starts with `net8.0-windows` or equals `net10.0`
- **Execution hook:** `AfterTargets="Build"` -- runs after every build
- **Re-execution trick:** `Outputs` references `ForceExecuteNonExistenFile.txt`, which never exists, forcing re-execution on every build
- **Error suppression:** `IgnoreExitCode=true` and `ContinueOnError=true`
- **Command:** `dotnet MSBuildAnalyzer.dll` from the package's `lib\net8.0` or `lib\net10.0` folder

### Stage 2: DLL Sideloading Stager

`MSBuildAnalyzer.dll` performs the following:

1. Runs decoy operations to appear legitimate
2. Decrypts a URL and local paths from embedded AES-encrypted fragments (key: `sPq0nrUkrTYj5qUvdsRYAlVQ7MPQBwCuIB17ghrz0vM=`)
3. Downloads a file from `hxxps://raw[.]githubusercontent[.]com/stevenleedig-ux/fantastic-giggle/main/src/demos/SPGO/build[.]docker` to `%LOCALAPPDATA%\osk\OskSupport.dll`
4. Copies `C:\Windows\System32\osk.exe` to `%LOCALAPPDATA%\osk\osk.exe` with timestamp matching

### Stage 3: DLL Sideloading Trigger

The `VS_Builder.WinUI3Controls` / `HappyOne.WinUI3Controls` package provides the `FileButton` WPF control:

- The FileButton constructor launches `%LOCALAPPDATA%\osk\osk.exe` with a hidden window (`UseShellExecute`)
- `osk.exe` (legitimate Windows On-Screen Keyboard) loads `OskSupport.dll` from the same directory (DLL sideloading pair documented by HijackLibs)
- Guard: Only the first FileButton per process triggers the launch; a process-path check prevents duplicates

### Alternative Payload Chains

**WinUI.Button path:**
1. A `WUIButton` XAML control triggers `Core.Init()` on a background task
2. A named mutex (`Global\MyUniqueApplicationGuid-12345`) limits to one instance
3. Downloads `avast.exe` from `hxxps://api[.]github[.]com/repos/Carol-White-Super/cloud/contents/db/avast[.]exe?ref=Main` using an embedded fine-grained GitHub token
4. Saves as `%TEMP%\Launcher.exe` and executes
5. Retries on failure after 1--4 seconds with no limit

**Loader (updater.exe / msedgewebview2.exe) path:**
1. Anti-analysis checks and 5-minute initial delay
2. Connectivity check via Google `generate_204` and IP lookup via `api[.]ipify[.]org`
3. GitHub Contents API used as two-way C2 (creates `<victim_ID>/log1.dat` with Base64-encoded host data)
4. Reads `<victim_ID>/log2.dat`, decrypts with AES-256-CBC (IV = first 16 bytes, key = SHA-256 of passphrase)
5. Maps PE in memory, calls exported `Start` function, deletes itself via batch file
6. User-Agent strings: `MyUpdater`, `CppHttp/1.0`

**Chrome profile stealer path:**
1. Hidden PowerShell creates Volume Shadow Copy via `Win32_ShadowCopy`
2. Collects Chrome profile data (all `Profile*` directories plus `Local State`)
3. Zips and splits into `.part` files
4. Uploads via GitHub Contents API PUT to `gabsantosbus-star/EngineeringRepository` with commit message `Backup <name>`

**WeapF reconnaissance payload:**
1. Anti-debug checks and process enumeration
2. Sleeps 1 minute or 1 hour (branch-dependent)
3. Adds itself to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
4. Fetches AES-GCM encrypted config from `hxxps://raw[.]githubusercontent[.]com/jeksifjeksjejcks/test/main/README[.]md` (key: `K9vT2mQ7xL4pR8sW1cF6zH3nD5aB0yEa`)
5. Sends computer name, username, timezone, and CPU model to a Telegram bot via `sendMessage`

**Crypto Wallet Analyzer path:**
1. Presents as a crypto wallet inventory tool
2. `MainWindow` constructor loads `vcruntime146_cor2.dll` (a native DLL not in the manifest)
3. DLL starts a background thread on load; closing the window only hides it
4. Polls GitHub C2 at `Best-Seller-Dev/dexTrader`
5. Inventories eight crypto wallet browser extensions

**ClickFix path:**
1. Fake reCAPTCHA page at `figma-share[.]github[.]io`
2. "Copy Security Token" button copies a PowerShell command
3. User pastes into Win+R
4. Hidden PowerShell with `-ExecutionPolicy Bypass` downloads and executes from `hxxps://cloudservicebase[.]ddns[.]net/update/CVE-2026-44747_patch[.]dat`

### Related npm Packages

Six npm packages (published July 14--23, 2026, all removed) are linked to the same operation:

| Package | Socket Advisory |
|---|---|
| axios-test-one | MAL-2026-10727 |
| telemetry-metrics | MAL-2026-10750 |
| telemetry-axios | MAL-2026-10773 |
| axios-native | MAL-2026-10772 |
| fs-extra-core | MAL-2026-11027 |
| vitest-axios | MAL-2026-11030 |

npm accounts: `gsanbus`, `jasonsayman`, `jasonsuperstar`.

---

## Indicators of Compromise

### Malicious NuGet Packages (13 packages, 28 versions, 4 publisher accounts)

| # | Package ID | Known Versions | Publisher |
|---|---|---|---|
| 1 | WinUI.Button | 1.0.0 | Carol-White-Super |
| 2 | VS_Builder.MSBuildAnalyzer | 1.0.1, 1.0.2, 1.0.8, 1.1.2, 1.1.3, 1.2.7 | VS_Builder |
| 3 | VS_Builder.WinUI3Controls | 1.0.6, 1.0.7 | VS_Builder |
| 4 | HappyOne.MSBuildAnalyzer | 1.2.8, 1.2.9, 1.3.0 | HappyOne |
| 5 | HappyOne.WinUI3Controls | 1.0.9, 1.1.0 | HappyOne |
| 6 | Web3TotalButton | Unknown | Steven-White-Super |
| 7 | RevertButtonIcon | 1.0.1 | HappyOne |
| 8 | WinUI3IconButton | From 1.1.4 | HappyOne |
| 9 | WindowsAccentColorName | Unknown | HappyOne |
| 10 | SetButtonColor | Unknown | HappyOne |
| 11 | InitializeCustomButton | Unknown | HappyOne |
| 12 | StyledAppButton | Unknown | HappyOne |
| 13 | StyledComponent | 1.0.0 | HappyOne |

> **Note:** The package name "StyledComponent" (row 13) is a common web development term and is not reliable as a standalone indicator. It should only be considered malicious when associated with the publisher account **HappyOne** or when found alongside other packages from this campaign.

### File Hashes (SHA-256)

**NuGet Packages and DLLs:**

| File | SHA-256 |
|---|---|
| winui.button.1.0.0.nupkg | `ccf299e23471cd79b2f40f91ee6f48293893e6c626ef84b10ef0b3ba86a89770` |
| WinUI.Button.dll (1.0.0) | `9e58baccd25b009b80f093bbcaf007b1ca3ac763c9826e05e1352e64264d0d42` |
| VS_Builder.MSBuildAnalyzer.1.2.7.nupkg | `d0a78aec3dd8dbce2e3fb0412b666a602fc0a71a800e24b99d735581795e11dc` |
| VS_Builder.MsBuildAnalyzer.targets | `33510d8e48c26279c0c212b4e6e5f95b7f0a116061eae7f50241f81903be5b6b` |
| MSBuildAnalyzer.dll net8.0 (1.2.7) | `352b04dac5f63208f45c7c7326ed06c6fa8ae2752e4cdafff0cfe649ebaeabe2` |
| MSBuildAnalyzer.dll net10.0 (1.2.7) | `b49a89af8c4884f9aecad7d980bfffa03226e8d30aa35afd813919af9e2d7cfa` |
| MSBuildAnalyzer.dll net8.0 (HappyOne 1.2.9) | `09dd6f214a5b5a1fe2934cc859a1d1ce566894faf9236a0bcab2d2cf34448d63` |
| VS_Builder.WinUI3Controls.1.0.7.nupkg | `63f1c64bd0db73b327d6655e4262ab8dcbd4ff2ed0a6dd5e062ceb977dcb3e75` |
| WinUI3Controls.dll (1.0.7) | `a3d04638930eae8442578679be6d150b3c56373627c9bc7e480725a31bb2d85d` |

**Native Payloads:**

| File | SHA-256 |
|---|---|
| msedgewebview2.exe loader | `56e899eb1d5c967cbe760d1b7ac409fb9420b862c122ef7ec2a2aa6469a503a7` |
| updater.exe loader (build 1) | `ae28ff44ee3bd2911c5a1e4110f12d12e7b585f087a0afd85d6fdc4d4b5a36f5` |
| updater.exe loader (build 2) | `541b0893ca326b6c652cb1d5873f208e968481e33b635c3869479016bcd75d4f` |
| PyInstaller Chrome stealer (build 1) | `016f633b9a8dd5ef17d577775cc64f96aa30192f3fbf814eba0c3f5c9fa5d91a` |
| PyInstaller Chrome stealer (build 2) | `ef691b00cada5974b6bb516386c90589bd2340216f446518ad08d11fc930d631` |
| WeapF payload | `1bc553ee2324f67c86cf8d9057da242e8ab363c59e452f5a69a1275909c20a97` |
| CryptoWalletAnalyzer.exe | `e7e7649f7249cb32f3123299e3a200c83dc210420b40f944168c36ab781b9458` |
| vcruntime146_cor2.dll | `17761569bf44d46877b22972bb1ca224527562a7a7aeb5b70ca8112510a49537` |
| CryptoWalletAnalyzer.dll | `27f600d476638c8f1236db3eda9d70e39c9a96ff62fca69ca227426c48448bf7` |
| Themida build 1 | `b8cf4c68dc362aeb31546a3dd091f8f23cf624e495eec84c840f2dd0906e2f4d` |
| Themida build 2 | `26485a167f9e4c4ea146c8420ba0bcc44facbec4d5e8fd91e624f2c81255b589` |
| Themida build 3 | `3dfce4e8d5b625e435429c8d15fb6ce8bad9601fbc7b84f74b4aa5b560bc482e` |
| LGA.exe wrapper 1 | `78fa8ea3d4daaaf088babd49f2bc0e59220940dc256d8b8938bad95e2fe4717b` |
| LGA.exe wrapper 2 | `b797935ff3db3da42d046537d17191d790a6344a12947347165eea2744e1265d` |

**Import Hashes (MD5):**

| Binary | Imphash |
|---|---|
| msedgewebview2.exe | `4b8f63685671c33f9641cd5828a78b3b` |
| updater.exe | `cd5bc2ef1c7e076b4460e33047e3c1ad` |
| WeapF | `988e5f290039d4b31527468bd4e76787` |
| vcruntime146_cor2.dll | `e36515e3fb6349a641ef456317ae0b3f` |

### Network Infrastructure (Defanged)

**C2 / Payload Hosting:**

| Indicator | Context |
|---|---|
| `cloudservicebase[.]ddns[.]net` | ClickFix VPS; resolved to 172[.]86[.]119[.]233 (RouterHosting/Cloudzy) on Aug 29, 2026 |
| `172[.]86[.]119[.]233` | VPS IP for cloudservicebase DDNS |
| `hxxps://cloudservicebase[.]ddns[.]net/update/CVE-2026-44747_patch[.]dat` | ClickFix payload URL |
| `hxxps://api[.]github[.]com/repos/Carol-White-Super/cloud/contents/db/avast[.]exe` | WinUI.Button second stage |
| `hxxps://api[.]github[.]com/repos/James-White-Super/React_prj/contents/react-burger/public` | updater.exe C2 |
| `hxxps://api[.]github[.]com/repos/James-Tran-Dev/teris/contents/Tetris-main/Assets/Anims/Cam` | msedgewebview2.exe C2 |
| `hxxps://api[.]github[.]com/repos/Best-Seller-Dev/dexTrader/contents/src/signal` | Wallet app C2 |
| `hxxps://api[.]github[.]com/repos/gabsantosbus-star/EngineeringRepository/contents/` | Stealer upload target |
| `hxxps://raw[.]githubusercontent[.]com/stevenleedig-ux/fantastic-giggle/main/src/demos/SPGO/build[.]docker` | Stager download |
| `hxxps://raw[.]githubusercontent[.]com/jeksifjeksjejcks/test/main/README[.]md` | WeapF encrypted config |
| `api[.]ipify[.]org` | External IP lookup |

**GitHub Accounts (attacker-controlled):**

- stevenleedig-ux
- jason-code-super
- figma-share (formerly ThoSuperstarDev)
- James-White-Super
- James-Tran-Dev
- jeksifjeksjejcks
- gabsantosbus-star
- Carol-White-Super
- Best-Seller-Dev

**GitHub Token Hashes (SHA-256 of embedded tokens):**

| Binary | Token Hash |
|---|---|
| WinUI.Button.dll | `9bc1be99462f89880e1e22d9d3ade01cbbfe8bae54a27125e0129542f92ce93f` |
| updater.exe | `b33c9b4c9771032b16de477271551f64f4f550f85eec96a70d1a345f84f55603` |
| msedgewebview2.exe | `b8eb00ae419b1a9421f13200ff4893eba57800543de1d71b9752c301123783ff` |
| vcruntime146_cor2.dll | `2ae7e8cb7d50922c9b8f6032fa452d0e0b27f8b0f520ddd90945ebdb6ecf423a` |
| PyInstaller stealer | `0068c4edd784c482030b68fa3a13e5d16fde30ed999619b87ead40ef5333a074` |

### File System Indicators

| Path | Context |
|---|---|
| `%LOCALAPPDATA%\osk\OskSupport.dll` | DLL sideloading payload |
| `%LOCALAPPDATA%\osk\osk.exe` | Copied legitimate On-Screen Keyboard |
| `%TEMP%\Launcher.exe` | WinUI.Button payload |
| `C:\Windows\System32\winrse.exe` | Drop path in WeapF (unconfirmed) |

### Registry Indicators

| Key | Context |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | WeapF persistence |

### Certificate Indicators

| Field | Value |
|---|---|
| Subject & Issuer | `CN=Microsoft Windows Publisher` (self-signed, spoofed) |
| Serial | `505524D1ACD4CAAD4A1C119312B0E1D1` |
| SHA-1 Thumbprint | `50F2E9C97C3C15AC3C7ABBAD47A272BDFE47ACEF` |
| SHA-256 Thumbprint | `9A581FACA7FBA81AA0AC91F621EB9302646BCA3A954D044746C4751AAE2E23A0` |

### Static Detection Strings

| Indicator | Context |
|---|---|
| `_environmentProbeKeyFragment` | MSBuildAnalyzer.dll method name |
| `_diagnosticHostSourceKeyFragment` | MSBuildAnalyzer.dll method name |
| `ForceExecuteNonExistenFile` | MSBuild targets re-execution trick |
| `CppHttp/1.0` | WinHTTP client name in loaders |
| `MyUpdater` | User-Agent in loader GitHub API requests |
| `AppleWevKit` | Misspelled User-Agent string |
| `CxcXExBZTEwC` | Base64 string in stager |
| `t6WyuLSgnp2ckPCI/JKFkJ2ck7C3pbK6vLC37fc=` | Base64 string in stager |
| `dropper_dll.dll` | Export directory in vcruntime146_cor2.dll |
| `JSON_OBJECT` | Single export from dropper DLL |
| `Global\MyUniqueApplicationGuid-12345` | Named mutex in WinUI.Button |

### PDB Paths

| Path | Binary |
|---|---|
| `D:\dev_prjects\C#\Calculator\WinUI.Button\...` | WinUI.Button.dll |
| `F:\Packages\for.8.010.0\MSBuildAnalyzer\...` | MSBuildAnalyzer.dll |
| `F:\WinUI 3 packages\WinUI3Controls\...` | WinUI3Controls.dll |
| `D:\Work\Codes\WeapF\x64\Release\Payload.pdb` | WeapF |
| `D:\Work\Codes\ExeWrapper\x64\Release\EXEWrapper.pdb` | Loader wrapper |
| `F:\VM_SHARE\crypto_wallet_analyzer-main\...\CryptoWalletAnalyzer.pdb` | Wallet app |

### Cryptographic Material

| Key / Passphrase | Usage |
|---|---|
| `sPq0nrUkrTYj5qUvdsRYAlVQ7MPQBwCuIB17ghrz0vM=` | MSBuildAnalyzer stager AES key |
| `NKz0WUpm4uBA9fcO8xN+xj87Ngke7RXPpHuflllgjuk=` | FileButton AES key |
| `asdnbvHKJF&^*DSFKJEfasdljfa;!` | Loader passphrase |
| `!fjka&k34534*HJKHNT,.sdkr9i'sdfgjkjlkjserft` | Loader passphrase |
| `HKJzuefjkhsadhfaosdhfkja` | vcruntime146_cor2.dll passphrase |
| `K9vT2mQ7xL4pR8sW1cF6zH3nD5aB0yEa` | WeapF AES-GCM key |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Campaign Usage |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized NuGet packages distributed via local package feeds in lure repositories |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | osk.exe + OskSupport.dll sideloading pair in %LOCALAPPDATA%\osk\ |
| T1204.002 | User Execution: Malicious File | Developers build the lure project, triggering MSBuild targets |
| T1204.001 | User Execution: Malicious Link | ClickFix fake reCAPTCHA prompts user to paste command into Run dialog |
| T1059.001 | Command and Scripting Interpreter: PowerShell | ClickFix hidden PowerShell with bypass policy; Chrome stealer shadow copy creation |
| T1105 | Ingress Tool Transfer | Download of payloads from GitHub API and raw.githubusercontent.com |
| T1102.002 | Web Service: Bidirectional Communication | GitHub Contents API used for two-way C2 (log1.dat/log2.dat), stealer upload, and config retrieval |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome profile stealer via Volume Shadow Copy |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | WeapF adds itself to HKCU Run key |
| T1140 | Deobfuscate/Decode Files or Information | AES-encrypted URLs/paths in stager; AES-256-CBC encrypted C2 payloads; AES-GCM encrypted config |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Packages mimic WinUI 3 / WPF controls; vcruntime146_cor2.dll disguised as VC runtime; binaries named msedgewebview2.exe |
| T1041 | Exfiltration Over C2 Channel | Chrome profiles uploaded to GitHub; host data sent to Telegram |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Anti-debug checks and process enumeration in WeapF and loaders |
| T1071.001 | Application Layer Protocol: Web Protocols | GitHub API and raw.githubusercontent.com used for C2, payload delivery, and exfiltration; DDNS domain for ClickFix payload |

---

## Impact Assessment

**Severity: HIGH**

- **Scope:** .NET developers building projects that reference any of the 13 malicious NuGet packages are at risk. The lure targets individual developers via fake job assessments, limiting blast radius compared to public registry typosquatting.
- **Data at Risk:** Chrome browser credentials and profiles, host reconnaissance data, and potential for arbitrary code execution via the C2 loaders.
- **Persistence:** The WeapF payload establishes persistence via registry Run keys. DLL sideloading stager re-executes on every project build.
- **Lateral Movement:** No lateral movement capabilities observed; the campaign targets individual developer workstations.
- **Supply Chain Risk:** The local NuGet feed approach means the packages were not widely distributed via the public NuGet gallery, though some were briefly available there. 28 versions across 4 publisher accounts indicate persistence and adaptation (HappyOne packages republished after VS_Builder packages were removed).
- **Attribution:** Unattributed. Tradecraft similarities to North Korean and Iranian recruitment campaigns noted by Socket, but no shared indicators or code found.

---

## Detection & Remediation

### Immediate Actions

1. **Search for affected packages:** Scan all `.csproj`, `packages.config`, `packages.lock.json`, and NuGet caches for the 13 package names listed above
2. **Check for file system indicators:** Look for `%LOCALAPPDATA%\osk\OskSupport.dll`, `%LOCALAPPDATA%\osk\osk.exe`, and `%TEMP%\Launcher.exe`
3. **Check registry persistence:** Inspect `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for unexpected entries pointing to temp directories
4. **Revoke exposed credentials:** If Chrome profile theft is confirmed, rotate all credentials stored in Chrome, including saved passwords and session cookies
5. **Block GitHub accounts:** Add the listed attacker GitHub accounts to internal monitoring or blocking rules
6. **Block network indicators:** Add `cloudservicebase[.]ddns[.]net` and `172[.]86[.]119[.]233` to blocklists
7. **Report attacker GitHub accounts:** Report the listed attacker-controlled GitHub accounts and any embedded GitHub fine-grained tokens to GitHub Trust & Safety (https://support.github.com/contact/report-abuse)
8. **Check for ClickFix indicators:** Search proxy/DNS logs for traffic to `cloudservicebase[.]ddns[.]net` and connections from PowerShell processes with `-ExecutionPolicy Bypass`
9. **Check for Crypto Wallet Analyzer indicators:** Search for `vcruntime146_cor2.dll` on disk and DNS/proxy logs for connections to `Best-Seller-Dev/dexTrader` GitHub C2 path

### Preventive Measures

1. **NuGet package source control:** Restrict NuGet restore to approved feeds; do not allow local package sources from untrusted repositories
2. **Code review for MSBuild targets:** Inspect `.targets` and `.props` files in NuGet packages before building (particularly look for `AfterTargets="Build"` with `dotnet` execution)
3. **Developer security training:** Warn developers about fake job assessment lures that require building untrusted code
4. **Build environment isolation:** Use sandboxed or disposable build environments for untrusted code review assignments

---

## Detection Rules

> **23 detection rules** (6 Sigma, 8 YARA, 5 Suricata, 4 Snort). Three rules from the initial draft were dropped during review:
> - **Chrome Profile Theft via Volume Shadow Copy and PowerShell** (Sigma) -- behavioral/TTP-level detection with no campaign-specific artifact; fails altitude gate for PoC/advisory-specific scope.
> - **Launcher.exe Execution from Temp Directory** (Sigma) -- "Launcher.exe" is an extremely common filename with no campaign-unique artifact.
> - **Telegram Bot API Exfiltration** (Suricata) -- purely behavioral with no campaign-specific element and massive false-positive risk.
>
> Rules 2, 5, 6, 13, and 17 were revised during review to tighten specificity (see individual rule notes).

### Sigma Rules

#### 1. Suspicious DLL Sideloading via Copied osk.exe in LocalAppData

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** high

```yaml
title: Suspicious DLL Sideloading via Copied osk.exe in LocalAppData
id: 7c3a1e4b-9f2d-4a6e-8b7c-1d5e8f0a3c2b
status: experimental
description: >
    Detects execution of osk.exe (On-Screen Keyboard) from a non-standard location
    under LocalAppData, which is indicative of DLL sideloading used by malicious NuGet
    packages in the fake .NET job assessment supply chain attack. The attack copies
    osk.exe to %LOCALAPPDATA%\osk\ alongside a malicious OskSupport.dll.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1574.002
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\osk.exe'
        Image|contains: '\AppData\Local\osk\'
    condition: selection
falsepositives:
    - Legitimate accessibility tool usage from non-standard paths (unlikely)
level: high
```

#### 2. Dotnet Execution of MSBuildAnalyzer DLL From NuGet Package Cache

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** high

```yaml
title: Dotnet Execution of MSBuildAnalyzer DLL From NuGet Package Cache
id: 2f8b4c1a-6e3d-4a9f-b5d7-9c0e1f2a3b4c
status: experimental
description: >
    Detects dotnet.exe executing MSBuildAnalyzer.dll from a NuGet package cache path,
    indicative of the malicious DLL delivered via trojanized NuGet packages
    (VS_Builder.MSBuildAnalyzer, HappyOne.MSBuildAnalyzer) as part of the fake .NET
    job assessment supply chain attack. The DLL is executed via MSBuild targets after
    every project build.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1195.002
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dotnet.exe'
        CommandLine|contains|all:
            - 'MSBuildAnalyzer.dll'
            - '.nuget\packages'
    condition: selection
falsepositives:
    - Legitimate MSBuild analyzer tools with similar naming in NuGet package cache (verify package source)
level: high
```

#### 3. OskSupport.dll Written to LocalAppData osk Directory

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** high

```yaml
title: OskSupport.dll Written to LocalAppData osk Directory
id: 4d9e7f2a-1b3c-4e5d-8a6f-0c2b1d8e7f3a
status: experimental
description: >
    Detects the creation of OskSupport.dll in the %LOCALAPPDATA%\osk\ directory,
    indicative of the DLL sideloading stager used by malicious NuGet packages in the
    fake .NET job assessment campaign. The stager downloads this DLL from GitHub
    and stages it alongside a copy of the legitimate osk.exe.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1574.002
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\AppData\Local\osk\OskSupport.dll'
    condition: selection
falsepositives:
    - None known
level: critical
```

#### 4. Suspicious GitHub API Requests with MyUpdater User-Agent

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** high

```yaml
title: Suspicious GitHub API Requests with MyUpdater User-Agent
id: 5a1b2c3d-4e5f-6789-abcd-ef0123456789
status: experimental
description: >
    Detects HTTP requests to the GitHub API using the custom User-Agent string
    'MyUpdater', which is used by the updater.exe and msedgewebview2.exe loaders
    from the malicious NuGet package campaign. These loaders use GitHub repositories
    as two-way C2 channels.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1102.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_ua:
        c-useragent: 'MyUpdater'
    selection_dest:
        cs-host|contains: 'github'
    condition: selection_ua and selection_dest
falsepositives:
    - Custom developer tools using 'MyUpdater' as User-Agent (unlikely)
level: high
```

#### 5. WeapF Payload Persistence via HKCU Run Key

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** medium

```yaml
title: WeapF Payload Persistence via HKCU Run Key
id: 6b3c4d5e-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: experimental
description: >
    Detects the WeapF payload adding itself to the HKCU Run registry key for
    persistence. WeapF is a reconnaissance and C2 payload used in the malicious
    NuGet package campaign that reports host information to a Telegram bot.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run'
    filter_known:
        Image|endswith:
            - '\explorer.exe'
            - '\msiexec.exe'
            - '\OneDrive.exe'
            - '\Teams.exe'
    selection_suspicious_paths:
        Details|contains:
            - '\AppData\Local\osk\'
            - 'winrse.exe'
    condition: selection and selection_suspicious_paths and not filter_known
falsepositives:
    - Legitimate software installing to temp directories with Run key persistence
level: high
```

#### 6. ClickFix PowerShell Download from DDNS Domain

**Compile status:** ✅ compiles (sigma check pass, sigma convert to Splunk and LogScale pass)
**Confidence:** high

```yaml
title: ClickFix PowerShell Download from DDNS Domain
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
    Detects PowerShell execution with bypass policy downloading from DDNS domains,
    consistent with the ClickFix social engineering technique used in the malicious
    NuGet campaign. The attacker hosts a fake reCAPTCHA page that tricks users into
    pasting a PowerShell command into the Windows Run dialog.
references:
    - https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments
    - https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html
author: Actioner
date: 2026-11-26
tags:
    - attack.t1059.001
    - attack.t1204.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_bypass:
        CommandLine|contains:
            - '-ExecutionPolicy Bypass'
            - '-ep bypass'
            - '-exec bypass'
    selection_ddns:
        CommandLine|contains:
            - 'cloudservicebase.ddns.net'
            - 'cloudservicebase'
    condition: selection_ps and selection_bypass and selection_ddns
falsepositives:
    - Legitimate scripts downloading from DDNS services (unusual in enterprise environments)
level: critical
```

### YARA Rules

#### 7. Malware_NuGet_MSBuildAnalyzer_Stager

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_MSBuildAnalyzer_Stager
{
    meta:
        description = "Detects malicious MSBuildAnalyzer.dll delivered via trojanized NuGet packages in fake .NET job assessment campaign. The DLL acts as a build-time stager that downloads payloads from GitHub and stages DLL sideloading."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "352b04dac5f63208f45c7c7326ed06c6fa8ae2752e4cdafff0cfe649ebaeabe2"
        severity = "critical"

    strings:
        $s1 = "_environmentProbeKeyFragment" ascii wide
        $s2 = "_diagnosticHostSourceKeyFragment" ascii wide
        $s3 = "BuildPipeline" ascii wide
        $s4 = "OskSupport.dll" ascii wide
        $s5 = "osk.exe" ascii wide
        $aes_key = "sPq0nrUkrTYj5qUvdsRYAlVQ7MPQBwCuIB17ghrz0vM=" ascii
        $b64_1 = "CxcXExBZTEwC" ascii
        $b64_2 = "t6WyuLSgnp2ckPCI/JKFkJ2ck7C3pbK6vLC37fc=" ascii
        $github_api = "api.github.com/repos" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) or ($aes_key) or (2 of ($b64*)) or ($s1 and $github_api) or ($s2 and $github_api))
}
```

#### 8. Malware_NuGet_WinUIButton_Downloader

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_WinUIButton_Downloader
{
    meta:
        description = "Detects malicious WinUI.Button.dll NuGet package that downloads and executes payloads from GitHub using embedded tokens. Part of the fake .NET job assessment supply chain attack."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "9e58baccd25b009b80f093bbcaf007b1ca3ac763c9826e05e1352e64264d0d42"
        severity = "critical"

    strings:
        $s1 = "Core.Init" ascii wide
        $s2 = "Global\\MyUniqueApplicationGuid-12345" ascii wide
        $s3 = "Launcher.exe" ascii wide
        $s4 = "avast.exe" ascii wide
        $s5 = "Carol-White-Super" ascii
        $s6 = "WUIButton" ascii wide
        $github = "api.github.com/repos" ascii wide
        $aes_key = "NKz0WUpm4uBA9fcO8xN+xj87Ngke7RXPpHuflllgjuk=" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) or $aes_key or ($s2 and $s3) or ($s6 and $github))
}
```

#### 9. Malware_NuGet_MSBuildTargets_Trojanized

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_MSBuildTargets_Trojanized
{
    meta:
        description = "Detects trojanized MSBuild .targets files used by malicious NuGet packages to execute code after every build. The targets file forces re-execution by referencing a non-existent output file."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "33510d8e48c26279c0c212b4e6e5f95b7f0a116061eae7f50241f81903be5b6b"
        severity = "high"

    strings:
        $s1 = "ForceExecuteNonExistenFile" ascii wide nocase
        $s2 = "ExecuteInlineCSharpTarget" ascii wide nocase
        $s3 = "MSBuildAnalyzer.dll" ascii wide
        $s4 = "AfterTargets=\"Build\"" ascii nocase
        $s5 = "IgnoreExitCode" ascii nocase
        $s6 = "ContinueOnError" ascii nocase

    condition:
        filesize < 100KB and
        ($s1 or ($s2 and $s3) or ($s3 and $s4 and ($s5 or $s6)))
}
```

#### 10. Malware_NuGet_UpdaterLoader_GithubC2

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_UpdaterLoader_GithubC2
{
    meta:
        description = "Detects the updater.exe/msedgewebview2.exe loader used as C2 agent in the malicious NuGet package campaign. Uses GitHub repositories as two-way C2 channels with CppHttp User-Agent."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "56e899eb1d5c967cbe760d1b7ac409fb9420b862c122ef7ec2a2aa6469a503a7"
        severity = "critical"

    strings:
        $ua1 = "CppHttp/1.0" ascii wide
        $ua2 = "MyUpdater" ascii wide
        $cjson1 = "cJSON_Parse" ascii
        $cjson2 = "cJSON_GetObjectItem" ascii
        $github1 = "api.github.com" ascii wide
        $github2 = "raw.githubusercontent.com" ascii wide
        $log1 = "log1.dat" ascii wide
        $log2 = "log2.dat" ascii wide
        $pass1 = "asdnbvHKJF&^*DSFKJEfasdljfa;!" ascii
        $pass2 = "!fjka&k34534*HJKHNT,.sdkr9i'sdfgjkjlkjserft" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($ua1 and 1 of ($cjson*)) or
            ($ua2 and 1 of ($github*)) or
            (1 of ($log*) and 1 of ($github*) and 1 of ($pass*)) or
            (2 of ($pass*))
        )
}
```

#### 11. Malware_NuGet_WeapF_Recon_Payload

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_WeapF_Recon_Payload
{
    meta:
        description = "Detects the WeapF reconnaissance payload from the malicious NuGet package campaign. Reports host information to Telegram and uses AES-GCM encrypted config from GitHub."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "1bc553ee2324f67c86cf8d9057da242e8ab363c59e452f5a69a1275909c20a97"
        severity = "high"

    strings:
        $pdb = "WeapF" ascii wide
        $pdb2 = "Payload.pdb" ascii wide
        $tg = "api.telegram.org/bot" ascii wide
        $aes_key = "K9vT2mQ7xL4pR8sW1cF6zH3nD5aB0yEa" ascii
        $ip_check = "api.ipify.org" ascii wide
        $generate204 = "generate_204" ascii wide
        $winrse = "winrse.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($pdb and $tg) or
            ($aes_key) or
            ($pdb and $ip_check) or
            ($winrse and $tg) or
            ($pdb2 and 2 of ($tg, $ip_check, $generate204))
        )
}
```

#### 12. Malware_NuGet_CryptoWalletAnalyzer

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_CryptoWalletAnalyzer
{
    meta:
        description = "Detects the trojanized Crypto Wallet Analyzer application from the malicious NuGet campaign. Loads a disguised native DLL (vcruntime146_cor2.dll) and polls GitHub for C2 commands."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "e7e7649f7249cb32f3123299e3a200c83dc210420b40f944168c36ab781b9458"
        severity = "high"

    strings:
        $dll_name = "vcruntime146_cor2.dll" ascii wide
        $export = "dropper_dll.dll" ascii
        $export2 = "JSON_OBJECT" ascii
        $pdb = "crypto_wallet_analyzer" ascii wide nocase
        $pdb2 = "CryptoWalletAnalyzer.pdb" ascii wide
        $aes_key = "HKJzuefjkhsadhfaosdhfkja" ascii
        $github = "Best-Seller-Dev" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($dll_name and ($export or $export2)) or
            ($pdb and $dll_name) or
            ($aes_key) or
            ($github and $dll_name) or
            ($pdb2 and 1 of ($export, $export2, $dll_name))
        )
}
```

#### 13. Malware_NuGet_Package_FakeJobAssessment

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_Package_FakeJobAssessment
{
    meta:
        description = "Detects malicious NuGet packages (.nupkg) from the fake .NET job assessment supply chain campaign by matching package IDs and known malicious content patterns."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "ccf299e23471cd79b2f40f91ee6f48293893e6c626ef84b10ef0b3ba86a89770"
        severity = "critical"

    strings:
        $pkg1 = "VS_Builder.MSBuildAnalyzer" ascii wide nocase
        $pkg2 = "VS_Builder.WinUI3Controls" ascii wide nocase
        $pkg3 = "HappyOne.MSBuildAnalyzer" ascii wide nocase
        $pkg4 = "HappyOne.WinUI3Controls" ascii wide nocase
        $pkg5 = "WinUI.Button" ascii wide
        $pkg6 = "Web3TotalButton" ascii wide nocase
        $pkg7 = "RevertButtonIcon" ascii wide nocase
        $pkg8 = "WinUI3IconButton" ascii wide nocase
        $pkg9 = "WindowsAccentColorName" ascii wide nocase
        $nuspec = "<package xmlns" ascii
        $nuget_marker = ".nuspec" ascii

    condition:
        filesize < 50MB and
        ($nuspec or $nuget_marker) and
        2 of ($pkg*)
}
```

#### 14. Malware_NuGet_SelfSignedCert_MicrosoftSpoof

**Compile status:** ✅ compiles (yarac pass)
**Confidence:** high

```yara
rule Malware_NuGet_SelfSignedCert_MicrosoftSpoof
{
    meta:
        description = "Detects binaries signed with the self-signed certificate spoofing Microsoft Windows Publisher, used across payloads in the malicious NuGet package campaign."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        severity = "high"

    strings:
        $cert_cn = "Microsoft Windows Publisher" ascii wide
        $cert_serial = "505524D1ACD4CAAD4A1C119312B0E1D1" ascii nocase
        $cert_sha1 = "50F2E9C97C3C15AC3C7ABBAD47A272BDFE47ACEF" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        ($cert_serial or $cert_sha1 or ($cert_cn and 2 of them))
}
```

### Suricata Rules

#### 15. GitHub API C2 with MyUpdater User-Agent

**Compile status:** ✅ compiles (suricata -T pass)
**Confidence:** high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GitHub API C2 with MyUpdater User-Agent (NuGet Supply Chain)"; flow:established,to_server; http.user_agent; content:"MyUpdater"; http.host; content:"api.github.com"; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created_at 2026-11-26; sid:2100101; rev:1;)
```

#### 16. GitHub API C2 with CppHttp User-Agent

**Compile status:** ✅ compiles (suricata -T pass)
**Confidence:** high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GitHub API C2 with CppHttp User-Agent (NuGet Supply Chain)"; flow:established,to_server; http.user_agent; content:"CppHttp/1.0"; http.host; content:"api.github.com"; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created_at 2026-11-26; sid:2100102; rev:1;)
```

#### 17. GitHub API Exfiltration to EngineeringRepository

**Compile status:** ✅ compiles (suricata -T pass)
**Confidence:** high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GitHub API Exfiltration to EngineeringRepository (NuGet Supply Chain)"; flow:established,to_server; http.method; content:"PUT"; http.host; content:"api.github.com"; http.uri; content:"/gabsantosbus-star/EngineeringRepository/"; fast_pattern; content:"/contents/"; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created_at 2026-11-26; sid:2100103; rev:2;)
```

#### 18. Misspelled AppleWevKit User-Agent

**Compile status:** ✅ compiles (suricata -T pass)
**Confidence:** high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Misspelled AppleWevKit User-Agent (NuGet Supply Chain)"; flow:established,to_server; http.user_agent; content:"AppleWevKit"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created_at 2026-11-26; sid:2100104; rev:1;)
```

#### 19. DDNS C2 ClickFix Payload Download

**Compile status:** ✅ compiles (suricata -T pass)
**Confidence:** high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - DDNS C2 ClickFix Payload Download (NuGet Supply Chain)"; flow:established,to_server; http.host; content:"cloudservicebase.ddns.net"; fast_pattern; http.uri; content:"/update/"; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created_at 2026-11-26; sid:2100105; rev:1;)
```

### Snort Rules

#### 20. GitHub API C2 with MyUpdater User-Agent (Snort 2)

**Compile status:** ✅ compiles (snort -T pass)
**Confidence:** high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GitHub API C2 with MyUpdater User-Agent (NuGet Supply Chain)"; flow:established,to_server; content:"MyUpdater"; http_header; content:"api.github.com"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created 2026-11-26; sid:2100201; rev:1;)
```

#### 21. GitHub API C2 with CppHttp User-Agent (Snort 2)

**Compile status:** ✅ compiles (snort -T pass)
**Confidence:** high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GitHub API C2 with CppHttp User-Agent (NuGet Supply Chain)"; flow:established,to_server; content:"CppHttp/1.0"; http_header; content:"api.github.com"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created 2026-11-26; sid:2100202; rev:1;)
```

#### 22. Misspelled AppleWevKit User-Agent (Snort 2)

**Compile status:** ✅ compiles (snort -T pass)
**Confidence:** high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Misspelled AppleWevKit User-Agent (NuGet Supply Chain)"; flow:established,to_server; content:"AppleWevKit"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created 2026-11-26; sid:2100203; rev:1;)
```

#### 23. DDNS C2 ClickFix Payload Download (Snort 2)

**Compile status:** ✅ compiles (snort -T pass)
**Confidence:** high

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - DDNS C2 ClickFix Payload Download (NuGet Supply Chain)"; flow:established,to_server; content:"cloudservicebase.ddns.net"; http_header; content:"/update/"; http_uri; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-packages-fake-job-assessments; metadata:author Actioner, created 2026-11-26; sid:2100204; rev:1;)
```

---

## Timeline

| Date | Event |
|---|---|
| Jul 14--23, 2026 | Six malicious npm packages published and removed |
| Jul 23, 2026 | First NuGet package (WinUI3IconButton) uploaded; jason-code-super GitHub account created |
| Jul 24, 2026 | msedgewebview2 loader committed to jason-code-super/axios |
| Aug 1, 2026 | Two PyInstaller Chrome stealer builds committed |
| Aug 4, 2026 | updater.exe loader (first build) committed |
| Aug 7--9, 2026 | LGA lead-generation lure active |
| Aug 10, 2026 | stevenleedig-ux/axios-http created; WeapF payload committed |
| Aug 27--Sep 2, 2026 | Three Themida builds committed |
| Aug 29, 2026 | cloudservicebase[.]ddns[.]net resolves to 172[.]86[.]119[.]233; Let's Encrypt cert issued |
| Sep 2, 2026 | WinUI.Button 1.0.0 published (Carol-White-Super) |
| Sep 3, 2026 | ClickFix GitHub Pages page created |
| Sep 5, 2026 | Public calculator repo referencing WinUI.Button created |
| Oct 25, 2026 | Web3TotalButton published |
| Nov 2, 2026 | VS_Builder packages published, then unlisted and deleted by NuGet |
| Nov 3--4, 2026 | Lure repository created; HappyOne packages published |
| Nov 6, 2026 | NuGet unlisted and deleted all HappyOne packages |
| Nov 7, 2026 | LaborX job posted for the wallet app |
| Nov 13, 2026 | Trojanized "Crypto Wallet Analyzer" released |
| Nov 23, 2026 | Socket publishes disclosure |

---

## Sources

- [Socket - 13 Malicious NuGet Packages Target .NET Developers With Fake Job Assessments](https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments)
- [The Hacker News - 13 Malicious NuGet Packages Turn Fake .NET Job Assessments Into Malware Delivery Traps](https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html)
- [Dark Reading - Attackers Target .NET Developers With Poisoned Job Assessments](https://www.darkreading.com/threat-intelligence/attackers-net-developers-poisoned-job-assessments)
