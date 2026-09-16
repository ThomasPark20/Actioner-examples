# Technical Analysis Report: Iranian CHOSEN BRICK Spyware (2026-09-16)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-16
Version: 1.1
<!-- revision: v1.1 – applied critic NEEDS-REVISION fixes: renamed Sigma #4 to generic TTP title; fixed Sigma #5 ATT&CK tag T1059→T1036.005; scoped Sigma #7 to advisory-specific hostnames; dropped Sigma #8 (generic proxy DNS); tightened YARA MsCache condition; added per-rule confidence labels; added Snort http_header/threshold notes; fixed Sigma #2 duplicate YAML key (CommandLine|contains) to use |contains|all -->

---

## Executive Summary

On September 15, 2026, the UK National Cyber Security Centre (NCSC), the US Federal Bureau of Investigation (FBI), and the Netherlands' General Intelligence and Security Service (AIVD) published a joint advisory exposing **CHOSEN BRICK** (NCSC designation) / **HEAVYGRAM** (FBI designation), a Windows-only spyware platform operated by Iran's Ministry of Intelligence and Security (MOIS). The malware has been used since at least autumn 2023 to surveil Iranian dissidents, opposition journalists, activists, and other individuals perceived as threats to the Iranian regime, with confirmed victims in the UK, US, and the Netherlands since 2025.

CHOSEN BRICK is a modular, multi-stage implant controlled entirely via the Telegram Bot API. Each victim is assigned a unique Telegram bot ID to limit cross-contamination. The malware provides comprehensive surveillance capabilities including email interception (Outlook and Gmail), screen and audio capture, browser credential theft, messaging data exfiltration (Telegram, WhatsApp), and file system enumeration. Data is exfiltrated through both Telegram and commercial cloud object storage services (VultrObjects, StorjShare, Backblaze B2). The FBI analyzed seven distinct malware samples across three behavioral clusters: masquerading droppers, persistent implants, and specialized modules.

This report provides a complete technical breakdown of the attack chain, extracted indicators of compromise from the FBI FLASH advisory (FLASH-20260915), MITRE ATT&CK mapping, and validated detection rules.

---

## Background: Iranian Cyber Operations Against Dissidents

Iran's MOIS has a documented history of using cyber operations to support the repression of individuals seen as a threat to the regime. The MOIS-linked groups behind CHOSEN BRICK overlap with personas known as **Handala Hack** and **Homeland Justice**, which have conducted data leaks and reputational attacks against opposition figures. Personal details of previous victims have appeared on pro-Iranian leak sites, increasing the physical safety risk to those affected.

The campaign targets a specific victim profile:
- Iranian dissidents and opposition figures
- Journalists critical of the Iranian government
- Members of organizations with views counter to Iranian government narratives
- Individuals Iran perceives as threats to regime stability

The threat actors operate across multiple countries, with documented targeting in the UK, US, Netherlands, and other locations worldwide.

---

## Attack Timeline

| Date | Event |
|------|-------|
| Autumn 2023 | Earliest observed CHOSEN BRICK deployment |
| 2025 | Documented victims in UK, US, and Netherlands |
| March 2026 | FBI publishes initial FLASH alert (FLASH-20260320-001) |
| September 15, 2026 | Joint NCSC/FBI/AIVD advisory published; FBI publishes updated FLASH with expanded IOCs |

---

## Root Cause: Social Engineering via Fake Medical Results

The initial compromise relies entirely on social engineering. MOIS actors establish contact with victims through messaging platforms -- primarily **Telegram**, **WhatsApp**, and **Instagram** -- and build rapport over time by impersonating known contacts or offering IT services. After gaining trust, actors deliver malicious files disguised as legitimate software or documents. Documented lures include:

- **Fake MRI scan results** (disk herniation) -- the most notable lure in the advisory
- **Pictory Premium** (AI video generator application)
- **Telegram Authenticator** (authentication application)
- **KeePass** (password manager)
- **Norton Antivirus**
- **Adobe Flash Player**
- **RunwayML** (AI creative tool)
- Offers of **AnyDesk** remote access (with actors requesting access strings)

The social engineering is tailored to each victim's interests and circumstances, making detection through content alone difficult.

---

## Technical Analysis

### 1. Initial Delivery (Stage 1 -- Masquerading Applications)

The first stage consists of Delphi-compiled or PyInstaller-packed executables that masquerade as legitimate software. Upon execution, they display convincing GUIs while silently dropping and executing the stage-2 implant.

**Sample: Pictory_premium_ver9.0.4.exe**
- SHA256: `E8B633DCAD173EB41EF02686B46779A4A0E53DF7F6C63039A798F2DB5EB83AFC`
- MD5: `1E6B601F733BC40EAA58916986BFC5B9`
- Compiler: Embarcadero Delphi (11.x Alexandria++)
- Downloaded from: `hxxps://sgp1[.]vultrobjects[.]com/downloads/pictory/Pictory_premium_ver9.0.4.exe`
- Contains hardcoded credential: `ghazalehmehrjo[at]gmail[.]com` / `8384238Fm@#$%^&*`
- Drops `File26.zip` containing Python dependencies and `smqdservice.exe` to `C:\ProgramData\SMQDServicePackages\488ht1-8ww648q\`
- Creates config at `%USERPROFILE%\AppData\Roaming\SMQDService\config.xml`

**Sample: Telegram_Authenticator.exe**
- SHA256: `9014FE4F16F01C0439B261ADE4CF980F460E0DAE46B1EC5F58FD9BC0AF26E531`
- MD5: `B9086413E7B6A0C6A11C25D14C22615F`
- Compiler: Embarcadelo Delphi (11.x Alexandria++), code-signed
- Drops `RuntimeSSH.exe` and dependencies to `C:\ProgramData\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\`

**Sample: KeePass.exe**
- SHA256: `C2DD678511373DC07E73EF1A580FC3332E640F15FF0D4C1044D4B9F305B6F503`
- MD5: `7402F2F9263782A4C469570035843510`
- Python 3.13 / PyInstaller, code-signed
- Functions as both masquerading app and persistent implant
- Configured with additional API endpoints: WhatsApp, Facebook Graph, Signal, Viber

### 2. CHOSEN BRICK Payload (Stage 2 -- Persistent Implants)

The stage-2 implants are Python-based executables compiled via PyInstaller. They share common code patterns (variable names like `ENC_KEY`, `XML_FILE_PATH`) suggesting a single developer.

**Sample: winappx.exe**
- SHA256: `8B595258CFF63C4F0EF9648ADB54C6AB050BB1D27933ECB3D687D31B51B7BA0C`
- MD5: `481C5B5E69A08C3DF206C59FD8DDC0DC`
- Python 3.9 / PyInstaller, code-signed (SSL.com certificate, revoked)
- Mutex: `euyrsmnszb85sf4444s`
- Install path: `%ALLUSERSPROFILE%\MicrosoftDistribution\sysmain\winappx.exe`
- Primary C2 implant with full command set

**Sample: smqdservice.exe**
- SHA256: `4A3B003994112B4DD24AC8B9CC4757F4A12576B57B3CC8F5028D85FBCEB7C405`
- MD5: `7E23FFADB664B0E53D821478A249D84C`
- Python 3.11 / PyInstaller
- Mutex: `nih6723443489kcvrf`
- Install path: `C:\ProgramData\SMQDServicePackages\488ht1-8ww648q\smqdservice.exe`
- Sends daily health messages (`Health message: <hostname> is active`)

**Sample: RuntimeSSH.exe** (two variants)
- SHA256 (v1): `0D74156089292EEE308017C8E8A7550739ECB6149FF379810F7C54B1DBAABC91`
- MD5 (v1): `E51FF37FB431767DCDEC0B5E6D2A786A`
- SHA256 (v2): `97C9E2CBE728153A350A280CACA6ED38F650014F6D1821B7764AFF4704FE12D9`
- MD5 (v2): `EBDD9595B79B39F53909D862499DBC94`
- Python 3.11 / PyInstaller
- Mutex: `ytyjyujyu`
- Install path: `C:\ProgramData\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\RuntimeSSH.exe`
- Creates spoofed directory `"C:\Windows \SysWOW64"` (note trailing space) for DLL staging

**C2 Command Set (from winappx.exe decompilation):**

| Command | Function |
|---------|----------|
| `ProcessList` | Enumerate running processes |
| `SysInfo` | Collect system information via `systeminfo` |
| `ss` | Take screenshot, send as PNG |
| `SendFile` | Exfiltrate staged files via Vultr S3 |
| `DefaultTelegram` / `AllTelegram` | Exfiltrate Telegram Desktop data |
| `StoreTelegram` | Exfiltrate Windows Store Telegram data |
| `GetChrome` / `GetMozilla` / `GetEdge` | Exfiltrate browser profiles |
| `GetChromePass` | Decrypt and exfiltrate Chrome saved passwords |
| `GetChromeTelWhat` | Exfiltrate WhatsApp/Telegram browser data |
| `OutlookExtract` | Extract all Outlook mailbox contents via COM |
| `EnableMic` | Download and deploy MicDriver audio surveillance |
| `MyWhatsApp` | Deploy trojanized WhatsApp (`WhatssApp.exe`) |
| `GetMyWhatSesion` | Exfiltrate WhatsApp session data |
| `ListFiles` | Enumerate all files on all drives |
| `GetFilePhone` | Copy data from USB/MTP connected devices |
| `UpdateTro` | Update implant configuration |
| `ChangeToken` | Change Telegram bot token and chat ID |
| `ChangeVicName` | Rename victim identifier |
| `@<command>` | Execute arbitrary OS command via `os.popen()` |
| `##<script>` | Execute Python script from `rantom.txt` |

### 3. Telegram C2 Communication

CHOSEN BRICK uses the Telegram Bot API exclusively for command and control:

- **Command polling**: `POST hxxps://api[.]telegram[.]org/bot<token>/getUpdates`
- **File exfiltration**: `POST hxxps://api[.]telegram[.]org/bot<token>/sendDocument`
- **Screenshot exfiltration**: `POST hxxps://api[.]telegram[.]org/bot<token>/sendPhoto?chat_id=<chat_id>`
- **File download from C2**: `POST hxxps://api[.]telegram[.]org/bot<token>/getFile?file_id=<file_id>`

Each victim device connects to a **unique Telegram Bot ID** as an operational security precaution, preventing cross-contamination between victims. Newer variants route traffic through residential proxy services (IPRoyal, LightningProxies) to obfuscate the Telegram traffic.

The configuration file stores token, userId, s3_hostname, s3_secret_key, s3_access_key, and VicName. The `ChangeToken` command allows operators to dynamically rotate bot credentials.

### 4. Surveillance Capabilities

**Email Theft:**
- Outlook: Enumerates all top-level mailboxes (Inbox, Deleted Items, Sent Items, Archive, Junk Email) via COM, extracts messages and attachments, compresses to `OU*.zip`
- Gmail: `MsCache.exe` module uses Selenium and a legitimate `chromedriver.exe` to perform OAuth token theft via headless Chrome; tokens stored as `.pickle` files and exfiltrated via Telegram

**MsCache.exe (Gmail Stealer):**
- SHA256: `4908C0BC11A933D83C83935D9468BA8D08BC23529E5FF4D4344D4F0787B84BB6`
- MD5: `3E7A2FCEF1D038D05B20148C573A6499`
- Downloads `credentials.json` from `hxxps://micbucket[.]ams1[.]vultrobjects[.]com/credentials.json`
- Uses OAuth scope `hxxps://mail[.]google[.]com/` for full Gmail access
- Stores tokens at `C:\ProgramData\ZlibDate\CachedFiles\<email>.pickle`
- Hardcoded user-agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36`

**Audio/Screen Capture (MicDriver):**
- `MicDriver.exe` (MD5: `D70EBF20E3D697897BAD5BEBF72EA271`, SHA256: `5D6AD895C126191FA202C412B08FE0DD8B75A72928B1E5E34986A040938384C6`)
- `MicDriver.dll` (MD5: `F8B5554808428291ACC65D1FD2EFE01C`, SHA256: `168A487F0E44FFEE975ECD27D3F4000C750E711963A61D6CE244FA390DD17441`)
- .NET assembly using `ZoomRecorder` namespace
- Captures screenshots as JPEG, audio as WAV (microphone + speaker)
- Archives with RAR using password `LoLoLoLo`
- Evidence of capturing victims during Zoom calls

**Browser Credential Theft:**
- Decrypts Chrome saved passwords using `win32crypt.CryptUnprotectData`
- Exports to `chrome_passwords.json` and sends to C2
- Copies Chrome, Firefox, and Edge user profile data

**WhatsApp Hijacking:**
- Deploys trojanized WhatsApp binary (`WhatssApp.exe` -- note double 's') with `WebView2Loader.dll`
- Installed to `C:\ProgramData\Drivers\Whatsapp\`
- Modifies WhatsApp shortcut to point to trojanized version
- Captures IndexedDB and Local Storage from both browser and installed WhatsApp

**Connected Device Harvesting:**
- Enumerates USB devices and Media Transfer Protocol (MTP) devices
- Copies files preserving original directory structure
- Stored in `%ALLUSERSPROFILE%\ZlibDate\Z84A847FEEB1FC2s\Files\Phones\`

### 5. Persistence Mechanisms

CHOSEN BRICK establishes persistence through Windows Registry Run keys at `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`:

| Value Name | Execution Path |
|------------|---------------|
| `SMQDService` | `C:\ProgramData\SMQDServicePackages\488ht1-8ww648q\smqdservice.exe` |
| `winappx` | `%ALLUSERSPROFILE%\MicrosoftDistribution\sysmain\winappx.exe` |
| `Default_SSH` | `C:\ProgramData\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\RuntimeSSH.exe` |
| `MicDriver` | `C:\ProgramData\Drivers\MicDriver\MicDriver.exe` |

**Antivirus Evasion:**
The malware adds Microsoft Defender exclusion paths via PowerShell:
```
Add-MpPreference -ExclusionPath 'C:\ProgramData\MicrosoftDistribution\sysmain'
Add-MpPreference -ExclusionPath 'C:\ProgramData\SMQDServicePackages\488ht1-8ww648q'
Add-MpPreference -ExclusionPath '<user>\Downloads\Telegram Desktop'
```

Both `pwsh.exe` (PowerShell 7) and `powershell.exe` (Windows PowerShell) are used, along with `cmd.exe /C powershell` variants, to maximize compatibility.

**Encrypted Configuration:**
- Configuration stored in XML format, encrypted via AES with HMAC verification
- Key derived through 8192 iterations of SHA-256 stretching
- Configuration path varies by variant: `%APPDATA%\SMQDService\config.xml`, `%APPDATA%\Config\config.xml`, `%ALLUSERSPROFILE%\ZlibDate\Settings\config.xml`

**Code Protection:**
- Core functionality stored in encrypted file `rantom.txt`
- Decrypted at runtime and executed via Python `exec()`
- Functions include persistence setup, Telegram data exfiltration, and command execution

---

## Indicators of Compromise (IOCs)

> All indicators are defanged for safe handling. Detection rules in this report use the original (non-defanged) values.

### File System

**Malware Hashes:**

| Sample | MD5 | SHA256 |
|--------|-----|--------|
| Pictory_premium_ver9.0.4.exe | `1E6B601F733BC40EAA58916986BFC5B9` | `E8B633DCAD173EB41EF02686B46779A4A0E53DF7F6C63039A798F2DB5EB83AFC` |
| Telegram_Authenticator.exe | `B9086413E7B6A0C6A11C25D14C22615F` | `9014FE4F16F01C0439B261ADE4CF980F460E0DAE46B1EC5F58FD9BC0AF26E531` |
| winappx.exe | `481C5B5E69A08C3DF206C59FD8DDC0DC` | `8B595258CFF63C4F0EF9648ADB54C6AB050BB1D27933ECB3D687D31B51B7BA0C` |
| smqdservice.exe | `7E23FFADB664B0E53D821478A249D84C` | `4A3B003994112B4DD24AC8B9CC4757F4A12576B57B3CC8F5028D85FBCEB7C405` |
| RuntimeSSH.exe (v1) | `E51FF37FB431767DCDEC0B5E6D2A786A` | `0D74156089292EEE308017C8E8A7550739ECB6149FF379810F7C54B1DBAABC91` |
| RuntimeSSH.exe (v2) | `EBDD9595B79B39F53909D862499DBC94` | `97C9E2CBE728153A350A280CACA6ED38F650014F6D1821B7764AFF4704FE12D9` |
| KeePass.exe | `7402F2F9263782A4C469570035843510` | `C2DD678511373DC07E73EF1A580FC3332E640F15FF0D4C1044D4B9F305B6F503` |
| MsCache.exe | `3E7A2FCEF1D038D05B20148C573A6499` | `4908C0BC11A933D83C83935D9468BA8D08BC23529E5FF4D4344D4F0787B84BB6` |
| MicDriver.exe | `D70EBF20E3D697897BAD5BEBF72EA271` | `5D6AD895C126191FA202C412B08FE0DD8B75A72928B1E5E34986A040938384C6` |
| MicDriver.dll | `F8B5554808428291ACC65D1FD2EFE01C` | `168A487F0E44FFEE975ECD27D3F4000C750E711963A61D6CE244FA390DD17441` |
| MicDriver.zip | `8C00489632CCEFDAC3612329FE5B5491` | `FFEAE7C9ED3EDABF3646376F50B738B4FBCA442154CBFB6252B3AA5845F3D793` |
| MDll.dll | `88022704FFB1264A6587E6E1B0759600` | `16162647CE3CC5B9043BF114F94E626E84188DA10FBF4882960A7EDE8EDE0868` |

**Mutexes:**

| Mutex | Associated Sample |
|-------|------------------|
| `euyrsmnszb85sf4444s` | winappx.exe |
| `nih6723443489kcvrf` | smqdservice.exe |
| `ytyjyujyu` | RuntimeSSH.exe |
| `noi672pp434awkc12f` | KeePass.exe |

**Key File Paths:**

- `C:\ProgramData\SMQDServicePackages\488ht1-8ww648q\` -- smqdservice.exe install directory
- `C:\ProgramData\MicrosoftDistribution\sysmain\` -- winappx.exe install directory
- `C:\ProgramData\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\` -- RuntimeSSH.exe install directory
- `C:\ProgramData\ZlibDate\` -- Primary staging/exfiltration root
  - `Z84A847FEEB1FC2s\` -- Exfiltration staging
  - `CachedFiles\` -- Downloaded files cache
  - `Settings\` -- Configuration storage
- `C:\ProgramData\Drivers\MicDriver\` -- Audio/screen capture module
  - `Cache\` -- Compressed capture cache
- `C:\ProgramData\Drivers\Whatsapp\` -- Trojanized WhatsApp
  - `WhatssApp.exe` (note double 's')
  - `WebView2Loader.dll`
- `"C:\Windows \SysWOW64\"` -- Spoofed system directory (trailing space after "Windows")
- `"C:\Windows \SysWOW64\bthudtask.exe"` -- DLL staged in spoofed directory
- `%APPDATA%\Config\config.xml` -- RuntimeSSH configuration
- `%APPDATA%\SMQDService\config.xml` -- smqdservice configuration
- `rantom.txt` -- Encrypted Python code (deployed with each variant)
- `chrome_passwords.json` -- Decrypted Chrome credentials dump
- `ChromePasswordsBackup.db` -- Chrome Login Data copy

**Registry Keys:**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SMQDService`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\winappx`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Default_SSH`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicDriver`

### Network

**Command & Control:**

| Indicator | Type | Purpose |
|-----------|------|---------|
| `api[.]telegram[.]org` | Domain | Primary C2 (Telegram Bot API) |
| `ams1[.]vultrobjects[.]com` | Domain | S3 data exfiltration endpoint |
| `sgp1[.]vultrobjects[.]com` | Domain | Malware hosting (Stage 1 download) |
| `micbucket[.]ams1[.]vultrobjects[.]com` | Domain | MicDriver module hosting |
| `api[.]ipify[.]org` | Domain | Victim IP address lookup |

**Cloud Exfiltration Services:**

| Indicator | Type | Purpose |
|-----------|------|---------|
| `vultrobjects[.]com` | Domain | Vultr Object Storage (S3-compatible) |
| `storjshare[.]io` | Domain | Storj decentralized cloud storage |
| `backblazeb2[.]com` | Domain | Backblaze B2 cloud storage |

**Proxy Obfuscation Services:**

| Indicator | Type | Purpose |
|-----------|------|---------|
| `iproyal[.]com` | Domain | Residential proxy service |
| `lightningproxies[.]net` | Domain | Residential proxy service |

**S3 Bucket Identifier:**
- Bucket name substring: `-ppmppnf12uyt4r5tifjdfh-` (seen in VultrObjects PUT requests)

**Embedded Credential:**
- Email: `ghazalehmehrjo[at]gmail[.]com`
- Password: `8384238Fm@#$%^&*`

### Behavioral

- Non-browser processes making POST requests to `api[.]telegram[.]org/bot*/sendDocument`
- Repeated `getUpdates` polling to Telegram Bot API (every 1-3 seconds)
- PowerShell `Add-MpPreference -ExclusionPath` targeting `ZlibDate`, `SMQDServicePackages`, or `MicrosoftDistribution\sysmain`
- File creation in `C:\ProgramData\ZlibDate\Z84A847FEEB1FC2s\` (unique directory identifier)
- Process execution from directory containing a space: `"C:\Windows \SysWOW64\"`
- `.Dat` file accumulation in `C:\ProgramData\ZlibDate\Z84A847FEEB1FC2s\` with prefixes: `SN_`, `LF`, `PL`, `Si`, `IP`, `0Tel`, `1Chr`, `1Edg`, `1Moz`, `OU`, `Z-`
- RAR archives with password `LoLoLoLo` in `C:\ProgramData\Drivers\MicDriver\Cache\`
- Trojanized WhatsApp process (`WhatssApp.exe`) running from `C:\ProgramData\Drivers\Whatsapp\`
- `wmic startup get caption,command` execution

---

## MITRE ATT&CK Mapping

| Technique ID | Name | CHOSEN BRICK Usage |
|-------------|------|-------------------|
| T1566.003 | Phishing: Spearphishing via Service | Social engineering via Telegram, WhatsApp, Instagram |
| T1204.002 | User Execution: Malicious File | Victims execute masquerading installers |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Fake Pictory, KeePass, Telegram, Norton executables; spoofed "C:\Windows \" directory |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | HKCU Run keys for SMQDService, winappx, Default_SSH, MicDriver |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defender exclusion paths via Add-MpPreference |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Defender exclusions, module downloads via Invoke-WebRequest |
| T1059.006 | Command and Scripting Interpreter: Python | Core implant logic in Python (PyInstaller) |
| T1102.002 | Web Service: Bidirectional Communication | Telegram Bot API for C2 |
| T1113 | Screen Capture | Screenshots sent as PNG via Telegram; MicDriver JPEG capture |
| T1123 | Audio Capture | MicDriver records microphone and speaker audio via WASAPI |
| T1114.001 | Email Collection: Local Email Collection | Outlook COM enumeration; Gmail OAuth token theft |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome password decryption via CryptUnprotectData |
| T1005 | Data from Local System | File enumeration, Telegram/WhatsApp data collection |
| T1025 | Data from Removable Media | USB and MTP device data harvesting |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | VultrObjects S3, StorjShare, Backblaze B2 |
| T1041 | Exfiltration Over C2 Channel | Files and data sent via Telegram Bot API |
| T1560.001 | Archive Collected Data: Archive via Utility | ZIP and RAR (password-protected) compression |
| T1057 | Process Discovery | Process list enumeration via psutil |
| T1082 | System Information Discovery | systeminfo command execution |
| T1083 | File and Directory Discovery | Full drive file listing (drives A-K) |
| T1090.002 | Proxy: External Proxy | IPRoyal and LightningProxies residential proxies |
| T1485 | Data Destruction | System wiping capability in some variants |

---

## Impact Assessment

**Severity: HIGH**

- **Confidentiality**: Complete compromise of email, messaging, browser data, files, audio, and screen content. Gmail OAuth tokens provide persistent access beyond device compromise.
- **Integrity**: WhatsApp shortcut hijacking redirects to trojanized binary. System wipe capability threatens data integrity.
- **Physical Safety**: Exfiltrated data has appeared on pro-Iranian leak sites, creating real-world safety risks for dissidents.
- **Scope**: While currently targeted at specific individuals, the modular architecture and commercial cloud infrastructure make CHOSEN BRICK operationally scalable.

The malware has not been observed spreading laterally to other machines, indicating focused targeting rather than mass deployment.

---

## Detection & Remediation

**Detection Priorities:**
1. Search for the specific file hashes listed above across all endpoints
2. Audit `HKCU\...\Run` keys for the four known value names
3. Search for the `ZlibDate` and `SMQDServicePackages` directory names
4. Monitor for non-browser processes connecting to `api.telegram.org`
5. Review Defender exclusion lists for the known staging paths

**Remediation Steps:**
1. Isolate affected systems immediately
2. Preserve forensic images before remediation
3. Remove all Registry Run key entries associated with CHOSEN BRICK
4. Remove Defender exclusion paths added by the malware
5. Delete all malware files and staging directories
6. Revoke and reset all credentials (email, browser-saved passwords, OAuth tokens)
7. Revoke any Google OAuth tokens stored as `.pickle` files
8. Check WhatsApp shortcuts for redirection to `WhatssApp.exe`
9. Scan for the spoofed `"C:\Windows \"` directory (with trailing space)
10. Monitor for re-compromise -- actors may re-target victims through different social engineering

---

## Detection Rules

### Sigma Rules

#### 1. CHOSEN BRICK Registry Run Key Persistence

Detects the four specific Run key value names used by CHOSEN BRICK variants for persistence at user logon. **Confidence: high.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_registry_persistence.yml -->

```yaml
title: CHOSEN BRICK Registry Run Key Persistence
id: 7a3c1e8b-4d2f-4a91-b6e3-9c8d7f2a1b05
status: experimental
description: Detects CHOSEN BRICK/HEAVYGRAM malware persistence via specific Run key value names used by Iranian MOIS actors.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
    selection_values:
        TargetObject|endswith:
            - '\SMQDService'
            - '\winappx'
            - '\Default_SSH'
            - '\MicDriver'
    condition: selection_key and selection_values
falsepositives:
    - Legitimate software using identical value names is unlikely but possible
level: high
```

#### 2. CHOSEN BRICK Defender Exclusion Paths

Detects PowerShell commands adding Microsoft Defender exclusions for CHOSEN BRICK staging directories. **Confidence: high.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_defender_exclusion.yml -->

```yaml
title: CHOSEN BRICK Defender Exclusion Paths
id: 2b4f8c9e-1a3d-4e7b-8f6c-5d2e9a0b3c17
status: experimental
description: Detects PowerShell commands adding Microsoft Defender exclusions for paths associated with CHOSEN BRICK/HEAVYGRAM malware staging directories.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains|all:
            - 'Add-MpPreference'
            - '-ExclusionPath'
    selection_paths:
        CommandLine|contains:
            - 'SMQDServicePackages'
            - 'MicrosoftDistribution\sysmain'
            - 'ZlibDate'
    condition: selection_cmd and selection_paths
falsepositives:
    - Legitimate administrator adding exclusions for identically named directories
level: critical
```

#### 3. CHOSEN BRICK Staging Directory File Creation

Detects file creation in the unique staging directories used by CHOSEN BRICK for exfiltration data accumulation. **Confidence: high.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_file_creation.yml -->

```yaml
title: CHOSEN BRICK Staging Directory File Creation
id: 3e6a9d1c-8b4f-42e7-a5d3-7c0f2e8b1a94
status: experimental
description: Detects file creation in staging directories characteristic of CHOSEN BRICK/HEAVYGRAM malware, including ZlibDate exfiltration folders and MicDriver cache.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\ZlibDate\Z84A847FEEB1FC2s\'
            - '\ZlibDate\CachedFiles\'
            - '\ZlibDate\Settings\'
            - '\Drivers\MicDriver\Cache\'
            - '\SMQDServicePackages\488ht1-8ww648q\'
            - '\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\'
    condition: selection
falsepositives:
    - Very unlikely given the unique directory names
level: critical
```

#### 4. Suspicious Non-Browser Telegram Bot API DNS Query

Detects non-Telegram processes querying `api.telegram.org`. This is a generic TTP-level detector -- any non-Telegram process resolving the Bot API domain is suspicious but not CHOSEN-BRICK-specific. **Confidence: medium.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_telegram_c2.yml -->

```yaml
title: Suspicious Non-Browser Telegram Bot API DNS Query
id: 4f7b0e2d-9c5a-43f8-b6e4-8d1f3a7c2b06
status: experimental
description: Detects non-Telegram processes resolving api.telegram.org via DNS. Multiple malware families including CHOSEN BRICK/HEAVYGRAM abuse the Telegram Bot API for C2.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1102.002
logsource:
    category: dns_query
    product: windows
detection:
    selection_dns:
        QueryName: 'api.telegram.org'
    filter_telegram:
        Image|endswith:
            - '\Telegram.exe'
            - '\Telegram Desktop\Telegram.exe'
    condition: selection_dns and not filter_telegram
falsepositives:
    - Custom scripts or bots legitimately using the Telegram Bot API
level: medium
```

#### 5. CHOSEN BRICK Malicious Process Execution

Detects execution of CHOSEN BRICK binaries from their characteristic installation paths. The binaries masquerade as legitimate Windows service names in crafted directory structures. **Confidence: high.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_suspicious_process.yml -->

```yaml
title: CHOSEN BRICK Malicious Process Execution
id: 5a8c1f3e-0d6b-44a9-c7f5-9e2a4b8d3c18
status: experimental
description: Detects execution of known CHOSEN BRICK/HEAVYGRAM malware binaries from characteristic file paths used by Iranian MOIS actors.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_paths:
        Image|contains:
            - '\SMQDServicePackages\488ht1-8ww648q\smqdservice.exe'
            - '\MicrosoftDistribution\sysmain\winappx.exe'
            - '\ssh-cache-default\{8bda3848-495e-43f4-8d10-7d37a67f1604}\RuntimeSSH.exe'
            - '\Drivers\MicDriver\MicDriver.exe'
            - '\Drivers\Whatsapp\WhatssApp.exe'
    condition: selection_paths
falsepositives:
    - Extremely unlikely given the highly specific paths
level: critical
```

#### 6. CHOSEN BRICK Spoofed Windows Directory

Detects file activity in a spoofed `"C:\Windows \"` directory with a trailing space, used for DLL staging. **Confidence: high.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_spoofed_sysdir.yml -->

```yaml
title: CHOSEN BRICK Spoofed Windows Directory with Trailing Space
id: 6b9d2a4f-1e7c-45b0-d8a6-0f3b5c9e4d29
status: experimental
description: Detects file activity in a spoofed Windows directory containing a trailing space ("C:\Windows \SysWOW64"), a known CHOSEN BRICK technique for DLL staging.
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 'C:\Windows \SysWOW64'
    condition: selection
falsepositives:
    - None known; a space after Windows in the path is inherently suspicious
level: critical
```

#### 7. CHOSEN BRICK Cloud Storage Exfiltration

Detects DNS queries to the specific VultrObjects hostnames observed in the CHOSEN BRICK advisory. Scoped to advisory IOCs rather than generic cloud-storage domains to reduce false positives. **Confidence: medium.**

<!-- audit: sigma check 0 errors, 0 issues; sigma convert splunk OK; file: chosen_brick_cloud_exfil.yml -->

```yaml
title: CHOSEN BRICK Cloud Storage Exfiltration via VultrObjects
id: 7c0e3b5a-2f8d-46c1-e9b7-1a4c6d0f5e30
status: experimental
description: Detects DNS queries to specific VultrObjects hostnames used by CHOSEN BRICK for malware hosting and data exfiltration. Scoped to advisory IOCs (sgp1, ams1, micbucket subdomains).
references:
    - https://www.ic3.gov/CSA/2026/260915.pdf
    - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
author: Actioner
date: 2026-09-16
tags:
    - attack.t1567.002
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName:
            - 'sgp1.vultrobjects.com'
            - 'ams1.vultrobjects.com'
            - 'micbucket.ams1.vultrobjects.com'
    condition: selection
falsepositives:
    - Legitimate use of these specific Vultr Object Storage regions (sgp1, ams1) by applications
level: medium
```

### Sigma: Residential Proxy Connection -- Dropped

Generic commercial proxy DNS detection with no CHOSEN BRICK discriminator; high FP in environments using proxy services for QA/monitoring. IPRoyal and LightningProxies are legitimate services. Retained as a contextual IOC in the network indicators table above.

### YARA Rules

Four YARA rules covering the full CHOSEN BRICK malware family, validated with `yarac`.

<!-- audit: yarac compiled successfully with 0 errors; file: chosen_brick.yar -->

```yara
rule CHOSEN_BRICK_HEAVYGRAM_Implant
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK/HEAVYGRAM persistent implant samples based on unique strings, mutexes, and code patterns from FBI FLASH-20260915"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "8B595258CFF63C4F0EF9648ADB54C6AB050BB1D27933ECB3D687D31B51B7BA0C"
        hash2 = "4A3B003994112B4DD24AC8B9CC4757F4A12576B57B3CC8F5028D85FBCEB7C405"
        hash3 = "0D74156089292EEE308017C8E8A7550739ECB6149FF379810F7C54B1DBAABC91"
        hash4 = "C2DD678511373DC07E73EF1A580FC3332E640F15FF0D4C1044D4B9F305B6F503"

    strings:
        $mutex1 = "euyrsmnszb85sf4444s" ascii wide
        $mutex2 = "nih6723443489kcvrf" ascii wide
        $mutex3 = "ytyjyujyu" ascii wide
        $mutex4 = "noi672pp434awkc12f" ascii wide

        $path1 = "ZlibDate\\Z84A847FEEB1FC2s" ascii wide
        $path2 = "ZlibDate\\Settings\\config.xml" ascii wide
        $path3 = "ZlibDate\\CachedFiles" ascii wide
        $path4 = "SMQDServicePackages\\488ht1-8ww648q" ascii wide
        $path5 = "MicrosoftDistribution\\sysmain" ascii wide
        $path6 = "ssh-cache-default\\{8bda3848-495e-43f4-8d10-7d37a67f1604}" ascii wide

        $cmd1 = "ProcessList" ascii
        $cmd2 = "SendFile" ascii
        $cmd3 = "DefaultTelegram" ascii
        $cmd4 = "AllTelegram" ascii
        $cmd5 = "StoreTelegram" ascii
        $cmd6 = "GetChromeTelWhat" ascii
        $cmd7 = "GetMyWhatSesion" ascii
        $cmd8 = "OutlookExtract" ascii
        $cmd9 = "EnableMic" ascii
        $cmd10 = "SugWhatsapp" ascii
        $cmd11 = "GetChromePass" ascii
        $cmd12 = "ChangeSnapTime" ascii
        $cmd13 = "ChangeVicName" ascii

        $api1 = "api.telegram.org/bot" ascii wide
        $api2 = "vultrobjects.com" ascii wide

        $file1 = "rantom.txt" ascii wide
        $file2 = "chrome_passwords.json" ascii wide
        $file3 = "WhatssApp.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($mutex*) or
            2 of ($path*) or
            4 of ($cmd*) or
            (1 of ($api*) and 1 of ($path*)) or
            (1 of ($file*) and 1 of ($path*))
        )
}

rule CHOSEN_BRICK_MicDriver
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK MicDriver audio/screen surveillance module based on unique namespace strings and file paths"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "168A487F0E44FFEE975ECD27D3F4000C750E711963A61D6CE244FA390DD17441"

    strings:
        $ns1 = "ZoomRecorder" ascii wide
        $ns2 = "getMState4" ascii wide
        $cfg1 = "C:\\ProgramData\\Drivers\\MicDriver\\Cache" ascii wide
        $cfg2 = "C:\\ProgramData\\ZlibDate\\Z84A847FEEB1FC2s\\Records" ascii wide
        $cfg3 = "C:\\ProgramData\\Drivers\\MicDriver" ascii wide
        $rar = "-pLoLoLoLo" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($ns*) and 1 of ($cfg*)) or
            ($rar and 1 of ($cfg*))
        )
}

rule CHOSEN_BRICK_Masquerading_Stage1
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK stage-1 masquerading droppers (Pictory, Telegram Authenticator) compiled with Embarcadero Delphi"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "E8B633DCAD173EB41EF02686B46779A4A0E53DF7F6C63039A798F2DB5EB83AFC"
        hash2 = "9014FE4F16F01C0439B261ADE4CF980F460E0DAE46B1EC5F58FD9BC0AF26E531"

    strings:
        $cred = "ghazalehmehrjo@gmail.com" ascii wide
        $pwd = "8384238Fm@#$%^&*" ascii wide
        $drop1 = "SMQDServicePackages" ascii wide
        $drop2 = "downloaded_file26.txt" ascii wide
        $drop3 = "File26.zip" ascii wide
        $drop4 = "ssh-cache-default" ascii wide
        $drop5 = "Runtime_SSH.zip" ascii wide
        $drop6 = "RuntimeSSH.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $cred or
            $pwd or
            2 of ($drop*)
        )
}

rule CHOSEN_BRICK_MsCache_Gmail
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK MsCache.exe Gmail OAuth token stealer module"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "4908C0BC11A933D83C83935D9468BA8D08BC23529E5FF4D4344D4F0787B84BB6"

    strings:
        $path1 = "C:\\ProgramData\\ZlibDate\\CachedFiles\\" ascii wide
        $path2 = "Google\\Chrome\\Settings\\User Data" ascii wide
        $path3 = "credentials.json" ascii wide
        $scope = "https://mail.google.com/" ascii wide
        $pickle = ".pickle" ascii wide
        $err = "C:\\ProgramData\\ZlibDate\\CachedFiles\\er.txt" ascii wide
        $api = "api.telegram.org" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($path1, $path2, $err)) and
        2 of them
}
```

### Suricata Rules

Seven rules detecting CHOSEN BRICK Telegram C2 and cloud exfiltration traffic patterns.

- **SID 2200001-2200003** (Telegram TTP rules): **Confidence: medium.** These fire on Telegram Bot API usage patterns that are not CHOSEN-BRICK-specific; useful as behavioral correlators.
- **SID 2200004-2200005** (VultrObjects bucket rules): **Confidence: high.** Match advisory-specific bucket name substrings and hostnames.
- **SID 2200006** (getFile): **Confidence: medium.** Generic Telegram Bot API file download detection.
- **SID 2200007** (Chrome passwords via Telegram): **Confidence: high.** Matches `chrome_passwords` in Telegram POST body -- a strong CHOSEN BRICK indicator.

<!-- audit: suricata -T compiled successfully; file: chosen_brick.suricata.rules -->

```
# SID 2200001 - Telegram Bot API sendDocument exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK Telegram Bot API sendDocument Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"/sendDocument"; sid:2200001; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200002 - Telegram Bot API sendPhoto screenshot exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK Telegram Bot API sendPhoto Screenshot Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"/sendPhoto"; sid:2200002; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200003 - Telegram Bot API C2 polling (threshold: 5 in 60s)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK Telegram Bot API C2 Polling getUpdates"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"/getUpdates"; threshold:type both, track by_src, count 5, seconds 60; sid:2200003; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200004 - VultrObjects S3 bucket exfiltration with known substring
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK VultrObjects S3 Exfiltration"; flow:established,to_server; http.host; content:"vultrobjects.com"; http.uri; content:"-ppmppnf12uyt4r5tifjdfh"; sid:2200004; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200005 - MicDriver download from VultrObjects micbucket
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK MicDriver Download from VultrObjects"; flow:established,to_server; http.host; content:"micbucket.ams1.vultrobjects.com"; sid:2200005; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200006 - Telegram Bot API file download (getFile)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK Telegram Bot API File Download getFile"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.uri; content:"/bot"; content:"/getFile"; sid:2200006; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2200007 - Chrome passwords exfiltration via Telegram
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CHOSEN BRICK Chrome Passwords Exfiltration via Telegram"; flow:established,to_server; http.method; content:"POST"; http.host; content:"api.telegram.org"; http.request_body; content:"chrome_passwords"; sid:2200007; rev:1; metadata:created_at 2026_09_16, updated_at 2026_09_16; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)
```

### Snort Rules

Five rules covering the primary CHOSEN BRICK network behaviors. **Confidence: medium-high** (structural check only; no Snort3 compiler available).

> **Note:** SID 2100001-2100005 use `http_header` which matches against the full header block, not just the Host header. This is less precise than the Suricata equivalents that use `http.host`. In high-traffic environments, consider supplementing with Suricata rules for tighter matching. SID 2100003 (getUpdates polling) lacks a threshold, unlike its Suricata counterpart SID 2200003 which applies `count 5, seconds 60`; deployers should add a detection_filter or threshold to avoid alert floods.

<!-- audit: snort3 not available for compilation; structural check only -->

```
# SID 2100001 - Telegram Bot API sendDocument exfiltration [structural check only]
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CHOSEN BRICK Telegram Bot API sendDocument Exfiltration"; flow:established,to_server; content:"POST"; http_method; content:"api.telegram.org"; http_header; content:"/sendDocument"; http_uri; sid:2100001; rev:1; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2100002 - Telegram Bot API sendPhoto screenshot exfiltration [structural check only]
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CHOSEN BRICK Telegram Bot API sendPhoto Screenshot Exfiltration"; flow:established,to_server; content:"POST"; http_method; content:"api.telegram.org"; http_header; content:"/sendPhoto"; http_uri; sid:2100002; rev:1; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2100003 - Telegram Bot API C2 polling [structural check only]
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CHOSEN BRICK Telegram Bot API C2 Polling"; flow:established,to_server; content:"POST"; http_method; content:"api.telegram.org"; http_header; content:"/getUpdates"; http_uri; sid:2100003; rev:1; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2100004 - VultrObjects S3 bucket exfiltration [structural check only]
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CHOSEN BRICK VultrObjects S3 Exfiltration Bucket"; flow:established,to_server; content:"vultrobjects.com"; http_header; content:"-ppmppnf12uyt4r5tifjdfh"; http_uri; sid:2100004; rev:1; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)

# SID 2100005 - MicDriver download from micbucket [structural check only]
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CHOSEN BRICK MicDriver Download from micbucket"; flow:established,to_server; content:"micbucket.ams1.vultrobjects.com"; http_header; sid:2100005; rev:1; reference:url,www.ic3.gov/CSA/2026/260915.pdf; classtype:trojan-activity;)
```

---

## Sources

- [FBI FLASH: Update on Government of Iran Cyber Actors' Deployment of Telegram C2 to Push Malware (FLASH-20260915)](https://www.ic3.gov/CSA/2026/260915.pdf)
- [NCSC: UK and allies expose spyware used by Iranian state actors](https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists)
- [NCSC: Iranian cyber targeting of dissidents, activists and journalists (Advisory)](https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists)
- [The Record: Iranian cyber spies used fake MRI scan results to hack 'enemy of regime'](https://therecord.media/iran-cyber-spies-use-fake-mri-scans-as-lure)
- [The Hacker News: Iranian Hackers Use Telegram-Controlled Malware to Spy on Dissidents and Journalists](https://thehackernews.com/2026/09/iranian-hackers-use-telegram-controlled.html)
- [Infosecurity Magazine: NCSC and Allies Warn of Iranian CHOSEN BRICK Spyware](https://www.infosecurity-magazine.com/news/ncsc-allies-warn-iranian-chosen/)
- [Computer Weekly: UK, US and Netherlands warn over Iranian state spyware campaign](https://www.computerweekly.com/news/366650300/UK-US-and-Netherlands-warn-over-Iranian-state-spyware-campaign)
- [Al Jazeera: UK, US, Netherlands warn of Iranian spyware targeting dissidents](https://www.aljazeera.com/news/2026/9/15/western-intelligence-warns-of-iranian-cyber-threats-targeting-dissidents)
