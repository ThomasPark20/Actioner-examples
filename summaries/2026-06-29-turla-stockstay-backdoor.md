# Technical Analysis Report: Turla STOCKSTAY Backdoor (2026-06-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-29
Version: 1.1 (REVISED)
<!-- revision: v1.1 — Applied critic CONDITIONAL PASS revisions: dropped Sigma 0004 (onrender wildcard FP), dropped all 5 Snort rules (redundant with Suricata sticky-buffer rules), fixed Sigma 0001 ATT&CK tags (t1059->t1204.002), fixed YARA STOCKBROKER condition precedence bug, downgraded Sigma 0002 level to high, removed unused YARA dotnet import, replaced ATT&CK T1001.003 with T1573.002. Final rule count: 4 Sigma, 7 YARA, 0 Snort, 10 Suricata = 21 rules. -->

## Executive Summary

STOCKSTAY is a multi-component .NET backdoor developed and deployed by the Russian state-sponsored threat actor Turla (attributed to FSB Center 16) for espionage operations targeting government and military organizations in Ukraine, with secondary targeting of entities in Italy, the Netherlands, Poland, and Germany. Google Threat Intelligence Group (GTIG) documented the backdoor's continuous development since at least December 2022 through active campaigns in November 2025. STOCKSTAY uses the Windows Forms framework and communicates via secure WebSocket (WSS) connections using the open-source websocket-sharp library. The malware consists of four distinct components -- MARKETMAKER (downloader), STOCKMARKET (orchestrator), STOCKBROKER (proxy-aware tunneler), and STOCKTRADER (main backdoor) -- that communicate via WM_COPYDATA IPC messages. STOCKSTAY shares significant code and functional overlaps with Kazuar, another Turla backdoor, including the K1MORPHER string obfuscation class using the Squirrel3 PRNG algorithm. Delivery mechanisms include phishing with malicious RDP files, MSI installers hosted on GitHub, HTA scripts within RAR archives exploiting CVE-2025-8088 (WinRAR path traversal), and payloads hosted on compromised WordPress instances and Ukrainian government infrastructure. C2 infrastructure leverages legitimate cloud hosting platforms including Glitch.me and Render.com for WebSocket server hosting.

## Background: Targeted Organizations

Turla has deployed STOCKSTAY against Ukrainian government and military organizations as a primary target set, consistent with Russian state intelligence collection priorities related to the Ukraine-Russia conflict. Secondary targets include entities with interests in Italian foreign policy (including the Circolo Degli Esteri foreign affairs organization), and organizations in the Netherlands, Poland, and Germany. Early versions of the backdoor used academic- and diplomatic-themed lures, while later campaigns pivoted to military-themed lures including drone reports and military personnel benefit calculators. The malware was observed co-deployed alongside other Turla tools including KAZUAR, WILDDAY, and DIAMONDBACK, with STOCKSTAY potentially serving as a failsafe in case KAZUAR was detected and remediated.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| December 2022 | Earliest identifiable STOCKSTAY artifact (websocket-sharp.dll compilation timestamp) |
| September 21, 2023 | First observed sample (DriversPrinterGraphic.rar) -- combined monolithic executable uploaded from Germany within 20 minutes of creation |
| December 5-6, 2023 | First component separation observed (Netherlands upload) -- STOCKMARKET, STOCKBROKER, STOCKTRADER split |
| January 2024 | Deployment against Ukrainian organization via malicious GPO from compromised domain controller alongside KAZUAR, WILDDAY, DIAMONDBACK |
| February 20, 2024 | Copia.msi deployed against Italian foreign affairs entity; masqueraded as ILSpy application |
| March 18 - April 2, 2025 | Phishing campaign with malicious RDP files targeting Ukrainian university; MARKETMAKER downloader introduced |
| May 14, 2025 | K1MORPHER obfuscation introduced (Poland-linked samples) |
| May 28 - August 8, 2025 | HTA + RAR archive campaign targeting Ukrainian military via compromised UKR.NET account and IT infrastructure |
| July 23-28, 2025 | GitHub accounts (Roberto1983-ai, ChikenFresh) created for staging MSI installers and C2 controller code |
| August 14, 2025 | C2 server code uploaded to GitHub (google-ai-labs-it repository) |
| November 6-14, 2025 | Drone-themed phishing campaign targeting ~20 Ukrainian military entities via CVE-2025-8088 exploitation |
| June 2026 | GTIG publishes comprehensive STOCKSTAY analysis |

## Root Cause: Multi-Vector Initial Access

Turla employs multiple initial access vectors across STOCKSTAY campaigns:

- **Phishing with Malicious RDP Files (T1566.001)** -- RDP configuration file attachments that establish connections to attacker-controlled infrastructure, enabling STOCKSTAY deployment. Observed in March 2025 campaign targeting Ukrainian universities.
- **CVE-2025-8088 Exploitation (T1203)** -- WinRAR path traversal vulnerability used to extract STOCKSTAY components (LNK files) directly to the Windows startup directory. Exploited in November 2025 campaign via malicious RAR archives.
- **Malicious MSI Installers (T1204.002)** -- Custom MSI files with sequence-1 custom actions that execute before other installer actions. Hosted on GitHub (Roberto1983-ai account). Masqueraded as legitimate software (ILSpy, DiplomacyEduAI).
- **HTA Scripts in RAR Archives (T1204.002)** -- HTML Application files with embedded JavaScript that rename and execute STOCKSTAY.MARKETMAKER. Displayed lure content (military personnel cash benefit calculator) while executing malware.
- **Compromised Infrastructure for Staging (T1584)** -- Payloads hosted on compromised Ukrainian government servers (State Regulatory Service), Ukrainian IT companies, and WordPress instances.

## Technical Analysis of the Malicious Payload

### 1. STOCKSTAY Architecture Overview

STOCKSTAY is a modular .NET backdoor consisting of four components that communicate via WM_COPYDATA IPC messages using serialized JSON with "action" and "container" fields:

| Component | Internal Name | Role | Example Filenames |
|-----------|--------------|------|-------------------|
| STOCKSTAY.MARKETMAKER | N/A | Downloader / initial deployment | MicrosoftUpdateOneDrive.exe, styles.dat.exe |
| STOCKSTAY.STOCKMARKET | "cor" | Configuration parser / orchestrator | StockMarketView.exe, ViewPdf.exe, MSViewer.exe |
| STOCKSTAY.STOCKBROKER | "net" | Proxy-aware WebSocket tunneler | StockMarketNet.exe, SMNet.exe, ClientMNGR.exe, MSDriver.exe |
| STOCKSTAY.STOCKTRADER | "sys" | Main backdoor / information gathering | StockMarketSystem.exe, SMEditor.exe, ConverterDDSNet.exe, MSRender.exe |

### 2. STOCKSTAY.MARKETMAKER (Downloader)

The MARKETMAKER component handles initial deployment:
1. Downloads a ZIP archive from compromised infrastructure (WordPress sites, Ukrainian government servers)
2. Extracts STOCKSTAY core components to the target system
3. Establishes persistence via Registry Run keys (`Software\Microsoft\Windows\CurrentVersion\Run`) or LNK files in the startup directory
4. Contains methods: `CheckAutoRun`, `SetupAutoRun`, `DownloadAndExtractZip`, `GetSystemProxy`

### 3. STOCKSTAY.STOCKMARKET (Orchestrator)

The orchestrator manages component lifecycle and configuration:
- Implements WinForms class `StockMarketViewPage` with timer-based orchestration (`TMR_AppInit_Tick`, `TMR_Engine_Tick`, `TMR_KeepAlive_Tick`, `TMR_PingNet_Tick`, `TMR_PingSystem_Tick`)
- Maintains local SQLite databases with tables: `News` (inbound tasks), `Trade` (outbound results), `Market` (component registration)
- Parses configuration files encrypted with AES using environmental keying (hostname hash, domain name hash, or hardcoded passwords)
- Generates a unique 4096-bit RSA key pair on first execution for encrypting outbound data
- Uses protocol message classes: `ProtocolMessageConnect`, `ProtocolMessageEnd`, `ProtocolMessagePing`, `ProtocolMessageRequestRecv`, `ProtocolMessageRequestSend`, `ProtocolMessageTask`, `ProtocolMessageTaskSysinfo`

### 4. STOCKSTAY.STOCKBROKER (Tunneler)

The proxy-aware tunneler handles network communication:
- Implements WinForms class `SMNetPage`
- Establishes WSS (WebSocket Secure) connections to C2 servers on port 443 using the websocket-sharp library
- Relays encrypted messages between STOCKMARKET and C2 via WM_COPYDATA IPC
- Contains handler `OnGetDataFromServer` and variables `webSocket`, `wmCopyData`, `tempStorage`
- Uses `ProtocolMessageStatusConnection`, `ProtocolMessageResult`, `ProtocolMessageEnd`

### 5. STOCKSTAY.STOCKTRADER (Backdoor)

The main backdoor implements espionage capabilities via WinForms class `SMEditorPage`:

| Command | Description |
|---------|-------------|
| Del | Delete specified files (semicolon-separated paths) |
| Dir | Enumerate directories (optional recursive) |
| Get | Retrieve files by path or extension as Base64-encoded ZIP archive |
| Image | Screen capture |
| MultyTask | Process multiple serialized tasks sequentially |
| Put | Upload file in append mode |
| RegRead | Read registry values |
| RegWrite | Set registry values (with configurable data type) |
| RegDelete | Delete registry values |
| Run | Execute process (windowless, stdout redirected, 60s default timeout) |
| Sysinfo | Collect OS/hardware info via WMI (OSVersion, Architecture, SerialNumber, ProcessorName, MemoryCapacity, running processes) |
| UnpackArchive | Extract ZIP to current directory |
| MkDir / RmDir | Create / remove directories |

### 6. C2 Communication Protocol

**WebSocket C2 Architecture:**
- Protocol: WSS (WebSocket Secure) on port 443 with `/ws` path
- Server framework: Tornado WebSocket (Python)
- `check_origin()` hardcoded to return `True`
- Server-side database: SQLite3 (`weather_data1.db`) with `weather_data` table (columns: degrees/target UUID, pressure/sender UUID, wdata/encrypted message, coords/IP, status, datetime)

**Message Format:**
```
Outbound: {"action": "send|recv", "container": {"target": "<internal_id>", "sender": "<client_uuid>", "message": "<CryptoContainer>"}}
Inbound: {"target": "<uuid>", "sender": "<uuid>", "message": "<CryptoContainer>", "ip": "<ip_or_none_ip>", "time": "<datetime>"}
```

**Encryption:** RSA-4096 for outbound data encryption (public key sent to server on first connection); AES (`AesCryptoServiceProvider`) for configuration files; `Windows-1251` encoding throughout (Cyrillic support).

### 7. K1MORPHER Obfuscation

Introduced in May 2025, K1MORPHER is a .NET obfuscation class (`K1.Morpher`) using the Squirrel3 PRNG algorithm for string encryption. Methods include `DecryptArraySimple`, `DecryptIntSimple`, `DecryptLongSimple`, `DecryptFloatSimple`, `DecryptStringSimple`, `DecryptDoubleSimple`. This same obfuscation class was later observed in Kazuar samples (June 2025), providing a strong attribution link between STOCKSTAY and Turla's broader tooling.

### 8. Environmental Keying Evolution

| Period | Keying Method |
|--------|--------------|
| December 2023 - January 2024 | Hash of target's hostname (lowercase) |
| February 2024 onwards | Hash of target's domain name |
| March-April 2025 | Hard-coded passwords (initial access operations) |

### 9. Operational Patterns

- **Working hours:** Monday-Friday 09:00-18:00 (victim local time) -- hardcoded in configuration
- **Staging timeline:** Components prepared 4-6 hours before phishing delivery
- **Masquerading:** Stock market applications (early), PDF readers, calculators, Microsoft update tools (later)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation. Domains: `[.]` replacing dots. URLs: `hxxps://` replacing `https://`.

### File System -- Core Components

| Component | Filename | SHA-256 |
|-----------|----------|---------|
| Combined (early) | StockMarketNews.exe | `1fc23ec18a94a599a34c74ef5f49a1e27acd37a07d5846661702b5e7e81a6a24` |
| STOCKMARKET | StockMarketView.exe | `9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec` |
| STOCKBROKER | StockMarketNet.exe | `34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b` |
| STOCKTRADER | StockMarketSystem.exe | `0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b` |
| STOCKMARKET | StockMarketView.exe | `82707cfdf24dcb762f4615f01e1ba4d3dfdec4abe9cd588558d2634d7e6a5eeb` |
| STOCKBROKER | StockMarketNet.exe | `249a4c7cacdd8e99a2a089a5c0ce904f2eff22e0e40fcfb10f7824dca6c51ecb` |
| STOCKTRADER | StockMarketSystem.exe | `b728eba4f0d6d16602fbad05a591f14391594262d3584b2e249e97f86e4dcc5a` |
| MARKETMAKER | MicrosoftUpdateOneDrive.exe | `da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40` |
| STOCKTRADER | SMEditor.exe | `e1d16fb635060d23e889b0617d77f0cf06d00cc19b43a2c8b5ac53ac027ac722` |
| STOCKBROKER | SMNet.exe | `dfd5cb91d06b9649d4cab500343af80ad1144a9e46641cc406f43dd169003c22` |
| STOCKMARKET | StockMarketView.exe | `2af7b513c05e76d7da5f75bb0a223c894a706c99ef2c2ddfe4eae542f95a08e0` |
| STOCKBROKER | ClientMNGR2.exe | `d3fd32f915c239872c9e7ed9408b1f36dfcef03aa68f9a396d05c437667cdb43` |
| STOCKBROKER | GR3.exe | `98ce3c6e4dd05887ea619f2bbfeb2e2c2805ed07e85e119b79b828b7ef8be397` |
| STOCKTRADER | ConverterDDSNet.exe | `55249f296b63a8bcf918b8bc96de43c1ac2b4a56c150a19d33d892a47e57352c` |
| STOCKBROKER | ClientMNGR.exe | `80f6c010fd260d0bcf18a4b6a8d62505adbed50d2e615ed9522c4bfd61c00661` |
| STOCKMARKET | ViewPdf.exe | `45bb8d1ab2c13bf4354294e13d3c9be15de625d807301905b98462f43f93e893` |
| STOCKTRADER | ConverterDDSNet.exe | `d8fe8f3fe838d5b1a1043096f6f6bb6f524f5f1b0c9f83a081078a824daa0cf3` |
| STOCKMARKET | MSViewer.exe | `a40bf9c75d1bfa6d66f1179f2321de6589f80d3089d992797a9cb0e84f6196ce` |
| STOCKMARKET | MSViewer.exe | `e316b1e13154dc6115e1e0c023f6fe3d17861cae839d4a4a81779b6aad9a24f8` |
| STOCKBROKER | MSDriver.exe | `c905cb512018cc55512c6a22677c3d6f389c47afd54d7c85797868fc4fcb90e9` |
| STOCKTRADER | MSRender.exe | `667a8f568a611f2f3d84a366b7946b360e055bece9699c95aad619637ab72a38` |
| websocket-sharp.dll | websocket-sharp.dll | `d1e54270433a94aa3d45d888e4c62299bee3480eb2cb4a5489c7dda69d476c3e` |

### File System -- Configuration Files

| Filename | SHA-256 |
|----------|---------|
| sample.conf | `1a2ca8b8e0344fe3d80da7352206a470245443e2349a237bc093df934ddc011f` |
| default.conf | `2623c6e3c1f5a7b5e735a64813bc0e1382ae45831f5fadffb08c0e7b096627f7` |
| default.conf | `40b1208dda0cd5dd95c6b57764b2cfe7145b3ed9457f498408b4aaa05bf3ef50` |
| fonts | `40a3b969d81ef1ef35dd9ebcc6774e060b1b8949d3d74f38ca6b7d789c95cdb3` |
| fonts | `e3364ee21cae6725451e8bc9ab9933df0000fd19814170bd132da68d1906d5ff` |
| fonts | `e83f274bf9914c6cfc0c6b3cdadf089565f49dace4aca93287c22aba9641c8f3` |
| fonts | `f964353b9ae4bedbe62de6c0d7eafa9fb8b87897bbaea483aedaa8ae191834da` |

### File System -- Delivery / Archive Files

| Filename | SHA-256 |
|----------|---------|
| DriversPrinterGraphic.rar | `e6d8192960a89d5480868b94088cccdaa1560f9c8a0b0282ced2b7c1f72341b6` |
| apps_libwallets_v1.3.rar | `81aabf646619ea5f4a72457cd3aa17c5988003d67e6454f45e7cb33613021bac` |
| Copia.msi | `b064a3efb04ed77e6c57955089ce639e193d166c8ea2216c98c3e9b701ea2cff` |
| docs.zip | `9fe944147c15a87963b06baf6473288d64c23655a0ba9369c35566272d8efc73` |
| calculator.rar | `6da0b4c1a5d0d3fb6e6a2990a82ba51db1f68a3bba818baa46526a29731e2342` |
| EditorToolsPdf.zip | `447f430b46fad5a3f8e8c5aad1f8f7f79af069489c3d9c29224bb9f14f0c7bf4` |
| DiplomacyEduAI.msi | `19e6ed42248f9d03beb343a7c09a864dcd3cd671c29e1e5eac93579225224ac9` |
| DiplomacyEduAI.msi | `6298f3150ad94a242e649886d47c59c634a4d04b9af5ee15e3bf335c40b5e58e` |

### File System -- Lure and Phishing Components

| Filename | SHA-256 |
|----------|---------|
| Kalculator hroshovoho zabezpechennia (military calculator HTA) | `0d6b083208097d5b3e189891338540f6c64faaaaf268b0bb0b085dd53d5857b4` |
| styles.dat.exe | `626330d22f77d9cbca9d40cc06568041703f194610c4c5a84bbb05a2e4ee7459` |
| MSViewer.lnk | `3627f582420ad2782d452fe6d13fae42658d1484296351d3916703e25dcadd14` |
| MSRender.lnk | `77417df21b4b4e8d86b8bda4afeef93df36f355362586b2d1f51121a82244167` |
| MSDriver.lnk | `813c78b5b6ed28a9c0ed35f2c6cd88fc50880ab91f8777dfe7aaccb1c24b08d5` |

### File System -- Supporting Libraries

| Filename | SHA-256 |
|----------|---------|
| ms-lib-math-core.dll | `b287347a5bff8af360ce0e6500c336b6fe6d97920abc26202c9d843ffebc5f89` |
| ms-api-wmcpdt.dll | `e2a0f4440f67998a0215d49be31746ea192bfcb4dc4ee532a218f8cf13605714` |

### File System -- C2 Server Code (GitHub-hosted)

| Filename | SHA-256 |
|----------|---------|
| server.py | `f04f43b6f7c2d86109c495179b497f7fb45fd95816623de1b77900f71b4f99ed` |
| models.py | `7615140f78d9a0ce31cc9fe8c54c60028a7439cb32526fd97b10afef7145dd78` |
| wtools.py | `b55f3b8a7334af049ba3f70a9ad3fe78574b1e180c68baf9a7110d104387a636` |

### Network -- C2 Infrastructure

| Type | Value | Context |
|------|-------|---------|
| C2 URL | wss://wool-basalt-clock[.]glitch[.]me/ws | Early C2 (Jan-Feb 2024, Ukraine + Italy) |
| C2 URL | wss://weatherdataai[.]theworkpc[.]com/ws | March-April 2025 campaign (Ukraine) |
| C2 URL | wss://canal1zac1a[.]onrender[.]com/ws | May-Aug 2025 campaign (Ukraine) |
| C2 URL | wss://google-ai-labs-it[.]onrender[.]com/ws | Aug 2025+ (GitHub-linked C2) |
| C2 URL | wss://driverx86-adobe[.]onrender[.]com/ws | Nov 2025 campaign (Ukraine military) |
| Domain | wool-basalt-clock[.]glitch[.]me | Glitch platform C2 hosting |
| Domain | weatherdataai[.]theworkpc[.]com | Custom domain C2 |
| Domain | canal1zac1a[.]onrender[.]com | Render platform C2 |
| Domain | google-ai-labs-it[.]onrender[.]com | Render platform C2 |
| Domain | driverx86-adobe[.]onrender[.]com | Render platform C2 |

### Network -- Compromised Infrastructure (Payload Staging)

| Type | Value | Context |
|------|-------|---------|
| URL | hxxps://www[.]drs[.]gov[.]ua/wp-content/themes/twentytwentyfive/docs.zip | State Regulatory Service of Ukraine |
| URL | hxxps://basecon[.]com[.]ua/calculator.rar | Ukrainian IT company |
| URL | hxxps://online[.]zp[.]ua/wp-content/uploads/Tools/EditorToolsPdf.zip | Compromised WordPress (Ukraine) |

### Network -- GitHub Infrastructure

| Type | Value | Context |
|------|-------|---------|
| GitHub Account | Roberto1983-ai | Created July 23, 2025 -- hosted DiplomacyEduAI.msi |
| GitHub Repo | Roberto1983-ai/msi_installer_test2 | Created July 24, 2025 |
| GitHub Repo | Roberto1983-ai/msi_installer_test3 | Created July 28, 2025 |
| GitHub Account | ChikenFresh | Created August 14, 2025 -- hosted C2 controller code |
| GitHub Repo | ChikenFresh/google-ai-labs-it | C2 server code (server.py, models.py, wtools.py) |

### Registry

| Key | Value | Context |
|-----|-------|---------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Path to STOCKSTAY.MARKETMAKER executable (e.g., MicrosoftUpdateOneDrive) | Persistence mechanism |

### File Paths

| Path | Context |
|------|---------|
| `%LOCALAPPDATA%\Programs\SMN\` | Default STOCKSTAY installation directory |
| `calculator_2025_files\` | HTA lure working directory |

### Behavioral

**Process chain:** MARKETMAKER downloads ZIP from compromised infrastructure, extracts STOCKMARKET/STOCKBROKER/STOCKTRADER, sets registry/startup persistence. STOCKMARKET orchestrates via timers, STOCKBROKER establishes WSS C2, STOCKTRADER executes espionage tasks. All inter-component communication via WM_COPYDATA IPC.

**WinForms window names:** `StockMarketViewPage`, `SMNetPage`, `SMEditorPage`, `window_system32_x128`, `window_system32_x64`, `window_system32_x32`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious RDP configuration files and HTA scripts as email attachments |
| T1566.002 | Phishing: Spearphishing Link | UKR.NET file sharing links to malicious RAR archives |
| T1203 | Exploitation for Client Execution | CVE-2025-8088 (WinRAR path traversal) for LNK extraction to startup |
| T1204.002 | User Execution: Malicious File | RDP files, MSI installers, HTA scripts requiring user interaction |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | MARKETMAKER sets Run key entries for STOCKSTAY persistence |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | LNK files extracted to startup directory (November 2025) |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Filenames mimicking PDF viewers, calculators, Microsoft updates |
| T1027 | Obfuscated Files or Information | K1MORPHER string obfuscation, junk code insertion |
| T1140 | Deobfuscate/Decode Files or Information | Runtime deobfuscation via Squirrel3 PRNG |
| T1071.001 | Application Layer Protocol: Web Protocols | WebSocket (WSS) C2 over port 443 |
| T1090.001 | Proxy: Internal Proxy | STOCKBROKER acts as proxy-aware tunneler between C2 and orchestrator |
| T1132.001 | Data Encoding: Standard Encoding | Base64 encoding of C2 messages |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | CryptoContainer format with RSA-4096 + AES encryption |
| T1082 | System Information Discovery | Sysinfo command collects OS/hardware details via WMI |
| T1083 | File and Directory Discovery | Dir command for directory enumeration |
| T1113 | Screen Capture | Image command for screenshots |
| T1005 | Data from Local System | Get command for file collection as ZIP archives |
| T1041 | Exfiltration Over C2 Channel | All exfiltration via encrypted WSS C2 channel |

## Impact Assessment

STOCKSTAY represents a significant, persistent espionage threat from Russia's FSB-attributed Turla group. The backdoor's three-year continuous development (December 2022 to present), multi-component architecture, environmental keying, and progressive adoption of obfuscation (K1MORPHER) demonstrate sustained investment in this capability. The operational targeting of Ukrainian government and military organizations during active conflict makes this a high-priority intelligence collection tool. The shared K1MORPHER codebase with Kazuar indicates Turla's active consolidation of tooling, with STOCKSTAY potentially serving as a redundant access path. The use of legitimate cloud platforms (Glitch, Render) for C2 hosting complicates network-based blocking. The approximately 30% email open rate observed in the November 2025 campaign against Ukrainian military targets demonstrates continued effectiveness of social engineering.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for STOCKSTAY registry persistence
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null | findstr /i "MicrosoftUpdate StockMarket ViewPdf MSViewer ConverterDDS"

# Check for STOCKSTAY component files
Get-ChildItem -Path "$env:LOCALAPPDATA","$env:APPDATA","C:\ProgramData" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "StockMarket|SMEditor|SMNet|ViewPdf|MSViewer|MSDriver|MSRender|ClientMNGR|ConverterDDS|websocket-sharp" }

# Check for STOCKSTAY default installation directory
Test-Path "$env:LOCALAPPDATA\Programs\SMN\"

# Check DNS cache for C2 domains
Get-DnsClientCache | Where-Object { $_.Entry -match "onrender\.com|glitch\.me|theworkpc\.com" }

# Check for LNK files with STOCKSTAY names in startup
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Filter "*.lnk" | Where-Object { $_.Name -match "MSViewer|MSDriver|MSRender" }
```

### Remediation

1. **Contain:** Isolate affected hosts; block all C2 domains at DNS/proxy (wool-basalt-clock[.]glitch[.]me, weatherdataai[.]theworkpc[.]com, canal1zac1a[.]onrender[.]com, google-ai-labs-it[.]onrender[.]com, driverx86-adobe[.]onrender[.]com)
2. **Eradicate:** Remove Registry Run key entries; delete LNK files from startup; remove all STOCKSTAY components from `%LOCALAPPDATA%\Programs\SMN\` and other deployment directories; remove websocket-sharp.dll
3. **Credential Reset:** Assume full compromise of any accessed credentials; reset domain credentials; review for lateral movement indicators
4. **Patch:** Apply WinRAR patches for CVE-2025-8088; review RDP configuration policies
5. **Hunt:** Search for other Turla tools (KAZUAR, WILDDAY, DIAMONDBACK) on any host where STOCKSTAY is found -- co-deployment is documented

### Long-Term Hardening

- Block outbound WebSocket connections to cloud hosting platforms (onrender.com, glitch.me) at the proxy if not business-required
- Deploy application allowlisting to prevent unauthorized .NET executable execution
- Enable Sysmon with configuration covering process creation (EID 1), image loads (EID 7), registry events (EID 13), DNS queries (EID 22), and network connections (EID 3)
- Monitor for WM_COPYDATA IPC patterns between multiple suspicious processes
- Implement email gateway filtering for RDP file attachments and HTA files within archives
- Block RDP file execution via Group Policy or WDAC

## Detection Rules

These detections target STOCKSTAY backdoor component execution, registry persistence, C2 infrastructure, WebSocket communication, and .NET assembly artifacts. 21 rules total: 4 Sigma, 7 YARA, 10 Suricata. PoC/advisory-specific altitude; all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles clean does not mean fires clean -- verify rules in your pipeline with representative telemetry.

### Sigma: STOCKSTAY Backdoor Component Process Execution
Detects execution of known STOCKSTAY backdoor component filenames across all documented campaigns.
**Status:** compile pass (splunk + log_scale convert exit 0) -- confidence: high
<!-- audit: sigma check failed due to MITRE STIX download timeout (network issue, not rule issue). splunk convert exit 0; log_scale convert exit 0. Fields: Image (process_creation/windows) -- standard Sysmon/4688 field, no encoding concerns. Non-defanged paths in detection values. -->
<!-- revision: Removed attack.t1059 tag (process filename detection does not equal scripting interpreter use). Added attack.t1204.002 (User Execution: Malicious File) which better reflects the detection context. -->
```yaml
title: STOCKSTAY Backdoor Component Process Execution
id: a1b2c3d4-1111-4aaa-bbbb-000000000001
status: experimental
description: >
    Detects execution of known STOCKSTAY backdoor component filenames used by
    Turla APT for espionage operations against Ukrainian government and military
    targets. STOCKSTAY uses multiple executable names across campaigns including
    stock market themed names, PDF viewer names, and Microsoft impersonation names.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering
    - https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html
author: Actioner
date: 2026/06/29
tags:
    - attack.t1036.005
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\StockMarketView.exe'
            - '\StockMarketNet.exe'
            - '\StockMarketSystem.exe'
            - '\StockMarketNews.exe'
            - '\SMEditor.exe'
            - '\SMNet.exe'
            - '\ViewPdf.exe'
            - '\ClientMNGR.exe'
            - '\ClientMNGR2.exe'
            - '\GR3.exe'
            - '\ConverterDDSNet.exe'
            - '\MSViewer.exe'
            - '\MSDriver.exe'
            - '\MSRender.exe'
            - '\MicrosoftUpdateOneDrive.exe'
    condition: selection
falsepositives:
    - Legitimate stock market software using identical filenames (unlikely)
level: high
```

### Sigma: STOCKSTAY MARKETMAKER Registry Run Key Persistence
Detects STOCKSTAY.MARKETMAKER establishing persistence via registry Run keys pointing to known component executables.
**Status:** compile pass (splunk + log_scale convert exit 0) -- confidence: high
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. TargetObject + Details (registry_set/windows) -- standard Sysmon EID 13 fields. -->
<!-- revision: Downgraded level from critical to high -- registry Run key persistence with generic-ish filenames warrants high but not critical severity. -->
```yaml
title: STOCKSTAY MARKETMAKER Registry Run Key Persistence
id: a1b2c3d4-2222-4aaa-bbbb-000000000002
status: experimental
description: >
    Detects STOCKSTAY.MARKETMAKER establishing persistence via registry Run keys
    pointing to known STOCKSTAY component executables. The MARKETMAKER downloader
    sets autorun entries under HKCU Run to ensure STOCKSTAY components execute on
    user logon.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering
    - https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html
author: Actioner
date: 2026/06/29
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
    selection_value:
        Details|endswith:
            - '\StockMarketView.exe'
            - '\SMEditor.exe'
            - '\ViewPdf.exe'
            - '\MSViewer.exe'
            - '\MicrosoftUpdateOneDrive.exe'
            - '\ConverterDDSNet.exe'
    condition: selection_key and selection_value
falsepositives:
    - Unlikely in production environments
level: high
```

### Sigma: STOCKSTAY C2 DNS Query to Known Infrastructure
Detects DNS queries to known STOCKSTAY C2 domains hosted on Glitch, Render, and custom domains.
**Status:** compile pass (splunk + log_scale convert exit 0) -- confidence: critical
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. QueryName (dns_query) -- standard Sysmon EID 22 field. IOC-exact match, extremely low FP. -->
```yaml
title: STOCKSTAY C2 DNS Query to Known Infrastructure
id: a1b2c3d4-3333-4aaa-bbbb-000000000003
status: experimental
description: >
    Detects DNS queries to known STOCKSTAY C2 infrastructure hosted on Render
    and Glitch platforms. Turla uses legitimate cloud hosting services for
    WebSocket-based C2 communication.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering
    - https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html
author: Actioner
date: 2026/06/29
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - 'wool-basalt-clock.glitch.me'
            - 'weatherdataai.theworkpc.com'
            - 'canal1zac1a.onrender.com'
            - 'google-ai-labs-it.onrender.com'
            - 'driverx86-adobe.onrender.com'
    condition: selection
falsepositives:
    - Legitimate access to these specific subdomains (extremely unlikely)
level: critical
```

<!-- revision: DROPPED Sigma Rule 0004 (Suspicious DNS Query to Onrender Subdomain) per review — fires on ANY *.onrender.com causing massive FP; already covered by Rule 0003's specific C2 subdomain matches. -->

### Sigma: STOCKSTAY WebSocket Sharp DLL Load by Suspicious Process
Detects loading of websocket-sharp.dll by processes matching known STOCKSTAY component names.
**Status:** compile pass (splunk + log_scale convert exit 0) -- confidence: high
<!-- audit: sigma check failed (STIX network timeout). splunk/log_scale convert exit 0. ImageLoaded + Image (image_load/windows) -- standard Sysmon EID 7 fields. -->
```yaml
title: STOCKSTAY WebSocket Sharp DLL Load by Suspicious Process
id: a1b2c3d4-5555-4aaa-bbbb-000000000005
status: experimental
description: >
    Detects loading of the websocket-sharp.dll library by processes matching
    known STOCKSTAY component names. STOCKSTAY.STOCKBROKER uses the open-source
    websocket-sharp library for WebSocket C2 communication.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering
    - https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html
author: Actioner
date: 2026/06/29
tags:
    - attack.t1071.001
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith: '\websocket-sharp.dll'
    selection_process:
        Image|endswith:
            - '\StockMarketNet.exe'
            - '\SMNet.exe'
            - '\ClientMNGR.exe'
            - '\ClientMNGR2.exe'
            - '\GR3.exe'
            - '\MSDriver.exe'
    condition: selection_dll and selection_process
falsepositives:
    - Legitimate .NET applications using websocket-sharp with matching filenames (unlikely)
level: high
```

### YARA: STOCKSTAY Component Detection (7 rules)
Suite of YARA rules detecting STOCKSTAY.STOCKTRADER backdoor, STOCKSTAY.STOCKMARKET orchestrator, STOCKSTAY.STOCKBROKER tunneler, STOCKSTAY.MARKETMAKER downloader, CryptoContainer parsing code, K1MORPHER obfuscation, and plaintext configuration files.
**Status:** compile pass (yarac exit 0) -- confidence: high
<!-- audit: yarac /dev/null exit 0. 7 rules in single file. All use PE header check + .NET-specific strings. -->
<!-- revision: Removed unused import "dotnet" declaration -- adds scan overhead and breaks builds without the dotnet module compiled in. No rule in this file references dotnet module features. Fixed STOCKBROKER_Tunneler condition operator precedence bug (or branch was bypassing MZ+filesize checks). -->
```yara
rule APT_Turla_STOCKSTAY_STOCKTRADER_Backdoor
{
    meta:
        description = "Detects STOCKSTAY.STOCKTRADER backdoor component based on known command handler class names"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $cmd_1 = "AppDel" ascii
        $cmd_2 = "AppDeleteRegistryValue" ascii
        $cmd_3 = "AppDir" ascii
        $cmd_4 = "AppGet" ascii
        $cmd_5 = "AppMkdir" ascii
        $cmd_6 = "AppPut" ascii
        $cmd_7 = "AppReadRegistryValue" ascii
        $cmd_8 = "AppRegistryKeyExists" ascii
        $cmd_9 = "AppRmdir" ascii
        $cmd_10 = "AppRun" ascii
        $cmd_11 = "AppWriteRegistryValue" ascii
        $cmd_12 = "AppUnpackArchive" ascii
        $cmd_13 = "ArchiveFiles" ascii
        $cmd_14 = "GetFiles" ascii

        $class_1 = "SMEditorPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (10 of ($cmd*) or ($class_1 and 5 of ($cmd*)))
}

rule APT_Turla_STOCKSTAY_STOCKMARKET_Orchestrator
{
    meta:
        description = "Detects STOCKSTAY.STOCKMARKET orchestrator component based on protocol message classes and timer methods"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $proto_1 = "ProtocolMessageConnect" ascii
        $proto_2 = "ProtocolMessageEnd" ascii
        $proto_3 = "ProtocolMessagePing" ascii
        $proto_4 = "ProtocolMessageRequestRecv" ascii
        $proto_5 = "ProtocolMessageRequestSend" ascii
        $proto_6 = "ProtocolMessageTask" ascii
        $proto_7 = "ProtocolMessageTaskSysinfo" ascii

        $tmr_1 = "TMR_AppInit_Tick" ascii
        $tmr_2 = "TMR_Engine_Tick" ascii
        $tmr_3 = "TMR_KeepAlive_Tick" ascii
        $tmr_4 = "TMR_PingNet_Tick" ascii
        $tmr_5 = "TMR_PingSystem_Tick" ascii

        $sql_1 = "CREATE TABLE IF NOT EXISTS News (" wide
        $sql_2 = "CREATE TABLE IF NOT EXISTS Trade (" wide
        $sql_3 = "CREATE TABLE IF NOT EXISTS Market (" wide

        $class_1 = "StockMarketViewPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (5 of ($proto*) or (3 of ($tmr*) and 1 of ($sql*)) or ($class_1 and 3 of ($proto*)))
}

rule APT_Turla_STOCKSTAY_STOCKBROKER_Tunneler
{
    meta:
        description = "Detects STOCKSTAY.STOCKBROKER tunneler component based on IPC message handler and WebSocket variable names"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $s1 = "_CorExeMain" ascii
        $s2 = "ProtocolMessageStatusConnection" ascii
        $s3 = "ProtocolMessageResult" ascii
        $s4 = "ProtocolMessageEnd" ascii
        $s5 = "OnGetDataFromServer" ascii
        $s6 = "webSocket" ascii
        $s7 = "wmCopyData" ascii
        $s8 = "tempStorage" ascii

        $class_1 = "SMNetPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (($s1 and 5 of ($s*)) or ($class_1 and 3 of ($s*)))
}

rule APT_Turla_STOCKSTAY_CryptoContainer
{
    meta:
        description = "Detects STOCKSTAY CryptoContainer parsing code used for encrypted C2 communication with RSA and AES"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "82707cfdf24dcb762f4615f01e1ba4d3dfdec4abe9cd588558d2634d7e6a5eeb"
        tlp = "WHITE"
        severity = "high"

    strings:
        $s1 = "BuildCryptoContainer" ascii
        $s2 = "ParseCryptoContainer" ascii
        $s3 = "Windows-1251" wide
        $s4 = "AesCryptoServiceProvider" ascii
        $s5 = "RSACryptoServiceProvider" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule APT_Turla_STOCKSTAY_MARKETMAKER_Downloader
{
    meta:
        description = "Detects STOCKSTAY.MARKETMAKER downloader based on method names and payload filenames used for initial deployment"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $f1 = "CheckAutoRun" ascii
        $f2 = "SetupAutoRun" ascii
        $f3 = "DownloadAndExtractZip" ascii
        $f4 = "GetSystemProxy" ascii

        $s0 = "_CorExeMain" ascii
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "StockMarketView.exe" wide
        $s3 = "SMNet.exe" wide
        $s4 = "SMEditor.exe" wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($f*) and $s0 and 2 of ($s*)
}

rule APT_Turla_STOCKSTAY_K1MORPHER_Obfuscation
{
    meta:
        description = "Detects K1.Morpher obfuscation class used by STOCKSTAY and Kazuar backdoors for string encryption via Squirrel3 PRNG"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "45bb8d1ab2c13bf4354294e13d3c9be15de625d807301905b98462f43f93e893"
        tlp = "WHITE"
        severity = "high"

    strings:
        $api_1 = "Squirrel3" ascii
        $api_2 = "DecryptArraySimple" ascii
        $api_3 = "DecryptIntSimple" ascii
        $api_4 = "DecryptLongSimple" ascii
        $api_5 = "DecryptFloatSimple" ascii
        $api_6 = "DecryptStringSimple" ascii
        $api_7 = "DecryptDoubleSimple" ascii
        $api_8 = "_squ_ui1" ascii
        $api_9 = "_squ_ui2" ascii
        $api_10 = "_squ_ui3" ascii
        $api_11 = "InjectedSeedCipher" ascii

    condition:
        uint16(0) == 0x5A4D and
        5 of ($api*)
}

rule APT_Turla_STOCKSTAY_Config_Plaintext
{
    meta:
        description = "Detects plaintext STOCKSTAY configuration files containing internal IDs, service endpoints, and operational parameters"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        tlp = "WHITE"
        severity = "high"

    strings:
        $id1 = "\"internal_id\"" ascii
        $id2 = "\"i_id\"" ascii
        $key1 = "\"internal_key\"" ascii
        $key2 = "\"i_k\"" ascii
        $eng1 = "\"interval_engine\"" ascii
        $eng2 = "\"ie\"" ascii
        $srv1 = "\"service\"" ascii
        $srv2 = "\"srv\"" ascii
        $dnw1 = "\"days_not_work\"" ascii
        $dnw2 = "\"dnw\"" ascii
        $sp1 = "\"system_properties\"" ascii
        $sp2 = "\"sp\"" ascii

    condition:
        filesize < 100KB and
        any of ($id*) and
        any of ($key*) and
        any of ($eng*) and
        any of ($srv*) and
        any of ($dnw*) and
        any of ($sp*)
}
```

<!-- revision: DROPPED all 5 Snort rules (SID 2100101-2100105) per review — redundant with superior Suricata rules that use protocol-aware dns.query and tls.sni sticky buffers. Raw TCP content matching on port 443 is unreliable for TLS 1.3 where SNI may be encrypted. The Suricata rules below provide equivalent or better coverage. -->

### Suricata: STOCKSTAY C2 DNS and TLS Indicators (10 rules)
Detects DNS queries and TLS SNI matches for all known STOCKSTAY C2 domains using Suricata's dns.query and tls.sni sticky buffers.
**Status:** compile pass (suricata -T exit 0) -- confidence: critical
<!-- audit: suricata -T -S rules -l /tmp exit 0. Uses dns.query and tls.sni dot-notation sticky buffers. All 10 rules validated. -->
```
alert dns $HOME_NET any -> any any (msg:"Actioner - STOCKSTAY C2 DNS Query to wool-basalt-clock.glitch.me"; flow:to_server; dns.query; content:"wool-basalt-clock.glitch.me"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100201; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - STOCKSTAY C2 DNS Query to weatherdataai.theworkpc.com"; flow:to_server; dns.query; content:"weatherdataai.theworkpc.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100202; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - STOCKSTAY C2 DNS Query to canal1zac1a.onrender.com"; flow:to_server; dns.query; content:"canal1zac1a.onrender.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100203; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - STOCKSTAY C2 DNS Query to google-ai-labs-it.onrender.com"; flow:to_server; dns.query; content:"google-ai-labs-it.onrender.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100204; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - STOCKSTAY C2 DNS Query to driverx86-adobe.onrender.com"; flow:to_server; dns.query; content:"driverx86-adobe.onrender.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100205; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - STOCKSTAY C2 TLS SNI to wool-basalt-clock.glitch.me"; flow:established,to_server; tls.sni; content:"wool-basalt-clock.glitch.me"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100206; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - STOCKSTAY C2 TLS SNI to canal1zac1a.onrender.com"; flow:established,to_server; tls.sni; content:"canal1zac1a.onrender.com"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100207; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - STOCKSTAY C2 TLS SNI to google-ai-labs-it.onrender.com"; flow:established,to_server; tls.sni; content:"google-ai-labs-it.onrender.com"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100208; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - STOCKSTAY C2 TLS SNI to driverx86-adobe.onrender.com"; flow:established,to_server; tls.sni; content:"driverx86-adobe.onrender.com"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100209; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - STOCKSTAY C2 TLS SNI to weatherdataai.theworkpc.com"; flow:established,to_server; tls.sni; content:"weatherdataai.theworkpc.com"; fast_pattern; classtype:trojan-activity; reference:url,cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering; metadata:author Actioner, created_at 2026-06-29; sid:2100210; rev:1;)
```

## References

- [Google Threat Intelligence Group: The Latest Addition to Turla's Intelligence Gathering Apparatus](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering)
- [The Hacker News: Google Details Turla's New STOCKSTAY Backdoor Used in Ukraine Espionage Attacks](https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html)
- [The Record: Turla group adds more malware to Russia's espionage efforts against Ukraine](https://therecord.media/russia-turla-espionage-ukraine-stockstay-malware)
- [SC Media: Turla group deploys new STOCKSTAY backdoor against Ukraine and Italy](https://www.scworld.com/brief/turla-group-deploys-new-stockstay-backdoor-against-ukraine-and-italy)
- [CISA Advisory AA23-129A: Hunting Russian Intelligence Snake Malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)
- [Google Cloud Blog: Diverse Threat Actors Exploiting Critical WinRAR Vulnerability CVE-2025-8088](https://cloud.google.com/blog/topics/threat-intelligence/exploiting-critical-winrar-vulnerability)
