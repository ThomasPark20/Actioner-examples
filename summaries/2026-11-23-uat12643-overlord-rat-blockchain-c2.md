# UAT-12643: North Korea-aligned Actor with Blockchain C2 and Overlord RAT

**Date:** 2026-11-23
**Classification:** DRAFT
**TLP:** TLP:CLEAR (based on public Cisco Talos research)
**Source:** Cisco Talos primary research
**Viability Gate:** PASS — Talos primary research with 11 SHA-256 hashes, 1 IP address, named malware families, detailed behavioral analysis, and ClamAV/Snort signatures published.

---

## Executive Summary

Cisco Talos published research on **UAT-12643**, a suspected North Korea-aligned threat actor deploying a toolkit of three malware families: the **Overlord RAT** (a Go-based modular RAT with 35 commands), a **Good Game Stealer** (a Python/PyInstaller infostealer), and a **Clipboard Hijacker** (a C++ crypto address swapper). The defining innovation is the use of **Solana blockchain transaction memos** as a dead-drop resolver for C2 addresses, making infrastructure takedown extremely difficult since blockchain entries are immutable and censorship-resistant. The actor stores AES-256-encrypted, Base58-encoded WebSocket C2 URLs in Solana Memo Program instructions, allowing infrastructure rotation without binary updates.

---

## Threat Actor Profile

| Attribute | Detail |
|---|---|
| **Designation** | UAT-12643 |
| **Attribution** | North Korea-aligned (low confidence, per Talos) |
| **Motivation** | Financial (cryptocurrency theft, credential harvesting) |
| **Tooling** | Overlord RAT, Good Game Stealer v1.1.2, Clipboard Hijacker |
| **Infrastructure** | Solana blockchain dead-drop, Flask file server, WebSocket C2, gofile[.]io exfiltration, Discord webhooks |
| **Build Environment** | Hostname: `win-8oa3ccqae4d` |

---

## Kill Chain / Attack Flow

```
1. Delivery ──► Weaponized LNK / HTA / MSBuild XML files
                │
2. Execution ──► LOLBin abuse: MpCmdRun -DownloadFile, certutil -urlcache,
                 mshta.exe, msbuild.exe CodeTaskFactory
                │
3. Staging ────► Payloads fetched from 41[.]216[.]188[.]11:8000
                 (Flask server with byte-range resume)
                │
4. Evasion ────► VM/sandbox detection (DLL checks, MAC OUI, RAM/uptime),
                 process masquerading (RuntimeBroker.exe, MsgEdgeUpdate.exe)
                │
5. Persistence ► Run keys (Zoipers, MsgEdgeUpdate, randomized),
                 Startup folder, WinRE OEM folder + ResetConfig.xml
                │
6. C2 ─────────► Overlord RAT: Solana memo → AES decrypt → WebSocket :5173
                 Good Game: TCP :5656, :5959
                │
7. Collection ──► Keylogging, screen/webcam/mic capture, browser creds,
                  crypto wallets (21), Discord tokens, gaming platforms (4),
                  file sweep (45 extensions, 4-language keyword list)
                │
8. Exfiltration ► ZIP archive (SK_ prefix) → gofile[.]io → Discord webhook
                │
9. Monetization ► Clipboard hijacker swaps crypto addresses in real-time
```

---

## MITRE ATT&CK Mapping

| Technique ID | Name | UAT-12643 Usage |
|---|---|---|
| T1204.002 | User Execution: Malicious File | LNK, HTA, XML lures |
| T1218.005 | System Binary Proxy Execution: Mshta | HTA stager via mshta.exe |
| T1127.001 | Trusted Developer Utilities: MSBuild | Inline C# CodeTaskFactory downloader |
| T1105 | Ingress Tool Transfer | certutil, MpCmdRun -DownloadFile |
| T1140 | Deobfuscate/Decode Files or Information | certutil -urlcache used to download and decode payloads |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Zoipers, MsgEdgeUpdate, randomized values |
| T1542 | Pre-OS Boot | WinRE OEM folder persistence with ResetConfig.xml |
| T1036.005 | Masquerading: Match Legitimate Name | RuntimeBroker.exe, MsgEdgeUpdate.exe |
| T1497 | Virtualization/Sandbox Evasion | DLL checks, MAC OUI, RAM/uptime thresholds |
| T1562.001 | Impair Defenses: Disable or Modify Tools | DisableTaskMgr during exfiltration |
| T1102.001 | Web Service: Dead Drop Resolver | Solana Memo Program for C2 address storage |
| T1071.001 | Application Layer Protocol: Web | WebSocket C2, HTTPS exfil |
| T1571 | Non-Standard Port | WebSocket :5173, TCP :5656, :5959 |
| T1090 | Proxy | Reverse SOCKS proxy over C2 channel |
| T1056.001 | Input Capture: Keylogging | GetAsyncKeyState-based keylogger |
| T1113 | Screen Capture | Desktop screenshot collection |
| T1125 | Video Capture | Webcam frame capture |
| T1123 | Audio Capture | Microphone and desktop audio |
| T1115 | Clipboard Data | 500ms polling + address replacement |
| T1555.003 | Credentials from Password Stores: Browsers | 23 Chromium/Firefox browser credential theft |
| T1539 | Steal Web Session Cookie | ROBLOSECURITY cookie, Discord tokens (dQw4w9WgXcQ prefix) |
| T1005 | Data from Local System | File sweep across user directories |
| T1560.001 | Archive Collected Data | ZIP with SK_ prefix |
| T1567 | Exfiltration Over Web Service | gofile[.]io upload + Discord webhook notification |
| T1082 | System Information Discovery | system_infos.txt collection |
| T1620 | Reflective Code Loading | In-memory DLL injection via HTTP plugin delivery |
| T1027 | Obfuscated Files or Information | XOR-encrypted clipper addresses, AES-encrypted C2 URLs |

---

## Indicators of Compromise

### File Hashes (SHA-256)

| Hash | Description |
|---|---|
| `b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c` | Overlord RAT |
| `16622bb8df60403217ccf8e326e2e9e718e01c85d7b52fe5c5e1cf44d62d25c8` | Good Game Stealer |
| `b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33` | Good Game Stealer (Python script) |
| `5a52d6773840fd5ab45d781d572d9fbd6a8dacb08dcda65036ce8b28548a5224` | Good Game Stealer |
| `f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588` | Clipboard Hijacker |
| `f7951b11be06d59a3e8fdd9bde4f19869978de8385c9107129c635b2cdba5082` | LNK Generator (PowerShell) |
| `19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2` | dl.xml (MSBuild downloader) |
| `1b268a08e83839f6e89acf0987657776398de2ba5a323b04b1dd3925ce3a5b45` | document.lnk |
| `c8f9ce4b58acec3ce5640041cbc6d4802e30b2dded4a88766ee2de2cefde45f7` | payload.hta |
| `eb5730784e7d63e1fe38a0bc28be8f2210666662e9a660efcc3282f0489ef870` | payment-invoice.pdf.lnk |
| `68786345f67152eb0d52bb198b5904924cfbdbf50c078432e5329e5d02fc6659` | Viber.lnk |

### Network Infrastructure

| Indicator | Type | Context |
|---|---|---|
| `41[.]216[.]188[.]11` | IPv4 | Primary C2/staging server |
| `41[.]216[.]188[.]11:8000` | IP:Port | Flask file delivery server (HTTP) |
| `41[.]216[.]188[.]11:5173` | IP:Port | Overlord RAT WebSocket C2 |
| `41[.]216[.]188[.]11:5656` | IP:Port | Python stealer TCP C2 |
| `41[.]216[.]188[.]11:5959` | IP:Port | Python stealer TCP C2 |
| `upload[.]gofile[.]io` | Domain | Exfiltration endpoint (POST /uploadFile) |
| `gofile[.]io` | Domain | Download links for exfiltrated archives |
| `ipwhois[.]app` | Domain | Geolocation lookup |

### Solana Blockchain Indicators

| Indicator | Context |
|---|---|
| Solana Memo Program | C2 addresses stored as transaction memo data |
| `getSignaturesForAddress` | RPC method used for wallet transaction enumeration |
| `getTransaction` (jsonParsed) | RPC method used to retrieve memo content |
| 43-character instruction data | Length filter for identifying C2 memo entries (AES-256 encrypted, Base58 encoded) |

### File System Artifacts

| Path / Name | Context |
|---|---|
| `%TEMP%\s.exe` | HTA stager payload drop location |
| `%APPDATA%\MsgEdgeUpdate.exe` | Clipboard hijacker persistence location (hidden+system) |
| `%TARGETOSDRIVE%\Recovery\OEM\<random20>.exe` | WinRE persistence executable |
| `%TARGETOSDRIVE%\Recovery\OEM\<name>.bat` | WinRE persistence batch launcher |
| `ResetConfig.xml` | Modified for WinRE boot persistence |
| `RuntimeBroker.exe` | Masqueraded Overlord RAT filename |
| `Payload.exe`, `MyApp2.exe`, `Ovl.exe`, `Client.exe` | Payload names on staging server |
| `Ova.exe`, `Microsip-config.exe`, `microsip-config1.exe` | Additional payload names |
| `final_build.pyc`, `kora.pyc` | Good Game Stealer compiled Python modules |
| `system_infos.txt` | System profile collection file |
| `SK_<8random>.zip` | Exfiltration archive naming pattern |
| `url_opened_<hash>.flag` | One-time decoy URL marker |

### Registry Keys

| Key / Value | Context |
|---|---|
| `HKCU\...\CurrentVersion\Run\Zoipers` | Good Game Stealer persistence |
| `HKCU\...\CurrentVersion\Run\MsgEdgeUpdate` | Clipboard Hijacker persistence |
| `HKCU\...\CurrentVersion\Run\<random>` | Overlord RAT persistence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` = 1 | Task Manager disabled during exfil |

### Mutex

| Value | Context |
|---|---|
| `UuuRjinBZPBMIjnc` | Clipboard Hijacker single-instance mutex |

### User-Agent

| Value | Context |
|---|---|
| `Microsoft BITS/7.8` | Spoofed UA in MSBuild inline C# downloader |

### VM/Sandbox Detection Artifacts

**DLLs checked:** `sbiedll.dll`, `api_log.dll`, `vmcheck.dll`, `wpespy.dll`, `cmdvrt64.dll`, `avghookx.dll`, `snxhk.dll`, `guard32.dll`

**MAC OUI prefixes:** VMware (`00:05:69`, `00:0c:29`, `00:50:56`), VirtualBox (`08:00:27`), Hyper-V (`00:15:5d`), Xen (`00:16:3e`), Parallels (`00:1c:42`)

**Other checks:** `C:\windows\system32\wineboot.exe` (Wine), machine name substrings (`VBOX`, `VMWARE`, `QEMU`, `SANDBOX`), <2 GB RAM, <5 min uptime

---

## Malware Analysis

### Overlord RAT (Go binary)

- **35 modular commands** including: keylogging, webcam/mic/desktop audio capture, screen capture, file operations (upload, download, compress, recursive search), process enumeration/termination, command execution with streamed output, reverse SOCKS proxy, HTTP plugin delivery with in-memory reflective DLL injection
- **C2 Discovery:** Queries Solana Memo Program via actor's wallet. Filters for 43-character instruction data fields containing AES-256-encrypted, Base58-encoded WebSocket URLs. Each installation picks up updated C2 on next poll cycle without redeployment.
- **Anti-Termination:** Acquires `SeDebugPrivilege`, calls `NtSetInformationProcess` with `ProcessBreakOnTermination` to trigger CRITICAL_PROCESS_DIED BSoD if killed.
- **Persistence:** Registry Run key (randomized name) + WinRE OEM folder with batch launcher and modified `ResetConfig.xml` (pre-OS boot survival).
- **Random 20-character filenames** generated per installation.

### Good Game Stealer v1.1.2 (Python 3.12 / PyInstaller)

- **Third-party publicly available stealer** distributed by UAT-12643.
- **Launcher** (`final_build.pyc`): hides console, shows tkinter Notepad decoy GUI, opens decoy PDF URL once per machine, acts as reverse-shell client.
- **Stealer** (`kora.pyc`): Windows-only with internet check (Google GET), sandbox/VM evasion.
- **Targets:** 23 Chromium/Firefox browsers (creds, cookies, Discord tokens including `dQw4w9WgXcQ:` encrypted-token prefix), 21 crypto wallets (Exodus, Electrum, Ledger Live, Trezor Suite, Atomic, Trust Wallet, Coinbase, Binance, +13 others), 4 gaming platforms (Steam, Riot, Epic, Rockstar), Telegram sessions.
- **Collection:** System profile, public IP geolocation (ipwhois.app), screenshot, webcam frame, file sweep across Desktop/Downloads/Documents/Pictures/Videos/OneDrive/Recent (45-extension allowlist, 4-language keyword filter).
- **Exfiltration:** ZIP (`SK_` prefix) to gofile[.]io, Discord webhook notification with host details and download link. Artifacts deleted post-exfil.
- **Defense Evasion:** Sets `DisableTaskMgr=1` during exfiltration, resets to 0 after.

### Clipboard Hijacker (C++ x64)

- **No network component** -- operates purely locally.
- **Polls clipboard every 500ms** via dynamically resolved `user32.dll` functions.
- **Matches cryptocurrency address regex patterns** and replaces with attacker-controlled addresses (XOR-encrypted in data section).
- **Persistence:** Copies to `%APPDATA%\MsgEdgeUpdate.exe` with hidden+system attributes, creates `MsgEdgeUpdate` Run key.
- **Global mutex:** `UuuRjinBZPBMIjnc`

---

## Vendor Detection Coverage

### ClamAV Signatures
- `Win.Trojan.OverlordRAT-10060615-0`
- `Win.Trojan.OverlordRAT2-10060616-0`
- `Win.Infostealer.GoodGame-10060617-0`
- `Win.Infostealer.PyStealerDeps-10060618-0`
- `Py.Infostealer.GoodGame-10060619-0`
- `Py.Trojan.GoodGameLoader-10060620-0`
- `Win.Trojan.WalletClipper-10060621-0`
- `Win.Downloader.LNKMpCmdRun-10060622-0`
- `Win.Downloader.LNKCertutil-10060623-0`
- `Win.Trojan.LNKVideosExe-10060624-0`
- `Ps1.Trojan.LNKBuilder-10060627-0`
- `Html.Downloader.HTAStager-10060656-1`
- `Xml.Downloader.MSBuildInline2-10060657-0`

### Snort Signatures
- Snort2 SIDs: `1:67491`, `1:67490`
- Snort3 SIDs: `7:75`, `7:74`

---

## Detection Rules

### Sigma Rules

All Sigma rules validated via `sigma convert --without-pipeline -t splunk` and `-t log_scale` (all 10 converted successfully). Tags contain only technique/sub-technique identifiers (no tactic-level tags). Note: `sigma check` was not run; tag correctness was verified by manual review against the MITRE ATT&CK framework.

#### 1. Overlord RAT RuntimeBroker Masquerade
- **File:** `/tmp/actioner/sigma-uat12643-overlord-rat-process.yml`
- **Log Source:** process_creation / windows
- **Logic:** RuntimeBroker.exe executing from outside System32/SysWOW64
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 2. MpCmdRun -DownloadFile Abuse
- **File:** `/tmp/actioner/sigma-uat12643-lnk-mpcmdrun-download.yml`
- **Log Source:** process_creation / windows
- **Logic:** MpCmdRun.exe with -DownloadFile and -url flags
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 3. Certutil URLCache Download
- **File:** `/tmp/actioner/sigma-uat12643-certutil-download.yml`
- **Log Source:** process_creation / windows
- **Logic:** certutil.exe with -urlcache -f and http in command line
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 4. MSBuild Inline Task Execution
- **File:** `/tmp/actioner/sigma-uat12643-msbuild-inline-task.yml`
- **Log Source:** process_creation / windows
- **Logic:** MSBuild.exe executing .xml/.csproj/.proj without Visual Studio parent
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** medium (legitimate MSBuild CLI use possible)
- **Status:** ✅ converted (Splunk, LogScale)

#### 5. HTA Stager via Mshta
- **File:** `/tmp/actioner/sigma-uat12643-hta-stager.yml`
- **Log Source:** process_creation / windows
- **Logic:** mshta.exe with remote HTTP/HTTPS URLs in command line (bare .hta match removed to avoid FP on legitimate local HTA invocations)
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** medium (some legitimate HTA applications fetch remote resources)
- **Status:** ✅ converted (Splunk, LogScale)

#### 6. Clipboard Hijacker MsgEdgeUpdate Persistence
- **File:** `/tmp/actioner/sigma-uat12643-clipboard-hijacker-persistence.yml`
- **Log Source:** process_creation / windows
- **Logic:** MsgEdgeUpdate.exe running from AppData\Roaming
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 7. Good Game Stealer Zoipers Registry Persistence
- **File:** `/tmp/actioner/sigma-uat12643-goodgame-persistence.yml`
- **Log Source:** registry_set / windows
- **Logic:** Registry Run key value "Zoipers" created
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 8. WinRE OEM Persistence
- **File:** `/tmp/actioner/sigma-uat12643-winre-persistence.yml`
- **Log Source:** file_event / windows
- **Logic:** Executable or batch file written to Recovery\OEM\ or ResetConfig.xml modified
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high
- **Status:** ✅ converted (Splunk, LogScale)

#### 9. DisableTaskMgr During Exfiltration
- **File:** `/tmp/actioner/sigma-uat12643-disable-taskmgr.yml`
- **Log Source:** registry_set / windows
- **Logic:** DisableTaskMgr DWORD set to 1 under Policies\System
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** high (but may fire from GPO in managed environments)
- **Status:** ✅ converted (Splunk, LogScale)

#### 10. Solana RPC Dead-Drop Resolver
- **File:** `/tmp/actioner/sigma-uat12643-solana-rpc-beacon.yml`
- **Log Source:** dns_query / windows
- **Logic:** DNS queries to known Solana RPC provider domains
- **Compile:** Splunk SPL / LogScale -- converted successfully
- **Confidence:** medium (legitimate blockchain developers may trigger)
- **Status:** ✅ converted (Splunk, LogScale)

### YARA Rules

- **File:** `/tmp/actioner/yara-uat12643-overlord-rat.yar`
- **Status:** ⚠️ uncompiled (structural check only)
- **Rules contained:**

| Rule Name | Target | Confidence |
|---|---|---|
| `UAT12643_OverlordRAT` | Overlord RAT Go binary (Solana RPC, WebSocket, NtSetInformationProcess, WinRE persistence) | high |
| `UAT12643_GoodGameStealer` | Good Game Stealer PyInstaller bundle (exfil to gofile.io, wallet targets, VM detection) | high |
| `UAT12643_ClipboardHijacker` | Clipboard Hijacker C++ binary (mutex, MsgEdgeUpdate, clipboard API chain) | high |
| `UAT12643_MSBuild_Downloader_XML` | dl.xml MSBuild inline task (CodeTaskFactory, BITS/7.8 UA) | high |

### Snort/Suricata Rules

- **File:** `/tmp/actioner/snort-uat12643-c2.rules`
- **Status:** ⚠️ uncompiled (structural check only)
- **Rules contained:**

| SID | Description | Confidence |
|---|---|---|
| 2026112301 | Known C2 IP 41[.]216[.]188[.]11 | high |
| 2026112302 | WebSocket C2 on port 5173 | medium (port 5173 is Vite dev server default; FP risk in dev environments) |
| 2026112303 | Flask payload server known filenames on port 8000 | high |
| 2026112304 | Spoofed BITS/7.8 User-Agent | high |
| 2026112305 | Exfiltration to gofile[.]io /uploadFile | medium |
| 2026112306 | Solana RPC getSignaturesForAddress (blockchain dead-drop) | medium |
| 2026112307 | Python stealer non-standard TCP ports 5656/5959 | medium |

---

## Defensive Recommendations

1. **Block known infrastructure:** Add `41[.]216[.]188[.]11` to network blocklists. Monitor for connections to ports 5173, 5656, 5959, and 8000 on external IPs.
2. **Monitor Solana RPC traffic:** Where no business need for blockchain development exists, alert on or block outbound connections to public Solana RPC endpoints (api.mainnet-beta.solana.com, QuickNode, Ankr, Alchemy, Tatum). Inspect JSON-RPC payloads for `getSignaturesForAddress` and `getTransaction` methods.
3. **LOLBin monitoring:** Alert on `MpCmdRun.exe -DownloadFile`, `certutil -urlcache -f` with HTTP URLs, `mshta.exe` with remote URLs, and `MSBuild.exe` executing XML files outside developer workflows.
4. **Registry monitoring:** Watch for creation of Run key values named `Zoipers`, `MsgEdgeUpdate`, and the `DisableTaskMgr` policy toggle.
5. **WinRE integrity:** Monitor the `Recovery\OEM` folder and `ResetConfig.xml` for unauthorized modifications. This persistence technique survives OS reinstall/reset.
6. **Exfiltration detection:** Alert on uploads to `upload[.]gofile[.]io` and outbound Discord webhook traffic from non-browser processes.
7. **Clipboard monitoring:** Consider endpoint detection for high-frequency clipboard polling (500ms intervals) by non-standard processes, especially those matching crypto address regex patterns.
8. **Hash-based blocking:** Deploy the 11 SHA-256 hashes to EDR and proxy allowlist/blocklist systems.

---

## Intelligence Gaps

- **Solana wallet address(es):** Not disclosed in the public report; needed for blockchain-level monitoring.
- **Replacement cryptocurrency addresses:** XOR-encrypted in the clipboard hijacker binary; not published.
- **Initial delivery mechanism:** The report does not describe how lure files reach victims.
- **Discord webhook URL:** Hardcoded but not disclosed.
- **Attribution confidence:** Talos assesses North Korea alignment at LOW confidence only.

---

## References

- Cisco Talos. "UAT-12643: Suspected North Korea-aligned actor blends blockchain resilience with targeted infostealing." November 2026. https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
- Cisco Talos. "The challenge of defending against bulletproof dead-drops on public blockchains." November 2026. https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/
- Cisco Talos IOCs. https://github.com/Cisco-Talos/IOCs/tree/main/2026/11

---

## Detection Rule Files

| File | Type | Rules | Status |
|---|---|---|---|
| `/tmp/actioner/sigma-uat12643-overlord-rat-process.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-lnk-mpcmdrun-download.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-certutil-download.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-msbuild-inline-task.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-hta-stager.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-clipboard-hijacker-persistence.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-goodgame-persistence.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-winre-persistence.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-disable-taskmgr.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/sigma-uat12643-solana-rpc-beacon.yml` | Sigma | 1 | ✅ converted |
| `/tmp/actioner/yara-uat12643-overlord-rat.yar` | YARA | 4 | ⚠️ uncompiled |
| `/tmp/actioner/snort-uat12643-c2.rules` | Snort/Suricata | 7 | ⚠️ uncompiled |
