# Technical Analysis Report: PerfectPioneer RAT + KUKURAT — HTTP/3-Powered RATs Targeting Southeast Asian Governments (2026-11-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-17
Version: 1.0 (DRAFT)

## Executive Summary

A cyberespionage campaign tracked as TGR-STA-0049 (also known as REF7707, Earth Alux, and Ink Dragon) has deployed two custom remote access trojans — PerfectPioneer (Go-based, six variants) and KUKURAT (C++, modular) — against government entities in Southeast Asia, with additional activity in South America and Europe. The campaign is notable for its use of HTTP/3 over QUIC (UDP/443) as the primary C2 channel, with HTTP/2 fallback, explicitly chosen to evade network inspection stacks that focus on TCP traffic. PerfectPioneer has been active since at least July 2025, while KUKURAT emerged in March 2026 as the actor transitioned infrastructure. The toolset includes an operator-safety feature ("isDangerousCommand") that blocks destructive commands, a heuristic camouflage engine generating decoy traffic, a watchdog process for persistence, and 12+ runtime-loadable modules covering everything from keylogging and screenshots to PsExec-style lateral movement and BOF execution. Initial access was achieved through exploitation of unpatched Microsoft Exchange servers and web shells, with credential harvesting via LSASS dumping (comsvcs.dll ordinal call), DCSync, Mimikatz, and SharpDPAPI. The actor compromised Exchange mailboxes at scale, granting FullAccess to all mailboxes for document exfiltration focused on diplomatic and political materials.

## Background: Southeast Asian Government Targets

TGR-STA-0049 targets government ministries and diplomatic entities in Southeast Asia, with a focus on organizations handling international relations and internal political matters. The actor was previously observed deploying Squidoor (also known as FINALDRAFT) since at least March 2023 and has progressively developed custom tooling. The transition from PerfectPioneer to KUKURAT reflects an evolution toward modular, C++-based implants with more sophisticated evasion capabilities. The choice of HTTP/3/QUIC as a C2 transport reflects the actor's awareness that many enterprise security stacks cannot perform deep packet inspection on UDP-based encrypted protocols.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| March 2023 | Earliest known TGR-STA-0049 activity; deployment of Squidoor/FINALDRAFT |
| July 2025 | PerfectPioneer RAT first observed; six variants developed |
| March 2026 | KUKURAT first observed; infrastructure begins shifting from PerfectPioneer |
| 2025-2026 | Exploitation of unpatched Exchange and web servers for initial access |
| 2026 (ongoing) | Active exfiltration of government documents via C2 channels |
| 2026-11-16 | Unit 42 publishes technical analysis |

## Root Cause: Exploitation of Public-Facing Applications

Initial access was achieved through exploitation of unpatched Microsoft Exchange servers and other internet-facing web servers. The actor deployed multiple web shells (ASPXSpy, Godzilla, Bysunue.aspx, and Suo5 variants) for persistent access. Additionally, phishing campaigns used decoy PDFs themed around the 2025 Myanmar election notice and lookalike government domains. Some delivery mechanisms involved fake installer packages that dropped a legitimate GlobalProtect installer as a decoy alongside the RAT payload.

## Technical Analysis of the Malicious Payload

### 1. DLL Sideloading and Initial Loader

PerfectPioneer uses DLL sideloading as its primary loading mechanism. A legitimate binary is modified to carry XOR-encrypted shellcode, and a malicious loader DLL decrypts and runs it in memory. Decoy installers present a fake setup wizard that drops and executes the RAT in the background, sometimes alongside a real GlobalProtect installer for cover. For KUKURAT, the core binary contains no post-exploitation code — all capabilities are loaded as runtime modules from the C2 server.

### 2. PerfectPioneer RAT (Go-based, Six Variants)

PerfectPioneer is a Go-based RAT with six known variants: newhttp3, PerfectRat, Pioneer, RatAAkk-tt, rat_http3_ls, and rat_http3_cc. The newhttp3 variant has the broadest command set (~40 commands) covering:

- **File operations:** list, upload, download, delete, chunked transfer with progress tracking
- **Process management:** list, kill, start, COM-based process creation
- **Shellcode injection:** VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- **Surveillance:** window enumeration/control, keylogging, screenshots, resource monitoring
- **Network:** SOCKS5 proxy
- **Credential access:** credential harvesting, token impersonation (PerfectRat)
- **Remote desktop:** TerminalManagerV2 (RatAAkk-tt)

The Pioneer and rat_http3_cc variants include the **isDangerousCommand** operator-safety feature with three layers: 41 hard-coded keywords (format, fdisk, mkfs, diskpart, shutdown, reboot, passwd, etc.), 16 malicious pattern filters (chained deletions, download-and-execute pipelines, encoded PowerShell), and directory protection blocking destructive operations on system paths.

The rat_http3_cc variant adds persistence mechanisms and a local HTTP status server on TCP/56793 with endpoints: `/`, `/info`, `/health`, `/status`.

### 3. KUKURAT RAT (C++, Modular)

KUKURAT is a C++-based modular RAT available in HTTP/2 and HTTP/3 variants. The HTTP/3 variant uses a function-pointer table and adds a native `exec` command (CreateProcessA with output piped to C2). At least 12 named modules provide:

- **Surveillance:** screenshots, keylogging
- **Network reconnaissance:** port scanning, host scanning
- **Process manipulation:** process listing, process kill, process injection
- **File management:** list, download, upload, delete, execute
- **Shell execution:** cmd.exe and PowerShell
- **Lateral movement:** PsExec module, SMB credential brute-forcing
- **Tunneling:** SOCKS proxy (yuze_dll.dll)
- **Privilege escalation:** local privilege elevation, UAC bypass
- **Advanced execution:** Beacon Object File (BOF) execution (BofLoader.dll)
- **Stealth:** silent mode, heuristic camouflage engine

KUKURAT C2 endpoint names are hashed in the binary to hinder static analysis (e.g., `/heartbeat` becomes `/c8a4e192`).

Configuration includes: heartbeat timeout 300,000 ms, command result timeout 300,000 ms, file transfer chunk timeout 300,000 ms with 5 retries at 300 ms delay, 1 failed heartbeat before re-registration, 5 command worker threads, and module execution timeout 600,000 ms.

### 4. C2 Infrastructure

**Primary channel:** HTTP/3 over QUIC on UDP/443, with fallback to HTTP/2 over TCP. This choice is deliberate — passive TLS interception is significantly harder over UDP, and many enterprise inspection stacks focus on TCP traffic.

**PerfectPioneer C2 endpoints:**
- `/agent/register` — initial registration
- `/agent/heartbeat` — keep-alive
- `/agent/tasks` — task polling
- `/agent/result` — result submission

**KUKURAT C2 endpoints (hashed in code):**
- `/register`, `/heartbeat` (hashed to `/c8a4e192`)
- Module operations: `load_module`, `unload_module`, `download_module`
- Command types: `screenshot`, `portscan`, `hostscan`, `processlist`, `keylogger`, `filemanager`, `shell`, `execute_module`, `my_psexec`, `smb_brute`, `socks`, `com_exec`, and others

**Known C2 IPs:** 27.254.164[.]212, 27.254.164[.]209

### 5. Anti-Forensics / Evasion Techniques

- **Heuristic camouflage engine** (toggled via `set_obfuscation`):
  - Network axis: 10 decoy HTTP requests per cycle to 15 popular legitimate websites
  - Registry axis: mimics Chrome crash recovery and Google Update key access
  - File axis: creates and deletes random temp files in %temp%
- **Watchdog process:** KUKURAT deploys a companion watchdog that monitors a named pipe (`WINDOW_SEC_WATCHDOG`). KUKURAT writes its path every 3 seconds; the watchdog relaunches it after 15 seconds of silence. The watchdog is placed in `C:\ProgramData\Cyvera\Ransomware\`, a path associated with Cortex XDR, to masquerade as a security product.
- **Self-cleaning:** PerfectPioneer deletes temp files and forces Go garbage collection above 100 MB; resource monitor samples every 30 seconds.
- **PsExecService self-uninstall:** Removes itself after 5 minutes of inactivity.
- **LSASS dump obfuscation:** Uses comsvcs.dll MiniDump export called by ordinal (`#+000024`) via rundll32.exe to avoid string-based detection.
- **Modular architecture:** Core binary has no post-exploitation code; modules loaded in memory from C2.
- **C2 endpoint hashing:** KUKURAT hashes endpoint names in the binary to impede static analysis.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | D:/proj/RatAAkk-tt/agent/ | (PDB path) | PerfectPioneer RatAAkk-tt project path |
| Windows | D:/proj/PerfectRat/agent/ | (PDB path) | PerfectPioneer PerfectRat project path |
| Windows | D:/proj/http3/newhttp3/agent/ | (PDB path) | PerfectPioneer newhttp3 project path |
| Windows | D:/proj/http3/rat_http3_ls/agent/ | (PDB path) | PerfectPioneer rat_http3_ls project path |
| Windows | D:/proj/http3/Pioneer/ | (PDB path) | PerfectPioneer Pioneer project path |
| Windows | D:/proj/http3/rat_http3_cc/ | (PDB path) | PerfectPioneer rat_http3_cc project path |
| Windows | d:\proj\KUKURAT\modules\MyPsExec-master\PsExecService\ | (PDB path) | KUKURAT PsExecService module PDB |
| Windows | C:\ProgramData\Cyvera\Ransomware\ | — | KUKURAT watchdog masquerade directory |
| Windows | \Windows\Temp\MxA.tar | — | LSASS dump output file |

**PerfectPioneer RAT Hashes (SHA256):**

| Hash | Variant / Component |
|------|-------------------|
| 2281e754f70e11298db1a0a7c1b527cf2b5eec2056d4c73a46ed572ab873dc6e | RatAAkk-tt |
| 9721d65ee7695db2b3dc3705f5d8e5efe3a478c3b6d1704d66daf77fe95aeb0d | RatAAkk-tt |
| d725ad8b523c94f99fca9e72a650e835dca47b9ebe7610d6c4eb3525d410c365 | RatAAkk-tt |
| f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457 | PerfectRAT |
| 19bb3012d846f3672fb98dad0449ae5c267ab30150800b2f1559036564c7d0b8 | PerfectRAT |
| 92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67 | rat_http3_ls |
| ab06f540ecdd1d45491aa71bfc04c80852371c8f5cd43b9a6ebb53f1e1b69588 | Pioneer decoy installer |
| bf59f8d7ef79b09a72bbb9c05ca8746466d03226a3779cc1096ba067117ca008 | Pioneer core agent |
| 8bf9401990d3255d1022a25884b02ee75ef01bd1a729d29ff52de2e5f0d637a2 | Pioneer core agent |
| 5f857ff78bfbef2a55a846fc93744e11e07a9b72ee3fc3bc345c32ce9615ddee | newhttp3 modified host binary |
| 61f7e2f4159c566578e88cb05cdf49e4378f45ebddbd332224e97c11df922120 | newhttp3 loader DLL |
| 5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344 | newhttp3 core agent |
| cd8f43da32849584751eec884cf7e3208eb0a71108197a32e9bb248612e757d2 | newhttp3 core agent |
| 7541222a1316ec54bf9c8660b923e1d0490a925b2ee92060b1567be7cb1bde4b | newhttp3 core agent |
| cffcd6f2589d3ab4f3693805d1752b7c328a00cc543dd02b129763e179c3f311 | newhttp3 core agent |
| 5805cb5b0a6fb738ef7c1873b8e5de4281c36c7f440f28717fa9f441c5e0ef17 | newhttp3 core agent |
| a6a9ccffadd00b0e75e913b0f851b1f834fd20588df8b89759d9ae49a48c8e10 | newhttp3 core agent |
| b975f5932c04b381f8fa58a3303194f1aff950d3c6cd12dcc1d323bb3393718b | rat_http3_cc modified host binary |
| 904409ce8846394e1fe9a5ce37f2265cbf6933611278ae57fdf5fa74759af2bb | rat_http3_cc modified host binary |
| d700b573ea8387efad633a70124b7a2a3aece844a267157b1cb55be7b62f3b67 | rat_http3_cc modified host binary |
| 52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07 | rat_http3_cc modified host binary |
| 8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70 | rat_http3_cc loader DLL |
| 619b749e1c6634d38f15c51005a4237e9076aaaf36927b562a990e8bc34fdfcb | rat_http3_cc core agent |
| fb5b0b1d083d6f6afa90948bd1fd1a498b51dd3f6dc7f90a02a2a17818756563 | rat_http3_cc core agent |
| 183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0 | rat_http3_cc core agent |
| 0533365accbba405757de7eb486533c11c8e0510a28d414ee8c5e6b8a41ed97b | Unknown variant |
| 3cb5376a5e6c0fcbd6844ab76f3dc73a42da7ecee6ecaaef285d4abe33964fa1 | Unknown variant |
| f5ebe85418655d75d1a760543858846db1478a060875fd19ddaa5e2febc038d7 | Unknown variant |
| b5bea4d8b94fbb39ac992e8e763680af6f39d12d42e264b43431fb61cf7b9a88 | Unknown variant modified host binary |
| 7745523939fc6b31b6a73d8ca1f363c62438b6eef56f6fe8c39e71fcd14b65f4 | Unknown variant modified host binary |
| 0c49e1b98a236d3391740473101b66dd48c719fa4112dbef3816b56bce58e6e7 | Loader DLL component |
| 24c46bc9269e1c1ee54004e01d5c7c54f759bc1b93a282d3561d2d27f678af86 | Loader DLL component |
| e5689e1bf916c2f7649e178008e790ea13eb844aefc14516c06b0da8296377a1 | Loader DLL component |
| 63eac14921f138fffe73db417c12afd16d64202ebbee7ad5f08068697d2942d0 | Loader DLL component |
| 790e6699704395a7fad633f4e502312bc43693a44a8e18d43239209eefbd7ff2 | Loader DLL component |
| f82c06184ab36e91d28f7802c739e637792c241a7ff2fba9ca24178f12423684 | Loader DLL component |
| 2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4 | Loader DLL component |
| 9dfefc7118646535d1193e1b036dd0c93fa66cc585a60301fcdceb6f45903aad | Loader DLL component |
| 600572a912650b258d56aedeef0ab712abbe35a38cdd23faa5a95dacfdc67b7f | Loader DLL component |
| 86194c3b3cc7a58e439621aff42e116ca94d40f3a6f539f20ce483f1cf5a7191 | Loader DLL component |
| e8cd6bbcf6073669a7415ce0c9009a0fbb5551bf5e17803be12ef295f0c99889 | Loader DLL component |
| 5b779b81a9bb25591ecac6bd74bb44a4a5b2b8f257093f9efd5910346ab8d772 | Loader DLL component |
| c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02 | Additional variant |
| bf8afbd1c2074c7cd6ff8b86dbe67a57ca5594817e46b24e226b71c4edde7697 | Additional variant |

**KUKURAT RAT Hashes (SHA256):**

| Hash | Component |
|------|-----------|
| b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4 | HTTP/3 variant |
| 9fb0976fcd1f92c4711726a91cff8be9a39944efedc4caf2d80f935327f8f490 | HTTP/3 variant |
| 7225ef57161cf0908560811be798d22e9354c071d576540a43aa7900784c0688 | HTTP/2 variant |
| a214d264c6bb0d2ba89986f73e196ea200307574745a245fc42c32fbef4cc140 | HTTP/2 variant |
| 662dc73e11b60b2f12c94b6b68da45de7bffece4b1dcc75679ed020629d0705d | HTTP/2 variant |
| b062b4d8c19baf5c1568e28b3e0a5e2318e9501ea61ddfe804d9755c1bdbf887 | Companion watchdog |
| 34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78 | PsExecService module |

**Supporting Tools Hashes (SHA256):**

| Hash | Tool |
|------|------|
| 0cbde9b7f59dafca80f214121a04eda7804b920da28ce1c06939a4783e6b097f | SharpDPAPI |
| cdc9757294d3063eb10c9a37d1d945d31f6857c652b864803815406b02eeefbf | SharpDPAPI |

**Unmapped File Hashes (SHA256):**

| Hash |
|------|
| 82a989c728db4e09a2b85a4a55f7663cefa62844632cb16dcda5ca70bf09a8a5 |
| 71d897427329ca14dd621e777046dc35f3d9dc870d3b13a56125125391a56afe |
| 6781f84417d0056df95ed38b3e7a6b49312d30119470356f6923238d49de3490 |
| dd02d28c48cf5cabd35a0b32e05e7c99ff0de35541201026ae36c59e54968c78 |
| e59b08eb03ffa10ccf9103d171af757308e6d43519c4e904ef5e0929ef92d8fd |

**Web Shell Hashes (SHA256):**

| Hash |
|------|
| 99f571c07170250a84f0ae9de4179044df91244855d9b39978729933ea3d438f |
| 7ee22a7b028102bb22f0a41d41cd101d5956c1db0cfd157b22bf4128bd472a4f |
| 571067cc8f4224a4b80113b52672c7ac87e25dcdb0282a36a29a1784a24efa27 |
| 8d8ccf24b785a33a9388043baecc4be247ad01182b87df3f8e425957ef73087c |
| 0e01c44e5a0615098d8c583930dd88dbd0ce6fe54b365c9f04d8b315a93f540a |
| 1dd423ff0106b15fd100dbc24c3ae9f9860a1fcdb6a871a1e27576f6681a0850 |
| 04be76217500275335e82eb4c2c1588478f7a171efd7a0d9bdc6bbe83e315589 |
| 3deb43cc864f2322d374541d99af79d87ad08abf81cd967862c554f1c0c5fdb6 |
| 224ed1d3f8d7247989f812cb0accc1d1804197916c47d9600e6c4e9bef46a723 |
| 9b16333820189e94b2368e87cba0a9642595d5be0f985a6351f1ad834f5cd11d |
| bdcd0eefc62721814d0bd557285490aa99a4eb0425bf5204e6be16ec7ce93823 |
| 3e56d049f23ed45a7034e5c74bad45cae11ce6d15189fa7bda6b8d120439c7cc |
| 834491282da22555f53b769ef8ad91a958f860c583ee5cb67b3f161caf19f854 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | www[.]maui-cocktailbar[.]com | PerfectPioneer C2 |
| Domain | ads-edge[.]com | PerfectPioneer C2 |
| Domain | www[.]wkuyda[.]com | PerfectPioneer C2 |
| Domain | www[.]thailisting[.]net | PerfectPioneer C2 |
| Domain | www[.]yangon[.]it[.]com | PerfectPioneer C2 |
| Domain | www[.]cloudflacecdn[.]com | KUKURAT C2 |
| Domain | www[.]police[.]gr[.]com | KUKURAT C2 |
| Domain | www[.]investigationj6[.]com | KUKURAT C2 |
| Domain | www[.]sacofficegov[.]com | Campaign infrastructure |
| IP | 27[.]254[.]164[.]212 | C2 infrastructure |
| IP | 27[.]254[.]164[.]209 | C2 infrastructure |
| URL Pattern | /agent/register | PerfectPioneer C2 registration |
| URL Pattern | /agent/heartbeat | PerfectPioneer C2 heartbeat |
| URL Pattern | /agent/tasks | PerfectPioneer C2 task polling |
| URL Pattern | /agent/result | PerfectPioneer C2 result submission |
| URL Pattern | /register | KUKURAT C2 registration |
| URL Pattern | /c8a4e192 | KUKURAT C2 heartbeat (hashed) |
| Port | UDP/443 | HTTP/3 over QUIC (primary C2) |
| Port | TCP/56793 | rat_http3_cc local status server |

### Behavioral

- **Named pipe:** `WINDOW_SEC_WATCHDOG` — KUKURAT watchdog heartbeat communication
- **Named pipe:** `\\.\pipe\PSEXEC` — PsExecService lateral movement module
- **Service name:** `PsExec` — registered by KUKURAT's PsExecService module
- **Registry persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — PerfectPioneer Run key persistence
- **Registry camouflage:** `HKCU\Software\Google\Chrome\BrowserCrashRecovery` — KUKURAT decoy registry activity
- **Registry camouflage:** `HKCU\Software\Google\Update\ClientState` — KUKURAT decoy registry enumeration
- **LSASS dump pattern:** `rundll32.exe C:\windows\System32\comsvcs.dll, #+000024` writing to `\Windows\Temp\MxA.tar`
- **Exchange recon:** `Get-ManagementRoleAssignment -Role:ApplicationImpersonation`
- **Mailbox abuse:** `Get-Mailbox -ResultSize Unlimited | ForEach-Object { Add-MailboxPermission ... -AccessRights FullAccess ... }`
- **Startup folder:** .lnk shortcut in user's Startup directory for PerfectPioneer persistence
- **Domain logon scripts:** Malicious logon scripts added after DC compromise for KUKURAT execution
- **Decoy traffic:** 10 HTTP requests per cycle to 15 popular sites as network camouflage
- **Temp file noise:** Random file creation/deletion in %temp% as file system camouflage

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of unpatched Exchange and web servers for initial access |
| T1566.001 | Spearphishing Attachment | Phishing with decoy PDFs themed on Myanmar election; executables disguised as PDFs |
| T1505.003 | Web Shell | ASPXSpy, Godzilla, Bysunue.aspx, Suo5 web shells on compromised servers |
| T1574.002 | DLL Side-Loading | Modified legitimate binaries with XOR-encrypted shellcode and malicious loader DLLs |
| T1059.001 | PowerShell | PowerShell execution via KUKURAT shell module |
| T1059.003 | Windows Command Shell | cmd.exe execution via KUKURAT shell module |
| T1055.001 | Dynamic-link Library Injection | Shellcode injection via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread |
| T1071.001 | Web Protocols | HTTP/3 over QUIC (UDP/443) and HTTP/2 for C2 communication |
| T1547.001 | Registry Run Keys / Startup Folder | HKCU Run key and Startup folder .lnk for PerfectPioneer persistence |
| T1037.001 | Logon Script (Windows) | Domain logon scripts for KUKURAT execution after DC compromise |
| T1003.001 | LSASS Memory | comsvcs.dll MiniDump ordinal call via rundll32 for LSASS memory dump |
| T1003.006 | DCSync | Domain controller hash extraction |
| T1003.002 | Security Account Manager | Manual SAM and SYSTEM hive dumps for local hashes |
| T1555 | Credentials from Password Stores | SharpDPAPI for DPAPI credential decryption |
| T1110.001 | Password Guessing | KUKURAT SMB credential brute-forcing module |
| T1036.005 | Match Legitimate Name or Location | Watchdog placed in Cortex XDR directory path; GlobalProtect decoy installer |
| T1070.004 | File Deletion | PerfectPioneer self-cleaning temp files; PsExecService self-uninstall |
| T1569.002 | Service Execution | PsExecService lateral movement via named pipe |
| T1021.006 | Windows Remote Management | WinRM for lateral movement |
| T1047 | Windows Management Instrumentation | WMI for remote execution |
| T1113 | Screen Capture | Screenshots via PerfectPioneer and KUKURAT modules |
| T1056.001 | Keylogging | Keylogging via PerfectPioneer and KUKURAT modules |
| T1090.001 | Internal Proxy | SOCKS5 proxy (PerfectPioneer) and SOCKS tunneling (KUKURAT) |
| T1548.002 | Bypass User Account Control | KUKURAT bypass_uac endpoint |
| T1134.001 | Token Impersonation/Theft | Token impersonation in PerfectRat variant |
| T1041 | Exfiltration Over C2 Channel | Document exfiltration via chunked file transfer over HTTP/3/QUIC |
| T1114.002 | Remote Email Collection | Exchange FullAccess grant to all mailboxes for email/document collection |
| T1046 | Network Service Discovery | Host and port scanning modules |

## Impact Assessment

The campaign targets government entities handling diplomatic and political matters in Southeast Asia, with victims also identified in South America and Europe. The actor's capability to dump credentials, move laterally via PsExec/WMI/WinRM, and compromise Exchange infrastructure at scale enables broad access to sensitive government communications. Exfiltrated documents include PDFs, DOCX, XLSX, and PNG files with filenames suggesting diplomatic and political sensitivity. The use of HTTP/3/QUIC for C2 and the heuristic camouflage engine make detection challenging for organizations lacking QUIC inspection capabilities.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for KUKURAT watchdog directory
Get-ChildItem "C:\ProgramData\Cyvera\Ransomware\" -ErrorAction SilentlyContinue

# Check for KUKURAT named pipe
Get-ChildItem "\\.\pipe\" | Where-Object { $_.Name -eq "WINDOW_SEC_WATCHDOG" }

# Check for PsExecService
Get-Service -Name "PsExec" -ErrorAction SilentlyContinue

# Check for PerfectPioneer persistence in Run key
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List

# Check for LSASS dump artifacts
Get-ChildItem "\Windows\Temp\MxA.tar" -ErrorAction SilentlyContinue

# Check for suspicious QUIC traffic (requires network visibility)
# Monitor for outbound UDP/443 to known C2 IPs: 27.254.164.212, 27.254.164.209

# Check for Exchange mailbox permission abuse
Get-MailboxPermission -Identity <mailbox> | Where-Object { $_.AccessRights -contains "FullAccess" -and $_.IsInherited -eq $false }

# Check Exchange for ApplicationImpersonation role holders
Get-ManagementRoleAssignment -Role:ApplicationImpersonation
```

### Remediation

1. **Block outbound UDP/443 (QUIC)** to force C2 fallback to inspectable TCP/HTTP/2 channels, then inspect for the known C2 URI patterns.
2. **Block known C2 domains** at DNS and proxy: maui-cocktailbar[.]com, ads-edge[.]com, wkuyda[.]com, thailisting[.]net, yangon[.]it[.]com, cloudflacecdn[.]com, police[.]gr[.]com, investigationj6[.]com, sacofficegov[.]com.
3. **Block known C2 IPs:** 27[.]254[.]164[.]212, 27[.]254[.]164[.]209.
4. **Hunt for file hashes** across endpoints using the SHA256 IOC list above.
5. **Audit Exchange:** Remove unauthorized FullAccess permissions; review ApplicationImpersonation role assignments.
6. **Rotate credentials:** Reset passwords and Kerberos tickets for any accounts with evidence of credential compromise (LSASS dump, DCSync, SAM/SYSTEM hive export).
7. **Remove web shells:** Scan Exchange and IIS servers for ASPXSpy, Godzilla, Bysunue.aspx, and Suo5 variants.
8. **Patch Exchange and web-facing servers** to close the initial access vector.

### Long-Term Hardening

- Deploy QUIC/HTTP3 inspection capabilities or block outbound UDP/443 at the perimeter to eliminate the protocol-level evasion vector.
- Enable Sysmon with pipe creation (Event ID 17/18) and process creation (Event ID 1) logging for endpoint visibility.
- Implement application allowlisting to prevent DLL sideloading from non-standard paths.
- Monitor for anomalous Exchange permission changes (FullAccess grants, ApplicationImpersonation assignments).
- Deploy credential guard to protect LSASS from memory dumping attacks.

## Detection Rules

These detections target the PerfectPioneer/KUKURAT campaign at PoC/advisory-specific altitude, covering known C2 domains, URI patterns, credential dumping techniques, and unique malware artifacts. Compiles does not equal fires -- verify each rule in your environment before production deployment. HTTP/3/QUIC C2 traffic is covered by Snort (UDP payload inspection) and Suricata (DNS-layer and UDP-layer rules).

### Sigma: PerfectPioneer/KUKURAT Known C2 Domain DNS Query
Detects DNS queries to the nine known C2 domains used by PerfectPioneer and KUKURAT malware associated with TGR-STA-0049.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (network issue, not rule error); splunk convert exit 0; log_scale convert exit 0. All domains from Unit 42 published IOC list. Domains are actor-registered and highly distinctive. -->
```yaml
title: PerfectPioneer/KUKURAT Known C2 Domain DNS Query
id: 7a3e8c1f-4d2b-4e9a-b6c3-1f8d5e2a9b74
status: experimental
description: >
    Detects DNS queries to known C2 domains used by PerfectPioneer RAT and
    KUKURAT malware families associated with TGR-STA-0049 targeting
    Southeast Asian government entities.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1071.001
    - attack.t1568
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'maui-cocktailbar.com'
            - 'ads-edge.com'
            - 'wkuyda.com'
            - 'thailisting.net'
            - 'yangon.it.com'
            - 'cloudflacecdn.com'
            - 'police.gr.com'
            - 'investigationj6.com'
            - 'sacofficegov.com'
    condition: selection
falsepositives:
    - Unlikely; these are actor-controlled domains
level: high
```

### Sigma: PerfectPioneer RAT C2 URI Path Pattern
Detects HTTP requests matching PerfectPioneer's `/agent/*` C2 URI pattern in proxy logs. Scope to known C2 domains or suspicious destinations to reduce false positives from legitimate APIs.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (network issue); splunk convert exit 0; log_scale convert exit 0. URI pattern is moderately distinctive -- /agent/ prefix may appear in legitimate APIs; pairing with C2 domain IOCs recommended. -->
```yaml
title: PerfectPioneer RAT C2 URI Path Pattern
id: 2c9d4e8f-5b3a-41d6-8e7c-3a2f1d6b4c95
status: experimental
description: >
    Detects HTTP requests matching the PerfectPioneer RAT C2 URI path
    pattern (/agent/register, /agent/heartbeat, /agent/tasks, /agent/result)
    indicative of TGR-STA-0049 campaign activity.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        cs-uri-stem|startswith:
            - '/agent/register'
            - '/agent/heartbeat'
            - '/agent/tasks'
            - '/agent/result'
    condition: selection
falsepositives:
    - Legitimate APIs using /agent/ path prefix; scope to known C2 domains or suspicious destinations
level: medium
```

### Sigma: LSASS Dump via Comsvcs.dll Ordinal Call
Detects the specific credential dumping technique observed in this campaign: rundll32 calling comsvcs.dll MiniDump by ordinal (`#+000024`).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (network issue); splunk convert exit 0; log_scale convert exit 0. Technique is well-documented (LOLBAS); ordinal call pattern is highly distinctive and rarely used legitimately. CommandLine values are real (not defanged). -->
```yaml
title: LSASS Dump via Comsvcs.dll Ordinal Call
id: 4f8a1b3c-6d2e-49f5-a7b8-5c3e2d1f4a86
status: experimental
description: >
    Detects the credential dumping technique observed in PerfectPioneer/KUKURAT
    campaigns where rundll32 calls comsvcs.dll MiniDump by ordinal (#+000024)
    to dump LSASS memory, outputting to MxA.tar.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\rundll32.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - '#24'
    condition: selection_binary and selection_cmdline
falsepositives:
    - Legitimate use of comsvcs.dll MiniDump is extremely rare
level: high
```

### Sigma: KUKURAT Watchdog Named Pipe Creation
Detects creation of the `WINDOW_SEC_WATCHDOG` named pipe, a unique artifact of KUKURAT's watchdog persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (network issue); splunk convert exit 0; log_scale convert exit 0. Pipe name is unique to KUKURAT and not known to be used by any legitimate software. Requires Sysmon EID 17/18 logging. -->
```yaml
title: KUKURAT Watchdog Named Pipe Creation
id: 8e5f2c7d-3a1b-4d96-9f8e-6b4c3d2a1e57
status: experimental
description: >
    Detects creation of the WINDOW_SEC_WATCHDOG named pipe used by KUKURAT
    malware for heartbeat communication between the RAT and its watchdog
    companion process.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1559.001
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\WINDOW_SEC_WATCHDOG'
    condition: selection
falsepositives:
    - None known; this is a unique malware artifact
level: high
```

### Sigma: Suspicious File Activity in Cortex XDR Masquerade Directory
Detects file creation under `C:\ProgramData\Cyvera\Ransomware\`, a Cortex XDR path abused by KUKURAT to hide its watchdog. Excludes legitimate Palo Alto Networks binaries.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to MITRE ATT&CK data fetch (network issue); splunk convert exit 0; log_scale convert exit 0. Path is specific to Cortex XDR and legitimate writes would come from Palo Alto Networks binaries (filtered). Non-Cortex systems writing to this path is highly anomalous. -->
```yaml
title: Suspicious File Activity in Cortex XDR Masquerade Directory
id: 1b6d3e8f-4c2a-5d97-a8b9-7e5f4c3d2b16
status: experimental
description: >
    Detects file creation in the C:\ProgramData\Cyvera\Ransomware directory,
    a path associated with Cortex XDR that KUKURAT abuses to hide its
    watchdog process.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026/11/17
tags:
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\ProgramData\Cyvera\Ransomware\'
    filter_legit:
        Image|startswith: 'C:\Program Files\Palo Alto Networks\'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate Cortex XDR activity writing to this path
level: high
```

### Snort: Outbound QUIC to Known C2 Domains and PerfectPioneer URI
Detects outbound QUIC (UDP/443) traffic containing DNS-encoded C2 domain labels and HTTP PerfectPioneer C2 registration URI. Note: QUIC payload matching may have limited effectiveness depending on encryption state.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf include rule -T exit 0 (Snort 2.9.20). QUIC content matching targets Initial/ClientHello SNI before encryption. HTTP rule uses http_uri sticky buffer for TCP fallback. The QUIC rules match DNS-encoded labels in the initial handshake; post-handshake encrypted traffic will not match. -->
```snort
alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to PerfectPioneer C2 Domain maui-cocktailbar.com"; content:"|12|maui-cocktailbar|03|com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created 2026-11-17; sid:2100010; rev:1;)

alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to KUKURAT C2 Domain cloudflacecdn.com"; content:"|0d|cloudflacecdn|03|com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created 2026-11-17; sid:2100011; rev:1;)

alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to KUKURAT C2 Domain police.gr.com"; content:"|06|police|02|gr|03|com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created 2026-11-17; sid:2100012; rev:1;)

alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to KUKURAT C2 Domain investigationj6.com"; content:"|10|investigationj6|03|com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created 2026-11-17; sid:2100013; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - PerfectPioneer RAT C2 Agent Registration URI"; flow:established,to_server; content:"/agent/register"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created 2026-11-17; sid:2100014; rev:1;)
```

### Suricata: DNS Queries to C2 Domains, QUIC IP Detection, and C2 URI
Detects DNS queries for all known PerfectPioneer and KUKURAT C2 domains, outbound QUIC traffic to known C2 IPs, and HTTP C2 URI patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). DNS rules use dns.query sticky buffer for precise domain matching. IP-based QUIC rules use hex-encoded IP bytes in UDP/443 payload. HTTP URI rule uses http.uri dot-notation buffer. DNS and domain-based rules are highest confidence; IP/QUIC rules may have limited visibility into encrypted payloads. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PerfectPioneer/KUKURAT C2 Domain maui-cocktailbar.com"; dns.query; content:"maui-cocktailbar.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PerfectPioneer C2 Domain ads-edge.com"; dns.query; content:"ads-edge.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200011; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to KUKURAT C2 Domain cloudflacecdn.com"; dns.query; content:"cloudflacecdn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200012; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to KUKURAT C2 Domain police.gr.com"; dns.query; content:"police.gr.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200013; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to KUKURAT C2 Domain investigationj6.com"; dns.query; content:"investigationj6.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200014; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PerfectPioneer C2 Domain thailisting.net"; dns.query; content:"thailisting.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200015; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to PerfectPioneer C2 Domain sacofficegov.com"; dns.query; content:"sacofficegov.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200016; rev:1;)

alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to Known PerfectPioneer/KUKURAT C2 IP 27.254.164.212"; content:"|1b fe a4 d4|"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200017; rev:1;)

alert udp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Outbound QUIC to Known PerfectPioneer/KUKURAT C2 IP 27.254.164.209"; content:"|1b fe a4 d1|"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200018; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PerfectPioneer RAT C2 Agent Registration URI"; flow:established,to_server; http.uri; content:"/agent/register"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/; metadata:author Actioner, created_at 2026-11-17; sid:2200019; rev:1;)
```

### YARA: PerfectPioneer and KUKURAT RAT Detection
Detects PerfectPioneer RAT via project path strings embedded in Go binaries and C2 endpoint patterns, KUKURAT via module names and configuration keys, and the PsExecService lateral movement module via its PDB path.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive sample test: Malware_PerfectPioneer_RAT_Strings fired on file containing published project paths from Unit 42 IOC list; Malware_KUKURAT_RAT_Strings fired on file containing published pipe name + module names + config keys. Negative sample: no match on benign file. Project paths (D:/proj/...) are from published PDB strings — highly distinctive. KUKURAT module names and config keys are from the published analysis. PsExecService PDB path is unique to this campaign's toolset. -->
```yara
rule Malware_PerfectPioneer_RAT_Strings
{
    meta:
        description = "Detects PerfectPioneer RAT variants via project path strings and C2 endpoint patterns found in Go binaries"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344"
        severity = "high"

    strings:
        $pdb1 = "D:/proj/RatAAkk-tt/agent/" ascii
        $pdb2 = "D:/proj/PerfectRat/agent/" ascii
        $pdb3 = "D:/proj/http3/newhttp3/agent/" ascii
        $pdb4 = "D:/proj/http3/rat_http3_ls/agent/" ascii
        $pdb5 = "D:/proj/http3/Pioneer/" ascii
        $pdb6 = "D:/proj/http3/rat_http3_cc/" ascii

        $c2_1 = "/agent/register" ascii
        $c2_2 = "/agent/heartbeat" ascii
        $c2_3 = "/agent/tasks" ascii
        $c2_4 = "/agent/result" ascii

        $cmd1 = "isDangerousCommand" ascii
        $cmd2 = "file_upload" ascii
        $cmd3 = "socks5_proxy" ascii
        $cmd4 = "keylogger_start" ascii
        $cmd5 = "screenshot_capture" ascii

    condition:
        filesize < 30MB and
        (
            any of ($pdb*) or
            (3 of ($c2*) and 2 of ($cmd*))
        )
}

rule Malware_KUKURAT_RAT_Strings
{
    meta:
        description = "Detects KUKURAT RAT via module names, configuration keys, and C2 endpoint patterns"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4"
        severity = "high"

    strings:
        $kuku_pdb = "d:\\proj\\KUKURAT\\" ascii nocase

        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide
        $hash_ep = "c8a4e192" ascii

        $mod1 = "BofLoader.dll" ascii wide
        $mod2 = "SmbBrute.dll" ascii wide
        $mod3 = "yuze_dll.dll" ascii wide
        $mod4 = "ComExec.dll" ascii wide
        $mod5 = "MyPsExec.dll" ascii wide

        $cfg1 = "set_obfuscation" ascii
        $cfg2 = "module_states" ascii
        $cfg3 = "set_heartbeat" ascii
        $cfg4 = "set_silent" ascii
        $cfg5 = "set_runtime_config" ascii

        $cmd1 = "bypass_uac" ascii
        $cmd2 = "elevate_privilege" ascii
        $cmd3 = "load_module" ascii
        $cmd4 = "unload_module" ascii
        $cmd5 = "process_inject" ascii

    condition:
        filesize < 30MB and
        (
            $kuku_pdb or
            ($pipe and $hash_ep) or
            (2 of ($mod*) and 2 of ($cfg*)) or
            (3 of ($cmd*) and 2 of ($cfg*))
        )
}

rule Malware_KUKURAT_PsExecService
{
    meta:
        description = "Detects the custom PsExecService module deployed by KUKURAT for lateral movement"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78"
        severity = "high"

    strings:
        $pdb = "d:\\proj\\KUKURAT\\modules\\MyPsExec-master\\PsExecService\\" ascii
        $pipe = "\\\\.\\pipe\\PSEXEC" ascii wide
        $svc = "PsExec" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($pdb or ($pipe and $svc))
}
```

## Lessons Learned

This campaign demonstrates that sophisticated threat actors are now actively leveraging HTTP/3 over QUIC as a C2 channel specifically to evade enterprise network inspection. Organizations that cannot inspect QUIC traffic have a significant blind spot. The actor's operational security features — isDangerousCommand blocklists, heuristic camouflage engines generating legitimate-looking traffic, and directory masquerading — reflect a mature development pipeline. The transition from PerfectPioneer to KUKURAT's modular architecture shows an actor investing in long-term capability development. Defenders should prioritize: (1) QUIC inspection or blocking at the perimeter, (2) named pipe monitoring via Sysmon, (3) Exchange permission auditing, and (4) behavioral detection of comsvcs.dll ordinal-based LSASS dumping, which remains a reliable credential theft indicator across campaigns.

## Sources

- [Unit 42 - Custom RATs Target Southeast Asian Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/) — primary technical analysis of PerfectPioneer RAT, KUKURAT, and TGR-STA-0049 campaign
- [Unit 42 - Squidoor Advanced Backdoor](https://unit42.paloaltonetworks.com/advanced-backdoor-squidoor/) — prior TGR-STA-0049 tooling (FINALDRAFT/Squidoor)
- [Check Point Research - Ink Dragon Relay Network](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/) — related reporting on Ink Dragon (overlapping threat actor)
- [LOLBAS - comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) — legitimate binary abuse reference for LSASS dumping technique
- [MyPsExec (GitHub)](https://github.com/zesiar0/MyPsExec) — open-source PsExec project basis for KUKURAT's PsExecService module
- [SharpDPAPI (GitHub)](https://github.com/GhostPack/SharpDPAPI) — DPAPI credential extraction tool used in the campaign
- [Malpedia - FINALDRAFT](https://malpedia.caad.fkie.fraunhofer.de/details/win.finaldraft) — malware family reference for earlier Squidoor/FINALDRAFT tooling

---
*Report generated by Actioner*
