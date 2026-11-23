# PerfectPioneer RAT & KUKURAT -- HTTP/3 C2 RATs Targeting Southeast Asian Governments

> **Status:** Draft -- generated 2026-11-23 by Actioner
> **Altitude:** PoC / advisory-specific
> **Viability Gate:** PASS -- Unit 42 primary research with 60+ SHA256 hashes, 9 C2 domains, 2 C2 IPs, PDB paths, named pipes, full C2 protocol documentation, process chains, and persistence mechanisms. Exceptionally rich IOC set supports all rule types.

<!-- audit: source fetched 2026-11-23; Unit 42 blog (primary). All IOCs extracted from single authoritative source. Sigma check blocked by MITRE ATT&CK data fetch (network proxy 403); sigma convert to splunk and loki used as structural validation -- all 6 rules parse and convert cleanly. YARA: 5/5 pass yara-python compile. Suricata: structural check only (no suricata binary available). -->

---

## Executive Summary

Unit 42 (Palo Alto Networks) published primary research on a cyberespionage campaign by threat actor **TGR-STA-0049** (also tracked as REF7707, Earth Alux, Ink Dragon) targeting Southeast Asian government entities. The campaign deploys two novel remote access trojans: **PerfectPioneer** (a custom modular Go-based RAT with at least 6 identified variants) and **KUKURAT** (a modular C++ framework). Both RATs use **HTTP/3 over QUIC (UDP 443)** for command-and-control, with PerfectPioneer falling back to HTTP/2 when QUIC fails. The actor gains initial access via web shells on Exchange and web servers, then deploys RATs via DLL side-loading, decoy installers, and disguised PDF executables. Post-compromise activity includes LSASS credential dumping (via comsvcs.dll ordinal #24), Exchange mailbox FullAccess delegation for email collection, SMB brute-forcing, and lateral movement via a custom PsExecService module. KUKURAT features a companion watchdog process that masquerades as Cortex XDR (placed in `C:\ProgramData\Cyvera\Ransomware\`), heuristic camouflage generating decoy HTTP traffic, and a silent mode that suppresses all activity for configurable periods.

### Sources

| Tag | Source |
|-----|--------|
| Unit 42 (primary) | [Custom RATs Target Southeast Asia Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/) |

---

## Infection Chain

```
Web Shell (ASPXSpy, Godzilla, Suo5, Bysunue.aspx variants) on Exchange/IIS
  --> PerfectPioneer RAT deployed for initial recon
      Delivery vectors:
      (a) DLL Side-Loading: Modified legitimate EXE + malicious loader DLL
          --> Loader reads XOR-encrypted shellcode from modified host binary
          --> Decrypts and executes RAT agent in memory
      (b) Decoy Installer: GlobalProtect installer runs visibly
          --> RAT agent runs silently in background
      (c) Disguised PDF: Executable with PDF icon
          --> Opens decoy PDF (Myanmar election document)
          --> RAT agent runs silently

  --> PerfectPioneer persists via:
      - HKCU\...\Run (registry Run key)
      - Startup folder .lnk shortcut

  --> C2 communication: HTTP/3 (QUIC UDP/443) or HTTP/2 fallback
      Endpoints: /agent/register, /agent/heartbeat, /agent/tasks, /agent/result

  --> KUKURAT deployed into already-compromised networks (from March 2026)
      - Domain logon script modified in SYSVOL for execution on user logon
      - Watchdog companion in C:\ProgramData\Cyvera\Ransomware\
      - Named pipe heartbeat: WINDOW_SEC_WATCHDOG
      - C2 endpoints hashed (e.g., /heartbeat -> /c8a4e192)

  --> Post-compromise:
      - LSASS dump: rundll32.exe comsvcs.dll #+000024 -> \Windows\Temp\MxA.tar
      - SAM/SYSTEM hive dump
      - SharpDPAPI credential extraction
      - Exchange: Get-Mailbox | Add-MailboxPermission -AccessRights FullAccess
      - SMB brute force (SmbBrute.dll module)
      - Lateral movement: PsExecService.exe (custom, self-uninstalls after 5 min)
      - Data exfiltration: .pdf, .docx, .xlsx, .png files (international relations content)
```

---

## Indicators of Compromise

### File Hashes (SHA-256)

#### PerfectPioneer RAT Variants

| Hash | Variant | Component |
|------|---------|-----------|
| `2281e754f70e11298db1a0a7c1b527cf2b5eec2056d4c73a46ed572ab873dc6e` | RatAAkk-tt | Agent |
| `9721d65ee7695db2b3dc3705f5d8e5efe3a478c3b6d1704d66daf77fe95aeb0d` | RatAAkk-tt | Agent |
| `d725ad8b523c94f99fca9e72a650e835dca47b9ebe7610d6c4eb3525d410c365` | RatAAkk-tt | Agent |
| `f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457` | PerfectRat | Agent |
| `19bb3012d846f3672fb98dad0449ae5c267ab30150800b2f1559036564c7d0b8` | PerfectRat | Agent |
| `92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67` | rat_http3_ls | Agent |
| `ab06f540ecdd1d45491aa71bfc04c80852371c8f5cd43b9a6ebb53f1e1b69588` | Pioneer | Decoy installer |
| `bf59f8d7ef79b09a72bbb9c05ca8746466d03226a3779cc1096ba067117ca008` | Pioneer | Core agent |
| `8bf9401990d3255d1022a25884b02ee75ef01bd1a729d29ff52de2e5f0d637a2` | Pioneer | Core agent |
| `5f857ff78bfbef2a55a846fc93744e11e07a9b72ee3fc3bc345c32ce9615ddee` | newhttp3 | Modified host binary |
| `61f7e2f4159c566578e88cb05cdf49e4378f45ebddbd332224e97c11df922120` | newhttp3 | Loader DLL |
| `5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344` | newhttp3 | Core agent |
| `cd8f43da32849584751eec884cf7e3208eb0a71108197a32e9bb248612e757d2` | newhttp3 | Core agent |
| `7541222a1316ec54bf9c8660b923e1d0490a925b2ee92060b1567be7cb1bde4b` | newhttp3 | Core agent |
| `cffcd6f2589d3ab4f3693805d1752b7c328a00cc543dd02b129763e179c3f311` | newhttp3 | Core agent |
| `5805cb5b0a6fb738ef7c1873b8e5de4281c36c7f440f28717fa9f441c5e0ef17` | newhttp3 | Core agent |
| `a6a9ccffadd00b0e75e913b0f851b1f834fd20588df8b89759d9ae49a48c8e10` | newhttp3 | Core agent |
| `b975f5932c04b381f8fa58a3303194f1aff950d3c6cd12dcc1d323bb3393718b` | rat_http3_cc | Modified host binary |
| `904409ce8846394e1fe9a5ce37f2265cbf6933611278ae57fdf5fa74759af2bb` | rat_http3_cc | Modified host binary |
| `d700b573ea8387efad633a70124b7a2a3aece844a267157b1cb55be7b62f3b67` | rat_http3_cc | Modified host binary |
| `52d3442fb26023ebc0bc76542b56be88d1c3327c8bcedf1dcb95f80511527f07` | rat_http3_cc | Modified host binary |
| `8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70` | rat_http3_cc | Loader DLL |
| `619b749e1c6634d38f15c51005a4237e9076aaaf36927b562a990e8bc34fdfcb` | rat_http3_cc | Core agent |
| `fb5b0b1d083d6f6afa90948bd1fd1a498b51dd3f6dc7f90a02a2a17818756563` | rat_http3_cc | Core agent |
| `183abf82951c2052e9a1829c70c173c11756e8df0e86c8071c27df0988caeaa0` | rat_http3_cc | Core agent |
| `0533365accbba405757de7eb486533c11c8e0510a28d414ee8c5e6b8a41ed97b` | Unknown | Agent |
| `3cb5376a5e6c0fcbd6844ab76f3dc73a42da7ecee6ecaaef285d4abe33964fa1` | Unknown | Agent |
| `f5ebe85418655d75d1a760543858846db1478a060875fd19ddaa5e2febc038d7` | Unknown | Agent |
| `b5bea4d8b94fbb39ac992e8e763680af6f39d12d42e264b43431fb61cf7b9a88` | Unknown | Modified host binary |
| `7745523939fc6b31b6a73d8ca1f363c62438b6eef56f6fe8c39e71fcd14b65f4` | Unknown | Modified host binary |

#### PerfectPioneer Loader DLL Components

| Hash |
|------|
| `0c49e1b98a236d3391740473101b66dd48c719fa4112dbef3816b56bce58e6e7` |
| `24c46bc9269e1c1ee54004e01d5c7c54f759bc1b93a282d3561d2d27f678af86` |
| `e5689e1bf916c2f7649e178008e790ea13eb844aefc14516c06b0da8296377a1` |
| `63eac14921f138fffe73db417c12afd16d64202ebbee7ad5f08068697d2942d0` |
| `790e6699704395a7fad633f4e502312bc43693a44a8e18d43239209eefbd7ff2` |
| `f82c06184ab36e91d28f7802c739e637792c241a7ff2fba9ca24178f12423684` |
| `2e52b2936e67872d1364d2d0d26a8733ed9582b38f6f0b3a877ffdd6e2c04aa4` |
| `9dfefc7118646535d1193e1b036dd0c93fa66cc585a60301fcdceb6f45903aad` |
| `600572a912650b258d56aedeef0ab712abbe35a38cdd23faa5a95dacfdc67b7f` |
| `86194c3b3cc7a58e439621aff42e116ca94d40f3a6f539f20ce483f1cf5a7191` |
| `e8cd6bbcf6073669a7415ce0c9009a0fbb5551bf5e17803be12ef295f0c99889` |
| `5b779b81a9bb25591ecac6bd74bb44a4a5b2b8f257093f9efd5910346ab8d772` |

#### PerfectPioneer Additional Variants

| Hash |
|------|
| `c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02` |
| `bf8afbd1c2074c7cd6ff8b86dbe67a57ca5594817e46b24e226b71c4edde7697` |

#### KUKURAT

| Hash | Variant | Component |
|------|---------|-----------|
| `b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4` | HTTP/3 | Agent |
| `9fb0976fcd1f92c4711726a91cff8be9a39944efedc4caf2d80f935327f8f490` | HTTP/3 | Agent |
| `7225ef57161cf0908560811be798d22e9354c071d576540a43aa7900784c0688` | HTTP/2 | Agent |
| `a214d264c6bb0d2ba89986f73e196ea200307574745a245fc42c32fbef4cc140` | HTTP/2 | Agent |
| `662dc73e11b60b2f12c94b6b68da45de7bffece4b1dcc75679ed020629d0705d` | HTTP/2 | Agent |
| `b062b4d8c19baf5c1568e28b3e0a5e2318e9501ea61ddfe804d9755c1bdbf887` | -- | Watchdog |
| `34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78` | -- | PsExecService.exe |

#### SharpDPAPI

| Hash |
|------|
| `0cbde9b7f59dafca80f214121a04eda7804b920da28ce1c06939a4783e6b097f` |
| `cdc9757294d3063eb10c9a37d1d945d31f6857c652b864803815406b02eeefbf` |

#### Web Shells

| Hash |
|------|
| `99f571c07170250a84f0ae9de4179044df91244855d9b39978729933ea3d438f` |
| `7ee22a7b028102bb22f0a41d41cd101d5956c1db0cfd157b22bf4128bd472a4f` |
| `571067cc8f4224a4b80113b52672c7ac87e25dcdb0282a36a29a1784a24efa27` |
| `8d8ccf24b785a33a9388043baecc4be247ad01182b87df3f8e425957ef73087c` |
| `0e01c44e5a0615098d8c583930dd88dbd0ce6fe54b365c9f04d8b315a93f540a` |
| `1dd423ff0106b15fd100dbc24c3ae9f9860a1fcdb6a871a1e27576f6681a0850` |
| `04be76217500275335e82eb4c2c1588478f7a171efd7a0d9bdc6bbe83e315589` |
| `3deb43cc864f2322d374541d99af79d87ad08abf81cd967862c554f1c0c5fdb6` |
| `224ed1d3f8d7247989f812cb0accc1d1804197916c47d9600e6c4e9bef46a723` |
| `9b16333820189e94b2368e87cba0a9642595d5be0f985a6351f1ad834f5cd11d` |
| `bdcd0eefc62721814d0bd557285490aa99a4eb0425bf5204e6be16ec7ce93823` |
| `3e56d049f23ed45a7034e5c74bad45cae11ce6d15189fa7bda6b8d120439c7cc` |
| `834491282da22555f53b769ef8ad91a958f860c583ee5cb67b3f161caf19f854` |

#### Unmapped

| Hash |
|------|
| `82a989c728db4e09a2b85a4a55f7663cefa62844632cb16dcda5ca70bf09a8a5` |
| `71d897427329ca14dd621e777046dc35f3d9dc870d3b13a56125125391a56afe` |
| `6781f84417d0056df95ed38b3e7a6b49312d30119470356f6923238d49de3490` |
| `dd02d28c48cf5cabd35a0b32e05e7c99ff0de35541201026ae36c59e54968c78` |
| `e59b08eb03ffa10ccf9103d171af757308e6d43519c4e904ef5e0929ef92d8fd` |

### Network Indicators

| Indicator | Type | Role |
|-----------|------|------|
| `www.maui-cocktailbar[.]com` | Domain | PerfectPioneer C2 |
| `ads-edge[.]com` | Domain | PerfectPioneer C2 |
| `www.wkuyda[.]com` | Domain | PerfectPioneer C2 |
| `www.thailisting[.]net` | Domain | PerfectPioneer C2 |
| `www.yangon.it[.]com` | Domain | PerfectPioneer C2 |
| `www.cloudflacecdn[.]com` | Domain | KUKURAT C2 |
| `www.police.gr[.]com` | Domain | KUKURAT C2 |
| `www.investigationj6[.]com` | Domain | KUKURAT C2 |
| `www.sacofficegov[.]com` | Domain | Associated |
| `27.254.164[.]212` | IPv4 | C2 infrastructure |
| `27.254.164[.]209` | IPv4 | C2 infrastructure |

### File System Artifacts

| Path / File | Purpose |
|-------------|---------|
| `C:\ProgramData\Cyvera\Ransomware\` | KUKURAT watchdog directory (Cortex XDR impersonation) |
| `\Windows\Temp\MxA.tar` | LSASS dump output |
| `PsExecService.exe` | KUKURAT lateral movement module |
| `SecurityGuard.exe` | Not recovered -- associated component |
| Startup folder `.lnk` shortcut | PerfectPioneer persistence |

### Registry Indicators

| Key | Purpose |
|-----|---------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | PerfectPioneer persistence |
| `HKCU\Software\Google\Chrome\BrowserCrashRecovery` | KUKURAT camouflage (write/read/delete) |
| `HKCU\Software\Google\Update\ClientState` | KUKURAT camouflage (enumeration) |

### Named Pipes

| Pipe Name | Purpose |
|-----------|---------|
| `WINDOW_SEC_WATCHDOG` | KUKURAT watchdog heartbeat |
| `\\.\pipe\PSEXEC` | PsExecService lateral movement |

### Project / PDB Paths

| Path | Component |
|------|-----------|
| `D:/proj/RatAAkk-tt/agent/` | PerfectPioneer variant |
| `D:/proj/PerfectRat/agent/` | PerfectPioneer variant |
| `D:/proj/http3/newhttp3/agent/` | PerfectPioneer variant |
| `D:/proj/http3/rat_http3_ls/agent/` | PerfectPioneer variant |
| `D:/proj/http3/Pioneer/` | PerfectPioneer variant |
| `D:/proj/http3/rat_http3_cc/` | PerfectPioneer variant |
| `d:\proj\KUKURAT\modules\MyPsExec-master\PsExecService\` | KUKURAT module |

### KUKURAT Module DLLs

| Module | Capability |
|--------|------------|
| `MyPsExec.dll` | Remote execution via named pipe |
| `SmbBrute.dll` | SMB credential brute force |
| `yuze_dll.dll` | Unknown |
| `ComExec.dll` | COM-based execution |
| `BofLoader.dll` | Beacon Object File loader |

### C2 Protocol Details

**PerfectPioneer:**
- Transport: HTTP/3 (QUIC, UDP 443) with HTTP/2 fallback
- Endpoints: `/agent/register`, `/agent/heartbeat`, `/agent/tasks`, `/agent/result`
- rat_http3_cc local listener: TCP 56793 with `/`, `/info`, `/health`, `/status`
- Written in Go

**KUKURAT:**
- Transport: HTTP/3 (QUIC, UDP 443) or HTTP/2 depending on variant
- Endpoints hashed in code (e.g., `/heartbeat` -> `/c8a4e192`)
- Written in C++
- Registration data: hostname, username, integrity level, OS, architecture, host IP, random agent ID
- Heartbeat payload: session_id, heartbeat interval min/max, silent mode state, loaded modules, module states
- Default config: heartbeat_timeout_ms=300000, command_worker_threads=5, module_exec_timeout_ms=600000
- Camouflage: 10 decoy HTTP requests per cycle to 15 hard-coded popular sites

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | Actor Activity |
|--------|----|-----------|----------------|
| Initial Access | T1190 | Exploit Public-Facing Application | Exchange/IIS web shells |
| Initial Access | T1566.001 | Spearphishing Attachment | Disguised PDF executables |
| Execution | T1204.002 | User Execution: Malicious File | Decoy installer, fake PDF |
| Execution | T1569.002 | Service Execution | PsExecService |
| Execution | T1047 | WMI | Lateral movement |
| Execution | T1559.001 | Component Object Model | ComExec.dll module |
| Persistence | T1547.001 | Registry Run Keys | HKCU Run key |
| Persistence | T1547.009 | Shortcut Modification | Startup folder .lnk |
| Persistence | T1037.003 | Network Logon Script | SYSVOL logon script modification |
| Persistence | T1543.003 | Windows Service | PsExec service (self-deleting) |
| Defense Evasion | T1574.002 | DLL Side-Loading | Loader DLL with modified host binary |
| Defense Evasion | T1036 | Masquerading | Cortex XDR directory, Chrome registry |
| Defense Evasion | T1027 | Obfuscated Files | XOR shellcode, hashed endpoints |
| Defense Evasion | T1070.004 | File Deletion | Self-cleaning temp files |
| Credential Access | T1003.001 | LSASS Memory | comsvcs.dll ordinal #24 dump |
| Credential Access | T1003.002 | SAM | SAM/SYSTEM hive dump |
| Credential Access | T1555 | Credentials from Password Stores | SharpDPAPI |
| Discovery | T1046 | Network Service Discovery | Port scanning |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | PsExec, SmbBrute |
| Lateral Movement | T1021.006 | WinRM | Remote execution |
| Collection | T1114.002 | Remote Email Collection | Exchange FullAccess delegation |
| Collection | T1056.001 | Keylogging | KUKURAT keylogger module |
| Collection | T1113 | Screen Capture | KUKURAT screenshot module |
| C2 | T1071.001 | Web Protocols | HTTP/3 over QUIC |
| C2 | T1090 | Proxy | SOCKS5 proxy capability |
| C2 | T1055 | Process Injection | KUKURAT process_inject command |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | File exfiltration over HTTP/3 |
| Impact | T1098.002 | Exchange Email Delegate Permissions | Bulk FullAccess grants |

---

## Campaign Timeline

| Date | Event |
|------|-------|
| March 2023+ | TGR-STA-0049 active with Squidoor/FINALDRAFT tooling |
| July 2025 | PerfectPioneer RAT first observed |
| March 2026 | KUKURAT deployed into already-compromised networks |
| November 2026 | Unit 42 publishes research |

---

## Detection Rules

### Sigma Rules

All six Sigma rules validate via `sigma convert --without-pipeline -t splunk` and `sigma convert --without-pipeline -t loki`. `sigma check` could not run (MITRE ATT&CK data fetch blocked by network proxy).

---

#### SIGMA-1: PerfectPioneer Registry Run Key Persistence

Detects registry Run key persistence set by PerfectPioneer RAT variants where the executable path references the fake Cortex XDR directory (`C:\ProgramData\Cyvera\Ransomware\`).

**Status:** compile PASS (splunk + loki convert clean) -- confidence: high

```yaml
title: PerfectPioneer RAT - Registry Run Key Persistence
id: a1b2c3d4-1111-4aaa-bbbb-100000000001
status: experimental
description: Detects registry Run key persistence set by PerfectPioneer RAT variants (RatAAkk-tt, rat_http3_cc) targeting Southeast Asian government entities. The RAT writes to HKCU Run for automatic launch on user logon.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run'
    selection_suspicious_paths:
        Details|contains:
            - '\ProgramData\Cyvera\'
            - '\Ransomware\'
    condition: selection_key and selection_suspicious_paths
falsepositives:
    - Cortex XDR installations using C:\ProgramData\Cyvera path (legitimate Cortex XDR uses different subdir names)
level: high
```

<!-- audit: SIGMA-1 -- advisory-specific. Keys on Run key + Cyvera\Ransomware path combination. FP risk: low (legitimate Cortex XDR does not use Ransomware subdir). Splunk: TargetObject="*\Software\Microsoft\Windows\CurrentVersion\Run*" Details IN ("*\ProgramData\Cyvera\*", "*\Ransomware\*"). -->

---

#### SIGMA-2: LSASS Dump via comsvcs.dll Ordinal 24

Detects the LSASS credential dumping technique used by TGR-STA-0049 operators. The actor uses `rundll32.exe` to call `comsvcs.dll` MiniDump by ordinal (`#+000024`) to avoid string-based detection, dumping output to `\Windows\Temp\MxA.tar`.

**Status:** compile PASS (splunk + loki convert clean) -- confidence: critical

```yaml
title: PerfectPioneer - LSASS Dump via comsvcs.dll Ordinal 24
id: a1b2c3d4-1111-4aaa-bbbb-100000000002
status: experimental
description: Detects the LSASS credential dumping technique used by TGR-STA-0049 operators via PerfectPioneer campaigns. The actor uses rundll32.exe to call comsvcs.dll MiniDump by ordinal number (+000024 / #24) to avoid string-based detection, dumping LSASS to a tar file in Windows\Temp.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll32:
        Image|endswith: '\rundll32.exe'
    selection_comsvcs_ordinal:
        CommandLine|contains:
            - 'comsvcs.dll'
    selection_ordinal_patterns:
        CommandLine|contains:
            - '#+000024'
            - '#24'
            - 'MiniDump'
    selection_output:
        CommandLine|contains:
            - '\Windows\Temp\MxA.tar'
    condition: selection_rundll32 and selection_comsvcs_ordinal and (selection_ordinal_patterns or selection_output)
falsepositives:
    - Legitimate crash dump collection tools using comsvcs.dll MiniDump (should be investigated)
level: critical
```

<!-- audit: SIGMA-2 -- behavioral + advisory-specific. The comsvcs.dll + ordinal pattern is well-known but the MxA.tar output path is campaign-specific. The OR structure catches either the ordinal trick or the unique output path. FP risk: very low for the campaign-specific path, low-moderate for the generic ordinal pattern. -->

---

#### SIGMA-3: KUKURAT Chrome Registry Camouflage

Detects non-Chrome processes writing to `HKCU\Software\Google\Chrome\BrowserCrashRecovery`, a heuristic camouflage technique used by KUKURAT to blend with Chrome telemetry.

**Status:** compile PASS (splunk + loki convert clean) -- confidence: high

```yaml
title: KUKURAT - Suspicious Chrome Registry Camouflage Activity
id: a1b2c3d4-1111-4aaa-bbbb-100000000003
status: experimental
description: Detects KUKURAT RAT heuristic camouflage behavior where the malware writes to, reads back, and deletes values under HKCU\Software\Google\Chrome\BrowserCrashRecovery and enumerates HKCU\Software\Google\Update\ClientState to blend in with legitimate Chrome telemetry.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Google\Chrome\BrowserCrashRecovery'
    filter_chrome:
        Image|endswith: '\chrome.exe'
    condition: selection and not filter_chrome
falsepositives:
    - Third-party Chrome management or monitoring tools writing to this specific subkey
level: high
```

<!-- audit: SIGMA-3 -- behavioral rule. BrowserCrashRecovery is not a standard Chrome registry key used by legitimate tools. Any non-chrome.exe process writing there is suspicious. FP risk: low. -->

---

#### SIGMA-4: KUKURAT Watchdog Named Pipe

Detects creation of the `WINDOW_SEC_WATCHDOG` named pipe used by the KUKURAT watchdog for heartbeat communication with the main RAT agent.

**Status:** compile PASS (splunk + loki convert clean) -- confidence: critical

```yaml
title: KUKURAT - Watchdog Named Pipe WINDOW_SEC_WATCHDOG
id: a1b2c3d4-1111-4aaa-bbbb-100000000004
status: experimental
description: Detects creation of the WINDOW_SEC_WATCHDOG named pipe used by the KUKURAT watchdog component for heartbeat communication with the main RAT agent. The watchdog relaunches KUKURAT after 15 seconds without a heartbeat.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.execution
    - attack.t1559
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\WINDOW_SEC_WATCHDOG'
    condition: selection
falsepositives:
    - None known
level: critical
```

<!-- audit: SIGMA-4 -- advisory-specific IOC. WINDOW_SEC_WATCHDOG is a unique pipe name with no known legitimate use. FP risk: near-zero. Requires Sysmon Event ID 17/18. -->

---

#### SIGMA-5: Exchange Mailbox FullAccess Permission Grant

Detects PowerShell execution of `Add-MailboxPermission` with FullAccess, used by TGR-STA-0049 for bulk email collection after compromising Exchange servers.

**Status:** compile PASS (splunk + loki convert clean) -- confidence: high

```yaml
title: TGR-STA-0049 - Exchange Mailbox FullAccess Permission Grant
id: a1b2c3d4-1111-4aaa-bbbb-100000000005
status: experimental
description: Detects bulk Exchange mailbox FullAccess permission grants used by TGR-STA-0049 operators for email collection. The actor pipes Get-Mailbox results into Add-MailboxPermission with FullAccess access rights via web shells on compromised Exchange servers.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.collection
    - attack.t1114.002
    - attack.t1098.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_exchange_commands:
        CommandLine|contains|all:
            - 'Add-MailboxPermission'
            - 'FullAccess'
    condition: selection_powershell and selection_exchange_commands
falsepositives:
    - Legitimate Exchange administration scripts granting FullAccess permissions (should be audited)
level: high
```

<!-- audit: SIGMA-5 -- behavioral rule applicable beyond this campaign. Any Add-MailboxPermission + FullAccess via PowerShell warrants investigation. FP risk: moderate in Exchange admin environments (tune with known admin accounts). -->

---

#### SIGMA-6: Executable in Fake Cortex XDR Directory

Detects process execution from `C:\ProgramData\Cyvera\Ransomware\`, a directory path used by KUKURAT watchdog to masquerade as a Cortex XDR component.

**Status:** compile PASS (splunk + loki convert clean) -- confidence: critical

```yaml
title: KUKURAT - Executable in Fake Cortex XDR Directory
id: a1b2c3d4-1111-4aaa-bbbb-100000000006
status: experimental
description: Detects process execution from C:\ProgramData\Cyvera\Ransomware, a directory path used by KUKURAT watchdog to masquerade as a Cortex XDR component. Legitimate Cortex XDR uses C:\ProgramData\Cyvera but not a Ransomware subdirectory for executable files.
references:
    - https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
author: Actioner
date: 2026-11-23
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\ProgramData\Cyvera\Ransomware\'
    condition: selection
falsepositives:
    - None known - legitimate Cortex XDR does not place executables in a Ransomware subdirectory
level: critical
```

<!-- audit: SIGMA-6 -- advisory-specific IOC. The Cyvera\Ransomware path is unique to this campaign. FP risk: near-zero. -->

---

### YARA Rules

All five YARA rules validate via `yara-python 4.5.4` compile.

---

#### YARA-1: PerfectPioneer Go Agent

Detects PerfectPioneer RAT Go-based agent variants by matching embedded project paths, C2 endpoint patterns, `isDangerousCommand` blocklist strings, and C2 domain indicators.

**Status:** compile PASS (yara-python 4.5.4) -- confidence: high

```yara
rule PerfectPioneer_RAT_Go_Agent
{
    meta:
        description = "Detects PerfectPioneer RAT Go-based agent variants (RatAAkk-tt, PerfectRat, rat_http3_ls, Pioneer, newhttp3, rat_http3_cc) by matching project paths, C2 endpoint patterns, and isDangerousCommand blocklist strings"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "2281e754f70e11298db1a0a7c1b527cf2b5eec2056d4c73a46ed572ab873dc6e"
        hash2 = "f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457"
        hash3 = "92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67"
        hash4 = "ab06f540ecdd1d45491aa71bfc04c80852371c8f5cd43b9a6ebb53f1e1b69588"

    strings:
        // Project paths embedded in Go binaries
        $pdb1 = "D:/proj/RatAAkk-tt/agent/" ascii
        $pdb2 = "D:/proj/PerfectRat/agent/" ascii
        $pdb3 = "D:/proj/http3/newhttp3/agent/" ascii
        $pdb4 = "D:/proj/http3/rat_http3_ls/agent/" ascii
        $pdb5 = "D:/proj/http3/Pioneer/" ascii
        $pdb6 = "D:/proj/http3/rat_http3_cc/" ascii

        // C2 HTTP endpoints
        $ep1 = "/agent/register" ascii
        $ep2 = "/agent/heartbeat" ascii
        $ep3 = "/agent/tasks" ascii
        $ep4 = "/agent/result" ascii

        // isDangerousCommand blocklist (distinctive subset)
        $cmd1 = "isDangerousCommand" ascii
        $cmd2 = "cipher /w:" ascii
        $cmd3 = "crontab -r" ascii
        $cmd4 = "bcdedit" ascii
        $cmd5 = "curl | sh" ascii
        $cmd6 = "wget | bash" ascii
        $cmd7 = "powershell -enc" ascii

        // Local HTTP listener (rat_http3_cc)
        $local1 = "/info" ascii
        $local2 = "/health" ascii
        $local3 = "/status" ascii

        // C2 domains
        $c2_1 = "maui-cocktailbar" ascii
        $c2_2 = "ads-edge.com" ascii
        $c2_3 = "wkuyda.com" ascii
        $c2_4 = "thailisting.net" ascii
        $c2_5 = "yangon.it.com" ascii

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            (3 of ($ep*) and 2 of ($cmd*)) or
            ($cmd1 and 3 of ($cmd*)) or
            2 of ($c2*) or
            (3 of ($local*) and any of ($ep*))
        )
}
```

<!-- audit: YARA-1 -- multi-tier condition. Tier 1: any PDB path is a direct hit (high confidence). Tier 2: C2 endpoints + command blocklist (medium-high, the endpoint paths are common but combined with blocklist strings raises confidence). Tier 3: isDangerousCommand function name + 3 blocklist entries (high, unique function name). Tier 4: 2+ C2 domains (high, campaign-specific). Tier 5: local listener + C2 endpoint (medium). -->

---

#### YARA-2: PerfectPioneer Loader DLL

Detects PerfectPioneer loader DLL that side-loads from a modified legitimate binary, reads XOR-encrypted shellcode, and launches the in-memory agent.

**Status:** compile PASS (yara-python 4.5.4) -- confidence: medium

```yara
rule PerfectPioneer_Loader_DLL
{
    meta:
        description = "Detects PerfectPioneer loader DLL that side-loads from a modified legitimate binary, reads XOR-encrypted shellcode, and launches the in-memory agent"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "61f7e2f4159c566578e88cb05cdf49e4378f45ebddbd332224e97c11df922120"
        hash2 = "8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70"

    strings:
        // XOR decryption patterns common in PE loader stubs
        $xor_loop = { 30 ?? 4? 3B ?? 72 }
        $xor_loop2 = { 32 ?? 4? 3B ?? 72 }

        // VirtualAlloc + shellcode execution pattern
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "CreateThread" ascii

        // Known C2 domains that may be embedded in loader config
        $c2_1 = "maui-cocktailbar" ascii
        $c2_2 = "ads-edge" ascii
        $c2_3 = "thailisting" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($xor_loop*) and 2 of ($api*)) or
            1 of ($c2*)
        )
}
```

<!-- audit: YARA-2 -- medium confidence. The XOR loop + API pattern is generic for shellcode loaders; the C2 domain match is high confidence but may not appear in all loader variants. This rule should be used in combination with YARA-1 for confirmation. -->

---

#### YARA-3: KUKURAT C++ Agent

Detects KUKURAT modular C++ RAT by matching PDB project path, module DLL names, hashed C2 endpoints, named pipe, configuration defaults, and capability command strings.

**Status:** compile PASS (yara-python 4.5.4) -- confidence: high

```yara
rule KUKURAT_RAT_CPP_Agent
{
    meta:
        description = "Detects KUKURAT modular C++ RAT by matching PDB project path, module DLL names, hashed C2 endpoints, named pipe, and configuration defaults"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4"
        hash2 = "7225ef57161cf0908560811be798d22e9354c071d576540a43aa7900784c0688"

    strings:
        // PDB / project path
        $pdb1 = "KUKURAT" ascii wide
        $pdb2 = "d:\\proj\\KUKURAT\\" ascii nocase
        $pdb3 = "MyPsExec-master\\PsExecService" ascii

        // Module DLL names
        $mod1 = "MyPsExec.dll" ascii wide
        $mod2 = "SmbBrute.dll" ascii wide
        $mod3 = "yuze_dll.dll" ascii wide
        $mod4 = "ComExec.dll" ascii wide
        $mod5 = "BofLoader.dll" ascii wide

        // Named pipe for watchdog heartbeat
        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide

        // Hashed endpoint example
        $hash_ep = "/c8a4e192" ascii

        // C2 domains
        $c2_1 = "cloudflacecdn" ascii
        $c2_2 = "police.gr.com" ascii
        $c2_3 = "investigationj6" ascii

        // Configuration keys
        $cfg1 = "heartbeat_timeout_ms" ascii wide
        $cfg2 = "command_result_timeout_ms" ascii wide
        $cfg3 = "file_transfer_chunk_timeout_ms" ascii wide
        $cfg4 = "command_worker_threads" ascii wide
        $cfg5 = "module_exec_timeout_ms" ascii wide
        $cfg6 = "heartbeat_retry_before_rereg" ascii wide
        $cfg7 = "silent_mode_enabled" ascii wide
        $cfg8 = "loaded_modules" ascii wide
        $cfg9 = "module_states" ascii wide

        // Camouflage registry path
        $reg1 = "Google\\Chrome\\BrowserCrashRecovery" ascii wide
        $reg2 = "Google\\Update\\ClientState" ascii wide

        // KUKURAT capability command strings
        $cap1 = "bypass_uac" ascii wide
        $cap2 = "port_scan" ascii wide
        $cap3 = "proxy_start" ascii wide
        $cap4 = "download_module" ascii wide
        $cap5 = "process_inject" ascii wide
        $cap6 = "keylogger_start" ascii wide
        $cap7 = "powershell_execute" ascii wide
        $cap8 = "elevate_privilege" ascii wide
        $cap9 = "set_obfuscation" ascii wide
        $cap10 = "set_silent" ascii wide

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            3 of ($mod*) or
            ($pipe and 2 of ($cfg*)) or
            2 of ($c2*) or
            4 of ($cap*) or
            (($reg1 or $reg2) and 2 of ($cap*)) or
            ($hash_ep and $pipe)
        )
}
```

<!-- audit: YARA-3 -- multi-tier. PDB paths are direct hits. Module DLL names are distinctive (3-of-5 required). Named pipe + config keys is campaign-specific. C2 domains are IOC-based. Capability strings are distinctive command names (4-of-10 required to reduce FP from generic RAT terminology). -->

---

#### YARA-4: KUKURAT Watchdog Component

Detects the KUKURAT watchdog companion binary that monitors agent health via the `WINDOW_SEC_WATCHDOG` named pipe.

**Status:** compile PASS (yara-python 4.5.4) -- confidence: high

```yara
rule KUKURAT_Watchdog_Component
{
    meta:
        description = "Detects the KUKURAT watchdog companion binary that monitors agent health via WINDOW_SEC_WATCHDOG named pipe and relaunches the agent after 15 seconds of heartbeat silence"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "b062b4d8c19baf5c1568e28b3e0a5e2318e9501ea61ddfe804d9755c1bdbf887"

    strings:
        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide
        $path = "\\ProgramData\\Cyvera\\Ransomware\\" ascii wide
        $api1 = "CreateNamedPipe" ascii
        $api2 = "ConnectNamedPipe" ascii
        $api3 = "CreateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        $pipe and
        (1 of ($path, $api1, $api2, $api3))
}
```

<!-- audit: YARA-4 -- anchored on unique WINDOW_SEC_WATCHDOG pipe name + at least one supporting indicator. FP risk: near-zero. -->

---

#### YARA-5: KUKURAT PsExecService Module

Detects the KUKURAT PsExecService.exe lateral movement module with its distinctive PDB path and named pipe.

**Status:** compile PASS (yara-python 4.5.4) -- confidence: high

```yara
rule KUKURAT_PsExecService_Module
{
    meta:
        description = "Detects the KUKURAT PsExecService.exe lateral movement module that opens a named pipe server (PSEXEC) with shell, upload, download, and directory listing capabilities"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78"

    strings:
        $pdb = "MyPsExec-master\\PsExecService" ascii
        $pipe = "\\\\.\\ pipe\\PSEXEC" ascii wide nocase
        $pipe2 = "PSEXEC" ascii wide
        $svc = "PsExec" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        ($pdb or ($pipe and $svc) or ($pipe2 and $svc))
}
```

<!-- audit: YARA-5 -- PDB path is a direct hit. PSEXEC pipe + service name combination may also match legitimate Sysinternals PsExec; the PDB path differentiates. Use in conjunction with hash-based detection for confirmation. -->

---

### Suricata Rules

Structural check only (no Suricata binary available). 22 rules total: 9 DNS-based, 6 QUIC SNI-based (requires Suricata 7.0+), 4 IP-based, 3 HTTP endpoint-based.

**Note on QUIC/HTTP3 detection challenges:** HTTP/3 traffic is encrypted after the QUIC handshake, making deep packet inspection of C2 commands impossible without TLS termination. The QUIC SNI rules (SID 2026110010-2026110015) match the Server Name Indication in the cleartext QUIC Client Hello (Initial) packet. The DNS rules provide the broadest coverage. The HTTP endpoint rules (SID 2026110020-2026110022) require TLS decryption/inspection to function.

---

#### SURICATA-1 through SURICATA-9: DNS Lookups for C2 Domains

**Status:** structural PASS -- confidence: high

```
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE PerfectPioneer RAT C2 DNS Lookup (maui-cocktailbar)"; dns.query; content:"maui-cocktailbar"; nocase; classtype:trojan-activity; sid:2026110001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE PerfectPioneer RAT C2 DNS Lookup (ads-edge.com)"; dns.query; content:"ads-edge.com"; nocase; classtype:trojan-activity; sid:2026110002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE PerfectPioneer RAT C2 DNS Lookup (wkuyda.com)"; dns.query; content:"wkuyda.com"; nocase; classtype:trojan-activity; sid:2026110003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE PerfectPioneer RAT C2 DNS Lookup (thailisting.net)"; dns.query; content:"thailisting.net"; nocase; classtype:trojan-activity; sid:2026110004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE PerfectPioneer RAT C2 DNS Lookup (yangon.it.com)"; dns.query; content:"yangon.it.com"; nocase; classtype:trojan-activity; sid:2026110005; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE KUKURAT RAT C2 DNS Lookup (cloudflacecdn.com)"; dns.query; content:"cloudflacecdn"; nocase; classtype:trojan-activity; sid:2026110006; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE KUKURAT RAT C2 DNS Lookup (police.gr.com)"; dns.query; content:"police.gr.com"; nocase; classtype:trojan-activity; sid:2026110007; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE KUKURAT RAT C2 DNS Lookup (investigationj6.com)"; dns.query; content:"investigationj6"; nocase; classtype:trojan-activity; sid:2026110008; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETPRO MALWARE TGR-STA-0049 Associated Domain DNS Lookup (sacofficegov.com)"; dns.query; content:"sacofficegov"; nocase; classtype:trojan-activity; sid:2026110009; rev:1;)
```

---

#### SURICATA-10 through SURICATA-15: QUIC SNI Detection

**Status:** structural PASS -- confidence: high
**Requires:** Suricata 7.0+ with `quic.sni` keyword support

```
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PerfectPioneer QUIC C2 SNI (maui-cocktailbar)"; quic.sni; content:"maui-cocktailbar"; nocase; classtype:trojan-activity; sid:2026110010; rev:1;)
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PerfectPioneer QUIC C2 SNI (ads-edge.com)"; quic.sni; content:"ads-edge.com"; nocase; classtype:trojan-activity; sid:2026110011; rev:1;)
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PerfectPioneer QUIC C2 SNI (thailisting.net)"; quic.sni; content:"thailisting.net"; nocase; classtype:trojan-activity; sid:2026110012; rev:1;)
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE KUKURAT QUIC C2 SNI (cloudflacecdn.com)"; quic.sni; content:"cloudflacecdn"; nocase; classtype:trojan-activity; sid:2026110013; rev:1;)
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE KUKURAT QUIC C2 SNI (police.gr.com)"; quic.sni; content:"police.gr.com"; nocase; classtype:trojan-activity; sid:2026110014; rev:1;)
alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE KUKURAT QUIC C2 SNI (investigationj6.com)"; quic.sni; content:"investigationj6"; nocase; classtype:trojan-activity; sid:2026110015; rev:1;)
```

---

#### SURICATA-16 through SURICATA-19: IP-Based Detection

**Status:** structural PASS -- confidence: high (time-limited -- IPs may rotate)

```
alert udp $HOME_NET any -> 27.254.164.212 443 (msg:"ETPRO MALWARE TGR-STA-0049 C2 IP (27.254.164.212 UDP/443 QUIC)"; classtype:trojan-activity; sid:2026110016; rev:1;)
alert udp $HOME_NET any -> 27.254.164.209 443 (msg:"ETPRO MALWARE TGR-STA-0049 C2 IP (27.254.164.209 UDP/443 QUIC)"; classtype:trojan-activity; sid:2026110017; rev:1;)
alert tcp $HOME_NET any -> 27.254.164.212 443 (msg:"ETPRO MALWARE TGR-STA-0049 C2 IP (27.254.164.212 TCP/443 HTTP2 fallback)"; classtype:trojan-activity; sid:2026110018; rev:1;)
alert tcp $HOME_NET any -> 27.254.164.209 443 (msg:"ETPRO MALWARE TGR-STA-0049 C2 IP (27.254.164.209 TCP/443 HTTP2 fallback)"; classtype:trojan-activity; sid:2026110019; rev:1;)
```

---

#### SURICATA-20 through SURICATA-22: HTTP Endpoint Detection (requires TLS inspection)

**Status:** structural PASS -- confidence: medium (requires TLS decryption)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PerfectPioneer HTTP C2 Registration Endpoint"; http.uri; content:"/agent/register"; http.host; content:"maui-cocktailbar"; classtype:trojan-activity; sid:2026110020; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE PerfectPioneer HTTP C2 Heartbeat Endpoint"; http.uri; content:"/agent/heartbeat"; http.host; content:"maui-cocktailbar"; classtype:trojan-activity; sid:2026110021; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO MALWARE KUKURAT HTTP C2 Hashed Heartbeat Endpoint"; http.uri; content:"/c8a4e192"; classtype:trojan-activity; sid:2026110022; rev:1;)
```

---

## Analyst Notes

### QUIC/HTTP3 Detection Strategy

The use of HTTP/3 over QUIC for C2 presents significant detection challenges:

1. **Encrypted payload**: After the QUIC handshake, all HTTP/3 frames are encrypted. Traditional DPI cannot inspect C2 commands, heartbeats, or exfiltrated data within QUIC streams.

2. **Detection surface**: The only cleartext elements are:
   - DNS lookups (best coverage)
   - QUIC Initial packet SNI (Suricata 7.0+ `quic.sni` keyword)
   - Destination IP/port (UDP 443)

3. **Recommended approach**: Organizations should monitor outbound UDP 443 traffic anomalies (volume, frequency, destination diversity), correlate with DNS logs for known C2 domains, and consider QUIC traffic analysis tools for behavioral detection.

4. **PerfectPioneer HTTP/2 fallback**: The newhttp3 variant falls back to HTTP/2 when QUIC fails, providing a secondary detection opportunity via TLS inspection of HTTP/2 traffic.

### Behavioral Indicators Worth Monitoring

- **isDangerousCommand safety switch**: PerfectPioneer actively blocks destructive commands, suggesting the operator values stealth over scorched-earth capability. This is characteristic of long-term espionage operations.
- **KUKURAT silent mode**: The `set_silent` command suppresses all activity for configurable periods, indicating awareness of incident response timelines.
- **Decoy traffic**: KUKURAT generates 10 decoy HTTP requests per cycle to 15 popular sites, inflating legitimate traffic to mask C2 patterns.
- **Self-cleaning**: newhttp3 deletes temp files and forces Go garbage collection above 100 MB, minimizing forensic artifacts.
- **Resource monitoring**: newhttp3 records CPU and memory every 30 seconds, potentially to avoid detection by resource-based anomaly detectors.
