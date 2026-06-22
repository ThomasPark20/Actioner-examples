# Technical Analysis Report: CryptoBandits USB Clipper Worm (2026-06-22)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-22
Version: 1.0-DRAFT

## Executive Summary

CryptoBandits is an active Windows-based cryptocurrency-stealing malware campaign first observed in February 2026 and publicly detailed by Microsoft Threat Intelligence on June 17, 2026. The malware comprises two components: a worm that propagates via USB drives by replacing legitimate document files with malicious LNK shortcuts, and a clipper/stealer that intercepts clipboard content every ~500ms to steal cryptocurrency seed phrases, private keys, and wallet addresses. The stealer substitutes copied wallet addresses with attacker-controlled ones, captures screenshots, and communicates exclusively over Tor hidden services using a bundled portable Tor client renamed `ugate.exe`. The C2 channel supports remote code execution via an "EVAL" command, making this malware a lightweight backdoor in addition to a financial stealer. Microsoft Defender Antivirus detects the threat as Trojan:Win32/CryptoBandits.A and related variants.

## Background: Windows Cryptocurrency Users

This campaign targets Windows users who handle cryptocurrency assets -- wallet addresses, seed phrases, and private keys commonly copied via clipboard during transactions. The attack exploits the widespread practice of transferring files via USB drives, using social engineering through file-type impersonation (replacing DOC, XLSX, and PDF files with identically named LNK shortcuts). The malware's lightweight, script-based architecture (JavaScript executed via Windows Script Host) and Tor-based C2 make it difficult to detect with traditional network monitoring.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| February 2026 | First observed CryptoBandits infections |
| 2026-06-17 | Microsoft Threat Intelligence publishes detailed analysis |
| 2026-06-18 to 2026-06-19 | Secondary reporting by The Hacker News, BleepingComputer, SecurityWeek |
| 2026-06-22 | This analysis produced |

## Root Cause: Malicious LNK Files on USB Drives

Initial access occurs when a user inserts an infected USB drive and opens what appears to be a legitimate document file. The worm component has replaced original DOC, XLSX, and PDF files on the USB with malicious Windows shortcut (.lnk) files bearing identical names. The hidden originals remain on the drive. When the LNK is opened, it executes the worm payload via WScript/CScript, which checks for existing infection, downloads additional payloads from C2 through Tor, and deploys both the worm and stealer components.

## Technical Analysis of the Malicious Payload

### 1. USB Worm Propagation

The worm component monitors for newly connected USB storage devices via a scheduled task. When a removable drive is detected, the worm:

- Scans for files with `.doc`, `.xlsx`, and `.pdf` extensions
- Hides the original files (sets hidden attribute)
- Creates replacement `.lnk` shortcut files with identical names
- The LNK files invoke wscript.exe or cscript.exe to execute the worm payload
- Checks for existing infection before re-deploying payloads

### 2. Clipper/Stealer Component

The stealer operates as a JavaScript payload executed by Windows Script Host, using ActiveXObject for OS interaction. Core capabilities:

- **Clipboard monitoring** every ~500ms, matching:
  - 12-word and 24-word BIP39 seed phrases
  - Ethereum private keys
  - Bitcoin WIF keys
  - Bitcoin addresses (legacy "1", P2SH "3", Bech32 "bc1q", Taproot "bc1p")
  - Tron addresses (starting with "T", 34 characters)
  - Monero addresses (starting with "4" or "8", 95 characters)
- **Wallet address substitution**: replaces detected wallet addresses with attacker-controlled alternatives, matching first/last characters to reduce visual suspicion
- **Screenshot capture**: five screenshots every ten seconds, exfiltrated via curl through Tor
- **C2 action codes**: GUID (heartbeat), SEED (seed phrase exfil), PKEY (private key exfil), REPL (address replacement notification)

### 3. C2 Infrastructure

The malware deploys a portable Tor client renamed to `ugate.exe`, executed in a hidden window. After a ~60-second Tor bootstrap wait, it establishes a local SOCKS5 proxy on `localhost:9050`. Communication uses curl with `--socks5-hostname localhost:9050` flags to reach Tor hidden service C2 servers.

**C2 Endpoints:**
- `/route.php` -- beacon and command retrieval
- `/recvf.php` -- file upload (screenshots)
- `/stub.php` -- payload download

**C2 .onion domains (published by Microsoft):**
- `cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad[.]onion`
- `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad[.]onion`
- `he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad[.]onion`
- `lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad[.]onion`
- `j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd[.]onion`
- `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion`
- `7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid[.]onion`
- `facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd[.]onion`
- `wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid[.]onion`
- `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion`

The C2 generates a unique victim identifier (GUID) combined with geolocation data (GEIP) for registration. The stealer polls the C2 every ~500ms for instructions. If the C2 returns an "EVAL" response, the malware executes arbitrary JScript code, making it a full remote code execution backdoor.

### 4. Platform-Specific Behavior

#### Windows

This malware exclusively targets Windows systems. It relies on:
- Windows Script Host (wscript.exe / cscript.exe) for execution
- ActiveXObject for OS interaction (WScript.Shell, Win32_Process WMI class)
- curl.exe (present in Windows 10+ by default) for data exfiltration
- PowerShell for screenshot capture
- schtasks.exe for persistence
- cmd.exe for command execution

**Deployment path:** `C:\Users\Public\Documents\[5-char-name]\` with two JavaScript payload files and a scheduled task XML file.

**Scheduled task creation pattern:** `schtasks.exe /create /tn [a-z]{4,6} /xml C:\Users\Public\Documents\[a-z]{4,6}\[a-z]{4,6}.xml /f`

### 5. Anti-Forensics / Evasion Techniques

- **Anti-analysis:** queries WMI `Win32_Process` class and terminates execution if Task Manager (taskmgr.exe) is detected among running processes
- **Multi-layered obfuscation:** all components are encrypted with runtime-only decryption; dual-layer JavaScript obfuscation with shuffled strings and decoder functions
- **Python obfuscation:** PyArmor-protected Python scripts packaged via PyInstaller
- **Defender exclusions:** creates Windows Defender scanning exclusions for the staging folders and Windows binaries used by the malware
- **Hidden Tor execution:** ugate.exe runs in a hidden window to avoid visual detection
- **File hiding:** original USB files are hidden; replaced with LNK files of the same name

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `domain[.]onion`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\Users\Public\Documents\[5-char]\[5-char].js` | See hash list below | JavaScript stealer/worm payload |
| Windows | `C:\Users\Public\Documents\[5-char]\[5-char].xml` | -- | Scheduled task XML configuration |
| Windows | `C:\Users\Public\Documents\[5-char]\ugate.exe` | -- | Renamed portable Tor client |

**Published SHA-256 hashes (Microsoft):**

| SHA-256 | Description |
|---------|-------------|
| `7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c` | CryptoBandits sample |
| `a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630` | CryptoBandits sample |
| `23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43` | CryptoBandits sample |
| `cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30` | CryptoBandits sample |
| `100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8` | CryptoBandits sample |
| `d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f` | CryptoBandits sample |
| `9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96` | CryptoBandits sample |
| `67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5` | CryptoBandits sample |
| `0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a` | CryptoBandits sample |
| `35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd` | CryptoBandits sample |
| `c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502` | CryptoBandits sample |
| `d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba` | CryptoBandits sample |
| `b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f` | CryptoBandits sample |
| `7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05` | CryptoBandits sample |
| `f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0` | CryptoBandits sample |
| `20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1` | CryptoBandits sample |

### Network

| Type | Value | Context |
|------|-------|---------|
| Tor hidden service | `cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad[.]onion` | C2 server |
| Tor hidden service | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad[.]onion` | C2 server |
| Tor hidden service | `he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad[.]onion` | C2 server |
| Tor hidden service | `lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad[.]onion` | C2 server |
| Tor hidden service | `j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd[.]onion` | C2 server |
| Tor hidden service | `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion` | C2 server |
| Tor hidden service | `7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid[.]onion` | C2 server |
| Tor hidden service | `facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd[.]onion` | C2 server |
| Tor hidden service | `wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid[.]onion` | C2 server |
| Tor hidden service | `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion` | C2 server |
| SOCKS5 proxy | `127.0.0.1:9050` | Local Tor proxy endpoint |
| URL pattern | `/route.php` | C2 beacon/command retrieval |
| URL pattern | `/recvf.php` | Screenshot upload endpoint |
| URL pattern | `/stub.php` | Payload download endpoint |

### Behavioral

- WScript/CScript spawning curl.exe with `--socks5-hostname localhost:9050` arguments
- ugate.exe execution from `C:\Users\Public\Documents\` subdirectory
- Scheduled task creation via schtasks.exe with XML from `C:\Users\Public\Documents\` subdirectory
- JavaScript execution from `C:\Users\Public\Documents\` subdirectory via wscript.exe/cscript.exe
- Clipboard access every ~500ms with pattern matching for cryptocurrency formats
- Screenshot capture via PowerShell every 10 seconds
- Process enumeration via WMI Win32_Process class checking for taskmgr.exe
- Windows Defender exclusion creation for malware staging directories

### Detection Signatures (Microsoft Defender)

| Detection Name | Type |
|----------------|------|
| Trojan:Win32/CryptoBandits.A | Antivirus |
| Trojan:Win32/CryptoBandits.B | Antivirus |
| Trojan:JS/CryptoBandits.A | Antivirus |
| Trojan:JS/CryptoBandits.B | Antivirus |
| Behavior:Win64/PyPowJs.STA | Behavioral |
| Behavior:Win64/ProcessExclusion.ST | Behavioral |
| Behavior:Win64/PathExclusion.STA | Behavioral |
| Behavior:Win64/PathExclusion.STB | Behavioral |
| Behavior:Win64/CurlOnion.STA | Behavioral |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1091 | Replication Through Removable Media | Worm propagates by creating malicious LNK files on USB drives, replacing legitimate DOC/XLSX/PDF files |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | Uses WScript/CScript to execute JavaScript payloads via Windows Script Host |
| T1059.007 | Command and Scripting Interpreter: JavaScript | JavaScript-based stealer and worm payloads |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used for screenshot capture |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Creates scheduled tasks with randomized names for persistence of both worm and stealer components |
| T1115 | Clipboard Data | Monitors clipboard every ~500ms for seed phrases, private keys, and wallet addresses |
| T1113 | Screen Capture | Captures five screenshots every ten seconds for exfiltration |
| T1090 | Proxy | Deploys portable Tor client (ugate.exe) as local SOCKS5 proxy on port 9050 |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltrates screenshots and stolen data via curl through Tor |
| T1027 | Obfuscated Files or Information | Multi-layered runtime decryption, shuffled strings, PyArmor obfuscation |
| T1057 | Process Discovery | Queries Win32_Process WMI class to detect Task Manager (anti-analysis) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Creates Windows Defender scanning exclusions for staging folders |
| T1105 | Ingress Tool Transfer | Downloads additional payloads from C2 via /stub.php endpoint |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Hides original USB files and replaces them with LNK shortcuts |

## Impact Assessment

The campaign targets individual Windows users who handle cryptocurrency, particularly those who transfer files via USB drives. The impact is primarily financial: stolen seed phrases and private keys provide complete access to cryptocurrency wallets, while address substitution diverts transactions to attacker-controlled wallets. The "EVAL" backdoor capability extends the impact beyond financial theft to full system compromise. The worm's USB propagation mechanism enables lateral spread through shared physical media, making it particularly dangerous in environments where USB drives circulate among users (offices, schools, shared workstations). No specific victim counts or financial loss figures have been published.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for ugate.exe (renamed Tor binary)
Get-Process -Name "ugate" -ErrorAction SilentlyContinue

# Check for CryptoBandits staging directory pattern
Get-ChildItem "C:\Users\Public\Documents\" -Directory | Where-Object { $_.Name -match '^[a-z]{5}$' }

# Check for suspicious scheduled tasks with short random names
Get-ScheduledTask | Where-Object { $_.TaskName -match '^[a-z]{4,6}$' }

# Check for localhost:9050 connections (Tor SOCKS5 proxy)
netstat -ano | findstr ":9050"

# Check for Defender exclusions in Public Documents
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Where-Object { $_ -like '*Public\Documents*' }

# Search for known hashes
Get-ChildItem "C:\Users\Public\Documents\" -Recurse -File | Get-FileHash -Algorithm SHA256 | Where-Object { $_.Hash -in @('7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c','a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630','23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43') }
```

### Remediation

1. **Isolate** affected systems from the network immediately
2. **Kill** any running wscript.exe/cscript.exe processes associated with suspicious JavaScript files in `C:\Users\Public\Documents\`
3. **Terminate** the ugate.exe process to shut down the Tor proxy
4. **Remove** the staging directory under `C:\Users\Public\Documents\[5-char-name]\`
5. **Delete** associated scheduled tasks: `schtasks /delete /tn [task-name] /f`
6. **Remove** Windows Defender exclusions added by the malware
7. **Scan** all USB drives previously connected to the affected system; restore hidden files and remove malicious LNK shortcuts
8. **Rotate** all cryptocurrency seed phrases, private keys, and wallet addresses that may have been exposed
9. **Review** transaction history for any unauthorized address substitutions
10. **Update** Microsoft Defender definitions and run a full system scan

### Long-Term Hardening

- Enforce USB device control policies to block unauthorized removable media
- Deploy application whitelisting to prevent unauthorized script execution via wscript.exe/cscript.exe
- Monitor for Tor traffic patterns (connections to port 9050, Tor directory authorities)
- Enable PowerShell script block logging and Windows command-line auditing
- Implement clipboard monitoring policies in high-value environments
- Consider disabling Windows Script Host via Group Policy where not required

## Detection Rules

These rules target distinctive CryptoBandits artifacts: the `ugate.exe` Tor proxy binary, WScript-to-curl-SOCKS5 process chains, Public Documents staging paths, scheduled task creation patterns, and localhost:9050 Tor proxy connections. Compiles does not equal fires -- verify each rule in your pipeline with representative telemetry before promoting to production.

### Sigma: WScript/CScript Spawning Curl with Tor SOCKS5 Proxy

Detects the campaign's most distinctive process chain: wscript.exe or cscript.exe launching curl.exe with `--socks5-hostname localhost:9050` arguments for Tor-proxied C2 communication.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on parent-child + specific cmdline args. Very low FP surface — wscript spawning curl with Tor SOCKS5 args is highly anomalous. -->
```yaml
title: CryptoBandits - WScript/CScript Spawning Curl with Tor SOCKS5 Proxy
id: 8a3f7c12-4e9b-4d1a-b6c5-2e8f0a9d3b7e
status: experimental
description: >
    Detects wscript.exe or cscript.exe spawning curl.exe with SOCKS5 proxy
    arguments pointing to localhost:9050, consistent with the CryptoBandits
    crypto clipper using Tor for C2 communication and data exfiltration.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
    - https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html
author: Actioner
date: 2026/06/22
tags:
    - attack.t1059.005
    - attack.t1090
    - attack.t1048.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_child:
        Image|endswith: '\curl.exe'
        CommandLine|contains|all:
            - 'socks5'
            - 'localhost:9050'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate scripts using Tor SOCKS5 proxy via curl (unlikely in enterprise)
level: high
```

### Sigma: Execution of ugate.exe Tor Proxy Binary

Detects execution of `ugate.exe`, the renamed portable Tor binary deployed by CryptoBandits for C2 anonymization.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on distinctive binary name. "ugate.exe" is not a known legitimate binary name. Evasion: adversary could rename; but this is the published artifact. -->
```yaml
title: CryptoBandits - Execution of ugate.exe Tor Proxy Binary
id: c5d2e8f1-3a7b-4c96-9e0d-1f4a6b8c2d5e
status: experimental
description: >
    Detects execution of ugate.exe, a renamed portable Tor client binary
    used by the CryptoBandits campaign to establish a local SOCKS5 proxy
    for anonymous C2 communication over Tor hidden services.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
    - https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html
author: Actioner
date: 2026/06/22
tags:
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ugate.exe'
    condition: selection
falsepositives:
    - Legitimate software using a binary named ugate.exe (uncommon)
level: high
```

### Sigma: Scheduled Task Created from Public Documents Subfolder

Detects schtasks.exe creating a scheduled task using an XML definition file from a subdirectory of `C:\Users\Public\Documents\`, consistent with CryptoBandits persistence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on specific cmdline pattern: /create + /xml + Public\Documents path. Low FP — scheduled tasks from Public\Documents are unusual. -->
```yaml
title: CryptoBandits - Scheduled Task Created from Public Documents Subfolder
id: 7e9a1b3c-5d2f-4a86-b8c0-6e3f2d7a4c9e
status: experimental
description: >
    Detects schtasks.exe creating a task using an XML file located in a
    subfolder of C:\Users\Public\Documents, consistent with CryptoBandits
    persistence mechanism using randomized 4-6 character folder names.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
    - https://www.bleepingcomputer.com/news/security/usb-worm-spreads-crypto-stealing-malware-via-windows-shortcut-files/
author: Actioner
date: 2026/06/22
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/xml'
            - '\Users\Public\Documents\'
    condition: selection
falsepositives:
    - Legitimate software creating scheduled tasks with XML configs in Public Documents
level: high
```

### Sigma: Script Execution from Public Documents Subfolder

Detects wscript.exe or cscript.exe executing .js files from `C:\Users\Public\Documents\` subdirectories, the CryptoBandits payload staging location.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Medium confidence because legitimate scripts could reside in Public\Documents, though uncommon in enterprise. Keys on specific path + js extension. -->
```yaml
title: CryptoBandits - Script Execution from Public Documents Subfolder
id: a2b4c6d8-1e3f-5a7b-9c0d-8e6f4a2b0c1d
status: experimental
description: >
    Detects wscript.exe or cscript.exe executing JavaScript files from a
    subfolder of C:\Users\Public\Documents, consistent with the CryptoBandits
    malware staging its JS payloads in randomized subdirectories under
    that path.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
    - https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html
author: Actioner
date: 2026/06/22
tags:
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains: '\Users\Public\Documents\'
        CommandLine|endswith: '.js'
    condition: selection
falsepositives:
    - Legitimate scripts deployed in Public Documents (uncommon in enterprise)
level: medium
```

### Sigma: Outbound Connection to Localhost SOCKS5 Proxy Port 9050

Detects processes connecting to localhost on port 9050, the default Tor SOCKS5 proxy port used by CryptoBandits via `ugate.exe`. Scope to environments where Tor Browser is not authorized to reduce false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0; splunk 0; log_scale 0. Medium confidence: port 9050 is standard Tor, so legitimate Tor users will trigger. Distinctive in enterprise environments where Tor is not sanctioned. Requires Sysmon EID 3 or equivalent. -->
```yaml
title: CryptoBandits - Outbound Connection to Localhost SOCKS5 Proxy Port 9050
id: d3e5f7a9-2b4c-6d8e-0f1a-3b5c7d9e1f2a
status: experimental
description: >
    Detects processes connecting to localhost on port 9050, the default Tor
    SOCKS5 proxy port. The CryptoBandits campaign deploys a portable Tor
    client (ugate.exe) that listens on this port for proxying C2 traffic.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
    - https://www.securityweek.com/cryptobandits-malware-doubles-as-a-backdoor-abuses-tor/
author: Actioner
date: 2026/06/22
tags:
    - attack.t1090
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationIp: '127.0.0.1'
        DestinationPort: 9050
    condition: selection
falsepositives:
    - Tor Browser or legitimate Tor relay operators
    - Privacy-focused applications using Tor
level: medium
```

### Snort: CryptoBandits Tor SOCKS5 Proxy Connection

Detects TCP connections to localhost port 9050 with SOCKS5 handshake initiation byte, indicating potential CryptoBandits Tor proxy activity.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -T exit 0 (validated via snort -c snort.conf -R cb.rules -T from /etc/snort). SOCKS5 version byte 0x05 at offset 0 is the SOCKS5 greeting. Medium confidence: any SOCKS5 client connecting to 9050 will match; distinctive in enterprise networks without sanctioned Tor. -->
```snort
alert tcp $HOME_NET any -> 127.0.0.1 9050 (msg:"Actioner - CryptoBandits Tor SOCKS5 Proxy Connection to localhost:9050"; flow:established, to_server; content:"|05|"; depth:1; detection_filter:track by_src, count 5, seconds 60; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/; sid:2100001; rev:1;)
```

### Suricata: CryptoBandits Tor SOCKS5 Proxy Connection

Detects TCP connections to localhost port 9050 with SOCKS5 initiation, indicating potential CryptoBandits Tor proxy activity.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Threshold reduces noise. Medium confidence: any SOCKS5 connection to 9050 will match. -->
```suricata
alert tcp $HOME_NET any -> 127.0.0.1 9050 (msg:"Actioner - CryptoBandits Tor SOCKS5 Proxy Connection to localhost:9050"; flow:established,to_server; content:"|05|"; depth:1; threshold:type both, track by_src, count 5, seconds 60; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/; metadata:author Actioner, created_at 2026-06-22; sid:2200001; rev:1;)
```

### YARA: CryptoBandits Clipper JS Payload Strings

Detects CryptoBandits JavaScript payloads via distinctive C2 endpoint paths (`/route.php`, `/recvf.php`, `/stub.php`), action codes (`SEED`, `PKEY`, `REPL`, `EVAL`), and Tor proxy arguments (`socks5-hostname`, `localhost:9050`, `ugate.exe`).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive (published strings in pos_cb.txt) matched CryptoBandits_Clipper_JS_Strings + CryptoBandits_Clipper_Hashes; negative (benign JS) silent. Keys on published C2 endpoints and action codes — highly distinctive string combination. -->
```yara
rule CryptoBandits_Clipper_JS_Strings
{
    meta:
        description = "Detects CryptoBandits crypto clipper JavaScript payload via distinctive C2 endpoint paths, action codes, and Tor proxy arguments"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "high"

    strings:
        $c2_route = "/route.php" ascii wide
        $c2_recv = "/recvf.php" ascii wide
        $c2_stub = "/stub.php" ascii wide
        $act_seed = "SEED" ascii
        $act_pkey = "PKEY" ascii
        $act_repl = "REPL" ascii
        $act_eval = "EVAL" ascii
        $socks = "socks5-hostname" ascii wide
        $proxy = "localhost:9050" ascii wide
        $tor_bin = "ugate.exe" ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*) and 2 of ($act_*)) or
            ($tor_bin and $socks and $proxy) or
            (3 of ($c2_*) and $socks)
        )
}
```

### YARA: CryptoBandits Known Sample Strings

Detects CryptoBandits samples by co-occurrence of C2 endpoint strings, Tor proxy binary name, and Windows scripting object references. Published SHA-256 hashes included in meta for hash-based lookup.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: fired on positive. Condition requires 4 of 7 strings — combination of route.php + recvf.php + ugate.exe + ActiveXObject/WScript.Shell/Win32_Process is distinctive to this campaign. Hash meta enables hash-match in platforms that support YARA meta hash lookup. -->
```yara
rule CryptoBandits_Clipper_Hashes
{
    meta:
        description = "Detects known CryptoBandits crypto clipper samples by matching known internal strings"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        hash1 = "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c"
        hash2 = "a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630"
        hash3 = "23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43"
        hash4 = "cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30"
        hash5 = "100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8"
        hash6 = "d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f"
        hash7 = "9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96"
        hash8 = "67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5"
        hash9 = "0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a"
        hash10 = "35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd"
        hash11 = "c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502"
        hash12 = "d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba"
        hash13 = "b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f"
        hash14 = "7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05"
        hash15 = "f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0"
        hash16 = "20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1"
        severity = "critical"

    strings:
        $s1 = "route.php" ascii wide
        $s2 = "recvf.php" ascii wide
        $s3 = "ugate.exe" ascii wide
        $s4 = "socks5-hostname" ascii wide
        $s5 = "ActiveXObject" ascii wide
        $s6 = "WScript.Shell" ascii wide
        $s7 = "Win32_Process" ascii wide

    condition:
        filesize < 10MB and 4 of ($s*)
}
```

### YARA: CryptoBandits LNK USB Worm

Detects malicious LNK shortcut files matching the CryptoBandits USB worm pattern: LNK magic bytes at offset 0, with WScript/CScript invocation referencing `\Users\Public\Documents\` and `.js` extension.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: constructed LNK with magic bytes + path pattern fired correctly; negative benign JS silent. LNK magic at offset 0 + Public\Documents + .js is a tight condition. -->
```yara
rule CryptoBandits_LNK_USB_Worm
{
    meta:
        description = "Detects malicious LNK shortcut files used by CryptoBandits for USB worm propagation, matching WScript/CScript invocation patterns targeting Public Documents"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "high"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $wscript = "wscript" ascii wide nocase
        $cscript = "cscript" ascii wide nocase
        $public_docs = "\\Users\\Public\\Documents\\" ascii wide nocase
        $js_ext = ".js" ascii wide

    condition:
        $lnk_magic at 0 and
        filesize < 100KB and
        ($wscript or $cscript) and
        $public_docs and
        $js_ext
}
```

## Lessons Learned

This campaign demonstrates that simple, script-based malware can be highly effective when it combines social engineering (file-type impersonation on USB drives), commodity anonymization (Tor), and targets high-value assets (cryptocurrency). The reliance on Windows Script Host and built-in tools (curl, PowerShell, schtasks) makes this a living-off-the-land attack at its core, though the distinctive `ugate.exe` binary and `C:\Users\Public\Documents\` staging path provide clear detection opportunities. Organizations handling cryptocurrency should treat USB device control and script execution policies as critical security controls, not optional hardening measures.

## Sources

- [Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/) -- primary technical analysis with IOCs, hashes, and C2 infrastructure
- [The Hacker News: Microsoft Details Windows Clipper Malware](https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html) -- secondary reporting with campaign overview
- [BleepingComputer: USB worm spreads crypto-stealing malware via Windows shortcut files](https://www.bleepingcomputer.com/news/security/usb-worm-spreads-crypto-stealing-malware-via-windows-shortcut-files/) -- additional technical details on propagation mechanism
- [SecurityWeek: CryptoBandits malware doubles as a backdoor, abuses Tor](https://www.securityweek.com/cryptobandits-malware-doubles-as-a-backdoor-abuses-tor/) -- backdoor capabilities and Tor abuse analysis

---
*Report generated by Actioner*
