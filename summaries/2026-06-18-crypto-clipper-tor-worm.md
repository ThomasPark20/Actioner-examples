# Technical Analysis Report: CryptoBandits Crypto Clipper Worm (2026-06-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-18
Version: 1.0 (DRAFT)

---

## Executive Summary

A cryptocurrency clipper malware campaign tracked as **CryptoBandits** (Microsoft detection family `Trojan:Win32/CryptoBandits`) has been active since at least **February 2026**, employing worm-like USB propagation and Tor-based command-and-control infrastructure. The malware is distributed via malicious `.lnk` shortcut files on USB storage devices that masquerade as legitimate documents. Once executed, it deploys a multi-stage attack chain consisting of an obfuscated JavaScript payload, a renamed Tor binary (`ugate.exe`) for anonymized C2 communications, and a clipboard-monitoring stealer that targets cryptocurrency wallet addresses and BIP39 seed phrases.

The campaign uses a notably sophisticated infrastructure: C2 traffic is routed through 10 distinct `.onion` domains via a local SOCKS5 proxy on port 9050, supporting remote code execution (`EVAL` command), screenshot exfiltration, and cryptocurrency address replacement across Bitcoin (legacy, P2SH, Bech32, Taproot), Tron, and Monero wallets. Persistence is achieved through scheduled tasks created from XML files, and defense evasion includes Defender exclusion manipulation and dual-layer JavaScript obfuscation. The threat actor also operates a broader social engineering campaign across GitHub (fake repositories with 146 stars), SourceForge (44,485+ claimed downloads), YouTube (91,000+ subscriber channel), and WordPress phishing sites.

**Viability Gate: PASS** -- The Microsoft blog provides 16 SHA-256 hashes, 10 .onion C2 domains, specific C2 endpoint paths, exact file naming conventions, scheduled task patterns, and distinctive command-line indicators suitable for high-confidence detection rule development.

---

## Background: Cryptocurrency Clipper Malware via USB Worm

Cryptocurrency clipper malware monitors the system clipboard for content matching cryptocurrency wallet address patterns and silently replaces victim addresses with attacker-controlled addresses. This class of malware targets the common user behavior of copying wallet addresses during transactions. CryptoBandits combines this theft mechanism with worm-like propagation through removable USB media, allowing it to spread across air-gapped and loosely connected networks without requiring internet-based distribution.

The malware is written as an obfuscated JavaScript payload executed by Windows Script Host (WScript/CScript), with the initial installer being a Python script obfuscated with PyArmor and packaged via PyInstaller. The use of Tor for C2 communications makes network-based detection and infrastructure takedown significantly more challenging.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02 (est.) | Campaign begins active distribution via USB media |
| 2026-07 (est.) | Threat actor YouTube channel created (91,000+ subscribers by discovery) |
| 2026-06-17 | Microsoft Security Blog publishes technical analysis |
| 2026-06-18 | The Hacker News covers campaign with additional distribution infrastructure details |

---

## Root Cause: USB-Based Worm Propagation (T1091)

Initial access is achieved through **malicious `.lnk` shortcut files distributed via USB storage devices**. The worm component:

1. Enumerates removable drives connected to the victim system
2. Hides legitimate document files (`.doc`, `.xlsx`, `.pdf`) on the USB drive
3. Replaces visible files with `.lnk` shortcuts that reference the worm executable with command-line arguments
4. When a user inserts the infected USB and clicks what appears to be a document, the `.lnk` executes the worm payload
5. The worm then stages itself on the new victim and repeats the propagation cycle

---

## Technical Analysis of the Malicious Payload

### 1. Initial Loader: PyInstaller + PyArmor Obfuscation

The initial worm installer is a Python script obfuscated with **PyArmor** and packaged as a standalone executable using **PyInstaller**. This dual-layer obfuscation complicates static analysis and signature-based detection. Upon execution, the installer:

- Decrypts and deploys JavaScript payload files to `C:\Users\Public\Documents\[5-char-name]\[5-char-name].js`
- Deploys the renamed Tor binary as `ugate.exe`
- Creates scheduled task XML files alongside the JavaScript payloads
- Establishes persistence via `schtasks.exe`

### 2. JavaScript Stealer Payload

The core stealer functionality is implemented in obfuscated JavaScript executed by WScript/CScript with ActiveX objects. Key capabilities:

**Clipboard Monitoring (T1115):**
- Monitors the clipboard every **500 milliseconds**
- Detects **12 or 24-word BIP39 seed phrases** and validates against word lists
- Extracts **Ethereum private keys** and **Bitcoin WIF-format keys**
- Stolen seeds/keys are saved locally to a `GOOD` path as backup, exfiltrated to C2 via Tor, retried until acknowledged, then backup is deleted

**Cryptocurrency Address Replacement:**

| Currency | Pattern | Replacement Strategy |
|----------|---------|---------------------|
| Bitcoin Legacy | Starts with "1", 32-36 chars | Replace, preserve first 2 characters |
| Bitcoin P2SH | Starts with "3", 32-36 chars | Replace, preserve first 2 characters |
| Bitcoin Taproot | Starts with "bc1p", 40-64 chars | Replace, preserve last character |
| Bitcoin Bech32 | Starts with "bc1q", 40-64 chars | Replace, preserve last character only |
| Tron | Starts with "T", exactly 34 chars | Replace, preserve first 2 characters |
| Monero | Starts with "4" or "8", exactly 95 chars | Replace entire address |

**Screen Capture (T1113):**
- Captures **5 screenshots at 10-second intervals** when a seed phrase or private key is detected
- Screenshots are uploaded asynchronously through Tor via the `/recvf.php` endpoint

### 3. C2 Infrastructure

**Transport:** HTTP over Tor (SOCKS5 proxy at `127.0.0.1:9050`)

The malware deploys a renamed Tor binary (`ugate.exe`) that bootstraps in approximately 60 seconds, establishing a local SOCKS5 proxy. All C2 communication uses `curl.exe` with the `--socks5-hostname` flag to route through this proxy.

**C2 Endpoints:**

| Endpoint | Function |
|----------|----------|
| `/route.php` | Beacon heartbeat and command retrieval |
| `/recvf.php` | File upload (screenshots) |
| `/stub.php` | Payload download |

**C2 Actions (client to server):**

| Action | Description |
|--------|-------------|
| `GUID` | Heartbeat beacon with device identifier |
| `SEED` | Exfiltrated BIP39 seed phrase |
| `PKEY` | Exfiltrated private key |
| `REPL` | Address replacement notification |
| `GOOD` | Legacy/fallback action |

**C2 Commands (server to client):**

| Command | Description |
|---------|-------------|
| `GUID` | Acknowledge/refresh victim GUID |
| `EVAL` | Execute arbitrary JScript code (remote code execution) |

**Victim Identification:** Each compromised device is assigned a generated GUID, combined with geolocation data (GEIP) for authentication.

### 4. Platform-Specific Behavior

#### Windows

The malware targets Windows systems exclusively for its worm and stealer components. Key platform-specific behaviors:

- **Staging path:** `C:\Users\Public\Documents\[5-char-name]\` with randomly generated 5-character lowercase alphabetic directory and file names
- **Tor binary:** Renamed to `ugate.exe` and deployed alongside payloads
- **Backup file:** `cfile` used for caching payloads from C2
- **Script execution:** WScript/CScript with ActiveX objects for system interaction
- **Payload delivery:** If not already present locally, payloads are fetched from C2 through Tor via `/stub.php`

### 5. Anti-Forensics / Evasion Techniques

- **Dual-layer JavaScript obfuscation:** All JavaScript components are encrypted and decrypted at runtime
- **PyArmor + PyInstaller:** Initial installer uses code protection and standalone packaging
- **Defender exclusion manipulation:** Malware excludes staging folders and Windows binaries from Microsoft Defender scanning using process and path exclusion techniques
- **Anti-analysis check:** Queries `Win32_Process` WMI class and terminates execution if Task Manager process is detected (T1057)
- **Tor-routed C2:** Eliminates DNS visibility for C2 domain resolution; .onion addresses resolve only within the Tor network
- **Document mimicry on USB:** Hides real documents and replaces them with .lnk files to maintain user trust
- **Character-preserving address replacement:** Keeps first or last characters of replaced crypto addresses to reduce visual suspicion

---

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - .onion addresses: `[.]onion` notation

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\Users\Public\Documents\[5-char]\[5-char].js` | -- | Obfuscated JS stealer payload |
| Windows | `C:\Users\Public\Documents\[5-char]\[5-char].xml` | -- | Scheduled task XML definition |
| Windows | ugate.exe (staged with payloads) | -- | Renamed Tor binary |
| Windows | cfile (staged with payloads) | -- | Cached C2 payload backup |

**Known Worm Sample Hashes (SHA-256):**

| SHA-256 | Component |
|---------|-----------|
| `7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c` | Worm |
| `a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630` | Worm |
| `23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43` | Worm |
| `cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30` | Worm |
| `100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8` | Worm |
| `d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f` | Worm |
| `9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96` | Worm |
| `67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5` | Worm |
| `0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a` | Worm |
| `35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd` | Worm |
| `c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502` | Worm |
| `d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba` | Worm |
| `b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f` | Worm |
| `7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05` | Worm |
| `f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0` | Worm |
| `20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1` | Worm |

### Network

| Type | Value | Context |
|------|-------|---------|
| Tor C2 | `cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad[.]onion` | C2 server |
| Tor C2 | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad[.]onion` | C2 server |
| Tor C2 | `he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad[.]onion` | C2 server |
| Tor C2 | `lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad[.]onion` | C2 server |
| Tor C2 | `j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd[.]onion` | C2 server |
| Tor C2 | `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion` | C2 server |
| Tor C2 | `7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid[.]onion` | C2 server |
| Tor C2 | `facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd[.]onion` | C2 server |
| Tor C2 | `wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid[.]onion` | C2 server |
| Tor C2 | `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion` | C2 server |
| Proxy | `127.0.0.1:9050` | Local Tor SOCKS5 proxy |
| URI Pattern | `/route.php` | C2 beacon endpoint |
| URI Pattern | `/recvf.php` | Screenshot upload endpoint |
| URI Pattern | `/stub.php` | Payload download endpoint |

### Behavioral

- **Clipboard polling at 500ms intervals** for cryptocurrency addresses and BIP39 seed phrases
- **schtasks.exe** creating tasks from XML files in `C:\Users\Public\Documents\[a-z]{4,6}\` subdirectories with `/tn [a-z]{4,6}` naming convention
- **curl.exe** with `--socks5-hostname localhost:9050` connecting to `.onion` domains
- **WScript/CScript** executing `.js` files from `C:\Users\Public\Documents\` subdirectories
- **ugate.exe** (renamed Tor binary) listening on port 9050
- **Win32_Process WMI query** checking for Task Manager as anti-analysis
- **Microsoft Defender exclusion modification** for staging directories
- **5 screenshots at 10-second intervals** triggered by seed phrase or private key detection
- **USB drive enumeration** with hiding of `.doc`, `.xlsx`, `.pdf` files and replacement with `.lnk` shortcuts

### Microsoft Defender Detections

| Detection Name | Type |
|----------------|------|
| `Trojan:Win32/CryptoBandits.A` | AV |
| `Trojan:Win32/CryptoBandits.B` | AV |
| `Trojan:JS/CryptoBandits.A` | AV |
| `Trojan:JS/CryptoBandits.B` | AV |
| `Behavior:Win64/PyPowJs.STA` | Behavioral |
| `Behavior:Win64/ProcessExclusion.ST` | Behavioral |
| `Behavior:Win64/PathExclusion.STA` | Behavioral |
| `Behavior:Win64/PathExclusion.STB` | Behavioral |
| `Behavior:Win64/CurlOnion.STA` | Behavioral |

---

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1091 | Replication Through Removable Media | Worm spreads via USB drives by hiding documents and replacing them with malicious .lnk files |
| T1059.007 | JavaScript | Obfuscated JavaScript payloads executed via WScript/CScript with ActiveX objects |
| T1053.005 | Scheduled Task | Persistence via indefinite scheduled tasks created from XML files in Public Documents |
| T1115 | Clipboard Data | Clipboard monitored every 500ms for crypto addresses, seed phrases, and private keys |
| T1113 | Screen Capture | 5 screenshots captured at 10-second intervals upon detecting seed phrases or keys |
| T1090.003 | Multi-hop Proxy | C2 traffic routed through local Tor SOCKS5 proxy (ugate.exe on port 9050) |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Stolen data exfiltrated via curl through Tor SOCKS5 proxy |
| T1027 | Obfuscated Files or Information | Dual-layer JavaScript encryption, PyArmor obfuscation on installer |
| T1036.005 | Match Legitimate Name or Location | Tor binary renamed to ugate.exe; staging in Public Documents |
| T1057 | Process Discovery | WMI query for Task Manager process as anti-analysis check |
| T1562.001 | Disable or Modify Tools | Microsoft Defender exclusion additions for staging paths and processes |

---

## Impact Assessment

The CryptoBandits campaign presents a **medium-to-high** impact threat, particularly to organizations where USB media sharing is common (government, education, manufacturing, air-gapped environments). The worm propagation mechanism enables spread without requiring internet connectivity at the point of infection.

**Financial impact** is direct: cryptocurrency transactions are silently redirected to attacker-controlled wallets. The preservation of address prefix/suffix characters during replacement makes visual detection by users difficult. The theft of BIP39 seed phrases and private keys enables complete wallet compromise beyond individual transactions.

**Distribution scale** is notable: the threat actor maintains infrastructure across GitHub (at least 6 accounts, repositories with 146 stars and 62 forks), SourceForge (44,485+ claimed downloads), YouTube (91,000+ subscriber channel with AI-generated content), and WordPress phishing pages. The malware is disguised as Solana sniper bots, Pump.fun sniper bots, and crash-game predictors.

---

## Detection & Remediation

### Immediate Detection

Check for CryptoBandits artifacts on Windows systems:

```powershell
# Check for ugate.exe (renamed Tor binary)
Get-ChildItem -Path C:\ -Recurse -Filter "ugate.exe" -ErrorAction SilentlyContinue

# Check for suspicious JS files in Public Documents subdirectories
Get-ChildItem -Path "C:\Users\Public\Documents" -Recurse -Filter "*.js" -ErrorAction SilentlyContinue

# Check for suspicious scheduled tasks with short random names
schtasks /query /fo csv | Select-String -Pattern '"[a-z]{4,6}"'

# Check for Tor SOCKS proxy on port 9050
netstat -ano | findstr ":9050"

# Check for Defender exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
```

### Remediation

1. **Contain:** Isolate affected systems from the network and disconnect USB devices
2. **Kill processes:** Terminate `ugate.exe`, any `wscript.exe`/`cscript.exe` running from `C:\Users\Public\Documents\`
3. **Remove persistence:** Delete malicious scheduled tasks (short random-name tasks referencing Public Documents XML files)
4. **Clean staging directory:** Remove `C:\Users\Public\Documents\` subdirectories containing `.js` and `.xml` files
5. **Remove Defender exclusions:** Run `Remove-MpPreference -ExclusionPath` and `Remove-MpPreference -ExclusionProcess` for any illegitimate entries
6. **Scan USB drives:** Check all removable media for hidden documents and malicious `.lnk` files; restore hidden files with `attrib -h -s`
7. **Rotate crypto keys:** Any cryptocurrency wallets accessed from compromised systems should be considered compromised; transfer funds to new wallets generated on clean systems
8. **Update signatures:** Ensure Microsoft Defender definitions include CryptoBandits detections

### Long-Term Hardening

- **Disable autorun/autoplay** for removable media via Group Policy
- **Restrict script execution:** Block WScript/CScript execution from `C:\Users\Public\` via AppLocker or WDAC policies
- **Monitor USB activity:** Deploy endpoint detection for removable media enumeration and `.lnk` file creation
- **Block Tor:** Detect and block Tor relay connections at the network perimeter; alert on port 9050 listener creation
- **Clipboard protection:** Deploy endpoint security that monitors for rapid clipboard access patterns (500ms polling)

---

## Detection Rules

Five Sigma rules, two YARA rules, and one Suricata rule cover the distinctive artifacts of this campaign: scheduled task persistence from Public Documents, curl-based Tor C2 communication, the renamed Tor binary, local SOCKS5 proxy connections, and WScript execution of JavaScript payloads from the staging directory. Note that Tor-based C2 renders traditional DNS/HTTP network rules less effective; endpoint-focused detections are the primary detection surface.

### Sigma: CryptoBandits Scheduled Task Creation via XML in Public Documents

Detects `schtasks.exe /create` using XML files stored in `C:\Users\Public\Documents` subdirectories, the persistence mechanism used by the CryptoBandits worm.

**Status:** compile ✅ -- confidence: high

<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Keys on distinctive schtasks+/xml+Public Documents path combination. Low FP surface — legitimate software rarely creates scheduled tasks from XML in Public Documents. -->

```yaml
title: CryptoBandits Scheduled Task Creation via XML in Public Documents
id: 8a3b7c4d-1e2f-4a5b-9c6d-7e8f0a1b2c3d
status: experimental
description: >
    Detects scheduled task creation using XML files stored in C:\Users\Public\Documents
    subdirectories, consistent with the CryptoBandits crypto clipper worm persistence mechanism.
    The malware creates indefinite scheduled tasks from XML files in randomly named 4-6 character
    subdirectories under Public Documents.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\schtasks.exe'
    selection_args:
        CommandLine|contains|all:
            - '/create'
            - '/xml'
            - '\Users\Public\Documents\'
            - '/f'
        CommandLine|contains:
            - '/tn '
    condition: selection_binary and selection_args
falsepositives:
    - Legitimate software installers that deploy scheduled tasks from Public Documents
level: high
```

### Sigma: Curl SOCKS5 Proxy Communication to Tor Onion Address

Detects `curl.exe` using `--socks5-hostname` with `localhost:9050` to communicate with `.onion` domains, the primary C2 channel of the CryptoBandits worm.

**Status:** compile ✅ -- confidence: high

<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk exit 0. Requires all four conditions (curl binary + socks5-hostname flag + localhost:9050 + .onion in command line) for high specificity. -->

```yaml
title: Curl SOCKS5 Proxy Communication to Tor Onion Address
id: 9b4c8d5e-2f3a-4b6c-ad7e-8f9a0b1c2d3e
status: experimental
description: >
    Detects curl.exe using the --socks5-hostname flag with localhost:9050 to route
    traffic through a local Tor SOCKS5 proxy to .onion domains. This is the primary
    C2 communication method used by the CryptoBandits crypto clipper worm.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1090.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\curl.exe'
    selection_socks:
        CommandLine|contains: '--socks5-hostname'
    selection_tor:
        CommandLine|contains:
            - 'localhost:9050'
            - '127.0.0.1:9050'
    selection_onion:
        CommandLine|contains: '.onion'
    condition: selection_binary and selection_socks and selection_tor and selection_onion
falsepositives:
    - Legitimate Tor-based applications using curl for onion service communication
    - Security researchers testing Tor connectivity
level: critical
```

### Sigma: Renamed Tor Binary Execution as ugate.exe

Detects execution of `ugate.exe`, the filename used by CryptoBandits for its renamed Tor binary that establishes the local SOCKS5 proxy for C2 communications.

**Status:** compile ✅ -- confidence: high

<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk exit 0. Simple image-name match on a distinctive, non-standard binary name. "ugate.exe" is not a known legitimate Windows binary. -->

```yaml
title: Renamed Tor Binary Execution as ugate.exe
id: ab5d9e6f-3a4b-4c7d-be8f-9a0b1c2d3e4f
status: experimental
description: >
    Detects execution of ugate.exe, the renamed Tor binary used by the CryptoBandits
    crypto clipper worm to establish a local SOCKS5 proxy for C2 communication over
    the Tor network.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ugate.exe'
    condition: selection
falsepositives:
    - Legitimate software named ugate.exe (uncommon)
level: high
```

### Sigma: Network Connection to Local Tor SOCKS5 Proxy on Port 9050

Detects outbound network connections to localhost port 9050 (the default Tor SOCKS5 proxy port), filtering out legitimate Tor Browser usage.

**Status:** compile ✅ -- confidence: medium

<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk exit 0. Port 9050 is standard Tor; filter excludes Tor Browser. Medium confidence because other Tor-using applications (OnionShare, Brave Tor mode) may also connect to this port. -->

```yaml
title: Network Connection to Local Tor SOCKS5 Proxy on Port 9050
id: bc6ea0f1-4b5c-4d8e-cf9a-0b1c2d3e4f5a
status: experimental
description: >
    Detects outbound network connections to localhost port 9050, the default Tor SOCKS5
    proxy port. The CryptoBandits worm deploys a renamed Tor binary (ugate.exe) and
    routes all C2 traffic through this local proxy.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1090.003
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 9050
        DestinationIp:
            - '127.0.0.1'
            - '::1'
    filter_tor_browser:
        Image|contains: 'Tor Browser'
    condition: selection and not filter_tor_browser
falsepositives:
    - Legitimate Tor Browser usage
    - Privacy-focused applications using Tor
level: medium
```

### Sigma: WScript Execution of JavaScript from Public Documents Subdirectory

Detects WScript or CScript executing `.js` files from `C:\Users\Public\Documents` subdirectories, the execution method for the CryptoBandits stealer payload.

**Status:** compile ✅ -- confidence: high

<!-- audit: sigma check 0 errors, 0 issues; sigma convert --without-pipeline -t splunk exit 0. WScript/CScript executing JS from Public Documents is highly anomalous in enterprise environments. Combines interpreter selection + path + extension for specificity. -->

```yaml
title: WScript Execution of JavaScript from Public Documents Subdirectory
id: cd7fb1a2-5c6d-4e9f-da0b-1c2d3e4f5a6b
status: experimental
description: >
    Detects WScript or CScript executing JavaScript files from C:\Users\Public\Documents
    subdirectories. The CryptoBandits worm stores obfuscated JS payloads in randomly
    named subdirectories under this path and executes them via script interpreters.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
author: Actioner
date: 2026-06-18
tags:
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_interpreter:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_path:
        CommandLine|contains: '\Users\Public\Documents\'
    selection_ext:
        CommandLine|endswith: '.js'
    condition: selection_interpreter and selection_path and selection_ext
falsepositives:
    - Legitimate scripts stored in Public Documents (uncommon)
level: high
```

### YARA: CryptoBandits Worm String Detection

Detects CryptoBandits worm samples by matching combinations of C2 endpoint paths, action keywords, Tor proxy indicators, and known `.onion` C2 domains.

**Status:** compile ✅ -- confidence: high

<!-- audit: yarac exit 0. Rule uses three alternative condition paths: (1) 2+ C2 endpoints + 2+ action strings, (2) 1 C2 endpoint + Tor proxy indicator + 1 action string, (3) 2+ known onion domains. All paths require filesize < 10MB. Onion domains are campaign-specific and high-fidelity. -->

```yara
rule Malware_CryptoBandits_Worm_Strings
{
    meta:
        description = "Detects CryptoBandits crypto clipper worm via characteristic C2 endpoint strings, action keywords, and Tor proxy usage patterns"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "critical"

    strings:
        $c2_route = "/route.php" ascii wide
        $c2_recvf = "/recvf.php" ascii wide
        $c2_stub = "/stub.php" ascii wide

        $action_seed = "SEED" ascii wide
        $action_pkey = "PKEY" ascii wide
        $action_repl = "REPL" ascii wide
        $action_guid = "GUID" ascii wide
        $action_good = "GOOD" ascii wide
        $action_eval = "EVAL" ascii wide

        $socks_proxy = "socks5-hostname" ascii wide
        $tor_port = "localhost:9050" ascii wide
        $tor_port2 = "127.0.0.1:9050" ascii wide

        $onion1 = "cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad.onion" ascii wide
        $onion2 = "gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion" ascii wide
        $onion3 = "he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad.onion" ascii wide
        $onion4 = "lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad.onion" ascii wide
        $onion5 = "j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd.onion" ascii wide
        $onion6 = "shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion" ascii wide
        $onion7 = "7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid.onion" ascii wide
        $onion8 = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion" ascii wide
        $onion9 = "wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid.onion" ascii wide
        $onion10 = "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion" ascii wide

    condition:
        filesize < 10MB and
        (
            (2 of ($c2_*) and 2 of ($action_*)) or
            (1 of ($c2_*) and 1 of ($socks_proxy, $tor_port, $tor_port2) and 1 of ($action_*)) or
            2 of ($onion*)
        )
}
```

### YARA: CryptoBandits Worm Artifact and Crypto Pattern Detection

Detects CryptoBandits worm artifacts including the `ugate.exe` filename, Public Documents staging path, backup file marker, and cryptocurrency address regex patterns used by the clipper.

**Status:** compile ✅ -- confidence: medium

<!-- audit: yarac exit 0. Condition requires co-occurrence of campaign-specific artifacts (ugate.exe, Public Documents path, cfile) with crypto address regex patterns. Medium confidence because individual strings (ugate, crypto regexes) could appear in unrelated crypto software; the combination requirement mitigates this. -->

```yara
rule Malware_CryptoBandits_Worm_Hashes
{
    meta:
        description = "Detects known CryptoBandits worm samples by artifact strings and cryptocurrency address regex patterns embedded in the binary"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        hash = "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c"
        severity = "critical"

    strings:
        $ugate = "ugate.exe" ascii wide nocase
        $public_docs = "\\Users\\Public\\Documents\\" ascii wide
        $cfile = "cfile" ascii fullword

        $crypto_btc_legacy = "^1[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii
        $crypto_btc_p2sh = "^3[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii
        $crypto_btc_bech32 = "^bc1q[a-z0-9]{38,62}$" ascii
        $crypto_btc_taproot = "^bc1p[a-z0-9]{38,62}$" ascii
        $crypto_tron = "^T[a-km-zA-HJ-NP-Z1-9]{33}$" ascii
        $crypto_monero = "^[48][0-9AB][a-zA-Z0-9]{93}$" ascii

    condition:
        filesize < 10MB and
        (
            ($ugate and $public_docs) or
            ($ugate and 2 of ($crypto_*)) or
            ($public_docs and $cfile and 1 of ($crypto_*)) or
            (3 of ($crypto_*) and ($ugate or $cfile))
        )
}
```

### Suricata: CryptoBandits Tor SOCKS5 Proxy Connection

Detects SOCKS5 handshake initiation to port 9050 (local Tor proxy), matching the initial SOCKS5 greeting bytes sent by clients connecting to the CryptoBandits Tor proxy.

**Status:** compile ✅ -- confidence: medium

<!-- audit: suricata -T exit 0 ("Configuration provided was successfully loaded"). Matches SOCKS5 version 5 + 1 method + no-auth greeting at the start of TCP payload to port 9050. Medium confidence because any SOCKS5 client connecting to port 9050 will match; combine with endpoint telemetry for higher fidelity. -->

```
alert tcp $HOME_NET any -> any 9050 (msg:"Actioner - CryptoBandits Tor SOCKS5 Proxy Connection to localhost:9050"; flow:established,to_server; content:"|05 01 00|"; depth:3; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/; metadata:author Actioner, created_at 2026-06-18; sid:2100101; rev:1;)
```

---

## Lessons Learned

1. **Tor-based C2 defeats traditional network monitoring.** The use of `.onion` domains with a locally deployed Tor proxy means no DNS queries are visible to network sensors, and C2 traffic blends with legitimate Tor traffic. Organizations must prioritize endpoint-based detection (process creation, command-line logging, Sysmon) over network-centric approaches for this class of threat.

2. **USB propagation remains a viable attack vector.** Despite years of awareness, worm-like USB propagation continues to succeed, particularly in environments with inadequate removable media controls. The technique of hiding legitimate documents and replacing them with `.lnk` shortcuts exploits user trust in familiar file names.

3. **Cryptocurrency address replacement is increasingly sophisticated.** By preserving the first or last characters of replaced addresses, CryptoBandits reduces the likelihood that users will notice the substitution during visual verification. Wallet applications and exchanges should implement more robust address verification mechanisms.

4. **Social engineering at scale amplifies distribution.** The threat actor's multi-platform presence (GitHub, SourceForge, YouTube, WordPress) combined with reputation manipulation (fake reviews, VirusTotal poisoning, press releases through legitimate newswires) demonstrates the industrialization of social engineering for malware distribution.

---

## Sources

- [Microsoft Security Blog - Crypto Clipper uses Tor and worm-like propagation](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/) -- primary technical analysis with IOCs, TTPs, and detection guidance
- [The Hacker News - Crypto Clipper Campaign Abuses Fake Repositories](https://thehackernews.com/2026/06/crypto-clipper-campaign-abuses-fake.html) -- additional distribution infrastructure details (GitHub, SourceForge, YouTube, WordPress)
- [Microsoft Threat Intelligence Blog](https://aka.ms/threatintelblog) -- general Microsoft threat intelligence reference

---
*Report generated by Actioner*
