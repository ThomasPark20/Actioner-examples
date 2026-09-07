# Technical Analysis Report: DeadLock Ransomware (2026-08-11)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-11
Version: FINAL

## Executive Summary

DeadLock is a financially motivated ransomware operation first observed in July 2025, employing a Rust-based encryptor with a distinctive decentralized recovery infrastructure built on the Polygon blockchain and Session messaging network. The operators use double extortion tactics -- encrypting victim environments while threatening to publicly release exfiltrated data -- and have published more than 80 compromised organizations on their leak site, with over half of the victims in Europe. The ransomware features aggressive defense evasion (disabling Windows Defender, event logs, VSS, and backup services), XChaCha20 file encryption with Curve25519 ECDH key exchange, language-based geofencing to avoid CIS countries, and a self-contained HTML ransom note that functions as an end-to-end encrypted chat application connecting to attacker infrastructure via blockchain-resolved proxy servers.

The use of Polygon smart contracts to store and rotate C2 proxy URLs represents a significant evolution in ransomware infrastructure resilience, making traditional domain/IP blocking substantially less effective. Microsoft Threat Intelligence published a detailed technical breakdown of the encryptor on August 10, 2026, and Group-IB provided supplementary analysis of the blockchain C2 infrastructure.

## Background: DeadLock Ransomware Operation

DeadLock emerged in mid-July 2025 as a human-operated ransomware operation targeting organizations across multiple sectors including Technology, Manufacturing, Energy & Utilities, Healthcare, and Government. As of August 2026, at least 80-102 organizations across 46 countries have been compromised. The operation maintains multiple leak sites (both clearnet and Tor-based) and uses a distinctive recovery infrastructure that combines blockchain smart contracts for C2 resolution with the Session decentralized messenger for victim communication.

The ransomware binary is written in Rust and uses established cryptographic primitives (XChaCha20, Curve25519 ECDH, XSalsa20-Poly1305) implemented via NaCl-compatible libraries. Initial access vectors include exploitation of CVE-2024-51324 (Baidu Antivirus) and lateral movement via PsExec and WMI.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-July 2025 | DeadLock operations first observed |
| 2026-08-10 | Microsoft Threat Intelligence publishes detailed technical analysis |
| 2026-08-11 | Group-IB publishes supplementary blockchain infrastructure analysis |
| As of Aug 2026 | 80+ organizations published on leak site; 102 victims across 46 countries reported |

## Root Cause: Initial Access

Initial access vectors observed include exploitation of CVE-2024-51324 in Baidu Antivirus software. Lateral movement is conducted via PsExec and WMI commands. The ransomware operators employ human-operated intrusion tradecraft before deploying the encryptor.

## Technical Analysis of the Malicious Payload

### 1. Configuration Decryption and Pre-Flight Checks

Upon execution, DeadLock decrypts its embedded configuration blob using XOR decoding with an 8-byte key. The configuration contains the operator public key, file extension settings, encryption rules, exclusion lists, and blockchain RPC endpoints. The malware then queries the system's default and UI languages and self-deletes immediately if the system locale matches CIS-region languages (Russian/1049, Ukrainian/1058, Belarusian/1059, Tajik/1064, Persian/1065, Armenian/1067, Azeri/1068, Georgian/1079, Kazakh/1087, Kyrgyz/1088, Turkmen/1090, Syriac/1114, Romanian-Moldova/2072, Uzbek-Cyrillic/2115, and several Arabic variants/8193/9217).

### 2. Privilege Escalation and Defense Evasion

If executed without administrator privileges and no target directory is specified via command line, the malware generates a randomly named `.cmd` file (8 uppercase characters, e.g., `ESYEKQSY.cmd`) and executes it via `ShellExecuteW` with the `RunAs` verb to trigger UAC elevation. Once elevated, it escalates token privileges (SeDebugPrivilege, SeRestorePrivilege).

The defense evasion phase is aggressive and multi-layered:
- **Process termination:** Kills security tools (`msmpeng`, `securityhealthservice`, `smartscreen`), cloud sync (`onedrive`, `dropbox`, `googledrivefs`, `owncloud`), remote access (`anydesk`, `putty`, `mstsc`, `rustdesk`), and system utilities (`explorer`, `powershell`, `taskmgr`, `cmd`).
- **Service termination:** Stops `windefend` (Defender), `vss`/`swprv`/`wbengine` (shadow copies/backup), `vmcompute`/`vmms` (Hyper-V), `adws`/`ntds`/`kdc` (Active Directory), and `mssearch`.
- **Event log destruction (three methods):** Direct clearing via classic Event Log API; registry-based disabling (sets `Enabled` to 0 and overwrites `ChannelAccess` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`); and modern API enumeration via `wevtapi.dll`.
- **Recycle bin emptying:** Silently empties the recycle bin on all drives without UI or confirmation.

### 3. Encryption Engine

The encryption engine spawns 2x CPU core count worker threads with resource-aware throttling -- a dedicated monitoring/dispatch thread per drive batch polls system utilization and pauses when memory exceeds 29% or CPU load exceeds 70%.

**Per-file cryptographic process:**
1. Generate 32-byte random XChaCha20 key (via Windows CryptoAPI)
2. Generate 24-byte random nonce
3. Generate 32-byte random ephemeral Curve25519 private key
4. Generate 12-byte random file tag and 1-10 bytes random padding
5. Derive shared secret via Curve25519 ECDH with operator public key (`03bf50bbf97c4e951e66ff12b689a37a3ce675b4921e254eae76da77573843e4a9`)
6. Encrypt metadata using NaCl `crypto_box` (XSalsa20-Poly1305) with zero nonce
7. Encrypt file content using XChaCha20
8. Rename file to `<filename>.<UID>.dlock`
9. Append footer: encrypted metadata + magic marker `dDlK` + `FA` flag + 12-byte file ID + 33-byte ephemeral public key + Poly1305 MAC

**Size-based encryption strategy:**
- 100% encryption for files under ~50 MB
- 50% encryption for files ~50-118 MB
- 25% encryption for files ~118-500 MB
- 10% encryption for files ~500 MB - 1 GB
- Chunked mode for files over 1 GB

### 4. C2 Infrastructure (Blockchain-Backed)

DeadLock's most distinctive feature is its decentralized recovery infrastructure:

**Polygon Smart Contracts:**
- Chat proxy contract (`0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe`, selector `0x933a9ce8`): Stores the current proxy server URL, enabling infrastructure rotation without binary updates.
- Blog contract (`0x757984507c82c8dA1d3969c535dB5706eEE6426C`, selector `0xd4070542`): Stores leak blog posts with pagination support, BBCode formatting, and file attachment links.
- Additional contract (`0xAc9f868E285C8141617a97b85b667f229147815c`) observed by Group-IB.
- Wallet address (contract creator): `0x8f2fef1339E0d90362F3cEAd9C27B661d964a022`.

**RPC Endpoints (6 for redundancy):**
The malware queries Polygon blockchain state via public JSON-RPC endpoints: `polygon-bor-rpc.publicnode.com`, `polygon.drpc.org`, `polygon-pokt.nodies.app`, `polygon-rpc.com`, `1rpc.io/matic`, `polygon.meowrpc.com`.

**Proxy Servers (rotated via smart contract):**
- `138.226.236.51` and `94.74.164.207` (with `/prrq.php` endpoint)
- Compromised websites: `biggoalsports.co.za/minif.php`, `nmsneustadtl.ac.at/xml.php`, `envisionreg.com/wp-activate.php`

**Session Messenger Integration:**
Victim identity is derived deterministically from sign-in credentials: hash as seed, generate Ed25519 keypair, convert to Curve25519, prepend `05` network identifier to produce a Session address. Communication is end-to-end encrypted via the onion-routed Session network.

**Data Hosting:**
Exfiltrated data is hosted on Wasabi (AWS S3-compatible) with AWS4-HMAC-SHA256 signed requests for file browsing and pre-signed download URLs.

### 5. Post-Encryption and Self-Deletion

After encryption, the malware:
- Generates a custom BMP wallpaper at runtime stating "your infrastructure is DeadLocked"
- Sets it as desktop background via `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Wallpaper`
- Registers a custom icon for `.dlock` files via `HKLM\SOFTWARE\Classes\.dlock\DefaultIcon` pointing to `C:\ProgramData\<UID>.ico`
- Deploys ransom notes: `HOW_RECOVER.<UID>.txt` (text) and `RECOVERY_CHAT.<UID>.html` (interactive SPA with chat, blog browser, and file browser)
- Creates a batch script that loops until it successfully deletes the malware binary, then removes itself

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | Encryptor binary | `a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4` | DeadLock ransomware encryptor (Microsoft) |
| Windows | Encryptor sample | `3c1b9df801b9abbb3684670822f367b5b8cda566b749f457821b6481606995b3` | DeadLock encryptor variant (Group-IB) |
| Windows | Encryptor sample | `3cd5703d285ed2753434f14f8da933010ecfdc1e5009d0e438188aaf85501612` | DeadLock encryptor variant (Group-IB) |
| Windows | Encryptor sample | `c9cc95ff8f2998229394dfd31c2bd6b723e826a3ca5e008d2b5be19ba419ae2c` | DeadLock encryptor variant (Group-IB) |
| Windows | Encryptor sample | `be1037fac396cf54fb9e25c48e5b0039b3911bb8426cbf52c9433ba06c0685ce` | DeadLock encryptor variant (Group-IB) |
| Windows | `C:\ProgramData\<UID>.ico` | -- | Custom icon for .dlock extension |
| Windows | `C:\ProgramData\<UID>.bmp` | -- | Custom wallpaper (Vista+) |
| Windows | `HOW_RECOVER.<UID>.txt` | -- | Text ransom note |
| Windows | `RECOVERY_CHAT.<UID>.html` | -- | Interactive HTML ransom note/chat |
| Windows | `<filename>.<UID>.dlock` | -- | Encrypted file extension pattern |

**Additional hashes (Group-IB):**

| Type | Hash |
|------|------|
| SHA-1 | `e5ba4affd0f49a9e451aa913115cf16b481fe1dc` |
| SHA-1 | `45f7f7e87d18fbe71745a0cc170ae08571c2ba0d` |
| SHA-1 | `2204d64b82765db4598714fe8bc6e71a24958a7f` |
| SHA-1 | `235d6bdf25437b0b004152a263cb483aac08fd10` |
| MD5 | `505d23c7a66a02239056ac3cfed24132` |
| MD5 | `9a4dcce25a87819585aa0a1dd16186c8` |
| MD5 | `4374eb7807fbcb767ae3a6202b4dd8f8` |
| MD5 | `c8e16b76ae25d2f27e581a9bef134ea8` |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `deadlock[.]liveblog365[.]com` | Leak site (clearnet) |
| Domain | `dlock[.]liveblog365[.]com` | Leak site (clearnet) |
| Domain | `deadlockblog[.]great-site[.]net` | Leak site (clearnet) |
| Domain | `deadlockblog[.]medianewsonline[.]com` | Leak site (clearnet) |
| Onion | `deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd[.]onion` | Leak site (Tor) |
| Domain | `polygon-bor-rpc[.]publicnode[.]com` | Polygon RPC endpoint |
| Domain | `polygon[.]drpc[.]org` | Polygon RPC endpoint |
| Domain | `polygon-pokt[.]nodies[.]app` | Polygon RPC endpoint |
| Domain | `polygon-rpc[.]com` | Polygon RPC endpoint |
| Domain | `1rpc[.]io/matic` | Polygon RPC endpoint |
| Domain | `polygon[.]meowrpc[.]com` | Polygon RPC endpoint |
| IP | `138[.]226[.]236[.]51` | C2 proxy server |
| IP | `94[.]74[.]164[.]207` | C2 proxy server |
| URL | `hxxp://138[.]226[.]236[.]51/prrq.php` | C2 proxy endpoint |
| URL | `hxxp://94[.]74[.]164[.]207/prrq.php` | C2 proxy endpoint |
| URL | `hxxps://biggoalsports[.]co[.]za/minif.php` | Compromised proxy |
| URL | `hxxps://nmsneustadtl[.]ac[.]at/xml.php` | Compromised proxy |
| URL | `hxxps://envisionreg[.]com/wp-activate.php` | Compromised proxy |
| Smart Contract | `0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe` | Chat proxy contract (Polygon) |
| Smart Contract | `0x757984507c82c8dA1d3969c535dB5706eEE6426C` | Blog contract (Polygon) |
| Smart Contract | `0xAc9f868E285C8141617a97b85b667f229147815c` | Additional contract (Group-IB) |
| Wallet | `0x8f2fef1339E0d90362F3cEAd9C27B661d964a022` | Contract creator wallet |
| Session ID | `05084f9b14b02f4ffa97795a60ab1fafaf5128e3259c75459aaaeaebc80c14da78` | Operator Session address |

### Behavioral

- Generates randomly named 8-character uppercase `.cmd` file for UAC elevation via `ShellExecuteW` with `RunAs` verb
- Terminates security processes (`msmpeng`, `securityhealthservice`, `smartscreen`) and backup/cloud sync processes
- Stops critical services (`windefend`, `vss`, `swprv`, `wbengine`, `vmcompute`, `vmms`, `adws`, `ntds`, `kdc`)
- Clears event logs via three complementary methods (API, registry disabling, `wevtapi.dll` enumeration)
- Registers custom `.dlock` file extension icon via registry
- Sets custom wallpaper via Group Policy registry key
- Self-deletes via looping batch script
- Resource-aware encryption throttling (pauses at >29% memory or >70% CPU)
- File footer contains `dDlK` magic marker and `FA` mode flag

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1486 | Data Encrypted for Impact | XChaCha20 encryption of files with .dlock extension |
| T1490 | Inhibit System Recovery | VSS, swprv, wbengine service termination; recycle bin emptying |
| T1489 | Service Stop | Stops windefend, vss, Hyper-V, AD, and backup services |
| T1562.001 | Disable or Modify Tools | Terminates Defender, security health service, SmartScreen processes |
| T1562.002 | Disable Windows Event Logging | Three-method event log clearing/disabling |
| T1070.001 | Clear Windows Event Logs | Direct API clearing and wevtapi.dll enumeration clearing |
| T1070.004 | File Deletion | Self-deletion via looping batch script |
| T1548.002 | Bypass User Account Control | RunAs verb elevation via randomly named CMD file |
| T1112 | Modify Registry | Custom icon registration, wallpaper, event log channel disabling |
| T1059.003 | Windows Command Shell | CMD file generation and execution for privilege escalation |
| T1140 | Deobfuscate/Decode Files | XOR decoding of embedded configuration |
| T1021 | Remote Services | Lateral movement via PsExec and WMI |

## Impact Assessment

DeadLock has compromised 80-102 organizations across 46 countries, with over half of victims in Europe. The double extortion model combines operational disruption (encryption) with data theft threats. The use of blockchain-backed infrastructure makes takedown significantly harder than traditional domain-based C2 -- smart contracts on Polygon are immutable once deployed and proxy URLs can be rotated by the operator at any time without updating the malware binary. The encryption scheme (XChaCha20 + Curve25519 ECDH) is cryptographically sound, making decryption without the operator's private key infeasible.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for .dlock encrypted files
Get-ChildItem -Recurse -Filter "*.dlock" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime

# Check for ransom notes
Get-ChildItem -Recurse -Filter "HOW_RECOVER*.txt" -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "RECOVERY_CHAT*.html" -ErrorAction SilentlyContinue

# Check for registry modifications
Get-ItemProperty "HKLM:\SOFTWARE\Classes\.dlock\DefaultIcon" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -ErrorAction SilentlyContinue

# Check for custom icon/wallpaper files in ProgramData
Get-ChildItem "C:\ProgramData\*.ico","C:\ProgramData\*.bmp" -ErrorAction SilentlyContinue

# Check DNS logs for Polygon RPC endpoints
Get-DnsClientCache | Where-Object { $_.Entry -match "polygon|publicnode|drpc|nodies|meowrpc" }
```

### Remediation

1. **Containment:** Isolate affected hosts immediately; block the known proxy IPs (`138[.]226[.]236[.]51`, `94[.]74[.]164[.]207`) and leak site domains at the firewall.
2. **Block Polygon RPC resolution:** While blocking public RPC endpoints may have collateral impact on legitimate blockchain activity, monitor for DNS queries to the listed endpoints from non-blockchain workstations.
3. **Eradication:** Remove malware artifacts, clean registry keys (`.dlock` DefaultIcon, wallpaper policy), restore event log channels.
4. **Recovery:** Restore from offline backups; do not pay the ransom. The XChaCha20+Curve25519 encryption is not breakable without the operator's private key.
5. **Secret rotation:** Rotate all credentials accessible from compromised systems, especially AD service accounts.

### Long-Term Hardening

- Enable Attack Surface Reduction (ASR) rules: block process creations originating from PsExec and WMI commands.
- Maintain offline/immutable backup copies (the malware specifically targets VSS, backup engine, and cloud sync services).
- Monitor for bulk registry modifications under WINEVT\Channels as an early warning.
- Implement network segmentation to limit lateral movement via PsExec/WMI.
- Note: Blocking Polygon public RPC endpoints may affect legitimate uses; a more targeted approach is monitoring for the specific smart contract function selectors (`0x933a9ce8`, `0xd4070542`) in outbound traffic.

## Detection Rules

These detections target DeadLock ransomware's distinctive pre-encryption activity (UAC elevation, event log disabling, .dlock icon registration), known network infrastructure (leak site domains, C2 proxy IPs), and file-level artifacts. PoC/advisory-specific altitude (default); all Sigma rules convert to Splunk and CrowdStrike LogScale. Compile status reflects actual tool output -- `sigma check` failed due to MITRE ATT&CK data fetch (proxy environment), so portability is proven via `sigma convert` only.

### Sigma: DeadLock Ransomware UAC Elevation via Random CMD File

Detects the DeadLock-specific privilege escalation pattern where a randomly named 8-character uppercase CMD file triggers UAC elevation.
**Status:** compile ✅ compiles (convert-only; sigma check blocked by proxy) · confidence: medium
<!-- audit: sigma convert splunk 0, log_scale 0. sigma check failed (MITRE ATT&CK data fetch 403 from proxy, not a rule defect). Keys on distinctive 8-char uppercase CMD + High integrity level — highly specific to DeadLock UAC pattern. FP risk: legitimate 8-char uppercase batch scripts are rare. Caveat: IntegrityLevel field is Sysmon-specific (process_creation channel); CrowdStrike LogScale and other EDR backends may not populate this field, reducing portability. -->

```yaml
title: DeadLock Ransomware UAC Elevation via Random CMD File
id: 7a3e8b1c-5d4f-4e92-b6a1-9c0d2e3f4a5b
status: experimental
description: >
    Detects DeadLock ransomware privilege escalation pattern where a randomly named 8-character
    uppercase CMD file is generated and executed with RunAs verb via ShellExecuteW to bypass UAC.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/
    - https://www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1548.002
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentCommandLine|re: '\\[A-Z]{8}\.cmd'
    selection_child:
        IntegrityLevel: 'High'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate administrative scripts with 8-character uppercase names
    - IntegrityLevel field requires Sysmon; CrowdStrike and other EDR backends may not populate it
level: medium
```

<!-- revision: dropped by critic — EventID 7036 param1 contains display names not short service names; rule will never fire as written. Also lacks correlation threshold for multiple service stops. -->

### Sigma: DeadLock Ransomware Event Log Channel Disabling via Registry

Detects registry modifications disabling Windows event log channels under the WINEVT\Channels key -- a distinctive DeadLock anti-forensics technique.
**Status:** compile ✅ compiles (convert-only; sigma check blocked by proxy) · confidence: medium
<!-- audit: sigma convert splunk 0, log_scale 0. Targets registry_set events on WINEVT\Channels\*\Enabled set to 0. Shared technique pattern — other ransomware families (e.g., BlackCat, Hive) use the same registry-based event log disabling. Legitimate event log disabling via registry is rare outside of group policy deployment. -->

```yaml
title: DeadLock Ransomware Event Log Channel Disabling via Registry
id: 3c5d7e9f-2a4b-6c8d-0e1f-5b7a9d3c1e0f
status: experimental
description: >
    Detects DeadLock ransomware disabling Windows event log channels by setting the Enabled
    registry value to 0 under WINEVT Channels, a distinctive anti-forensics technique.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1562.002
    - attack.t1070.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Microsoft\Windows\CurrentVersion\WINEVT\Channels\'
        TargetObject|endswith: '\Enabled'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Legitimate event log management by administrators
level: high
```

### Sigma: DeadLock Ransomware .dlock File Extension Icon Registration

Detects DeadLock ransomware registering a custom icon for the `.dlock` encrypted file extension -- a near-zero false-positive indicator.
**Status:** compile ✅ compiles (convert-only; sigma check blocked by proxy) · confidence: high
<!-- audit: sigma convert splunk 0, log_scale 0. Extremely specific — .dlock extension is unique to DeadLock ransomware. Only FP scenario: security researcher or incident response tooling creating this key during analysis. -->

```yaml
title: DeadLock Ransomware Custom File Extension Icon Registration
id: 4d6e8f0a-3b5c-7d9e-1f2a-6c8b0d4e2f1a
status: experimental
description: >
    Detects DeadLock ransomware registering a custom icon for the .dlock file extension
    by creating the DefaultIcon registry key under HKLM\SOFTWARE\Classes\.dlock.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\Classes\.dlock\DefaultIcon'
    condition: selection
falsepositives:
    - Legitimate software registering .dlock extension (unlikely)
level: critical
```

<!-- revision: dropped by critic — Generic self-deletion batch loop pattern used by dozens of malware families; not DeadLock-specific. TTP mislabeled as specific. -->

<!-- revision: dropped by critic — Generic single-taskkill pattern; veeam not in DeadLock's actual process list. TTP mislabeled as specific. -->

### Snort: DeadLock Ransomware DNS and HTTP C2 Indicators

Detects DNS queries to DeadLock leak site domains and HTTP POST requests to the known `/prrq.php` proxy endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 via minimal config with classification.config. DNS rules use wire-format label-length encoding. HTTP rules target the specific prrq.php endpoint and known proxy IPs from Group-IB report. Polygon RPC endpoint rules dropped (public infrastructure, not DeadLock-specific). Leak site domain rules are zero-FP. -->

```snort
# revision: dropped SID 2100001 — public Polygon RPC endpoint, not DeadLock-specific; millions of legitimate users generate this traffic.

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to DeadLock Leak Site deadlock.liveblog365.com"; flow:to_server; content:"|08|deadlock|0b|liveblog365|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created 2026-08-11; sid:2100002; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to DeadLock Leak Site dlock.liveblog365.com"; flow:to_server; content:"|05|dlock|0b|liveblog365|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created 2026-08-11; sid:2100005; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to DeadLock Leak Site deadlockblog.great-site.net"; flow:to_server; content:"|0c|deadlockblog|0a|great-site|03|net|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created 2026-08-11; sid:2100006; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP POST to DeadLock Proxy Endpoint prrq.php"; flow:established,to_server; content:"POST"; http_method; content:"/prrq.php"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/; metadata:author Actioner, created 2026-08-11; sid:2100003; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to DeadLock Proxy Server 138.226.236.51"; flow:established,to_server; content:"/prrq.php"; http_uri; fast_pattern; content:"138.226.236.51"; http_header; classtype:trojan-activity; reference:url,www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/; metadata:author Actioner, created 2026-08-11; sid:2100004; rev:1;)
```

### Suricata: DeadLock Ransomware DNS and HTTP C2 Indicators

Detects DNS queries to DeadLock leak site infrastructure and HTTP POST to the known proxy endpoint using Suricata's `dns.query` and `http.*` sticky buffers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. DNS rules use dns.query buffer (Suricata-native). HTTP rules target prrq.php and known proxy IPs. Polygon RPC endpoint rules dropped (public infrastructure, not DeadLock-specific). Leak site rules are zero-FP. -->

```suricata
# revision: dropped SIDs 2200001-2200004 — public Polygon RPC endpoints, not DeadLock-specific; millions of legitimate users generate this traffic.

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DeadLock Leak Site deadlock.liveblog365.com"; flow:to_server; dns.query; content:"deadlock.liveblog365.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created_at 2026-08-11; sid:2200005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DeadLock Leak Site deadlockblog.medianewsonline.com"; flow:to_server; dns.query; content:"deadlockblog.medianewsonline.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created_at 2026-08-11; sid:2200006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DeadLock Leak Site dlock.liveblog365.com"; flow:to_server; dns.query; content:"dlock.liveblog365.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created_at 2026-08-11; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to DeadLock Leak Site deadlockblog.great-site.net"; flow:to_server; dns.query; content:"deadlockblog.great-site.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/; metadata:author Actioner, created_at 2026-08-11; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP POST to DeadLock Ransomware Proxy Endpoint prrq.php"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/prrq.php"; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/; metadata:author Actioner, created_at 2026-08-11; sid:2200007; rev:1;)

alert http $HOME_NET any -> 138.226.236.51 any (msg:"Actioner - HTTP to DeadLock Ransomware Proxy Server 138.226.236.51"; flow:established,to_server; http.uri; content:"/prrq.php"; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/; metadata:author Actioner, created_at 2026-08-11; sid:2200008; rev:1;)

alert http $HOME_NET any -> 94.74.164.207 any (msg:"Actioner - HTTP to DeadLock Ransomware Proxy Server 94.74.164.207"; flow:established,to_server; http.uri; content:"/prrq.php"; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/; metadata:author Actioner, created_at 2026-08-11; sid:2200009; rev:1;)
```

### YARA: DeadLock Ransomware Encryptor

Detects DeadLock ransomware binary via the `dDlK` footer magic marker, ransom note patterns, `.dlock` extension, blockchain contract addresses, and the operator public key.
**Status:** compile ✅ compiles · confidence: high · sample: fired (constructed positive)
<!-- audit: yarac exit 0. yara fired on constructed positive (MZ header + dDlK + .dlock + HOW_RECOVER + DeadLocked + contract address + RPC domain), quiet on negative (MZ + benign content). Constructed positive uses published IOC strings from Microsoft report, not invented strings. Multiple condition branches: magic+ext+note (file-level), contract+RPC/selector combo (requires at least one contract address), or operator public key (unique 33-byte SEC1 key). -->

```yara
rule Ransomware_DeadLock_Encryptor
{
    meta:
        description = "Detects DeadLock ransomware encryptor via distinctive footer magic marker, ransom note patterns, and configuration artifacts"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/"
        hash = "a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4"
        severity = "critical"

    strings:
        $magic = "dDlK" ascii
        $note1 = "HOW_RECOVER" ascii wide
        $note2 = "RECOVERY_CHAT" ascii wide
        $ext = ".dlock" ascii wide
        $wallpaper_msg = "DeadLocked" ascii wide
        $contract1 = "0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe" ascii
        $contract2 = "0x757984507c82c8dA1d3969c535dB5706eEE6426C" ascii
        $rpc1 = "polygon-bor-rpc.publicnode.com" ascii
        $rpc2 = "polygon.drpc.org" ascii
        $rpc3 = "polygon-rpc.com" ascii
        $rpc4 = "polygon.meowrpc.com" ascii
        $func1 = "0x933a9ce8" ascii
        $func2 = "0xd4070542" ascii
        $opkey = { 03 bf 50 bb f9 7c 4e 95 1e 66 ff 12 b6 89 a3 7a 3c e6 75 b4 92 1e 25 4e ae 76 da 77 57 38 43 e4 a9 }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 10MB and
        (
            ($magic and $ext and 1 of ($note*)) or
            (1 of ($contract*) and 1 of ($rpc*, $func*)) or
            ($opkey) or
            ($wallpaper_msg and $ext and 1 of ($note*))
        )
}
```

## Lessons Learned

- **Blockchain-based C2 resilience is maturing.** DeadLock's use of Polygon smart contracts to store and rotate proxy URLs represents a growing trend where ransomware operators leverage immutable public infrastructure to survive takedown attempts. Traditional domain/IP blocklisting is insufficient; defenders need to monitor for smart contract interactions and function selectors.
- **Multi-method log destruction raises the bar for forensics.** DeadLock's three-method approach to event log elimination (API clearing, registry disabling, wevtapi enumeration) means that restoring a single method is insufficient -- all three paths must be monitored and protected.
- **Resource-aware throttling shows operational maturity.** The malware's CPU/memory throttling is designed to avoid crashing systems before encryption completes, showing an operator focus on reliable deployment over speed.
- **Self-contained HTML ransom notes as SPAs** reduce dependency on external infrastructure and provide a richer extortion experience without requiring the victim to install additional software or navigate to Tor sites.

## Sources

- [Microsoft Threat Intelligence - DeadLock Ransomware Technical Breakdown](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/) -- Primary source: detailed technical analysis of the Rust-based encryptor, encryption scheme, and blockchain infrastructure
- [Group-IB - DeadLock Ransomware Polygon Smart Contracts](https://www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts/) -- Supplementary analysis of blockchain C2 infrastructure, additional hashes, proxy server IPs, and compromised website indicators
- [SOCRadar - DeadLock Ransomware Group Profile](https://socradar.io/free-tools/ransomware-intelligence/groups/deadlock) -- Threat group profile with victim statistics, sector targeting, and MITRE ATT&CK mappings
- [SC Media - DeadLock Ransomware Uses Blockchain for Evasion](https://www.scworld.com/brief/deadlock-ransomware-uses-blockchain-for-evasion) -- Industry reporting confirming blockchain-based evasion techniques

---
*Report generated by Actioner*
