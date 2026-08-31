# Technical Analysis Report: TerminalFix ClickFix Campaign (2026-08-31)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-31
Version: 1.1 (REVISED)

<!-- revision: v1.1 -- Fixed Sigma sideloading description (removed DLL loading claim; rule is process_creation only). Dropped YARA Malware_TerminalFix_dui70_DLL_Hash (hashes in meta only, condition matches legitimate dui70.dll). Removed T1053.005 (no evidence of scheduled tasks), T1018 (redundant with T1482), T1087.002 (redundant with T1069.002). Downgraded Snort SID 2300104 and Suricata SID 2400104 to medium confidence (compromised legitimate site; age out when clean). -->

## Executive Summary

TerminalFix is a multistage malware campaign documented by [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) on August 28, 2026. The campaign uses fake Cloudflare CAPTCHA overlays on compromised websites to trick users into executing malicious PowerShell commands -- a technique known as ClickFix. The infection chain downloads a ZIP archive (verify_pkg.zip), extracts it to `C:\ProgramData\f47f2a8c21c9df4e`, and launches a batch script that executes the legitimate signed binary LockScreenContentServer.exe. This binary is abused for DLL sideloading of a malicious dui70.dll, which retrieves steganographically encoded payloads from PNG images hosted on attacker infrastructure and deploys a custom Python-based reverse tunnel implant (client.py) via pythonw.exe. The implant establishes a persistent WebSocket-based SOCKS5 tunnel over TLS on port 443 to the C2 server gitnow[.]dev, providing the attacker with network-level proxy access for lateral movement. Persistence is achieved via registry Run keys with randomized service-like names. Active Directory enumeration commands (nltest, net group, systeminfo) are executed post-compromise for domain reconnaissance.

## Background

ClickFix is a social engineering technique in which fake verification or CAPTCHA overlays instruct users to execute commands on their system, typically by opening the Windows Run dialog or terminal and pasting attacker-controlled content. The technique has been observed across multiple campaigns throughout 2025-2026, evolving from simple PowerShell downloaders to sophisticated multistage chains. TerminalFix specifically abuses the Cloudflare brand, presenting a convincing CAPTCHA overlay on compromised or attacker-controlled websites to maximize victim compliance. The campaign's post-exploitation phase is notable for deploying a purpose-built reverse tunnel implant rather than commodity RATs, indicating the operators prioritize persistent network access over traditional endpoint control.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Unknown | Compromised website linked-log[.]com weaponized with ClickFix overlay |
| Unknown | Victims encounter fake Cloudflare CAPTCHA; PowerShell downloads verify_pkg.zip |
| Unknown | DLL sideloading chain deploys reverse tunnel implant; AD enumeration begins |
| 2026-08-28 | Microsoft Threat Intelligence publishes technical analysis of the campaign |
| 2026-08-31 | This report drafted |

## Root Cause: ClickFix Social Engineering (User Execution)

Victims visit a compromised website (e.g., linked-log[.]com) or attacker-controlled page that displays a fake Cloudflare CAPTCHA overlay. The overlay instructs the user to "verify" themselves by executing a command -- typically copied to the clipboard and pasted into a Run dialog or PowerShell prompt. The PowerShell command downloads a ZIP archive (verify_pkg.zip), prints the message "Starting Cloudflare verification..." to maintain the illusion of legitimacy, and initiates the infection chain. The attack relies entirely on user execution; no exploit is required.

## Technical Analysis of the Malicious Payload

### 1. Initial Access and Delivery

The PowerShell command executed by the victim performs the following:

1. Downloads `verify_pkg.zip` (SHA-256: `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f`) from attacker infrastructure
2. Prints "Starting Cloudflare verification..." to the console as a social engineering decoy
3. Extracts the archive to `C:\ProgramData\f47f2a8c21c9df4e`
4. Executes `1.bat` silently

The ZIP archive contains:
- `1.bat` -- batch launcher
- `LockScreenContentServer.exe` -- legitimate Microsoft signed binary
- `dui70.dll` -- malicious DLL for sideloading
- `client.py` -- Python-based reverse tunnel implant

### 2. DLL Sideloading Chain

The batch file `1.bat` launches `LockScreenContentServer.exe`, a legitimate signed Windows binary that imports `dui70.dll` at load time. The malicious dui70.dll is placed alongside the executable so Windows loads it from the local directory before searching system paths. Microsoft has published nine SHA-256 hashes for dui70.dll variants, indicating ongoing development or polymorphic generation.

Once loaded, the malicious DLL:
1. Retrieves steganographic PNG images from `bestsocialmedianewspapper[.]com` (with `offlineupdater[.]com` as a failover domain)
2. Extracts embedded payloads from the PNG pixel data
3. Launches `pythonw.exe` with `client.py` as the reverse tunnel implant

### 3. Steganographic Payload Extraction

The campaign uses LSB (Least Significant Bit) steganography to embed malicious payloads within PNG images hosted on dedicated infrastructure. This technique conceals the payload within the image's pixel data, making it invisible to casual inspection and evading content-based network detection. The image hosting domain (`bestsocialmedianewspapper[.]com`) is a purpose-registered domain designed to appear as a legitimate media site.

### 4. Reverse Tunnel Implant (client.py)

The core implant is a custom Python script (`client.py`, SHA-256: `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a`) that establishes a reverse tunnel via WebSocket over TLS to the C2 server `gitnow[.]dev` on port 443.

**Protocol details:**
- Transport: WebSocket over TLS (port 443)
- Message format: 7-byte binary header containing message type (1 byte), stream ID (2 bytes), and payload length (4 bytes)
- Message types: 8 distinct types including MSG_SHUTDOWN for clean teardown
- Proxy mode: SOCKS5-style TCP proxying, allowing the attacker to route arbitrary traffic through the victim's network
- Evasion: User-Agent rotation across requests to blend with normal web traffic

The reverse tunnel architecture gives the attacker network-level proxy access through the victim's machine, enabling lateral movement, internal service access, and data exfiltration through the victim's network egress point without requiring additional tools on the endpoint.

### 5. Persistence

Registry Run key persistence is established under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with randomized service-like value names (e.g., `LockScreenContentServer_MuODG5yBM`). The value points to the sideloading binary in the ProgramData extraction directory, ensuring the full chain re-executes on user logon.

### 6. Post-Compromise Reconnaissance

The following Active Directory enumeration commands are executed:

- `nltest /domain_trusts` -- enumerates trust relationships between domains (T1482)
- `net group "domain admins" /domain` -- lists members of the Domain Admins group (T1069.002)
- `systeminfo` with multilingual `findstr` -- collects system configuration and identifies OS language/locale (T1082)

### 7. Anti-Forensics / Evasion Techniques

- **DLL sideloading (T1574.002):** Legitimate signed binary loads malicious DLL from local directory
- **Steganography (T1027.003):** Payloads embedded in PNG images via LSB extraction
- **Masquerading (T1036.005):** Legitimate binary name and extraction to ProgramData path
- **Hidden files/directories (T1564.001):** Randomized hex directory name in ProgramData
- **User-Agent rotation:** WebSocket C2 traffic uses rotating User-Agent strings
- **TLS encryption:** All C2 communication encrypted via TLS on standard HTTPS port 443
- **Fake verification message:** "Starting Cloudflare verification..." deters user suspicion during execution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Type | Path / Name | Hash (SHA-256) | Description |
|------|-------------|----------------|-------------|
| ZIP | verify_pkg.zip | 18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f | Initial payload archive |
| Python | client.py | b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a | Reverse tunnel implant |
| DLL | dui70.dll | ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07 | Malicious sideloaded DLL |
| DLL | dui70.dll variant | 026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab | DLL variant |
| DLL | dui70.dll variant | 032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22 | DLL variant |
| DLL | dui70.dll variant | df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf | DLL variant |
| DLL | dui70.dll variant | eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0 | DLL variant |
| DLL | dui70.dll variant | 5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8 | DLL variant |
| DLL | dui70.dll variant | 9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24 | DLL variant |
| DLL | dui70.dll variant | 342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e | DLL variant |
| DLL | dui70.dll variant | ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d | DLL variant |
| EXE | LockScreenContentServer.exe | -- | Legitimate signed binary abused for sideloading |
| BAT | 1.bat | -- | Batch launcher |
| DIR | C:\ProgramData\f47f2a8c21c9df4e | -- | Extraction directory |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | gitnow[.]dev | Primary C2 server (port 443, TLS/WebSocket) |
| Domain | bestsocialmedianewspapper[.]com | Steganographic image hosting |
| Domain | offlineupdater[.]com | Failover domain |
| Domain | linked-log[.]com | Compromised website used for initial access |

### Registry

| Key | Value Name Pattern | Context |
|-----|-------------------|---------|
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run | LockScreenContentServer_\<random\> (e.g., LockScreenContentServer_MuODG5yBM) | Persistence; points to sideloading binary in ProgramData |

### Behavioral

- LockScreenContentServer.exe executing from `C:\ProgramData\` (not its normal system path)
- dui70.dll loaded from `C:\ProgramData\f47f2a8c21c9df4e\`
- pythonw.exe spawned by LockScreenContentServer.exe
- PowerShell execution containing "Starting Cloudflare verification"
- WebSocket connections to gitnow[.]dev over port 443 with rotating User-Agent strings
- AD enumeration commands (nltest /domain_trusts, net group "domain admins" /domain)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Compromised website hosts fake Cloudflare CAPTCHA overlay |
| T1204.002 | User Execution: Malicious File | ClickFix lure tricks users into executing PowerShell download command |
| T1059.001 | PowerShell | Initial payload download and execution via PowerShell |
| T1105 | Ingress Tool Transfer | ZIP archive downloaded from attacker infrastructure |
| T1574.002 | DLL Side-Loading | LockScreenContentServer.exe loads malicious dui70.dll |
| T1036.005 | Match Legitimate Name or Location | Legitimate binary name used; extraction to ProgramData subdirectory |
| T1027.003 | Steganography | Payloads embedded in PNG images via LSB extraction |
| T1564.001 | Hidden Files and Directories | Randomized hex-named directory in ProgramData |
| T1547.001 | Registry Run Keys / Startup Folder | Run key persistence with randomized service-like names |
| T1572 | Protocol Tunneling | WebSocket-based SOCKS5 reverse tunnel through victim network |
| T1071.001 | Web Protocols | C2 communication via WebSocket over HTTPS (port 443) |
| T1082 | System Information Discovery | systeminfo with multilingual findstr for locale identification |
| T1069.002 | Domain Groups | net group "domain admins" /domain |
| T1482 | Domain Trust Discovery | nltest /domain_trusts |

## Impact Assessment

TerminalFix represents a focused intrusion campaign designed to establish persistent network-level proxy access rather than deploy commodity malware. The reverse tunnel architecture is particularly concerning because it gives the attacker SOCKS5-style TCP proxying through the victim's network, enabling lateral movement and internal service access without deploying additional tools on interior hosts. The use of DLL sideloading via a legitimate signed Microsoft binary (LockScreenContentServer.exe) complicates detection by application whitelisting solutions and EDR products that trust signed binaries. The nine published dui70.dll hash variants suggest active development or build-time polymorphism to evade static detection. The combination of steganographic payload delivery and TLS-encrypted WebSocket C2 minimizes network-level detection opportunities, and the campaign's AD enumeration commands indicate the operators' intent to escalate access within enterprise environments.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for TerminalFix extraction directory
Test-Path "C:\ProgramData\f47f2a8c21c9df4e"

# Check for LockScreenContentServer.exe outside system directories
Get-ChildItem "C:\ProgramData" -Recurse -Filter "LockScreenContentServer.exe" -ErrorAction SilentlyContinue

# Check registry Run keys for TerminalFix persistence
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object -Property * | Where-Object { $_ -match "LockScreenContentServer" }

# Check for dui70.dll in ProgramData
Get-ChildItem "C:\ProgramData" -Recurse -Filter "dui70.dll" -ErrorAction SilentlyContinue
```

### Remediation

1. **Containment:** Block all listed IOC domains (gitnow[.]dev, bestsocialmedianewspapper[.]com, offlineupdater[.]com) at the network perimeter and DNS resolver. Isolate hosts with evidence of the extraction directory or registry persistence.
2. **Eradication:** Delete `C:\ProgramData\f47f2a8c21c9df4e` and all contents. Remove the registry Run key entry referencing LockScreenContentServer. Terminate pythonw.exe processes associated with client.py.
3. **Recovery:** Rotate all credentials accessible from compromised hosts, especially domain admin accounts. Review AD group memberships for unauthorized changes. Audit domain trust configurations.
4. **Secret rotation:** Assume any credentials cached or accessible on compromised endpoints are compromised. Rotate service accounts, VPN credentials, and API keys.

### Long-Term Hardening

- Monitor for DLL sideloading: alert on legitimate signed binaries executing from non-standard paths (ProgramData, user temp directories)
- Restrict PowerShell execution policy and enable ScriptBlock logging, Module logging, and Transcription
- Deploy application control policies that prevent execution of binaries from ProgramData subdirectories
- Monitor WebSocket connections to newly registered or low-reputation domains on port 443
- Implement DNS sinkholing for known TerminalFix infrastructure
- Block or alert on nltest and net group commands from non-administrative contexts

## Detection Rules

These detections target TerminalFix-specific artifacts: the DLL sideloading chain via LockScreenContentServer.exe, the fake Cloudflare verification PowerShell lure, registry Run key persistence, known dui70.dll variants, and C2 domain infrastructure. PoC/advisory-specific altitude (default); compiles != fires -- verify in your pipeline.

### Sigma: TerminalFix DLL Sideloading via LockScreenContentServer

Detects LockScreenContentServer.exe executing from ProgramData and spawning Python interpreters, matching the TerminalFix DLL sideloading chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert splunk exit 0, log_scale exit 0. ParentImage path constraint (ProgramData) + child process (pythonw/python) is highly specific; LockScreenContentServer does not normally reside in ProgramData or spawn Python. -->
<!-- revision: v1.1 -- removed "or loading dui70.dll" from description; rule uses process_creation log source only, cannot detect DLL loads. -->
```yaml
title: TerminalFix DLL Sideloading via LockScreenContentServer
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects LockScreenContentServer.exe executing from C:\ProgramData and
    spawning Python interpreters, consistent with the TerminalFix campaign
    DLL sideloading chain.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/31
tags:
    - attack.t1574.002
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\LockScreenContentServer.exe'
        ParentImage|contains: '\ProgramData\'
    selection_child:
        Image|endswith:
            - '\pythonw.exe'
            - '\python.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate LockScreenContentServer.exe is a Windows system binary but does not normally reside in ProgramData or spawn Python interpreters
level: high
```

### Sigma: TerminalFix Fake Cloudflare Verification via PowerShell

Detects PowerShell execution containing the fake "Starting Cloudflare verification" string used by the TerminalFix ClickFix lure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert splunk exit 0, log_scale exit 0. The exact string "Starting Cloudflare verification" is a campaign-specific artifact not found in legitimate Cloudflare tooling. -->
```yaml
title: TerminalFix Fake Cloudflare Verification via PowerShell
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
    Detects PowerShell execution containing the fake Cloudflare verification
    string used by the TerminalFix campaign to social-engineer victims into
    running malicious downloads.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/31
tags:
    - attack.t1059.001
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains: 'Starting Cloudflare verification'
    condition: selection_ps
falsepositives:
    - Unlikely; this exact string is specific to the TerminalFix ClickFix social engineering lure
level: high
```

### Sigma: TerminalFix Registry Run Key Persistence

Detects registry Run key creation referencing LockScreenContentServer.exe from ProgramData paths, matching the TerminalFix persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data 403); sigma convert splunk exit 0, log_scale exit 0. Legitimate LockScreenContentServer does not persist via user Run keys from ProgramData paths; the combination is campaign-specific. -->
```yaml
title: TerminalFix Registry Run Key Persistence with LockScreenContentServer
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
    Detects registry Run key creation referencing LockScreenContentServer.exe
    from ProgramData paths, matching the TerminalFix campaign persistence
    mechanism that uses randomized service-like value names.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
author: Actioner
date: 2026/08/31
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains: '\CurrentVersion\Run\'
    selection_value:
        Details|contains|all:
            - 'LockScreenContentServer'
            - 'ProgramData'
    condition: selection_key and selection_value
falsepositives:
    - Legitimate LockScreenContentServer is a system binary that does not persist via user Run keys from ProgramData
level: high
```

### YARA: TerminalFix dui70.dll File Detection

One rule detects dui70.dll by behavioral strings (ProgramData path, sideloading binary name, tunnel implant references). Not tested against a real captured sample.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Rule uses string intersection of campaign-specific paths and binary names; no real sample available for firing test. -->
<!-- revision: v1.1 -- DROPPED Malware_TerminalFix_dui70_DLL_Hash: hashes were in meta only (documentation), not in condition; actual condition (MZ + filesize < 10MB + "dui70" export string) matches the legitimate Microsoft dui70.dll (DirectUI framework) on every Windows install. False-positive machine. -->
```yara
rule Malware_TerminalFix_dui70_DLL
{
    meta:
        description = "Detects dui70.dll variants used in the TerminalFix ClickFix campaign for DLL sideloading via LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-08-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        severity = "critical"
        tlp = "white"

    strings:
        $dll_name = "dui70.dll" ascii wide
        $path1 = "\\ProgramData\\f47f2a8c21c9df4e" ascii wide
        $path2 = "LockScreenContentServer" ascii wide
        $bat = "1.bat" ascii wide

        $py_tunnel1 = "client.py" ascii wide
        $py_tunnel2 = "pythonw.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($path*, $dll_name, $bat)) or
            ($dll_name and $py_tunnel1) or
            ($path1 and 1 of ($py_tunnel*))
        )
}
```

### Snort: TerminalFix C2 Domain Detection

Detects HTTP traffic to the four known TerminalFix domains via Host header matching. Note: the primary C2 (gitnow[.]dev) uses TLS/WebSocket on port 443, so this HTTP-layer rule will only match if TLS inspection is in place. SID 2300104 (linked-log[.]com) targets a compromised legitimate site and should be aged out once the site is confirmed clean.
**Status:** uncompiled (Snort not installed) · confidence: high (SID 2300101-2300103), medium (SID 2300104)
<!-- audit: Snort not installed; structural review only. Rules follow standard Snort 2.x syntax with flow:established,to_server, Host header content match, and classtype:trojan-activity. Domain strings are exact IOC matches. The gitnow.dev rule (sid:2300101) requires TLS inspection to be effective since the real C2 uses encrypted WebSocket. SID 2300104 downgraded to medium: linked-log.com is a compromised legitimate site; disable this rule once the site is remediated. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TerminalFix C2 Domain gitnow.dev in HTTP Host Header"; flow:established,to_server; content:"Host|3a| "; nocase; content:"gitnow.dev"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2300101; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TerminalFix Stego Image Host bestsocialmedianewspapper.com"; flow:established,to_server; content:"Host|3a| "; nocase; content:"bestsocialmedianewspapper.com"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2300102; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TerminalFix Failover Domain offlineupdater.com"; flow:established,to_server; content:"Host|3a| "; nocase; content:"offlineupdater.com"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2300103; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - TerminalFix Compromised Site linked-log.com"; flow:established,to_server; content:"Host|3a| "; nocase; content:"linked-log.com"; nocase; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2300104; rev:1;)
```

### Suricata: TerminalFix C2 TLS SNI Detection

Detects TLS connections to the four known TerminalFix domains via SNI (Server Name Indication) matching. This covers the primary C2 channel (gitnow[.]dev uses TLS/WebSocket on 443) without requiring TLS decryption. SID 2400104 (linked-log[.]com) targets a compromised legitimate site and should be aged out once the site is confirmed clean.
**Status:** compile ✅ compiles · confidence: high (SID 2400101-2400103), medium (SID 2400104)
<!-- audit: suricata -T -S exit 0. All four rules use tls.sni content match with endswith; exact IOC domain matching with no regex. High confidence for campaign-specific domains. SID 2400104 downgraded to medium: linked-log.com is a compromised legitimate site; disable this rule once the site is remediated. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix C2 TLS SNI gitnow.dev"; flow:established,to_server; tls.sni; content:"gitnow.dev"; endswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2400101; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Stego Host TLS SNI bestsocialmedianewspapper.com"; flow:established,to_server; tls.sni; content:"bestsocialmedianewspapper.com"; endswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2400102; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Failover TLS SNI offlineupdater.com"; flow:established,to_server; tls.sni; content:"offlineupdater.com"; endswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2400103; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TerminalFix Compromised Site TLS SNI linked-log.com"; flow:established,to_server; tls.sni; content:"linked-log.com"; endswith; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/; metadata:author Actioner, created_at 2026-08-31; sid:2400104; rev:1;)
```

## Lessons Learned

1. **DLL sideloading via signed binaries remains effective.** The use of a legitimate Microsoft-signed binary (LockScreenContentServer.exe) to load malicious code bypasses application whitelisting and complicates EDR detection. Defenders should monitor for signed binaries executing from non-standard paths, not just unsigned executables.

2. **Reverse tunnels are harder to detect than RATs.** Unlike traditional remote access trojans that expose a command interface, the TerminalFix implant provides network-level proxy access via SOCKS5 tunneling. This allows lateral movement without deploying additional tools on interior hosts, reducing the forensic footprint.

3. **Steganography defeats content inspection.** Embedding payloads in PNG images makes network-level content inspection ineffective. The use of dedicated image hosting domains (rather than compromised legitimate image services) is a detection opportunity, but only if domain reputation feeds are current.

4. **ClickFix continues to evolve.** The TerminalFix campaign demonstrates that ClickFix social engineering is being adopted by intrusion operators focused on persistent access, not just commodity malware distributors. The technique's effectiveness depends on user compliance, making security awareness training a critical control.

## Sources

- [Microsoft Threat Intelligence - TerminalFix campaign deploys reverse tunnel through multistage intrusion](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) -- primary source; all IOCs, TTPs, and technical details originate from this analysis

---
*Report generated by Actioner*
