# Technical Analysis Report: BlackX UEFI Bootkit (2026-10-28)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-28
Version: 1.2 (FINAL)

## Executive Summary

BlackX is a novel UEFI bootkit attributed with medium confidence to APT41 (FishMonger/Aquatic Panda/Earth Lusca), discovered by Kaspersky in October 2026 targeting diplomatic organizations in Tajikistan, Uzbekistan, and Turkmenistan. The bootkit exploits CVE-2022-21894 (Baton Drop) to bypass Secure Boot on systems where the Windows Production PCA 2011 certificate has not been added to the Secure Boot Forbidden Signature Database (DBX). Despite Microsoft's patch being available since 2023, the manual DBX revocation step is frequently missed, leaving many production systems vulnerable. The infection chain uses DLL sideloading, a revoked code-signing certificate, and cloud-based C2 (Google Drive, OneDrive, Yandex.Disk) alongside a dedicated C2 domain. The kernel driver disables ETW providers and attempts to blind security products.

## Background: UEFI Secure Boot and Baton Drop (CVE-2022-21894)

Secure Boot is a UEFI feature that verifies the integrity of boot components before loading them. CVE-2022-21894 (Baton Drop) allows attackers with administrator privileges to install custom Machine Owner Keys (MOK) and load arbitrary EFI binaries during boot. Microsoft patched the vulnerability but left the critical revocation step — adding the expired "Windows Production PCA 2011" certificate to the DBX — as a manual procedure (KB5025885). Organizations that applied the patch but skipped the DBX update remain vulnerable. The certificate expired on October 19, 2026, but expiry alone does not prevent the vulnerable binaries from loading — only the DBX blocklist entry does.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Early 2026 | Campaign targeting diplomatic entities in Central Asia begins |
| 2026-10-22 | Kaspersky publishes technical analysis of BlackX on Securelist |
| 2026-10-24 | The Hacker News, CyberSecurity News, and other outlets publish coverage |
| 2026-10-28 | This report generated |

## Root Cause: Administrator Access + Unrevoked Boot Components

The attack requires local administrator privileges or physical access. The root cause is the gap between patching CVE-2022-21894 and completing the manual DBX revocation. The bootkit exploits this gap to install MOKs and load a malicious EFI binary that persists across OS reinstallation.

## Technical Analysis of the Malicious Payload

### 1. Initial Installation

The installer `inst.exe` is staged at `C:\ProgramData\Intel\inst.exe` alongside `PVMDIJGKAX2`, an extensionless RC4-encrypted container holding the bootkit components. The command line uses a hardcoded RC4 key:

```
C:\ProgramData\Intel\inst.exe PVMDIJGKAX2 Q46F6MDLI3RX2KV1
```

The installer decrypts the container and drops files to both the system partition and the EFI System Partition (ESP). Specific ESP paths were not disclosed in public reporting.

### 2. UEFI Bootkit Persistence

BlackX exploits CVE-2022-21894 to register custom MOKs in the UEFI firmware. The implementation is described as very similar to the BlackLotus bootkit, though with distinct differences. The bootkit injects a malicious kernel driver during the Windows boot process, achieving persistence that survives OS reinstallation.

### 3. C2 Infrastructure

The Rust-based payload communicates with `www[.]archivetj[.]com` for plugin delivery and command execution. Plugins are DLLs exporting a `create_plugin` function. A .NET-based remote access trojan uses cloud storage services — Google Drive, OneDrive, and Yandex.Disk — as secondary C2 channels, interpreting files by suffix to receive tasks, return results, and transfer files.

### 4. DLL Sideloading (OxiDLLRunner)

A legitimate binary `googleupdate.exe` (original filename `jcef_helper.exe`, MD5: `AF8A983B9ADA07EAE1259BF2953ABD40`) sideloads the OxiDLLRunner DLL. The DLL decrypts `v8_context_snapshot.bin` to launch a Rust-based payload that connects to the C2 domain.

### 5. Kernel Driver and Defense Evasion

The malicious kernel driver is signed with a certificate issued to "Wenjiang District Mingyu Network Technology Service Studio" (serial: `0bcdf5e0da32d68900b8b7638459d072`, now revoked). The driver:
- Disables process, thread, and registry callbacks used by security products
- Alters Event Tracing for Windows (ETW) providers
- Contains specific routines targeting Kaspersky and Avast products (assessed as ineffective by Kaspersky)
- Returns a handle to `calc.exe` when BlackX files are opened, hiding them from inspection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `C:\ProgramData\Intel\inst.exe` | Not disclosed | BlackX installer |
| Windows | `C:\ProgramData\Intel\PVMDIJGKAX2` | Not disclosed | RC4-encrypted bootkit payload container |
| Windows | `googleupdate.exe` (orig: `jcef_helper.exe`) | MD5: `af8a983b9ada07eae1259bf2953abd40` | DLL sideloading host |
| Windows | `v8_context_snapshot.bin` | Not disclosed | Encrypted Rust payload |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `archivetj[.]com` | Rust payload C2 — plugin delivery |
| Domain | `www[.]archivetj[.]com` | Rust payload C2 — primary communication |
| Cloud Service | Google Drive, OneDrive, Yandex.Disk | .NET RAT secondary C2 channels |

### Certificates

| Attribute | Value |
|-----------|-------|
| Subject | Wenjiang District Mingyu Network Technology Service Studio |
| Serial | `0bcdf5e0da32d68900b8b7638459d072` |
| Status | Revoked |

### Behavioral

- BlackX installer uses RC4 decryption key `Q46F6MDLI3RX2KV1` passed as command-line argument
- DLL sideloading via renamed `jcef_helper.exe` → `googleupdate.exe`
- Kernel driver disables ETW providers and security product callbacks
- File-access interception returns `calc.exe` handle to hide bootkit files
- `create_plugin` export in remotely delivered DLL plugins
- `xdd` attribution string shared with FishMonger kernel implant

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1542.003 | Pre-OS Boot: Bootkit | UEFI bootkit persists via Baton Drop exploitation and MOK registration |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | OxiDLLRunner sideloaded via renamed jcef_helper.exe |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Binary renamed to googleupdate.exe |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Driver disables ETW, security callbacks |
| T1102 | Web Service | C2 via Google Drive, OneDrive, Yandex.Disk |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 to archivetj.com |
| T1105 | Ingress Tool Transfer | Plugin DLLs downloaded from C2 |
| T1027 | Obfuscated Files or Information | RC4-encrypted payloads, OLLVM obfuscation |
| T1553.006 | Subvert Trust Controls: Code Signing Policy Modification | MOK registration to bypass Secure Boot |

## Impact Assessment

The campaign targets diplomatic organizations in Central Asia (Tajikistan, Uzbekistan, Turkmenistan), consistent with Chinese state espionage interests. UEFI-level persistence makes detection and remediation exceptionally difficult — the bootkit survives OS reinstallation and disk replacement. Any organization that patched CVE-2022-21894 but did not apply the manual DBX revocation is potentially vulnerable if an attacker achieves administrator access.

## Detection & Remediation

### Immediate Detection

1. Search for `C:\ProgramData\Intel\inst.exe` and `PVMDIJGKAX2` on endpoints
2. Query DNS logs for `archivetj.com` or `www.archivetj.com`
3. Check for processes where OriginalFileName is `jcef_helper.exe` but Image path ends in `googleupdate.exe`
4. Scan for certificate serial `0bcdf5e0da32d68900b8b7638459d072` in loaded drivers
5. Check Windows Event ID 1037 (Secure Boot revocation) — absence may indicate incomplete patching

### Remediation

1. **Apply DBX revocation immediately**: Follow KB5025885 to add Windows Production PCA 2011 to the Secure Boot Forbidden Signature Database. Verify with Event ID 1037.
2. **Incident response**: If BlackX artifacts are found, assume full system compromise including firmware. Reimaging alone is insufficient — UEFI firmware must be reflashed from a known-good image.
3. **Credential rotation**: Assume all credentials on compromised hosts are captured.
4. **Block C2**: Block `archivetj[.]com` at DNS and web proxy level. Note cloud C2 channels use legitimate services — monitor for anomalous cloud storage API access patterns.

### Long-Term Hardening

1. Audit DBX revocation status across all managed endpoints — do not rely on patch compliance alone
2. Enable Measured Boot with TPM attestation to detect boot chain tampering
3. Restrict local administrator privileges to reduce initial access surface
4. Monitor for unsigned or suspiciously signed kernel drivers via driver block list policies

## Detection Rules

These detections target the BlackX UEFI bootkit installer chain, DLL sideloading, staging artifacts, and C2 communication. All Sigma rules convert to Splunk and CrowdStrike (LogScale). `sigma check` ATT&CK tag validation could not complete due to proxy restrictions; tags validated manually.

### Sigma: BlackX Installer Execution
Detects execution of `inst.exe` from the known staging path with the RC4 payload file or key as arguments.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. Keyed on unique installer path + hardcoded RC4 key/payload name. No known benign use of PVMDIJGKAX2 or Q46F6MDLI3RX2KV1 strings. -->
```yaml
title: BlackX UEFI Bootkit Installer Execution
id: 7a3e1b4c-9d2f-4e8a-b1c5-6f3d8e2a9b7c
status: experimental
description: Detects execution of the BlackX bootkit installer inst.exe from its known staging path with the RC4-encrypted payload file as argument.
references:
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
    - https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/
author: Actioner
date: 2026/10/28
tags:
    - attack.t1542.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|endswith: '\inst.exe'
        Image|contains: '\ProgramData\Intel\'
    selection_cmdline:
        CommandLine|contains:
            - 'PVMDIJGKAX2'
            - 'Q46F6MDLI3RX2KV1'
    condition: selection_path and selection_cmdline
falsepositives:
    - Unlikely - both the path and argument strings are highly specific to BlackX
level: critical
```

### Sigma: BlackX OxiDLLRunner Sideloading via Fake Google Update
Detects DLL sideloading where the PE original filename is `jcef_helper.exe` but the process image ends with `googleupdate.exe`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. OriginalFileName from PE metadata is rename-resistant. Pairing with mismatched Image|endswith is highly distinctive. -->
```yaml
title: BlackX OxiDLLRunner Sideloading via Fake Google Update
id: 2c8f5a1d-7b3e-4d9c-a6f2-1e4b8c3d5a7f
status: experimental
description: Detects DLL sideloading of the OxiDLLRunner payload via a renamed jcef_helper.exe binary masquerading as googleupdate.exe, a known BlackX UEFI bootkit technique.
references:
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
    - https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/
author: Actioner
date: 2026/10/28
tags:
    - attack.t1574.002
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'jcef_helper.exe'
        Image|endswith: '\googleupdate.exe'
    condition: selection
falsepositives:
    - Legitimate jcef_helper.exe renamed to googleupdate.exe is extremely unlikely
level: high
```

### Sigma: BlackX Staging File Creation
Detects creation of BlackX-specific staging files (extensionless RC4 container and encrypted Rust payload) in the known staging directory.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. PVMDIJGKAX2 is a unique 11-char alphanumeric identifier with no benign meaning. -->
```yaml
title: BlackX Bootkit Staging File Creation
id: 9e1d4b6a-3c7f-4a2e-8d5b-0f6c9a1e3b8d
status: experimental
description: Detects creation of BlackX-specific staging files in the ProgramData\Intel directory, including the encrypted payload container and the encrypted Rust payload.
references:
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
    - https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/
author: Actioner
date: 2026/10/28
tags:
    - attack.t1542.003
    - attack.t1027
logsource:
    category: file_event
    product: windows
detection:
    selection_payload:
        TargetFilename|endswith:
            - '\ProgramData\Intel\PVMDIJGKAX2'
            - '\ProgramData\Intel\inst.exe'
    selection_rust:
        TargetFilename|endswith: '\v8_context_snapshot.bin'
        TargetFilename|contains: '\ProgramData\Intel\'
    condition: selection_payload or selection_rust
falsepositives:
    - The extensionless file name PVMDIJGKAX2 is unique to BlackX
level: high
```

### Sigma: BlackX C2 Domain Resolution
Detects DNS query for `archivetj.com`, the known C2 domain used by the BlackX Rust payload.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. Domain archivetj.com is purpose-registered C2 infra with no legitimate services. -->
```yaml
title: BlackX C2 Domain Resolution - archivetj.com
id: 4f2a8c3d-1e6b-4d7a-9c5f-3b8e2d1a6c4f
status: experimental
description: Detects DNS resolution of archivetj.com, the known C2 domain used by the BlackX UEFI bootkit Rust-based payload for plugin delivery.
references:
    - https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html
    - https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/
author: Actioner
date: 2026/10/28
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'archivetj.com'
    condition: selection
falsepositives:
    - Legitimate access to archivetj.com is unlikely in most enterprise environments
level: critical
```

### Suricata: BlackX C2 DNS and HTTP
Detects DNS queries and HTTP connections to the BlackX C2 domain archivetj.com.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. DNS query and HTTP host content match on purpose-registered C2 domain. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - BlackX UEFI Bootkit C2 DNS Query for archivetj.com"; dns.query; content:"archivetj.com"; nocase; endswith; classtype:trojan-activity; reference:url,thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html; metadata:author Actioner, created_at 2026-10-28; sid:2200301; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - BlackX OxiDLLRunner Plugin Download from archivetj.com"; flow:established,to_server; http.host; content:"archivetj.com"; endswith; http.method; content:"GET"; classtype:trojan-activity; reference:url,blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/; metadata:author Actioner, created_at 2026-10-28; sid:2200302; rev:1;)
```

### Snort: BlackX C2 HTTP Communication
Detects HTTP connections to the BlackX C2 domain archivetj.com.
**Status:** ⚠️ uncompiled (structural check only) — snort not installed in this environment
<!-- audit: structural check only; snort binary absent. Rule uses standard http service, content match on Host header. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - BlackX UEFI Bootkit C2 Communication to archivetj.com"; flow:established,to_server; content:"archivetj.com"; http_header; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html; metadata:author Actioner, created 2026-10-28; sid:2100301; rev:1;)
```

### YARA: BlackX Installer and OxiDLLRunner Artifacts
Detects BlackX installer, OxiDLLRunner DLL, and binaries signed with the revoked certificate via distinctive strings and certificate serial.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Three rules: APT41_BlackX_Installer (3-of-6 strings including RC4 key, payload name, C2 domain), APT41_BlackX_OxiDLLRunner (jcef_helper.exe + C2/export), APT41_BlackX_Certificate (cert serial bytes + CN string). Positive test fired on constructed sample with published strings; negative test quiet. Cert serial bytes extracted from published serial 0bcdf5e0da32d68900b8b7638459d072. -->
```yara
rule APT41_BlackX_Installer : bootkit apt41
{
    meta:
        description = "Detects BlackX UEFI bootkit installer or payload artifacts via distinctive strings"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $payload_name = "PVMDIJGKAX2" ascii wide
        $c2_domain = "archivetj.com" ascii wide
        $export_fn = "create_plugin" ascii
        $xdd_marker = "xdd" ascii fullword
        $staging_path = "\\ProgramData\\Intel\\inst.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule APT41_BlackX_OxiDLLRunner : sideload apt41
{
    meta:
        description = "Detects BlackX OxiDLLRunner DLL sideloaded via jcef_helper.exe renamed as googleupdate.exe"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/"
        hash = "af8a983b9ada07eae1259bf2953abd40"
        tlp = "WHITE"
        severity = "high"

    strings:
        $orig_name = "jcef_helper.exe" ascii wide
        $c2 = "archivetj.com" ascii wide
        $export = "create_plugin" ascii
        $v8_snap = "v8_context_snapshot.bin" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide

    condition:
        uint16(0) == 0x5A4D and (($orig_name and ($c2 or $export)) or (3 of them))
}

rule APT41_BlackX_Certificate : certificate apt41
{
    meta:
        description = "Detects binaries signed with the revoked certificate used by BlackX bootkit kernel driver"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $cert_serial = { 0B CD F5 E0 DA 32 D6 89 00 B8 B7 63 84 59 D0 72 }
        $cert_cn = "Wenjiang District Mingyu Network Technology Service Studio" ascii wide

    condition:
        uint16(0) == 0x5A4D and any of them
}
```

## Lessons Learned

1. **Patch ≠ Protected**: The gap between applying Microsoft's CVE-2022-21894 patch and completing the manual DBX revocation creates a window for UEFI-level compromise. Compliance dashboards that show "patched" may be misleading.
2. **UEFI persistence is real**: BlackX joins BlackLotus, MosaicRegressor, and MoonBounce in demonstrating that UEFI bootkits are no longer theoretical — they're deployed in targeted espionage campaigns.
3. **Cloud C2 complicates detection**: Using Google Drive, OneDrive, and Yandex.Disk as C2 channels means blocking the C2 requires behavioral analysis, not just domain/IP blocklisting.
4. **Certificate revocation is not instantaneous**: The Wenjiang District certificate was revoked, but signed binaries remain valid until explicitly distrusted. Driver block lists and WDAC policies provide defense in depth.

## Sources

- [The Hacker News](https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html) — Primary coverage with IOCs and infection chain details
- [NetManageIT Blog](https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/) — Additional IOCs including MD5 hash and certificate serial
- [DEV Community (anoymask)](https://dev.to/anoymask/blackx-apt41-associated-uefi-bootkit-bypassing-secure-boot-via-baton-drop-9pl) — Detailed IOC compilation including v8_context_snapshot.bin and OxiDLLRunner details
- [Kaspersky Securelist](https://securelist.com/blackx-uefi-bootkit/) — Primary research source (full report titled "How APT41 revived the BlackLotus bootkit to attack diplomatic organizations in Central Asia"; exact URL may differ — search Securelist for BlackX)

---
*Report generated by Actioner*
