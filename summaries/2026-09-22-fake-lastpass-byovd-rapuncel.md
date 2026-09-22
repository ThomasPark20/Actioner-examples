# Fake LastPass Authenticator BYOVD + Rapuncel Stealer Campaign

**Date:** 2026-09-22 | **Status:** Final | **TLP:** CLEAR | **Altitude:** PoC/Advisory-Specific

---

## Executive Summary

A malware-as-a-service (MaaS) campaign impersonating LastPass Authenticator distributes trojanized installers via SEO-poisoned GitHub repositories. The installer performs DLL side-loading through a renamed Microsoft debugger (`vsdbg.exe`), loads a Microsoft-signed BYOVD kernel driver (`Alinubx.sys`, a renamed copy of `CcProtect.sys` from CnCrypt) to terminate 145 EDR/AV products via IOCTL `0x222024`, and deploys the "Rapuncel" infostealer. The stealer harvests credentials from 25+ browsers (including Chrome app-bound encryption bypass), 30+ crypto wallets, Discord/Steam/Telegram sessions, and Windows Credential Manager, then exfiltrates a ZIP archive to `2[.]26[.]126[.]50`. The campaign uses the Cruciferra PUROSANGUE crypter and shares infrastructure and artifacts with the BoryptGrab stealer family documented by Trend Micro (March 2026). At least 40 companies are impersonated via the `albinofennel[.]com` kit.

## Sources

| Source | URL |
|--------|-----|
| The Hacker News | [Fake LastPass Authenticator Installer](https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html) |
| SecurityWeek | [Fake LastPass Installers Push Kernel-Level EDR Killer](https://www.securityweek.com/fake-lastpass-installers-push-kernel-level-edr-killer-rapuncel-stealer/) |
| LastPass / Delphos Labs Joint Report | [Rapuncel Infostealer Report](https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer) |
| LOLDrivers - Alinubx.sys | [LOLDrivers 84a3007a](https://www.loldrivers.io/drivers/84a3007a-de5e-4622-bfc5-f05d927c3618/) |
| LOLDrivers - CcProtect.sys | [LOLDrivers 3e3067b0](https://www.loldrivers.io/drivers/3e3067b0-3d74-46fe-9f57-1ae3a0293958/) |
| Microsoft Driver Blocklist | [Microsoft Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) |

## Viability Gate

| Criterion | Status |
|-----------|--------|
| Public IOCs with hashes | PASS - 6 SHA256 hashes, MD5/SHA1 for drivers |
| Named malware components | PASS - Rapuncel, Cruciferra PUROSANGUE, Alinubx.sys |
| Attack chain documented | PASS - Full 13-step chain from LastPass/Delphos |
| Network IOCs | PASS - 4 domains, 1 exfil IP, 3 GitHub Pages redirectors |
| Detection feasibility | PASS - Driver hashes, file paths, service names, network indicators |
| **Gate result** | **PASS** |

## Kill Chain

```
                 GitHub SEO Lure
                       |
          lastpass-authenticator.github.io
                       |
       Hidden GitHub Pages 404.html Redirectors
       (edgarcostartqd / dallikilic54)
                       |
         istatlmenus[.]com/mandua.wonted
           (Cloudflare traffic director)
                       |
          albinofennel[.]com / hanselarinmusky[.]com
                (payload delivery)
                       |
     ZIP Archive (148MB / 127.9MB, padded with junk)
                       |
          vsdbg.exe (renamed MS debugger)
            + vsdbg.dll (Cruciferra loader)
                       |
          3x UAC Bypass -> SYSTEM
                       |
     NvFsFilter service -> nvfsflt64.sys
     (Alinubx.sys BYOVD driver, IOCTL 0x222024)
                       |
        Terminates 145 AV/EDR processes
                       |
         Rapuncel Stealer Deployed
   (browsers, wallets, Discord, Steam, Telegram,
    Windows Credential Manager, screenshots)
                       |
        Chrome App-Bound Encryption Bypass
        (browser injection DLL -> Elevation Service)
                       |
     ZIP exfiltration -> POST /upload
          2[.]26[.]126[.]50 (3 retries)
```

## MITRE ATT&CK Mapping

| ID | Technique | Campaign Usage |
|----|-----------|----------------|
| T1574.002 | DLL Side-Loading | vsdbg.exe loads malicious vsdbg.dll |
| T1548.002 | Bypass User Account Control | 3 UAC bypass methods to reach SYSTEM |
| T1562.001 | Disable or Modify Tools | Kernel driver terminates 145 AV/EDR processes |
| T1068 | Exploitation for Privilege Escalation | BYOVD driver exploitation |
| T1543.003 | Create or Modify System Process: Windows Service | NvFsFilter service creation |
| T1555.003 | Credentials from Web Browsers | Chrome/Edge app-bound encryption bypass |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Windows Credential Manager harvesting |

## IOCs

### File Hashes

| Component | SHA256 | MD5 |
|-----------|--------|-----|
| vsdbg.dll (Cruciferra loader) | `ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6` | -- |
| Rapuncel stealer payload | `aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd` | -- |
| Alinubx.sys (BYOVD driver) | `611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61` | `10b3049f4a954665512eca5d24728c89` |
| Browser injection DLL | `75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40` | -- |
| ProtectR3.dll x64 (unpacked) | `26db14b956e33f69b3397a36387d32e01eb63613acff91069dc76b6ed7de45a8` | -- |
| CcProtect.sys v1.32 (original) | `5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c` | `e74d70c851e0c39cdb19af3bd2920efd` |
| istatlmenus[.]com JS payload | `1e6c1766ac78d7adfdae71d361cb132d972771897ae9065503b135cb812d7c35` | -- |

<!-- audit: All SHA256 hashes sourced from LastPass/Delphos joint report via blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer. MD5 for Alinubx.sys confirmed via LOLDrivers entry 84a3007a. MD5 for CcProtect.sys confirmed via LOLDrivers entry 3e3067b0. -->

### Alinubx.sys Extended Hashes (LOLDrivers)

| Type | Value |
|------|-------|
| SHA256 | `611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61` |
| SHA1 | `172c5ce3afab6d63fe12a7e036f20271b9d09c13` |
| MD5 | `10b3049f4a954665512eca5d24728c89` |
| Imphash | `57a2f40fccb4fb28f3e0fc12f06cf4b2` |
| Authentihash MD5 | `207e7aaa3c30c8dffeb20fd8f3b72852` |
| Authentihash SHA1 | `1cbb8931e81f662af15b71db621d78d7988fe704` |
| Authentihash SHA256 | `c202e7bb00135434321dad49f6c746b1ea071f6e7400a598438868f660f0e887` |

### CcProtect.sys v1.32 Extended Hashes (LOLDrivers)

| Type | Value |
|------|-------|
| SHA256 | `5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c` |
| SHA1 | `0cbc7b342fa3e988192d6c9178c562c2244c3ea2` |
| MD5 | `e74d70c851e0c39cdb19af3bd2920efd` |
| Imphash | `dd0b39ba9e2c95e68b934a065d9144bc` |
| Authentihash MD5 | `c44f751b6b255ab1646133301d7c03cd` |
| Authentihash SHA1 | `83a3311c1a92dacabbd026f807ffb05bf74299a1` |
| Authentihash SHA256 | `61b268c31404e7b77868f5efdc2f134fffcf3059680e1ac26d93ead48529f9a7` |

### Network IOCs

| Type | Indicator | Role |
|------|-----------|------|
| Domain | `albinofennel[.]com` | Primary payload server (40+ branded lures) |
| Domain | `hanselarinmusky[.]com` | Secondary payload server |
| Domain | `icansamyope[.]com` | Tertiary payload server |
| Domain | `istatlmenus[.]com` | Cloudflare-fronted traffic director |
| Domain | `macperformancetools[.]com` | Terminal redirect (parked) |
| Domain | `zaffersnouty[.]com` | Terminal redirect (parked) |
| IP | `2[.]26[.]126[.]50` | Exfiltration endpoint (POST /upload) |
| IP | `104[.]21[.]27[.]38` | Cloudflare proxy (albinofennel) |
| IP | `172[.]67[.]168[.]224` | Cloudflare proxy (albinofennel) |
| IP | `172[.]67[.]212[.]253` | Cloudflare proxy (istatlmenus) |
| IP | `104[.]21[.]20[.]224` | Cloudflare proxy (macperformancetools) |
| IP | `104[.]21[.]18[.]89` | Cloudflare proxy (zaffersnouty) |
| URL | `istatlmenus[.]com/mandua.wonted` | JavaScript redirect payload |
| GitHub | `lastpass-authenticator[.]github[.]io` | Initial lure page |
| GitHub | `edgarcostartqd[.]github[.]io` | Hidden waypoint (404.html) |
| GitHub | `dallikilic54[.]github[.]io` | Hidden waypoint (404.html) |
| GitHub Org | `github[.]com/LastPass-Authenticator` | Fake organization |
| GitHub Org | `github[.]com/LastPass-S` | Secondary (macOS variant) |

### Host IOCs

| Type | Indicator |
|------|-----------|
| File path | `C:\Windows\System32\drivers\nvfsflt64.sys` |
| Service name | `NvFsFilter` |
| Service description | "NVIDIA File System Filter Driver" |
| Device path | `\\.\Alinubx` |
| IOCTL code | `0x222024` |
| Registry target | `HKCU\Software\Google\Chrome\PreferenceMACs\Default\extensions.settings` |
| Temp artifact | `%TEMP%\browser_decryption.log` |
| Temp artifact | `%TEMP%\sends.log` |
| Collection artifact | `UserInformation.txt` (with BUILD NAME field) |
| Collection artifact | `installed_applications.txt` |
| Collection artifact | `Filegraber` (misspelled directory) |
| Junk files | `TitanStorage.dll`, `ProManager.dll` |
| Archive names | `LastPass-Authenticator-download-1.66.2.zip` (148MB) |
| Archive names | `lastpass-authenticator-2.78.7.zip` (127.9MB) |
| Build string | `C:\ExploitTests\purosangue.tx` |
| Favicon dhash | `3761dd64e0d46913` (kit identification pivot) |
| Driver signer | Microsoft Windows Hardware Compatibility Publisher |
| Driver original signer | Henan Dafeng Software Co., Ltd. |
| Driver signing date | March 2023 |

### Driver Details

- **Deployed name:** `Alinubx.sys` (renamed from `CcProtect.sys`)
- **Original product:** CnCrypt disk-encryption (Henan Dafeng Software Co., Ltd.)
- **Version:** 1.32
- **Architecture:** AMD64
- **Signing chain:** Microsoft Windows Hardware Compatibility Publisher (attestation-signed)
- **VirusTotal detections:** 0/72 as of 2026-08-20
- **Microsoft Driver Blocklist status:** NOT PRESENT as of 2026-08-20
- **Kill mechanism:** IOCTL `0x222024` -> `PsLookupProcessByProcessId` -> `ObOpenObjectByPointer` -> `ZwTerminateProcess`
- **Targeted processes:** 145 AV/EDR product process names (hardcoded list, not enumerated in public reports)

## Detection Rules

---

### Sigma: BYOVD Driver Load Detection

Detects loading of the Alinubx.sys or nvfsflt64.sys kernel driver (or their known SHA256/MD5 hashes) used in the Rapuncel BYOVD campaign to terminate security products.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: sigma check passed with custom validation config (MITRE ATT&CK tag validator excluded due to proxy-blocked network fetch — not a rule error). Splunk and LogScale conversion both produce syntactically valid output. Hashes sourced from LOLDrivers entries 84a3007a and 3e3067b0. File paths sourced from LastPass/Delphos report. -->

```yaml
title: Rapuncel Campaign - Alinubx.sys BYOVD Driver Load
id: 19f3e831-f269-4baa-ae73-236445634f80
status: experimental
description: Detects loading of the Alinubx.sys kernel driver (renamed CcProtect.sys from CnCrypt) used in the Rapuncel stealer campaign to kill EDR/AV processes via BYOVD.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
    - https://www.loldrivers.io/drivers/84a3007a-de5e-4622-bfc5-f05d927c3618/
    - https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html
author: Actioner
date: 2026-09-22
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1068
logsource:
    category: driver_load
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61'
            - '5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c'
            - '10b3049f4a954665512eca5d24728c89'
            - 'e74d70c851e0c39cdb19af3bd2920efd'
    selection_name:
        ImageLoaded|endswith:
            - '\Alinubx.sys'
            - '\nvfsflt64.sys'
    condition: selection_hash or selection_name
falsepositives:
    - Legitimate CnCrypt/CcProtect.sys usage (rare outside China)
level: critical
```

---

### Sigma: NvFsFilter Fake NVIDIA Service Installation

Detects registry writes creating the NvFsFilter service or referencing nvfsflt64.sys, which is the fake NVIDIA service name the Rapuncel campaign uses to load its BYOVD driver.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Rule keys on specific service name "NvFsFilter" and driver path "nvfsflt64.sys" from LastPass/Delphos report. False positive rate expected near-zero — legitimate NVIDIA drivers use NVDisplay/nvlddmkm service names, not NvFsFilter. -->

```yaml
title: Rapuncel Campaign - NvFsFilter Fake NVIDIA Service Installation
id: adebb372-e43d-4085-b14c-71aa79c338d2
status: experimental
description: Detects creation of the NvFsFilter service used by the Rapuncel campaign to load its BYOVD kernel driver disguised as an NVIDIA File System Filter Driver.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
    - https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html
author: Actioner
date: 2026-09-22
tags:
    - attack.persistence
    - attack.t1543.003
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: registry_set
detection:
    selection_service:
        TargetObject|contains: '\Services\NvFsFilter'
    selection_driver_path:
        Details|contains: 'nvfsflt64.sys'
    condition: selection_service or selection_driver_path
falsepositives:
    - Legitimate NVIDIA file system filter drivers use different service names (NVDisplay, nvlddmkm)
level: critical
```

---

### Sigma: vsdbg.exe DLL Side-Loading Outside Visual Studio

Detects execution of vsdbg.exe from any path other than its legitimate Visual Studio, .vscode, or dotnet installation directories, indicating potential DLL side-loading. This is a broader hunt rule -- vsdbg.exe side-loading has been observed in the Rapuncel campaign but is not exclusive to it.

**Status:** compile ✅ compiles · confidence: medium

<!-- audit: vsdbg.exe is Microsoft's .NET Core debugger. Outside its standard installation directories it is a strong indicator of DLL side-loading. Filter covers VS, VS Code, VS extensions, and dotnet shared runtime. Retitled from campaign-specific to broader hunt rule per altitude review -- detection is generic vsdbg outside VS dirs without campaign-specific co-indicators. Confidence lowered from high to medium accordingly. -->

```yaml
title: vsdbg.exe DLL Side-Loading Outside Visual Studio Directories
id: 92651a82-a1f6-4eae-aaf3-831d56cccf36
status: experimental
description: Detects execution of vsdbg.exe outside its normal Visual Studio installation paths, which may indicate DLL side-loading. Observed in the Rapuncel stealer campaign (Cruciferra loader) but applicable to any abuse of vsdbg.exe for side-loading.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
    - https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vsdbg.exe'
    filter_legitimate:
        Image|contains:
            - '\Microsoft Visual Studio\'
            - '\.vscode\'
            - '\.vs\extensions\'
            - '\dotnet\shared\'
    condition: selection and not filter_legitimate
falsepositives:
    - Portable or custom Visual Studio debugging setups
level: medium
```

---

### Sigma: Rapuncel Stealer EXE by Hash (process_creation)

Detects execution of the known Rapuncel stealer EXE payload identified by its SHA256 hash from the LastPass/Delphos report.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Pure hash-based detection. SHA256 for the Rapuncel stealer EXE payload from LastPass/Delphos joint report. Zero false positive risk but limited to exact known sample. Split from original combined rule: process_creation logsource only logs hashes of spawned process images (EXEs), not loaded DLLs. -->

```yaml
title: Rapuncel Campaign - Stealer EXE by Hash
id: 1d564361-011e-458c-b6ba-094cdd838daf
status: experimental
description: Detects execution of the known Rapuncel stealer EXE payload by its SHA256 hash.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
    - https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.credential_access
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
            - 'aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

---

### Sigma: Rapuncel Campaign DLLs by Hash (image_load)

Detects loading of known Rapuncel campaign DLL components (Cruciferra vsdbg.dll loader, browser injection DLL, ProtectR3.dll) identified by their SHA256 hashes from the LastPass/Delphos report. Uses the `image_load` logsource (Sysmon EID 7) which captures hashes of loaded DLLs.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Pure hash-based detection. Three SHA256 values for DLL components from LastPass/Delphos joint report. Split from original combined rule: DLL hashes appear in image_load (Sysmon EID 7) with ImageLoaded and Hashes fields, not in process_creation which only logs hashes of the spawned process image (EXE). -->

```yaml
title: Rapuncel Campaign - Malicious DLLs by Hash
id: 7a2e9c45-83b1-4d6f-a5e2-1f8b3c094d7e
status: experimental
description: Detects loading of known Rapuncel campaign DLLs (Cruciferra loader vsdbg.dll, browser injection DLL, ProtectR3.dll) by their SHA256 hashes via Sysmon image_load events.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
    - https://thehackernews.com/2026/09/fake-lastpass-authenticator-installer.html
author: Actioner
date: 2026-09-22
tags:
    - attack.execution
    - attack.t1574.002
    - attack.credential_access
    - attack.t1555.003
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Hashes|contains:
            - 'ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6'
            - '75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40'
            - '26db14b956e33f69b3397a36387d32e01eb63613acff91069dc76b6ed7de45a8'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

---

### Sigma: Chrome App-Bound Encryption Bypass via Elevation Service

Detects non-browser processes accessing Chrome's Elevation Service, a technique used by multiple infostealers (Rapuncel, Lumma, Vidar, and others) to call the DecryptData method and bypass app-bound encryption for credential theft. This is a broader hunt rule not specific to any single campaign.

**Status:** compile ✅ compiles · confidence: medium

<!-- audit: Elevation Service access by non-Chrome/Edge processes is abnormal. Filter excludes legitimate browser binaries. Chrome ABEK bypass is a generic technique used by multiple stealer families (Lumma, Vidar, Rapuncel, etc.). Retitled from campaign-specific to broader hunt rule per altitude review. Confidence lowered to medium due to potential false positives from browser management tools. -->

```yaml
title: Chrome App-Bound Encryption Bypass via Elevation Service
id: f11abd63-87d8-4486-a886-e2d61a9bac32
status: experimental
description: Detects suspicious non-browser process accessing Chrome Elevation Service for DecryptData, a technique used by multiple infostealers (Rapuncel, Lumma, Vidar) to bypass app-bound encryption and harvest browser credentials.
references:
    - https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer
author: Actioner
date: 2026-09-22
tags:
    - attack.credential_access
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'elevation_service'
    filter_chrome:
        Image|contains:
            - '\Google\Chrome\'
            - '\Microsoft\Edge\'
    filter_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
    condition: selection and not (filter_chrome or filter_parent)
falsepositives:
    - Third-party browser management tools
    - Enterprise browser management solutions
level: medium
```

---

### YARA: Rapuncel Campaign Multi-Rule Set

Five YARA rules covering the BYOVD driver (Alinubx.sys / CcProtect.sys), the Cruciferra PUROSANGUE loader (vsdbg.dll), the Rapuncel stealer payload, the browser injection DLL, and the fake LastPass installer archive.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: yarac compiled to /dev/null with exit code 0. Rules use pe and hash modules. Hash-based matching provides zero-FP anchor. String-based matching for PUROSANGUE build path, custom Base16 alphabet (0x50-0x5F), device path "\\.\Alinubx", and stealer artifacts (browser_decryption.log, Filegraber misspelling). Archive rule triggers on ZIP > 100MB with LastPass naming and junk padding DLLs. -->

```yara
import "pe"
import "hash"

rule Rapuncel_Alinubx_BYOVD_Driver {
    meta:
        description = "Detects Alinubx.sys BYOVD driver (renamed CcProtect.sys) used in Rapuncel campaign to terminate security products"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        reference2 = "https://www.loldrivers.io/drivers/84a3007a-de5e-4622-bfc5-f05d927c3618/"
        hash1 = "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $device_path = "\\\\.\\Alinubx" wide ascii
        $original_name = "CcProtect" wide ascii
        $publisher = "CnCrypt" wide ascii
        $dafeng = "Henan Dafeng" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            2 of ($device_path, $original_name, $publisher, $dafeng) or
            hash.sha256(0, filesize) == "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61" or
            hash.sha256(0, filesize) == "5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c"
        )
}

rule Rapuncel_Cruciferra_Loader {
    meta:
        description = "Detects vsdbg.dll loader built with Cruciferra PUROSANGUE crypter used in Rapuncel campaign"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6"
        severity = "critical"

    strings:
        $build_path = "ExploitTests\\purosangue" ascii nocase
        $custom_b16 = { 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F }
        $reloc_payload = ".reloc" ascii
        $vsdbg_name = "vsdbg.dll" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            $build_path or
            ($custom_b16 and $reloc_payload and $vsdbg_name and pe.number_of_sections > 4) or
            hash.sha256(0, filesize) == "ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6"
        )
}

rule Rapuncel_Stealer_Payload {
    meta:
        description = "Detects Rapuncel infostealer payload targeting browsers, crypto wallets, and messaging apps"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd"
        severity = "critical"

    strings:
        $log1 = "browser_decryption.log" ascii wide
        $log2 = "sends.log" ascii wide
        $artifact1 = "UserInformation.txt" ascii wide
        $artifact2 = "installed_applications.txt" ascii wide
        $artifact3 = "Filegraber" ascii wide
        $harvest1 = "PreferenceMACs" ascii wide
        $harvest2 = "extensions.settings" ascii wide
        $upload = "/upload" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($log1, $log2, $artifact1, $artifact2, $artifact3)) or
            ($harvest1 and $harvest2 and $upload) or
            hash.sha256(0, filesize) == "aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd"
        )
}

rule Rapuncel_Browser_Injection_DLL {
    meta:
        description = "Detects the browser injection DLL used by Rapuncel to bypass Chrome app-bound encryption"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40"
        severity = "high"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40" or
            hash.sha256(0, filesize) == "26db14b956e33f69b3397a36387d32e01eb63613acff91069dc76b6ed7de45a8"
        )
}

rule Rapuncel_Fake_LastPass_Archive {
    meta:
        description = "Detects fake LastPass Authenticator installer archives used for Rapuncel distribution"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        severity = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $lp_name1 = "LastPass-Authenticator" ascii wide
        $lp_name2 = "lastpass-authenticator" ascii wide
        $junk1 = "TitanStorage.dll" ascii wide
        $junk2 = "ProManager.dll" ascii wide
        $vsdbg = "vsdbg" ascii wide

    condition:
        $zip_magic at 0 and
        filesize > 100MB and
        (1 of ($lp_name*)) and
        (1 of ($junk*) or $vsdbg)
}
```

---

### Snort: Rapuncel Campaign Network Detection

Six Snort rules detecting exfiltration to the known C2 IP (`2[.]26[.]126[.]50`), DNS queries to the four campaign domains (`albinofennel[.]com`, `hanselarinmusky[.]com`, `icansamyope[.]com`, `istatlmenus[.]com`), and access to the traffic director endpoint (`/mandua.wonted`).

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Snort 2.9.20 validated via include directive appended to /etc/snort/snort.conf. DNS content patterns use standard label-length encoding. HTTP rules use flow:to_server,established and http_method/http_uri modifiers. SIDs 2026001-2026006 in reserved range. Cloudflare proxy IPs intentionally excluded from IP-based rules to avoid false positives on shared infrastructure. -->

```
# Rapuncel Campaign - Network Detection Rules (Snort)
# Reference: https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer

# Detect C2 exfiltration to known IP
alert tcp $HOME_NET any -> 2.26.126.50 any (msg:"MALWARE Rapuncel Stealer - Exfiltration to Known C2 IP"; flow:to_server,established; content:"POST"; http_method; content:"/upload"; http_uri; classtype:trojan-activity; sid:2026001; rev:1;)

# Detect known payload domains in DNS
alert udp $HOME_NET any -> any 53 (msg:"MALWARE Rapuncel Campaign - DNS Query for albinofennel.com"; content:"|0c|albinofennel|03|com|00|"; nocase; classtype:trojan-activity; sid:2026002; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"MALWARE Rapuncel Campaign - DNS Query for hanselarinmusky.com"; content:"|0f|hanselarinmusky|03|com|00|"; nocase; classtype:trojan-activity; sid:2026003; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"MALWARE Rapuncel Campaign - DNS Query for icansamyope.com"; content:"|0b|icansamyope|03|com|00|"; nocase; classtype:trojan-activity; sid:2026004; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"MALWARE Rapuncel Campaign - DNS Query for istatlmenus.com"; content:"|0b|istatlmenus|03|com|00|"; nocase; classtype:trojan-activity; sid:2026005; rev:1;)

# Detect traffic director endpoint
alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"MALWARE Rapuncel Campaign - Traffic Director Endpoint Access"; flow:to_server,established; content:"GET"; http_method; content:"/mandua.wonted"; http_uri; classtype:trojan-activity; sid:2026006; rev:1;)
```

---

### Suricata: Rapuncel Campaign Network Detection

Six Suricata rules using modern protocol-aware keywords (`http.method`, `http.uri`, `dns.query`) to detect exfiltration traffic, domain queries, and traffic director endpoint access.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Suricata 7.0.3 validated with -T -S flag. Rules use sticky buffers (http.method, http.uri, dns.query) appropriate for Suricata 7.x. SIDs 3026001-3026006. DNS rules use endswith for domain matching. SID 3026007 (generic ZIP upload pattern) dropped per review — too generic (POST /upload with application/zip fires on any app uploading ZIPs) and SID 3026001 already covers the campaign-specific case pinned to C2 IP. -->

```
# Rapuncel Campaign - Network Detection Rules (Suricata)
# Reference: https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer

# Detect exfiltration POST to known C2 IP
alert http $HOME_NET any -> 2.26.126.50 any (msg:"MALWARE Rapuncel Stealer - Exfiltration to Known C2 IP"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/upload"; classtype:trojan-activity; sid:3026001; rev:1;)

# Detect known payload domain DNS queries
alert dns $HOME_NET any -> any any (msg:"MALWARE Rapuncel Campaign - DNS Query for albinofennel.com"; dns.query; content:"albinofennel.com"; nocase; endswith; classtype:trojan-activity; sid:3026002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE Rapuncel Campaign - DNS Query for hanselarinmusky.com"; dns.query; content:"hanselarinmusky.com"; nocase; endswith; classtype:trojan-activity; sid:3026003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE Rapuncel Campaign - DNS Query for icansamyope.com"; dns.query; content:"icansamyope.com"; nocase; endswith; classtype:trojan-activity; sid:3026004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"MALWARE Rapuncel Campaign - DNS Query for istatlmenus.com"; dns.query; content:"istatlmenus.com"; nocase; endswith; classtype:trojan-activity; sid:3026005; rev:1;)

# Detect traffic director endpoint
alert http $HOME_NET any -> any any (msg:"MALWARE Rapuncel Campaign - Traffic Director Endpoint Access"; flow:to_server,established; http.method; content:"GET"; http.uri; content:"/mandua.wonted"; endswith; classtype:trojan-activity; sid:3026006; rev:1;)
```

---

## Attribution and Relationships

- **Cruciferra PUROSANGUE:** Delphos assesses with high confidence that vsdbg.dll was produced by the Cruciferra crypter or a direct derivative. Key overlaps: `.reloc` payload storage, custom Base16 alphabet (`0x50-0x5F`), DLL side-loading, UAC bypass, and the build string `C:\ExploitTests\purosangue.tx`.
- **BoryptGrab relationship:** Moderate confidence per Delphos. Shared indicators: overlapping GitHub/Pages architecture, identical collection artifacts (`UserInformation.txt` with BUILD NAME, `installed_applications.txt`, misspelled `Filegraber` directory), shared Chrome app-bound encryption bypass workflow, and archive size inflation technique. Key differences: distinct hashes, different build names, different C2 infrastructure, and the kernel driver component is unique to Rapuncel.
- **Scale:** Arctic Wolf documented nearly 300 similar GitHub repositories distributing stealers as of July 2026.

## Recommendations

1. **Immediate:** Block the exfiltration IP `2[.]26[.]126[.]50` and all listed domains at the network perimeter.
2. **Driver blocklist:** Add the Alinubx.sys and CcProtect.sys hashes to your WDAC/HVCI driver block policy. Verify that the Microsoft Recommended Driver Block Rules are enforced and current — these drivers were NOT in the blocklist as of 2026-08-20.
3. **Hunt:** Search for the NvFsFilter service, `nvfsflt64.sys` in `%SYSTEMROOT%\System32\drivers\`, and the `\\.\Alinubx` device path.
4. **Sysmon config:** Ensure Sysmon Event ID 6 (driver load) and Event ID 13 (registry value set) are captured for the detection rules above.
5. **User awareness:** Warn users about fake software download sites on GitHub. The campaign uses convincing trust badges and multi-layer redirects through legitimate GitHub Pages infrastructure.

---

*Final -- Actioner automated analysis -- 2026-09-22*
