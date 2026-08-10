# Technical Analysis Report: UAC-0099 BURNYBEAR Campaign via Trojanized Notepad++ Plugin (2026-07-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-25
Version: 1.1 REVISED

## Executive Summary

Russia-aligned threat cluster UAC-0099, tracked by CERT-UA since mid-2022, has adopted a new toolchain to target Ukrainian state authorities, defense forces, and defense-industrial complex enterprises. The campaign distributes phishing emails containing VBScript files disguised with double file extensions (e.g., `.pdf .vbs`) that deploy a trojanized Notepad++ v8.8.3 installation bundled with a malicious plugin called LUNCHPOKE (`NppExport.dll`). Once loaded, LUNCHPOKE establishes persistence via a Windows scheduled task running every three minutes, extracts a password-protected RAR archive, and deploys the BURNYBEAR loader (`RemoteLibUpdater.exe`) alongside MATCHBOIL.V2 (`InitTest.dll`), a C#-based secondary payload loader. BURNYBEAR includes deliberate anti-analysis logic that exhausts system CPU and RAM if executed without the correct command-line arguments, frustrating sandbox and manual analysis. UAC-0099 has been linked to providing initial access for APT44 (Sandworm) in subsequent attack stages.

## Background: Notepad++ Plugin Mechanism

Notepad++ is a widely used open-source text editor for Windows that supports extensibility through DLL-based plugins. Plugins placed in the application's `plugins` directory are automatically loaded at startup. This legitimate functionality, identified controversially as CVE-2025-56383 (disputed by the Notepad++ development team as intended behavior), is abused by UAC-0099 by bundling a portable Notepad++ installation with a malicious plugin DLL. Because the plugin loading mechanism is by design, no vulnerability exploitation is required -- the attacker simply ensures the malicious DLL resides in the expected plugin directory structure.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-2022 | UAC-0099 first tracked by CERT-UA targeting Ukrainian organizations |
| 2024-2025 | Earlier campaigns using MATCHBOIL, MATCHWOK, and DRAGSTARE malware families; exploitation of WinRAR vulnerabilities |
| Mid-Summer 2026 | New campaign observed using LUNCHPOKE, BURNYBEAR, and MATCHBOIL.V2 toolchain |
| 2026-07-21 | CERT-UA publishes advisory #6318634 attributing campaign to UAC-0099 |
| 2026-07-22-24 | Multiple security vendors publish technical analyses (BleepingComputer, The Hacker News, SecurityAffairs) |

## Root Cause: Spearphishing with Social Engineering

The attack begins with a spearphishing email containing an embedded image attachment. Clicking the image activates a hyperlink routed through a URL shortener, which redirects the victim to a file-sharing platform (EasySend[.]co) hosting a ZIP archive (e.g., "Attachments to the Order.zip"). Inside the archive is a VBScript file using a double file extension trick -- the filename appears to be a PDF document (e.g., "Zavodskyi rayon.pdf .vbs") with extensive whitespace between the fake and real extensions to hide the `.vbs` extension from the user.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery -- VBScript Dropper (Double Extension)

The VBScript file serves as the initial dropper. When executed via Windows Script Host, it:
- Downloads and displays a decoy PDF document to maintain the social engineering illusion
- Retrieves a secondary archive named `Evernote.zip` from an external source
- Extracts and installs the contents to a randomly named directory under `%PUBLIC%\Libraries\` (e.g., `%PUBLIC%\Libraries\fFthY3-Ytrevc3w-ab3\`)
- Launches `notepad++.exe` from the extracted directory

The VBScript uses standard COM objects (`XMLHTTP`, `ADODB.Stream`, `WScript.Shell`) for download and execution operations.

### 2. LUNCHPOKE -- Malicious Notepad++ Plugin (NppExport.dll)

The `Evernote.zip` archive contains a complete, legitimate Notepad++ v8.8.3 installation alongside:
- `NppExport.dll` -- the LUNCHPOKE malicious plugin, placed in the plugins directory
- `updater.rar` -- a password-protected RAR archive containing the next-stage payloads
- `winrar.exe` -- a legitimate WinRAR executable for extracting the RAR archive

When Notepad++ launches, it automatically loads `NppExport.dll` through its standard plugin mechanism. LUNCHPOKE then:
1. Copies the legitimate `schtasks.exe` to `%PUBLIC%\Wallpapers\Background.exe` (masquerading)
2. Creates a scheduled task at `\W1n3r-U09oTy-Ap5\Updates` configured to run every 3 minutes
3. The scheduled task executes `RemoteLibUpdater.exe` with the arguments `setup nodisplay`
4. Extracts `updater.rar` using the bundled WinRAR, deploying `RemoteLibUpdater.exe` and `InitTest.dll`

### 3. BURNYBEAR -- Loader with Anti-Analysis (RemoteLibUpdater.exe)

`RemoteLibUpdater.exe` is the BURNYBEAR loader, a .NET executable that serves as a wrapper for the final payload. Its key behaviors:

**Correct execution path** (with `setup nodisplay` arguments):
- Loads and executes `InitTest.dll` (MATCHBOIL.V2)
- Updates C2 configuration
- Enables secondary payload delivery

**Anti-analysis path** (without correct arguments):
- Deliberately activates resource exhaustion logic that consumes all available CPU and RAM
- This serves dual purposes: sandbox evasion (resource-constrained sandboxes crash) and analyst frustration (manual execution without correct arguments triggers the decoy behavior)

### 4. MATCHBOIL.V2 -- Secondary Payload Loader (InitTest.dll)

`InitTest.dll` is a modified version of the previously documented MATCHBOIL malware, a C#-based loader capable of:
- Delivering secondary payloads from C2 infrastructure
- Establishing persistent communication channels
- Facilitating follow-on operations potentially conducted by APT44 (Sandworm)

Additional files observed in associated samples include `mimeTools.dll` and `certificate.pem`, suggesting TLS-based C2 communication capabilities.

### 5. C2 Infrastructure

No specific C2 domains, IP addresses, or communication protocols were disclosed in available reporting. CERT-UA noted that "C2 server URLs are still reachable" at the time of advisory publication, but withheld specific indicators. The presence of `certificate.pem` suggests TLS-encrypted C2 communications.

### 6. Anti-Forensics / Evasion Techniques

- **Double file extension**: VBScript files disguised as PDFs with whitespace padding
- **Legitimate application abuse**: Using genuine Notepad++ for DLL loading
- **Binary masquerading**: Copying `schtasks.exe` as `Background.exe` in the Wallpapers directory
- **Password-protected archives**: RAR file requires a password, hindering static analysis
- **Resource exhaustion anti-analysis**: BURNYBEAR deliberately crashes analysis environments
- **Randomized directory names**: Extraction path uses random alphanumeric directory names
- **Legitimate tool bundling**: WinRAR binary included to avoid reliance on system-installed archivers

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Notepad++ | 8.8.3 (legitimate, abused) | Portable installation used to sideload LUNCHPOKE plugin |
| NppExport.dll | LUNCHPOKE | Trojanized plugin establishing persistence and deploying BURNYBEAR |
| RemoteLibUpdater.exe | BURNYBEAR | .NET loader with anti-analysis resource exhaustion |
| InitTest.dll | MATCHBOIL.V2 | C#-based secondary payload loader |

### File System

| Platform | Path / Filename | SHA-256 (truncated) | Description |
|----------|-----------------|---------------------|-------------|
| Windows | NppExport.dll | `4552e84e...28236c` | LUNCHPOKE malicious plugin |
| Windows | RemoteLibUpdater.exe | `a0016420...0614b` | BURNYBEAR loader |
| Windows | InitTest.dll | `2da2fcd6...ad5ce` | MATCHBOIL.V2 payload loader |
| Windows | updater.rar | `5af95489...d4f7f2` | Password-protected archive |
| Windows | mimeTools.dll | `c6c250e1...5d91c` | Associated component |
| Windows | certificate.pem | `fbd959e9...c80b9` | TLS certificate for C2 |
| Windows | %PUBLIC%\Libraries\[random]\ | -- | Extraction directory |
| Windows | %PUBLIC%\Wallpapers\Background.exe | -- | Copied schtasks.exe (masquerading) |
| Windows | \W1n3r-U09oTy-Ap5\Updates | -- | Scheduled task path (persistence) |

**File Hashes (from CERT-UA / Rewterz):**

<!-- revision: mapped each hash to its corresponding malware component per Rewterz IOC ordering -->

| Component | SHA-256 | SHA-1 | MD5 |
|-----------|---------|-------|-----|
| NppExport.dll (LUNCHPOKE) | 4552e84edd73799b3a6e8e6d8ad0cb231d44241748ecb072c82ee9211728236c | e11ae6392aebab8a878bf4bfa3f6e68ced0c6658 | c4ac3b4ce7aa4ca1234d2d3787323de2 |
| RemoteLibUpdater.exe (BURNYBEAR) | a001642046a6e99ab2b412d96020a243a221e3819eaac94ab3251fad7d20614b | 2e4b1e2bbe9ec23d9b1d83a800c06afdf4aafa12 | 6136ce65b22f59b9f8e564863820720b |
| InitTest.dll (MATCHBOIL.V2) | 2da2fcd61d20eb6f842d833e7fd5ccc6c2aadde908b6e435cd1c94d469aad5ce | fc86d79e67ebe6352343ce370c7ff32711171af9 | fe4237ab7847f3c235406b9ac90ca845 |
| updater.rar | 5af95489c5c3c6e2643a4218543e6e39b62ed6c5b4c97cef9c812ba913d4f7f2 | 12c8d43af0077c400fdf4d3e9c83fcef6111ba57 | d29f25c4b162f6a19d4c6b96a540648c |
| mimeTools.dll | c6c250e1cd6d5477b46871ffe17deac248d723ad45687fc54ae4fc5e3f45d91c | a8473f2db5cc7d2cba76416be23d7c55fc38c8dc | 8b7a358005eff6c44d66e44f5b266d33 |
| certificate.pem | fbd959e9578a01c763fd72bec06c8a3bf6683800d587bfd46cc8abe8342c80b9 | a9f9d07bc8a020ab42db8d217a8df8d334a3febb | d5ea5ad8678f362bac86875cad47ba21 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | easysend[.]co | File-sharing platform used for initial payload delivery |

*Note: No C2 domains or IP addresses were disclosed in available reporting.*

### Behavioral

- Notepad++ (`notepad++.exe`) loading DLLs from `%PUBLIC%\Libraries\` subdirectories
- `schtasks.exe` copied to `%PUBLIC%\Wallpapers\Background.exe`
- Scheduled task creation with path `\W1n3r-U09oTy-Ap5\Updates` running at 3-minute intervals
- `RemoteLibUpdater.exe` executed with arguments `setup nodisplay`
- VBScript files with double file extensions containing extensive whitespace padding
- Process chain: `wscript.exe` -> `notepad++.exe` -> `schtasks.exe` / `RemoteLibUpdater.exe`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.001 | Spearphishing Attachment | Phishing email with embedded image linking to EasySend file-sharing platform |
| T1204.002 | User Execution: Malicious File | VBScript with double extension tricks user into executing malware |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript dropper downloads and deploys the Notepad++ package |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Legitimate Notepad++ loads LUNCHPOKE from bundled plugin directory; malicious NppExport.dll loaded via plugin mechanism |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence via scheduled task running BURNYBEAR every 3 minutes |
| T1036 | Masquerading | schtasks.exe copied as Background.exe; VBS disguised as PDF |
| T1036.007 | Masquerading: Double File Extension | VBScript files named with .pdf .vbs double extension |
| T1027 | Obfuscated Files or Information | Password-protected RAR archive for payload storage |
| T1497 | Virtualization/Sandbox Evasion | BURNYBEAR resource exhaustion when executed without correct arguments |
| T1105 | Ingress Tool Transfer | VBScript downloads Evernote.zip from external hosting |

## Impact Assessment

**Breadth**: Campaign targets Ukrainian state authorities, armed forces, and defense-industrial complex enterprises. The exact number of compromised organizations is not disclosed but CERT-UA investigated multiple incidents.

**Depth**: Full compromise chain from initial access through persistent backdoor installation. The link to APT44 (Sandworm) for subsequent operations indicates potential for destructive or espionage-focused follow-on actions with significant national security implications.

**Stealth**: Multi-stage execution chain using legitimate applications (Notepad++, WinRAR, schtasks.exe) makes detection challenging. The anti-analysis resource exhaustion in BURNYBEAR specifically hinders incident response and malware analysis efforts.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for known scheduled task path
schtasks /query /tn "\W1n3r-U09oTy-Ap5\Updates" 2>$null

# Check for Background.exe masquerading as schtasks
Get-FileHash "$env:PUBLIC\Wallpapers\Background.exe" -ErrorAction SilentlyContinue

# Check for RemoteLibUpdater.exe in Public directories
Get-ChildItem -Path "$env:PUBLIC" -Recurse -Filter "RemoteLibUpdater.exe" -ErrorAction SilentlyContinue

# Check for suspicious Notepad++ installations in Public directories
Get-ChildItem -Path "$env:PUBLIC\Libraries" -Recurse -Filter "notepad++.exe" -ErrorAction SilentlyContinue

# Check for InitTest.dll
Get-ChildItem -Path "$env:PUBLIC" -Recurse -Filter "InitTest.dll" -ErrorAction SilentlyContinue

# Search for known file hashes
Get-ChildItem -Path "$env:PUBLIC" -Recurse -File | Get-FileHash | Where-Object {
    $_.Hash -in @(
        '4552e84edd73799b3a6e8e6d8ad0cb231d44241748ecb072c82ee9211728236c',
        'a001642046a6e99ab2b412d96020a243a221e3819eaac94ab3251fad7d20614b',
        '2da2fcd61d20eb6f842d833e7fd5ccc6c2aadde908b6e435cd1c94d469aad5ce',
        '5af95489c5c3c6e2643a4218543e6e39b62ed6c5b4c97cef9c812ba913d4f7f2',
        'fbd959e9578a01c763fd72bec06c8a3bf6683800d587bfd46cc8abe8342c80b9'
    )
}
```

### Remediation

1. **Contain**: Isolate affected endpoints from the network immediately. Disable the scheduled task `\W1n3r-U09oTy-Ap5\Updates`.
2. **Eradicate**: Remove all files from `%PUBLIC%\Libraries\[random]\`, delete `%PUBLIC%\Wallpapers\Background.exe`, remove the scheduled task.
3. **Recover**: Reimage affected systems. Reset credentials for any accounts accessed from compromised endpoints.
4. **Hunt**: Search for the listed file hashes across the enterprise. Review scheduled task logs for the 3-minute execution pattern. Audit Notepad++ plugin directories across all endpoints.

### Long-Term Hardening

<!-- revision: removed 7-Zip reference; 7-Zip is not part of this attack chain (only WinRAR) -->
- Update Notepad++ to version 8.9.7 or later and WinRAR to 7.23
- Implement application whitelisting to prevent execution from `%PUBLIC%` directories
- Configure email gateway rules to block or quarantine archives containing VBScript files
- Enable Windows Script Host restrictions via Group Policy where scripting is not required
- Monitor for DLL loading from non-standard directories using Sysmon Event ID 7
- Deploy scheduled task monitoring (Sysmon Event ID, Windows Security 4698) with alerting for unusual task creation patterns

## Detection Rules

<!-- revision: updated rule count after dropping Sigma 1 (generic parent-child), Sigma 4 (generic double-ext), YARA 3 (generic MATCHBOIL strings), Snort 1 (legitimate service FP), Suricata 1 (legitimate service FP) -->
Three Sigma rules and three YARA rules cover the observable attack chain from DLL sideloading through BURNYBEAR persistence and execution. No C2 network indicators were published, and delivery-phase network rules (EasySend) were dropped due to unacceptable false-positive rates against a legitimate file-sharing service. All rules are advisory-specific and should be tested against local telemetry before production deployment.

<!-- revision: Sigma Rule 1 (Notepad++ Spawning Scripting Engine, id:52e6674a) DROPPED. Generic parent-child detection; NppExec plugin routinely spawns cmd/powershell; no campaign-specific conditions. -->

### Sigma Rule 1: Suspicious DLL Loaded by Notepad++ from Public Libraries Directory

Detects Notepad++ loading DLLs from `%PUBLIC%\Libraries\` subdirectories, the specific extraction path used by UAC-0099's portable installation sideloading technique.

<!-- revision: narrowed ImageLoaded|contains to '\Users\Public\Libraries\' (campaign-specific path); removed redundant 'C:\Users\Public\' pattern subsumed by the first -->

**Status**: `compile: pass` | `confidence: medium`

```yaml
title: Suspicious DLL Loaded by Notepad++ from Public Libraries Directory - UAC-0099
id: b5612330-106e-44c6-8f79-2396b7315205
status: experimental
description: >
    Detects Notepad++ loading a DLL from the %PUBLIC%\Libraries\ directory tree,
    indicating potential DLL sideloading as used by UAC-0099 to load the malicious
    LUNCHPOKE plugin (NppExport.dll) bundled alongside a portable Notepad++ installation
    extracted to a randomized subdirectory under %PUBLIC%\Libraries\.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1574.002
    - attack.t1036
logsource:
    category: image_load
    product: windows
detection:
    selection_process:
        Image|endswith: '\notepad++.exe'
    selection_dll:
        ImageLoaded|contains: '\Users\Public\Libraries\'
    condition: selection_process and selection_dll
falsepositives:
    - Portable Notepad++ installations intentionally placed in Public\Libraries directories
level: high
```

<!-- audit: sigma check pass (tag validators excluded -- proxy blocks ATT&CK fetch); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. Requires Sysmon EID 7 (image_load). Medium confidence: narrowed to Libraries subdirectory reduces FP surface. -->

### Sigma Rule 2: Scheduled Task Created for BURNYBEAR Persistence

Detects `schtasks.exe` creating a scheduled task referencing `RemoteLibUpdater.exe` with the `setup nodisplay` arguments, the exact persistence mechanism documented by CERT-UA.

**Status**: `compile: pass` | `confidence: high`

```yaml
title: Scheduled Task Created for BURNYBEAR Persistence - UAC-0099
id: b44142b3-ba33-4180-8122-ea01857e4f46
status: experimental
description: >
    Detects creation of a scheduled task matching the UAC-0099 persistence pattern,
    including the known task path pattern and the RemoteLibUpdater.exe binary with
    arguments "setup nodisplay" used by the BURNYBEAR loader.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - 'RemoteLibUpdater'
            - 'setup'
            - 'nodisplay'
    condition: selection_schtasks
falsepositives:
    - Unlikely in legitimate environments
level: critical
```

<!-- audit: sigma check pass; splunk/log_scale convert pass. High confidence: three-keyword AND on schtasks command line is highly specific to this campaign. Requires command-line auditing (Sysmon EID 1 or Windows 4688 with command-line logging). -->

<!-- revision: Sigma Rule 4 (VBScript Double File Extension, id:e7176ecc) DROPPED. Generic TTP used by dozens of groups; no UAC-0099-specific artifacts; |re: modifier has poor backend portability. -->

### Sigma Rule 3: BURNYBEAR Loader Execution -- RemoteLibUpdater

Detects execution of `RemoteLibUpdater.exe`, the BURNYBEAR loader binary name specific to the UAC-0099 campaign.

<!-- revision: fixed title to remove "with Setup Arguments" (detection checks Image name only, not arguments); replaced attack.t1059 with attack.t1204.002 (compiled .NET loader, not scripting interpreter); updated description to match actual detection logic -->

**Status**: `compile: pass` | `confidence: high`

```yaml
title: BURNYBEAR Loader Execution - RemoteLibUpdater
id: 04b1ef77-8983-4729-a7ad-8fbee8230d81
status: experimental
description: >
    Detects execution of RemoteLibUpdater.exe, the BURNYBEAR loader used by UAC-0099.
    This .NET binary loads the MATCHBOIL.V2 payload (InitTest.dll) when executed with
    the correct arguments, or triggers anti-analysis resource exhaustion otherwise.
    Detection is based on the executable image name, which is campaign-specific.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1204.002
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\RemoteLibUpdater.exe'
    condition: selection
falsepositives:
    - Legitimate software named RemoteLibUpdater.exe (uncommon)
level: critical
```

<!-- audit: sigma check pass (tag validators excluded -- proxy blocks ATT&CK fetch); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. High confidence: RemoteLibUpdater.exe is not a known legitimate binary name. Simple Image-based detection is robust across all process_creation log sources. -->

### YARA Rule 1: UAC0099_LUNCHPOKE_NppExport_Plugin

Detects the LUNCHPOKE malicious Notepad++ plugin by matching characteristic strings associated with the scheduled task creation, RAR extraction, and BURNYBEAR deployment logic.

**Status**: `compile: pass` | `confidence: medium`

```yara
import "pe"

rule UAC0099_LUNCHPOKE_NppExport_Plugin
{
    meta:
        description = "Detects the LUNCHPOKE malicious Notepad++ plugin (NppExport.dll) used by UAC-0099 to establish persistence and deploy BURNYBEAR loader"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $npp_export1 = "NppExport" ascii wide
        $schtasks = "schtasks" ascii wide nocase
        $updater_rar = "updater.rar" ascii wide
        $remote_lib = "RemoteLibUpdater" ascii wide
        $init_test = "InitTest.dll" ascii wide
        $setup_arg = "setup" ascii wide
        $nodisplay = "nodisplay" ascii wide
        $public_path = "\\Users\\Public\\" ascii wide
        $wallpapers = "\\Wallpapers\\Background.exe" ascii wide
        $task_path = "W1n3r-U09oTy-Ap5" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($npp_export1 and $schtasks and ($updater_rar or $remote_lib)) or
            ($task_path) or
            ($wallpapers and $schtasks) or
            ($public_path and $remote_lib and $init_test) or
            (4 of ($schtasks, $updater_rar, $remote_lib, $init_test, $setup_arg, $nodisplay))
        )
}
```

<!-- audit: yarac compile pass (exit 0). Medium confidence: string-based detection without sample hashes; the task_path string "W1n3r-U09oTy-Ap5" is a high-fidelity indicator but the broader string combinations may produce FPs on legitimate software referencing common terms. PE header check constrains scope. -->

### YARA Rule 2: UAC0099_BURNYBEAR_Loader

Detects the BURNYBEAR loader (`RemoteLibUpdater.exe`) via its .NET characteristics and the combination of the binary name, DLL loading target, and command-line argument strings.

**Status**: `compile: pass` | `confidence: medium`

```yara
rule UAC0099_BURNYBEAR_Loader
{
    meta:
        description = "Detects the BURNYBEAR loader (RemoteLibUpdater.exe) used by UAC-0099 that loads MATCHBOIL.V2 and includes anti-analysis resource exhaustion logic"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://cert.gov.ua/article/6318634"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $name1 = "RemoteLibUpdater" ascii wide fullword
        $dll_load = "InitTest.dll" ascii wide
        $arg_setup = "setup" ascii wide
        $arg_nodisplay = "nodisplay" ascii wide
        $resource_exhaust1 = "System.Threading" ascii wide
        $resource_exhaust2 = "MemoryStream" ascii wide
        $dotnet1 = "_CorExeMain" ascii fullword
        $dotnet2 = "mscoree.dll" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($name1 and $dll_load and ($arg_setup or $arg_nodisplay)) or
            ($name1 and 1 of ($dotnet*) and 1 of ($resource_exhaust*))
        )
}
```

<!-- audit: yarac compile pass. Medium confidence: requires the embedded binary name string which is campaign-specific but could be stripped in future variants. .NET indicators help constrain the match. -->

<!-- revision: YARA Rule 3 (UAC0099_MATCHBOIL_V2_Loader) DROPPED. "InitTest" too generic, "certificate.pem" very common; no unique MATCHBOIL.V2 strings. -->

### YARA Rule 3: UAC0099_VBS_Double_Extension_Dropper

Detects VBScript dropper files used for initial delivery, matching VBS execution patterns combined with references to the Evernote.zip / Notepad++ payload chain.

<!-- revision: removed $zip_ref (".zip") from third condition branch -- too broad, matches countless VBS downloaders. Second branch now requires $evernote or $rar_ref only (both campaign-specific). -->

**Status**: `compile: pass` | `confidence: medium`

```yara
rule UAC0099_VBS_Double_Extension_Dropper
{
    meta:
        description = "Detects VBScript dropper files using double file extension technique as used in UAC-0099 phishing campaigns to deliver LUNCHPOKE and BURNYBEAR"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $vbs_header1 = "CreateObject" ascii nocase
        $vbs_header2 = "WScript" ascii nocase
        $evernote = "Evernote" ascii wide nocase
        $notepad = "notepad++" ascii wide nocase
        $npp = "NppExport" ascii wide
        $rar_ref = "updater.rar" ascii wide nocase
        $download1 = "XMLHTTP" ascii nocase
        $download2 = "ADODB.Stream" ascii nocase
        $shell1 = "WScript.Shell" ascii nocase

    condition:
        filesize < 500KB and
        1 of ($vbs_header*) and
        (
            ($evernote and ($notepad or $npp)) or
            ($download1 and $shell1 and ($evernote or $rar_ref)) or
            ($download2 and ($notepad or $npp))
        )
}
```

<!-- audit: yarac compile pass. Medium confidence: VBS file detection without PE header check (VBS files are plaintext). The Evernote/notepad++/updater.rar string combinations are campaign-specific. $zip_ref removed to eliminate broad-match FP path. -->

<!-- revision: Snort Rule 1 (EasySend File Download) DROPPED. EasySend is a legitimate file-sharing platform; rule alerts on ALL EasySend usage, producing extremely high false positives. -->

<!-- revision: Suricata Rule 1 (EasySend File Sharing Download) DROPPED. Same issue as Snort -- legitimate service with unacceptable FP rate. -->

## Lessons Learned

1. **Legitimate application plugin mechanisms remain a reliable sideloading vector.** The Notepad++ plugin loading functionality is by design, making it impossible to patch away without breaking core functionality. This pattern applies broadly to any extensible application (VS Code extensions, browser plugins, IDE add-ons). Organizations should monitor DLL loading from non-standard directories regardless of the parent application's legitimacy.

2. **Anti-analysis techniques are evolving beyond detection evasion.** BURNYBEAR's resource exhaustion approach is a deliberate time-wasting tactic targeting analysts, not just automated sandboxes. By making incorrect execution actively harmful to the analysis environment, the attacker raises the cost of reverse engineering and slows incident response timelines.

3. **Initial access brokers and APT operators increasingly operate as distinct stages.** UAC-0099's role as an initial access provider for APT44 (Sandworm) illustrates the maturation of the cyber-attack supply chain. Detection strategies must account for both the access broker's TTPs (phishing, persistence) and the follow-on operator's objectives, as the two may have very different signatures.

## Sources

- [CERT-UA Advisory #6318634](https://cert.gov.ua/article/6318634) -- original CERT-UA advisory attributing campaign to UAC-0099 with LUNCHPOKE, BURNYBEAR, and MATCHBOIL.V2 toolchain details
- [SecurityAffairs](https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html) -- reporting on UAC-0099 campaign with attack chain details, file paths, and scheduled task indicators
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-abuse-notepad-plus-plus-plugins-to-stealthily-install-malware/) -- technical coverage including CVE-2025-56383 dispute and APT44 attribution context
- [The Hacker News](https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html) -- campaign analysis with execution chain details and EasySend delivery mechanism
- [Rewterz Threat Advisory](https://rewterz.com/threat-advisory/threat-actors-executed-malicious-code-by-abusing-notepad-plugin-active-iocs) -- active IOC list with SHA-256, SHA-1, and MD5 file hashes
- [CyberPress](https://cyberpress.org/hackers-weaponize-notepad-8-8-3/) -- supplementary technical analysis with file path details

---
*Report generated by Actioner*
