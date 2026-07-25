# Technical Analysis Report: UAC-0099 BURNYBEAR Campaign via Trojanized Notepad++ Plugin (2026-07-25)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-25
Version: 1.0 DRAFT

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

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Windows | NppExport.dll | See hash table below | LUNCHPOKE malicious plugin |
| Windows | RemoteLibUpdater.exe | See hash table below | BURNYBEAR loader |
| Windows | InitTest.dll | See hash table below | MATCHBOIL.V2 payload loader |
| Windows | updater.rar | See hash table below | Password-protected archive |
| Windows | mimeTools.dll | See hash table below | Associated component |
| Windows | certificate.pem | See hash table below | TLS certificate for C2 |
| Windows | %PUBLIC%\Libraries\[random]\ | -- | Extraction directory |
| Windows | %PUBLIC%\Wallpapers\Background.exe | -- | Copied schtasks.exe (masquerading) |

**File Hashes (from CERT-UA / Rewterz):**

| SHA-256 | SHA-1 | MD5 |
|---------|-------|-----|
| 4552e84edd73799b3a6e8e6d8ad0cb231d44241748ecb072c82ee9211728236c | e11ae6392aebab8a878bf4bfa3f6e68ced0c6658 | c4ac3b4ce7aa4ca1234d2d3787323de2 |
| a001642046a6e99ab2b412d96020a243a221e3819eaac94ab3251fad7d20614b | 2e4b1e2bbe9ec23d9b1d83a800c06afdf4aafa12 | 6136ce65b22f59b9f8e564863820720b |
| 2da2fcd61d20eb6f842d833e7fd5ccc6c2aadde908b6e435cd1c94d469aad5ce | fc86d79e67ebe6352343ce370c7ff32711171af9 | fe4237ab7847f3c235406b9ac90ca845 |
| 5af95489c5c3c6e2643a4218543e6e39b62ed6c5b4c97cef9c812ba913d4f7f2 | 12c8d43af0077c400fdf4d3e9c83fcef6111ba57 | d29f25c4b162f6a19d4c6b96a540648c |
| c6c250e1cd6d5477b46871ffe17deac248d723ad45687fc54ae4fc5e3f45d91c | a8473f2db5cc7d2cba76416be23d7c55fc38c8dc | 8b7a358005eff6c44d66e44f5b266d33 |
| fbd959e9578a01c763fd72bec06c8a3bf6683800d587bfd46cc8abe8342c80b9 | a9f9d07bc8a020ab42db8d217a8df8d334a3febb | d5ea5ad8678f362bac86875cad47ba21 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | easysend[.]co | File-sharing platform used for initial payload delivery |
| Scheduled Task | \W1n3r-U09oTy-Ap5\Updates | Persistence mechanism, executes every 3 minutes |

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
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Malicious NppExport.dll loaded via Notepad++ plugin mechanism |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Legitimate Notepad++ loads LUNCHPOKE from bundled plugin directory |
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

- Update Notepad++ to version 8.9.7 or later, 7-Zip to 26.02, and WinRAR to 7.23
- Implement application whitelisting to prevent execution from `%PUBLIC%` directories
- Configure email gateway rules to block or quarantine archives containing VBScript files
- Enable Windows Script Host restrictions via Group Policy where scripting is not required
- Monitor for DLL loading from non-standard directories using Sysmon Event ID 7
- Deploy scheduled task monitoring (Sysmon Event ID, Windows Security 4698) with alerting for unusual task creation patterns

## Detection Rules

Five Sigma rules, four YARA rules, and two Snort/Suricata rules cover the observable attack chain from VBScript delivery through BURNYBEAR execution. No C2 network indicators were published, limiting network-layer detection to delivery-phase infrastructure. All rules are advisory-specific and should be tested against local telemetry before production deployment.

### Sigma Rule 1: Notepad++ Spawning Scripting Engine or Command Shell

Detects Notepad++ spawning suspicious child processes (scripting interpreters, task scheduler) indicative of LUNCHPOKE plugin post-exploitation activity.

**Status**: `compile: pass` | `confidence: medium`

```yaml
title: Notepad++ Spawning Scripting Engine or Command Shell - UAC-0099 LUNCHPOKE
id: 52e6674a-2473-4a10-8235-c217f1486de8
status: experimental
description: >
    Detects Notepad++ spawning a scripting interpreter (wscript, cscript, cmd, powershell)
    or task scheduler, which may indicate the LUNCHPOKE malicious plugin (NppExport.dll)
    executing post-exploitation actions in the UAC-0099 campaign targeting Ukrainian organizations.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1574.001
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\notepad++.exe'
    selection_child:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\schtasks.exe'
            - '\mshta.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Notepad++ plugins that invoke command-line utilities
    - NppExec plugin executing user-configured scripts
level: high
```

<!-- audit: sigma check pass (no-validator mode, ATT&CK tag fetch blocked by proxy); sigma convert --without-pipeline -t splunk pass; sigma convert --without-pipeline -t log_scale pass. Medium confidence due to potential FP from NppExec plugin. Parent-child process_creation is well-supported across Sysmon/4688 pipelines. -->

### Sigma Rule 2: Suspicious DLL Loaded by Notepad++ from Public Directory

Detects Notepad++ loading DLLs from `%PUBLIC%` directories, a hallmark of the UAC-0099 portable installation sideloading technique.

**Status**: `compile: pass` | `confidence: medium`

```yaml
title: Suspicious DLL Loaded by Notepad++ from Public Directory - UAC-0099
id: b5612330-106e-44c6-8f79-2396b7315205
status: experimental
description: >
    Detects Notepad++ loading a DLL from a non-standard directory such as %PUBLIC%,
    indicating potential DLL sideloading as used by UAC-0099 to load the malicious
    LUNCHPOKE plugin (NppExport.dll) bundled alongside a portable Notepad++ installation.
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
        ImageLoaded|contains:
            - '\Users\Public\'
            - 'C:\Users\Public\'
    condition: selection_process and selection_dll
falsepositives:
    - Portable Notepad++ installations intentionally placed in Public directories
level: high
```

<!-- audit: sigma check pass; splunk/log_scale convert pass. Requires Sysmon EID 7 (image_load) to be enabled with appropriate configuration -- not universally deployed. Medium confidence: the path-based condition is specific to this campaign's observed behavior but relies on the %PUBLIC% extraction path which could vary in future variants. -->

### Sigma Rule 3: Scheduled Task Created for BURNYBEAR Persistence

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

### Sigma Rule 4: VBScript Execution with Double File Extension

Detects VBScript execution where the command line contains a double file extension pattern, consistent with the UAC-0099 initial delivery technique.

**Status**: `compile: pass` | `confidence: medium`

```yaml
title: VBScript Execution with Double File Extension - UAC-0099 Delivery
id: e7176ecc-781c-4d9b-8099-9099aba73ab8
status: experimental
description: >
    Detects execution of VBScript files using double file extensions (e.g. .pdf.vbs),
    a social engineering technique used by UAC-0099 to disguise malicious VBS scripts
    as PDF documents for initial delivery of the LUNCHPOKE/BURNYBEAR toolchain.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1059.005
    - attack.t1036.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_engine:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_double_ext:
        CommandLine|re: '\.(pdf|doc|docx|xls|xlsx|jpg|png)\s+\.vbs'
    condition: selection_engine and selection_double_ext
falsepositives:
    - Legitimate scripts with unusual naming conventions
level: high
```

<!-- audit: sigma check pass; splunk/log_scale convert pass. Medium confidence: regex depends on command-line capturing the full filename with whitespace padding -- some environments may truncate or normalize the path. The regex pattern covers the specific double-extension trick with space padding used by UAC-0099. -->

### Sigma Rule 5: BURNYBEAR Loader Execution -- RemoteLibUpdater

Detects execution of `RemoteLibUpdater.exe`, the BURNYBEAR loader binary name specific to the UAC-0099 campaign.

**Status**: `compile: pass` | `confidence: high`

```yaml
title: BURNYBEAR Loader Execution - RemoteLibUpdater with Setup Arguments
id: 04b1ef77-8983-4729-a7ad-8fbee8230d81
status: experimental
description: >
    Detects execution of RemoteLibUpdater.exe, the BURNYBEAR loader used by UAC-0099,
    particularly when launched with the "setup nodisplay" arguments that trigger the
    correct malware execution path rather than the anti-analysis resource exhaustion routine.
references:
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
    - https://cert.gov.ua/article/6318634
author: Actioner
date: 2026/07/25
tags:
    - attack.t1059
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

<!-- audit: sigma check pass; splunk/log_scale convert pass. High confidence: RemoteLibUpdater.exe is not a known legitimate binary name. Simple Image-based detection is robust across all process_creation log sources. -->

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

### YARA Rule 3: UAC0099_MATCHBOIL_V2_Loader

Detects the MATCHBOIL.V2 payload DLL (`InitTest.dll`) by matching its name alongside .NET runtime markers and associated component filenames.

**Status**: `compile: pass` | `confidence: low`

```yara
rule UAC0099_MATCHBOIL_V2_Loader
{
    meta:
        description = "Detects MATCHBOIL.V2 (InitTest.dll), a C#-based malware loader deployed by BURNYBEAR in the UAC-0099 campaign against Ukrainian organizations"
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://cert.gov.ua/article/6318634"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $name1 = "InitTest" ascii wide fullword
        $dotnet1 = "_CorDllMain" ascii fullword
        $dotnet2 = "mscoree.dll" ascii fullword
        $cert = "certificate.pem" ascii wide
        $mime = "mimeTools.dll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $name1 and
        1 of ($dotnet*) and
        ($cert or $mime)
}
```

<!-- audit: yarac compile pass. Low confidence: "InitTest" is somewhat generic; the rule relies on co-occurrence with .NET markers and the certificate.pem/mimeTools.dll strings. Without sample-specific byte patterns or hashes, this is best used alongside hash-based IOC matching. -->

### YARA Rule 4: UAC0099_VBS_Double_Extension_Dropper

Detects VBScript dropper files used for initial delivery, matching VBS execution patterns combined with references to the Evernote.zip / Notepad++ payload chain.

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
        $zip_ref = ".zip" ascii wide nocase
        $rar_ref = "updater.rar" ascii wide nocase
        $download1 = "XMLHTTP" ascii nocase
        $download2 = "ADODB.Stream" ascii nocase
        $shell1 = "WScript.Shell" ascii nocase

    condition:
        filesize < 500KB and
        1 of ($vbs_header*) and
        (
            ($evernote and ($notepad or $npp)) or
            ($download1 and $shell1 and ($evernote or $zip_ref or $rar_ref)) or
            ($download2 and ($notepad or $npp))
        )
}
```

<!-- audit: yarac compile pass. Medium confidence: VBS file detection without PE header check (VBS files are plaintext). The Evernote/notepad++ string combination is specific to this campaign variant but the broader download pattern conditions could match other VBS downloaders. -->

### Snort Rule 1: EasySend File Download -- UAC-0099 Delivery Infrastructure

Detects HTTP requests to the EasySend[.]co file-sharing platform used as the delivery mechanism for the initial ZIP archive.

**Status**: `compile: uncompiled` | `confidence: low`

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to EasySend File Sharing - Potential UAC-0099 Delivery"; flow:established, to_server; http_uri; content:"/dl/"; http_header; content:"Host: "; content:"easysend.co", distance 0, within 20; classtype:trojan-activity; reference:url,cert.gov.ua/article/6318634; metadata:author Actioner, created 2026-07-25; sid:2100101; rev:1;)
```

<!-- audit: structural check only -- snort not installed. Semicolons terminate all options; flow set for TCP; http_uri and http_header sticky buffers used with http protocol; msg/sid/rev present. Low confidence: EasySend is a legitimate service; this rule will generate false positives and should be used with threat-intel enrichment or alongside other indicators. -->

### Suricata Rule 1: EasySend File Sharing Download -- UAC-0099 Delivery

Detects HTTP traffic to EasySend[.]co, the file-sharing service observed hosting the UAC-0099 initial ZIP payload.

**Status**: `compile: uncompiled` | `confidence: low`

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to EasySend - Potential UAC-0099 Payload Delivery"; flow:established,to_server; http.host; content:"easysend.co"; endswith; http.uri; content:"/dl/"; startswith; classtype:trojan-activity; reference:url,cert.gov.ua/article/6318634; metadata:author Actioner, created_at 2026-07-25; sid:2100101; rev:1;)
```

<!-- audit: structural check only -- suricata not installed. Dot-notation sticky buffers (http.host, http.uri) correctly used; semicolons on all options; msg/sid/rev present; endswith/startswith modifiers correctly applied. Low confidence: EasySend is a legitimate file-sharing platform; this rule requires tuning with additional context (e.g., ZIP content type, specific URI patterns) to reduce FP rate. -->

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
