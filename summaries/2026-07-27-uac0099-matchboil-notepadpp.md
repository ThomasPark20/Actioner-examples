# Technical Analysis Report: UAC-0099 MATCHBOIL.V2 via Fake Notepad++ Plugin (2026-07-27)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-27
Version: 1.0

<!-- revision: removed import "pe" from YARA (dead import); T1566.001→T1566.002 (link not attachment); split T1036 into T1036.003 (renamed schtasks) + T1036.005 (NppExport only); removed T1547.001 (not observed this campaign); removed CVE-2025-56383 from Xcitium source; updated Sigma tag on renamed-schtasks rule to T1036.003. -->

## Executive Summary

Russia-aligned threat actor UAC-0099 has deployed an updated infection chain targeting Ukrainian government agencies, defense forces, and defense-industrial enterprises using a trojanized Notepad++ plugin. The campaign, disclosed by CERT-UA in mid-July 2026, delivers a malicious DLL named LUNCHPOKE (NppExport.dll) alongside a legitimate Notepad++ v8.8.3 installation, which sideloads the plugin to deploy two new tools -- BURNYBEAR (RemoteLibUpdater.exe) and an upgraded C#-based loader, MATCHBOIL.V2 (InitTest.dll). Persistence is established via a scheduled task running every three minutes. MATCHBOIL.V2 communicates with C2 infrastructure at geostat[.]lat and can download secondary payloads, create additional scheduled tasks, and retrieve WinRAR from Dropbox if it is absent on the victim host.

UAC-0099 has conducted espionage operations against Ukraine since at least mid-2022, previously using MATCHBOIL, MATCHWOK, and DRAGSTARE tooling. This campaign represents a tactical shift to DLL sideloading through legitimate software plugins, increasing evasion against endpoint detection.

## Background: Notepad++ Plugin Architecture

Notepad++ is a widely used open-source text editor on Windows that supports extensibility through DLL plugins loaded from its `plugins` subdirectory. On startup, Notepad++ automatically loads all DLLs in its plugin folders, making it an attractive target for DLL sideloading attacks. The plugin NppExport.dll is a legitimate plugin name used for exporting formatted text, which the threat actor has replaced with a weaponized version. By bundling an older but legitimate Notepad++ v8.8.3 executable with the malicious DLL in a portable installation under `%PUBLIC%`, the attacker abuses the trust relationship between the signed application and its plugin loading mechanism. CERT-UA noted that the current legitimate version is 8.9.7 as of July 21, 2026, making the bundled 8.8.3 three major versions behind.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-July 2026 | CERT-UA discloses campaign activity by UAC-0099 using Notepad++ plugin sideloading |
| T+0 | Phishing email with embedded image attachment delivered to Ukrainian targets |
| T+0 (click) | Victim clicks image, which opens concealed URL via link shortener |
| T+1 | Redirect to EasySend[.]co file-sharing service retrieves initial ZIP archive (e.g., "Додатки до розпорядження.zip") |
| T+2 | ZIP contains VBScript with double extension masquerading as PDF (e.g., "Заводський район.pdf                    .vbs") |
| T+3 | VBScript downloads Evernote.zip, extracts Notepad++ v8.8.3 with LUNCHPOKE (NppExport.dll) to `%PUBLIC%\Libs_<random>\Notepad\` |
| T+4 | VBScript launches Notepad++, which automatically loads NppExport.dll (LUNCHPOKE) |
| T+5 | LUNCHPOKE extracts updater.rar (password-protected) containing RemoteLibUpdater.exe and InitTest.dll to `%PUBLIC%\Libraries\<random>\` |
| T+6 | LUNCHPOKE copies schtasks.exe to `%PUBLIC%\Wallpapers\Background.exe` and creates scheduled task `\W1n3r-U09oTy-Ap5\Updates` |
| T+7 | Scheduled task executes RemoteLibUpdater.exe (BURNYBEAR) with arguments "setup nodisplay" every 3 minutes |
| T+8 | BURNYBEAR loads InitTest.dll (MATCHBOIL.V2), which establishes C2 communication with geostat[.]lat |

## Root Cause: Phishing with DLL Sideloading Chain

Initial access is achieved through spearphishing emails targeting Ukrainian government and defense organizations. The phishing email contains an image attachment that, when clicked, redirects the victim through a link shortener to the EasySend[.]co file-sharing platform. The downloaded ZIP archive contains a VBScript file disguised with a double-extension technique -- the filename ends in ".pdf" followed by extensive whitespace padding and then ".vbs", causing it to appear as a PDF document in default Windows Explorer views. The VBScript orchestrates the entire deployment chain including downloading payloads, extracting components, launching the legitimate Notepad++ executable to trigger DLL sideloading, and establishing persistence.

## Technical Analysis of the Malicious Payload

### 1. LUNCHPOKE -- Malicious Notepad++ Plugin (NppExport.dll)

LUNCHPOKE replaces the legitimate NppExport.dll Notepad++ plugin. When Notepad++ v8.8.3 launches, it automatically loads NppExport.dll from its plugins directory via the standard plugin loading mechanism. LUNCHPOKE performs the following actions:

- Extracts the password-protected archive `updater.rar` (bundled with a legitimate `winrar.exe`) to a randomly-named directory under `%PUBLIC%\Libraries\`
- Copies `schtasks.exe` to `%PUBLIC%\Wallpapers\Background.exe` to evade command-line monitoring of the original schtasks binary
- Creates a scheduled task named `\W1n3r-U09oTy-Ap5\Updates` configured to run every 3 minutes, executing `RemoteLibUpdater.exe` with arguments `setup nodisplay`

The use of a renamed schtasks.exe binary is a deliberate evasion technique -- defenders monitoring for schtasks.exe process creation events will not see the renamed `Background.exe` variant without specific detection for this masquerading behavior.

### 2. BURNYBEAR -- Anti-Analysis Loader (RemoteLibUpdater.exe)

BURNYBEAR serves as a loader for the MATCHBOIL.V2 payload (InitTest.dll). It implements an anti-analysis mechanism: if launched without the correct arguments ("setup nodisplay"), BURNYBEAR activates resource exhaustion logic that consumes excessive RAM and CPU, designed to degrade sandbox and automated analysis environments. When launched correctly via the scheduled task, BURNYBEAR loads and executes InitTest.dll.

### 3. MATCHBOIL.V2 -- C#-Based Loader (InitTest.dll)

MATCHBOIL.V2 is an evolution of the original MATCHBOIL loader with the following capabilities:

- **C2 Communication**: Connects to geostat[.]lat via HTTP, using the path `/articles/images/forest.jpg` to retrieve commands or configuration
- **System Fingerprinting**: Collects CPU hardware ID, BIOS serial number, username, and MAC address; concatenates these values and sends them in the "SN" HTTP header
- **Scheduled Task Management**: Can create additional scheduled tasks for secondary persistence
- **C2 Configuration Updates**: Can update its own C2 configuration dynamically
- **Payload Download**: Downloads and deploys secondary payloads
- **WinRAR Extraction**: Uses WinRAR to extract downloaded archives; if WinRAR is not present on the victim, retrieves it from Dropbox
- **Payload Decoding**: Decodes payloads from HEX and BASE64 formats

### 4. C2 Infrastructure

| Attribute | Value |
|-----------|-------|
| C2 Domain | geostat[.]lat |
| Beacon Path | /articles/images/forest.jpg |
| Protocol | HTTP |
| Fingerprint Header | "SN" (CPU HW ID + BIOS SN + username + MAC) |
| Fallback Infrastructure | Dropbox (for WinRAR retrieval) |

No additional C2 IP addresses or domains were disclosed in the available reporting.

### 5. Anti-Forensics / Evasion Techniques

- **DLL Sideloading**: Legitimate signed Notepad++ executable loads the malicious plugin through its standard loading mechanism, inheriting trust from the parent process
- **Renamed System Binary**: `schtasks.exe` copied to `%PUBLIC%\Wallpapers\Background.exe` to evade process name monitoring
- **Double Extension Masquerading**: VBScript uses ".pdf" + whitespace padding + ".vbs" to appear as a PDF document
- **Anti-Sandbox**: BURNYBEAR exhausts system resources when launched without correct arguments, disrupting automated analysis
- **Randomized Directories**: Extraction paths use randomly generated directory names under `%PUBLIC%\Libraries\`
- **Legitimate Software Bundling**: Full legitimate Notepad++ v8.8.3 and WinRAR executables included to avoid detection of standalone malicious binaries

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Notepad++ | 8.8.3 (legitimate, bundled) | Abused for DLL sideloading; current version is 8.9.7 |
| NppExport.dll (LUNCHPOKE) | Trojanized | Replaces legitimate NppExport plugin; unpacks RAR, establishes persistence |
| RemoteLibUpdater.exe (BURNYBEAR) | Malicious | Anti-analysis loader for MATCHBOIL.V2; resource exhaustion if run without args |
| InitTest.dll (MATCHBOIL.V2) | Malicious | C#-based loader with C2, scheduled task, and payload download capabilities |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `%PUBLIC%\Libs_<random>\Notepad\plugins\NppExport.dll` | Not disclosed | LUNCHPOKE plugin DLL |
| Windows | `%PUBLIC%\Libraries\<random>\RemoteLibUpdater.exe` | Not disclosed | BURNYBEAR loader |
| Windows | `%PUBLIC%\Libraries\<random>\InitTest.dll` | Not disclosed | MATCHBOIL.V2 payload |
| Windows | `%PUBLIC%\Wallpapers\Background.exe` | N/A (renamed schtasks.exe) | Renamed system binary for task creation |
| Windows | `%PUBLIC%\Libraries\<random>\updater.rar` | Not disclosed | Password-protected archive with BURNYBEAR + MATCHBOIL.V2 |
| Windows | Archive: Evernote.zip | Not disclosed | Second-stage archive containing Notepad++ bundle |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | geostat[.]lat | MATCHBOIL.V2 C2 domain |
| URL Pattern | hxxp://geostat[.]lat/articles/images/forest[.]jpg | C2 beacon/config retrieval path |
| Service | EasySend[.]co | File-sharing service used for initial payload delivery |
| Service | Dropbox | Used by MATCHBOIL.V2 to retrieve WinRAR if not present |

### Behavioral

- Scheduled task `\W1n3r-U09oTy-Ap5\Updates` executing every 3 minutes
- `RemoteLibUpdater.exe` launched with arguments `setup nodisplay`
- `schtasks.exe` copied to `%PUBLIC%\Wallpapers\Background.exe`
- NppExport.dll loaded from `%PUBLIC%\` paths (non-standard Notepad++ install location)
- HTTP requests with custom "SN" header containing concatenated system fingerprint data
- VBScript files using double-extension with whitespace padding (.pdf + spaces + .vbs)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Spearphishing Link | Phishing email with embedded image link redirecting to EasySend file-sharing download |
| T1204.002 | User Execution: Malicious File | Victim opens VBScript disguised as PDF via double extension |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript orchestrates download, extraction, and execution chain |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Notepad++ loads malicious NppExport.dll through standard plugin mechanism |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence via `\W1n3r-U09oTy-Ap5\Updates` task running every 3 minutes |
| T1036.003 | Masquerading: Rename System Utilities | schtasks.exe copied and renamed to Background.exe in Public\Wallpapers |
| T1036.005 | Masquerading: Match Legitimate Name or Location | NppExport.dll mimics legitimate Notepad++ plugin name and location |
| T1140 | Deobfuscate/Decode Files or Information | MATCHBOIL.V2 decodes payloads from HEX and BASE64 |
<!-- Removed: T1547.001 (Registry Run Keys) -- not observed in this campaign; historical UAC-0099 behavior only -->
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over HTTP to geostat[.]lat |
| T1105 | Ingress Tool Transfer | Downloads secondary payloads and WinRAR from Dropbox |
| T1082 | System Information Discovery | Collects CPU HW ID, BIOS serial, username, MAC address |
| T1027 | Obfuscated Files or Information | Password-protected RAR archive, encoded payloads |

## Impact Assessment

UAC-0099 is a persistent espionage-focused threat actor active since mid-2022, primarily targeting Ukrainian government agencies, defense forces, and defense-industrial enterprises. The MATCHBOIL.V2 campaign represents an escalation in tradecraft sophistication through the adoption of DLL sideloading via trusted applications. The attack chain is multi-stage and designed for stealth, with anti-analysis capabilities in BURNYBEAR and multiple evasion techniques throughout the kill chain. The C#-based MATCHBOIL.V2 loader's ability to download secondary payloads means initial compromise can lead to deployment of the DRAGSTARE information stealer or MATCHWOK backdoor, enabling browser credential theft, file exfiltration, and remote command execution. Organizations in the Ukrainian defense ecosystem face the highest risk, but the techniques are transferable to other targets.

## Detection & Remediation

### Immediate Detection

```powershell
# Check for the specific scheduled task
schtasks /query /tn "\W1n3r-U09oTy-Ap5\Updates" 2>&1

# Check for renamed schtasks.exe in Public\Wallpapers
Get-Item "$env:PUBLIC\Wallpapers\Background.exe" -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime

# Check for RemoteLibUpdater.exe and InitTest.dll under Public\Libraries
Get-ChildItem "$env:PUBLIC\Libraries" -Recurse -Include "RemoteLibUpdater.exe","InitTest.dll" -ErrorAction SilentlyContinue

# Check for NppExport.dll in non-standard locations under Public
Get-ChildItem "$env:PUBLIC" -Recurse -Include "NppExport.dll" -ErrorAction SilentlyContinue

# Check for Notepad++ in Public directories (portable/non-standard install)
Get-ChildItem "$env:PUBLIC" -Recurse -Include "notepad++.exe" -ErrorAction SilentlyContinue

# Check DNS logs for C2 domain
# (adapt to your DNS logging solution)
Get-DnsClientCache | Where-Object { $_.Entry -like "*geostat*" }
```

### Remediation

1. **Containment**: Isolate affected hosts from the network immediately. Block geostat[.]lat at the DNS and proxy level.
2. **Eradication**: Delete the scheduled task `\W1n3r-U09oTy-Ap5\Updates`. Remove all files from `%PUBLIC%\Libraries\<random>\` and `%PUBLIC%\Libs_<random>\`. Remove `%PUBLIC%\Wallpapers\Background.exe`.
3. **Credential Rotation**: Assume credentials stored in Chrome and Mozilla browsers are compromised (DRAGSTARE capability). Rotate all passwords and revoke active sessions.
4. **Recovery**: Reimage affected systems. Restore from known-good backups where available.
5. **Secret Rotation**: Rotate any API keys, tokens, or credentials accessible from compromised hosts.

### Long-Term Hardening

- Implement application whitelisting to control which DLLs can be loaded by signed applications, particularly in user-writable directories like `%PUBLIC%`.
- Block execution of scripts and executables from `%PUBLIC%` directories via Group Policy or endpoint detection rules.
- Monitor for renamed system binaries (e.g., schtasks.exe, cmd.exe) using OriginalFileName PE metadata comparison.
- Deploy Sysmon with image load logging (Event ID 7) to detect DLL sideloading from non-standard paths.
- Keep Notepad++ and other commonly abused software updated to current versions (8.9.7+ as of July 2026).

## Detection Rules

These rules target the specific, distinctive artifacts from the UAC-0099 MATCHBOIL.V2 campaign disclosed in July 2026, covering endpoint persistence and execution indicators via Sigma, file-level detection via YARA, and network C2 communication via Suricata and Snort. No file hashes were published in the available reporting, so rules key on behavioral artifacts and infrastructure indicators instead.

### Sigma: BURNYBEAR Loader Execution

Detects RemoteLibUpdater.exe (BURNYBEAR) launched with the campaign-specific "setup nodisplay" arguments, the exact invocation used by the persistence scheduled task.
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by MITRE ATT&CK data fetch 403 (proxy restriction, not rule defect); field names Image/CommandLine standard for process_creation/windows; values are real (not defanged); tags are technique-only per convention. -->

**Compile**: pass (splunk + log_scale) | **Confidence**: high

```yaml
title: UAC-0099 BURNYBEAR Loader Execution With Setup Nodisplay Arguments
id: 7a3c1e9f-4b2d-4f8a-b6e5-2d1c9a8f7e3b
status: experimental
description: >
    Detects execution of RemoteLibUpdater.exe (BURNYBEAR loader) with the distinctive
    "setup nodisplay" command-line arguments used by UAC-0099 to silently load
    MATCHBOIL.V2 payloads targeting Ukrainian organizations.
references:
    - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
author: Actioner
date: 2026-07-27
tags:
    - attack.t1204.002
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\RemoteLibUpdater.exe'
        CommandLine|contains|all:
            - 'setup'
            - 'nodisplay'
    condition: selection
falsepositives:
    - Unknown legitimate software using an executable with this exact name and arguments
level: high
```

### Sigma: MATCHBOIL Scheduled Task Persistence

Detects any process referencing the distinctive scheduled task path `W1n3r-U09oTy-Ap5` used exclusively by this campaign for three-minute-interval persistence.
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check blocked by MITRE ATT&CK data fetch 403 (proxy restriction, not rule defect); single-field contains match on highly specific randomized string; no FP risk from partial match given string entropy. -->

**Compile**: pass (splunk + log_scale) | **Confidence**: high

```yaml
title: UAC-0099 MATCHBOIL Scheduled Task Persistence via W1n3r Task Path
id: 8b4d2f0a-5c3e-4a7b-c8f6-3e2d0b9a8f4c
status: experimental
description: >
    Detects creation or reference to the specific scheduled task path
    W1n3r-U09oTy-Ap5\Updates used by UAC-0099 LUNCHPOKE and MATCHBOIL.V2
    for persistence with three-minute execution intervals.
references:
    - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
author: Actioner
date: 2026-07-27
tags:
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'W1n3r-U09oTy-Ap5'
    condition: selection
falsepositives:
    - None expected - highly specific task path name unique to this campaign
level: critical
```

### Sigma: LUNCHPOKE NppExport DLL Sideloading

Detects NppExport.dll loaded from a `%PUBLIC%` directory, indicating the trojanized Notepad++ plugin was deployed to a non-standard location for DLL sideloading.
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; category image_load requires Sysmon EID 7; ImageLoaded field standard for image_load/windows; both endswith and contains modifiers validated in output. -->

**Compile**: pass (splunk + log_scale) | **Confidence**: high

```yaml
title: UAC-0099 LUNCHPOKE NppExport DLL Loaded From Public Directory
id: 9c5e3a1b-6d4f-4b8c-d9a7-4f3e1c0b9a5d
status: experimental
description: >
    Detects NppExport.dll (LUNCHPOKE) being loaded from a directory under
    C:\Users\Public, indicating DLL sideloading via a trojanized Notepad++
    plugin distributed by UAC-0099 to deploy MATCHBOIL.V2.
references:
    - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
author: Actioner
date: 2026-07-27
tags:
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\NppExport.dll'
        ImageLoaded|contains: '\Public\'
    condition: selection
falsepositives:
    - Legitimate Notepad++ installation placed under a Public user directory
level: high
```

- Requires Sysmon Event ID 7 (image load) logging enabled.

### Sigma: Renamed Schtasks in Public Wallpapers

Detects execution of Background.exe from the `%PUBLIC%\Wallpapers` directory, where UAC-0099 places a renamed copy of schtasks.exe to create persistence tasks while evading process name monitoring.
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; path-only detection is sufficient given the specificity of the Wallpapers\Background.exe path; OriginalFileName check omitted as schtasks.exe PE metadata OriginalFileName value varies across Windows versions. -->

**Compile**: pass (splunk + log_scale) | **Confidence**: medium

```yaml
title: UAC-0099 Renamed Schtasks Execution From Public Wallpapers Directory
id: ad6f4b2c-7e5a-4c9d-ea08-5a4f2d1c0b6e
status: experimental
description: >
    Detects execution of a binary from the Public\Wallpapers directory named
    Background.exe, which UAC-0099 uses as a renamed copy of schtasks.exe
    to create persistence scheduled tasks while evading detection.
references:
    - https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html
    - https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html
author: Actioner
date: 2026-07-27
tags:
    - attack.t1036.003
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Wallpapers\Background.exe'
    condition: selection
falsepositives:
    - Legitimate wallpaper management software executing from this exact path
level: high
```

### YARA: MATCHBOIL.V2 Campaign PE Artifacts

Detects PE files containing two or more campaign-specific strings from the UAC-0099 MATCHBOIL.V2 toolset, including the scheduled task path, C2 infrastructure, loader names, and evasion artifacts.
<!-- audit: yarac exit 0; import "pe" removed (unused -- condition uses uint16(0) not pe module); rule requires MZ header + filesize < 10MB + 2-of-8 strings; strings cover all three malware components (LUNCHPOKE, BURNYBEAR, MATCHBOIL.V2); no hashes available for hash meta field; ascii wide modifiers on all strings for encoding coverage. -->

**Compile**: pass (yarac) | **Confidence**: high

```yara
rule UAC0099_MATCHBOIL_V2_Campaign_Artifacts
{
    meta:
        description = "Detects UAC-0099 MATCHBOIL.V2, LUNCHPOKE, or BURNYBEAR PE components based on campaign-specific strings including scheduled task paths, C2 infrastructure, and loader artifacts"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $task_path = "\\W1n3r-U09oTy-Ap5\\Updates" ascii wide
        $args = "setup nodisplay" ascii wide
        $c2_domain = "geostat.lat" ascii wide
        $c2_path = "/articles/images/forest.jpg" ascii wide
        $loader = "RemoteLibUpdater" ascii wide
        $payload = "InitTest.dll" ascii wide
        $rar = "updater.rar" ascii wide
        $bg_schtasks = "\\Wallpapers\\Background.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}
```

### Suricata: MATCHBOIL.V2 C2 DNS Query

Detects DNS queries resolving the C2 domain geostat[.]lat used by MATCHBOIL.V2 for command and control communication.
<!-- audit: suricata -T exit 0; dns protocol with dns.query sticky buffer; content is real domain (not defanged); nocase for DNS case-insensitivity. -->

**Compile**: pass (suricata -T) | **Confidence**: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - UAC-0099 MATCHBOIL.V2 DNS Query to C2 Domain geostat.lat"; flow:to_server; dns.query; content:"geostat.lat"; nocase; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/fake-notepad-plugin-delivers.html; metadata:author Actioner, created_at 2026-07-27; sid:2100010; rev:1;)
```

### Suricata: MATCHBOIL.V2 C2 HTTP Beacon

Detects HTTP requests to geostat[.]lat with the specific beacon path `/articles/images/forest.jpg` used by MATCHBOIL.V2 for C2 configuration retrieval and tasking.
<!-- audit: suricata -T exit 0; http protocol with http.host and http.uri dot-notation buffers; fast_pattern on URI path; both content values are real (not defanged). -->

**Compile**: pass (suricata -T) | **Confidence**: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - UAC-0099 MATCHBOIL.V2 HTTP C2 Beacon to geostat.lat"; flow:established,to_server; http.host; content:"geostat.lat"; http.uri; content:"/articles/images/forest.jpg"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/fake-notepad-plugin-delivers.html; metadata:author Actioner, created_at 2026-07-27; sid:2100011; rev:1;)
```

### Snort: MATCHBOIL.V2 C2 DNS Query

Detects DNS queries for geostat[.]lat using DNS wire-format label-length encoding, matching the C2 domain in UDP port 53 traffic.
<!-- audit: snort -T exit 0 (validated via include in minimal config with classification.config); Snort 2.9.20; DNS label encoding: |07|geostat (7 chars) |03|lat (3 chars) |00| (root); nocase for DNS case-insensitivity; no flow keyword for UDP rule. -->

**Compile**: pass (snort -T) | **Confidence**: high

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - UAC-0099 MATCHBOIL.V2 DNS Query to C2 Domain geostat.lat"; content:"|07|geostat|03|lat|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/07/fake-notepad-plugin-delivers.html; sid:2100010; rev:1;)
```

## Lessons Learned

This campaign demonstrates several evolving tradecraft trends worth noting for defenders:

1. **Trusted Application Abuse**: UAC-0099's shift from HTA/VBScript-based direct execution to DLL sideloading via legitimate applications like Notepad++ signals an adaptation to improved endpoint detection. The plugin loading mechanism of legitimate software provides a clean execution context that inherits the trust and reputation of the parent application.

2. **System Binary Renaming**: The technique of copying `schtasks.exe` to `Background.exe` in `%PUBLIC%\Wallpapers` is simple but effective against detection rules that key solely on process names. Defenders should correlate process image paths with OriginalFileName PE metadata (via Sysmon Event ID 1) to detect this class of evasion.

3. **Anti-Analysis Evolution**: BURNYBEAR's resource exhaustion logic when launched without correct arguments is a pragmatic anti-sandbox measure. Rather than checking for VM artifacts (which are increasingly spoofed), it assumes incorrect invocation equals analysis and degrades the analysis environment's performance.

4. **Supply Chain Adjacent**: While not a true supply chain attack, bundling a legitimate but outdated software version with a trojanized plugin blurs the line. Organizations should monitor for portable installations of common tools in user-writable directories, particularly `%PUBLIC%`.

## Sources

- [The Hacker News - Fake Notepad++ Plugin Delivers MATCHBOIL.V2 in UAC-0099 Attacks](https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html) -- primary reporting on the campaign with infection chain details
- [SecurityAffairs - UAC-0099 Is Now Hiding Malware Inside a Fake Notepad++ Plugin](https://securityaffairs.com/195923/cyber-warfare-2/uac-0099-is-now-hiding-malware-inside-a-fake-notepad-plugin-to-target-ukrainian-organizations.html) -- additional details on scheduled task name, file paths, and BURNYBEAR arguments
- [BleepingComputer - Hackers Abuse Notepad++ Plugins to Stealthily Install Malware](https://www.bleepingcomputer.com/news/security/hackers-abuse-notepad-plus-plus-plugins-to-stealthily-install-malware/) -- coverage of VBScript delivery and LUNCHPOKE functionality
- [Xcitium ThreatLabs - Fake Notepad++ Plugin Hijacks a Trusted Editor](https://threatlabsnews.xcitium.com/blog/fake-notepad-plugin-hijacks-a-trusted-editor-to-deliver-matchboil-v2-malware/) -- C2 domain (geostat[.]lat) and beacon path details
- [Cybersecurity Help - UAC-0099 Uses Legitimate Notepad++ to Hide Malicious Code](https://www.cybersecurity-help.cz/blog/5537.html) -- CERT-UA advisory context and recommended software versions
- [SOC Prime - UAC-0099 Attack Detection](https://socprime.com/blog/detect-uac-0099-attacks-against-ukraine/) -- historical UAC-0099 TTP context, MATCHBOIL/MATCHWOK/DRAGSTARE capabilities, and MITRE ATT&CK mapping

---
*Report generated by Actioner*
