# Technical Analysis Report: Star Blizzard RedFlick Campaign — CosmicPulse Backdoor (2026-09-30)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-09-30
Version: 0.1 (DRAFT)

## Executive Summary

Since January 2026, Russian state-sponsored threat actor **Star Blizzard** (FSB Center 18; also tracked as SEABORGIUM, Callisto Group, TA446, COLDRIVER) has conducted at least **13 large-scale phishing campaigns** targeting **over 100 organizations** — primarily in the United States and United Kingdom — with a focus on Ukrainian entities, NGOs, think tanks, and international policy organizations supporting Ukraine. This represents a significant tactical shift from Star Blizzard's historical targeted spear-phishing to bulk campaign operations.

The campaigns introduce a novel malware delivery technique called **"RedFlick"** that uses Windows Scheduled Tasks to deploy the actor's custom Python backdoor, **CosmicPulse** (also known as NOROBOT, BAITSWITCH, YESROBOT). Unlike earlier ClickFix-based campaigns requiring multiple user interactions, RedFlick reduces infection friction to a single user action — opening a password-protected archive. The technique leverages Control Panel applet (CPL) DLLs, WebDAV UNC paths, SSH PermitLocalCommand abuse, and PDF steganography to evade detection. Infrastructure has rotated monthly across at least 16 domains and 6 IP addresses, with compromised WordPress/cPanel websites used for email delivery since March 2026.

Severity: **High** — active, attributed FSB cyberespionage campaign with evolving TTPs, broad targeting, and ongoing operations.

## Background: Star Blizzard and the RedFlick Technique

Star Blizzard is a Russian Federal Security Service (FSB)-affiliated advanced persistent threat (APT) group that has historically specialized in credential theft and cyberespionage against government, defense, academic, and civil society targets. The group's operations primarily support Russian foreign intelligence objectives, with particular focus on organizations involved in Ukraine policy.

Prior to 2026, Star Blizzard relied on targeted spear-phishing with ClickFix lures (fake CAPTCHA pages) and tools like Evilginx for password and session cookie theft. The RedFlick technique represents a "notable departure" by automating payload delivery through scheduled tasks, reducing the required victim interaction to simply opening an archive file. This evolution coincided with a shift from targeted operations to campaigns numbering "tens to hundreds of emails" per wave.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-01 | First RedFlick campaigns targeting Ukr.net users with fake Ukrainian tax audit/fine notices; VHDX-based delivery via password-protected ZIP archives |
| 2026-02 | Continued Ukrainian-focused targeting with iterating infrastructure (groy[.]cc, muvb[.]net) |
| 2026-03 | Pivot to international targeting (IISS, Atlantic Council, CES-themed lures); shift to compromised WordPress/cPanel website accounts for email delivery |
| 2026-04 | Multi-task persistence evolution: MSI now creates three distinct scheduled tasks for beaconing, WebDAV enablement, and CPL execution; C2 at 103.245.213[.]217 |
| 2026-05 | "Future of Peace Operations Forum" and "Future of Liberty Forum" lures |
| 2026-06 | Chatham House London Conference 2026 lure; PDF-embedded payload technique introduced (cAB magic header steganography) |
| 2026-07 | USUBC Private Executive Roundtable Webex lure; Kyiv hotel water-supply-shutdown social engineering targeting; PowerShell-based MSI installer delivery |
| 2026-08 | Payment Advice Note lure targeting financial institution staff; steganography implementation; continued CPL-based CosmicPulse deployment |
| 2026-09-29 | Microsoft Security Blog publishes detailed technical analysis |

## Root Cause: Phishing with Password-Protected Archives

Star Blizzard's campaigns use a two-stage social engineering approach: (1) an initial contact email without attachments to build trust, followed by (2) a follow-up email containing a password-protected archive (ZIP or RAR) with the archive password displayed as an image to evade automated scanning. Lures impersonate known organizations (Chatham House, Atlantic Council, IISS, Ukraine Recovery Conference) or mimic internal communications (tax audit notices, payment advice notes, water supply notifications).

Since March 2026, phishing emails are sent from accounts on compromised WordPress and cPanel-hosted websites, replacing previous reliance on free email services (Protonmail, Microsoft consumer accounts). This infrastructure shift supports the higher-volume campaign model.

## Technical Analysis of the Malicious Payload

### 1. Initial Delivery — Archive and LNK Execution

**January 2026 variant (VHDX-based):**
A password-protected ZIP (`Documents.zip`) contains a VHDX virtual hard disk file (`Documents.vhdx`). The VHDX houses a malicious LNK file disguised as a PDF alongside a BAT script and a decoy PDF document. When the user opens the LNK, it launches `conhost.exe` in a hidden window, which spawns `cmd.exe` to execute the embedded BAT script. The BAT script opens the decoy PDF (to satisfy the user) and invokes `SSH.exe` with `PermitLocalCommand=yes` and `LocalCommand=cmd.exe`, which downloads and executes a remotely hosted MSI installer.

**July 2026 variant (PDF steganography):**
Phishing emails contain nested password-protected archives (RAR inside ZIP). The LNK file uses `conhost.exe` and `curl` to download a PDF from an actor-controlled server. PowerShell then searches the PDF for the magic header `cAB`, extracts 208 bytes of Base64-encoded data following the header, decodes it, and executes the result via PowerShell. This fetches and installs the MSI payload.

### 2. RedFlick Persistence — Scheduled Task Chain

The malicious MSI installer creates up to three scheduled tasks masquerading as legitimate system utilities:

**Task 1 — "Internet Quality Test Connection":**
Sends UTF-16 Base64-encoded device information (hostname, username) to the C2 server as a registration beacon. Subsequently executes a remote attacker-controlled DLL via `Shell32.dll Control_RunDLL` using a WebDAV UNC path (e.g., `\\[C2-server]\[remote-path]`), enabling dynamic code execution over HTTP.

**Task 2 — "Network Configuration Manager":**
Prepares WebDAV functionality by invoking `net.exe` to activate the WebClient service, enabling Windows to treat UNC-style paths as WebDAV resources. This ensures Task 1's remote DLL execution functions over HTTP rather than requiring SMB.

**Task 3 — "System Health Monitor":**
Uses `control.exe` to access a hardcoded C2 server path and execute the CosmicPulse downloader, compiled as a Control Panel applet (CPL) DLL file.

### 3. CosmicPulse Backdoor Deployment

The CosmicPulse downloader (CPL file) executes via `control.exe` and performs the following:

1. Downloads two ZIP files from actor-controlled infrastructure
2. Writes an encrypted AES key to the registry at `HKEY_CURRENT_USER\Software\Classes\.mollis`
3. First ZIP contains a Python 3.8 64-bit distribution and a bootstrapper script
4. Second ZIP contains the encrypted CosmicPulse payload
5. The bootstrapper reads the encrypted AES key from the `.mollis` registry key
6. Recovers the actual key using an embedded secondary key in **AES-ECB mode**
7. Decrypts and executes the CosmicPulse Python backdoor

CosmicPulse is a Python-based backdoor whose capabilities remain consistent with versions documented by Google Threat Intelligence Group in their October 2025 COLDCOPY report.

### 4. C2 Infrastructure

Star Blizzard rotates C2 infrastructure approximately monthly:

| Period | MSI/Installer Domains | CosmicPulse Download Domains/IPs |
|--------|----------------------|----------------------------------|
| Jan 2026 | etia[.]ca | 103.245.231[.]248 |
| Feb 2026 | groy[.]cc, muvb[.]net | 2.57.241[.]246, 89.125.209[.]168 |
| Mar 2026 | matjk[.]click, bpdaersa[.]click | 103.245.231[.]79 |
| Apr 2026 | Itechx[.]tel | 45.84.59[.]66, 103.245.213[.]217 |
| Jun 2026 | guach[.]net | ruten[.]observer |
| Jul 2026 | byveo[.]org | secure-dns-hub[.]com, qumel[.]link, 103.160.59[.]97 |
| Aug 2026 | cyrna[.]top | drasw[.]club |

Communication protocols include HTTP/HTTPS via WebDAV for payload delivery, SSH with PermitLocalCommand for initial staging (January campaigns), and scheduled task-based automated beaconing.

### 5. Anti-Forensics / Evasion Techniques

- **CPL masquerading:** CosmicPulse downloader compiled as a Control Panel applet DLL, avoiding traditional EXE-based detection
- **LNK-as-PDF disguise:** Shortcut files renamed with PDF extensions/icons to deceive users
- **PDF steganography:** Payloads hidden within PDF files using the `cAB` magic header marker
- **WebDAV over HTTP:** UNC path redirection to avoid SMB-based network monitoring
- **UTF-16 Base64 encoding:** Device information encoded before exfiltration via beaconing
- **AES-ECB encryption:** Payload stored encrypted on disk with key in registry
- **SSH tunneling:** Initial payload download through SSH with PermitLocalCommand
- **Infrastructure rotation:** Monthly domain/IP rotation with compromised website accounts for email delivery
- **Password-as-image:** Archive passwords embedded in images to evade automated email scanning
- **Obfuscated code:** PowerShell and Python code obfuscation in MSI installers and bootstrappers

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `secure-dns-hub[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `103.245.231[.]248`)
> - URLs: `hxxps://` or `hxxp://`

### File System

| Description | Hash (SHA256) |
|-------------|---------------|
| Password-protected ZIP (Documents.zip) — Jan 2026 | `9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b` |
| VHDX file (Documents.vhdx) — Jan 2026 | `1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d` |
| RAR archive (Chatham_London_Conference_2026_Invitation.rar) — Jun 2026 | `699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9` |
| RAR archive (USUBC_Private_Executive_Roundtable_Webex.rar) — Jul 2026 | `24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7` |
| ZIP archive (Payment Advice Note.zip) — Aug 2026 | `dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4` |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | etia[.]ca | RedFlick MSI installer host (Jan 2026) |
| Domain | groy[.]cc | RedFlick MSI installer (Feb 2026) |
| Domain | gliderrompercycl[.]com | CosmicPulse backdoor download |
| Domain | muvb[.]net | RedFlick MSI installer (Feb 2026) |
| Domain | divekickspolic[.]org | CosmicPulse backdoor download |
| Domain | matjk[.]click | RedFlick MSI installer (Mar 2026) |
| Domain | bpdaersa[.]click | RedFlick MSI installer (Mar 2026) |
| Domain | stuseamandesilt[.]org | CosmicPulse backdoor download |
| Domain | Itechx[.]tel | RedFlick MSI installer (Apr 2026) |
| Domain | guach[.]net | RedFlick PowerShell installer (Jun 2026) |
| Domain | ruten[.]observer | CosmicPulse downloader DLL (Jun-Jul 2026) |
| Domain | byveo[.]org | RedFlick PowerShell installer (Jul 2026) |
| Domain | secure-dns-hub[.]com | CosmicPulse downloader DLL (Jul 2026-current) |
| Domain | qumel[.]link | CosmicPulse downloader DLL (Jul 2026) |
| Domain | cyrna[.]top | RedFlick MSI installer (Aug 2026) |
| Domain | drasw[.]club | CosmicPulse downloader DLL (Aug 2026) |
| IP | 103.245.231[.]248 | CosmicPulse downloader DLL host (Jan 2026) |
| IP | 2.57.241[.]246 | CosmicPulse downloader DLL (Feb 2026) |
| IP | 89.125.209[.]168 | CosmicPulse downloader DLL (Feb 2026) |
| IP | 103.245.231[.]79 | CosmicPulse downloader DLL (Mar 2026) |
| IP | 45.84.59[.]66 | CosmicPulse downloader DLL (Apr 2026) |
| IP | 103.160.59[.]97 | CosmicPulse downloader DLL (Jul 2026) |

### Behavioral

- **Scheduled task names:** "Internet Quality Test Connection", "Network Configuration Manager", "System Health Monitor"
- **Registry key:** `HKEY_CURRENT_USER\Software\Classes\.mollis` (AES key storage)
- **Archive passwords observed:** `LiveCrown8142`, `LiteRaspberry9415`, `BirdMouseCrab`
- **SSH abuse pattern:** `ssh.exe` with `-o PermitLocalCommand=yes -o LocalCommand=cmd.exe`
- **Process chain:** `conhost.exe` -> `cmd.exe` -> `ssh.exe` (January variant); `conhost.exe` -> `curl.exe` -> PDF download (July variant)
- **CPL execution:** `control.exe` loading remote DLLs via WebDAV UNC paths
- **Shell32.dll Control_RunDLL:** Dynamic DLL execution via WebDAV for Task 1 beaconing

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.001 | Phishing: Spearphishing Attachment | Password-protected archives with malicious LNK/VHDX payloads |
| T1566.002 | Phishing: Spearphishing Link | Initial contact emails building rapport for follow-up delivery |
| T1204.002 | User Execution: Malicious File | Victim opens archive, triggering LNK execution |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Three scheduled tasks created by MSI for persistence and execution |
| T1218.002 | System Binary Proxy Execution: Control Panel | CosmicPulse downloader compiled as CPL, executed via control.exe |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Shell32.dll Control_RunDLL for dynamic DLL execution |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PDF steganography extraction and payload execution |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | BAT script execution, cmd.exe via SSH LocalCommand |
| T1105 | Ingress Tool Transfer | MSI, DLL, and CosmicPulse payload downloads from C2 |
| T1140 | Deobfuscate/Decode Files or Information | Base64 decoding of PDF-embedded payload, AES-ECB decryption |
| T1112 | Modify Registry | AES key written to HKCU\Software\Classes\.mollis |
| T1036 | Masquerading | LNK as PDF, CPL as legitimate Control Panel item, task names mimicking system utilities |
| T1027.003 | Obfuscated Files or Information: Steganography | Payload embedded in PDF with cAB magic header |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/WebDAV for C2 communication and payload delivery |

## Impact Assessment

**Breadth:** Over 100 organizations across at least 13 campaigns since January 2026, primarily in the US and UK, with initial Ukrainian targeting expanding globally. Sectors include NGOs, think tanks (Atlantic Council, Chatham House, IISS), government agencies, financial institutions, academic institutions, and media organizations.

**Depth:** Full backdoor deployment (CosmicPulse) enables persistent cyberespionage access. The Python backdoor provides the actor with ongoing intelligence collection capabilities aligned with Russian foreign policy objectives.

**Stealth:** Monthly infrastructure rotation, CPL masquerading, PDF steganography, WebDAV evasion, and scheduled task persistence all contribute to detection difficulty. Microsoft notes "various little changes to circumvent existing signatures" have been made throughout 2026.

**Ongoing threat:** The secure-dns-hub[.]com infrastructure remains active as of the September 29, 2026 report date, and the campaign shows no signs of abating.

## Detection & Remediation

### Immediate Detection

Check for the following indicators on Windows endpoints:

```powershell
# Check for RedFlick scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskName -in @('Internet Quality Test Connection','Network Configuration Manager','System Health Monitor')}

# Check for CosmicPulse registry key
Get-ItemProperty -Path 'HKCU:\Software\Classes\.mollis' -ErrorAction SilentlyContinue

# Check for recent SSH PermitLocalCommand abuse
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Message -match 'PermitLocalCommand.*yes'}

# Check DNS logs for known C2 domains
Get-DnsClientCache | Where-Object {$_.Entry -match 'secure-dns-hub|gliderrompercycl|divekickspolic|stuseamandesilt|ruten\.observer|drasw\.club'}
```

### Remediation

1. **Contain:** Isolate affected endpoints; disable the three named scheduled tasks immediately
2. **Eradicate:** Remove the `.mollis` registry key, associated Python installations, CPL files, and downloaded MSI artifacts
3. **Investigate:** Review email logs for phishing lures matching known subject lines; check for SSH outbound connections to external hosts; audit WebDAV/WebClient service usage
4. **Rotate:** Rotate credentials for any accounts accessed from compromised endpoints
5. **Block:** Add all IOC domains and IPs to DNS sinkhole, firewall, and proxy blocklists

### Long-Term Hardening

- Deploy phishing-resistant authentication (FIDO2/passkeys) across all accounts
- Block outbound SSH to external/public networks via Windows Firewall unless explicitly required
- Enable Attack Surface Reduction rules: "Block executable files with no prevalence/age/trusted list criteria" and "Block execution of potentially obfuscated scripts"
- Monitor for anomalous `control.exe` execution with remote UNC paths
- Enable PowerShell Script Block Logging and Sysmon with comprehensive configuration
- Implement Conditional Access policies with continuous access evaluation
- Deploy email protection with Safe Links (recheck on click), Safe Attachments, and Zero-Hour Auto Purge

## Detection Rules

The following rules target Star Blizzard RedFlick technique artifacts and CosmicPulse indicators at PoC/advisory-specific altitude. Rules key on the distinctive scheduled task names, SSH PermitLocalCommand abuse, CPL/WebDAV execution patterns, PDF steganography extraction, and known C2 domains. The primary caveat: IOC-based rules (DNS queries, file hashes) have a finite shelf life as the actor rotates infrastructure monthly.

### Sigma Rules

#### 1. RedFlick Scheduled Task Creation

Detects schtasks.exe creating tasks with the three distinctive names used by RedFlick MSI installers.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline -t splunk and -t log_scale on 2026-09-30. sigma check blocked by proxy (MITRE ATT&CK data fetch 403) — syntax verified via successful backend conversion. Tags: attack.t1053.005, attack.t1547.001. Logsource: process_creation/windows. Fields: Image (endswith), CommandLine (contains OR list). No defanged values in detection — task names are plaintext strings. FP note: task names are specific enough to yield near-zero false positives in production. -->

```yaml
title: RedFlick Scheduled Task Creation - Star Blizzard
id: 5a46b0b6-4779-4ffe-bca7-1f2f0094d28c
status: experimental
description: >
    Detects creation of scheduled tasks with names associated with Star Blizzard's
    RedFlick technique used to deploy the CosmicPulse backdoor. The tasks masquerade
    as legitimate system utilities (Internet Quality Test Connection, Network Configuration
    Manager, System Health Monitor).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1053.005
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
    selection_tasknames:
        CommandLine|contains:
            - 'Internet Quality Test Connection'
            - 'Network Configuration Manager'
            - 'System Health Monitor'
    condition: selection_schtasks and selection_tasknames
falsepositives:
    - Legitimate software using identical task names (unlikely given specificity)
level: high
```

#### 2. SSH PermitLocalCommand Abuse for Payload Delivery

Detects SSH.exe with PermitLocalCommand=yes used to launch cmd.exe, an uncommon pattern on Windows exploited by RedFlick for initial payload staging.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1218, attack.t1059.003. Logsource: process_creation/windows. Uses contains|all for PermitLocalCommand + yes (AND), plus LocalCommand. PermitLocalCommand on Windows SSH is genuinely rare. No defanged values. -->

```yaml
title: SSH PermitLocalCommand Abuse for Payload Delivery
id: ac6c8839-7796-48b1-9c9d-df1afcd65a8f
status: experimental
description: >
    Detects SSH.exe execution with PermitLocalCommand=yes and LocalCommand=cmd.exe,
    a technique used by Star Blizzard in RedFlick campaigns to download and execute
    MSI payloads via SSH tunneling.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1218
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_ssh:
        Image|endswith: '\ssh.exe'
    selection_permit:
        CommandLine|contains|all:
            - 'PermitLocalCommand'
            - 'yes'
    selection_localcmd:
        CommandLine|contains: 'LocalCommand'
    condition: selection_ssh and selection_permit and selection_localcmd
falsepositives:
    - Legitimate SSH automation scripts using PermitLocalCommand (rare on Windows)
level: high
```

#### 3. Control Panel Applet Execution from Remote UNC Path

Detects control.exe accessing remote UNC or HTTP paths, consistent with RedFlick CPL-based CosmicPulse deployment via WebDAV.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1218.002, attack.t1105. Remote control.exe execution is inherently suspicious. Backslash escaping in YAML: '\\\\' matches literal \\. No defanged values — real paths used in detection. -->

```yaml
title: Control Panel Applet Execution via Control.exe - RedFlick CPL Loader
id: 210f1df2-b2a8-4f7c-bd59-2180faa10c8c
status: experimental
description: >
    Detects control.exe executing a Control Panel applet (CPL) from a remote UNC path
    or suspicious local path, consistent with Star Blizzard's RedFlick technique
    where CosmicPulse downloader is compiled as a CPL DLL.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1218.002
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_control:
        Image|endswith: '\control.exe'
    selection_remote:
        CommandLine|contains:
            - '\\\\'
            - 'http://'
            - 'https://'
    condition: selection_control and selection_remote
falsepositives:
    - Legitimate remote Control Panel applet management (very rare)
level: high
```

#### 4. CosmicPulse Registry Key — AES Key in .mollis

Detects writes to the `.mollis` registry extension key where CosmicPulse stores its encrypted AES decryption key. This is a high-fidelity indicator.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1112, attack.t1027. Logsource: registry_set/windows. Single-field detection on TargetObject containing \Software\Classes\.mollis. Extremely specific — .mollis is not a real file extension. No defanged values (registry path is not a network indicator). -->

```yaml
title: CosmicPulse Registry Key Creation - AES Key Storage in .mollis
id: 2d4b5f57-bb95-409a-8264-36084b2e2535
status: experimental
description: >
    Detects creation or modification of the registry key HKCU\Software\Classes\.mollis,
    which Star Blizzard's CosmicPulse backdoor uses to store encrypted AES keys for
    payload decryption.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1112
    - attack.t1027
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Classes\.mollis'
    condition: selection
falsepositives:
    - Application registering .mollis file extension (extremely unlikely)
level: critical
```

#### 5. Conhost Spawning Curl for PDF Download

Detects the process chain conhost.exe -> curl.exe downloading PDF files, matching the July 2026 RedFlick delivery variant.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **medium**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1105, attack.t1059.003. The conhost->curl->PDF chain is unusual but could arise in edge-case automation. Medium confidence due to non-zero FP surface. No defanged values. -->

```yaml
title: Conhost Spawning Curl to Download PDF - RedFlick Delivery
id: 36b02ecd-006b-4a3a-8950-2dd52b7e69d9
status: experimental
description: >
    Detects conhost.exe spawning curl.exe to download PDF files, a technique
    observed in Star Blizzard's July 2026 RedFlick campaigns where LNK files
    use conhost to invoke curl for downloading PDFs containing embedded payloads.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1105
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\conhost.exe'
    selection_curl:
        Image|endswith: '\curl.exe'
    selection_pdf:
        CommandLine|contains: '.pdf'
    condition: selection_parent and selection_curl and selection_pdf
falsepositives:
    - Legitimate scripts using conhost to invoke curl for PDF downloads (unlikely chain)
level: high
```

#### 6. PowerShell PDF Steganography Extraction (cAB Header)

Detects PowerShell scripts searching for the `cAB` magic header and invoking Base64 decoding, consistent with RedFlick PDF-embedded payload extraction.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **medium**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1027.003, attack.t1059.001. Logsource: ps_script/windows (Script Block Logging). cAB is the Base64 encoding of the cabinet file header bytes — matching both cAB and FromBase64String in the same script block is reasonably specific. Medium confidence: cAB could appear in legitimate CAB file processing. -->

```yaml
title: PowerShell PDF Steganography Extraction - RedFlick Payload
id: 26d43f13-2b87-48b7-88f7-841cb10e0c6f
status: experimental
description: >
    Detects PowerShell commands that search PDF content for the magic header 'cAB'
    and decode Base64 data, consistent with Star Blizzard's RedFlick technique
    of embedding payloads within PDF files using steganography.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1027.003
    - attack.t1059.001
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'cAB'
            - 'FromBase64String'
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts processing Base64-encoded cabinet file data
level: high
```

#### 7. Shell32 Control_RunDLL via WebDAV UNC Path

Detects Shell32.dll Control_RunDLL invocation with a UNC path, matching RedFlick Task 1's remote DLL execution via WebDAV.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1218.011, attack.t1071.001. Uses contains|all for Shell32.dll + Control_RunDLL + \\\\ (UNC). Control_RunDLL over UNC is not expected in normal operations. No defanged values. -->

```yaml
title: Shell32 Control_RunDLL via WebDAV UNC Path - RedFlick DLL Execution
id: f3149fcc-3a52-46c4-8559-2ea790bcd0b1
status: experimental
description: >
    Detects rundll32.exe or control.exe invoking Shell32.dll Control_RunDLL with
    a WebDAV UNC path, consistent with Star Blizzard's RedFlick Task 1 executing
    remote attacker-controlled DLLs via WebDAV.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1218.011
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith:
            - '\rundll32.exe'
            - '\control.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'Shell32.dll'
            - 'Control_RunDLL'
            - '\\\\'
    condition: selection_binary and selection_cmdline
falsepositives:
    - Legitimate Control Panel operations using UNC paths (rare in most environments)
level: high
```

#### 8. DNS Query to Star Blizzard RedFlick Infrastructure

Detects DNS queries to known Star Blizzard domains used for MSI delivery, CosmicPulse downloads, and downloader DLL hosting. IOC-based; requires updates as infrastructure rotates.

compile: **Splunk** ✅ | **LogScale** ✅ -- confidence: **high**

<!-- Audit: Validated via sigma convert --without-pipeline. Tags: attack.t1071.001, attack.t1568. Logsource: dns_query (no product — cross-platform). Uses endswith for domain matching to capture subdomains. 16 domains from Microsoft blog IOC table (Jan-Aug 2026). Values are NOT defanged per logsource-encoding rules. IOC shelf-life: actor rotates monthly. -->

```yaml
title: Star Blizzard CosmicPulse C2 DNS Query
id: d8729af2-d8d6-4ea5-b9d2-526e7e3a4b10
status: experimental
description: >
    Detects DNS queries to domains associated with Star Blizzard's RedFlick
    infrastructure used for MSI installer hosting, CosmicPulse backdoor download,
    and downloader DLL delivery (January-August 2026 campaigns).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1071.001
    - attack.t1568
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'etia.ca'
            - 'groy.cc'
            - 'gliderrompercycl.com'
            - 'muvb.net'
            - 'divekickspolic.org'
            - 'matjk.click'
            - 'bpdaersa.click'
            - 'stuseamandesilt.org'
            - 'itechx.tel'
            - 'guach.net'
            - 'ruten.observer'
            - 'byveo.org'
            - 'secure-dns-hub.com'
            - 'qumel.link'
            - 'cyrna.top'
            - 'drasw.club'
    condition: selection
falsepositives:
    - Extremely unlikely given the specificity of these domains
level: critical
```

### YARA Rules

#### 9. CosmicPulse Dropper / RedFlick CPL Artifact

Detects PE files containing CosmicPulse-associated strings (registry path, scheduled task names, CPlApplet export, Control_RunDLL), and archives containing multiple RedFlick indicators.

compile: ✅ (`yarac` exit 0) -- confidence: **high**

<!-- Audit: Compiled with yarac on 2026-09-30. Rule 1 targets PE files (MZ header) under 10MB with CosmicPulse-specific strings: .mollis registry key, CPlApplet export, scheduled task names, Control_RunDLL. Alt branch matches any file under 50MB with 3+ of the 4 most distinctive strings. All strings use ascii wide for encoding coverage. Hash meta includes 5 known sample SHA-256s. No FP-prone generic strings. -->

```yara
rule APT_StarBlizzard_CosmicPulse_Dropper
{
    meta:
        description = "Detects Star Blizzard CosmicPulse downloader CPL files and associated archive lures based on known file hashes and characteristic strings"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
        tlp = "WHITE"
        severity = "critical"
        hash1 = "9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b"
        hash2 = "1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d"
        hash3 = "699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9"
        hash4 = "24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7"
        hash5 = "dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4"

    strings:
        $mollis = "Software\\Classes\\.mollis" ascii wide
        $schtask1 = "Internet Quality Test Connection" ascii wide
        $schtask2 = "Network Configuration Manager" ascii wide
        $schtask3 = "System Health Monitor" ascii wide
        $ctrl_rundll = "Control_RunDLL" ascii wide
        $cpl_export = "CPlApplet" ascii

    condition:
        (uint16(0) == 0x5A4D and filesize < 10MB and
            (
                $mollis or
                ($cpl_export and 2 of ($schtask*)) or
                ($ctrl_rundll and any of ($schtask*))
            )
        )
        or
        (filesize < 50MB and 3 of ($schtask1, $schtask2, $schtask3, $mollis))
}
```

#### 10. RedFlick PDF Steganography (cAB Header)

Detects PDF files containing a `cAB` marker followed by a large Base64 block, consistent with Star Blizzard's technique of hiding payloads inside PDFs.

compile: ✅ (`yarac` exit 0) -- confidence: **medium**

<!-- Audit: Compiled with yarac on 2026-09-30. Matches %PDF header at offset 0, then cAB marker + regex for 200+ Base64 chars. cAB is the Base64 encoding of cabinet file magic bytes (MSCF). Medium confidence: legitimate PDFs could contain encoded CAB data, though the 200-byte minimum and co-occurrence reduce FP risk. -->

```yara
rule APT_StarBlizzard_RedFlick_PDF_Steganography
{
    meta:
        description = "Detects PDF files containing embedded payloads using the cAB magic header technique employed by Star Blizzard RedFlick campaigns"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pdf_header = "%PDF" ascii
        $magic_cab = "cAB" ascii
        $b64_block = /cAB[A-Za-z0-9+\/]{200,}/

    condition:
        $pdf_header at 0 and
        filesize < 20MB and
        ($magic_cab and $b64_block)
}
```

### Suricata Rules

#### 11-15. DNS Queries to Star Blizzard RedFlick C2 Domains

Detect DNS queries to five key CosmicPulse infrastructure domains active during the campaign. Each rule targets a single domain for granular alerting.

compile: ✅ (`suricata -T` exit 0) -- confidence: **high**

<!-- Audit: All 5 rules validated with suricata -T -S on 2026-09-30, Suricata 7.0.3. Protocol: dns. Uses dns.query sticky buffer with content match + nocase. Domains NOT defanged per logsource-encoding.md. SIDs 2100010-2100014. IOC shelf-life limited by actor infrastructure rotation. -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Star Blizzard RedFlick C2 Domain secure-dns-hub.com"; flow:to_server; dns.query; content:"secure-dns-hub.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created_at 2026-09-30; sid:2100010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Star Blizzard RedFlick C2 Domain gliderrompercycl.com"; flow:to_server; dns.query; content:"gliderrompercycl.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created_at 2026-09-30; sid:2100011; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Star Blizzard RedFlick C2 Domain divekickspolic.org"; flow:to_server; dns.query; content:"divekickspolic.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created_at 2026-09-30; sid:2100012; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Star Blizzard RedFlick C2 Domain stuseamandesilt.org"; flow:to_server; dns.query; content:"stuseamandesilt.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created_at 2026-09-30; sid:2100013; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Star Blizzard RedFlick C2 Domain ruten.observer"; flow:to_server; dns.query; content:"ruten.observer"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created_at 2026-09-30; sid:2100014; rev:1;)
```

### Snort 3 Rules

#### 16-18. DNS Queries to Star Blizzard C2 Domains (Label-Encoded)

Detect DNS queries to three key domains using label-length encoding in the UDP payload, as Snort 3 has no DNS-specific sticky buffer.

compile: ✅ (`snort -T` exit 0) -- confidence: **high**

<!-- Audit: All 3 rules validated with snort -T on 2026-09-30, Snort 2.9.20. Protocol: udp, port 53. Uses label-length-encoded domain names in content match (e.g., |0e| = 14 bytes for "secure-dns-hub"). Domains NOT defanged. SIDs 2100020-2100022. -->

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - Star Blizzard RedFlick DNS Query secure-dns-hub.com"; flow:to_server; content:"|0e|secure-dns-hub|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created 2026-09-30; sid:2100020; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - Star Blizzard RedFlick DNS Query gliderrompercycl.com"; flow:to_server; content:"|12|gliderrompercycl|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created 2026-09-30; sid:2100021; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - Star Blizzard RedFlick DNS Query divekickspolic.org"; flow:to_server; content:"|10|divekickspolic|03|org|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/; metadata:author Actioner, created 2026-09-30; sid:2100022; rev:1;)
```

## Lessons Learned

1. **Scheduled task abuse remains undermonitored.** RedFlick demonstrates that scheduled tasks with plausible-sounding names provide effective persistence while blending into normal system activity. Organizations should monitor scheduled task creation events (Sysmon EID 11, Windows Security 4698) and alert on tasks referencing remote paths or suspicious executables.

2. **CPL files are an underappreciated LOLBin vector.** Compiling malware as Control Panel applets (CPL DLLs) executed via `control.exe` sidesteps many endpoint detection rules focused on traditional PE executables. Security teams should treat `control.exe` executing non-standard CPL files — especially from user-writable or remote paths — as suspicious.

3. **WebDAV enables SMB-like remote execution over HTTP.** The WebClient service turns UNC paths into HTTP requests, allowing attackers to deliver and execute payloads without triggering SMB-focused network monitoring. Consider disabling the WebClient service where not required, and monitor for `net use` commands activating WebDAV.

4. **Volume does not mean unsophisticated.** Star Blizzard's shift from targeted spear-phishing to 13+ bulk campaigns while simultaneously evolving technical delivery mechanisms (VHDX -> LNK+SSH -> PDF steganography) shows an actor scaling operations without sacrificing technical capability.

5. **PDF steganography warrants file-content inspection.** Embedding executable payloads within PDF files using Base64-encoded markers bypasses signature-based scanning. File inspection solutions should flag PDFs containing large Base64 blobs, particularly those with non-standard markers like `cAB`.

## Sources

- [Microsoft Security Blog — Star Blizzard refines phishing and malware delivery with the RedFlick technique](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/) — primary source with full technical analysis, IOCs, advanced hunting queries, and detection guidance
- [The Hacker News — Russia's Star Blizzard Targets 100+ Organizations](https://thehackernews.com/2026/09/russias-star-blizzard-targets-100.html) — supplementary reporting with campaign context and attribution details
- [CyberScoop — Microsoft Star Blizzard RedFlick Phishing Campaigns](https://cyberscoop.com/microsoft-star-blizzard-redflick-phishing-campaigns/) — additional context on campaign scale and organizational targeting

---
*Report generated by Actioner*
