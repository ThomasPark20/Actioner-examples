# Technical Analysis Report: Microsoft SharePoint Deserialization RCE — CVE-2026-45659 (2026-07-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-06
Version: 1.1 (FINAL)

## Executive Summary

CVE-2026-45659 is a high-severity (CVSS 8.8) remote code execution vulnerability in Microsoft SharePoint Server caused by unsafe deserialization of untrusted data (CWE-502). Any authenticated user with minimum Site Member permissions can exploit the flaw to execute arbitrary code on the server by sending crafted requests containing malicious serialized payloads. Microsoft patched the vulnerability in late May 2026 via an out-of-band security update (KB5002863, KB5002870, KB5002868), but CISA added it to the Known Exploited Vulnerabilities (KEV) catalog on July 2, 2026, confirming active exploitation in the wild. The threat actor Storm-2603 is known to exploit SharePoint deserialization vulnerabilities for initial access before deploying Warlock ransomware.

Affected products include SharePoint Server Subscription Edition (below build 16.0.19725.20280), SharePoint Server 2019 (below 16.0.10417.20128), and SharePoint Enterprise Server 2016 (below 16.0.5552.1002). Over 10,000 SharePoint servers are estimated to be exposed online, with an unknown proportion remaining unpatched.

## Background: Microsoft SharePoint Server

Microsoft SharePoint Server is an enterprise collaboration platform widely deployed in government and corporate environments for document management, intranet portals, and workflow automation. On-premises SharePoint deployments are particularly attractive targets because they often hold sensitive business data, Active Directory credentials, and serve as a pivot point for lateral movement within enterprise networks. SharePoint runs on IIS (Internet Information Services), with worker processes (`w3wp.exe`) handling all application requests, including deserialization of user-supplied data.

Since 2021, CISA has tracked 11 Microsoft SharePoint vulnerabilities exploited in the wild, with 7 of those also used in ransomware campaigns, making SharePoint one of the most consistently targeted enterprise applications.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-21 | Microsoft releases out-of-band security updates for SharePoint Server (KB5002863, KB5002870, KB5002868), though CVE-2026-45659 was initially omitted from the May 2026 Security Updates advisory |
| 2026-05-26 | Microsoft updates advisory to explicitly list CVE-2026-45659 as addressed by the May 2026 updates |
| 2026-07-02 | CISA adds CVE-2026-45659 to the Known Exploited Vulnerabilities (KEV) catalog, confirming active exploitation |
| 2026-07-05 | Federal Civilian Executive Branch (FCEB) agencies deadline to apply patches per Binding Operational Directive 26-04 |

## Root Cause: Deserialization of Untrusted Data (CWE-502)

CVE-2026-45659 is caused by unsafe deserialization of untrusted data in SharePoint Server code paths. An authenticated attacker with at least Site Member permissions sends crafted HTTP requests containing malicious serialized .NET payloads (e.g., BinaryFormatter or LosFormatter serialized objects) to SharePoint endpoints. Upon deserialization, the crafted objects instantiate arbitrary types, leading to code execution in the context of the SharePoint IIS worker process (`w3wp.exe`) under the application pool's service identity.

The vulnerability has a network-based attack vector with low attack complexity. As Microsoft stated: "Any authenticated attacker could trigger this vulnerability. It does not require admin or other elevated privileges." No user interaction is required. The CVSS 3.1 vector is AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8 High).

## Technical Analysis of the Malicious Payload

### 1. Initial Access: SharePoint Deserialization Exploitation

The attacker authenticates to a vulnerable SharePoint server using valid credentials with at minimum Site Member permissions. Crafted HTTP POST requests are sent to SharePoint endpoints (historically, the `/_layouts/` path hierarchy and `/_vti_bin/` service endpoints have been targeted in SharePoint deserialization attacks). The POST body contains a serialized .NET payload (base64-encoded BinaryFormatter or LosFormatter object) that, upon deserialization by the SharePoint server-side code, instantiates arbitrary objects leading to code execution.

The resulting code execution occurs inside the `w3wp.exe` IIS worker process, running under the SharePoint application pool identity. The attacker does not need significant prior knowledge of the system and can achieve repeatable success.

### 2. Post-Exploitation and Persistence

Based on observed activity from Storm-2603 and related campaigns exploiting SharePoint deserialization flaws, post-exploitation typically includes:

- **Webshell deployment:** ASPX webshell files are dropped into SharePoint `TEMPLATE\LAYOUTS` directories (e.g., `%ProgramFiles%\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\`). Previous campaigns used naming patterns such as `spinstall0.aspx`, `spinstall.aspx`, `spinstall1.aspx`.
- **Process spawning from w3wp.exe:** The compromised IIS worker process spawns command interpreters (`cmd.exe`, `powershell.exe`) and compilation tools (`csc.exe`) for further payload execution.
- **Credential harvesting:** Mimikatz or similar tools targeting LSASS memory, MachineKey theft from SharePoint configuration.
- **Privilege escalation:** PsExec with `-s` flag for SYSTEM-level execution, WMI command execution via Impacket.

### 3. C2 Infrastructure and Persistence Channels

Storm-2603 establishes multiple redundant persistence and remote access channels after SharePoint compromise:

- **Cloudflare Tunnels:** `cloudflared.exe` configured for reverse tunneling to attacker-controlled infrastructure
- **Zoho Assist:** Remote access sessions for interactive control
- **SSH via Visual Studio Code:** SSH connections routed through VS Code for stealth
- **Velociraptor:** Abuse of the legitimate forensic tool to blend malicious activity with trusted administrative operations
- **Ngrok tunnels:** Used for payload delivery (e.g., PowerShell scripts)

Related C2 infrastructure from previous Storm-2603 SharePoint campaigns:
- Domains: `update[.]updatemicfosoft[.]com`, `msupdate[.]updatemicfosoft[.]com`
- IPs: `65.38.121[.]198`, `131.226.2[.]6`, `134.199.202[.]205`, `104.238.159[.]149`, `188.130.206[.]168`

### 4. Platform-Specific Behavior

#### Windows (SharePoint Server)

SharePoint Server runs exclusively on Windows Server. Exploitation targets the IIS worker process `w3wp.exe`. Post-exploitation artifacts include:
- New `.aspx` files in `\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\`
- `IIS_Server_dll.dll` (IIS backdoor component in prior campaigns)
- Suspicious child processes spawned by `w3wp.exe`
- Scheduled tasks and GPO modifications for persistence
- Lateral movement via PsExec, Impacket, and SMB

### 5. Anti-Forensics / Evasion Techniques

- Use of legitimate administrative tools (Velociraptor, VS Code, PsExec) to blend in with authorized activity
- Encrypted C2 channels via Cloudflare tunnels and SSH
- Webshell filenames mimicking legitimate SharePoint installation files (e.g., `spinstall*.aspx`)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| SharePoint Server Subscription Edition | Below 16.0.19725.20280 | Deserialization RCE (CVE-2026-45659), fixed in KB5002863 |
| SharePoint Server 2019 | Below 16.0.10417.20128 | Deserialization RCE (CVE-2026-45659), fixed in KB5002870 |
| SharePoint Enterprise Server 2016 | Below 16.0.5552.1002 | Deserialization RCE (CVE-2026-45659), fixed in KB5002868 |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx` | `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514` | Webshell (from related Storm-2603 campaign) |
| Windows | `IIS_Server_dll.dll` | `4c1750a14915bf2c0b093c2cb59063912dfa039a2adfe6d26d6914804e2ae928` | IIS backdoor (related campaign) |
| Windows | `SharpHostInfo.x64.exe` | `d6da885c90a5d1fb88d0a3f0b5d9817a82d5772d5510a0773c80ca581ce2486d` | Host enumeration tool (related campaign) |
| Windows | `xd.exe` | `62881359e75c9e8899c4bc9f452ef9743e68ce467f8b3e4398bebacde9550dea` | Reverse proxy to C2 (related campaign) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `update[.]updatemicfosoft[.]com` | C2 domain (Storm-2603 — related campaign) |
| Domain | `msupdate[.]updatemicfosoft[.]com` | C2 domain (Storm-2603 — related campaign) |
| IP | `65.38.121[.]198` | Post-exploitation C2 (related campaign) |
| IP | `131.226.2[.]6` | C2 infrastructure (related campaign) |
| IP | `134.199.202[.]205` | C2 infrastructure (related campaign) |
| IP | `104.238.159[.]149` | C2 infrastructure (related campaign) |
| IP | `188.130.206[.]168` | C2 infrastructure (related campaign) |

**Note:** The network IOCs above are from the Microsoft July 2025 blog on disrupting SharePoint exploitation by the same threat actor cluster. No CVE-2026-45659-specific network IOCs have been published at the time of this report.

### Behavioral

- `w3wp.exe` spawning `cmd.exe`, `powershell.exe`, `pwsh.exe`, `csc.exe`, `certutil.exe`, or `msbuild.exe`
- New `.aspx` file creation in SharePoint `TEMPLATE\LAYOUTS` directories
- Execution of `cloudflared.exe` with `tunnel` arguments on SharePoint servers
- Execution of Zoho Assist binaries (`ZohoMeeting.exe`, `ZohoAssist.exe`, `ZA_Connect.exe`)
- Execution of `SharpHostInfo.x64.exe` or `xd.exe` (reverse proxy)
- Authenticated POST requests to SharePoint `/_layouts/` or `/_vti_bin/` endpoints with abnormally large bodies or base64-encoded serialized .NET payloads
- SharePoint ULS logs showing deserialization errors or exception traces referencing object activation

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2026-45659 on internet-facing SharePoint servers |
| T1059.001 | PowerShell | Post-exploitation PowerShell execution spawned by w3wp.exe |
| T1059.003 | Windows Command Shell | cmd.exe spawned by compromised SharePoint worker process |
| T1505.003 | Web Shell | ASPX webshell deployment in SharePoint LAYOUTS directories |
| T1219 | Remote Access Software | Zoho Assist, Velociraptor abuse for persistent remote access |
| T1572 | Protocol Tunneling | Cloudflare Tunnel and SSH via VS Code for C2 communication |
| T1003.001 | LSASS Memory | Mimikatz credential harvesting post-exploitation |
| T1021.002 | SMB/Windows Admin Shares | PsExec lateral movement |
| T1486 | Data Encrypted for Impact | Warlock ransomware deployment (Storm-2603 objective) |

## Impact Assessment

The impact is severe for organizations running unpatched on-premises SharePoint Server:

- **Breadth:** Over 10,000 SharePoint servers are exposed to the internet (Shadowserver tracking). Federal, state, and local government agencies and large enterprises are primary targets.
- **Depth:** Full remote code execution with the privileges of the SharePoint application pool identity. Post-exploitation leads to domain-wide compromise and ransomware deployment (Warlock).
- **Stealth:** The vulnerability requires only standard Site Member credentials, making it accessible to any attacker who has obtained or compromised a basic SharePoint account. Microsoft initially assessed exploitation as "less likely," which may have delayed patching by some organizations.
- **Disclosure gap:** The CVE was inadvertently omitted from the May 2026 Security Updates advisory, creating a window where patched organizations may not have known they were protected, and unpatched organizations may not have prioritized the update.

## Detection & Remediation

### Immediate Detection

**Version check (PowerShell on SharePoint server):**
```powershell
# Check SharePoint build version
(Get-SPFarm).BuildVersion
# Compare against patched builds:
# Subscription Edition: 16.0.19725.20280+
# 2019: 16.0.10417.20128+
# 2016: 16.0.5552.1002+
```

**IIS log hunt for suspicious POST requests:**
```powershell
# Search IIS logs for POST requests to common SharePoint exploitation endpoints
Get-Content C:\inetpub\logs\LogFiles\W3SVC*\*.log | Select-String -Pattern "POST.*(/_layouts/|/_vti_bin/).*200"
```

**Process tree hunt (Sysmon Event ID 1 or Windows Security 4688):**
```
# Hunt for w3wp.exe spawning command interpreters
ParentImage endswith \w3wp.exe AND Image endswith (\cmd.exe OR \powershell.exe OR \csc.exe)
```

**File system hunt for webshells:**
```powershell
# Check for recently created ASPX files in SharePoint directories
Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\*\TEMPLATE\LAYOUTS\" -Filter "*.aspx" -Recurse | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) }
```

### Remediation

1. **Apply security updates immediately:** Install KB5002863 (Subscription Edition), KB5002870 (2019), or KB5002868 (2016)
2. **Restart IIS** on all SharePoint servers post-patching to ensure patched assemblies are loaded by worker processes
<!-- revision: reworded IIS restart rationale — "ensure patched assemblies are loaded" replaces "clear cached cryptographic material" -->
3. **Enable AMSI in Full Mode** on SharePoint servers for runtime protection (after performance validation in a non-production environment)
<!-- revision: added AMSI performance validation caveat -->
4. **Hunt for indicators of prior compromise:** Check for webshells, suspicious ASPX files, unauthorized scheduled tasks, and evidence of credential harvesting
5. **Review authentication logs** for any suspicious Site Member activity preceding the patch application
6. **Rotate credentials** for SharePoint service accounts and any accounts that may have been compromised
7. **Isolate compromised servers** from the network if indicators of compromise are found

### Long-Term Hardening

- Restrict SharePoint internet exposure behind a reverse proxy or VPN with MFA
- Enable Sysmon or EDR monitoring on SharePoint servers to capture process creation trees from `w3wp.exe`
- Implement file integrity monitoring on SharePoint TEMPLATE directories
- Apply principle of least privilege for SharePoint site membership
- Monitor for Microsoft Defender XDR signatures: `Exploit:Script/SuspSignoutReq.A`, `Trojan:Win32/HijackSharePointServer.A`, `Trojan:PowerShell/MachineKeyFinder.DA!amsi` (from related SharePoint exploitation campaigns; verify current applicability -- these are not CVE-2026-45659-specific)
<!-- revision: added Defender XDR signatures provenance caveat -->

## Detection Rules

<!-- revision: added altitude mismatch note — requested "specific" detections but delivered "behavioral" since no public PoC exists -->
> **Altitude note:** The original request called for CVE-specific detection signatures. Because no public proof-of-concept or detailed exploit chain for CVE-2026-45659 has been published, all rules below are **behavioral / TTP-derived** rather than exploit-string-specific. They detect the *class* of activity (SharePoint deserialization RCE exploitation and Storm-2603 post-exploitation) rather than a unique CVE-2026-45659 artifact. If a PoC surfaces, network rules should be updated with exact payload signatures.

These detections target SharePoint deserialization exploitation patterns (CVE-2026-45659) at two layers: endpoint behavioral indicators (w3wp.exe child processes, webshell drops, post-exploitation tools) and network-level serialized payload markers. All rules are behavioral/TTP-derived since no public PoC with exact exploit strings exists; confidence is medium. Compiles does not equal fires -- verify in your SIEM/IDS pipeline with SharePoint telemetry.

### Sigma: SharePoint Worker Process Spawning Suspicious Child Process

Detects the SharePoint IIS worker process (`w3wp.exe`) spawning command interpreters or compilation tools, the primary behavioral signal for any SharePoint deserialization RCE exploitation.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed (MITRE ATT&CK data HTTP 403 from proxy — external connectivity issue, not rule error). sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. Behavioral/TTP rule — keys on parent-child process relationship, not CVE-specific artifact. FP risk: legitimate SharePoint admin tasks spawning cmd/powershell; filter covers iisreset/appcmd. Evasion: attacker could use less common LOLBins not in the child list. -->
```yaml
title: SharePoint Worker Process Spawning Suspicious Child Process
id: 7c3a9d1e-4b2f-48e5-a6c0-3d8f1e9b5a72
status: experimental
description: >
    Detects the SharePoint IIS worker process (w3wp.exe) spawning command interpreters
    or compilation tools, indicating potential exploitation of CVE-2026-45659 or similar
    SharePoint deserialization RCE vulnerabilities. Code execution from deserialization
    runs inside w3wp.exe and typically spawns cmd.exe, powershell.exe, or csc.exe.
references:
    - https://www.bleepingcomputer.com/news/security/cisa-microsoft-sharepoint-rce-flaw-now-actively-exploited/
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659
    - https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/
author: Actioner
date: 2026/07/06
tags:
    - attack.t1190
    - attack.t1059.001
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\w3wp.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\csc.exe'
            - '\certutil.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\rundll32.exe'
            - '\msbuild.exe'
    filter_iisreset:
        CommandLine|contains:
            - 'iisreset'
            - 'appcmd'
    condition: selection_parent and selection_child and not filter_iisreset
falsepositives:
    - Legitimate SharePoint administration tasks that spawn command interpreters
    - SharePoint health monitoring scripts
    - Custom SharePoint solutions with server-side code execution
level: medium
```
<!-- revision: level high→medium per critic (behavioral rule, similar rules exist in SigmaHQ) -->

### Sigma: Suspicious ASPX File Creation in SharePoint Layouts Directory

Detects creation of ASPX files in SharePoint `TEMPLATE\LAYOUTS` directories, a common webshell deployment pattern observed in Storm-2603 campaigns. Scope to change-window exclusions if SharePoint updates trigger false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. File event rule — requires Sysmon EID 11 or equivalent file creation logging on SharePoint servers. FP risk: legitimate SharePoint feature/solution deployment and cumulative updates create ASPX files in LAYOUTS. Recommend pairing with the w3wp child process rule for higher fidelity. -->
```yaml
title: Suspicious ASPX File Creation in SharePoint Layouts Directory
id: 2e8b4f1a-9c3d-4a7e-b5f2-6d1c0e8a3b94
status: experimental
description: >
    Detects creation of ASPX files in SharePoint TEMPLATE LAYOUTS directories,
    which may indicate webshell deployment following exploitation of CVE-2026-45659
    or similar SharePoint RCE vulnerabilities. Observed in Storm-2603 campaigns
    deploying spinstall variants and other webshells.
references:
    - https://www.bleepingcomputer.com/news/security/cisa-microsoft-sharepoint-rce-flaw-now-actively-exploited/
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659
    - https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/
author: Actioner
date: 2026/07/06
tags:
    - attack.t1505.003
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains: '\Microsoft Shared\Web Server Extensions\'
    selection_layouts:
        TargetFilename|contains: '\TEMPLATE\LAYOUTS\'
    selection_ext:
        TargetFilename|endswith: '.aspx'
    condition: selection_path and selection_layouts and selection_ext
falsepositives:
    - Legitimate SharePoint feature deployment or solution installation
    - SharePoint cumulative update installation creating ASPX files in LAYOUTS directories
level: medium
```
<!-- revision: level high→medium per critic; expanded FP entry for cumulative updates creating ASPX files -->

### Sigma: Storm-2603 Post-Exploitation Tool Execution on SharePoint Server

Detects execution of remote access and enumeration tools associated with Storm-2603 post-exploitation following SharePoint compromise. Hunt-oriented; pair with the w3wp child process rule as the anchor signal. **Caveat:** Operators should evaluate each selection independently -- consider disabling `selection_cloudflared` and `selection_zohoassist` in environments where Cloudflare tunnels or Zoho Assist are authorized, or split into per-tool-family rules to reduce noise.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; -t log_scale exit 0. TTP rule targeting post-exploitation tool execution, not CVE-specific. FP risk: cloudflared.exe with tunnel args may be legitimate; ZohoAssist may be authorized IT support; xd.exe filename collision possible. SharpHostInfo.x64.exe is distinctive. Recommend scoping to SharePoint server assets. -->
```yaml
title: Storm-2603 Post-Exploitation Tool Execution on SharePoint Server
id: 5f1d8c3a-2e7b-4d9f-a0c6-8b4e3f2d1a95
status: experimental
description: >
    Detects execution of tools associated with Storm-2603 post-exploitation activity
    following SharePoint compromise. The group establishes persistence via Cloudflare
    tunnels, Zoho Assist remote access, and reverse proxies after exploiting
    CVE-2026-45659 and similar SharePoint deserialization vulnerabilities.
references:
    - https://www.bleepingcomputer.com/news/security/cisa-microsoft-sharepoint-rce-flaw-now-actively-exploited/
    - https://thehackernews.com/2026/07/sharepoint-rce-cve-2026-45659-added-to.html
    - https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/
author: Actioner
date: 2026/07/06
tags:
    - attack.t1219
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_cloudflared:
        Image|endswith: '\cloudflared.exe'
        CommandLine|contains: 'tunnel'
    selection_zohoassist:
        Image|endswith:
            - '\ZohoMeeting.exe'
            - '\ZohoAssist.exe'
            - '\ZA_Connect.exe'
    selection_sharphost:
        Image|endswith: '\SharpHostInfo.x64.exe'
    selection_xd_proxy:
        Image|endswith: '\xd.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Cloudflare tunnel usage for authorized remote access
    - Authorized Zoho Assist remote support sessions
level: medium
```

### Snort: HTTP POST to SharePoint with .NET Deserialization Marker

Detects HTTP POST requests to SharePoint `/_layouts/` endpoints containing the base64-encoded .NET BinaryFormatter magic header (`AAEAAAD`), indicating a potential deserialization exploit attempt.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c snort_sharepoint.conf -T exit 0. Snort 2.9.20 validated. Keys on /_layouts/ URI + AAEAAAD BinaryFormatter base64 header in POST body. AAEAAAD is the base64 encoding of the BinaryFormatter preamble bytes (0x00 0x01 0x00 0x00 0x00). FP risk: legitimate SharePoint POST requests rarely contain raw BinaryFormatter payloads in modern versions, but custom solutions could trigger. The /_layouts/ path is broad; the body content match adds specificity. -->
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - HTTP POST to SharePoint with .NET Deserialization Marker (CVE-2026-45659)"; flow:established,to_server; content:"POST"; http_method; content:"/_layouts/"; http_uri; fast_pattern; content:"AAEAAAD"; http_client_body; classtype:web-application-attack; reference:url,msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659; reference:cve,2026-45659; sid:2100101; rev:1;)
```

### Suricata: HTTP POST to SharePoint with .NET Deserialization Marker

Detects HTTP POST requests to SharePoint `/_layouts/` endpoints containing the base64-encoded .NET BinaryFormatter magic header (`AAEAAAD`) in the request body.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S sharepoint-rce-deser-suri.rules -l /tmp/actioner exit 0. Suricata 7.0.3. Uses dot-notation sticky buffers (http.method, http.uri, http.request_body). Same detection logic as Snort rule but for Suricata deployments. FP/evasion same as Snort rule above. Attacker could use LosFormatter instead of BinaryFormatter (different header) or apply additional encoding layers to evade the AAEAAAD content match. -->
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - HTTP POST to SharePoint with .NET Deserialization Marker (CVE-2026-45659)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/_layouts/"; fast_pattern; http.request_body; content:"AAEAAAD"; classtype:web-application-attack; reference:url,msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659; reference:cve,2026-45659; metadata:author Actioner, created_at 2026-07-06; sid:2200101; rev:1;)
```

### YARA: N/A

No file-level indicators specific to CVE-2026-45659 exploitation are publicly available. The webshell hashes documented in the IOC section are from related Storm-2603 campaigns targeting earlier SharePoint CVEs and are covered by Microsoft Defender signatures. A YARA rule for the `spinstall` webshell family could be produced if samples become available.

## Lessons Learned

1. **Advisory disclosure gaps create risk:** CVE-2026-45659 was inadvertently omitted from the May 2026 Security Updates advisory despite being patched. Organizations that rely solely on advisory text (rather than KB-level tracking) may have missed the patch, contributing to the exploitation window.

2. **"Exploitation less likely" assessments can mislead:** Microsoft initially assessed exploitation of this vulnerability as "less likely." CISA's KEV addition weeks later proves the assessment was wrong. Organizations should weight CVSS score and vulnerability class (deserialization RCE with low-privilege auth) over vendor exploitability predictions.

3. **SharePoint remains a top target:** With 11 SharePoint CVEs exploited in the wild since 2021 and 7 used in ransomware campaigns, on-premises SharePoint should be treated as critical infrastructure requiring priority patching, EDR coverage, and behavioral monitoring.

4. **Behavioral detection fills the PoC gap:** No public PoC or detailed exploit chain exists for CVE-2026-45659, but the exploitation class (deserialization → w3wp.exe code execution → post-exploitation tools) is well-characterized from prior SharePoint attacks. Behavioral rules targeting `w3wp.exe` child processes and webshell drops provide detection coverage independent of the specific exploit payload.

## Sources

- [BleepingComputer: CISA: Microsoft SharePoint RCE flaw now actively exploited](https://www.bleepingcomputer.com/news/security/cisa-microsoft-sharepoint-rce-flaw-now-actively-exploited/) — Primary reporting on CISA KEV addition and active exploitation status
- [The Hacker News: SharePoint RCE CVE-2026-45659 Added to CISA KEV](https://thehackernews.com/2026/07/sharepoint-rce-cve-2026-45659-added-to.html) — Storm-2603 attribution and post-exploitation tool details
- [SecurityWeek: CISA Warns of Actively Exploited Microsoft SharePoint Vulnerability](https://www.securityweek.com/cisa-warns-of-actively-exploited-microsoft-sharepoint-vulnerability/) — Exploit complexity and authentication requirements
- [Microsoft MSRC: CVE-2026-45659 Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659) — Vendor advisory with CVSS, affected versions, and patches
- [Penligent: CVE-2026-45659, SharePoint RCE That Needs More Than a Patch Ticket](https://www.penligent.ai/hackinglabs/cve-2026-45659/) — Affected build versions and behavioral hunting guidance
- [SOCRadar: CISA Flags SharePoint RCE (CVE-2026-45659)](https://socradar.io/blog/cisa-sharepoint-rce-cve-2026-45659/) — Exploitation pattern overview and CWE-502 classification
- [Threat-Modeling.com: CVE-2026-45659 SharePoint Deserialization RCE](https://threat-modeling.com/cve-2026-45659-microsoft-sharepoint-deserialization-rce-cisa-kev/) — CISA KEV timeline and remediation deadline details
- [The Register: Microsoft said exploitation was 'less likely' but CISA just added SharePoint RCE to KEV list](https://www.theregister.com/security/2026/07/02/microsoft-said-exploitation-was-less-likely-but-cisa-just-added-sharepoint-rce-to-kev-list/5265886) — Critique of Microsoft exploitability assessment
- [Microsoft Security Blog: Disrupting active exploitation of on-premises SharePoint vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/) — Detailed technical analysis of Storm-2603 SharePoint exploitation patterns, IOCs, webshell artifacts, and C2 infrastructure from related campaigns
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Authoritative KEV listing

---
*Report generated by Actioner*
