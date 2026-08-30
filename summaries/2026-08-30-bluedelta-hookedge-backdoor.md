# Technical Analysis Report: BlueDelta HOOKEDGE Backdoor Campaign (2026-08-30)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-08-30
Version: DRAFT

## Executive Summary

From late September 2025 through early April 2026, BlueDelta -- a Russian GRU-linked threat group overlapping with APT28, Fancy Bear, and Forest Blizzard -- conducted a targeted espionage campaign against European defense manufacturing, government, and diplomatic organizations in Romania, Spain, and Turkiye. The campaign deployed a previously undocumented lightweight Windows batch-script backdoor dubbed **HOOKEDGE**, delivered via macro-enabled Word documents with diplomatic-themed lures. HOOKEDGE represents a direct evolutionary successor to the HEADLACE backdoor, sharing batch scripting methodology, GUID-based file naming conventions, and abuse of legitimate infrastructure services (LIS) for command-and-control. The backdoor's distinguishing feature is its exclusive abuse of webhook[.]site -- a free developer testing service -- as its entire C2, staging, and exfiltration infrastructure, combined with the use of Microsoft Edge (msedge.exe) in headless or hidden-window mode for HTTP communications. Recorded Future's Insikt Group identified 32 distinct webhook endpoints and 26 malware samples across the campaign, with moderate-confidence attribution to BlueDelta based on code overlap and tradecraft consistency with HEADLACE operations. The campaign was timed to coincide with geopolitically significant events, including Moldova's September 2025 parliamentary elections.

## Background: European Defense and Diplomatic Targets

BlueDelta (APT28/Fancy Bear/Forest Blizzard) is a Russian state-sponsored threat group attributed to the GRU (Main Directorate of the General Staff of the Armed Forces of the Russian Federation), Unit 26165. The group has historically targeted NATO member states, European governments, defense contractors, and diplomatic organizations for intelligence collection aligned with Russian strategic interests. HOOKEDGE continues a pattern of BlueDelta campaigns designed to collect intelligence on European defense policy, diplomatic negotiations, and political developments in countries neighboring Russia's sphere of influence. The targeting of Romania, Spain, and Turkiye aligns with Russian intelligence priorities regarding NATO's eastern flank, Mediterranean security dynamics, and Moldovan political alignment. The campaign's evolution from HEADLACE -- a modular backdoor used since April 2023 -- to HOOKEDGE reflects an operational adaptation toward lighter-weight, more disposable tooling that leverages commodity infrastructure to reduce attribution risk and infrastructure costs.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-09-08 | Meeting between Spanish and Moldovan officials (lure pretext date) |
| 2025-09-26 | First HOOKEDGE delivery document created; Spanish Ministry lure impersonating Ministry of the Presidency, Justice and Relations with the Cortes |
| 2025-09 (late) | Initial HOOKEDGE deployment with 30-minute beaconing interval |
| 2025-10 | Beaconing interval increased from 30 to 61 minutes (sandbox evasion) |
| 2025-10 -- 2025-12 | Lure documents shift from Spanish Ministry theme to generic "Enable Content" prompts |
| 2026-01 | `mailopened.jpg` email-open canary tracking introduced |
| 2026-04 (early) | Turkiye-targeting variants observed via network telemetry; campaign operational end |
| 2026-04 | `doc.jpg` revised document-open canary introduced |
| 2026-06 | Document-open canaries removed (operational refinement) |
| 2026-08-28 | Recorded Future Insikt Group publishes HOOKEDGE research; Security Affairs, The Hacker News coverage |

## Root Cause: Spearphishing with Macro-Enabled Documents

Initial access was achieved via spearphishing emails containing macro-enabled Microsoft Word documents (.docm) with diplomatic-themed lures. The earliest identified lure impersonated Spain's Ministry of the Presidency, Justice and Relations with the Cortes, referencing a September 8, 2025 meeting with Moldovan officials -- timed to coincide with Moldova's parliamentary elections. The documents relied on the `AutoOpen()` VBA macro subroutine to execute the installation chain when the target enabled macros. Later variants (October 2025 onward) shifted from contextual diplomatic lures to simpler generic "Enable Content" prompts with fake error dialogs, broadening the targeting from Spanish diplomatic organizations to Romanian institutions and eventually Turkish entities. Hidden image references within the documents served as canary tracking mechanisms, pinging webhook endpoints to notify operators of successful document opens before payload execution began.

## Technical Analysis of the Malicious Payload

### 1. Delivery: Macro-Enabled Word Documents

The delivery documents employ VBA macros triggered by the `AutoOpen()` subroutine. Upon execution, the macro performs two primary functions:

- **Canary callback:** Embeds hidden image references (e.g., `hxxp://webhook[.]site/62114596-33f5-47fb-9012-0223529e5a13/docopened[.]jpg`) that signal successful document opening to operators
- **Payload installation:** Drops six files to the `%userprofile%` directory, each named with a GUID matching the corresponding webhook endpoint UUID

Dropped file naming convention observed:

| Filename Pattern | Purpose |
|------------------|---------|
| `[UUID].bat` | HOOKEDGE backdoor payload (batch script) |
| `[UUID].vbs` | VBScript launcher for the backdoor |
| `[UUID].cmd` | Installer / setup script |
| `[UUID-alt].vbs` | Installer launcher |
| `[UUID].htm` | Exfiltration HTML header (auto-submitting form) |
| `[UUID].xhtml` | Exfiltration HTML footer |

Example: Files using UUID `cf25f91c-0a20-4339-834f-02f73e8bc75e` from an observed webhook endpoint; the `.75e` extension references the final characters of the webhook UUID.

### 2. Persistence: Scheduled Task Execution

The installer creates a Windows scheduled task for persistent execution:

```
schtasks /create /tn [HOOKEDGE-UUID] /tr "wscript.exe [UUID].vbs" /sc minute /mo 30
```

The scheduled task executes the VBScript launcher at regular intervals. After creating the task, the installer self-deletes along with the launcher and task definition file to minimize forensic artifacts. The task name uses the same GUID convention as the dropped files.

### 3. C2 Infrastructure

HOOKEDGE's C2 architecture is built entirely on webhook[.]site, a legitimate free developer testing service repurposed for command-and-control:

**Dual-webhook architecture:**
- **Tasking webhook:** Receives polling requests from the backdoor; operators stage `.cmd` payloads here for the implant to retrieve
- **Exfiltration webhook:** Receives command output wrapped in auto-submitting HTML forms

**Infrastructure constraints and adaptations:**
- Webhook[.]site free tier limits each endpoint to **100 requests**
- 61-minute beaconing interval extends operational lifespan to approximately 2-3 days per endpoint
- Separate endpoints segregate routine beaconing from high-priority exfiltration to conserve quota
- 32 distinct webhook endpoints identified across the campaign
- Prior migration from mocky[.]io to webhook[.]site demonstrates infrastructure adaptability

**Observed webhook endpoint UUIDs (partial list):**
- `62114596-33f5-47fb-9012-0223529e5a13` (canary)
- `c29905ab-e5fa-446c-8958-4eab15d8fb80` (email tracking)
- `cf25f91c-0a20-4339-834f-02f73e8bc75e` (staging/tasking)
- `01d6a811-ae9a-4ecb-be3f-610075556304` (staging)
- `272f1315-14d7-458c-a4ca-e2df423490b4` (staging)
- `1e72b758-79e4-4c1c-90ed-7a8dc118f105` (C2/staging)
- `34f908b6-dd89-4600-b413-a29cd5e37a0b`
- `36c9aecd-19f5-4564-a354-7708d947da8e`
- `4e6cf717-e4d6-4f40-9f2d-134196fa5e7d`
- `4e81a907-cc30-45c0-8bbd-5248e9f6dacd`
- `4ef62d6a-90c0-4a70-8dd2-468879c70fd`

NordVPN IP addresses were observed administering the webhook endpoints.

### 4. HOOKEDGE Backdoor Operation

HOOKEDGE is a Windows batch-script backdoor that enters a polling loop to facilitate remote command execution:

**Polling loop cycle:**
1. Deletes `.75e`, `.tmp`, and `.crdownload` files from `%userprofile%\Downloads\` (cleanup of prior cycle artifacts)
2. Launches Microsoft Edge (`msedge.exe`) to retrieve `.75e` payload files from the staging webhook
3. Concatenates retrieved files into a `.cmd` payload and executes it
4. Wraps command output between the pre-staged `.htm` header and `.xhtml` footer files (creating an auto-submitting HTML form)
5. Launches a second Edge instance to POST the exfiltration HTML to the exfiltration webhook
6. Terminates processes matching the HOOKEDGE task identifier

**Microsoft Edge exploitation:**
- Early variants (September 2025): Headless mode using `--headless=new` flag
- Later variants (October 2025+): Hidden or off-screen browser window execution to reduce detection surface
- Legitimate browser binary blends malicious HTTP traffic with normal browsing activity

**Tiered operational model:**
- **First-stage implant:** Broad initial access; 61-minute beaconing for reconnaissance
- **Second-stage implant:** Deployed to high-value targets with 5-minute beaconing intervals for interactive tasking
- Operators triage victims through canary callbacks and initial webhook communications before escalating

### 5. Anti-Forensics / Evasion Techniques

- **Sandbox evasion:** Beaconing interval increased from 30 to 61 minutes, exceeding the typical 60-minute monitoring window of automated sandboxes
- **Fake error dialogs:** Displayed post-execution to discourage user scrutiny or incident reporting
- **Self-deletion:** Installation artifacts (installer, launcher, task definition) are deleted after scheduled task creation
- **File cleanup:** Each polling cycle begins by deleting temporary artifacts from the previous cycle
- **Hidden browser windows:** Later variants shifted from `--headless` to hidden/off-screen windows to avoid headless-mode detection
- **Legitimate infrastructure:** Exclusive use of webhook[.]site eliminates dedicated C2 infrastructure, complicating network-based attribution
- **Canary refinement:** Document-open canaries removed by June 2026 to reduce network-based indicator exposure

### Code Overlap with HEADLACE

HOOKEDGE is assessed as a direct evolutionary successor to HEADLACE based on:
- Identical Windows batch scripting approach for the backdoor
- Shared abuse of legitimate infrastructure services for C2 communications
- Hidden/headless browser instances for HTTP-based C2
- Second-stage JavaScript payloads sharing identical variable names and base64 encoding schemes
- Consistent GUID-formatted file-naming conventions tied to infrastructure endpoints

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Windows | `%userprofile%\[UUID].bat` | `001b57368c10bee9e62374e3b3f232b113eb75a1f198243d43a5bb90e1d0f500` | HOOKEDGE batch backdoor payload |
| Windows | `%userprofile%\[UUID].vbs` | `c2c9187033d22d7944ea9298461a0ac693ef2774b4ce08b0955d2aba3646fb44` | VBScript launcher |
| Windows | `%userprofile%\[UUID].cmd` | -- | Installer script |
| Windows | `%userprofile%\[UUID].htm` | -- | Exfiltration HTML header |
| Windows | `%userprofile%\[UUID].xhtml` | -- | Exfiltration HTML footer |
| Windows | `%userprofile%\Downloads\*.75e` | -- | Downloaded payload fragments |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `webhook[.]site` | C2, staging, exfiltration, canary tracking |
| URL Pattern | `hxxp://webhook[.]site/[UUID]/docopened[.]jpg` | Document-open canary tracking |
| URL Pattern | `hxxp://webhook[.]site/[UUID]/mailopened[.]jpg` | Email-open canary tracking |
| URL Pattern | `hxxp://webhook[.]site/[UUID]/doc[.]jpg` | Revised document-open canary |
| URL | `hxxp://webhook[.]site/62114596-33f5-47fb-9012-0223529e5a13/docopened[.]jpg` | Canary endpoint |
| URL | `hxxp://webhook[.]site/c29905ab-e5fa-446c-8958-4eab15d8fb80/mailopened[.]jpg` | Email tracking endpoint |
| URL | `hxxp://webhook[.]site/cf25f91c-0a20-4339-834f-02f73e8bc75e` | Staging/tasking endpoint |
| URL | `hxxps://webhook[.]site/01d6a811-ae9a-4ecb-be3f-610075556304` | Staging endpoint |
| URL | `hxxps://webhook[.]site/272f1315-14d7-458c-a4ca-e2df423490b4` | Staging endpoint |
| URL | `hxxps://webhook[.]site/1e72b758-79e4-4c1c-90ed-7a8dc118f105` | C2/staging endpoint |
| URL | `hxxps://webhook[.]site/34f908b6-dd89-4600-b413-a29cd5e37a0b` | Campaign endpoint |
| URL | `hxxps://webhook[.]site/36c9aecd-19f5-4564-a354-7708d947da8e` | Campaign endpoint |
| URL | `hxxps://webhook[.]site/4e6cf717-e4d6-4f40-9f2d-134196fa5e7d` | Campaign endpoint |
| URL | `hxxps://webhook[.]site/4e81a907-cc30-45c0-8bbd-5248e9f6dacd` | Campaign endpoint |

### Behavioral

- **Scheduled task creation** using `schtasks /create` with GUID-formatted task names launching `wscript.exe` against `.vbs` files in `%userprofile%`
- **Microsoft Edge launched in headless mode** (`--headless=new`) or hidden-window mode by scheduled task / batch script context (not interactive user session)
- **Outbound HTTP/HTTPS to webhook[.]site** from `msedge.exe`, `cmd.exe`, or `wscript.exe` processes
- **GUID-named files** with `.bat`, `.vbs`, `.cmd`, `.htm`, `.xhtml` extensions created in user profile root directory
- **Periodic cleanup** of `.75e`, `.tmp`, `.crdownload` files from `%userprofile%\Downloads\`
- **Beaconing interval anomaly:** 61-minute polling cadence (designed to exceed sandbox monitoring windows)
- **Auto-submitting HTML forms** used for data exfiltration (output wrapped between `.htm` header and `.xhtml` footer)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1583.006 | Web Services | Abuse of webhook[.]site as free C2, staging, and exfiltration infrastructure |
| T1566.001 | Spearphishing Attachment | Macro-enabled Word documents with diplomatic-themed lures sent via email |
| T1204.002 | Malicious File | User executes macro in Word document, triggering HOOKEDGE installation |
| T1059.003 | Windows Command Shell | HOOKEDGE is a batch script backdoor using cmd.exe for execution |
| T1059.005 | Visual Basic | VBScript launcher (.vbs) used to initiate backdoor execution |
| T1053.005 | Scheduled Task | Persistence via schtasks with 30-61 minute intervals |
| T1027.013 | Encrypted/Encoded File | Base64 encoding scheme shared with HEADLACE |
| T1070.004 | File Deletion | Self-deletion of installer, per-cycle cleanup of temporary files |
| T1140 | Deobfuscate/Decode Files | Runtime decoding of staged payloads |
| T1083 | File and Directory Discovery | Reconnaissance of target filesystem |
| T1074.001 | Local Data Staging | Command output staged in HTML files before exfiltration |
| T1071.001 | Web Protocols | HTTP/HTTPS used for all C2 communication via webhook[.]site |
| T1105 | Ingress Tool Transfer | Second-stage payloads and .cmd commands downloaded from webhook |
| T1041 | Exfiltration Over C2 Channel | Command output exfiltrated via HTTP POST to webhook endpoint |
| T1567.004 | Exfiltration Over Webhook | Data sent to webhook[.]site for collection |
| T1218 | System Binary Proxy Execution | msedge.exe used as a proxy for C2 communications |

## Impact Assessment

**Breadth:** The campaign targeted government, diplomatic, and defense manufacturing organizations across three NATO-member or NATO-aligned countries (Romania, Spain, Turkiye). Recorded Future identified 26 distinct malware samples and 32 webhook endpoints, suggesting a sustained, multi-target operation over approximately 7 months.

**Depth:** HOOKEDGE's tiered operational model -- with first-stage broad access and second-stage interactive tasking for high-value targets -- indicates a deliberate intelligence collection operation with victim triage. Second-stage implants with 5-minute beaconing enable real-time interactive access for deep network exploitation.

**Stealth:** The exclusive use of webhook[.]site for all C2 infrastructure means all malicious traffic targets a legitimate, widely-used developer service over standard HTTP/HTTPS ports. The use of msedge.exe as the HTTP client further blends malicious traffic with normal browsing. The 61-minute beaconing interval is specifically designed to evade sandbox analysis. Self-deleting installers and per-cycle file cleanup reduce forensic evidence.

**Strategic context:** Campaign timing aligned with Moldova's September 2025 parliamentary elections and broader European security dynamics, consistent with GRU intelligence collection priorities regarding NATO's eastern flank.

## Detection & Remediation

### Immediate Detection

**Check for active scheduled tasks with GUID names launching scripts:**
```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } | Format-Table TaskName, State, @{N='Actions';E={$_.Actions.Execute + ' ' + $_.Actions.Arguments}}
```

**Check for GUID-named script files in user profile:**
```powershell
Get-ChildItem "$env:USERPROFILE" -Filter "????????-????-????-????-????????????.*" | Where-Object { $_.Extension -in '.bat','.vbs','.cmd','.htm','.xhtml' }
```

**Check for webhook.site in proxy/DNS logs:**
```
# Splunk
index=proxy OR index=dns dest="webhook.site" OR query="webhook.site"
| stats count by src_ip, dest, uri_path
```

**Check for headless Edge execution:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object { $_.Properties[4].Value -like '*msedge.exe*' -and $_.Properties[10].Value -like '*--headless*' }
```

### Remediation

1. **Containment:** Isolate affected endpoints from the network immediately. Block outbound traffic to `webhook.site` at the network perimeter (firewall, proxy, DNS sinkhole).
2. **Scheduled task removal:** Remove any scheduled tasks matching the GUID-naming convention identified above. Terminate any running `wscript.exe` or `cmd.exe` processes associated with HOOKEDGE scripts.
3. **File cleanup:** Remove all GUID-named `.bat`, `.vbs`, `.cmd`, `.htm`, `.xhtml` files from `%userprofile%`. Remove `.75e`, `.crdownload` files from `%userprofile%\Downloads\`.
4. **Credential rotation:** Rotate credentials for all accounts on affected systems, particularly any accounts with access to diplomatic, defense, or classified materials.
5. **Email quarantine:** Quarantine and remove macro-enabled Word documents matching the diplomatic-themed lure patterns from email systems and endpoints.
6. **Forensic triage:** Collect and preserve scheduled task logs, Sysmon logs, proxy logs, and browser history from affected endpoints for timeline reconstruction.

### Long-Term Hardening

1. **Disable Office macros** for documents downloaded from the internet (Attack Surface Reduction rules or Group Policy). Implement a macro trust model that only allows signed macros from trusted publishers.
2. **Block or monitor webhook services:** Evaluate whether webhook[.]site, mocky[.]io, and similar services have legitimate business use. If not, block at the proxy/firewall. If yes, monitor and alert on access patterns.
3. **Application control:** Restrict or monitor `msedge.exe` execution with `--headless` flags, particularly when launched from non-interactive contexts (scheduled tasks, scripts).
4. **Scheduled task monitoring:** Implement monitoring for scheduled task creation in user-writable directories, particularly those launching script interpreters (wscript.exe, cscript.exe, cmd.exe).
5. **Network segmentation:** Restrict outbound internet access from sensitive diplomatic/defense workstations to approved destinations only.

## Detection Rules

These rules target the specific HOOKEDGE tradecraft documented by Recorded Future Insikt Group: headless Edge for C2, webhook[.]site abuse, GUID-named persistence artifacts, and canary tracking callbacks. Organizations using webhook[.]site for legitimate development should tune or whitelist known-good source IPs before deploying the network-layer rules.

### Sigma Rules

Detects msedge.exe launched with headless mode flags outside of browser update contexts, a key HOOKEDGE C2 communication technique.
**compile: pass (Splunk + LogScale) | confidence: high**

```yaml
title: Microsoft Edge Headless Mode Launched From Scheduled Task Context
id: 26f3641c-cf28-4795-8e80-b4e399f21f1c
status: experimental
description: >
    Detects Microsoft Edge (msedge.exe) launched with headless mode flags,
    particularly when the parent process is consistent with scheduled task
    execution. HOOKEDGE backdoor uses Edge in headless mode for C2
    communication and data exfiltration via webhook.site endpoints.
references:
    - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
    - https://securityaffairs.com/197996/apt/russian-apt-bluedelta-uses-hookedge-to-target-defense-and-diplomatic-organizations.html
author: Actioner
date: 2026-08-30
tags:
    - attack.t1218
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_edge:
        Image|endswith: '\msedge.exe'
    selection_headless:
        CommandLine|contains:
            - '--headless'
            - '--headless=new'
    filter_browser_updates:
        ParentImage|endswith:
            - '\MicrosoftEdgeUpdate.exe'
            - '\setup.exe'
    condition: selection_edge and selection_headless and not filter_browser_updates
falsepositives:
    - Automated browser testing pipelines using Edge in headless mode
    - Web scraping or PDF rendering tools using Edge headless
    - Legitimate developer tooling invoking headless Edge
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk → Image="*\\msedge.exe" CommandLine IN ("*--headless*", "*--headless=new*") NOT (...); sigma convert --without-pipeline -t log_scale → pass. sigma check skipped (MITRE ATT&CK data fetch blocked by proxy; does not affect rule validity). No defanged values in detection fields. -->

---

Detects network connections from cmd.exe, msedge.exe, or wscript.exe to webhook[.]site, covering the HOOKEDGE C2 tasking and exfiltration channels.
**compile: pass (Splunk + LogScale) | confidence: high**

```yaml
title: Batch Script C2 Beaconing to Webhook.site
id: e5064949-1870-47b7-8f0f-133de9ab37fe
status: experimental
description: >
    Detects network connections from cmd.exe or msedge.exe to webhook.site,
    a free developer testing service abused by BlueDelta (APT28) HOOKEDGE
    backdoor for command-and-control tasking and data exfiltration.
references:
    - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
    - https://securityaffairs.com/197996/apt/russian-apt-bluedelta-uses-hookedge-to-target-defense-and-diplomatic-organizations.html
author: Actioner
date: 2026-08-30
tags:
    - attack.t1071.001
    - attack.t1567.004
logsource:
    category: network_connection
    product: windows
detection:
    selection_dest:
        DestinationHostname|endswith: '.webhook.site'
    selection_process:
        Image|endswith:
            - '\msedge.exe'
            - '\cmd.exe'
            - '\wscript.exe'
    condition: selection_dest and selection_process
falsepositives:
    - Developers testing webhook integrations from command-line tools
    - Automated CI/CD pipelines using webhook.site for testing
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk → DestinationHostname="*.webhook.site" Image IN ("*\\msedge.exe", "*\\cmd.exe", "*\\wscript.exe"); LogScale → pass. DestinationHostname uses real (not defanged) domain. Requires Sysmon EID 3. -->

---

Detects schtasks.exe creating tasks that execute VBS or batch scripts from user profile directories, matching HOOKEDGE persistence mechanism.
**compile: pass (Splunk + LogScale) | confidence: high**

```yaml
title: Scheduled Task Creating Scripts in User Profile Directory
id: 1d6c8cbe-9a01-42ab-8104-29cbf62b3637
status: experimental
description: >
    Detects creation of scheduled tasks that execute VBS or batch scripts
    from the user profile directory. HOOKEDGE backdoor creates a scheduled
    task to execute a VBS launcher from %userprofile% with 30-61 minute
    intervals for persistent C2 beaconing.
references:
    - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
    - https://securityaffairs.com/197996/apt/russian-apt-bluedelta-uses-hookedge-to-target-defense-and-diplomatic-organizations.html
author: Actioner
date: 2026-08-30
tags:
    - attack.t1053.005
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    selection_user_path:
        CommandLine|contains:
            - '\Users\'
            - '%userprofile%'
    selection_script:
        CommandLine|contains:
            - '.vbs'
            - '.bat'
            - '.cmd'
            - 'wscript'
    condition: selection_schtasks and selection_user_path and selection_script
falsepositives:
    - Legitimate software installers creating scheduled tasks in user directories
    - User-created automation scripts with scheduled execution
level: high
```

<!-- audit: sigma convert --without-pipeline -t splunk → Image="*\\schtasks.exe" CommandLine="*/create*" CommandLine IN ("*\\Users\\*", "*%userprofile%*") CommandLine IN ("*.vbs*", "*.bat*", "*.cmd*", "*wscript*"); LogScale → pass. -->

---

Detects GUID-named files with script/HTML extensions created in user profile root, matching HOOKEDGE's file-drop naming convention.
**compile: pass (Splunk + LogScale) | confidence: medium**

```yaml
title: HOOKEDGE GUID-Named File Creation in User Profile
id: 60801bf4-912f-43ec-8b1e-19bc0a1d1b4b
status: experimental
description: >
    Detects creation of files with GUID-formatted names and suspicious
    extensions (.bat, .vbs, .cmd, .htm, .xhtml) in the user profile
    directory. HOOKEDGE backdoor drops six files using GUID names matching
    webhook endpoint UUIDs with extensions such as .bat, .vbs, .cmd, .htm,
    and .xhtml.
references:
    - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
author: Actioner
date: 2026-08-30
tags:
    - attack.t1059.003
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|re: '\\Users\\[^\\]+\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(bat|vbs|cmd|htm|xhtml)$'
    condition: selection_path
falsepositives:
    - Software using GUID-named temporary files in user directories
    - Development tools generating UUID-named artifacts
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk → uses regex; LogScale → pass. Regex-based rule; confirm Sysmon EID 11 coverage. Medium confidence due to potential legitimate GUID-named temp files. -->

---

Detects DNS resolution of webhook[.]site, a legitimate developer service abused as C2 by HOOKEDGE and HEADLACE backdoors.
**compile: pass (Splunk + LogScale) | confidence: medium**

```yaml
title: DNS Query or Proxy Connection to Webhook.site
id: 8a232792-f8e0-4397-a067-eeb4c0d9c723
status: experimental
description: >
    Detects DNS resolution or proxy traffic to webhook.site, a legitimate
    developer service abused by BlueDelta HOOKEDGE and HEADLACE backdoors
    for C2 communication. While webhook.site has legitimate uses, its
    presence in enterprise environments should be investigated.
references:
    - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
author: Actioner
date: 2026-08-30
tags:
    - attack.t1071.001
    - attack.t1583.006
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'webhook.site'
    condition: selection
falsepositives:
    - Developers using webhook.site for API testing
    - Webhook testing during software development
level: medium
```

<!-- audit: sigma convert --without-pipeline -t splunk → QueryName="*webhook.site"; LogScale → pass. Broad rule; medium confidence due to legitimate developer use. Best deployed with process-correlation for Edge/cmd.exe or with IP/user allowlists. -->

### Suricata Rules

Detects HTTP requests to webhook[.]site with UUID path patterns matching HOOKEDGE C2 beaconing structure.
**compile: pass (suricata -T) | confidence: high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HOOKEDGE C2 Beacon to webhook.site"; flow:established,to_server; http.host; content:"webhook.site"; fast_pattern; http.uri; pcre:"/^\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"; classtype:trojan-activity; reference:url,www.recordedfuture.com/research/bluedelta-targets-with-hookedge; metadata:author Actioner, created_at 2026-08-30, mitre_attack T1071.001; sid:2100100; rev:1;)
```

<!-- audit: suricata -T -S → "Configuration provided was successfully loaded. Exiting." exit 0. Uses http.host (dot-notation), http.uri with pcre for UUID path matching. Real domain in content match. -->

---

Detects HTTP requests to webhook[.]site fetching canary tracking images (docopened.jpg, mailopened.jpg, doc.jpg) used by HOOKEDGE for delivery confirmation.
**compile: pass (suricata -T) | confidence: high**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HOOKEDGE Canary Tracking Image Request via webhook.site"; flow:established,to_server; http.host; content:"webhook.site"; http.uri; content:"/"; startswith; pcre:"/\/(docopened|mailopened|doc)\.jpg$/"; classtype:trojan-activity; reference:url,www.recordedfuture.com/research/bluedelta-targets-with-hookedge; metadata:author Actioner, created_at 2026-08-30, mitre_attack T1071.001; sid:2100101; rev:1;)
```

<!-- audit: suricata -T -S → "Configuration provided was successfully loaded. Exiting." exit 0. Targets specific canary filenames from Recorded Future report. High confidence for this campaign; canary names may change in future variants. -->

---

Detects DNS queries resolving webhook[.]site, used as the exclusive C2 infrastructure for HOOKEDGE.
**compile: pass (suricata -T) | confidence: medium**

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to webhook.site (Potential HOOKEDGE C2)"; flow:to_server; dns.query; content:"webhook.site"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.recordedfuture.com/research/bluedelta-targets-with-hookedge; metadata:author Actioner, created_at 2026-08-30, mitre_attack T1071.001; sid:2100102; rev:1;)
```

<!-- audit: suricata -T -S → "Configuration provided was successfully loaded. Exiting." exit 0. Broad DNS detection; medium confidence due to legitimate use of webhook.site. Deploy with src_ip allowlists for developer workstations. -->

### Snort Rules

Equivalent Snort 3 rules for the same network indicators. Note: these use underscore-notation (`http_uri`) per Snort 3 conventions.
**compile: N/A (snort not installed) | confidence: medium**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HOOKEDGE C2 Beacon to webhook.site"; flow:established,to_server; http_header; content:"Host|3a 20|webhook.site"; fast_pattern; http_uri; pcre:"/^\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"; classtype:trojan-activity; reference:url,www.recordedfuture.com/research/bluedelta-targets-with-hookedge; metadata:author Actioner, created_at 2026-08-30; sid:1100100; rev:1;)
```

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HOOKEDGE Canary Tracking Image via webhook.site"; flow:established,to_server; http_header; content:"Host|3a 20|webhook.site"; http_uri; pcre:"/\/(docopened|mailopened|doc)\.jpg$/"; classtype:trojan-activity; reference:url,www.recordedfuture.com/research/bluedelta-targets-with-hookedge; metadata:author Actioner, created_at 2026-08-30; sid:1100101; rev:1;)
```

<!-- audit: snort not installed; structural check only. Uses http_header (underscore), http_uri per Snort 3. Hex |3a 20| encodes ": " in Host header. SIDs in 1100000 range to avoid Suricata collision. -->

### YARA Rule

File-level detection for HOOKEDGE batch script artifacts based on webhook[.]site references, msedge.exe usage, canary filenames, and GUID-extension artifacts.
**compile: pass (yarac) | confidence: medium**

```yara
rule HOOKEDGE_Batch_Backdoor
{
    meta:
        description = "Detects HOOKEDGE batch script backdoor used by BlueDelta (APT28) for C2 via webhook.site"
        author = "Actioner"
        date = "2026-08-30"
        reference = "https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge"
        hash1 = "001b57368c10bee9e62374e3b3f232b113eb75a1f198243d43a5bb90e1d0f500"
        hash2 = "c2c9187033d22d7944ea9298461a0ac693ef2774b4ce08b0955d2aba3646fb44"

    strings:
        $webhook = "webhook.site" ascii wide nocase
        $edge1 = "msedge.exe" ascii wide nocase
        $edge2 = "--headless" ascii wide
        $schtasks = "schtasks" ascii wide nocase
        $canary1 = "docopened.jpg" ascii wide
        $canary2 = "mailopened.jpg" ascii wide
        $canary3 = "doc.jpg" ascii wide
        $ext1 = ".75e" ascii wide
        $ext2 = ".xhtml" ascii wide
        $ext3 = ".crdownload" ascii wide
        $bat_loop = "goto" ascii wide nocase
        $bat_del = "del " ascii wide nocase

    condition:
        filesize < 100KB and
        (
            ($webhook and $edge1 and ($schtasks or $bat_loop)) or
            ($webhook and 2 of ($canary1, $canary2, $canary3)) or
            ($webhook and $edge2 and $bat_del and $ext1) or
            (3 of ($ext1, $ext2, $ext3) and $webhook and $bat_loop)
        )
}
```

<!-- audit: yarac → exit 0, compiled successfully. Condition requires webhook.site plus behavioral indicators to reduce FP. filesize < 100KB scopes to batch scripts and small artifacts; will not match large binaries. Medium confidence because batch script content may vary across variants; rule based on reported behavioral patterns, not verbatim code. -->

## Lessons Learned

1. **Legitimate infrastructure abuse is the new normal.** HOOKEDGE's exclusive use of webhook[.]site for all C2 operations -- with no dedicated attacker infrastructure -- demonstrates that state-sponsored threat actors are fully embracing "living off legitimate services" to evade network detection. Organizations must develop monitoring and governance strategies for free developer services (webhook[.]site, mocky[.]io, pastebin, etc.) that may never have appeared on a threat intelligence blocklist before being abused.

2. **Batch scripting remains a viable backdoor platform.** Despite its simplicity, a Windows batch script combined with a legitimate browser binary (msedge.exe) and a legitimate web service (webhook[.]site) creates a remarkably stealthy and functional backdoor. The minimal footprint, lack of compiled binaries, and use of native OS tools make traditional file-based detection difficult.

3. **Sandbox evasion through timing is trivially effective.** The single-minute adjustment from 60 to 61 minutes in the beaconing interval defeats many automated sandbox environments that use a standard 60-minute monitoring window. This highlights the need for extended detonation times and behavioral analysis that spans multiple hours.

4. **Free-tier API limits create observable operational constraints.** The 100-request cap per webhook endpoint forced BlueDelta to use multiple endpoints and adopt a tiered victim triage model. This constraint creates detection opportunities: monitoring for organizations resolving or connecting to multiple distinct webhook[.]site UUID endpoints may indicate HOOKEDGE infrastructure enumeration.

5. **Macro-enabled documents remain effective for targeted campaigns.** Despite years of hardening guidance, macro-enabled documents with compelling diplomatic lures continue to achieve initial access against government and diplomatic targets. Organizations handling sensitive diplomatic communications must enforce macro-disabled policies with no exceptions.

## Sources

- [Recorded Future Insikt Group - BlueDelta Targets Defense and Diplomacy with HOOKEDGE](https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge) — Primary technical analysis; identified 26 samples, 32 webhook endpoints, full attack chain, MITRE mapping, and code overlap with HEADLACE
- [Security Affairs - Russian APT BlueDelta Uses HOOKEDGE to Target Defense and Diplomatic Organizations](https://securityaffairs.com/197996/apt/russian-apt-bluedelta-uses-hookedge-to-target-defense-and-diplomatic-organizations.html) — News coverage with campaign summary and key technical details
- [The Hacker News - APT28-Linked HOOKEDGE Backdoor Targets European Government and Diplomatic Organizations](https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html) — News coverage with additional context on HEADLACE evolution
- [GBHackers - BlueDelta Targets Defense and Diplomatic Organizations With HOOKEDGE Malware](https://gbhackers.com/hookedge-malware-campaign/) — Additional webhook endpoint IOCs and Edge exploitation details
- [CyberPress - APT28 HOOKEDGE Backdoor Abuses Microsoft Edge and webhook.site for C2 and Data Exfiltration](https://cyberpress.org/apt28-hookedge-exploits-edge-webhooks/) — Additional C2 endpoint IOCs

---
*Report generated by Actioner*
