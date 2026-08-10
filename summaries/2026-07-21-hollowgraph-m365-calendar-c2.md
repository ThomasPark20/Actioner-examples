# Technical Analysis Report: HollowGraph Malware -- M365 Calendar C2 (2026-07-21)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-21
Version: FINAL
<!-- revision: 2026-07-21 — applied critic verdicts: logAzure.txt Sigma level+confidence downgraded to medium; M365 Calendar Sigma title stripped "via Application" (no app-identity filter), narrowed 2050 match with calendar-context filter, flagged environment-specific; YARA sample label corrected to "untested (no public sample)"; graph.microsoft.com removed from IOC table (legitimate infrastructure — DO NOT BLOCK); defanging of graph.microsoft.com made consistent; M365 rule prose rewritten from pseudo-implemented to tuning recommendation. -->

## Executive Summary

HollowGraph is a .NET NativeAOT-compiled DLL attributed with high confidence to the **Cavern** (Cav3rn) command-and-control framework, an Iranian MOIS-linked modular backdoor platform tracked by Check Point Research as **Cavern Manticore**. Discovered by Group-IB, HollowGraph transforms a compromised Microsoft 365 mailbox calendar into a covert two-way C2 channel using the Microsoft Graph API. Commands and stolen files are hidden inside calendar event attachments dated to **May 13, 2050** -- a date so far in the future that the mailbox owner is unlikely to ever see them. The malware refreshes its authentication credentials via DNS tunneling through the attacker-controlled domain `cloudlanecdn[.]com`.

At least **12 systems** have been identified as infected, with approximately 3 actively communicating during the observation window of June 3 to July 9, 2026. All observed victims are **Israeli organizations**, consistent with a targeted espionage operation. This is not a vulnerability exploit -- it abuses legitimate Microsoft Graph API functionality via compromised OAuth client credentials, meaning no patch exists; detection and credential hygiene are the only mitigations.

## Background: Microsoft 365 Calendar via Graph API

Microsoft Graph API provides programmatic access to Microsoft 365 services including Outlook mail, calendar, and OneDrive. Applications authenticate using OAuth 2.0 client credentials (tenant ID, client ID, client secret) to access resources on behalf of users. Calendar events created via the Graph API endpoint `/users/{mailbox}/calendarView` or `/users/{mailbox}/calendar/events` can include file attachments, making them a viable covert data channel. Because all traffic flows to `graph.microsoft.com` over TLS, network-level inspection cannot distinguish malicious Graph API calls from legitimate Microsoft 365 application traffic without decryption.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Unknown | Initial compromise; attacker obtains Microsoft Entra ID application credentials for target M365 tenant |
| Unknown | HollowGraph .NET NativeAOT DLL deployed on at least 12 systems |
| 2026-06-03 | Earliest observed C2 communication between victim and attacker via compromised mailbox calendar |
| 2026-07-09 | Most recent observed C2 communication |
| 2026-07-20 | Group-IB publishes technical analysis; Check Point publishes Cavern Manticore framework research |

## Root Cause: Compromised Microsoft Entra ID Application Credentials

The initial access vector for HollowGraph is not fully documented in public reporting. The malware operates using **hardcoded Microsoft Entra ID application credentials** stored in a local configuration file (`logAzure.txt`). These credentials -- tenant ID, client ID, client secret, and target mailbox address -- grant the malware application-level access to a compromised M365 mailbox calendar via the Microsoft Graph API. The compromise likely originated through credential theft, phishing, or supply-chain compromise of an IT service provider, consistent with Cavern Manticore's known operational pattern of targeting IT providers and then pivoting to secondary victims.

## Technical Analysis of the Malicious Payload

### 1. Malware Architecture

HollowGraph is a **.NET NativeAOT-compiled DLL**. The NativeAOT compilation format produces a native binary from .NET code, stripping managed metadata and making reverse engineering significantly more difficult -- a technique shared with other Cavern framework components (e.g., `n-HTCommp.dll`, `n-ten.dll`). The malware supports only **two commands**: `get` (retrieve operator instructions) and `send` (exfiltrate stolen data), both executed exclusively through Microsoft Graph API calls to the compromised calendar.

### 2. Configuration and Credential Management

On startup, HollowGraph reads its configuration from a local file named `logAzure.txt`, which stores:

- Microsoft Entra ID **tenant ID**
- Application **(client) ID**
- **Client secret**
- **Target mailbox address**
- **C2 domain** (for DNS tunneling credential refresh)
- **Two RSA public keys** (separate keys for inbound tasking and outbound exfiltration)

This configuration file is periodically refreshed via a DNS tunneling channel.

### 3. C2 Infrastructure

#### Primary Channel: Microsoft 365 Calendar Dead Drop

HollowGraph uses the compromised M365 mailbox calendar as a bidirectional dead-drop C2 channel:

**GET (receive tasking):**
- Queries the Microsoft Graph API `calendarView` endpoint: `GET /users/{mailbox}/calendarView`
- Restricts search to a fixed time window: **2050-05-13, 22:00--23:00 UTC**
- Filters by subject line containing `Event ID: ` followed by a 7-character task identifier
- Downloads and decrypts attached instruction files

**SEND (exfiltrate data):**
- Creates new calendar events with subject pattern `Boss{..}ID{..}`
- Encrypts stolen files and uploads them as attachments named `File{n}.txt` (e.g., `File1.txt`, `File2.txt`)
- Uses Graph API endpoints:
  - `POST /users/{mailbox}/calendar/events` (create event)
  - `POST /users/{mailbox}/events/{event-id}/attachments` (upload attachment)
  - `PATCH /users/{mailbox}/events/{event-id}` (update event)

#### Secondary Channel: DNS Tunneling for Credential Refresh

HollowGraph uses DNS tunneling via the attacker-controlled domain `cloudlanecdn[.]com` to periodically obtain fresh Microsoft Entra ID credentials:

- Queries **IPv6 AAAA records** against subdomains `*.p.cloudlanecdn[.]com` (length queries) and `*.q.cloudlanecdn[.]com` (data queries)
- Each returned IPv6 address (16 bytes) yields **14 usable payload bytes**
- First two bytes of a length query encode the expected data size
- Subsequent data queries deliver 14-byte payloads that are reassembled and decoded as UTF-8 text
- Reassembled credentials are written to `logAzure.txt`

### 4. Encryption

All data moving through the calendar channel is protected with **hybrid RSA + AES-256-GCM encryption**:

- **RSA-OAEP-SHA256** for key wrapping
- **AES-256-GCM** for symmetric data encryption
- **Separate key pairs** for each communication direction: one for incoming tasking (operator-to-implant) and one for outgoing exfiltration (implant-to-operator)
- This dual-key design ensures that compromise of one direction's key material does not expose the other

### 5. Anti-Forensics / Evasion Techniques

- **Legitimate infrastructure abuse:** All C2 traffic flows to `graph.microsoft.com` over TLS, blending with normal M365 application traffic
- **Far-future calendar events:** Events dated 2050-05-13 are effectively invisible to the mailbox owner who would never scroll to that date
- **NativeAOT compilation:** Strips .NET metadata, complicating static analysis and decompilation
- **DNS tunneling for credential refresh:** Avoids embedding long-lived credentials; allows the operator to rotate Graph API access without redeploying the malware
- **No direct attacker infrastructure connection:** The malware never contacts attacker-owned servers directly (except for DNS tunneling), making network-based blocking extremely difficult

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `logAzure.txt` (working directory) | N/A | Configuration file storing Entra ID credentials, RSA keys, C2 domain |
| Windows | `File{n}.txt` | N/A | Naming pattern for exfiltrated file attachments (File1.txt, File2.txt, etc.) |

**Related Cavern framework hashes** (from Check Point Research):

| Hash (SHA256) | Component |
|---------------|-----------|
| `37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066` | Cavern Agent build 02 (uxtheme.dll) |
| `a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41` | Cavern HTTP communication module (n-HTCommp.dll) |
| `541b1f417b9e42078c3355693a8a492b6a76048850f6549a429e0be99e6819cb` | Older Cav3rn agent |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `cloudlanecdn[.]com` | DNS tunneling for Entra ID credential refresh |
| Subdomain pattern | `*.p.cloudlanecdn[.]com` | DNS tunnel length queries |
| Subdomain pattern | `*.q.cloudlanecdn[.]com` | DNS tunnel data queries |
| Domain | `hospitalinstallation[.]com` | Cavern framework C2 (Check Point) |
| Domain | `auth[.]hospitalinstallation[.]com` | Cavern framework C2 subdomain |
| Domain | `google[.]com[.]hospitalinstallation[.]com` | Cavern framework C2 subdomain (newer) |
| Domain | `adserviceupdate[.]com` | Legacy Cav3rn era C2 |
| Domain | `hygienehistory[.]com` | Legacy Cav3rn era C2 |

> **Note:** All HollowGraph C2 traffic transits `graph.microsoft.com` (the legitimate Microsoft Graph API endpoint). This domain is **NOT an IOC** and must **NOT** be added to blocklists -- doing so would disable Microsoft 365 for the organization. Detection must focus on audit-log-level inspection of application-driven calendar operations, not network-level domain blocking.

### Behavioral

- Calendar events created with dates in year **2050** (specifically 2050-05-13) via application credentials rather than interactive user
- Calendar event subjects matching patterns `Event ID: <7-char-ID>` (tasking) and `Boss{..}ID{..}` (exfiltration)
- Calendar event attachments named `File{n}.txt`
- High-volume AAAA DNS queries to subdomains of `cloudlanecdn[.]com`
- Cavern framework command delimiter syntax: `_;;_` (field separator) and `_,_` (argument separator)
- Debug toggle command: `MzU=` (Base64 decodes to `003`)
- Example tasking JSON: `{"cid": "oXhLaJ0ZvtPb9XB", "type": "self", "cmd": "003_;;__,__,_"}`
- Mutex names (Cavern framework): `MYMUTEX123HELLP`, `MYMUTEX123HELLP02`, `MYMUTEX123HELLP04`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1102.002 | Web Service: Bidirectional Communication | Calendar events used as bidirectional dead drop for tasking and exfiltration via Graph API |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Stolen files uploaded as calendar event attachments via Graph API |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS communication to graph.microsoft.com for all C2 operations |
| T1071.004 | Application Layer Protocol: DNS | DNS tunneling via AAAA records to cloudlanecdn.com for credential refresh |
| T1059.009 | Command and Scripting Interpreter: Cloud API | Direct use of Microsoft Graph API for command execution |
| T1078.004 | Valid Accounts: Cloud Accounts | Compromised Microsoft Entra ID application credentials for Graph API authentication |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Hybrid RSA-OAEP-SHA256 + AES-256-GCM with separate key pairs per direction |
| T1132.001 | Data Encoding: Standard Encoding | Base64 encoding of commands; UTF-8 reassembly of DNS tunnel payloads |
| T1564 | Hide Artifacts | Far-future calendar events (2050) to hide C2 artifacts from user view |
| T1001.003 | Data Obfuscation: Protocol Impersonation | Graph API traffic indistinguishable from legitimate M365 app traffic |

## Impact Assessment

- **Breadth:** At least 12 systems infected across Israeli organizations; limited but high-value target set
- **Depth:** Full bidirectional C2 capability enabling file exfiltration; espionage-grade encryption
- **Stealth:** Extremely high -- all C2 traffic flows through legitimate Microsoft infrastructure; no attacker-owned server connections except DNS tunneling; far-future calendar dates hide artifacts from users
- **Attribution:** High-confidence link to Cavern framework (Iranian MOIS-linked Cavern Manticore actor); low-confidence overlap with Lyceum/OilRig subgroup
- **Ongoing risk:** The technique requires no vulnerability exploitation -- only compromised credentials. Similar attacks can be launched against any organization with M365 tenants

## Detection & Remediation

### Immediate Detection

```powershell
# Search for logAzure.txt configuration file on Windows endpoints
Get-ChildItem -Path C:\ -Filter "logAzure.txt" -Recurse -ErrorAction SilentlyContinue

# Check DNS logs for cloudlanecdn.com queries
Get-DnsClientCache | Where-Object { $_.Entry -like "*cloudlanecdn*" }
```

```kql
# Microsoft 365 Unified Audit Log: search for application-driven calendar events with far-future dates
OfficeActivity
| where Operation in ("Create", "Update")
| where OfficeObjectId contains "calendar"
| where TimeGenerated > ago(30d)
| extend EventBody = tostring(parse_json(AuditData))
| where EventBody contains "2050"
```

```kql
# Microsoft Graph Activity Log: search for suspicious calendarView queries
MicrosoftGraphActivityLogs
| where RequestUri contains "calendarView"
| where RequestUri contains "2050"
| where ServicePrincipalId != ""
```

### Remediation

1. **Immediate:** Revoke all client secrets and certificates for the compromised Entra ID application registration; disable the application if no longer needed
2. **Containment:** Block DNS resolution of `cloudlanecdn[.]com` and all subdomains at the DNS resolver level
3. **Forensic review:** Audit the compromised mailbox calendar for events dated 2050 or other far-future dates; recover and decrypt attachments for damage assessment
4. **Credential rotation:** Rotate all Entra ID application credentials in the affected tenant; audit all application registrations for unauthorized grants
5. **Host remediation:** Identify and remove the HollowGraph DLL and `logAzure.txt` from all 12+ affected endpoints; reimage if full compromise is suspected

### Long-Term Hardening

- **Audit M365 application permissions:** Review all Entra ID application registrations with `Calendars.ReadWrite` or `Mail.ReadWrite` permissions; remove those that are unnecessary
- **Monitor Graph Activity Logs:** Enable Microsoft Graph Activity Logs and alert on application-driven calendar operations (events created, attachments uploaded, or subjects modified by an app identity rather than a user)
- **Conditional Access policies:** Restrict application access to M365 resources by IP range and require compliance policies
- **DNS monitoring:** Deploy DNS logging and alerting for high-volume AAAA queries to unusual domains, particularly those exhibiting tunneling patterns (high subdomain entropy, high query volume)
- **Application consent workflow:** Require admin consent for all new application registrations to prevent unauthorized OAuth grants

## Detection Rules

These detections target the HollowGraph campaign's distinctive IOCs: DNS tunneling domain, configuration file artifact, M365 calendar abuse pattern, and malware file-level strings. All Sigma rules convert to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your environment's telemetry pipeline.

### Sigma: DNS Query to HollowGraph C2 Domain

Detects DNS queries to `cloudlanecdn[.]com` or subdomains, used by HollowGraph for credential-refresh DNS tunneling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK fetch 403); splunk 0, log_scale 0, crowdstrike_falcon pipeline 0. IOC-anchored, single attacker domain — minimal FP surface. -->
```yaml
title: DNS Query to HollowGraph C2 Domain cloudlanecdn.com
id: 7a3e9b1c-4d2f-48e6-a5c7-9f0b8e2d1a3c
status: experimental
description: >
    Detects DNS queries to cloudlanecdn.com or its subdomains, used by the
    HollowGraph malware for DNS tunneling to refresh Microsoft Entra ID
    credentials. Subdomain patterns .p. and .q. are used for length and
    data queries respectively.
references:
    - https://www.group-ib.com/blog/hollowgraph-microsoft-365/
    - https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html
author: Actioner
date: 2026/07/21
tags:
    - attack.t1071.004
    - attack.t1132.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: '.cloudlanecdn.com'
    selection_exact:
        QueryName: 'cloudlanecdn.com'
    condition: selection or selection_exact
falsepositives:
    - Legitimate use of cloudlanecdn.com domain (unlikely - attacker-controlled)
level: high
```

### Sigma: HollowGraph Configuration File Creation

Detects creation of `logAzure.txt`, the on-disk config file storing compromised Entra ID credentials for Graph API authentication. Filename is not unique -- false positives from custom Azure logging scripts are acknowledged.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk 0, log_scale 0, splunk_windows pipeline 0. Filename is distinctive but not unique — FP possible from custom Azure logging scripts; confidence downgraded from high to medium per critic review. Best used as a supporting indicator alongside DNS or calendar detections. -->
```yaml
title: HollowGraph Configuration File logAzure.txt Creation
id: 2b5f8c4a-1e7d-49a3-b6f0-3c8d9e5a2f1b
status: experimental
description: >
    Detects the creation of logAzure.txt, the on-disk configuration file
    used by HollowGraph malware to store Microsoft Entra ID credentials
    (tenant ID, client ID, client secret) and RSA keys for Graph API
    authentication.
references:
    - https://www.group-ib.com/blog/hollowgraph-microsoft-365/
    - https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html
author: Actioner
date: 2026/07/21
tags:
    - attack.t1059.009
    - attack.t1078.004
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\logAzure.txt'
    condition: selection
falsepositives:
    - Custom Azure logging scripts that write to a file named logAzure.txt
level: medium
```

### Sigma: Suspicious M365 Calendar Event with Far-Future Date

Detects calendar event creation or modification in M365 audit logs where the item references the year 2050 alongside calendar-specific context, consistent with HollowGraph dead-drop C2. **Environment-specific:** requires M365 Unified Audit Log ingestion with `Operation` and `Item` fields; CrowdStrike Falcon does not ingest M365 audit logs in this schema natively. **Tuning recommendation:** if your pipeline exposes the actor identity type (e.g., `UserType` = `Application`), add that as a filter to scope to application-identity operations and reduce noise.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk 0, log_scale 0. M365 logsource (product: m365, service: exchange) is environment-specific; CrowdStrike does not ingest M365 audit logs in this schema. Confidence medium because 2050 substring match can hit room numbers, ticket numbers, or other numeric data — narrowed with calendar-context filter. Application-identity filter not implemented because field availability varies across ingestion pipelines; documented as tuning recommendation. -->
```yaml
title: Suspicious M365 Calendar Event with Far-Future Date
id: 9c4d1e6f-3b8a-42e5-a7f9-5d0c2b1e8a4f
status: experimental
description: >
    Detects calendar event creation or modification in Microsoft 365 audit
    logs where the item references the year 2050 alongside calendar context,
    consistent with HollowGraph malware using calendar events as a covert C2
    dead drop. The malware schedules events on 2050-05-13 between 22:00-23:00
    UTC. Tuning: add application-identity filter (e.g., UserType = Application)
    if your audit log pipeline exposes actor type.
references:
    - https://www.group-ib.com/blog/hollowgraph-microsoft-365/
    - https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html
author: Actioner
date: 2026/07/21
tags:
    - attack.t1102.002
    - attack.t1567.002
logsource:
    product: m365
    service: exchange
detection:
    selection_operation:
        Operation:
            - 'Create'
            - 'Update'
    selection_calendar:
        Item|contains:
            - 'calendar'
            - 'Calendar'
    selection_year:
        Item|contains: '2050'
    condition: selection_operation and selection_calendar and selection_year
falsepositives:
    - Legitimate calendar events intentionally scheduled for the year 2050
    - Calendar items containing the number 2050 in non-date context (room numbers, ticket IDs)
level: medium
```

### Snort: DNS Query to HollowGraph C2 Domain

Detects DNS wire-format queries for `cloudlanecdn[.]com`, the attacker-controlled domain used for credential-refresh DNS tunneling.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T 0 (via local.rules include). DNS label-length encoding: |0c| = 12 bytes ("cloudlanecdn"), |03| = 3 bytes ("com"), |00| = root. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to HollowGraph C2 Domain cloudlanecdn.com"; content:"|0c|cloudlanecdn|03|com|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/hollowgraph-microsoft-365/; sid:2100001; rev:1;)
```

### Suricata: DNS Query to HollowGraph C2 Domain

Detects DNS queries resolving `cloudlanecdn[.]com`, the attacker domain used by HollowGraph for DNS tunneling credential refresh.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S 0. Uses dns.query sticky buffer with content match on domain. Catches all subdomains including .p. and .q. tunneling patterns. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to HollowGraph C2 Domain cloudlanecdn.com"; dns.query; content:"cloudlanecdn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.group-ib.com/blog/hollowgraph-microsoft-365/; metadata:author Actioner, created_at 2026-07-21; sid:2200001; rev:1;)
```

### Suricata: DNS Tunneling to HollowGraph Credential Refresh Subdomain

Detects DNS queries to the `.p.` or `.q.` tunneling subdomains of `cloudlanecdn[.]com`, specifically targeting the credential-refresh protocol.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S 0. pcre matches .p. or .q. subdomain component within dns.query buffer, combined with cloudlanecdn.com content anchor. More specific than SID 2200001 — identifies active tunneling vs. general domain resolution. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Tunneling to HollowGraph Credential Refresh Subdomain"; dns.query; content:".cloudlanecdn.com"; nocase; fast_pattern; pcre:"/\.(p|q)\./i"; classtype:trojan-activity; reference:url,www.group-ib.com/blog/hollowgraph-microsoft-365/; metadata:author Actioner, created_at 2026-07-21; sid:2200002; rev:1;)
```

### YARA: HollowGraph Cavern DLL

Detects HollowGraph malware DLL via characteristic strings from the Cavern framework C2 component: configuration filename, Graph API endpoint patterns, calendar event subject patterns, and Cavern command delimiters.
**Status:** compile ✅ compiles · confidence: high · sample: untested (no public sample)
<!-- audit: yarac 0; no real HollowGraph binary was available for testing — sample label corrected from "fired" to "untested". NativeAOT may strip some strings — condition requires logAzure.txt (anchor) plus 2-of combinations for resilience. Strings sourced from Group-IB and BleepingComputer reporting. -->
```yara
rule Malware_HollowGraph_Cavern_DLL
{
    meta:
        description = "Detects HollowGraph malware DLL via characteristic strings from the Cavern framework C2 component that abuses Microsoft 365 calendar events"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.group-ib.com/blog/hollowgraph-microsoft-365/"
        severity = "high"

    strings:
        $cfg = "logAzure.txt" ascii wide
        $api1 = "calendarView" ascii wide
        $api2 = "/calendar/events" ascii wide
        $subj1 = "Event ID: " ascii wide
        $subj2 = "Boss" ascii wide
        $attach = "File1.txt" ascii wide
        $delim1 = "_;;_" ascii wide
        $delim2 = "_,_" ascii wide
        $debug = "MzU=" ascii wide
        $dns = "cloudlanecdn" ascii wide

    condition:
        filesize < 10MB and
        $cfg and
        (2 of ($api*,$subj*,$attach) or
         2 of ($delim*,$debug) or
         ($dns and 1 of ($api*)))
}
```

## Lessons Learned

1. **Legitimate cloud services as C2 infrastructure are extremely difficult to block.** HollowGraph's use of Microsoft Graph API means that blocking the C2 channel would require blocking `graph.microsoft.com` -- effectively disabling Microsoft 365 for the organization. Detection must shift from network blocking to audit log analysis and application identity monitoring.

2. **Application credential hygiene is as critical as user credential hygiene.** The entire attack chain depends on compromised Entra ID application credentials. Organizations must treat application registrations with the same rigor as privileged user accounts: regular credential rotation, least-privilege permission grants, conditional access policies, and continuous monitoring of Graph Activity Logs.

3. **Calendar events as data channels are a blind spot for most security tooling.** Security teams monitor email, file shares, and network traffic but rarely audit calendar event creation patterns. HollowGraph demonstrates that any M365 data store accessible via Graph API (calendar, OneDrive, SharePoint lists, Teams messages) can be weaponized as a C2 channel.

4. **Compilation format diversity is an emerging anti-analysis technique.** The Cavern framework's use of three different .NET compilation formats (IL-only, Mixed-Mode C++/CLI, NativeAOT) across its modules forces analysts to switch between multiple reverse engineering toolsets, significantly increasing analysis time.

## Sources

- [Group-IB Blog: HOLLOWGRAPH - Turning Microsoft 365 Calendars into Covert C2 Channels](https://www.group-ib.com/blog/hollowgraph-microsoft-365/) -- Primary technical analysis; malware discovery, C2 mechanism, DNS tunneling, and campaign details
- [The Hacker News: HollowGraph Malware Hides C2 and Stolen Files in Microsoft 365 Events Dated 2050](https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html) -- News coverage with technical details on Graph API endpoints, encryption scheme, and Cavern framework linkage
- [BleepingComputer: New HollowGraph malware uses Microsoft Graph for stealthy C2 comms](https://www.bleepingcomputer.com/news/security/new-hollowgraph-malware-uses-microsoft-graph-for-stealthy-c2-comms/) -- Additional technical reporting on DNS tunneling mechanism and calendar event structure
- [Infosecurity Magazine: New HollowGraph Malware Hijacks Microsoft 365 Calendars for Covert C2](https://www.infosecurity-magazine.com/news/hollowgraph-microsoft-calendars/) -- Coverage of command format, debug toggle, and Cavern framework overlap details
- [SC Media: HollowGraph malware uses Microsoft 365 calendar for command and control](https://www.scworld.com/brief/hollowgraph-malware-uses-microsoft-365-calendar-for-command-and-control) -- Brief with confirmation of Graph API endpoint usage and logAzure.txt configuration
- [The Register: Microsoft 365 calendars become spy drop boxes in HOLLOWGRAPH campaign](https://www.theregister.com/security/2026/07/20/microsoft-365-calendars-become-spy-drop-boxes-in-hollowgraph-campaign/5274982) -- Coverage of operational scope, victim geography, and Lyceum attribution assessment
- [Check Point Research: Cavern Manticore - Exposing Iran-Linked Modular C2 Framework](https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/) -- Cavern framework architecture, module details, MOIS attribution, and IOCs including file hashes and C2 domains

---
*Report generated by Actioner*
