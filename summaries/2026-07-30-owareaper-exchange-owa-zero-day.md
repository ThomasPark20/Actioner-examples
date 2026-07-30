# Technical Analysis Report: OWAReaper — TA488 Exchange OWA Zero-Day Campaign (2026-07-30)

Prepared by: Actioner (Researcher, DRAFT)
Classification: TLP:CLEAR
Date: 2026-07-30
Version: 0.1 (draft)

## Executive Summary

Russian state-sponsored group Laundry Bear (also tracked as Void Blizzard, TA488, CL-STA-1114, UNK_PitStop) is actively exploiting CVE-2026-42897, a cross-site scripting zero-day in Microsoft Exchange Outlook Web Access (OWA), to deploy a sophisticated JavaScript backdoor called OWAReaper. The campaign, which began around July 22, 2026, targets U.S. and European government entities as well as telecommunications, financial services, hospitality, and aerospace organizations. OWAReaper is described by Proofpoint as "the most sophisticated backdoor delivered via half-click exploits" they have observed. The implant uses three layered persistence mechanisms -- browser localStorage, IndexedDB offline cache injection, and server-side mailbox folder permission escalation -- the last of which survives both credential rotation and full device reimaging. C2 communication is conducted via the GitHub Commit Search API (queried every 24 hours) and email-based command channels. Data exfiltration uses AES-CTR encrypted HTTPS through CDN proxies with DNS tunneling as a fallback. The group connected to Yutek-NN, an FSB-linked IT firm, was first identified by Dutch authorities and Microsoft in 2025. Infrastructure for this campaign was created as early as March 2026, two months before Microsoft's initial advisory for the vulnerability.

## Background: Microsoft Exchange OWA and the Half-Click Attack Surface

Microsoft Exchange Server is the dominant enterprise email platform, with Outlook Web Access (OWA) providing browser-based mailbox access typically exposed on TCP/443 at paths like `/owa` and `/ecp`. OWA renders HTML email content in the browser, making it a recurring target for XSS attacks where the email sanitization pipeline fails to neutralize malicious script content. CVE-2026-42897 affects on-premises Exchange Server 2016, 2019, and Exchange Server Subscription Edition (SE) -- Exchange Online is not affected.

"Half-click" exploits are a class of webmail XSS attacks where viewing an email is sufficient to trigger compromise, requiring no explicit user interaction beyond opening the message. This attack class was previously used by TA458 (GRU-aligned) against Roundcube, Zimbra, mDaemon, and SOGo in Operation RoundPress. TA488's adoption of the technique -- first with ZimReaper against Zimbra (CVE-2025-66376) starting July 2025 and now with OWAReaper against Exchange OWA -- represents a significant escalation in capability and target scope.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| July 2025 | TA488 begins exploiting CVE-2025-66376 (Zimbra XSS) to deploy ZimReaper, stealing emails, 2FA codes, and credentials |
| March 2026 | Earliest OWAReaper campaign infrastructure created (two months before CVE-2026-42897 disclosure) |
| 2026-05-14 | CVE-2026-42897 reported to Microsoft; Microsoft warns of zero-day exploitation |
| 2026-05-15 | CISA adds CVE-2026-42897 to Known Exploited Vulnerabilities (KEV) catalog with May 29 remediation deadline |
| Mid-May 2026 | Microsoft deploys automatic mitigations via Exchange Emergency Mitigation Service (EEMS) |
| 2026-06-09 | Microsoft releases security updates in June 2026 Patch Tuesday |
| February -- July 2026 | Activity gap: no TA488 activity detected |
| 2026-07-22 | OWAReaper campaign resumes with broad targeting of U.S. and European organizations |
| 2026-07-23 | NSA/industry joint advisory issued regarding related Zimbra exploitation activity |
| Mid-July 2026 | Microsoft releases additional Exchange Server remediation via techcommunity blog |
| 2026-07-29 | Proofpoint publishes report: "Cleaning out Inboxes: TA488 comes to Outlook with another half-click exploit" |

## Root Cause: CVE-2026-42897 -- Improper HTML Sanitization in OWA (CWE-79)

CVE-2026-42897 is a cross-site scripting vulnerability caused by improper HTML sanitization in OWA email message body rendering. The vulnerability has a CVSS score of 8.1 HIGH (Microsoft CNA) / 6.1 MEDIUM (NIST). The exploit is delivered as a crafted email: when the victim opens the message in a vulnerable OWA instance, an `onload=` event handler in the message body triggers JavaScript execution in the authenticated browser session with no further user interaction required. The specific sanitization bypass technique has not been publicly disclosed by Microsoft. Critically, the exploit emails contain no suspicious URLs or attachments, making traditional email gateway detection ineffective.

## Technical Analysis of the Malicious Payload

### 1. Delivery Mechanism -- "Half-Click" Exploit Emails

TA488 delivers exploit emails from Proton Mail adversary-controlled accounts and previously compromised organizational email addresses. Lure topics are deliberately generic and unremarkable -- semiconductor supply chain analyses, gas market metrics, research updates, and tourism indicators -- designed to avoid suspicion and blend with mass-mailing spam. The unusually high volume of emails (atypical for the group) appears to be an intentional strategy to further blend in with spam traffic.

The exploit payload is embedded within the email HTML body using two steganographic techniques:
- **Social media icon URLs:** A JavaScript loader is hidden after the `#` fragment identifier in social media icon image URLs within the message HTML. Since fragments are not sent to the server, they evade server-side scanning.
- **Base64 blobs in HTML:** Secondary payload data is stored as Base64-encoded content within the message body.

The `onload=` event handler parses the message body, extracts the fragments, assembles them, and executes the resulting JavaScript -- the OWAReaper implant -- entirely within the OWA reading pane context.

### 2. OWAReaper Implant -- Browser-Resident JavaScript Backdoor

OWAReaper runs entirely as JavaScript within the victim's authenticated OWA browser session. It has no conventional file-system footprint, making endpoint detection challenging. Upon execution, it performs the following actions:

**Credential Harvesting:**
- Disables OWA pop-up notifications and right-click functionality
- Creates invisible DOM input elements to trigger browser autofill and capture saved credentials
- Collects the target's email address, username, and Outlook settings
- Generates a unique per-session encryption key for the target

**OAuth Token Theft:**
- Enumerates installed Outlook add-ins for those with `ReadWriteMailbox` permissions
- Steals OAuth tokens from identified add-ins via the `GetClientAccessToken` EWS operation
- Uses stolen tokens to perform privileged mailbox operations

### 3. Persistence -- Three Layered Mechanisms

OWAReaper employs three independent persistence mechanisms, each designed to survive different remediation actions:

**a) Browser localStorage Persistence:**
Writes an encrypted copy of itself plus a decryption wrapper into the browser's `localStorage` under legitimate-looking OWA settings keys. The implant auto-executes every time the victim opens a new OWA tab or window.

**b) IndexedDB Offline Cache Persistence:**
Enables OWA offline caching (if not already active) and injects a hidden `<iframe>` element into HTML email messages stored in the browser's IndexedDB offline cache. The iframe executes the implant every time the victim opens a poisoned email from the cache, re-infecting the session even after the localStorage entry is cleared.

**c) Server-Side Mailbox Permission Escalation (survives reimaging):**
Using the stolen OAuth tokens, OWAReaper executes an `UpdateFolder` EWS command that grants **Owner-level permissions to the "Default" user** on every mail folder in the victim's mailbox. This means any authenticated Exchange user (including other accounts TA488 controls) can access the victim's mailbox with full read/write permissions. This persistence mechanism **survives credential rotation, password changes, and full device reimaging** because it operates at the Exchange server level, not on the client device.

### 4. C2 Infrastructure

OWAReaper uses two independent C2 channels:

**Primary -- GitHub Commit Search API:**
The implant queries the GitHub Commit Search API (`api.github.com/search/commits`) every 24 hours, searching for commit messages that contain the target's email address. Matching commits contain encrypted commands, which are decrypted using a combination of a hard-coded key and the per-session AES key. This leverages a legitimate, high-reputation platform that is unlikely to be blocked by corporate proxies.

**Secondary -- Email-Based Commands:**
The implant polls the victim's mailbox every five minutes for inbound emails containing commands in the format `{target_email_address}{space}{Base64text}`. This provides a backup C2 channel if GitHub access is blocked.

**Command Types:**
- `code` -- Full toolkit replacement (update the implant)
- `domn` -- C2 domain/infrastructure rotation
- `cmnd` -- Arbitrary JavaScript execution via `eval()`

### 5. Data Exfiltration

Three exfiltration channels provide redundancy:

- **Primary:** HTTPS with AES-CTR encrypted URI paths, proxied through legitimate CDN image domains to disguise the traffic as normal web browsing
- **Secondary:** Direct HTTPS POST to attacker-controlled servers
- **Tertiary:** DNS tunneling using Base32-encoded encrypted data in DNS query labels to attacker-controlled domains

The predecessor ZimReaper was documented harvesting 90 days of victim mail data; OWAReaper's exfiltration scope is presumed similar or greater.

### 6. Anti-Forensics / Evasion Techniques

- **Post-infection email sanitization:** After successful exploitation, OWAReaper rewrites the original exploit email on the Exchange server to strip the malicious content, destroying the forensic evidence of the initial compromise vector
- **No file-system artifacts:** The entire implant resides in browser memory, localStorage, and IndexedDB -- no files are dropped to disk
- **Payload steganography:** Exploit code is fragmented across social media icon URLs and Base64 blobs, avoiding pattern-matching by email security gateways
- **Legitimate C2 infrastructure:** Uses GitHub (a trusted platform) and the victim's own mailbox for command delivery
- **CDN proxying:** Exfiltration traffic blends with legitimate CDN image requests

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: URLs use `hxxps://`, domains use `[.]`, IPs use `[.]`, emails use `[at]`.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | api[.]github[.]com | C2 polling endpoint (legitimate service abused); queries to `/search/commits` with email address in query string |
| URL Pattern | `hxxps://api[.]github[.]com/search/commits?q={email}` | OWAReaper C2 polling URL pattern (24-hour interval) |

> **Note:** Proofpoint's full report includes specific attack infrastructure domains, C2 server IPs, and exfiltration endpoints. These IOCs were not enumerated in the news reporting available at draft time. The Proofpoint IOC appendix should be incorporated when the full report is accessible.

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| N/A (browser-resident) | Browser localStorage (OWA settings keys) | N/A | Encrypted OWAReaper implant + decryption wrapper stored under legitimate OWA key names |
| N/A (browser-resident) | Browser IndexedDB (OWA offline cache) | N/A | Hidden iframe injected into cached HTML email messages |

> **Note:** OWAReaper has no traditional file-system footprint. Detection must focus on browser storage, Exchange server-side artifacts, and network traffic.

### Behavioral

- **Exchange folder permissions:** `Default` user granted `Owner`-level permissions on all mailbox folders via `UpdateFolder` EWS operation. This is the definitive server-side IOC.
- **OAuth token theft:** Anomalous `GetClientAccessToken` EWS requests from OWA sessions, particularly targeting add-ins with `ReadWriteMailbox` scope.
- **GitHub API polling:** Periodic (approximately 24-hour interval) HTTPS requests to `api.github.com/search/commits` with an email address in the query string from non-developer workstations.
- **Email-based C2:** Inbound emails containing the pattern `{email_address} {Base64text}` being parsed and processed by OWA JavaScript.
- **DNS tunneling:** DNS queries with unusually long labels (32+ characters) containing Base32-encoded data to attacker-controlled domains.
- **OWA offline cache manipulation:** Sudden enablement of OWA offline mode on accounts where it was not previously configured.
- **Post-exploitation email modification:** Exchange message tracking logs showing message body modifications (removal of HTML/script content) on recently received emails without user-initiated editing.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2026-42897 XSS in Exchange OWA; crafted email triggers JavaScript execution on view |
| T1059.007 | JavaScript | OWAReaper JavaScript backdoor executes in authenticated OWA browser context |
| T1185 | Browser Session Hijacking | Operates within and persists across OWA browser sessions via localStorage and IndexedDB |
| T1528 | Steal Application Access Token | Steals OAuth tokens from Outlook add-ins with ReadWriteMailbox permissions via GetClientAccessToken |
| T1098.002 | Additional Email Delegate Permissions | Grants Owner permissions to Default user on all mailbox folders; survives reimaging |
| T1056.003 | Web Portal Capture | Invisible DOM input elements harvest browser autofill credentials from OWA |
| T1102.002 | Bidirectional Communication | GitHub Commit Search API as primary C2 channel (24-hour polling interval) |
| T1071.003 | Mail Protocols | Secondary C2 via inbound emails with `{email}{space}{Base64}` command format |
| T1071.001 | Web Protocols | HTTPS exfiltration with AES-CTR encrypted URI paths through CDN image domains |
| T1071.004 | DNS | Tertiary exfiltration via DNS tunneling with Base32-encoded encrypted payloads |
| T1573.001 | Symmetric Cryptography | AES-CTR for exfiltration; AES with hard-coded + per-session keys for C2 decryption |
| T1114.002 | Remote Email Collection | Harvests target mailbox contents via compromised OWA session |
| T1070 | Indicator Removal | Rewrites exploit emails on Exchange server to strip malicious content post-infection |

## Impact Assessment

**Breadth:** All organizations running on-premises Exchange Server 2016, 2019, or SE with OWA exposed are potentially vulnerable. Exchange Online is not affected. TA488 is targeting broadly across U.S. and European government, telecoms, financial services, hospitality, and aerospace -- an unusually wide scope for this group, assessed as intentional to blend with spam. **Depth:** Critical. OWAReaper achieves persistent mailbox access that survives credential rotation and device reimaging. The OAuth token theft and folder permission escalation grant the attacker complete read/write access to the victim's mailbox through alternative authentication paths. **Stealth:** Very high. No file-system footprint, legitimate C2 infrastructure (GitHub), CDN-proxied exfiltration, and post-exploitation evidence destruction via email rewriting make this exceptionally difficult to detect with traditional security tooling.

## Detection & Remediation

### Immediate Detection

**Server-side (Exchange):**
```powershell
# Check for Default user Owner permissions on mailbox folders (the definitive OWAReaper persistence IOC)
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-MailboxFolderPermission -Identity "$($_.PrimarySmtpAddress):\Inbox" |
    Where-Object { $_.User -like "Default" -and $_.AccessRights -contains "Owner" }
}

# Audit OAuth token grants for add-ins with ReadWriteMailbox permissions
Get-App -Mailbox <user> | Where-Object { $_.Permissions -match "ReadWriteMailbox" }

# Review Exchange admin audit log for UpdateFolder operations
Search-AdminAuditLog -Cmdlets Set-MailboxFolderPermission -StartDate (Get-Date).AddDays(-30)
```

**Network/Proxy:**
```
# Search proxy logs for GitHub Commit Search API requests containing email addresses
index=proxy cs_host="api.github.com" cs_uri_stem="*/search/commits*" cs_uri_query="*@*"

# Hunt for DNS tunneling patterns (long Base32-encoded labels)
index=dns query_length>50 query=*[a-z2-7]{32,}*
```

**Client-side (if browser forensics are possible):**
- Inspect OWA localStorage for encrypted blobs under OWA settings key names
- Check IndexedDB for HTML email entries containing hidden `<iframe>` elements
- Review OWA offline cache enablement status per user

### Remediation

1. **Apply Exchange security updates immediately** -- both the June 2026 Patch Tuesday and mid-July 2026 supplemental updates for CVE-2026-42897.
2. **Revoke Exchange Web Services (EWS) tokens** for all users on affected servers.
3. **Audit and remove Default-user folder permission grants** on all mailboxes using the detection script above. Any mailbox where Default has Owner permissions should be treated as compromised.
4. **Clear OWA offline databases and localStorage** on all client browsers that accessed the affected Exchange server. Instruct users to clear browser site data for the OWA domain.
5. **Rotate all user credentials** -- but understand that credential rotation alone does NOT evict the actor due to the server-side permission persistence.
6. **Audit Outlook add-in OAuth token grants** and revoke any suspicious ReadWriteMailbox permissions.
7. **Review Exchange message tracking logs** for evidence of post-exploitation email body modifications.
8. **Monitor for re-compromise** -- the actor may attempt re-exploitation if the patch is not applied or if the server-side persistence was not fully remediated.

### Long-Term Hardening

- Restrict OWA access to managed devices and trusted networks; require VPN or conditional access policies.
- Deploy Content Security Policy (CSP) headers on OWA endpoints to limit the impact of future XSS vulnerabilities.
- Disable OWA offline mode organization-wide unless specifically required.
- Enable and monitor mailbox audit logging with focus on folder permission changes and OAuth token operations.
- Consider migrating to Exchange Online, which receives mitigations faster and is not affected by this vulnerability.
- Implement network monitoring for GitHub API traffic from non-developer systems and DNS tunneling patterns.

## Detection Rules

These detections target OWAReaper's distinctive C2 mechanism (GitHub Commit Search API polling) and the JavaScript implant's signature strings. The Sigma rule converts cleanly to Splunk and CrowdStrike LogScale; Snort and Suricata rules cover network-level detection; the YARA rule targets the implant payload in files, browser cache exports, or memory dumps. Note: compiles does not equal fires -- verify all rules against your environment's telemetry before production deployment.

### Sigma: GitHub Commit Search API Request - OWAReaper C2 Channel

Detects proxy log entries showing requests to the GitHub Commit Search API, the primary C2 polling mechanism used by OWAReaper every 24 hours.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to environment (MITRE ATT&CK data fetch blocked by proxy - HTTP 403, not a rule issue); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. No pipeline-mapped conversion attempted (no proxy pipeline available). FP risk: legitimate developer use of GitHub Commit Search API; reduce by scoping to non-developer endpoint populations. Evasion: actor could switch C2 to a different GitHub API or alternate platform. -->
```yaml
title: GitHub Commit Search API Request - Potential OWAReaper C2 Channel
id: b3f4a892-1e7d-4c5a-9b3e-8d2f6a1c0e7b
status: experimental
description: >
    Detects HTTP requests to the GitHub Commit Search API (api.github.com/search/commits),
    used by OWAReaper as a C2 polling channel. The implant queries this endpoint every 24 hours
    for commit messages containing the target email address to receive encrypted commands.
references:
    - https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/
    - https://thehackernews.com/2026/07/russian-hackers-exploit-microsoft-owa.html
author: Actioner
date: 2026/07/30
tags:
    - attack.t1102.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        cs-host: 'api.github.com'
        cs-uri-stem|contains: '/search/commits'
    condition: selection
falsepositives:
    - Legitimate developer tools querying the GitHub Commit Search API
    - CI/CD pipeline integrations searching commits
level: medium
```

### Snort: OWAReaper C2 via GitHub Commit Search API

Detects outbound HTTP traffic to the GitHub Commit Search API endpoint, consistent with OWAReaper C2 polling.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf (with rule included) -T exit 0. Snort 2.9.20 validated. Matches /search/commits in URI + api.github.com in HTTP headers. FP: legitimate GitHub API usage; scope to Exchange/OWA user segments. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OWAReaper C2 via GitHub Commit Search API"; flow:established,to_server; content:"/search/commits"; http_uri; fast_pattern; content:"api.github.com"; http_header; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/; sid:2100101; rev:1;)
```

### Suricata: OWAReaper C2 via GitHub Commit Search API

Detects outbound HTTP traffic to the GitHub Commit Search API endpoint using Suricata dot-notation sticky buffers.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S rules -l /tmp/actioner exit 0. Suricata 7.0.3. Uses http.host + http.uri dot-notation buffers. Same FP/evasion profile as Snort rule above. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OWAReaper C2 via GitHub Commit Search API"; flow:established,to_server; http.host; content:"api.github.com"; http.uri; content:"/search/commits"; fast_pattern; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/; metadata:author Actioner, created_at 2026-07-30; sid:2200101; rev:1;)
```

### YARA: OWAReaper JavaScript Implant Strings

Detects the OWAReaper JavaScript implant via distinctive string combinations: OAuth token theft API (`GetClientAccessToken`), EWS folder permission modification (`UpdateFolder`), GitHub C2 endpoint, and custom command type identifiers (`cmnd`, `domn`, `code`). Targets cached files, browser storage exports, HTML email bodies, or memory dumps.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive file (constructed from published API/command strings) matched; negative file (benign JS with partial overlap) did not match. The positive uses source-published strings (GetClientAccessToken, UpdateFolder, search/commits, cmnd/domn/code) per Proofpoint/news reporting. Condition requires multiple string class overlap, reducing FP risk to near-zero for legitimate files. Evasion: obfuscation of string constants would defeat this rule; behavioral detection would be needed. -->
```yara
rule APT_TA488_OWAReaper_JavaScript_Implant
{
    meta:
        description = "Detects OWAReaper JavaScript implant via distinctive string combinations: OAuth token theft API, EWS folder permission modification, GitHub C2 endpoint, and custom command type identifiers"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/"
        severity = "critical"

    strings:
        $api1 = "GetClientAccessToken" ascii wide
        $api2 = "UpdateFolder" ascii wide
        $c2_github = "search/commits" ascii wide
        $cmd_exec = "cmnd" ascii fullword
        $cmd_rotate = "domn" ascii fullword
        $cmd_replace = "code" ascii fullword
        $persist_ls = "localStorage" ascii wide
        $persist_idb = "indexedDB" ascii wide nocase
        $crypto = "AES-CTR" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            ($api1 and $api2 and 1 of ($cmd*)) or
            ($c2_github and 2 of ($cmd_exec, $cmd_rotate, $cmd_replace)) or
            ($api1 and $c2_github and $crypto) or
            (1 of ($api*) and $c2_github and 1 of ($persist*) and 1 of ($cmd*))
        )
}
```

## Lessons Learned

OWAReaper represents a significant evolution in webmail exploitation tradecraft. Three aspects demand particular attention from defenders:

1. **Reimaging does not equal eviction.** The server-side mailbox permission escalation (granting Owner to Default on all folders) persists on the Exchange server, completely independent of the victim's device. Organizations that reimage a compromised user's workstation and rotate credentials will falsely believe they have evicted the attacker while the mailbox remains fully accessible. Remediation must include server-side Exchange permission audits.

2. **Legitimate platform abuse defeats reputation-based controls.** By using the GitHub Commit Search API as a C2 channel and CDN image domains for exfiltration, OWAReaper avoids domain reputation and threat intelligence blocklists entirely. Detection must focus on behavioral anomalies (e.g., GitHub API usage from non-developer endpoints) rather than IOC matching.

3. **No-click email exploitation is maturing.** The half-click XSS attack class, previously associated with TA458/GRU operations against smaller webmail platforms (Roundcube, Zimbra, mDaemon, SOGo), has now reached Microsoft Exchange -- the highest-value enterprise email target. The payload steganography (fragments hidden in image URL fragments and Base64 blobs) and post-exploitation evidence destruction (email rewriting) demonstrate an attacker who anticipates and designs around modern email security gateway capabilities.

## Sources

- [BleepingComputer -- Russian hackers exploit Exchange OWA zero-day for long-term mailbox access](https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/) -- detailed technical analysis of OWAReaper delivery, persistence, C2, and exfiltration mechanisms
- [The Record -- Russia hackers Outlook webmail malware](https://therecord.media/russia-hackers-outlook-webmail-malware) -- timeline, attribution to Yutek-NN/FSB, Microsoft remediation link
- [The Hacker News -- Russian Hackers Exploit Microsoft OWA](https://thehackernews.com/2026/07/russian-hackers-exploit-microsoft-owa.html) -- CVSS 8.1 scoring, detailed OWAReaper execution chain, command types (code/domn/cmnd), ZimReaper predecessor details
- [Infosecurity Magazine -- TA488 Outlook Half-Click OWAReaper](https://www.infosecurity-magazine.com/news/ta488-outlook-half-click-owareaper/) -- remediation guidance (EWS token revocation, folder permission removal, localStorage clearing), on-premises-only scope
- [Microsoft Exchange Team -- Released: July 2026 Exchange Server Security Updates](https://techcommunity.microsoft.com/blog/exchange/released-july-2026-exchange-server-security-updates/4534146) -- vendor remediation advisory (content not fully extractable at fetch time)
- [Proofpoint Threat Insight -- "Cleaning out Inboxes: TA488 comes to Outlook with another half-click exploit"](https://www.proofpoint.com/us/blog/threat-insight/) -- primary technical research (full report URL not confirmed; IOC appendix not accessible at draft time)
- [Earlier Actioner analysis -- CVE-2026-42897 Exchange OWA XSS](2026-06-11-exchange-cve-2026-42897.md) -- prior analysis of the underlying vulnerability before OWAReaper attribution

---
*Report generated by Actioner*
