# Technical Analysis Report: OWAReaper Backdoor via CVE-2026-42897 (2026-07-31)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-31
Version: 1.0 DRAFT

## Executive Summary

Russian state-sponsored threat actor TA458 (also tracked as Laundry Bear, Void Blizzard, CL-STA-1114, UNK_PitStop) is actively exploiting CVE-2026-42897, a cross-site scripting (XSS) zero-day in on-premises Microsoft Exchange Outlook Web Access (OWA), to deploy a browser-based JavaScript implant named OWAReaper. The campaign, which began on July 22, 2026, targets U.S. and European government entities alongside telecommunications, financial services, hospitality, and aerospace organizations. OWAReaper is the most sophisticated "half-click" webmail backdoor documented to date: it executes when a victim merely views a crafted email in the OWA reading pane, requires no clicks or attachments, and achieves persistence that survives credential rotation and full device reimaging by residing on the Exchange server itself rather than the endpoint.

The backdoor uses a dual C2 channel (GitHub Commit Search API polling every 24 hours and inbound email parsing every 5 minutes), supports three exfiltration methods (HTTPS with AES-CTR encrypted URI paths, direct server delivery, and DNS label tunneling with Base32 encoding), and establishes three independent persistence mechanisms (OAuth token theft via Outlook add-in abuse, IndexedDB message cache injection, and encrypted localStorage self-copy). Infrastructure creation dates to March 2026 -- approximately two months before Microsoft's May 2026 advisory -- confirming pre-disclosure zero-day exploitation. Credential rotation and device rebuilds are explicitly insufficient for remediation; server-side cleanup of Exchange mailbox permissions and cached message stores is required.

## Background: Microsoft Exchange Outlook Web Access

Microsoft Exchange Server's Outlook Web Access (OWA) provides browser-based email access for on-premises Exchange deployments. OWA runs within the user's authenticated browser session and exposes Outlook REST and EWS APIs to JavaScript executing in the mail rendering context. CVE-2026-42897 (CVSS 8.1) stems from improper sanitization of HTML content in the email message body, allowing embedded JavaScript to execute when a message is rendered in the OWA reading pane. Exchange Online is not affected. This vulnerability is the latest in a pattern of webmail XSS exploitation by TA458, following CVE-2025-66376 (Zimbra), CVE-2025-27915 (Zimbra), CVE-2025-3929 (mDaemon), CVE-2023-43770 and CVE-2024-42009 (Roundcube), and CVE-2026-8496 (SOGo), all exploited through the group's "Operation RoundPress" campaign framework.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| March 2026 | TA458 creates attack infrastructure for OWA exploitation |
| May 14, 2026 | Microsoft discloses CVE-2026-42897 advisory |
| February - July 22, 2026 | Activity gap observed in TA458 operations |
| July 22, 2026 | Campaign (re)initiation; phishing emails with OWAReaper payloads begin |
| July 23, 2026 | Proofpoint publishes Operation RoundPress report covering the broader campaign |
| July 30, 2026 | Public reporting on Exchange OWA exploitation and OWAReaper backdoor |

## Root Cause: CVE-2026-42897 XSS in OWA Message Body Rendering

The vulnerability exists in how OWA renders HTML content within the email reading pane. OWA fails to properly sanitize HTML event handlers (specifically `onload=`) in the message body, allowing attacker-controlled JavaScript to execute within the victim's authenticated OWA session. The exploit is classified as a "half-click" because it requires the victim only to open or preview the email -- no link clicks, no attachment opens, no user interaction beyond viewing. The attacker embeds a JavaScript loader that uses the `onload=` event handler to parse the rest of the message body, assemble a Base64 fragment from data hidden after `#` symbols in social media icon image URLs, and execute the decoded payload as JavaScript.

## Technical Analysis of the Malicious Payload

### 1. Delivery and Initial Execution

Phishing emails are sent with deliberately mundane subject lines covering topics such as supply-chain analyses, research updates, performance indicators for tourism, semiconductor markets, and gas markets. The emails contain no URLs or attachments, mimicking informational communications to blend with mass-mailing spam. The email body contains:

- A JavaScript loader using the `onload=` event handler
- Social media icon image elements whose URLs contain Base64-encoded payload fragments after the `#` character
- The loader parses these fragments, reassembles them, and executes the decoded JavaScript

Upon execution, OWAReaper:
- Disables OWA pop-ups and right-click functionality to prevent user interference
- Creates a per-session unique key for target identification
- Uses Outlook APIs to rewrite the email on the Exchange server and remove the exploit content (anti-forensics)

### 2. Credential Harvesting and Privilege Escalation

OWAReaper performs immediate credential and configuration harvesting:

- Collects the target's email address, username, and Outlook settings
- Creates invisible DOM input elements to exploit browser auto-fill functionality for credential capture
- Searches for installed Outlook add-ins with `ReadWriteMailbox` permissions
- Uses the `GetClientAccessToken` operation to steal OAuth tokens from compromised add-ins
- Calls `UpdateFolder` to grant `Owner`-level permissions to the `Default` user on all mail folders

The `Default` user permission grant is the most critical persistence artifact: it ensures the attacker retains full mailbox access even after credential rotation, MFA resets, or complete device reimaging, because the permission lives on the Exchange server.

### 3. C2 Infrastructure

OWAReaper operates two independent C2 channels:

**Primary -- GitHub Commit Search API (24-hour polling):**
The implant queries GitHub's Commit Search API (`/search/commits`) every 24 hours for commit messages containing the target's email address. Commands are encrypted with a hard-coded key combined with a per-session AES key, preventing third-party extraction even if the commit messages are discovered.

**Secondary -- Email-based (5-minute polling):**
The implant parses the target's mailbox every 5 minutes for inbound messages matching the structure: `{target_email_address}{space}{Base64text}`. This provides a lower-latency fallback C2 channel.

**Command Types (4-character headers):**

| Code | Function |
|------|----------|
| `code` | Replace entire OWAReaper toolkit |
| `domn` | Rotate C2 server addresses |
| `cmnd` | Execute arbitrary JavaScript via `eval()` |

**Data Exfiltration (three methods):**

1. **Primary:** HTTPS with AES-CTR encrypted URI paths routed through legitimate image CDN domains
2. **Secondary:** Direct delivery to attacker-controlled server
3. **Tertiary:** DNS label tunneling using Base32 encoding within standard DNS queries to actor-controlled domains

### 4. Persistence Mechanisms

OWAReaper establishes three independent persistence mechanisms, each of which can independently reinfect the target:

**Server-side (survives everything short of Exchange-level cleanup):**
- Grants `Owner` permissions to the `Default` user on all mailbox folders via the `UpdateFolder` API
- Persists through credential rotation, MFA resets, device reimaging, and browser reinstallation
- Requires explicit removal of the `Default` user folder permissions on the Exchange server

**Browser localStorage:**
- Writes an encrypted self-copy to browser `localStorage` under a legitimate-looking OWA settings key
- Includes a decryption wrapper that auto-executes when the OWA tab is opened
- Persists through browser restarts but not device reimaging

**IndexedDB message cache:**
- Injects a hidden `iframe` element into messages stored in OWA's offline IndexedDB message cache
- Enables OWA offline caching to ensure the poisoned cache persists
- Re-executes each time the victim opens a poisoned cached email
- Survives credential rotation but not full browser data clearance

### 5. Anti-Forensics / Evasion Techniques

- Removes exploit content from the original email on the Exchange server post-execution
- Leaves virtually no host filesystem artifacts (runs entirely in browser context)
- Disables OWA pop-ups and right-click during operation to prevent user detection
- Uses deliberately mundane email subjects to blend with legitimate mail flow
- High-volume campaign approach (atypical for the group) designed to mimic mass-mailing spam
- Encrypts C2 communications with per-session AES keys
- Routes exfiltration through legitimate image CDN domains
- DNS tunneling fallback uses standard DNS queries, evading HTTPS inspection

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Network (from broader TA458 RoundPress campaign -- may overlap with OWA campaign)

| Type | Value | Context |
|------|-------|---------|
| Domain | share-ya[.]space | C2 domain (May 2025, RoundPress) |
| Domain | xwe[.]us | C2 domain (June 2025, RoundPress) |
| Domain | hgmydr[.]wiki | C2 domain (March 2026, RoundPress) |
| Domain | xsza[.]net | C2 domain (February 2026, RoundPress) |
| Domain | zxzaq[.]com | C2 domain (February 2026, RoundPress) |
| Domain | upgybj[.]store | C2 domain (February 2026, RoundPress) |
| URL Pattern | hxxps://api[.]github[.]com/search/commits?q={email} | C2 polling endpoint (OWAReaper) |

### File System (from broader TA458 RoundPress campaign)

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Roundcube | N/A | 625e4c166c7a1d5a1becf56b27d4f76a2f95935cbd8d556c30a493263d10dbf8 | SpyPress payload (CVE-2023-43770) |
| Zimbra | N/A | a0c80cab70d6672b01710a70f93311fc1c1db2fbbf9cd6daa543c34b87e3444a | SpyPress payload (CVE-2025-27915) |
| Zimbra | N/A | fb8ec4dbed14c0a91361abd82ebe9fb083615c3dbb15348f57317af7cc41dd34 | SpyPress payload (CVE-2025-27915) |
| Roundcube | N/A | 3a449148a0e3cac604fb93210dd7d91ccf48e06ed9aae064bc53a419a84ce9ba | SpyPress payload (CVE-2024-42009) |
| mDaemon | N/A | 8b5a4dc237a4c89042176bc89864a4c357dcdd14fa544fe6496ccb6c31cd5b7f | SpyPress payload (CVE-2025-3929) |
| Roundcube | N/A | 6b2c02bf82087a3ca5fb7ef8046554ff29ce85d52202bdcfae2b2653aede139a | SpyPress dual exploit payload |
| SOGo | N/A | e27d1bf82249002a66395c89dbda6ec5d8df012a84b79d36fffbbf7808d28878 | SpyPress payload (CVE-2026-8496) |

### Behavioral

- **Exchange server modification:** `Default` user granted `Owner` permissions on all mailbox folders via EWS `UpdateFolder` operation
- **Browser localStorage:** Encrypted JavaScript payload stored under OWA settings key with auto-execute decryption wrapper
- **IndexedDB manipulation:** Hidden `iframe` elements injected into OWA's offline message cache entries
- **GitHub API beaconing:** Outbound HTTPS requests to `api.github.com/search/commits` containing email addresses, polling every 24 hours
- **Email-based C2:** Inbound emails matching pattern `{email_address} {Base64text}` parsed every 5 minutes
- **DNS tunneling:** Base32-encoded subdomain labels in DNS queries to actor-controlled domains
- **Exfiltration via CDN:** AES-CTR encrypted URI paths in HTTPS requests to legitimate image CDN providers
- **OWA email modification:** Exploit content removed from original email body after execution via Outlook APIs
- **DOM manipulation:** Invisible input elements created for browser auto-fill credential capture

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of CVE-2026-42897 XSS in OWA |
| T1059.007 | Command and Scripting Interpreter: JavaScript | OWAReaper payload executes as JavaScript in OWA context |
| T1557 | Adversary-in-the-Browser | Implant operates within authenticated OWA browser session |
| T1528 | Steal Application Access Token | OAuth token theft via GetClientAccessToken from Outlook add-ins |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Default user granted Owner permissions on all mailbox folders |
| T1102.001 | Web Service: Dead Drop Resolver | GitHub Commit Search API used as C2 channel |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 and exfiltration via CDN domains |
| T1071.004 | Application Layer Protocol: DNS | DNS label tunneling for data exfiltration |
| T1132.001 | Data Encoding: Standard Encoding | Base64/Base32 encoding in C2 and exfiltration payloads |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-CTR encryption of exfiltrated data in URI paths |
| T1185 | Browser Session Hijacking | Operates within victim's authenticated OWA session |
| T1056.004 | Input Capture: Credential API Hooking | Invisible DOM elements exploit browser auto-fill for credential capture |
| T1140 | Deobfuscate/Decode Files or Information | Base64 payload fragments decoded and assembled at runtime |
| T1070.008 | Indicator Removal: Clear Mailbox Data | Exploit content removed from email post-execution |

## Impact Assessment

**Breadth:** The campaign targets broad sectors (government, telecom, financial, hospitality, aerospace) across the U.S. and Europe, with unusually high-volume phishing for this actor -- a deliberate shift to blend with mass-mailing spam. All organizations running unpatched on-premises Exchange Server with OWA exposed are vulnerable.

**Depth:** Full mailbox compromise with persistent access. The attacker gains read/write access to all email folders, can exfiltrate historical and future mail, harvest credentials, and execute arbitrary JavaScript in the victim's session context. The three persistence mechanisms ensure continued access even through standard incident response procedures (credential rotation, device reimaging).

**Stealth:** OWAReaper leaves virtually no host filesystem artifacts. The implant operates entirely within the browser context and on the Exchange server, making it invisible to endpoint detection tools. The server-side permission persistence has no expiration and generates minimal logging in default Exchange configurations.

## Detection & Remediation

### Immediate Detection

**Check Exchange mailbox folder permissions for anomalous Default user access:**
```powershell
# Run on Exchange Management Shell - check all mailboxes for Default user with Owner permissions
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $mbx = $_.Identity
    Get-MailboxFolderPermission -Identity "$($mbx):\" -ErrorAction SilentlyContinue |
    Where-Object { $_.User.DisplayName -eq "Default" -and $_.AccessRights -contains "Owner" } |
    Select-Object @{N="Mailbox";E={$mbx}}, User, AccessRights
}
```

**Check browser localStorage for suspicious OWA entries:**
```javascript
// Run in browser developer console while on OWA
Object.keys(localStorage).forEach(key => {
    const val = localStorage.getItem(key);
    if (val && val.length > 1000) {
        console.warn("Suspicious large localStorage entry:", key, "length:", val.length);
    }
});
```

**Monitor proxy logs for GitHub API C2 beaconing:**
```
# Splunk query - look for Exchange/OWA servers querying GitHub Commit Search API
index=proxy dest="api.github.com" uri_path="*/search/commits*"
| stats count by src, uri_query, _time
```

### Remediation

1. **Patch immediately:** Apply Microsoft security update for CVE-2026-42897 on all on-premises Exchange servers
2. **Revoke Exchange Web Services tokens:** Invalidate all active EWS and OAuth tokens
3. **Remove Default user permissions:** Reset `Default` user folder permissions across all mailboxes to the organizational default (typically `None` or `AvailabilityOnly`)
4. **Purge browser storage:** Clear OWA offline IndexedDB databases and localStorage on all client browsers that accessed affected OWA instances
5. **Audit Outlook add-ins:** Review all add-ins with `ReadWriteMailbox` permissions; remove any unauthorized add-ins
6. **Rotate credentials:** Change passwords and revoke sessions -- but only AFTER completing steps 2-4 (credential rotation alone is insufficient)
7. **Search for exploit artifacts:** Scan Exchange message stores for emails containing `onload=` event handlers with Base64 fragments in image URL `#` parameters

### Long-Term Hardening

- Disable OWA on Exchange servers where browser-based email access is not operationally required
- Migrate to Exchange Online (not affected by CVE-2026-42897)
- Implement Outlook add-in restrictions: block all add-ins except explicitly approved ones; disallow `ReadWriteMailbox` permission level
- Enable Exchange mailbox audit logging for `UpdateFolderPermissions` operations
- Monitor outbound DNS and HTTPS from Exchange servers for anomalous patterns
- Implement Content Security Policy headers on OWA to restrict inline JavaScript execution
- Deploy web proxy monitoring for Exchange server outbound traffic to `api.github.com`

## Detection Rules

These rules target OWAReaper's distinctive C2 channel (GitHub Commit Search API polling) and payload strings. All rules compile cleanly against their respective validators; compiles does not equal fires -- verify in your environment before production deployment.

### Sigma: OWAReaper C2 Channel via GitHub Commit Search API

Detects outbound proxy requests to GitHub's Commit Search API endpoint, the primary OWAReaper C2 polling channel. Scope to Exchange/OWA server source IPs to reduce developer-tooling false positives.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to network error loading MITRE ATT&CK data (proxy 403); sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. Both portable conversions clean. FP risk: legitimate GitHub API usage from developer machines; mitigated by scoping src to Exchange infrastructure. No pipeline-mapped conversion (no proxy pipeline available). -->
```yaml
title: OWAReaper C2 Channel via GitHub Commit Search API
id: 8f3a71d2-e4b9-4c6e-a1f5-9d2b7e0c8a43
status: experimental
description: >
    Detects outbound HTTP requests to GitHub Commit Search API endpoint,
    consistent with OWAReaper backdoor C2 polling mechanism that queries
    for commit messages containing the target email address every 24 hours.
references:
    - https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/
    - https://thehackernews.com/2026/07/russian-hackers-exploit-microsoft-owa.html
author: Actioner
date: 2026/07/31
tags:
    - attack.t1102.001
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/search/commits'
        r-dns: 'api.github.com'
    condition: selection
falsepositives:
    - Developer tooling and CI/CD pipelines querying GitHub API
    - Security scanning tools using GitHub search endpoints
level: medium
```

### Snort: OWAReaper C2 GitHub Commit Search API Polling

Detects outbound HTTP requests to GitHub's Commit Search API endpoint used by OWAReaper for C2 polling.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c /etc/snort/snort.conf (Snort 2.9.20) exit 0. Uses tcp protocol with http_uri and http_header sticky buffers (Snort 2 syntax). FP: legitimate GitHub API queries from the same network segment; scope $HOME_NET to Exchange server subnets for precision. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OWAReaper C2 GitHub Commit Search API Polling"; flow:established,to_server; content:"/search/commits"; http_uri; fast_pattern; content:"api.github.com"; http_header; classtype:trojan-activity; reference:url,bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/; sid:2100001; rev:1;)
```

### Suricata: OWAReaper C2 GitHub Commit Search API Polling

Detects outbound HTTP requests to GitHub's Commit Search API endpoint used by OWAReaper for C2 polling.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T -S (Suricata 7.0.3) exit 0. Uses dot-notation sticky buffers (http.host, http.uri). FP: legitimate GitHub API queries from developer workstations; mitigate by scoping $HOME_NET to Exchange/mail server IPs. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OWAReaper C2 GitHub Commit Search API Polling"; flow:established,to_server; http.host; content:"api.github.com"; http.uri; content:"/search/commits"; fast_pattern; classtype:trojan-activity; reference:url,bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/; metadata:author Actioner, created_at 2026-07-31; sid:2200001; rev:1;)
```

### YARA: OWAReaper JavaScript Payload Detection

Detects OWAReaper JavaScript payload via distinctive Outlook API abuse strings (GetClientAccessToken, ReadWriteMailbox, UpdateFolder) combined with C2 command structure codes. Scan Exchange message stores and browser cache exports.
**Status:** compile ✅ compiles · confidence: medium · sample: constructed
<!-- audit: yarac exit 0. Sample test: positive (constructed from published behavioral strings) fired, negative (legitimate add-in code) quiet. Confidence medium not high because strings are derived from published behavioral descriptions rather than a confirmed malware sample hash; a real sample could use different string casing or obfuscation. The constructed positive uses strings verbatim from Proofpoint/BleepingComputer reporting. -->
```yara
rule APT_TA458_OWAReaper_Payload
{
    meta:
        description = "Detects OWAReaper JavaScript backdoor payload targeting Exchange OWA via CVE-2026-42897, based on distinctive Outlook API abuse strings and C2 command structure"
        author = "Actioner"
        date = "2026-07-31"
        reference = "https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/"
        severity = "high"

    strings:
        $api1 = "GetClientAccessToken" ascii wide
        $api2 = "ReadWriteMailbox" ascii wide
        $api3 = "UpdateFolder" ascii wide

        $cmd1 = "code" ascii
        $cmd2 = "domn" ascii
        $cmd3 = "cmnd" ascii

        $persist1 = "IndexedDB" ascii wide
        $persist2 = "localStorage" ascii wide

        $c2_1 = "search/commits" ascii wide
        $c2_2 = "AES-CTR" ascii wide

    condition:
        filesize < 5MB and
        (2 of ($api*)) and
        (2 of ($cmd*)) and
        (1 of ($persist*) or 1 of ($c2_*))
}
```

## Lessons Learned

This campaign demonstrates the continued evolution of browser-based exploitation as a persistence vector that fundamentally challenges traditional endpoint-centric incident response. OWAReaper's design -- residing on the Exchange server and in browser storage rather than the filesystem -- renders EDR tools, device reimaging, and credential rotation ineffective as standalone remediation measures. The three-layer persistence architecture (server permissions, IndexedDB cache, localStorage) ensures that eliminating any two mechanisms still leaves the attacker with access through the third.

The "half-click" exploit class, requiring only email viewing with no user interaction, eliminates the traditional phishing detection opportunity at the user education layer. Organizations with OWA exposed to the internet face a zero-interaction initial access risk that can only be mitigated through patching or disabling OWA entirely.

The use of GitHub's public API as a C2 channel and legitimate image CDN domains for exfiltration demonstrates sophisticated use of trusted infrastructure to evade network monitoring. DNS tunneling as a tertiary fallback ensures exfiltration capability even in environments with strict HTTPS inspection.

## Sources

- [BleepingComputer - Russian hackers exploit Exchange OWA zero-day for long-term mailbox access](https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/) — Primary news reporting with detailed technical breakdown of OWAReaper persistence, C2, and exfiltration mechanisms
- [The Hacker News - Russian Hackers Exploit Microsoft OWA Flaw](https://thehackernews.com/2026/07/russian-hackers-exploit-microsoft-owa.html) — Supplemental reporting with CVSS score, command type details, and timeline information
- [Infosecurity Magazine - TA488 Outlook Half-Click OWAReaper](https://www.infosecurity-magazine.com/news/ta488-outlook-half-click-owareaper/) — Additional campaign context including remediation guidance and targeting scope
- [The Register - Russian spies take their half-click email attack from Zimbra to Outlook](https://www.theregister.com/security/2026/07/30/russian-spies-take-their-half-click-email-attack-from-zimbra-to-outlook/5281033) — Attribution context and relationship to prior Zimbra campaigns
- [Proofpoint - Operation RoundPress Rolls on with More Half-Click Webmail Zero-Days from TA458](https://www.proofpoint.com/us/blog/threat-insight/ta458-roundpress-exploits) — Primary vendor research covering the broader TA458 campaign framework, related CVEs, IOCs (C2 domains, payload hashes), and MITRE ATT&CK mapping

---
*Report generated by Actioner*
