# Technical Analysis Report: ARToken / EvilTokens Microsoft 365 PhaaS Platform (2026-07-03)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-03
Version: 1.1 (FINAL)

## Executive Summary

ARToken is a phishing-as-a-service (PhaaS) affiliate panel built on the EvilTokens infrastructure, targeting Microsoft 365 environments through device code phishing and OAuth token theft. Identified and documented by Cisco Talos in June 2026, the platform enables operators to steal Microsoft authentication tokens -- including Primary Refresh Tokens (PRTs) -- to gain persistent access to victim email, SharePoint, and OneDrive. The platform supports a full business email compromise (BEC) lifecycle: device code phishing for initial token capture, PRT persistence to survive password resets, inbox monitoring and email sending as the victim, SharePoint document exfiltration, and vendor-impersonation invoice fraud.

The platform employs a seven-layer anti-analysis defense system combining User-Agent filtering, browser fingerprinting, interaction telemetry, timing gates, and movement pattern analysis, with XOR-encrypted payloads to evade static analysis. Infrastructure is deployed via Cloudflare Workers with UUID-prefixed subdomains, and C2 operations run through the `pamconj[.]com` domain. The platform offers 80+ API endpoints and is sold as a subscription service at $1,500 one-time plus $500/month. At least 500+ Cloudflare Workers domains and 1,000+ phishing pages have been documented across the EvilTokens ecosystem.

## Background: Microsoft 365 Device Code Authentication

Microsoft's device code flow (RFC 8628) is designed for input-constrained devices -- it allows users to authenticate by entering a code at `microsoft.com/devicelogin` on a separate device. This legitimate authentication mechanism is abused by ARToken to trick victims into authorizing attacker-controlled device sessions. When the victim enters the code, the attacker's session receives the victim's access and refresh tokens, granting full API access to Microsoft 365 resources (Outlook, SharePoint, OneDrive) without needing the victim's password. The use of the Microsoft Authentication Broker (WAM) via the `clientMode: "broker"` parameter further elevates the token to a Primary Refresh Token, enabling persistence that survives credential rotation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| March-April 2026 | Sekoia publishes initial EvilTokens analysis (Part 1 and Part 2) |
| April 2026 | Microsoft security blog confirms EvilTokens device code phishing activity |
| 2026-04-20 | Observed ARToken spear-phishing email pair sent ~4 minutes apart to target |
| 2026-06-30 | Cisco Talos publishes detailed ARToken affiliate panel analysis |
| 2026-07-01 | The Register reports on expanded EvilTokens capabilities |

## Root Cause: Device Code Phishing via Vendor Impersonation

Initial access is achieved through targeted spear-phishing emails impersonating known vendors. The emails use the real vendor's domain in the From header with a Reply-To pivot to an attacker-controlled domain for response capture. Each email contains per-message mutations -- random hex strings and inline signature images (`pumber.png`) -- to evade hash-based detection. The visible URL text shows a legitimate SharePoint path while the actual href redirects to an attacker-controlled Cloudflare Workers page that extracts the victim's email from a `?hint=` URL parameter and initiates the device code phishing flow.

Authentication validation failures observed in sample emails include SPF failure, DKIM body-hash mismatch, and DMARC failure (compauth=none reason=405), indicating the emails are sent from infrastructure that does not authenticate for the spoofed sender domain.

## Technical Analysis of the Malicious Payload

### 1. Phishing Delivery via Cloudflare Workers

The phishing pages are deployed as Cloudflare Workers with UUID-prefixed subdomain patterns:
- `{uuid}-docviewer.{parent}.workers[.]dev` (document viewer lures)
- `{uuid}-onedrive.{parent}.workers[.]dev` (OneDrive lures)
- `{uuid}-adobe2.{parent}.workers[.]dev` (Adobe lures)

Observed parent Workers domains include `clear90489058903-document[.]workers[.]dev` and `reynoldsjace5[.]workers[.]dev`, with at least 8 UUID-prefixed subdomains documented in the Cisco Talos IOC repository.

The React-based SPA dashboard compiles to a 1.7MB JavaScript bundle. Geo-dynamic lure templates use placeholders (`{city}`, `{country_code}`, `{state}`) resolved by the victim's geolocation at load time.

### 2. Device Code Phishing and Token Capture

The phishing payload initiates the device code flow via `POST /api/device/start` with the following parameters:
- `userId` -- operator identifier
- `clientMode: "broker"` -- invokes the Microsoft Authentication Broker (WAM) flow
- `login_hint` -- victim email extracted from URL `?hint=` parameter
- `redirect_url` -- attacker callback

The C2 responds with `device_code`, `user_code`, `verification_uri`, and `expires_in` (default 900 seconds). The victim is directed to `microsoft.com/devicelogin` to complete authentication. The operator UUID `84eb384d-cd3e-4c90-a283-c960ce557913` is hardcoded in the observed payload.

The page also attempts to steal any existing JWT from localStorage via the key `artoken_jwt` for victim session correlation.

### 3. C2 Infrastructure

C2 operations are centralized on the `pamconj[.]com` domain:
- `dashboard-bl[.]pamconj[.]com` -- ARToken management panel (React SPA)
- `spx[.]pamconj[.]com` -- C2 API endpoint handling device code operations, PRT management, email operations, and SharePoint access

The platform resolves to IP `172[.]67[.]214[.]35` (Cloudflare infrastructure -- shared IP, not useful as a standalone IOC).

Telegram bot notifications are sent to operators upon successful token capture, providing real-time alerting on compromised accounts.

### 4. PRT Persistence Mechanism

Once a token is captured, the platform establishes Primary Refresh Token persistence through a dedicated endpoint chain:
- `/prt/setup` -- initialize PRT binding
- `/prt/refresh` -- token refresh
- `/prt/renew` -- token renewal
- `/prt/reacquire` -- token reacquisition after expiry
- `/prt/cookie` -- cookie chain completion for browser session persistence

A configuration flag `persistAfterPassChange: false` reveals the platform's awareness of token revocation on password reset, though the PRT mechanism itself can survive password changes when this flag is set.

### 5. Post-Compromise Operations

**Email Operations (ARTSender):**
- Full Outlook inbox read access per compromised account
- Email sending as the victim with BCC batch support and configurable inter-send delays
- Inbox rule creation for forwarding and auto-deletion (evidence suppression)
- Keyword-based cross-account monitoring ("Box Monitor")
- Email attachment access and download

**SharePoint/OneDrive Operations:**
- Site resolution and enumeration
- File upload/download operations
- Permission management manipulation
- Document theft and malicious file placement for lateral phishing

**Invoice Fraud (BEC):**
- Spoofed SharePoint tenant `mononapfpcom[.]sharepoint[.]com` for vendor impersonation
- Targeting accounts-payable professionals with vendor-impersonation invoice themes
- The article notes "tradecraft is targeted, not spray-and-pray"

### 6. Anti-Forensics / Evasion Techniques

The platform implements a seven-layer anti-analysis defense system before serving the phishing payload:

| Layer | Mechanism | Details |
|-------|-----------|---------|
| 1 | User-Agent regex filtering | Blocks headless browsers, Selenium, Puppeteer, Playwright, crawlers, wget, curl |
| 2 | navigator.webdriver detection | Detects automation frameworks via WebDriver API |
| 3 | Browser fingerprinting | Validates `window.chrome`, `navigator.vendor`, touch/mouse API presence |
| 4 | Window dimension analysis | Detects headless browsers with 0x0 outer dimensions |
| 5 | Interaction telemetry | Requires 3+ mouse moves or 1+ touch events before payload activation |
| 6 | Timing gate | Minimum 800ms elapsed since page load before proceeding |
| 7 | Movement pattern analysis | Validates mouse coordinate trajectories for organic (non-linear) motion |

**XOR Payload Encryption:**
The phishing payload is encrypted at delivery and decrypted client-side at runtime using a 16-byte XOR key: `[233, 69, 224, 219, 53, 48, 213, 165, 119, 243, 77, 151, 101, 148, 15, 227]` (hex: `E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3`). This evades static URL scanner analysis that cannot execute JavaScript.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | pamconj[.]com | Parent C2 domain |
| Domain | dashboard-bl[.]pamconj[.]com | ARToken management panel |
| Domain | spx[.]pamconj[.]com | C2 API endpoint |
| Domain | clear90489058903-document[.]workers[.]dev | Cloudflare Workers phishing parent |
| Domain | reynoldsjace5[.]workers[.]dev | Cloudflare Workers phishing parent |
| Domain | 917bedb0-554e-a8b9-79f1-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | 321a1392-939d-3bf5-4040-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | 98c4c82e-2d81-0837-e3d6-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | 112838d8-9a75-2e90-d63b-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | aquaclaude-09494-9099403-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | e5469cec-124a-c84f-abaa-docviewer[.]clear90489058903-document[.]workers[.]dev | Phishing page (docviewer lure) |
| Domain | 50a201fd-dd2d-cf72-5fa6-onedrive[.]clear90489058903-document[.]workers[.]dev | Phishing page (OneDrive lure) |
| Domain | 50a201fd-dd2d-cf72-5fa6-adobe2[.]reynoldsjace5[.]workers[.]dev | Phishing page (Adobe lure) |
| Domain | mononapfpcom[.]sharepoint[.]com | Spoofed vendor SharePoint tenant |
| IP | 172[.]67[.]214[.]35 | Cloudflare shared infrastructure (low-value standalone) |

### Behavioral

**API Endpoint Patterns:**
- `POST /api/device/start` with body containing `clientMode: "broker"` and operator UUID -- device code phishing initiation
- `/prt/setup`, `/prt/refresh`, `/prt/cookie`, `/prt/renew`, `/prt/reacquire` -- PRT persistence lifecycle

**Client-Side Artifacts:**
- localStorage key `artoken_jwt` -- session correlation token
- Operator UUID `84eb384d-cd3e-4c90-a283-c960ce557913` hardcoded in payload
- XOR key (16 bytes): `E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3`
- Signature image filename `pumber.png` in phishing emails
- Cloudflare Workers subdomain pattern: `{uuid}-(docviewer|onedrive|adobe2).{parent}.workers[.]dev`

**Email Indicators:**
- SPF/DKIM/DMARC triple failure on vendor-impersonation emails
- Reply-To pivot to attacker-controlled domain (different from From header domain)
- Per-message random hex string mutations in email body
- Paired email delivery approximately 4 minutes apart

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Vendor-impersonation emails with links to Cloudflare Workers phishing pages |
| T1528 | Steal Application Access Token | Device code phishing to steal Microsoft 365 OAuth tokens |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Stolen tokens used to access Outlook, SharePoint, OneDrive APIs |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | PRT persistence binding to maintain access across password changes |
| T1114.002 | Email Collection: Remote Email Collection | Full inbox read access and keyword-based cross-account monitoring |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Inbox rule creation for auto-deletion of security notifications |
| T1583.006 | Acquire Infrastructure: Web Services | Cloudflare Workers and spoofed SharePoint tenants for attack infrastructure |
| T1027 | Obfuscated Files or Information | XOR-encrypted payloads with client-side decryption |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Seven-layer anti-analysis with browser fingerprinting, interaction telemetry, timing gates |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTPS to spx[.]pamconj[.]com |

## Impact Assessment

The ARToken/EvilTokens ecosystem represents a mature, commercially operated PhaaS platform with documented scale of 500+ Cloudflare Workers domains and 1,000+ phishing pages. The platform's focus on device code phishing and PRT persistence creates a particularly dangerous threat to Microsoft 365 environments because:

1. **Credential rotation is insufficient** -- PRT persistence survives password changes, requiring explicit token revocation
2. **MFA bypass** -- Device code phishing inherently bypasses traditional MFA by having the victim authenticate on a legitimate Microsoft page
3. **Full BEC lifecycle** -- The platform provides everything from initial access to invoice fraud in a single toolset
4. **Anti-analysis maturity** -- Seven-layer defenses significantly hinder automated security scanning and researcher analysis
5. **Targeted tradecraft** -- Focus on accounts-payable and vendor relationships indicates high-value, low-volume targeting

## Detection & Remediation

### Immediate Detection

Check Azure AD sign-in logs for device code authentication events:
```
AuditLogs
| where OperationName == "Consent to application"
| where TargetResources has "devicecode"
```

Check for suspicious inbox rules created programmatically:
```
Search-UnifiedAuditLog -Operations New-InboxRule -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
```

Review Conditional Access policies for device code flow restrictions:
```
Get-AzureADMSConditionalAccessPolicy | Where-Object {$_.Conditions.ClientAppTypes -contains "all"}
```

### Remediation

1. **Immediate:** Revoke all refresh tokens and active sessions for compromised accounts via `Revoke-AzureADUserAllRefreshToken`
2. **Immediate:** Search for and remove malicious inbox rules (forwarding, auto-delete) created by the attacker
3. **Immediate:** Block known C2 domains (`pamconj[.]com`, Workers subdomains) at the proxy/DNS level
4. **Short-term:** Audit SharePoint/OneDrive access logs for unauthorized file downloads or permission changes
5. **Short-term:** Review sent emails from compromised accounts for BEC/invoice fraud activity
6. **Short-term:** Notify downstream vendors/partners if vendor impersonation was observed

### Long-Term Hardening

1. **Disable device code flow** via Conditional Access policy for all users who do not require it (most organizations)
2. **Enforce token protection** (token binding) where supported to prevent PRT theft
3. **Enable Continuous Access Evaluation (CAE)** to reduce token lifetime and enable near-real-time revocation
4. **Implement phishing-resistant MFA** (FIDO2/passkeys) to eliminate phishable authentication methods
5. **Deploy email authentication enforcement** -- reject emails failing SPF+DKIM+DMARC alignment
6. **Monitor for anomalous OAuth application consent** events in Azure AD audit logs

## Detection Rules

These detections target known ARToken/EvilTokens C2 domains, Cloudflare Workers phishing infrastructure, and distinctive payload artifacts. PoC/advisory-specific altitude (default); compiles does not equal fires -- verify in your pipeline before production deployment.

### Sigma: DNS Query to ARToken C2 and Phishing Infrastructure

Detects DNS queries resolving known ARToken C2 domains (`pamconj[.]com` and subdomains), Cloudflare Workers phishing parents, and the spoofed SharePoint tenant.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag validator excluded due to network — MITRE data endpoint blocked by proxy; rule syntax and structure fully validated). splunk convert 0. log_scale convert 0. No pipeline fit for dns_query category — schema mapping skipped (no overclaim). Values are real (not defanged). IOC domains from Cisco Talos GitHub IOC repo (TLP:WHITE, 2026-06-30). -->
```yaml
title: DNS Query to ARToken EvilTokens C2 and Phishing Infrastructure
id: f7a3e1b2-4c5d-4e6f-8a9b-1c2d3e4f5a6b
status: experimental
description: >
    Detects DNS queries to known ARToken/EvilTokens phishing-as-a-service C2 domains
    and Cloudflare Workers phishing infrastructure identified by Cisco Talos. Covers the
    management panel (dashboard-bl.pamconj.com), API endpoint (spx.pamconj.com), and
    phishing delivery Workers subdomains.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://github.com/Cisco-Talos/IOCs/tree/main/2026/07
author: Actioner
date: 2026/07/03
tags:
    - attack.t1566.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection_c2:
        QueryName|endswith:
            - 'pamconj.com'
    selection_workers:
        QueryName|endswith:
            - 'clear90489058903-document.workers.dev'
            - 'reynoldsjace5.workers.dev'
    selection_spoof_tenant:
        QueryName:
            - 'mononapfpcom.sharepoint.com'
    condition: 1 of selection_*
falsepositives:
    - Unlikely - pamconj.com and associated Workers domains are attacker-controlled infrastructure
level: high
```

### Sigma: Web Request to ARToken Phishing Infrastructure

Detects proxy/web gateway traffic to known ARToken C2 and phishing domains via the Host header.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (attacktag excluded — network). splunk convert 0. log_scale convert 0. Field cs-host is W3C ELF standard for proxy category — widely supported. Values real, not defanged. Same IOC provenance as DNS rule. -->
```yaml
title: Web Request to ARToken EvilTokens Phishing Infrastructure
id: a8b4c7d2-3e5f-4a1b-9c6d-7e8f0a1b2c3d
status: experimental
description: >
    Detects web proxy requests to known ARToken/EvilTokens C2 and phishing infrastructure.
    Matches the operator panel, C2 API endpoint, Cloudflare Workers phishing pages, and
    the spoofed SharePoint vendor-impersonation tenant.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://github.com/Cisco-Talos/IOCs/tree/main/2026/07
author: Actioner
date: 2026/07/03
tags:
    - attack.t1566.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_c2:
        cs-host|endswith:
            - 'pamconj.com'
    selection_workers:
        cs-host|endswith:
            - 'clear90489058903-document.workers.dev'
            - 'reynoldsjace5.workers.dev'
    selection_spoof_tenant:
        cs-host:
            - 'mononapfpcom.sharepoint.com'
    condition: 1 of selection_*
falsepositives:
    - Unlikely - pamconj.com and associated Workers domains are attacker-controlled infrastructure
level: high
```

### Snort: DNS Query to ARToken C2 Domain

Detects DNS queries containing the `pamconj.com` label sequence in wire format, covering the apex domain and all subdomains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -T exit 0 via minimal config with classification.config + reference.config. Wire-format encoding: pamconj=7 bytes (|07|), com=3 bytes (|03|). Substring match catches both apex and subdomain queries. nocase applied for case-insensitive DNS name matching. -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to ARToken C2 Domain pamconj.com"; flow:to_server; content:"|07|pamconj|03|com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; sid:2100001; rev:1;)
```

### Suricata: DNS and TLS Detection for ARToken Infrastructure

Five rules detecting DNS resolution and TLS handshakes to ARToken C2 and phishing domains. Scope to egress monitoring points.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T exit 0. Five rules: SID 2200001 (DNS pamconj.com), SID 2200002 (DNS Workers parent clear90489058903-document), SID 2200003 (TLS SNI pamconj.com), SID 2200004 (DNS Workers parent reynoldsjace5), SID 2200005 (DNS spoofed SharePoint tenant mononapfpcom). dns.query buffer provides normalized domain name — endswith matches apex + subdomains. tls.sni matches SNI in ClientHello. All values real. -->
<!-- revision: added SID 2200004 (reynoldsjace5.workers.dev) and SID 2200005 (mononapfpcom.sharepoint.com) to close Sigma parity gap flagged by critic. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ARToken C2 Domain pamconj.com"; flow:to_server; dns.query; content:"pamconj.com"; endswith; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-03; sid:2200001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ARToken Workers Phishing Infrastructure"; flow:to_server; dns.query; content:"clear90489058903-document.workers.dev"; endswith; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-03; sid:2200002; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to ARToken C2 Domain pamconj.com"; flow:established,to_server; tls.sni; content:"pamconj.com"; endswith; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-03; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ARToken Workers Phishing Infrastructure reynoldsjace5"; flow:to_server; dns.query; content:"reynoldsjace5.workers.dev"; endswith; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-03; sid:2200004; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ARToken Spoofed SharePoint Tenant"; flow:to_server; dns.query; content:"mononapfpcom.sharepoint.com"; nocase; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-03; sid:2200005; rev:1;)
```

### YARA: ARToken EvilTokens Phishing Payload

Detects the ARToken phishing JavaScript payload via the hardcoded operator UUID, `artoken_jwt` localStorage key, C2 domain strings, XOR decryption key bytes, or the device code API endpoint pattern combined with PRT lifecycle paths.
**Status:** compile ✅ compiles · confidence: high · synthetic-test: fired ✓ (constructed from Talos-published strings)
<!-- audit: yarac exit 0. yara positive test: fired on synthetic file containing published UUID + artoken_jwt + spx.pamconj.com — constructed from Talos blog strings, not a captured sample. yara negative test: quiet on benign JS. XOR key bytes E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3 from source (decimal [233,69,224,219,53,48,213,165,119,243,77,151,101,148,15,227] converted). $xor_key requires co-occurrence with API/config string to avoid 16-byte FP on arbitrary binaries. $img_artifact ("pumber.png") requires co-occurrence with at least one other string to avoid standalone FP on unrelated files containing that filename. Each top-level OR branch is individually distinctive. -->
<!-- revision: (1) relabeled "sample: fired" to "synthetic-test: fired" — test used constructed file, not captured payload. (2) $img_artifact now requires co-occurrence with 1 of other strings to prevent standalone FP. (3) ATT&CK T1531→T1564.008. (4) defanged bare pamconj.com in remediation. -->
```yara
rule PhaaS_ARToken_EvilTokens_Phishing_Payload
{
    meta:
        description = "Detects ARToken/EvilTokens phishing-as-a-service JavaScript payload via operator UUID, localStorage key, C2 domains, XOR key, or API endpoint patterns"
        author = "Actioner"
        date = "2026-07-03"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        severity = "high"

    strings:
        $uuid = "84eb384d-cd3e-4c90-a283-c960ce557913" ascii wide
        $jwt_key = "artoken_jwt" ascii wide
        $c2_domain = "spx.pamconj.com" ascii wide
        $dashboard = "dashboard-bl.pamconj.com" ascii wide
        $api_endpoint = "/api/device/start" ascii wide
        $client_mode = "clientMode" ascii wide
        $prt_setup = "/prt/setup" ascii wide
        $prt_refresh = "/prt/refresh" ascii wide
        $prt_cookie = "/prt/cookie" ascii wide
        $prt_renew = "/prt/renew" ascii wide
        $xor_key = { E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3 }
        $img_artifact = "pumber.png" ascii wide

    condition:
        filesize < 5MB and
        (
            $uuid or
            $jwt_key or
            $c2_domain or
            $dashboard or
            ($img_artifact and 1 of ($uuid, $jwt_key, $c2_domain, $dashboard, $api_endpoint, $client_mode)) or
            ($xor_key and 1 of ($api_endpoint, $client_mode, $uuid, $jwt_key)) or
            ($api_endpoint and $client_mode and 1 of ($prt_*))
        )
}
```

## Lessons Learned

1. **Device code flow is an underappreciated attack surface.** Most organizations have not restricted this OAuth flow via Conditional Access, leaving a MFA-bypassing authentication path wide open. Disabling device code flow for users who do not need it is a high-impact, low-effort hardening measure.

2. **Token persistence outlasts credential rotation.** The PRT persistence mechanism demonstrates that password resets alone are insufficient remediation -- explicit token revocation and session invalidation are required. Organizations should implement Continuous Access Evaluation (CAE) and token binding to limit token lifetime and portability.

3. **Anti-analysis sophistication is increasing in PhaaS.** The seven-layer behavioral verification system (requiring organic mouse movement, interaction counts, and timing thresholds) significantly raises the bar for automated URL scanning and sandboxed analysis. Defenders should supplement URL reputation with post-delivery detection of device code phishing patterns in authentication logs.

4. **Cloudflare Workers abuse creates a detection blind spot.** Legitimate `workers.dev` domains are ubiquitous, making broad domain-based blocking impractical. Detection must key on specific subdomain patterns (UUID prefixes, parent worker names) rather than the TLD.

5. **PhaaS commoditization of advanced techniques.** The commercialization of PRT persistence, cross-account monitoring, and SharePoint operations as a subscription service ($1,500 + $500/month) means that sophisticated M365 attacks are no longer limited to well-resourced threat actors.

## Sources

- [Cisco Talos Blog: ARToken Inside an EvilTokens Affiliate Panel Targeting Microsoft 365](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/) — primary technical analysis documenting ARToken affiliate panel, C2 infrastructure, API contracts, anti-analysis defenses, and attack lifecycle
- [Cisco Talos IOC Repository (2026/07)](https://github.com/Cisco-Talos/IOCs/tree/main/2026/07) — published indicators of compromise including domains, subdomains, and IP address (TLP:WHITE)
- [The Register: EvilTokens Device Code Phishing Kit Coverage](https://www.theregister.com/cyber-crime/2026/07/01/eviltokens-device-code-phishing-kit-totally-more-evil-than-we-all-thought/5265409) — secondary reporting on EvilTokens ecosystem capabilities (anti-bot blocked during fetch)

---
*Report generated by Actioner*
