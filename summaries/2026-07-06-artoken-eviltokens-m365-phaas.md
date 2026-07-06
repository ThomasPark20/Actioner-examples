# Technical Analysis Report: ARToken / EvilTokens -- Phishing-as-a-Service Platform Targeting Microsoft 365

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-06
Version: 1.0 (DRAFT)

## Executive Summary

ARToken is a phishing-as-a-service (PhaaS) affiliate panel built on the EvilTokens platform, targeting Microsoft 365 accounts through device code phishing. Discovered by Cisco Talos during an incident response engagement, the React-based panel exposes over 80 API endpoints covering the complete attack lifecycle: device code phishing for initial access, Primary Refresh Token (PRT) persistence that survives password resets, full Outlook mailbox access, inbox rule manipulation for evidence suppression, cross-account keyword monitoring, SharePoint/OneDrive exfiltration, and AI-augmented business email compromise (BEC) operations using Groq-hosted Llama and GPT-4o-mini models.

The platform deploys phishing infrastructure through Cloudflare Workers (500+ domains, 1,000+ phishing pages) and employs a 7-layer anti-analysis system combining client-side behavioral verification with XOR-encrypted payloads. Device code phishing attacks associated with EvilTokens increased 1,380% (37-fold) year-over-year in early 2026, with at least 11 competing kits now available. ARToken operates on a subscription model ($1,500 setup + $500/month) with Telegram-based operator notifications. The platform has since gone dark and likely relocated.

## Background: Microsoft 365 Device Code Authentication

Microsoft's OAuth 2.0 Device Authorization Grant (RFC 8628) enables authentication for devices with limited input capabilities (smart TVs, IoT devices, CLI tools). The flow works by displaying a user code that the user enters at `microsoft.com/devicelogin` on a separate device with a browser. Once authenticated, the requesting device receives access and refresh tokens. This legitimate flow is exploited by phishing kits because the victim completes their own MFA challenge on Microsoft's real infrastructure, granting the attacker valid tokens without exposing credentials. The tokens bypass MFA entirely since authentication was legitimately completed.

Primary Refresh Tokens (PRTs) are long-lived credentials issued when a device is registered with Azure AD. They enable single sign-on across Microsoft 365 applications and can persist even after password changes, making them a high-value target for persistent access.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-February 2026 | EvilTokens phishing pages first observed in the wild |
| 2026-03-03 | Sekoia TDR identifies EvilTokens via Telegram channel advertisement |
| 2026-03 | Sekoia publishes Part 1 analysis of EvilTokens platform |
| 2026-04-06 | Microsoft publishes analysis of AI-enabled device code phishing campaign |
| 2026-04 | Sekoia Part 2 details the AI-augmented BEC pipeline |
| 2026-04 | Microsoft confirms campaign scale; hundreds of organizations compromised daily |
| 2026-04-20 | Two near-identical ARToken phishing emails observed, sent 4 minutes apart |
| 2026-07-01 | Cisco Talos publishes ARToken analysis; panel has since gone dark |

## Root Cause: Device Code Phishing via Vendor-Impersonation Lures

The attack begins with targeted spearphishing emails that impersonate legitimate vendors. In the observed campaign, messages spoofed an accounts-payable contact at a legitimate Wisconsin contractor, addressed to an accounts-payable recipient at a U.S. life sciences company -- abusing a real vendor relationship rather than inventing a sender. The lure uses an outstanding-invoice theme.

Key email characteristics:
- Real vendor domain in the From header with Reply-To redirecting to an attacker-controlled domain
- SPF, DKIM (body-hash mismatch), and DMARC all fail; `compauth=none reason=405`
- Short random hex strings and inline signature images (`pumber.png`) for per-message mutation
- Visible anchor text spoofs legitimate SharePoint URLs while the actual href points to attacker-controlled lookalike domains
- Geo-dynamic template placeholders (`{city}`, `{country_code}`, `{state}`) resolve based on victim geolocation

## Technical Analysis of the Malicious Payload

### 1. Phishing Infrastructure (Cloudflare Workers Deployment)

ARToken deploys phishing pages through Cloudflare Workers using standardized subdomain naming patterns organized by template type:

| Template | Workers Domain Pattern |
|----------|----------------------|
| Adobe | `adobe-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| DocuSign | `docusign-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| OneDrive | `onedrive-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| SharePoint | `sharepoint-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| Voicemail | `voicemail-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| Calendar | `calendar_invite-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| Password Expiry | `page-password-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |
| Email Quarantine | `quarantine-[a-z0-9]{3}.[a-z0-9-]{3,}-s-account.workers.dev` |

Subdomains may encode the target email address with special characters replaced by dashes (e.g., `john-doe-example-com`). The platform automates Cloudflare API integration for Workers deployment and management.

### 2. Device Code Phishing Flow

On page load (`DOMContentLoaded`), the phishing payload executes:

1. Attempts to steal any existing JWT from `localStorage` (key: `artoken_jwt`)
2. Extracts the victim's email from the `?hint=` URL parameter
3. Sends `POST /api/device/start` to the C2 backend with the hardcoded operator UUID (`84eb384d-cd3e-4c90-a283-c960ce557913`) and `clientMode: "broker"`
4. The `clientMode: "broker"` parameter instructs the backend to use Microsoft's Authentication Broker (WAM) flow for PRT acquisition -- this is not a standard OAuth parameter
5. Backend contacts Microsoft's device authorization endpoint, returns `device_code`, `user_code`, `verification_uri`, and `expires_in`
6. Displays the device code to the victim with a 900-second countdown timer
7. Uses `navigator.clipboard.writeText()` to auto-copy the code to the victim's clipboard
8. Redirects the victim to `microsoft.com/devicelogin`
9. Backend polls `/api/device/status/{sessionId}` every 3-5 seconds via `checkStatus()` function
10. Upon victim MFA completion, the attacker obtains valid access and refresh tokens
11. Configuration flag `persistAfterPassChange: false` signals operator understanding that refresh tokens revoke on password reset (PRTs persist longer)

### 3. Primary Refresh Token Persistence

The PRT management API represents EvilTokens' core differentiator over traditional AitM phishing platforms:

| Endpoint | Function |
|----------|----------|
| `POST /api/prt/convert` | Converts refresh token to Primary Refresh Token |
| `POST /api/prt/refresh` | Obtains fresh access tokens using PRT |
| `POST /api/prt/exchange` | Obtains access tokens for resource shortcuts |
| `POST /api/prt/cookie` | Generates browser SSO cookies from PRT |
| `POST /api/prt/owa-session` | Obtains Outlook Web Access session cookies |
| `POST /api/prt/recon` | Performs Graph API reconnaissance |
| `POST /api/prt/azure` | Azure environment enumeration |
| `/prt/setup` | Initial PRT configuration |
| `/prt/renew` | PRT renewal |
| `/prt/reacquire` | PRT reacquisition after expiration |

PRTs enable persistence beyond password resets by registering new devices to generate long-lived credentials.

### 4. Post-Compromise BEC Operations (ARTSender)

After obtaining tokens, operators have access to:

**Email Operations:**
- Full Outlook inbox read access via Microsoft Graph API
- Email sending as the compromised user with batch BCC support and configurable inter-send delays
- Inbox rule creation for forwarding and auto-deletion (evidence suppression)
- Cross-account keyword monitoring ("Box Monitor") across all compromised accounts simultaneously
- Email attachment access and download

**SharePoint/OneDrive:**
- Site resolution, file browsing, upload, download, and permission management
- Document theft and malicious file placement capabilities

**AI-Augmented BEC:**
- Groq-hosted Llama models for financial exposure scoring
- GPT-4o-mini for email translation
- Produces three tailored BEC scenarios per compromised mailbox

**Desktop Tool:**
- ARTBrowser: Windows application enabling token-based Microsoft 365 session browsing outside the web panel
- $500 lifetime license (separate from platform subscription)

### 5. Anti-Analysis and Evasion Techniques

**Client-Side 7-Layer Anti-Analysis System:**

| Layer | Mechanism | Details |
|-------|-----------|---------|
| 1 | User-Agent blocking | Blocks headless browsers, Selenium, Puppeteer, Playwright, crawlers, wget, curl |
| 2 | `navigator.webdriver` | Detects automation framework presence |
| 3 | Browser fingerprinting | Checks for missing `window.chrome`, `navigator.vendor`, touch/mouse APIs |
| 4 | Window dimensions | Detects headless defaults (0x0 outer dimensions) |
| 5 | Interaction telemetry | Requires 3+ mouse moves OR 1+ touch events before proceeding |
| 6 | Timing gate | Enforces minimum 800ms elapsed since page load |
| 7 | Movement analysis | Validates mouse trajectories for organic (non-linear) motion |

**Payload Encryption:**
- XOR encryption with 16-byte key: `[233, 69, 224, 219, 53, 48, 213, 165, 119, 243, 77, 151, 101, 148, 15, 227]` (hex: `E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3`)
- Uses `crypto.subtle.decrypt()` with AES-GCM for runtime decryption
- Payload decrypts at runtime to evade static URL scanner analysis
- Decrypted content injected via `document.body.innerHTML`

**Server-Side Defense:**
- `X-Antibot-Token` header: SHA-256(secret + timestamp + "_antibot") with 5-minute validity window
- Over 900 confirmed instances of this header observed via urlquery as of March 2026

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | dashboard-bl[.]pamconj[.]com | ARToken panel dashboard |
| Domain | spx[.]pamconj[.]com | ARToken C2 API backend |
| Domain | clear90489058903-document[.]workers[.]dev | Cloudflare Workers phishing host |
| Domain | mononapfpcom[.]sharepoint[.]com | SharePoint lookalike for phishing |
| Domain | authdocspro[.]com | EvilTokens affiliate self-hosted domain |
| Domain | notificationsmanagersec[.]com | EvilTokens affiliate self-hosted domain |
| Domain | serenitygovsupplys[.]com | EvilTokens affiliate self-hosted domain |
| Domain | eventcalender-schedule[.]com | EvilTokens affiliate self-hosted domain |
| Domain | framebound[.]cloud | EvilTokens affiliate self-hosted domain |
| Domain | suctwocesonesstory[.]com | EvilTokens affiliate self-hosted domain |
| Domain | mirsanotolastik[.]com | EvilTokens affiliate self-hosted domain |
| Domain | smstltle[.]net | EvilTokens affiliate self-hosted domain |
| Domain | topbuysella[.]com | EvilTokens affiliate self-hosted domain |
| Domain | totalhomesafe[.]com | EvilTokens affiliate self-hosted domain |
| Domain | youremplregroup[.]com | EvilTokens affiliate self-hosted domain |
| Domain | infinitechai[.]org | EvilTokens affiliate self-hosted domain |
| Domain | evobothub[.]org | EvilTokens affiliate self-hosted domain |
| Domain | newmobilepolojean[.]com | EvilTokens affiliate self-hosted domain |
| Domain | macmamo[.]com | EvilTokens affiliate self-hosted domain |
| Domain | prcservis[.]com | EvilTokens affiliate self-hosted domain |
| URL Pattern | `hxxps://{template}-[a-z0-9]{3}[.][a-z0-9-]{3,}-s-account[.]workers[.]dev` | Cloudflare Workers phishing pattern |
| URL Pattern | `/api/device/start` | Device code initiation endpoint |
| URL Pattern | `/api/device/status/{sessionId}` | Authentication status polling |
| URL Pattern | `/api/prt/*` | PRT management endpoints |
| HTTP Header | `X-Antibot-Token` | EvilTokens anti-analysis header (SHA-256 hash) |
| IP Range | 162[.]220[.]232[.]0/24 | Railway.com sign-in infrastructure |
| IP Range | 162[.]220[.]234[.]0/24 | Railway.com sign-in infrastructure |
| IP Range | 89[.]150[.]45[.]0/24 | HZ Hosting sign-in infrastructure |
| IP Range | 185[.]81[.]113[.]0/24 | HZ Hosting sign-in infrastructure |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Web | localStorage key: `artoken_jwt` | N/A | JWT storage key used by ARToken phishing pages |
| Web | Inline image: `pumber.png` | N/A | Signature image used in phishing email mutation |

### Behavioral

- **Device Code Flow Abuse:** Successful `DeviceCodeFlow` authentication events in Azure AD/Entra ID sign-in logs, especially with `ErrorCode 50199` (user interaction pause) followed by `ErrorCode 0` (success)
- **Inbox Rule Manipulation:** `New-InboxRule` or `Set-InboxRule` operations targeting `ForwardTo`, `RedirectTo`, or `DeleteMessage` parameters shortly after device code authentication
- **Non-Standard OAuth Parameter:** POST requests containing `clientMode: "broker"` in the request body, specific to EvilTokens platform
- **Clipboard Hijacking:** Use of `navigator.clipboard.writeText()` on phishing pages to auto-copy device codes
- **Polling Behavior:** Repeated GET requests to `/api/device/status/{id}` at 3-5 second intervals from same source
- **XOR Key:** 16-byte XOR encryption key `E9 45 E0 DB 35 30 D5 A5 77 F3 4D 97 65 94 0F E3` in phishing payloads

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Vendor-impersonation emails with links to device code phishing pages on Cloudflare Workers |
| T1078.004 | Valid Accounts: Cloud Accounts | OAuth tokens obtained via device code flow used to access Microsoft 365 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Stolen access/refresh tokens used for M365 API access |
| T1098.005 | Account Manipulation: Device Registration | PRT acquisition via device registration for persistent access |
| T1114.002 | Email Collection: Remote Email Collection | Full Outlook inbox access via Microsoft Graph API |
| T1114.003 | Email Collection: Email Forwarding Rule | Inbox rules created to forward and auto-delete emails for evidence suppression |
| T1534 | Internal Spearphishing | Compromised accounts used for BEC operations against business partners |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | SharePoint/OneDrive document theft |
| T1583.006 | Acquire Infrastructure: Web Services | Cloudflare Workers used for distributed phishing infrastructure |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communication to panel API endpoints |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | XOR + AES-GCM encrypted phishing payloads |

## Impact Assessment

EvilTokens/ARToken attacks have compromised hundreds of organizations daily at peak activity. The platform specifically targets accounts-payable personnel via invoice-themed vendor impersonation, indicating financial fraud as the primary objective. The 1,380% (37-fold) year-over-year increase in device code phishing attacks -- with at least 11 competing kits -- signals this is a rapidly maturing threat category. The AI-augmented BEC pipeline (financial exposure scoring and automated scenario generation) significantly increases the scalability and sophistication of downstream fraud operations.

Public sector organizations are confirmed targets. The complete BEC operational environment -- from token theft to AI-generated fraud scenarios -- represents a qualitative escalation beyond traditional AitM phishing kits.

## Detection & Remediation

### Immediate Detection

**Azure AD / Entra ID Sign-In Log Queries:**

Detect device code authentication with error 50199 pause pattern:
```
EntraIdSigninEvents
| where ErrorCode in (0, 50199)
| summarize ErrorCodes = make_set(ErrorCode) by AccountUpn, CorrelationId, SessionId, bin(Timestamp, 1h)
| where ErrorCodes has_all (0, 50199)
```

Identify suspicious device registration post-compromise:
```
CloudAppEvents
| where AccountDisplayName == "Device Registration Service"
| extend ServiceName_ = tostring(ActivityObjects[0].Name)
```

Detect suspicious inbox rule creation:
```
CloudAppEvents
| where ApplicationId == "20893"
| where ActionType in ("New-InboxRule","Set-InboxRule")
```

Surface suspicious Graph API email access:
```
CloudAppEvents
| where ApplicationId == "20893"
| where ActionType == "MailItemsAccessed"
| where UncommonForUser has "ISP"
```

**Network IOC Check:**
- Search proxy/DNS logs for queries to `pamconj[.]com`, `authdocspro[.]com`, and other listed IOC domains
- Search HTTP logs for `X-Antibot-Token` header
- Search for Cloudflare Workers subdomains matching `*-s-account.workers.dev`

### Remediation

1. **Immediate:** Revoke all user refresh tokens via `revokeSigninSessions` Microsoft Graph API call for any compromised accounts
2. **Containment:** Consider temporary account disable; standard session revocation leaves access tokens active up to 60 minutes
3. **Inbox Rules:** Audit and remove any suspicious forwarding/deletion inbox rules created post-compromise
4. **Device Audit:** Review Azure AD device registrations for unauthorized entries
5. **Password Reset:** Force password reset, but note that PRTs may persist beyond password changes
6. **Secret Rotation:** Rotate any credentials or sensitive information accessed via compromised mailboxes

### Long-Term Hardening

1. **Block Device Code Flow:** Configure Conditional Access policies to block device code authentication where possible; apply restrictions for necessary scenarios
2. **Phishing-Resistant MFA:** Deploy FIDO2 security keys or Microsoft Authenticator with passkeys; avoid telephony-based MFA
3. **Conditional Access:** Implement sign-in risk policies forcing re-authentication for high-risk detections; block legacy authentication protocols
4. **Safe Links:** Enable Microsoft Defender for Office 365 Safe Links, which generates "high confidence Device Code phishing alerts"
5. **User Education:** Train users that sign-in prompts should require explicit confirmation of application context; never enter device codes from unexpected sources
6. **Monitor:** Enable Microsoft Entra threat intelligence correlation and monitor Risky Sign-in reports

## Detection Rules

These detections target ARToken/EvilTokens infrastructure and device code phishing TTPs at the PoC/advisory-specific altitude. The Sigma rules convert cleanly to both Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify all rules against your telemetry pipeline before production deployment.

### Sigma: Azure AD Device Code Flow Authentication from Suspicious Source

Detects successful device code flow authentication in Azure AD sign-in logs, the primary initial access vector for ARToken/EvilTokens.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check failed due to MITRE ATT&CK data download blocked by proxy (403), not a rule issue. sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Device code flow has legitimate uses (Azure CLI, IoT); filter_known_apps reduces but does not eliminate FPs. Behavioral rule — medium confidence ceiling. -->

```yaml
title: Azure AD Device Code Flow Authentication from Suspicious Source
id: 7a3e8f2d-c1b4-4d6e-9f5a-2b8c0e7d3a1f
status: experimental
description: >
    Detects successful device code flow authentication in Azure AD/Entra ID sign-in logs,
    which is the primary initial access vector used by ARToken/EvilTokens phishing-as-a-service
    platform. Device code phishing tricks victims into entering a code at microsoft.com/devicelogin,
    granting attackers access tokens that bypass MFA.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
author: Actioner
date: 2026-07-06
tags:
    - attack.t1078.004
    - attack.t1550.001
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        AuthenticationProtocol: 'deviceCode'
        ResultType: 0
    filter_known_apps:
        AppDisplayName:
            - 'Azure CLI'
            - 'Azure PowerShell'
            - 'Microsoft Azure PowerShell'
            - 'Azure IoT Hub'
    condition: selection and not filter_known_apps
falsepositives:
    - Legitimate device code authentication from IoT devices, smart TVs, or CLI tools
    - Azure DevOps pipeline authentication
level: medium
```

### Sigma: DNS Query to ARToken EvilTokens C2 Infrastructure

Detects DNS queries to known ARToken/EvilTokens C2 and phishing infrastructure domains identified by Cisco Talos and Sekoia.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. IOC-based rule keying on specific known-malicious domains. High confidence but will age as infrastructure rotates — update IOC list from future reporting. -->

```yaml
title: DNS Query to ARToken EvilTokens C2 Infrastructure
id: 9c4d2e8f-1a7b-4f3e-8d6c-5b0a9e2f7c1d
status: experimental
description: >
    Detects DNS queries to known ARToken/EvilTokens command-and-control and phishing
    infrastructure domains identified by Cisco Talos. Includes the panel dashboard domain
    and the API backend domain used for device code phishing operations.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
author: Actioner
date: 2026-07-06
tags:
    - attack.t1071.001
    - attack.t1583.006
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.pamconj.com'
            - '.authdocspro.com'
            - '.notificationsmanagersec.com'
            - '.serenitygovsupplys.com'
            - '.eventcalender-schedule.com'
            - '.framebound.cloud'
            - '.suctwocesonesstory.com'
            - '.mirsanotolastik.com'
    condition: selection
falsepositives:
    - Unlikely; these are known malicious infrastructure domains
level: high
```

### Sigma: HTTP Request to EvilTokens Device Code Phishing API Endpoints

Detects HTTP requests to the distinctive `/api/device/start`, `/api/device/status/`, and `/api/prt/*` API endpoints used by the EvilTokens platform.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. API path patterns are distinctive to EvilTokens but could theoretically collide with internal apps using similar REST naming. The combination of /api/device/start + /api/prt/* is highly specific. -->

```yaml
title: HTTP Request to EvilTokens Device Code Phishing API Endpoints
id: b2f8a1c3-5d7e-4a9b-8c6f-3e0d1b4a7f2e
status: experimental
description: >
    Detects HTTP requests to the distinctive API endpoints used by the EvilTokens/ARToken
    phishing platform for device code authentication initiation, status polling, and Primary
    Refresh Token management. These endpoints are exposed by the attacker backend infrastructure.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1
author: Actioner
date: 2026-07-06
tags:
    - attack.t1078.004
    - attack.t1550.001
logsource:
    category: proxy
detection:
    selection_device_api:
        cs-uri-stem|contains:
            - '/api/device/start'
            - '/api/device/status/'
            - '/api/device/sessions'
    selection_prt_api:
        cs-uri-stem|contains:
            - '/api/prt/convert'
            - '/api/prt/refresh'
            - '/api/prt/exchange'
            - '/api/prt/cookie'
            - '/api/prt/owa-session'
            - '/api/prt/recon'
            - '/api/prt/azure'
    condition: selection_device_api or selection_prt_api
falsepositives:
    - Custom internal applications using similar API path naming conventions
level: high
```

### Sigma: HTTP Request with EvilTokens X-Antibot-Token Header

Detects outbound HTTP requests containing the `X-Antibot-Token` header, a distinctive EvilTokens infrastructure indicator observed in 900+ instances.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. The cs-header-names field requires proxy logs that capture request header names (e.g., Zscaler, Palo Alto). Not all proxies log individual header names. IOC-specific — X-Antibot-Token is distinctive to EvilTokens. -->

```yaml
title: HTTP Request with EvilTokens X-Antibot-Token Header
id: d5e1c7a9-3f8b-4e2d-9a6c-1b0f4d7e8c3a
status: experimental
description: >
    Detects outbound HTTP requests containing the X-Antibot-Token header, a distinctive
    indicator of EvilTokens phishing infrastructure. This header carries a SHA-256 hash
    computed from a shared secret, Unix timestamp, and the string _antibot, with a 5-minute
    validity window.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1
author: Actioner
date: 2026-07-06
tags:
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        cs-header-names|contains: 'X-Antibot-Token'
    condition: selection
falsepositives:
    - Unlikely; this header name is specific to EvilTokens infrastructure
level: critical
```

### Sigma: Suspicious Inbox Rule Creation via Microsoft Graph API

Detects creation of inbox rules that forward or delete emails, consistent with post-compromise BEC operations by ARToken/EvilTokens operators.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0. sigma convert --without-pipeline -t log_scale exit 0. Behavioral rule — inbox rule creation is common in legitimate use. The combination with ForwardTo/DeleteMessage is more suspicious but not unique to EvilTokens. Medium confidence. -->

```yaml
title: Suspicious Inbox Rule Creation via Microsoft Graph API
id: e8a3f6b2-4c1d-4e7a-9b5f-2d0c8a3e6f1b
status: experimental
description: >
    Detects creation of inbox rules that forward or delete emails, consistent with post-compromise
    BEC operations conducted by ARToken/EvilTokens operators. After obtaining tokens via device
    code phishing, operators create inbox rules to suppress victim notifications and forward
    sensitive communications.
references:
    - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
    - https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
author: Actioner
date: 2026-07-06
tags:
    - attack.t1114.003
    - attack.t1564.008
logsource:
    product: m365
    service: threat_management
detection:
    selection_action:
        Operation:
            - 'New-InboxRule'
            - 'Set-InboxRule'
    selection_suspicious:
        Parameters|contains:
            - 'ForwardTo'
            - 'ForwardAsAttachmentTo'
            - 'RedirectTo'
            - 'DeleteMessage'
    condition: selection_action and selection_suspicious
falsepositives:
    - Legitimate inbox rules created by users for email management
    - Automated email workflows configured by IT administrators
level: medium
```

### Snort: EvilTokens Device Code API and X-Antibot-Token Header

Detects HTTP POST requests to the EvilTokens `/api/device/start` endpoint with `clientMode` in the body, and separately detects the distinctive `X-Antibot-Token` header.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T with minimal config exit 0. Snort 2.9.20 validated. Two rules: sid:2100101 keys on /api/device/start + clientMode body content; sid:2100102 keys on X-Antibot-Token header. Both are IOC/artifact-specific. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - EvilTokens Device Code Phishing API /api/device/start"; flow:established,to_server; content:"POST"; http_method; content:"/api/device/start"; http_uri; fast_pattern; content:"clientMode"; http_client_body; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created 2026-07-06; sid:2100101; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - EvilTokens X-Antibot-Token Header Detected"; flow:established,to_server; content:"X-Antibot-Token"; http_header; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created 2026-07-06; sid:2100102; rev:1;)
```

### Suricata: DNS Queries to ARToken/EvilTokens C2 Domains

Detects DNS queries to the ARToken C2 domain `pamconj.com` and the EvilTokens affiliate domain `authdocspro.com`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). IOC-specific DNS detection. Will age as infrastructure rotates. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to ARToken C2 Domain pamconj.com"; flow:to_server; dns.query; content:"pamconj.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-06; sid:2200101; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to EvilTokens Affiliate Domain authdocspro.com"; flow:to_server; dns.query; content:"authdocspro.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-06; sid:2200102; rev:1;)
```

### Suricata: EvilTokens HTTP API Endpoints and X-Antibot-Token Header

Detects HTTP traffic to EvilTokens API endpoints (`/api/device/start`, `/api/prt/*`) and the distinctive `X-Antibot-Token` header.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Three rules: sid:2200103 device code API + clientMode body; sid:2200104 X-Antibot-Token header; sid:2200105 PRT management API path. All artifact-specific. -->

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - EvilTokens Device Code API Endpoint /api/device/start"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/device/start"; fast_pattern; http.request_body; content:"clientMode"; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-06; sid:2200103; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - EvilTokens X-Antibot-Token Header in HTTP Request"; flow:established,to_server; http.header; content:"X-Antibot-Token"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-06; sid:2200104; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - EvilTokens PRT Management API Endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/prt/"; fast_pattern; classtype:trojan-activity; reference:url,blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/; metadata:author Actioner, created_at 2026-07-06; sid:2200105; rev:1;)
```

### YARA: ARToken EvilTokens Phishing Page Artifacts

Detects ARToken/EvilTokens phishing page HTML/JavaScript content including the `artoken_jwt` localStorage key, XOR decryption key bytes, device code API calls, and anti-analysis checks. Fires on constructed positive sample; quiet on benign HTML.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive test: matched Phishing_ARToken_EvilTokens_Page and Phishing_EvilTokens_Workers_Payload on pos_phishing.html. yara negative test: no match on neg_benign.html. Positive sample constructed from published source strings (artoken_jwt, /api/device/start, X-Antibot-Token, clientMode, navigator.webdriver, navigator.clipboard.writeText, microsoft.com/devicelogin, persistAfterPassChange). Two rules in file: Rule 1 keys on artoken_jwt + API paths or operator UUID or XOR key + crypto.subtle.decrypt or 3-of-N distinctive strings. Rule 2 keys on Workers payload patterns (div#r, AES-GCM, document.body.innerHTML). -->

```yara
rule Phishing_ARToken_EvilTokens_Page
{
    meta:
        description = "Detects ARToken/EvilTokens phishing page HTML/JavaScript artifacts including the artoken_jwt localStorage key, XOR decryption key, device code API calls, and anti-analysis checks"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        severity = "high"

    strings:
        $jwt_key = "artoken_jwt" ascii wide
        $api_start = "/api/device/start" ascii wide
        $api_status = "/api/device/status/" ascii wide
        $antibot = "X-Antibot-Token" ascii wide
        $clientmode = "clientMode" ascii wide
        $broker = "broker" ascii wide
        $xor_key_partial = { E9 45 E0 DB 35 30 D5 A5 }
        $webdriver = "navigator.webdriver" ascii
        $clipboard = "navigator.clipboard.writeText" ascii
        $crypto_decrypt = "crypto.subtle.decrypt" ascii
        $device_login = "microsoft.com/devicelogin" ascii wide
        $persist_flag = "persistAfterPassChange" ascii wide
        $operator_uuid = "84eb384d-cd3e-4c90-a283-c960ce557913" ascii wide

    condition:
        filesize < 5MB and
        (
            ($jwt_key and 1 of ($api_start, $api_status)) or
            ($antibot and $clientmode) or
            ($xor_key_partial and $crypto_decrypt) or
            ($operator_uuid) or
            (3 of ($api_start, $api_status, $antibot, $clientmode, $broker, $webdriver, $clipboard, $device_login, $persist_flag))
        )
}

rule Phishing_EvilTokens_Workers_Payload
{
    meta:
        description = "Detects EvilTokens Cloudflare Workers phishing payload with characteristic DOM manipulation, AES-GCM decryption, and anti-analysis behavior"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1"
        severity = "high"

    strings:
        $dom_placeholder = "<div id=\"r\">" ascii wide
        $aes_gcm = "AES-GCM" ascii wide
        $body_inject = "document.body.innerHTML" ascii wide
        $b64_decode = "atob(" ascii
        $antibot_header = "X-Antibot-Token" ascii wide
        $hint_param = "?hint=" ascii wide
        $device_start = "/device/start" ascii wide

    condition:
        filesize < 2MB and
        (
            ($dom_placeholder and $aes_gcm and $body_inject) or
            ($antibot_header and $device_start) or
            (4 of them)
        )
}
```

## Lessons Learned

1. **Device code authentication is a systemic blind spot.** The OAuth 2.0 device code flow was designed for input-constrained devices but is now weaponized at scale. Organizations should block this flow via Conditional Access policies wherever possible and treat any device code authentication as high-risk.

2. **MFA is not a silver bullet when the victim authenticates on the attacker's behalf.** Unlike traditional credential phishing, device code phishing has the victim complete MFA on Microsoft's legitimate infrastructure. Phishing-resistant authentication methods (FIDO2, passkeys) are the only effective countermeasure.

3. **Primary Refresh Tokens create persistence that survives password resets.** Traditional incident response playbooks that rely on password reset and session revocation are insufficient. Defenders must audit device registrations and revoke PRTs specifically.

4. **AI integration accelerates BEC at scale.** The use of Llama models for financial exposure scoring and GPT-4o-mini for email translation represents a qualitative shift in BEC automation -- compromised mailboxes are now automatically triaged and exploited with tailored fraud scenarios.

5. **PhaaS commoditization is accelerating.** With at least 11 competing device code phishing kits and a 37-fold increase in attacks, this technique has moved from novel to commodity. Detection and prevention must be treated as baseline requirements, not advanced threats.

## Sources

- [Cisco Talos Blog -- ARToken: Inside an EvilTokens affiliate panel targeting Microsoft 365](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/) -- Primary source; full technical analysis of ARToken panel, 80+ API endpoints, anti-analysis system, and BEC operations
- [BleepingComputer -- ARToken PhaaS exposes EvilTokens' Microsoft 365 phishing toolkit](https://www.bleepingcomputer.com/news/security/artoken-phaas-exposes-eviltokens-microsoft-365-phishing-toolkit/) -- Summary with attack scale context (37-fold increase, 11+ competing kits)
- [CyberScoop -- ARToken BEC platform](https://cyberscoop.com/artoken-bec-platform-cisco-talos/) -- Additional operational context and attribution gaps
- [Microsoft Security Blog -- AI-enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/) -- Detection guidance, hunting queries, infrastructure IOCs, Conditional Access recommendations
- [Sekoia -- New widespread EvilTokens kit: device code phishing as-a-service Part 1](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1) -- Initial EvilTokens discovery, Cloudflare Workers patterns, affiliate domain list, X-Antibot-Token mechanism
- [Sekoia -- EvilTokens: an AI-augmented phishing kit for automating BEC fraud Part 2](https://blog.sekoia.io/eviltokens-an-ai-augmented-phishing-as-a-service-for-automating-bec-fraud-part-2/) -- AI-augmented BEC pipeline details (Llama, GPT-4o-mini)

---
*Report generated by Actioner*
