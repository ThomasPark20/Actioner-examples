# Technical Analysis Report: ConnectWise Cloud Backup Supply Chain Attack (2026-10-18)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-18
Version: 2 (REVISED)

## Executive Summary

Between October 13 and 15, 2026, threat actors compromised application credentials belonging to ConnectWise Cloud Backup (formerly SkyKick Cloud Backup) and used them to authenticate directly as the backup application into customer Microsoft 365 / Entra ID tenants. The attackers leveraged the application's pre-existing broad consent -- including `Directory.ReadWrite.All`, full mailbox access, OneDrive/SharePoint, and Teams -- to conduct reconnaissance, self-assign privileged directory roles (Exchange Administrator, Global Administrator), and plant persistence credentials on other trusted applications. Huntress confirmed unauthorized sign-ins across at least 300 of the roughly 1,000 Entra tenants targeted, with 162+ confirmed compromised at time of disclosure. ConnectWise disabled seven application identities and took Cloud Backup, SaaS Security, and Cloud Management services offline on October 17, 2026. The root cause of the initial credential compromise remains under investigation.

## Background

ConnectWise Cloud Backup is a Microsoft 365 backup SaaS product acquired from SkyKick. It operates as a multi-tenant Entra ID enterprise application registered in ConnectWise's vendor tenant (`3f9cd7a0-127a-4ed4-bf06-2f830d5616b7`, "ConnectWise S-K LLC"). When MSPs consent to the application, it receives broad permissions across all managed tenants. Authentication uses a client assertion (certificate-based credential) that lives in the vendor's tenant, meaning the application can authenticate to any consented customer tenant without user interaction and without triggering MFA.

Seven ConnectWise application identities share this trust model, all registered under the same vendor tenant. Older tenants may list these applications under their former "SkyKick Cloud Manager" branding.

## Attack Timeline

All times UTC unless noted.

| Date/Time | Event |
|---|---|
| **Oct 13-14** | Password spray from `144[.]172[.]64[.]128` against four law firm tenants using user-agent `curl/7.88.1`. Scripted OAuth2 token requests from datacenter infrastructure. Smart lockout triggered on two accounts. No successful user sign-ins observed. |
| **Oct 14** | ConnectWise internally identifies suspicious activity through monitoring. |
| **Oct 15, ~01:58** | Approximately 50 Huntress-monitored tenants show ConnectWise Cloud Management service principals self-assigning directory roles, primarily Exchange Administrator. User-agent: `kiota-dotnet`. |
| **Oct 15, 03:44-03:49** | In one tenant, the MS Teams app (`24205314-2b89-4e07-a2a4-579e898a5640`) adds itself to Global Administrator (03:44, again 03:48). It then makes nine changes to two other apps (MSP management tool and Huntress Security Platform): six succeed, three fail. A certificate credential attempt fails on thumbprint mismatch; client secrets succeed. New secrets expire in 2028. User-agent: `Python-urllib/3.12`. |
| **Oct 15, 06:13-08:34** | Cloud Backup app authenticates from `144[.]172[.]64[.]128` and obtains Microsoft Graph tokens across 17 of the first ~290 tenants checked. Tenants are processed in sorted GUID order, seconds apart (scripted). |
| **Oct 15, 08:45** | Last observed malicious sign-in from the original attacker IP. |
| **Oct 15, 09:25-12:35** | First targeted sweep using SkyKick app tokens against ~16 tenants in policy, national security, trade, and critical minerals sectors. Most did not use ConnectWise products. Attempts failed where the service principal was absent. |
| **Oct 15, 13:54-14:20** | Second, apparently manual sweep against the same tenants. Targets: Exchange Online, SharePoint Online, Teams, Azure Resource Manager, Entra, and Office 365 Management APIs. |
| **Oct 16** | Huntress removes unauthorized credential from its own application (used seven times in quick succession). |
| **Oct 16, 19:00** | Huntress confirms 162 compromised tenants. |
| **Oct 17, 05:01** | ConnectWise announces service interruption. |
| **Oct 17, 07:00** | ConnectWise disables seven application identities and revokes certificates. Cloud Backup, SaaS Security, and Cloud Management taken offline. |
| **Oct 17, 10:30** | Huntress reports high-confidence abuse of Exchange Online, Teams, and SharePoint Online Cloud Management apps, noting these apps did not appear disabled. |

## Root Cause

The precise mechanism by which the attacker obtained the ConnectWise application credentials (client assertion / certificate) has not been publicly disclosed. The attack exploited the inherent trust model of multi-tenant Entra ID enterprise applications: once a vendor's credential is compromised, the attacker inherits the application's full consented permissions across every tenant where it is installed. No user interaction, MFA challenge, or Conditional Access evaluation applies to app-only client credential flows.

ConnectWise stated that existing backup archives remain encrypted and isolated with no evidence of breach or access to the backup storage layer itself.

## Technical Analysis

### Initial Access

The attacker authenticated using the ConnectWise Cloud Backup application's own client assertion credential. The authentication was app-only (client credentials grant), meaning:

- No user principal was involved
- MFA did not apply
- Conditional Access policies targeting user sign-ins were bypassed
- The `ConditionalAccessStatus` field showed `notApplied`
- All sign-ins appeared under the **Service principal sign-ins** tab in Entra, not the default User sign-ins tab

The sign-in characteristics included:
- `clientCredentialType`: clientAssertion
- `key_id` and `thumbprint`: empty
- `resource`: Microsoft Graph
- `isCAEToken`: True
- Session IDs beginning with `009ae85a-`

### Reconnaissance and Lateral Movement

The attacker operated from a single IP (`144[.]172[.]64[.]128`, AS14956 RouterHosting, geo-tagged to Cheyenne, WY / Sydney, AU depending on enrichment source). They used automated tooling to iterate through tenant GUIDs in sorted order, requesting Microsoft Graph tokens for each.

Legitimate ConnectWise backup traffic originates from Microsoft-internal private IPv6 addresses in the `fd00::/8` range (specifically `fde4:8dba:2600:37ce:6d26:200:a76:*`). Traffic from a public IPv4 hosting address is anomalous.

### Privilege Escalation

In approximately 50 tenants, ConnectWise service principals self-assigned directory roles:
- **Exchange Administrator** (most common)
- **Global Administrator** (at least one confirmed case via the MS Teams app)

The `Directory.ReadWrite.All` permission allowed the application to modify directory objects including its own role assignments.

### Persistence

The attacker added new client secrets to other trusted enterprise applications:
- An MSP management tool (unnamed)
- Huntress Security Platform application

This technique ensures continued access even after the original ConnectWise credential is rotated, since the newly planted secrets authenticate through different application identities.

A critical detection gap: directory reads through Microsoft Graph leave no audit trail. M365 audit records show Microsoft infrastructure IPs rather than the actor's IP; per-request source IPs are only available in `MicrosoftGraphActivityLogs`, which most tenants were not collecting.

### Token Persistence

Disabling the application in Entra stops new token issuance immediately but already-issued tokens remain valid for up to 90 minutes. Revoking user sessions does not terminate app-level access.

### Targeting Pattern

Huntress observed possible alphabetical targeting, with the most interesting victims' names starting with "A." A separate sweep targeted 16 tenants in policy, national security, trade, and critical mineral sectors, most of which did not use ConnectWise products, suggesting the attacker had a pre-built target list independent of the ConnectWise customer base.

## Indicators of Compromise (IOCs)

> All IPv4 network IOCs are defanged with bracket notation. The IPv6 ULA range below is shown verbatim as it is internal/non-routable and not an attacker indicator. Detection rules in the appendix use real (non-defanged) values.

### Network Indicators

| Indicator | Type | Context |
|---|---|---|
| `144[.]172[.]64[.]128` | IPv4 | Primary attacker IP, AS14956 RouterHosting |
| `fde4:8dba:2600:37ce:6d26:200:a76:*` | IPv6 ULA range | Legitimate ConnectWise/Azure internal traffic; also seen on post-escalation credential additions (not unique to attacker) |

### Application Identities (Compromised)

| Application Name | Application (Client) ID |
|---|---|
| ConnectWise Cloud Backup | `506e08f9-6e9a-4da4-942b-a099a03644ae` |
| ConnectWise Cloud Management | `2399d300-6fca-4e6a-a686-399fefe75b83` |
| ConnectWise Cloud Management - MS Teams | `24205314-2b89-4e07-a2a4-579e898a5640` |
| ConnectWise Cloud Management - Exchange Online | `b78f6a77-d4e5-46fb-87e5-d1648bd02519` |
| ConnectWise Cloud Management - MS Graph | `0de14c77-b9b0-4137-9360-34878a929827` |
| ConnectWise Cloud Management - Partner Center | `412dcf96-176d-4b3a-a1b0-4981ad66971e` |
| ConnectWise Cloud Management - SharePoint Online | `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` |

**Vendor (owner) tenant ID:** `3f9cd7a0-127a-4ed4-bf06-2f830d5616b7` (ConnectWise S-K LLC)

### User-Agent Strings

| User-Agent | Context |
|---|---|
| `curl/7.88.1` | Password spray / scripted OAuth2 token requests (Oct 13-14) |
| `Python-urllib/3.12` | Primary attacker tooling for Graph token acquisition and credential planting |
| `python-requests/2.31` | Listed by ConnectWise in suspicious authentication activity |
| `python-requests/2.34.2` | Additional variant observed |
| `kiota-dotnet` | Used on directory role self-assignments; also used by legitimate ConnectWise apps |

### Behavioral Indicators

- Service principal sign-ins for ConnectWise app IDs from non-Azure/non-Microsoft IP ranges
- Session IDs beginning with `009ae85a-`
- Tenants processed in sorted GUID order with seconds-apart timing
- ConnectWise/SkyKick apps adding themselves to Exchange Administrator or Global Administrator roles
- New client secrets added to enterprise applications by ConnectWise service principals
- Absence of active backup subscription in targeted tenants

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker compromised a trusted vendor's application credentials, gaining access to all consenting tenants |
| T1078.004 | Valid Accounts: Cloud Accounts | Authentication using legitimate ConnectWise application identity |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | App-only client credential flow bypassing user-based MFA and Conditional Access |
| T1528 | Steal Application Access Token | Obtained Graph tokens for customer tenants using stolen application credentials |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Service principals self-assigned Exchange Administrator and Global Administrator roles |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | New client secrets planted on MSP management tools and security applications |
| T1530 | Data from Cloud Storage | Potential access to SharePoint and OneDrive data through consented permissions |
| T1114.002 | Email Collection: Remote Email Collection | Full mailbox access available through Exchange Web Services consent |

## Impact Assessment

- **Scale:** ~1,000 Entra tenants had sign-ins from the attacker IP; 300+ succeeded; 162+ confirmed compromised by Huntress
- **Data at risk:** Email (full mailbox via EWS), OneDrive/SharePoint files, Teams chats, directory data
- **Persistence risk:** Client secrets planted on other applications survive rotation of the original ConnectWise credential
- **Service disruption:** ConnectWise Cloud Backup, SaaS Security, and Cloud Management offline with no restoration timeline
- **Sectors targeted:** Policy, national security, trade, critical minerals (targeted sweep), law firms (password spray)
- **Detection gap:** Directory reads via Graph leave no audit trail; per-request IPs require `MicrosoftGraphActivityLogs` (Entra ID P1/P2), which most affected tenants were not collecting

## Detection & Remediation

### Immediate Actions

1. **Disable all seven ConnectWise/SkyKick applications** in every managed tenant. In Entra: Enterprise applications > Properties > set "Enabled for users to sign-in" to **No**. Disable, do not delete (deletion removes consent and complicates re-enablement).

2. **Review service principal sign-in logs** (Monitoring > Sign-in logs > **Service principal sign-ins** tab, not User sign-ins) from October 13, 2026 onward, filtered by each of the seven application IDs. Flag any sign-ins from `144[.]172[.]64[.]128` or any non-Microsoft IP.

3. **Audit all credential additions** (client secrets and certificates) on enterprise applications and app registrations since October 13, 2026. Remove any you did not create.

4. **Review directory role assignments.** Check if any ConnectWise/SkyKick app holds Global Administrator, Exchange Administrator, or Privileged Authentication Administrator. Remove any role not intentionally granted.

5. **Check for persistence in other apps.** Inspect credentials on all enterprise applications, especially MSP management tools and security platforms. Rotate any secrets that may have been planted.

6. **Preserve sign-in and audit logs** before any containment actions (log retention may be limited, especially on Entra ID Free with 7-day retention).

7. **Review for downstream impact:** unauthorized mailbox forwarding, inbox/transport rules, delegated mailbox access, federation trust changes, Conditional Access exclusions for these apps, and recent OAuth consent grants.

### Hardening Recommendations

- **Application management policies:** Restrict or block client secrets on enterprise applications; cap credential lifetimes
- **Least-privilege roles:** Limit who holds Application Administrator and Cloud Application Administrator
- **Conditional Access for workload identities:** Restrict service principal sign-in locations (requires Entra ID P2 Workload Identities licensing)
- **Microsoft Entra ID Protection:** Enable risky service principal detection
- **Enable MicrosoftGraphActivityLogs:** Provides per-request source IPs for Graph API calls (Entra ID P1/P2 required; not retroactive)
- **Review all multi-tenant apps:** Audit consent grants, remove unused applications, enforce least-privilege consent

### Token Lifetime Caveat

Disabling an app blocks new token issuance immediately but already-issued tokens remain valid for up to **90 minutes**. Revoking user sessions does **not** terminate app-level access. Plan containment accordingly.

## Detection Rules

### Sigma: ConnectWise Cloud Backup Suspicious Service Principal Sign-In

Detects service principal sign-ins for the seven compromised ConnectWise application IDs from the known attacker IP `144.172.64.128`.

```yaml
title: ConnectWise Cloud Backup App Suspicious Service Principal Sign-In
id: f8a2c4e1-3d7b-4a91-b5e6-9c0d2f1a8b34
status: experimental
description: >
    Detects service principal sign-ins for compromised ConnectWise Cloud Backup
    (formerly SkyKick) application identities from the known attacker IP address
    144.172.64.128. In October 2026, attackers used stolen application credentials
    to authenticate as these apps and access Microsoft 365 tenant data.
    Confidence: HIGH - matches known attacker IP against specific compromised app IDs.
references:
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
    - https://thehackernews.com/2026/10/connectwise-suspends-cloud-backup-after.html
author: Actioner
date: 2026-10-18
tags:
    - attack.t1078.004
    - attack.t1550.001
# NOTE: This rule targets AADServicePrincipalSignInLogs (service principal sign-ins),
# not the default SigninLogs (user sign-ins). Some backends may require a custom
# pipeline to resolve this log source correctly.
logsource:
    product: azure
    service: aadserviceprincipalsigninlogs
detection:
    selection_app:
        AppId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '2399d300-6fca-4e6a-a686-399fefe75b83'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - 'b78f6a77-d4e5-46fb-87e5-d1648bd02519'
            - '0de14c77-b9b0-4137-9360-34878a929827'
            - '412dcf96-176d-4b3a-a1b0-4981ad66971e'
            - 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
    selection_ip:
        IpAddress: '144.172.64.128'
    condition: selection_app and selection_ip
falsepositives:
    - Legitimate ConnectWise Cloud Backup operations routed through this IP (unlikely given it is a RouterHosting VPS)
level: critical
```

**File:** `rules/sigma/connectwise-cloud-backup-sp-signin.yml`

### Sigma: ConnectWise App Self-Assigning Directory Role

Detects ConnectWise/SkyKick service principals adding themselves to Entra ID directory roles, the primary escalation technique observed in ~50 tenants.

```yaml
title: ConnectWise App Self-Assigning Directory Role
id: a7e3b1d9-5c2f-4e80-9a16-8d4f0e3c7b52
status: experimental
description: >
    Detects ConnectWise Cloud Management or SkyKick service principals adding
    themselves to Entra ID directory roles such as Exchange Administrator or Global
    Administrator. This behavior was observed in approximately 50 tenants during
    the October 2026 ConnectWise supply chain attack.
    Confidence: HIGH - role self-assignment by a backup application is not expected behavior.
references:
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
author: Actioner
date: 2026-10-18
tags:
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
# NOTE: 'InitiatedBy.app.appId' uses dot-notation for a nested JSON property.
# A Sigma pipeline or field mapping may be required for correct conversion.
detection:
    selection_operation:
        OperationName: 'Add member to role'
    selection_initiator:
        InitiatedBy.app.appId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '2399d300-6fca-4e6a-a686-399fefe75b83'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - 'b78f6a77-d4e5-46fb-87e5-d1648bd02519'
            - '0de14c77-b9b0-4137-9360-34878a929827'
            - '412dcf96-176d-4b3a-a1b0-4981ad66971e'
            - 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
    condition: selection_operation and selection_initiator
falsepositives:
    - Legitimate ConnectWise role configuration during initial product setup (rare and should be documented)
level: critical
```

**File:** `rules/sigma/connectwise-cloud-backup-directory-role.yml`

### Sigma: Credential Addition to Service Principal by ConnectWise App

Detects ConnectWise apps adding credentials to other service principals, the persistence mechanism used to plant secrets on MSP management tools and security platforms.

```yaml
title: Credential Addition to Service Principal by ConnectWise App
id: c5d8f2a6-4b19-4e73-8c0a-6e9d3f7b1a45
status: experimental
description: >
    Detects ConnectWise or SkyKick application identities adding credentials
    (client secrets or certificates) to other service principals. During the
    October 2026 supply chain attack, compromised ConnectWise apps added new
    client secrets to MSP management tools and security applications for
    persistence. Secrets were observed with expiry dates in 2028.
    Confidence: HIGH - credential addition by a backup application to unrelated
    service principals is anomalous.
references:
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
author: Actioner
date: 2026-10-18
tags:
    - attack.t1098.001
logsource:
    product: azure
    service: auditlogs
# NOTE: 'InitiatedBy.app.appId' uses dot-notation for a nested JSON property.
# A Sigma pipeline or field mapping may be required for correct conversion.
detection:
    selection_operation:
        OperationName:
            - 'Update application - Certificates and secrets management'
            - 'Add service principal credentials'
    selection_initiator:
        InitiatedBy.app.appId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '2399d300-6fca-4e6a-a686-399fefe75b83'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - 'b78f6a77-d4e5-46fb-87e5-d1648bd02519'
            - '0de14c77-b9b0-4137-9360-34878a929827'
            - '412dcf96-176d-4b3a-a1b0-4981ad66971e'
            - 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
    condition: selection_operation and selection_initiator
falsepositives:
    - Legitimate credential rotation by ConnectWise during scheduled maintenance
level: high
```

**File:** `rules/sigma/connectwise-cloud-backup-credential-addition.yml`

### Sigma: ConnectWise App Sign-In with Suspicious User-Agent

Detects ConnectWise app sign-ins using Python/curl user-agents associated with the attacker's tooling, distinct from the legitimate `kiota-dotnet` agent.

```yaml
title: ConnectWise App Sign-In with Suspicious User-Agent
id: e4b7a3c8-6d15-4f92-a8e1-2c9f0d5b4a67
status: experimental
description: >
    Detects service principal sign-ins for ConnectWise Cloud Backup or Cloud
    Management apps using user-agent strings associated with the October 2026
    supply chain attack tooling (Python-urllib, python-requests, curl). Legitimate
    ConnectWise traffic uses the kiota-dotnet user-agent from Azure infrastructure.
    Confidence: MEDIUM - user-agent strings can be spoofed, but these specific
    combinations with ConnectWise app IDs are strong indicators.
references:
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
    - https://todyl.com/blog/investigation-unauthorized-access-through-the-connectwise-cloud-backup-microsoft-365-app
author: Actioner
date: 2026-10-18
tags:
    - attack.t1078.004
    - attack.t1550.001
# NOTE: This rule targets AADServicePrincipalSignInLogs (service principal sign-ins),
# not the default SigninLogs (user sign-ins). Some backends may require a custom
# pipeline to resolve this log source correctly.
# NOTE: 'UserAgent' field may appear nested in some Entra schemas. Verify field
# mapping in your pipeline.
logsource:
    product: azure
    service: aadserviceprincipalsigninlogs
detection:
    selection_app:
        AppId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '2399d300-6fca-4e6a-a686-399fefe75b83'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - 'b78f6a77-d4e5-46fb-87e5-d1648bd02519'
            - '0de14c77-b9b0-4137-9360-34878a929827'
            - '412dcf96-176d-4b3a-a1b0-4981ad66971e'
            - 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
    selection_ua:
        UserAgent|contains:
            - 'Python-urllib'
            - 'python-requests'
            - 'curl/'
    condition: selection_app and selection_ua
falsepositives:
    - Custom integrations or testing scripts using these user agents against ConnectWise apps
level: high
```

**File:** `rules/sigma/connectwise-cloud-backup-suspicious-ua.yml`

### Suricata: ConnectWise Cloud Backup Attacker IP

Alerts on any traffic to or from the known attacker IP `144.172.64.128`.

```
alert ip 144.172.64.128 any -> $HOME_NET any (msg:"ACTIONER CTI ConnectWise Cloud Backup Supply Chain - Attacker IP Inbound"; reference:url,www.huntress.com/blog/vendor-credential-enables-unauthorized-access; classtype:trojan-activity; sid:2026101801; rev:2;)
alert ip $HOME_NET any -> 144.172.64.128 any (msg:"ACTIONER CTI ConnectWise Cloud Backup Supply Chain - Attacker IP Outbound"; reference:url,www.huntress.com/blog/vendor-credential-enables-unauthorized-access; classtype:trojan-activity; sid:2026101802; rev:2;)
```

**File:** `rules/suricata/connectwise-cloud-backup.rules`

### Detection Confidence Summary

| Rule | Confidence | Notes |
|---|---|---|
| SP Sign-In from Attacker IP | HIGH | Known attacker IP + specific compromised app IDs |
| Directory Role Self-Assignment | HIGH | Role self-assignment by backup app is never expected |
| Credential Addition | HIGH | Credential planting on unrelated apps is anomalous |
| Suspicious User-Agent | MEDIUM | User-agents are spoofable; combined with app ID filter improves fidelity |
| Suricata Attacker IP | HIGH | Direct IP match; limited shelf life |

### Supplementary Hunting Leads

The following indicators are supplementary hunting leads not covered by the detection rules above. They require manual investigation and context before escalation.

**Session ID prefix `009ae85a-`:** All malicious service principal sign-ins observed in this campaign shared session IDs beginning with `009ae85a-`. This prefix may be an artifact of the attacker's tooling or token request configuration. Hunt query: filter `AADServicePrincipalSignInLogs` for `CorrelationId` or `SessionId` values starting with `009ae85a-` in the October 13-17 window. Note: this is a weak indicator on its own and may match legitimate sessions; correlate with other IOCs before actioning.

**`kiota-dotnet` user-agent coverage gap:** The `kiota-dotnet` user-agent string was used by the attacker during the privilege escalation phase (directory role self-assignments). However, this is also the legitimate user-agent for ConnectWise Cloud Management traffic. A detection rule filtering on `kiota-dotnet` alone would produce excessive false positives. This user-agent is therefore excluded from the Suspicious User-Agent rule. Analysts should investigate `kiota-dotnet` sign-ins only when correlated with other indicators (non-Microsoft source IP, unexpected role assignment activity, or presence in a tenant that does not use ConnectWise products).

### YARA

No YARA rules generated. This attack operated entirely through cloud identity abuse (OAuth2 client credential flows, Graph API access, directory role manipulation). No file-based malware, binaries, or on-disk artifacts were reported by any source.

## Sources

- [BleepingComputer: Hackers breach Microsoft 365 tenants via ConnectWise supply chain attack](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/)
- [The Hacker News: ConnectWise Suspends Cloud Backup After Supply Chain Attack](https://thehackernews.com/2026/10/connectwise-suspends-cloud-backup-after.html)
- [The Hacker News: Hackers Use Compromised ConnectWise Cloud Backup](https://thehackernews.com/2026/10/hackers-use-compromised-connectwise.html)
- [Huntress: Vendor Credential Enables Unauthorized Access](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access)
- [Todyl: Investigation - Unauthorized Access Through the ConnectWise Cloud Backup Microsoft 365 App](https://todyl.com/blog/investigation-unauthorized-access-through-the-connectwise-cloud-backup-microsoft-365-app)
- [ConnectWise Trust Advisories](https://www.connectwise.com/company/trust/advisories)
- [ConnectWise Status Incident](https://status.connectwise.com/pages/incident/619cf82551fec9053d612f09/6ad263692dc48705ab3da2cb)
