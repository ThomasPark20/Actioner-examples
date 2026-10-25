# Technical Analysis Report: Storm-0940 ARTEX ConnectWise Supply Chain Attack (2026-10-25)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-25
Version: 0.1 (DRAFT)

## Executive Summary

Storm-0940, a China-state-aligned threat group tracked by Microsoft since 2021, compromised ConnectWise Cloud Backup (formerly SkyKick) application credentials and used the ARTEX agentic AI penetration testing framework to automate a supply chain attack against Microsoft 365 environments at scale. The attackers stole an API client secret for the ConnectWise multi-tenant OAuth application and used it to authenticate as the ConnectWise service principal across more than 2,250 downstream tenants. Huntress confirmed 162 unauthorized sign-ins, with over 300 successful authentications observed out of nearly 1,000 attempted Entra tenants. In at least two partner tenants, the compromised application escalated to Global Administrator and planted long-lived credentials (expiring 2028) on other applications for persistent backdoor access. The campaign targeted aerospace, defense, energy, financial services, government, semiconductor, technology, and think tank organizations across multiple regions.

The attack was accelerated by ARTEX, a Go-based open-source multi-agent AI framework that automates reconnaissance through data exfiltration. Microsoft observed the AI agents achieving privileged cloud access within three hours of initial targeting. Between October 10-14, a password spray phase generated over 151,000 failed logons at peak rates of 2,900 failures per minute. On October 15, the actors pivoted to abusing the stolen ConnectWise credentials, systematically authenticating across tenants in sorted GUID order and conducting Microsoft Graph reconnaissance, directory role assignments, and application credential modifications.

## Background: ConnectWise Cloud Backup and Microsoft 365 Integration

ConnectWise Cloud Backup (formerly SkyKick) is a widely deployed SaaS backup solution for Microsoft 365 environments used by managed service providers (MSPs) and their customers. The product operates as a multi-tenant OAuth application registered in Microsoft Entra ID (formerly Azure AD). Once authorized by a customer tenant, the application's service principal gains delegated or application-level permissions to access Exchange Online, SharePoint Online, Microsoft Teams, and Microsoft Graph APIs for backup operations. The multi-tenant architecture means a single compromised application credential (client secret or client assertion) can be used to request access tokens in any tenant where the application is installed -- without requiring any customer action or interactive sign-in.

ConnectWise also operates several related Cloud Management applications (MS Teams, Exchange Online, MS Graph, Partner Center, SharePoint Online) that share elevated permissions across customer environments, broadening the attack surface when their credentials are compromised.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 17, 2026 | Earliest activity linked to TAG-217 (Recorded Future tracking name) testing infrastructure for remote access |
| Early September 2026 | Storm-0940 begins using ARTEX framework to automate attacks on hundreds of organizations |
| October 10-14, 2026 | Cross-tenant password spray from 144.172.64[.]99 targeting 327 accounts across eight organizations; 151,000+ failed logons, peaking at 2,900/min on Oct 11 |
| October 13-14, 2026 | Scripted OAuth2 token requests and password spray from 144.172.64[.]128 against law firm tenants; accounts locked by smart lockout |
| October 15, 01:58 | ConnectWise Cloud Management service principals self-assign Exchange Administrator role in ~50 Huntress-monitored tenants |
| October 15, 03:44-03:49 | In one partner tenant: MS Teams app self-assigns Global Administrator; Python script adds credentials to two other applications (six succeed, three fail) |
| October 15, 06:13-08:34 | Token acquisition from 144.172.64[.]128 across tenants in sorted GUID order; 17 of first ~290 tenants authenticated successfully |
| October 15, 08:44 | Last confirmed successful sign-in with the stolen credential |
| October 15, 09:25-12:35 | Targeted wave against 16 tenants in policy, national security, trade, and critical minerals sectors |
| October 15, 13:54-14:20 | Manual second sweep targeting Exchange Online, SharePoint, Teams, ARM, Entra, and O365 Management APIs |
| October 15, 2026 | Microsoft Threat Intelligence observes broad successful sign-ins; Huntress publishes initial findings |
| October 16, 2026 | ConnectWise publishes advisory; Huntress confirms 162 unauthorized sign-ins; identifies and removes unauthorized credential from Huntress app |
| October 17, 05:00 | ConnectWise mitigations begin; services suspended |
| October 18, 2026 | ConnectWise temporarily shuts down Cloud Backup, SaaS Security, and Cloud Management services |
| October 21, 2026 | Microsoft publishes full attribution report; ConnectWise begins phased service restoration |

## Root Cause: Stolen Multi-Tenant OAuth Application Secret

The root cause was the theft of a highly sensitive API client secret (or client assertion) used by the ConnectWise Cloud Backup application to authenticate to Microsoft 365 environments. ConnectWise has not disclosed how the credential was obtained; the root cause remains under investigation. The credential's multi-tenant nature meant that anyone holding it could request access tokens in any tenant where the application was installed, without customer action and bypassing MFA (since application-level authentication does not require interactive sign-in).

The authentication used a client assertion, confirming the credential resided in the vendor's tenant. Customer-side actions could not have produced or prevented this compromise. This is a classic supply chain trust relationship abuse -- the attacker inherited all permissions previously consented to by downstream tenants.

## Technical Analysis of the Malicious Payload

### 1. ARTEX Agentic AI Framework

ARTEX is an open-source (later closed-source after abuse) penetration testing framework written in Go with a Next.js frontend. It uses multiple LLM agents to automate the full attack lifecycle from reconnaissance through data exfiltration with minimal human input. Key characteristics:

- **Multi-agent architecture:** Agents build a graph of discovered assets and vulnerabilities as the test proceeds
- **Model-agnostic:** Works with any AI model via OpenAI-compatible gateways; configurations found using DeepSeek, GLM, and Grok models
- **Cross-model review:** Prompts split tasks across models with peer review (e.g., GLM reviewing DeepSeek subagent work)
- **UI languages:** English (default), Korean, Mandarin, Spanish, Japanese
- **Zscaler findings:** Custom ARTEX deployments contained AI assistant configurations, synchronization scripts, network routing tools, and a Claude Code prompt history
- **Session behavior (Wiz):** Some sessions lasted 24-30 hours; when IPs were blocked, new addresses appeared within minutes

The ARTEX-driven attack sequence (observed by Wiz):
1. Discover internal API routes and application functionality
2. Repeatedly start sign-in flows and probe SSO/M365 endpoints
3. Password-spray corporate Okta and Entra ID environments
4. Invoke password-reset, username-recovery, activation, and reset-token endpoints
5. Register accounts with throwaway emails where possible
6. Scan for broken access controls and unauthorized cross-tenant data access
7. Rotate IP addresses when blocked

### 2. Application Credential Abuse and Lateral Movement

Once the ConnectWise application secret was obtained, the attack proceeded through:

**Token acquisition phase:**
- Automated token requests from 144.172.64[.]128 across tenants in sorted GUID order, a few seconds apart, indicating a scripted target list
- Authenticated in 17 of the first ~290 tenants checked
- Used user agents: `Python-urllib/3.12`, `python-requests/2.31.0`, `curl/7.88.1`, `azure-toolkit/1.0`

**Privilege escalation:**
- Service principals self-assigned Exchange Administrator role in ~50 tenants
- In at least one tenant: MS Teams app (24205314-2b89-4e07-a2a4-579e898a5640) self-assigned Global Administrator
- Used `kiota-dotnet` user agent for directory role assignments (mimicking vendor automation)

**Persistence:**
- Added long-lived client secrets (expiring 2028) to other applications via Python scripts
- Six credential additions succeeded, three failed (certificate thumbprint mismatch)
- Targeted MSP management applications and security tool applications (including Huntress)
- These planted credentials survive disabling or remediating the original ConnectWise application

### 3. C2 Infrastructure

The attack infrastructure was hosted at RouterHosting (AS14956):

| IP Address | Role |
|---|---|
| 144.172.64[.]60 | Limited failed user logins (Oct 18) |
| 144.172.64[.]99 | Primary password spray source (Oct 10-14) |
| 144.172.64[.]128 | Primary application sign-in and post-compromise activity |
| 144.172.94[.]243 | Broad ongoing failed login spray |

Transient VPN IPs used for Graph access (Oct 15-16):
| IP Address | Role |
|---|---|
| 187.15.88[.]186 | Graph access via compromised apps |
| 187.15.89[.]186 | Graph access via compromised apps |
| 187.15.90[.]217 | Graph access via compromised apps |

### 4. Microsoft Graph and Cloud API Abuse

Post-authentication activity included:
- Graph SharePoint enumeration
- Mailbox access through Microsoft Graph (reading email, accessing Teams messages)
- Bulk reads of Azure Key Vault secrets across multiple vaults
- Key enumeration and key-unwrap operations
- Changes to identities, groups, and privileged roles
- Attempts to add credentials to service principals for persistent backdoor access

### 5. Anti-Forensics / Evasion Techniques

- **Audit gap exploitation:** Directory reads through Microsoft Graph leave no audit record, preventing confirmation of data access
- **User agent mimicry:** Used `kiota-dotnet` (ConnectWise SDK agent) for role assignments to blend with legitimate vendor traffic
- **Sorted GUID targeting:** Systematic token acquisition in alphabetical order suggests automated, methodical enumeration
- **IP rotation:** When blocked, new addresses appeared within minutes
- **IPv6 ULA overlap:** Attacker traffic shared `fde4:8dba:2600:37ce:6d26:200:a76:*` range with legitimate ConnectWise traffic
- **Long credential lifetimes:** Planted secrets set to expire in 2028, surviving immediate remediation

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `144.172.64[.]99`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| ConnectWise Cloud Backup (SkyKick) | N/A -- credential theft | Application client secret stolen; app ID `506e08f9-6e9a-4da4-942b-a099a03644ae` |
| ConnectWise Cloud Management | N/A -- credential theft | App ID `2399d300-6fca-4e6a-a686-399fefe75b83` |
| Cloud Management - MS Teams | N/A -- credential abuse | App ID `24205314-2b89-4e07-a2a4-579e898a5640`; self-assigned Global Admin |
| Cloud Management - Exchange Online | N/A -- credential abuse | App ID `b78f6a77-d4e5-46fb-87e5-d1648bd02519` |
| Cloud Management - MS Graph | N/A -- credential abuse | App ID `0de14c77-b9b0-4137-9360-34878a929827` |
| Cloud Management - Partner Center | N/A -- credential abuse | App ID `412dcf96-176d-4b3a-a1b0-4981ad66971e` |
| Cloud Management - SharePoint Online | N/A -- credential abuse | App ID `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` |

Vendor (application owner) tenant ID: `3f9cd7a0-127a-4ed4-bf06-2f830d5616b7`

### File System

No file system artifacts identified. This was a cloud-native attack operating entirely through OAuth/Graph APIs.

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 144.172.64[.]60 | Failed user logins (Oct 18) -- AS14956 RouterHosting |
| IP | 144.172.64[.]99 | Primary password spray source (Oct 10-14) -- AS14956 RouterHosting |
| IP | 144.172.64[.]128 | Primary app sign-in and post-compromise activity -- AS14956 RouterHosting |
| IP | 144.172.94[.]243 | Broad ongoing failed login spray -- AS14956 RouterHosting |
| IP | 187.15.88[.]186 | Transient VPN -- Graph access via compromised apps |
| IP | 187.15.89[.]186 | Transient VPN -- Graph access via compromised apps |
| IP | 187.15.90[.]217 | Transient VPN -- Graph access via compromised apps |

### Behavioral

- Service principal sign-ins from non-Azure IP ranges (expected: Azure private IPv6 space) for ConnectWise applications
- Service principals self-assigning directory roles (Exchange Administrator, Global Administrator)
- Application credential additions (client secrets) by service principals to other applications
- Token acquisition across many tenants in sorted GUID order within seconds
- User agents `Python-urllib/3.12`, `python-requests/2.31.0`, `python-requests/2.34.2`, `curl/7.88.1`, `azure-toolkit/1.0` for service principal authentication
- Bulk Azure Key Vault SecretGet operations (20+ across 3+ vaults in 15-minute windows)
- Application role assignments by service principals to themselves

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Stolen ConnectWise Cloud Backup application secret used to access downstream customer M365 tenants |
| T1199 | Trusted Relationship | Abuse of pre-authorized multi-tenant OAuth application trust to reach customer environments |
| T1078.004 | Valid Accounts: Cloud Accounts | Authentication as ConnectWise service principals using stolen client assertion/secret |
| T1528 | Steal Application Access Token | Theft of OAuth application credential to obtain tokens without interactive user sign-in |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Adding long-lived client secrets (expiring 2028) to other applications for persistent access |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Self-assignment of Global Administrator and Exchange Administrator roles by compromised service principals |
| T1087.004 | Account Discovery: Cloud Account | Graph-based enumeration of directories, permissions, approvals, and identities |
| T1110.003 | Brute Force: Password Spraying | Over 151,000 failed logons across 327 accounts at 2,900 attempts/min |
| T1071.001 | Application Layer Protocol: Web Protocols | Microsoft Graph API abuse for reconnaissance, mail access, and credential modification |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Bulk reads of Azure Key Vault secrets, key enumeration, and key-unwrap operations |
| T1114.002 | Email Collection: Remote Email Collection | Mailbox access through Microsoft Graph; reading email and Teams messages |

## Impact Assessment

**Breadth:** Over 2,250 tenants received sign-in attempts; 300+ successful authentications; 162 confirmed unauthorized sign-ins (Huntress). Tens of thousands of ConnectWise customer tenants potentially at risk. Targeted sectors span aerospace, defense, energy, financial services, government, legal, manufacturing, military, semiconductor, software, technology, and think tanks/non-profits.

**Depth:** In at least two tenants, the attackers achieved Global Administrator access and planted persistent credentials on third-party applications. Bulk Azure Key Vault secret reads, mail access, and directory modifications were observed. The full extent of data exfiltration is unknown due to Microsoft Graph audit gaps (directory reads are not logged).

**Stealth:** The attack exploited a fundamental audit blind spot -- Microsoft Graph directory reads produce no audit trail. IPv6 ULA overlap with legitimate ConnectWise traffic complicated attribution. User agent mimicry using `kiota-dotnet` blended privilege escalation with legitimate vendor automation.

## Detection & Remediation

### Immediate Detection

1. **Check for affected applications** in Entra ID Enterprise Applications by searching for these Application IDs:
   - `506e08f9-6e9a-4da4-942b-a099a03644ae` (Cloud Backup)
   - `2399d300-6fca-4e6a-a686-399fefe75b83` (Cloud Management)
   - `24205314-2b89-4e07-a2a4-579e898a5640` (MS Teams)
   - `b78f6a77-d4e5-46fb-87e5-d1648bd02519` (Exchange Online)
   - `0de14c77-b9b0-4137-9360-34878a929827` (MS Graph)
   - `412dcf96-176d-4b3a-a1b0-4981ad66971e` (Partner Center)
   - `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` (SharePoint Online)

2. **Review Service Principal sign-ins** (not User sign-ins) for these app IDs, looking for IPs outside Microsoft/Azure ranges, specifically `144.172.64.128`.

3. **Search Entra audit logs** for:
   - `Add member to role` operations by ConnectWise/SkyKick service principals
   - `Update application` / `Add service principal credentials` events
   - Any service principal self-assigning directory roles
   - Credentials added since October 13, 2026

4. **Review Azure Key Vault** audit logs for identities performing 20+ SecretGet operations across 3+ vaults in 15-minute windows.

### Remediation

1. **Disable (do not delete)** all ConnectWise and SkyKick applications in Entra ID until ConnectWise confirms credential reset
2. Remove any directory role not intentionally granted to ConnectWise/SkyKick service principals (especially Global Administrator, Exchange Administrator)
3. Audit and remove unauthorized client secrets and certificates on all Enterprise applications, focusing on credentials added since October 13
4. Preserve Entra sign-in logs, audit logs, Purview audit records, and SIEM data from at least October 1
5. Verify no unauthorized credentials remain on security tool applications (Huntress, RMM tools, etc.)
6. Do not re-enable ConnectWise apps until formal restoration guidance is issued

### Long-Term Hardening

- Implement application management policies to restrict client secret creation and cap lifetimes
- Apply Conditional Access for workload identities (requires Entra ID P2 licensing)
- Enable Entra ID Protection for risky service principal detection
- Limit Application Administrator roles across the tenant
- Monitor credential additions, privilege assignments, and anomalous app-only activity for high-privilege applications
- Enable Microsoft Graph activity logging where available to close the directory-read audit gap
- Review and reduce multi-tenant app permissions to least privilege; audit consent grants regularly

## Detection Rules

These Sigma rules target the Storm-0940 ConnectWise supply chain attack indicators in Microsoft 365 and Azure AD audit logs: compromised ConnectWise application sign-ins from known attacker IPs, service principal self-assignment of privileged directory roles, unauthorized application credential additions, and bulk Key Vault secret access. All rules are PoC/advisory-specific (default altitude, strict leniency). Compiles does not equal fires -- verify in your environment's log pipeline.

### Sigma: ConnectWise Application Sign-in from Storm-0940 Infrastructure
Detects service principal sign-ins for known compromised ConnectWise application IDs originating from Storm-0940 attacker IP addresses.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403) -- not a rule issue. Keys on the intersection of seven ConnectWise app IDs and seven attacker IPs from the Microsoft/Huntress advisories. No fitting pipeline for azure logsource. FP: near-zero given IP+AppID intersection. Evasion: new IPs not in the list. -->
```yaml
title: ConnectWise App Sign-in from Storm-0940 Attacker IP
id: c7a1e3b5-4f2d-4a8e-9c6b-1d5e7f0a2b3c
status: experimental
description: >
    Detects service principal sign-ins for compromised ConnectWise Cloud Backup
    and Cloud Management application IDs from known Storm-0940 attacker IPs.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
author: Actioner
date: 2026/10/25
tags:
    - attack.t1078.004
    - attack.t1199
logsource:
    product: azure
    service: signinlogs
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
        IPAddress:
            - '144.172.64.60'
            - '144.172.64.99'
            - '144.172.64.128'
            - '144.172.94.243'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection_app and selection_ip
falsepositives:
    - Legitimate ConnectWise operations from these IPs (unlikely given RouterHosting ASN)
level: critical
```

### Sigma: Service Principal Self-Assignment of Privileged Directory Role
Detects a service principal adding itself to a privileged directory role (Global Administrator or Exchange Administrator), as observed in the Storm-0940 post-compromise phase.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0; log_scale 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403). Keys on Entra audit log "Add member to role" with privileged role names. FP: legitimate PIM activations or vendor provisioning. Evasion: using a different principal to assign the role, or non-standard role name. -->
```yaml
title: Service Principal Self-Assignment of Privileged Directory Role
id: d8b2f4c6-5e3a-4b9f-ad7c-2e6f8a1b3c4d
status: experimental
description: >
    Detects a service principal adding itself to Global Administrator or Exchange
    Administrator roles, as observed in the Storm-0940 ConnectWise supply chain
    attack where compromised apps self-elevated privileges.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
author: Actioner
date: 2026/10/25
tags:
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName: 'Add member to role'
        Category: 'RoleManagement'
    selection_role:
        TargetResources.modifiedProperties.newValue|contains:
            - 'Global Administrator'
            - 'Company Administrator'
            - 'Exchange Administrator'
    condition: selection and selection_role
falsepositives:
    - Legitimate Entra ID Privileged Identity Management (PIM) activations
    - Authorized vendor provisioning workflows
level: high
```

### Sigma: Unauthorized Application Credential Addition by Service Principal
Detects service principals adding new credentials (client secrets or certificates) to other applications, consistent with the Storm-0940 persistence mechanism of planting long-lived backdoor credentials.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0; log_scale 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403). Keys on credential addition audit events with Python/curl/azure-toolkit UAs from the advisory. FP: legitimate automation using Python/curl for app credential management. Scope to ConnectWise app IDs for higher precision. -->
```yaml
title: Application Credential Addition with Suspicious User Agent
id: e9c3a5d7-6f4b-4cae-be8d-3f7a9b2c4d5e
status: experimental
description: >
    Detects application credential additions (client secrets or certificates)
    performed with user agents associated with Storm-0940 tooling
    (Python-urllib, python-requests, curl), indicating automated credential
    planting for persistent backdoor access.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
author: Actioner
date: 2026/10/25
tags:
    - attack.t1098.001
logsource:
    product: azure
    service: auditlogs
detection:
    selection_operation:
        OperationName:
            - 'Update application - Certificates and secrets management'
            - 'Add service principal credentials'
    selection_useragent:
        InitiatedBy.app.userAgent|contains:
            - 'Python-urllib'
            - 'python-requests'
            - 'curl/'
            - 'azure-toolkit'
    condition: selection_operation and selection_useragent
falsepositives:
    - Legitimate automation scripts that manage application credentials using Python or curl
level: high
```

### Sigma: Azure Key Vault Secret Access from Storm-0940 Infrastructure
Detects successful SecretGet operations in Azure Key Vault originating from known Storm-0940 attacker IPs, consistent with post-compromise credential harvesting.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert splunk 0; log_scale 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403) -- not a rule issue. Keys on SecretGet + attacker IPs from the Microsoft advisory. FP: near-zero given RouterHosting ASN + operation intersection. Evasion: new IPs not in the list. -->
```yaml
title: Bulk Azure Key Vault Secret Access Across Multiple Vaults
id: f0d4b6e8-7a5c-4dbe-cf9e-4a8b0c3d5e6f
status: experimental
description: >
    Detects successful SecretGet operations in Azure Key Vault from Storm-0940
    attacker IPs, consistent with post-compromise credential harvesting
    from cloud secrets management stores.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/25
tags:
    - attack.t1555.006
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        OperationName: 'SecretGet'
        ResultType: 'Success'
    selection_ip:
        CallerIPAddress:
            - '144.172.64.60'
            - '144.172.64.99'
            - '144.172.64.128'
            - '144.172.94.243'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection and selection_ip
falsepositives:
    - Legitimate Key Vault access from these IP addresses (unlikely given RouterHosting ASN)
level: high
```

### Sigma: ConnectWise Application Sign-in with Anomalous User Agent
Detects service principal sign-ins for ConnectWise application IDs using user agents associated with scripted/automated attack tooling rather than legitimate ConnectWise SDK traffic.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert splunk 0; log_scale 0. sigma check blocked by proxy (MITRE ATT&CK data fetch 403). Keys on ConnectWise app IDs with Python/curl/azure-toolkit UAs. Legitimate ConnectWise traffic uses kiota-dotnet or Azure IPv6 ranges. FP: ConnectWise internal tooling changes, custom integrations. -->
```yaml
title: ConnectWise App Sign-in with Scripted User Agent
id: a1e5c7f9-8b6d-4ecf-da0f-5b9c1d4e6f7a
status: experimental
description: >
    Detects service principal sign-ins for ConnectWise Cloud Backup and Cloud
    Management applications using scripted user agents (Python, curl,
    azure-toolkit) instead of expected ConnectWise SDK agents.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
author: Actioner
date: 2026/10/25
tags:
    - attack.t1078.004
    - attack.t1528
logsource:
    product: azure
    service: signinlogs
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
            - 'azure-toolkit'
    condition: selection_app and selection_ua
falsepositives:
    - ConnectWise internal tooling using Python or curl for maintenance operations
level: high
```

### Snort: N/A
No HTTP/DNS/TLS-layer network signatures are applicable. The attack operated entirely through legitimate HTTPS Microsoft Graph API endpoints. The attacker IPs are better detected via cloud audit log correlation (Sigma rules above) than at the network perimeter, since the traffic is standard TLS to Microsoft infrastructure.

### Suricata: N/A
Same rationale as Snort. The attack traffic was OAuth2 token requests and Microsoft Graph API calls over standard HTTPS to Microsoft endpoints (login.microsoftonline.com, graph.microsoft.com). Network-layer signatures would either match all legitimate M365 traffic or require TLS interception, making them impractical for this cloud-native attack vector.

### YARA: N/A
No file-level indicators (malware samples, dropped files, binary payloads) were identified in this cloud-native supply chain attack.

## Lessons Learned

1. **Multi-tenant OAuth applications are high-value supply chain targets.** A single compromised application credential grants access to every downstream tenant that has authorized the application, without requiring customer interaction or MFA. Organizations should minimize multi-tenant app permissions, enforce credential lifecycle policies, and monitor service principal activity.

2. **AI-accelerated attacks compress the attack timeline.** Storm-0940's use of ARTEX to automate reconnaissance through privilege escalation achieved privileged cloud access within three hours. Defenders must detect and respond faster than traditional human-paced operations, making automated detection and response essential.

3. **Microsoft Graph audit gaps are a defensive blind spot.** Directory reads through Microsoft Graph produce no audit record, making it impossible to confirm or deny data access after a service principal compromise. Organizations should enable Microsoft Graph activity logging where available and advocate for expanded audit coverage.

4. **Credential persistence survives application disablement.** Planted credentials on other applications maintain access even after the originally compromised application is disabled or deleted. Incident response must include auditing credentials across all applications in the tenant, not just the known-compromised ones.

5. **Vendor trust requires continuous verification.** The attack exploited pre-existing trust relationships. Implementing Conditional Access for workload identities, restricting application consent, and monitoring for anomalous service principal behavior are essential defenses against supply chain abuse.

## Sources

- [Microsoft Security Blog: Storm-0940 Uses ARTEX](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) — primary attribution and technical analysis from Microsoft Threat Intelligence
- [Huntress: ConnectWise (SkyKick) Vendor Credentials Abused](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access) — detailed IOCs, timeline, and per-tenant post-compromise analysis
- [CyberScoop: Microsoft Attributes ConnectWise Attack to Storm-0940](https://cyberscoop.com/microsoft-attributes-connectwise-supply-chain-attack-china-storm-0940/) — attribution context, ARTEX framework details, and sector targeting
- [CyberScoop: ConnectWise Cloud Backup Supply Chain Attack](https://cyberscoop.com/connectwise-cloud-backup-supply-chain-attack/) — initial discovery timeline, Huntress/Todyl coordination, scope estimates
- [The Hacker News: China-Linked Hackers Use ARTEX AI](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html) — Zscaler/Wiz findings, ARTEX configuration details, post-compromise objectives
- [SecurityWeek: China APT Uses AI Pentest Tool ARTEX](https://www.securityweek.com/china-apt-uses-ai-pentest-tool-artex-in-connectwise-attacks/) — sector impact summary and cross-vendor attribution context

---
*Report generated by Actioner*
