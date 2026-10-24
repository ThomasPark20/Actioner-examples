# Technical Analysis Report: Storm-0940 / ARTEX ConnectWise Supply Chain Compromise (2026-10-24)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-24
Version: 1.1-REVISED

## Executive Summary

Storm-0940, a China state-aligned threat actor active since at least 2021, leveraged ARTEX -- an agentic AI penetration testing framework -- to automate and accelerate a supply chain compromise targeting ConnectWise Cloud Backup. The attackers obtained control of ConnectWise cloud application credentials and used them to authenticate directly into customer Microsoft 365 tenants without interactive user sign-in, bypassing MFA entirely. Between October 10--17, 2026, Storm-0940 conducted cross-tenant password spraying peaking at 2,900 failed logons per minute and attempted sign-ins to more than 2,250 tenants. In several confirmed cases, the actor escalated from initial application access to privileged cloud access (Global Administrator, Exchange Administrator) in under three hours. ConnectWise suspended Cloud Backup, SaaS Security, and Cloud Management services and disabled seven application identities on October 17. Microsoft published its attribution and detailed technical analysis on October 21, 2026.

## Background: ConnectWise Cloud Backup and Microsoft 365 Integration

ConnectWise Cloud Backup (formerly SkyKick) is a multi-tenant cloud backup solution used by managed service providers (MSPs) to protect Microsoft 365 data. The application and its related Cloud Management and SaaS Security services operate as registered OAuth applications within customer Microsoft 365 tenants, holding delegated or application-level permissions including `Directory.ReadWrite.All`. These permissions grant broad access to mail, OneDrive, SharePoint, Teams, and directory objects. Older tenants may list these applications under the "SkyKick Cloud Manager" display name.

The trust relationship inherent in the MSP supply chain model means that a single compromised vendor credential can cascade access across hundreds or thousands of downstream customer tenants -- making ConnectWise's cloud applications a high-value target for state-aligned actors seeking broad intelligence collection.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| August 17, 2026 | TAG-217 (Recorded Future designation) begins testing remote-access infrastructure and internet scanning |
| Early September 2026 | Earliest reported ARTEX-driven activity against target organizations |
| October 10, 2026 | Cross-tenant password spray campaign begins from 144.172.64[.]99 against 327 accounts across eight organizations |
| October 11, 2026 | Password spray peaks at ~2,900 failed logons per minute; over 111,000 failures recorded this day |
| October 13--14, 2026 | Scripted sign-in attempts from attacker infrastructure using curl and Python user-agents |
| October 15, 2026 | AI agents gain control of ConnectWise application identities; application-only authentication into customer tenants begins. Public reports of compromise surface referencing the 144.172.64[.]x range. PIM alerts fire for service principal self-assigning Exchange Administrator |
| October 16, 2026 | ConnectWise publishes initial advisory. Huntress confirms at least 162 compromised tenants in their environment |
| October 17, 05:01 UTC | ConnectWise announces Cloud Backup service interruption; disables seven application identities and revokes certificates |
| October 18, 01:00 UTC | ConnectWise update: backups not running; SaaS Security and Cloud Management offline as precaution |
| October 19, 2026 | ConnectWise advisory update: no successful threat activity observed since containment measures |
| October 20, 2026 | ConnectWise completes account and credential reset in Cloud Backup environment; prepares phased restoration |
| October 21, 2026 | Microsoft publishes attribution and technical analysis |

## Root Cause: Compromised ConnectWise Cloud Application Credentials

The attack vector was the theft and abuse of ConnectWise Cloud Backup application client secrets. The attackers authenticated directly as the backup application using its client secret through automated scripts. Because this was an application-only (non-interactive) authentication flow, no user sign-in occurred and multi-factor authentication did not apply. The application's previously granted high-privilege permissions (including `Directory.ReadWrite.All`) enabled immediate access to mail, OneDrive, SharePoint, Teams, and directory objects within each tenant where the application was installed.

The exact method by which the vendor credentials were initially obtained has not been publicly disclosed. The use of ARTEX suggests automated reconnaissance and credential discovery may have played a role in identifying and exploiting the credential storage mechanism.

## Technical Analysis of the Malicious Payload

### 1. ARTEX Agentic AI Framework

ARTEX is a multi-agent LLM system written in Go with a Next.js frontend that automates penetration testing from reconnaissance through data exfiltration with minimal human input. Key characteristics:

- **Architecture:** Multi-agent system where agents build a graph of discovered assets and vulnerabilities
- **AI Models:** Configured to use DeepSeek through an OpenAI-compatible gateway; additional configurations referenced DeepSeek, GLM (Zhipu AI), and Grok models
- **Multi-model workflow:** Prompts divide investigation tasks among models with cross-review (e.g., GLM reviewing DeepSeek's output)
- **Language support:** UI and output default to English but support Korean, Mandarin, Spanish, and Japanese
- **Observed capabilities:** Automated scanning, reconnaissance, password spraying, OAuth application abuse, SSO endpoint probing
- **Release timeline:** Released July 2026 for legitimate testing; reportedly went closed-source in October 2026 after misuse

Zscaler observed custom deployments containing AI assistant configurations, synchronization scripts, network routing tools, and Claude Code prompt history. Prompt objectives included bulk personal and transaction data extraction, payment gateway API key theft, NFT minting workflow exploitation, and gaining unauthorized admin privileges.

### 2. Password Spray Campaign (October 10--14)

Storm-0940 conducted a broad, low-rate cross-tenant password spray campaign from 144.172.64[.]99:

- **Scale:** 327 accounts across eight organizations
- **Volume:** Over 151,000 failed logon events; peak of 2,900 failures per minute
- **Targeting:** 48 accounts received more than 1,000 individual failures
- **Result:** Nearly 98% of activity resulted in lockouts; Microsoft reported no successful authentication during this phase
- **Intent:** Likely credential harvesting and target reconnaissance concurrent with the supply chain compromise

### 3. Supply Chain Application Compromise (October 15+)

Upon gaining control of ConnectWise application identities, the attack shifted to application-only authentication:

- **Authentication:** Over 200 sign-ins in under 4 minutes using 4 application credentials
- **Reconnaissance:** Microsoft Graph API calls for directory enumeration, permission discovery, and approval listing
- **Privilege escalation:** Cloud Management service principals self-assigned Exchange Administrator (in ~50 Huntress-observed tenants) and in at least one case Global Administrator
- **Persistence:** Added new client secrets and certificates to existing applications as backdoors. The choice of backdoored applications appeared random; the consistent factor was that credentials were planted in applications registered within the affected tenant
- **Speed:** Time from initial targeting to privileged cloud access was under 3 hours in several cases
- **Scope:** Attempted sign-ins to more than 2,250 tenants; Huntress confirmed 162--173 compromised tenants in their environment

### 4. Post-Compromise Activity

- **Graph API Reconnaissance:** Directory reads, user/group enumeration, permission and consent grant review
- **Privilege Modification:** Changes to identities, groups, and privileged roles
- **Credential Planting:** Adding secrets to multiple applications for persistent backdoor access, including MSP management tools and even Huntress's own application in one tenant
- **Data Access:** Potential access to mail, files, and Teams messages (Huntress found no evidence of mailbox or file manipulation in their observed tenants, but access was possible via granted permissions)

### 5. Evasion and Operational Security

- **IP Rotation:** Wiz reported new IPs appearing within minutes of blocks
- **Continuous Operation:** Sessions lasting 24--30 hours, consistent with AI-automated tooling
- **Token Persistence:** Disabling applications stops new tokens but existing access tokens remain valid until expiry; revoking user sessions does not end application-based access
- **Low-profile reconnaissance:** Graph API activity blends with legitimate application behavior

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `144.172.64[.]99`)
> - Domains: `[.]` replacing dots (e.g., `graph[.]microsoft[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| ARTEX | Unknown (released July 2026) | Go-based agentic AI penetration testing framework; closed-source as of October 2026 |

### File System

No file-level malware indicators (hashes, file paths, dropped binaries) were published in the available sources. ARTEX is a cloud-native framework operating through API calls, not endpoint-deployed malware.

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 144.172.64[.]99 | Primary password spray source; Storm-0940 infrastructure (AS14956, RouterHosting) |
| IP | 144.172.64[.]60 | Failed user logins, October 18 |
| IP | 144.172.64[.]128 | Primary application sign-in source; Graph API activity |
| IP | 144.172.94[.]243 | Broad failed login spray, ongoing |
| IP | 187.15.88[.]186 | Transient VPN source, October 15--16 |
| IP | 187.15.89[.]186 | Transient VPN source, October 15--16 |
| IP | 187.15.90[.]217 | Transient VPN source, October 15--16 |
| User-Agent | `python-requests/2.31.0` | Scripted access from ARTEX tooling |
| User-Agent | `python-requests/2.34.2` | Scripted access from ARTEX tooling |
| User-Agent | `Python-urllib/3.12` | Scripted access from ARTEX tooling |
| User-Agent | `curl/7.88.1` | Scripted sign-in attempts October 13--14 |
| User-Agent | `azure-toolkit/1.0` | Custom ARTEX user-agent for Graph API interaction |

### Compromised ConnectWise Application IDs

| Application Name | Application ID | Notes |
|------------------|---------------|-------|
| ConnectWise Cloud Backup | `506e08f9-6e9a-4da4-942b-a099a03644ae` | Primary attack vector |
| ConnectWise Cloud Management | `2399d300-6fca-4e6a-a686-399fefe75b83` | Self-assigned Exchange Administrator |
| Cloud Management - MS Teams | `24205314-2b89-4e07-a2a4-579e898a5640` | Self-assigned Global Administrator in one tenant |
| Cloud Management - Exchange Online | `b78f6a77-d4e5-46fb-87e5-d1648bd02519` | |
| Cloud Management - MS Graph | `0de14c77-b9b0-4137-9360-34878a929827` | |
| Cloud Management - Partner Center | `412dcf96-176d-4b3a-a1b0-4981ad66971e` | |
| Cloud Management - SharePoint Online | `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` | |

### Behavioral

- **Application-only authentication** from ConnectWise app IDs without interactive user sign-in, originating from non-ConnectWise infrastructure
- **Self-assignment of privileged directory roles** (Exchange Administrator, Global Administrator) by service principals within minutes of initial application sign-in
- **Rapid credential planting** -- new client secrets added to existing applications as backdoors, including applications unrelated to ConnectWise
- **High-velocity Graph API reconnaissance** -- directory enumeration, permission listing, approval queries from unusual source IPs
- **Cross-tenant password spray** -- broad low-rate spraying with concentration on selected accounts exceeding 1,000 failures each

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised ConnectWise Cloud Backup application credentials to access downstream customer tenants |
| T1199 | Trusted Relationship | Abused MSP trust relationship to pivot from ConnectWise to customer M365 environments |
| T1078.004 | Valid Accounts: Cloud Accounts | Authenticated using legitimate ConnectWise application credentials |
| T1110.003 | Brute Force: Password Spraying | Cross-tenant password spray campaign against 327 accounts, peaking at 2,900/min |
| T1528 | Steal Application Access Token | Obtained and used ConnectWise application client secrets for M365 access |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Added new client secrets/certificates to existing applications for persistence |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Service principals self-assigned Exchange Administrator and Global Administrator |
| T1087.004 | Account Discovery: Cloud Account | Graph API directory and user enumeration |
| T1580 | Cloud Infrastructure Discovery | Graph API reconnaissance of permissions, approvals, and infrastructure |
| T1595 | Active Scanning | ARTEX-driven automated scanning and reconnaissance |
| T1059 | Command and Scripting Interpreter | ARTEX framework execution via Go runtime with Python/curl scripted interactions |

## Impact Assessment

- **Breadth:** Attempted sign-ins to 2,250+ tenants; 162--173 confirmed compromised tenants (Huntress); hundreds of organizations targeted globally
- **Depth:** Privileged cloud access (Global Administrator) achieved in multiple tenants; potential for complete tenant takeover
- **Sectors:** Aerospace/defense, automotive, chemicals, energy, financial services, government, legal, manufacturing, media, military, semiconductors, software, technology, think tanks/nonprofits
- **Stealth:** Application-only authentication bypassed MFA; activity blended with legitimate ConnectWise app behavior; AI automation enabled 24--30 hour continuous sessions
- **Operational disruption:** ConnectWise suspended Cloud Backup, SaaS Security, and Cloud Management services for multiple days, impacting MSP backup operations

## Detection & Remediation

### Immediate Detection

Run these checks in your Microsoft 365 / Entra ID environment:

1. **Check for affected ConnectWise apps:** Search enterprise applications by the seven Application IDs listed above (search by App ID, not display name -- older tenants may use "SkyKick")
2. **Review service principal sign-in logs:** Filter by the seven App IDs for sign-ins from non-ConnectWise IPs, especially the IOC IPs, starting from October 1, 2026
3. **Audit role assignments:** Check for service principals that self-assigned Exchange Administrator, Global Administrator, Privileged Role Administrator, Application Administrator, or Cloud Application Administrator
4. **Check credential additions:** Review secrets and certificates added to any application since October 13 for unrecognized entries
5. **Review Graph API activity:** Examine MicrosoftGraphActivityLogs for requests from IOC IPs or ConnectWise app IDs with unusual patterns

### Remediation

1. **Keep affected ConnectWise apps disabled** until ConnectWise provides formal restoration instructions. Do not delete the enterprise apps -- preserve configuration and evidence
2. **Inventory all affected tenants** where any of the seven ConnectWise apps were installed or authorized, including tenants no longer in active use
3. **Remove unauthorized credentials** -- revoke any secrets or certificates added to applications since October 13 that are not recognized
4. **Revert unauthorized role assignments** -- remove Exchange Administrator, Global Administrator, and other privileged roles from ConnectWise service principals
5. **Preserve logs** -- retain Entra sign-in/audit logs, Purview audit records, SIEM data, and Graph telemetry starting from October 1, 2026
6. **Account for token lifetime** -- disabling applications stops new token issuance, but existing access tokens remain valid until expiry. Monitor for residual access
7. **Review downstream impact** -- MSPs must independently review their own tenants and all managed customer tenants

### Long-Term Hardening

- Implement least-privilege permissions for all third-party application integrations, especially MSP tools
- Enable continuous monitoring of application consent grants and credential changes
- Deploy conditional access policies restricting application-only authentication to expected IP ranges
- Monitor for service principal role self-assignment as a high-fidelity alert
- Assess supply chain dependencies in cloud backup and MSP management tooling

## Detection Rules

These detections target the Storm-0940 ConnectWise supply chain compromise at PoC/advisory-specific altitude, keying on published IOC IPs, compromised application IDs, suspicious user-agents, and privilege escalation patterns. Sigma rules compile to Splunk and CrowdStrike LogScale with caveats: Rules 3 and 4 depend on SIEM pipeline extraction of nested Azure audit log JSON fields (InitiatedBy, TargetResources); Rule 6 targets MicrosoftGraphActivityLogs, a newer log source with limited Sigma backend support. Field mappings must be verified per deployment. Compiles != fires -- verify in your pipeline.

### Sigma: ConnectWise Application Sign-In from Known IOC IPs
Detects service principal sign-ins from the seven compromised ConnectWise application IDs originating from published Storm-0940 infrastructure IPs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); splunk convert 0; log_scale convert 0. Fields: AppId (exact UUID match), IpAddress (exact match). Values are real (not defanged). -->
```yaml
title: Storm-0940 ConnectWise Cloud Backup Application Sign-In from Known IOC IPs
id: 8a3b2c4d-e5f6-4a7b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects service principal sign-ins from compromised ConnectWise Cloud Backup and Cloud Management
    application IDs originating from known Storm-0940 infrastructure IPs. These applications were
    abused in the October 2026 supply chain compromise to access Microsoft 365 tenant data.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
author: Actioner
date: 2026/10/24
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
        IpAddress:
            - '144.172.64.99'
            - '144.172.64.60'
            - '144.172.64.128'
            - '144.172.94.243'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection_app and selection_ip
falsepositives:
    - Legitimate ConnectWise infrastructure using the same IP range (unlikely given containment)
level: critical
```

### Sigma: ConnectWise Application Sign-In with Suspicious Scripted User-Agent
Detects sign-ins to ConnectWise application IDs using Python, curl, or azure-toolkit user-agents associated with ARTEX automation. The `azure-toolkit/` user-agent combined with a ConnectWise AppId is the highest-confidence indicator; `python-requests/` and `curl/` are common in legitimate automation and carry more false-positive risk.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy; splunk convert 0; log_scale convert 0. UserAgent startswith catches versioned variants (python-requests/2.31.0, curl/7.88.1, etc.). Downgraded to medium: python-requests/ and curl/ are common UAs in legitimate backend automation and monitoring tools. azure-toolkit/ is the strongest indicator. -->
```yaml
title: ConnectWise Application Sign-In with Suspicious Scripted User-Agent
id: 1f2e3d4c-5b6a-4789-8901-2345abcdef67
status: experimental
description: >
    Detects sign-ins to ConnectWise Cloud Backup or Cloud Management applications using
    scripted user-agents (Python, curl, azure-toolkit) associated with the Storm-0940
    ARTEX-driven supply chain compromise. These user-agents indicate automated tooling
    rather than legitimate application behavior.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
author: Actioner
date: 2026/10/24
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
        UserAgent|startswith:
            - 'python-requests/'
            - 'Python-urllib/'
            - 'curl/'
            - 'azure-toolkit/'
    condition: selection_app and selection_ua
falsepositives:
    - Legitimate ConnectWise backend services using Python or curl user-agents (common in cloud automation)
    - Internal monitoring or backup orchestration tools using python-requests or curl with ConnectWise application delegated permissions
    - azure-toolkit/ combined with ConnectWise AppIds is higher confidence; python-requests/ and curl/ alone are widespread
level: high
```

### Sigma: ConnectWise Service Principal Self-Assigned Privileged Directory Role (TTP Supplement)
TTP supplement (low confidence): Detects a service principal assigning a ConnectWise application service principal to a privileged directory role. Anchored to the seven compromised ConnectWise AppIds. Field-encoding caveat: `InitiatedBy` and `TargetResources` are nested JSON objects in Azure audit logs; the `|contains` modifier performs substring matching on the serialized JSON, which is pipeline-dependent and cannot reliably verify that the initiating principal is the same as the target (true self-assignment). SIEM pipelines that extract `InitiatedBy.app.servicePrincipalId` and `TargetResources[].id` into flat fields should replace the `|contains` filters with exact matches.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check blocked by proxy; splunk convert 0; log_scale convert 0. Anchored to ConnectWise AppIds per critic review. InitiatedBy|contains and TargetResources|contains operate on serialized JSON -- unreliable without pipeline extraction. Does not verify true self-assignment (initiator == target). Low confidence due to field encoding limitations. -->
```yaml
title: ConnectWise Service Principal Self-Assigned Privileged Directory Role (TTP Supplement)
id: 7c8d9e0f-1a2b-4c3d-5e6f-7a8b9c0d1e2f
status: experimental
description: >
    TTP supplement -- Detects a role assignment operation where a service principal adds
    a ConnectWise Cloud Backup or Cloud Management application to a privileged directory
    role (Global Administrator, Exchange Administrator, etc.). Observed in the Storm-0940
    ConnectWise supply chain compromise. IMPORTANT: InitiatedBy and TargetResources are
    nested JSON objects in Azure audit logs. The contains modifier performs substring matching
    on the serialized representation, which is pipeline-dependent. This rule does not verify
    true self-assignment (that the initiating SP is the same as the target SP). Deployments
    should replace contains filters with exact field matches after pipeline extraction.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    - https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
author: Actioner
date: 2026/10/24
tags:
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection_operation:
        OperationName: 'Add member to role'
        Category: 'RoleManagement'
    selection_initiator:
        InitiatedBy|contains: 'ServicePrincipal'
    selection_target_app:
        TargetResources|contains:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '2399d300-6fca-4e6a-a686-399fefe75b83'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - 'b78f6a77-d4e5-46fb-87e5-d1648bd02519'
            - '0de14c77-b9b0-4137-9360-34878a929827'
            - '412dcf96-176d-4b3a-a1b0-4981ad66971e'
            - 'b2b55f5b-7758-4719-8d8f-88ae172e6bdb'
    selection_role:
        TargetResources|contains:
            - 'Global Administrator'
            - 'Exchange Administrator'
            - 'Privileged Role Administrator'
            - 'Application Administrator'
            - 'Cloud Application Administrator'
    condition: selection_operation and selection_initiator and selection_target_app and selection_role
falsepositives:
    - Automated provisioning systems that legitimately assign roles to ConnectWise service principals
    - SIEM pipelines that do not extract InitiatedBy and TargetResources JSON fields may cause false positives or missed detections
level: critical
```

### Sigma: OAuth Credential Addition from Storm-0940 Infrastructure
Detects addition of new credentials (secrets/certificates) to OAuth applications from known Storm-0940 IPs, the primary persistence mechanism in this campaign. Pipeline note: `CallerIpAddress` must be extracted from the nested `InitiatedBy` JSON object (path: `InitiatedBy.user.ipAddress` or `InitiatedBy.app.ipAddress`). This extraction is pipeline-dependent; verify the field mapping in your SIEM before deployment.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert 0; log_scale convert 0. IOC-anchored: fires only from published threat actor IPs. Changed field from InitiatedByIpAddress (non-standard) to CallerIpAddress with pipeline extraction note. Added 187.15.x.x transient VPN IPs. -->
```yaml
title: Credential Addition to OAuth Application from Storm-0940 Infrastructure
id: 3e4f5a6b-7c8d-4e9f-0a1b-2c3d4e5f6a7b
status: experimental
description: >
    Detects the addition of new credentials (secrets or certificates) to OAuth applications
    originating from known Storm-0940 infrastructure IPs. This persistence technique was
    used to maintain access after the initial ConnectWise supply chain compromise, with
    attackers adding credentials to existing applications as backdoors. NOTE: The
    CallerIpAddress field must be extracted from the nested InitiatedBy JSON object
    (InitiatedBy.user.ipAddress or InitiatedBy.app.ipAddress) by your SIEM pipeline.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/24
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
    selection_ip:
        CallerIpAddress:
            - '144.172.64.99'
            - '144.172.64.60'
            - '144.172.64.128'
            - '144.172.94.243'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection_operation and selection_ip
falsepositives:
    - Legitimate credential rotation from the same IP range (unlikely given known Storm-0940 attribution)
level: critical
```

### Sigma: Failed Sign-In from Storm-0940 Infrastructure IP
Detects failed sign-in attempts from the specific IPs used in the Storm-0940 cross-tenant password spray campaign. This is a per-event IOC match, not an aggregation rule; volume-based spray detection requires SIEM-native correlation on top of this base signal.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy; splunk convert 0; log_scale convert 0. IOC-specific: exact IP match on known spray sources. Renamed from "High-Volume" to remove title/logic mismatch (no aggregation). Replaced Status|contains:'Failure' with ResultType filter -- ResultType 0 is success in Azure sign-in logs, all other values indicate failure. -->
```yaml
title: Failed Sign-In from Storm-0940 Infrastructure IP
id: 9d0e1f2a-3b4c-4d5e-6f7a-8b9c0d1e2f3a
status: experimental
description: >
    Detects failed sign-in attempts originating from known Storm-0940 infrastructure IPs
    used in the cross-tenant password spray campaign (144.172.64.99, 144.172.94.243).
    This rule matches individual failed sign-in events by IOC IP. For volume-based spray
    detection, layer SIEM-native aggregation (e.g., count by IpAddress > threshold within
    timeframe) on top of this base signal.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/24
tags:
    - attack.t1110.003
logsource:
    product: azure
    service: signinlogs
detection:
    selection_ip:
        IpAddress:
            - '144.172.64.99'
            - '144.172.94.243'
    filter_success:
        ResultType: '0'
    condition: selection_ip and not filter_success
falsepositives:
    - Legitimate failed sign-in attempts from shared infrastructure in the same IP range
level: high
```

### Sigma: Microsoft Graph API Activity from Storm-0940 Infrastructure
Detects Graph API requests from known Storm-0940 IPs used for directory reconnaissance, permission enumeration, and privilege modification. This rule targets `MicrosoftGraphActivityLogs`, a dedicated log source for Graph API traffic (distinct from Azure Activity Logs, which cover ARM management-plane operations). MicrosoftGraphActivityLogs requires explicit enablement in Azure diagnostic settings and has limited Sigma backend support; verify your pipeline handles the `microsoft365/microsoftgraphactivitylogs` logsource before deployment.
**Status:** compile ✅ compiles · confidence: high (pipeline-dependent)
<!-- audit: sigma check blocked by proxy; splunk convert 0; log_scale convert 0. Fixed logsource from azure/activitylogs (ARM plane) to microsoft365/microsoftgraphactivitylogs (Graph API plane). IPAddress is the standard field in MicrosoftGraphActivityLogs. Limited Sigma backend support for this logsource. -->
```yaml
title: Microsoft Graph API Activity from Storm-0940 Infrastructure
id: 4b5c6d7e-8f9a-4b0c-1d2e-3f4a5b6c7d8e
status: experimental
description: >
    Detects Microsoft Graph API requests originating from known Storm-0940 infrastructure
    IPs. The threat actor used Graph API for reconnaissance, application credential changes,
    privilege modification, and identity enumeration following the ConnectWise supply chain
    compromise. This rule targets MicrosoftGraphActivityLogs, which must be enabled in
    Azure diagnostic settings. The logsource microsoft365/microsoftgraphactivitylogs has
    limited Sigma backend support; verify pipeline compatibility before deployment.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/24
tags:
    - attack.t1087.004
    - attack.t1580
logsource:
    product: microsoft365
    service: microsoftgraphactivitylogs
detection:
    selection:
        IPAddress:
            - '144.172.64.99'
            - '144.172.64.60'
            - '144.172.64.128'
            - '144.172.94.243'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection
falsepositives:
    - Legitimate traffic from the same IP range (RouterHosting AS14956)
level: high
```

### Snort: Storm-0940 ARTEX Scripted User-Agent to Microsoft Graph
Detects outbound HTTP with the `azure-toolkit/` user-agent targeting Microsoft Graph API, the custom UA observed in ARTEX tooling.
**Prerequisite: TLS inspection required.** `graph.microsoft.com` is HTTPS-only (port 443). This rule inspects HTTP headers, which are encrypted inside TLS. It will only fire if the sensor performs SSL/TLS decryption (e.g., via an inline SSL proxy or Snort's SSL preprocessor with key material). Without TLS inspection, the rule will not match.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: snort -c test_snort.conf -T exit 0 (Snort 2.9.20). Medium confidence: azure-toolkit UA is distinctive but could be rotated. http_header content match; no field-specific header buffer in Snort 2. TLS inspection mandatory -- graph.microsoft.com is HTTPS-only. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Storm-0940 ARTEX Scripted User-Agent azure-toolkit to MS Graph"; flow:established,to_server; content:"azure-toolkit/"; http_header; fast_pattern; content:"graph.microsoft.com"; http_header; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/; metadata:author Actioner, created 2026-10-24; sid:2100001; rev:1;)
```

### Suricata: Storm-0940 ARTEX Scripted User-Agent to Microsoft Graph
Detects outbound HTTP with the `azure-toolkit/` user-agent targeting Microsoft Graph API, using Suricata's `http.user_agent` sticky buffer.
**Prerequisite: TLS inspection required.** `graph.microsoft.com` is HTTPS-only (port 443). This rule inspects HTTP-layer fields, which are encrypted inside TLS. It will only fire if Suricata is configured for TLS decryption (e.g., behind an SSL-terminating proxy or using Suricata's own TLS decryption capabilities). Without TLS inspection, the rule will not match.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Dot-notation buffers. Medium confidence: UA could be rotated, but combination with graph.microsoft.com host narrows FP. TLS inspection mandatory -- graph.microsoft.com is HTTPS-only. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Storm-0940 ARTEX Scripted User-Agent azure-toolkit to Microsoft Graph"; flow:established,to_server; http.user_agent; content:"azure-toolkit/"; startswith; fast_pattern; http.host; content:"graph.microsoft.com"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/; metadata:author Actioner, created_at 2026-10-24; sid:2200001; rev:1;)
```

### YARA: N/A
No file-level malware indicators (hashes, dropped binaries, byte patterns) were published in the available sources. The attack operated entirely through cloud API authentication and Graph API calls, leaving no endpoint file artifacts suitable for YARA detection.

## Lessons Learned

1. **Supply chain trust is a single point of failure.** MSP applications with `Directory.ReadWrite.All` and similar high-privilege permissions create a blast radius proportional to the number of downstream tenants. A single vendor credential compromise cascaded across 2,250+ tenants in hours.

2. **Application-only authentication bypasses MFA.** Traditional identity security measures (MFA, conditional access on user sign-ins) do not apply to application-only (client credential) authentication flows. Organizations must monitor and restrict application permissions and sign-in patterns with equal rigor.

3. **AI-augmented attacks compress timelines.** ARTEX's multi-agent AI automation reduced the time from reconnaissance to privileged access to under 3 hours and enabled 24--30 hour continuous operations. Defenders must assume machine-speed attacks when facing AI-augmented adversaries.

4. **Token persistence outlasts containment.** Disabling an application stops new token issuance but does not invalidate existing access tokens. Organizations must account for token lifetime windows during incident response.

5. **Credential rotation is not remediation.** Adding credentials to unrelated applications for persistence means vendor credential rotation alone does not eliminate attacker access. Comprehensive audit of all application credentials across all tenants is required.

## Sources

- [Microsoft Security Blog - Storm-0940 Uses ARTEX Agentic AI ConnectWise Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) -- primary technical analysis with IOCs, detection queries, and remediation guidance
- [The Hacker News - China-Linked Hackers Use ARTEX AI Agents in ConnectWise Supply Chain Attack](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html) -- additional timeline and ARTEX framework details including Zscaler and Wiz findings
- [BleepingComputer - Hackers Breach Microsoft 365 Tenants via ConnectWise Supply Chain Attack](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/) -- additional application IDs, Huntress findings, and remediation steps
- [The Hacker News - ConnectWise Resets Credentials as Cloud Backup Breach Widens](https://thehackernews.com/2026/10/connectwise-resets-credentials-as-cloud.html) -- ConnectWise response timeline and Huntress investigation details
- [Help Net Security - ConnectWise Suspends Cloud Backup Service](https://www.helpnetsecurity.com/?p=388341) -- ConnectWise service suspension details
- [Microsoft Threat Intelligence on X](https://x.com/MsftSecIntel/status/2112975078266716390) -- initial public disclosure thread
- [Aviatrix Threat Research - Storm-0940 ConnectWise Supply Chain Attack](https://aviatrix.ai/threat-research-center/microsoft-connectwise-supply-chain-attack-china-storm-0940/) -- additional MITRE ATT&CK mapping

---
*Report generated by Actioner*
