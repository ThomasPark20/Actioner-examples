# Technical Analysis Report: Storm-0940 / ARTEX ConnectWise Supply Chain Compromise (2026-10-22)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-22
Version: 1.0-DRAFT

## Executive Summary

On October 21, 2026, Microsoft disclosed that Storm-0940, a China-state-aligned threat actor active since at least 2021, leveraged the open-source ARTEX agentic AI penetration testing framework to automate a large-scale supply chain compromise through ConnectWise Cloud Backup (formerly SkyKick). The actor obtained highly privileged OAuth application credentials for ConnectWise multi-tenant cloud applications, enabling service-principal authentication into downstream customer Microsoft 365 environments without user interaction. The campaign reached over 2,250 tenants at up to 2,900 sign-in attempts per minute. In compromised tenants, the attacker self-assigned Global Administrator privileges, added backdoor credentials to other OAuth applications, and performed Microsoft Graph API reconnaissance. The attack bypassed MFA because it operated through pre-authorized service-principal flows, not interactive user sign-ins. Huntress confirmed unauthorized sign-ins in at least 162 tenants, with the true scope likely larger.

This report synthesizes technical details from Microsoft, CyberScoop, Huntress, The Hacker News, and Zscaler reporting. The viability gate is passed: the sources provide concrete OAuth application IDs, IP addresses, user-agent strings, operational timelines, and behavioral patterns sufficient for production detection engineering.

## Background: ConnectWise Cloud Backup and Multi-Tenant OAuth Architecture

ConnectWise Cloud Backup (formerly SkyKick) is a managed backup solution for Microsoft 365 environments widely used by Managed Service Providers (MSPs). It operates as a multi-tenant OAuth application registered in customer Azure AD (Entra ID) tenants with elevated permissions to access Exchange Online, SharePoint Online, Microsoft Teams, and Microsoft Graph API data. The trust model means that anyone holding the application's client secret can request access tokens in any tenant where the application is installed, as noted by Huntress researcher Jonathan Semon. ConnectWise also operates MS Teams and MS Graph integration apps with similar trust relationships.

Storm-0940 is a China-state-aligned espionage cluster first detailed by Microsoft in November 2024 in connection with the Quad7 botnet (CovertNetwork-1658). It targets aerospace/defense, automotive, energy, financial services, government, legal, manufacturing, media, military, semiconductor, software, technology, and think tank/non-profit organizations. Its historical tradecraft includes password spraying and exploitation of internet-facing applications.

ARTEX is a Go-based, multi-agent LLM-driven penetration testing framework with a Next.js front end. Zscaler research revealed custom deployments configured to use DeepSeek, GLM, and Grok models through OpenAI-compatible gateways, with multi-model workflows where agents review each other's findings. Following its abuse against South Korean financial institutions, ARTEX was made closed-source. Microsoft reports that multiple threat actors across various regions have weaponized ARTEX.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| September 2026 | Earliest Storm-0940 ARTEX-driven activity observed by Microsoft against hundreds of organizations |
| October 10, 2026 | Cross-tenant password-spray campaign begins from 144.172.64[.]99 targeting 327 accounts across eight organizations |
| October 11, 2026 | Peak spray activity: ~2,900 failures/minute, over 111,000 failures in a single day |
| October 14, 2026 | Password-spray campaign ends; no successful authentications detected |
| October 15, 2026 | Attacker gains control of ConnectWise multi-tenant app identities; begins service-principal sign-ins into customer tenants from 144.172.64[.]128 |
| October 15, 2026 | Microsoft Threat Intelligence observes broad successful sign-ins from malicious IP |
| October 16, 2026 | ConnectWise publishes initial advisory, later adds IOCs |
| October 17, 05:00 UTC | ConnectWise begins rolling out mitigations |
| October 18, 2026 | ConnectWise suspends Cloud Backup, SaaS Security, and Cloud Management services |
| October 20, 2026 | ConnectWise completes account and credential reset in affected Cloud Backup environment |
| October 21, 2026 | Microsoft publishes detailed blog post attributing activity to Storm-0940; ConnectWise begins phased service restoration |

## Root Cause: Compromised Multi-Tenant OAuth Application Credentials

The root cause was the unauthorized acquisition of a highly sensitive API secret (client credential) for ConnectWise Cloud Backup's multi-tenant OAuth application. ConnectWise described the incident as "attempted unauthorized access associated with Cloud Backup" but has not disclosed how the credential was obtained. Because the application is multi-tenant, the stolen credential enabled the attacker to request access tokens in any tenant where the application was installed, reaching well beyond any single organization. The multi-tenant trust model converted a single credential compromise into a supply-chain-wide breach.

The pre-compromise password-spray campaign (October 10-14) against Microsoft 365 and Exchange Online accounts across eight organizations appears to have been a separate, unsuccessful effort using the same infrastructure. The actual supply chain breach on October 15 operated through the compromised application credentials, not through any user account compromise.

## Technical Analysis of the Malicious Payload

### 1. Initial Access: ARTEX-Automated Reconnaissance and Password Spraying

Storm-0940 used ARTEX agents to automate scanning and reconnaissance of cloud resources at machine speed. From October 10-14, the actor conducted a cross-tenant password-spray campaign from 144.172.64[.]99 targeting 327 accounts across eight organizations. The campaign generated over 151,000 failed logon events, with 48 accounts receiving more than 1,000 failures each. Lockout responses accounted for nearly 98% of activity. No successful authentication was achieved during this phase.

### 2. Supply Chain Compromise: OAuth Application Identity Takeover

On October 15, the actor transitioned to exploiting compromised ConnectWise application identities. Using stolen client credentials for three ConnectWise OAuth applications, the actor performed service-principal (app-only) authentication into downstream customer tenants. This method:

- **Bypassed MFA** because service-principal authentication does not trigger interactive user sign-in or conditional access policies that require MFA
- **Operated at scale** reaching 2,250+ tenants at up to 2,900 attempts per minute
- **Exploited existing trust** that customers had granted to ConnectWise applications

The compromised applications were:
- **ConnectWise Cloud Backup** (AppId: `506e08f9-6e9a-4da4-942b-a099a03644ae`)
- **ConnectWise - MS Teams** (AppId: `24205314-2b89-4e07-a2a4-579e898a5640`)
- **ConnectWise - MS Graph** (AppId: `0de14c77-b9b0-4137-9360-34878a929827`)

Microsoft's immediate-actions section references four application IDs, but only three are published. The fourth remains unidentified.

### 3. Post-Compromise: Privilege Escalation and Persistence

In tenants where access succeeded, the attacker performed:

1. **Microsoft Graph API reconnaissance**: Directory reads, permission enumeration, and approval discovery
2. **Privilege escalation**: Self-assignment of Global Administrator role via "Add member to role" operations on the compromised application's service principal
3. **Persistence through credential planting**: Addition of new secrets/certificates to other OAuth applications within the tenant, creating backdoor access that would survive remediation of the original ConnectWise applications
4. **Identity and policy manipulation**: Changes to identities, groups, privileged roles, and potentially conditional access policies

Huntress observed that credential planting targeted applications seemingly at random within affected tenants, regardless of those applications' permissions. This persistence mechanism means that disabling the ConnectWise applications alone does not fully remediate the compromise.

### 4. C2 Infrastructure

All identified infrastructure resides in the AS14956 (RouterHosting) and Brazilian ISP address ranges:

| IP Address | Role | Active Period |
|------------|------|---------------|
| 144.172.64[.]128 | Primary: service-principal sign-ins and Graph API activity | October 15-16, 2026 |
| 144.172.64[.]99 | Password-spray campaign; matches ConnectWise advisory IOC | October 10-14, 2026 |
| 144.172.64[.]60 | Failed user logins | October 18, 2026 |
| 144.172.94[.]243 | Broad failed login spray against many organizations | Ongoing |
| 187.15.88[.]186 | VPN egress: Graph API access via compromised apps | October 15-16, 2026 |
| 187.15.90[.]217 | VPN egress: Graph API access via compromised apps | October 15-16, 2026 |
| 187.15.89[.]186 | VPN egress: Graph API access via compromised apps | October 15-16, 2026 |

The attacker used automation tooling with the following user-agent strings:

- `Python-urllib/3.12`
- `python-requests/2.31.0`
- `python-requests/2.34.2`
- `curl/7.88.1`
- `azure-toolkit/1.0`

No C2 domains, C2 beacon patterns, or file-level malware indicators were reported by any source.

### 5. ARTEX Framework Details (Zscaler)

Zscaler analysis of ARTEX deployments revealed:
- AI assistant configurations with synchronization scripts and network routing tools
- Configuration to use DeepSeek through an OpenAI-compatible gateway, with additional configurations for GLM and Grok models
- Multi-model workflows where investigation tasks are divided among models that review each other's findings (GLM reviewing DeepSeek's work)
- Claude Code prompt history found in a deployment
- Prompt histories requesting bulk personal and transaction data, selling stolen data, payment gateway API key extraction, NFT minting workflow exploitation, and unauthorized admin privilege acquisition

These details come from Zscaler's analysis and are not explicitly tied to the Storm-0940 ConnectWise campaign specifically.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `144.172.64[.]128`)
> - Domains: `[.]` replacing dots
> - URLs: `hxxps://` or `hxxp://`

### OAuth Application IDs

| Application Name | Application ID | Description |
|------------------|---------------|-------------|
| ConnectWise Cloud Backup | `506e08f9-6e9a-4da4-942b-a099a03644ae` | Primary supply chain vector; multi-tenant backup application |
| ConnectWise - MS Teams | `24205314-2b89-4e07-a2a4-579e898a5640` | Teams integration application abused for tenant access |
| ConnectWise - MS Graph | `0de14c77-b9b0-4137-9360-34878a929827` | Graph API integration application abused for tenant access |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 144.172.64[.]128 | Primary: app sign-ins and Graph activity (AS14956 RouterHosting) |
| IP | 144.172.64[.]99 | Password spray; matches ConnectWise advisory (AS14956) |
| IP | 144.172.64[.]60 | Failed login attempts (AS14956) |
| IP | 144.172.94[.]243 | Broad failed login spray, ongoing (AS14956) |
| IP | 187.15.88[.]186 | VPN egress for Graph API access (Brazilian ISP, transient) |
| IP | 187.15.90[.]217 | VPN egress for Graph API access (Brazilian ISP, transient) |
| IP | 187.15.89[.]186 | VPN egress for Graph API access (Brazilian ISP, transient) |

### User-Agent Strings

| User-Agent | Context |
|------------|---------|
| `Python-urllib/3.12` | ARTEX automation tooling |
| `python-requests/2.31.0` | ARTEX automation tooling |
| `python-requests/2.34.2` | ARTEX automation tooling |
| `curl/7.88.1` | ARTEX automation tooling |
| `azure-toolkit/1.0` | Custom ARTEX tooling user agent |

### Behavioral

- Service-principal (app-only) sign-ins from RouterHosting IP ranges using ConnectWise application IDs
- "Add member to role" audit events where a service principal assigns itself Global Administrator
- New credential additions ("Update application - Certificates and secrets management") to OAuth applications following ConnectWise app sign-ins
- Over 200 sign-ins in under 4 minutes using 4 application credentials
- Graph API reconnaissance patterns: directory reads, permission enumeration, approval discovery
- No interactive user sign-in associated with the malicious access

## MITRE ATT&CK Mapping

| TID | Technique | Tactic | Observed Behavior |
|-----|-----------|--------|-------------------|
| T1595 | Active Scanning | Reconnaissance | ARTEX-automated scanning and reconnaissance of cloud resources |
| T1110 | Brute Force | Credential Access | Cross-tenant password spraying: 151,000+ failed logons, 2,900/min peak, targeting 327 accounts |
| T1195 | Supply Chain Compromise | Initial Access | Compromise of ConnectWise Cloud Backup multi-tenant OAuth application credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | Defense Evasion, Initial Access | Service-principal authentication using compromised ConnectWise app credentials into 2,250+ tenants |
| T1528 | Steal Application Access Token | Credential Access | Theft and use of ConnectWise OAuth application client secrets for token generation |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Graph API directory and permission reconnaissance in victim tenants |
| T1580 | Cloud Infrastructure Discovery | Discovery | Enumeration of cloud infrastructure, approvals, and configurations via Graph API |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Persistence | Self-assignment of Global Administrator role by compromised ConnectWise service principal |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | Addition of new secrets/certificates to existing OAuth applications for backdoor persistence |

## Impact Assessment

- **Breadth**: Over 2,250 tenants targeted; Huntress confirmed unauthorized sign-ins in 162 tenants with more expected beyond its telemetry; ConnectWise describes impact reaching "well beyond any one company"
- **Depth**: In compromised tenants, Global Administrator was achieved, meaning full control over Azure AD/Entra ID, mail, files, and all integrated services
- **Stealth**: Service-principal sign-ins do not trigger user-facing MFA prompts or conditional access; the activity appears as normal application behavior in standard monitoring; some attacks went from initial targeting to privileged access in under 3 hours
- **Sector exposure**: Aerospace/defense, automotive, chemicals, energy, financial services, government, legal, manufacturing, media, military, semiconductor, software, technology, think tanks, and non-profits
- **Persistence risk**: Credential planting in other OAuth applications means the compromise can survive remediation of the ConnectWise applications alone

## Detection & Remediation

### Immediate Detection

**1. Check if compromised ConnectWise apps are present in your tenant:**

Inventory the following Application IDs in your Azure AD/Entra ID tenant:
- `506e08f9-6e9a-4da4-942b-a099a03644ae` (ConnectWise Cloud Backup)
- `24205314-2b89-4e07-a2a4-579e898a5640` (ConnectWise - MS Teams)
- `0de14c77-b9b0-4137-9360-34878a929827` (ConnectWise - MS Graph)

**2. Review service-principal sign-in logs from October 1 onward for these App IDs**, checking for:
- Sign-ins from the IOC IP addresses listed above
- Automated user-agent strings (python-requests, curl, azure-toolkit, Python-urllib)
- Unusually high volumes of sign-in activity

**3. Review Azure AD audit logs for:**
- "Add member to role" operations targeting Company Administrator / Global Administrator
- "Update application - Certificates and secrets management" or "Add service principal credentials" events
- New owners or service principals added to existing applications
- Conditional access policy changes
- Mailbox delegation or inbox/transport rule modifications

**4. Use Microsoft's published hunting queries** in Defender XDR Advanced Hunting and Sentinel:
- OAuthAppInfo query for the three App IDs
- Sign-in plus Graph correlation for App IDs and IOC IPs (from October 13)
- SigninLogs query showing resource authentication by app and IP
- MicrosoftGraphActivityLogs for Graph requests, methods, and scopes

An empty result does not prove no access occurred.

### Remediation

1. **Preserve evidence first**: Retain Entra sign-in and audit logs, Purview audit records, and SIEM data before any containment actions
2. **Disable (do not delete) the three ConnectWise enterprise applications** in your tenant
3. **Identify and revoke unauthorized credentials**: Check all OAuth applications and service principals for credentials added after October 1, 2026; remove any not recognized by your team
4. **Revoke Global Administrator assignments**: Remove any Global Administrator role assignments made by service principals that were not authorized
5. **Review and revert identity changes**: Check for new owners, consent grants, group membership changes, conditional access policy modifications, and inbox/transport rules
6. **Rotate credentials** on all OAuth applications that had unauthorized credential additions
7. **Do not reconnect ConnectWise applications** until ConnectWise issues formal restoration instructions
8. **Report to Microsoft** if compromise indicators are found in your tenant

### Long-Term Hardening

- Apply least-privilege to multi-tenant OAuth application permissions; avoid granting broad Graph API or directory permissions
- Implement continuous monitoring of service-principal sign-in activity with alerting on anomalous patterns
- Establish baseline for OAuth application credential management and alert on deviations
- Enable and retain MicrosoftGraphActivityLogs for Graph API audit trail
- Implement conditional access policies for workload identities (service principals) where supported
- Regularly review and audit third-party multi-tenant application permissions and consent grants
- Consider requiring admin consent for new third-party application registrations

## Detection Rules

The rules below cover the two primary detection surfaces exposed by this campaign: (1) Azure AD/Entra ID sign-in and audit log indicators detectable via Sigma, and (2) network-level IP and user-agent indicators detectable via Snort and Suricata. No YARA rules are provided because the sources disclose no file hashes, binary signatures, or endpoint file-level artifacts. All network IOC IPs are time-bound to the October 2026 campaign window and should be reviewed periodically for continued relevance.

### Sigma: Storm-0940 Compromised ConnectWise App Sign-in from Known Malicious IP

Detects service-principal sign-ins using the three compromised ConnectWise OAuth application IDs from IP addresses attributed to Storm-0940 infrastructure.
**Status**: compile (splunk, logscale) ✅ | confidence: high

```yaml
title: Storm-0940 Compromised ConnectWise App Sign-in from Known Malicious IP
id: f7a2c3d4-8e5b-4f19-a6d0-3b7c9e1f2a45
status: experimental
description: >
    Detects service principal sign-ins using compromised ConnectWise OAuth application
    IDs from IP addresses attributed to Storm-0940 infrastructure during the October
    2026 ConnectWise Cloud Backup supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/22
tags:
    - attack.t1078.004
    - attack.t1195
logsource:
    product: azure
    service: signinlogs
detection:
    selection_app:
        AppId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - '0de14c77-b9b0-4137-9360-34878a929827'
    selection_ip:
        IPAddress:
            - '144.172.64.128'
            - '144.172.64.99'
            - '144.172.64.60'
            - '187.15.88.186'
            - '187.15.90.217'
            - '187.15.89.186'
            - '144.172.94.243'
    condition: selection_app and selection_ip
falsepositives:
    - Legitimate ConnectWise operations from these IPs is unlikely given confirmed compromise
level: critical
```

<!-- AUDIT: sigma check blocked by network (MITRE ATT&CK data fetch 403); sigma convert --without-pipeline -t splunk and -t log_scale both produce correct output. Field names AppId and IPAddress match Azure AD SigninLogs schema. IPs are not defanged per logsource-encoding ref. Tags use technique-only format. -->

### Sigma: OAuth Application Self-Assigned Global Administrator Role

Detects an OAuth service principal adding itself to the Global Administrator (Company Administrator) directory role, the key privilege-escalation step observed in this campaign.
**Status**: compile (splunk, logscale) ✅ | confidence: high

```yaml
title: OAuth Application Self-Assigned Global Administrator Role
id: e8b3d4f5-9c6a-4a27-b1e0-4c8d0f2a3b56
status: experimental
description: >
    Detects an OAuth application or service principal adding itself to the Global
    Administrator directory role via Azure AD audit logs. Observed in the Storm-0940
    ConnectWise supply chain compromise where compromised apps elevated their own
    privileges to Global Administrator.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/22
tags:
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection_operation:
        OperationName:
            - 'Add member to role'
            - 'Add eligible member to role'
    selection_role:
        TargetResources|contains:
            - 'Company Administrator'
            - 'Global Administrator'
    condition: selection_operation and selection_role
falsepositives:
    - Legitimate emergency break-glass procedures assigning Global Administrator
level: critical
```

<!-- AUDIT: sigma check blocked by network; splunk and logscale convert OK. OperationName and TargetResources are standard Azure AD audit log field names. TargetResources is a JSON array in raw logs; |contains handles substring matching against the serialized form. Both "Company Administrator" (internal) and "Global Administrator" (display) names covered. -->

### Sigma: Suspicious Credential Addition to OAuth Application Service Principal

Detects addition of new credentials to OAuth application service principals, the persistence technique Storm-0940 used to maintain backdoor access after the initial ConnectWise compromise.
**Status**: compile (splunk, logscale) ✅ | confidence: medium

```yaml
title: Suspicious Credential Addition to OAuth Application Service Principal
id: c5f9a3d4-6e7b-4c0a-d1f8-3a4b5c6d7e8f
status: experimental
description: >
    Detects addition of new credentials such as secrets or certificates to OAuth
    application service principals. Storm-0940 used this technique for persistence
    after compromising ConnectWise applications to maintain backdoor access to
    victim Microsoft 365 tenants.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/22
tags:
    - attack.t1098.001
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName:
            - 'Update application - Certificates and secrets management'
            - 'Add service principal credentials'
            - 'Update service principal/Update Application - Certificates and secrets management'
    condition: selection
falsepositives:
    - Routine application credential rotation by administrators
    - Automated certificate renewal processes
level: high
```

<!-- AUDIT: sigma check blocked by network; splunk and logscale convert OK. This rule is broader (no IP/App pinning) because credential additions to ANY app are the persistence vector; the attacker planted credentials in random tenant applications. Medium confidence reflects higher FP potential from legitimate credential rotation. -->

### Sigma: Automated Tool User-Agent in ConnectWise App Sign-in

Detects Azure AD sign-ins to the compromised ConnectWise application IDs using the specific automation user-agent strings observed in the ARTEX-driven campaign.
**Status**: compile (splunk, logscale) ✅ | confidence: high

```yaml
title: Automated Tool User-Agent in ConnectWise App Sign-in
id: d6a0b4e5-7f8c-4d1b-e2a9-4b5c6d7e8f9a
status: experimental
description: >
    Detects Azure AD sign-ins to ConnectWise OAuth applications using automation
    tool user agents observed during the Storm-0940 ARTEX-driven ConnectWise supply
    chain attack, including python-requests, Python-urllib, curl, and azure-toolkit.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/22
tags:
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection_ua:
        UserAgent|startswith:
            - 'python-requests/'
            - 'Python-urllib/'
            - 'curl/'
            - 'azure-toolkit/'
    selection_app:
        AppId:
            - '506e08f9-6e9a-4da4-942b-a099a03644ae'
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - '0de14c77-b9b0-4137-9360-34878a929827'
    condition: selection_ua and selection_app
falsepositives:
    - Legitimate ConnectWise automation scripts using these user agents
level: high
```

<!-- AUDIT: sigma check blocked by network; splunk and logscale convert OK. UserAgent startswith avoids over-matching while catching all observed version strings. Pinning to ConnectWise App IDs reduces FPs from generic python-requests usage. -->

### Snort: Storm-0940 Infrastructure and User-Agent Detection

Two Snort 2.9 rules detecting outbound connections to known Storm-0940 RouterHosting IPs and the custom `azure-toolkit` user-agent string.
**Status**: compile ✅ | confidence: high (IP rule), medium (UA rule)

```
alert ip $HOME_NET any -> [144.172.64.128,144.172.64.99,144.172.64.60,144.172.94.243] any (msg:"Actioner - Outbound Connection to Storm-0940 RouterHosting Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created 2026-10-22; sid:2100001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP azure-toolkit User-Agent Associated with Storm-0940 ARTEX"; flow:established,to_server; content:"azure-toolkit/1.0"; http_header; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created 2026-10-22; sid:2100002; rev:1;)
```

<!-- AUDIT: Validated via snort -c /etc/snort/snort.conf -T (Snort 2.9.20): "Snort successfully validated the configuration!" IP rule covers the 4 RouterHosting-range IPs; Brazilian VPN egress IPs excluded due to transience. UA rule limited to azure-toolkit/1.0 (most distinctive; python-requests/curl are too common for network-level detection without additional context). -->

### Suricata: Storm-0940 Infrastructure and User-Agent Detection

Two Suricata rules using dot-notation sticky buffers for the same indicators.
**Status**: compile ✅ | confidence: high (IP rule), medium (UA rule)

```
alert ip $HOME_NET any -> [144.172.64.128,144.172.64.99,144.172.64.60,144.172.94.243] any (msg:"Actioner - Storm-0940 Outbound Connection to Known RouterHosting Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created_at 2026-10-22; sid:2200001; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Storm-0940 ARTEX azure-toolkit User-Agent in HTTP Request"; flow:established,to_server; http.user_agent; content:"azure-toolkit/"; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created_at 2026-10-22; sid:2200002; rev:1;)
```

<!-- AUDIT: Validated via suricata -T -S (Suricata 7.0.3): "Configuration provided was successfully loaded. Exiting." Dot-notation http.user_agent buffer used correctly. IP rule matches Snort rule scope. -->

### YARA

No YARA rules are provided. The sources disclose no file hashes, binary signatures, malware samples, or endpoint file-level artifacts associated with this campaign. ARTEX is described as a Go binary with a Next.js front end, but no sample hashes or distinctive file-level patterns were published.

## Lessons Learned

1. **Multi-tenant OAuth trust is a systemic supply-chain risk.** A single compromised client secret for a widely-deployed multi-tenant application cascades into every tenant where that application is installed. The MSP ecosystem amplifies this: one MSP tool compromise can reach hundreds or thousands of downstream organizations simultaneously.

2. **Service-principal authentication bypasses user-facing security controls.** MFA, conditional access policies targeting interactive sign-ins, and user-behavior analytics are blind to application-only authentication flows. Organizations must implement monitoring specifically for service-principal sign-in anomalies and workload identity conditional access policies.

3. **AI-augmented attack tooling changes the speed calculus.** ARTEX enabled Storm-0940 to operate at "machine speed," automating reconnaissance, credential spraying, and post-compromise activities across thousands of tenants simultaneously. The shift from initial targeting to Global Administrator access in under 3 hours demonstrates how agentic AI frameworks compress the attack lifecycle.

4. **Persistence through credential planting outlives primary remediation.** Disabling the compromised ConnectWise applications is necessary but insufficient. Organizations must audit all OAuth applications and service principals in their tenant for unauthorized credential additions, not just the known-compromised applications.

5. **Vendor transparency gaps slow response.** ConnectWise has not disclosed how the initial credential was obtained, making it difficult for defenders to assess whether similar compromise vectors exist in other multi-tenant applications they rely on.

## Sources

- [Microsoft Security Blog: Storm-0940 uses ARTEX agentic AI in ConnectWise supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) — primary technical source with IOCs, hunting queries, and detection guidance
- [CyberScoop: Microsoft attributes ConnectWise supply chain attack to China's Storm-0940](https://cyberscoop.com/microsoft-attributes-connectwise-supply-chain-attack-china-storm-0940/) — attribution context and Microsoft executive quotes
- [CyberScoop: ConnectWise Cloud Backup supply chain attack](https://cyberscoop.com/connectwise-cloud-backup-supply-chain-attack/) — Huntress analysis with additional IOC (144.172.94[.]243), tenant compromise statistics, and remediation context
- [The Hacker News: China-linked hackers use ARTEX AI](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html) — Zscaler ARTEX framework analysis, TAG-217/Recorded Future context, sector targeting
- [The Hacker News: ConnectWise resets credentials as Cloud Backup supply chain attack](https://thehackernews.com/2026/10/connectwise-resets-credentials-as-cloud.html) — ConnectWise remediation timeline and Huntress tenant-level impact assessment

---
*Report generated by Actioner*
