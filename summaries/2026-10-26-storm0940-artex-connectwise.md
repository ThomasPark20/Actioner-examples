# Technical Analysis Report: Storm-0940 ARTEX ConnectWise Supply Chain Attack (October 2026)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-10-26
Version: DRAFT 1.0

## Executive Summary

Chinese state-aligned threat actor Storm-0940, active since 2021, leveraged the ARTEX agentic AI penetration testing framework to automate a supply chain attack through ConnectWise Cloud Backup in October 2026. The actor compromised the application credentials of multiple ConnectWise cloud applications (Cloud Backup, MS Teams, MS Graph) and used them to authenticate to over 2,250 downstream Microsoft 365 customer tenants without interactive sign-in. Between October 10 and 14, a password-spray campaign from IP 144.172.64[.]99 generated over 151,000 failed logons against 327 accounts across eight organizations. On October 15, the actor transitioned to exploiting the stolen ConnectWise application credentials, reaching privileged cloud access in some tenants in under 3 hours. Post-authentication activity included Microsoft Graph reconnaissance, application credential additions for persistence, identity/group modifications, privileged role assignments (including self-assignment of Global Administrator), and bulk Azure Key Vault secret reads.

Microsoft Threat Intelligence attributed the campaign and published detection guidance, hunting queries, and IOCs on October 21, 2026. The attack highlights the risk of highly privileged multi-tenant OAuth applications as a supply chain vector and demonstrates how agentic AI frameworks accelerate adversary operations to machine speed.

## Background: ConnectWise Cloud Services and Microsoft 365 OAuth Trust

ConnectWise is a widely used managed service provider (MSP) platform whose cloud applications -- Cloud Backup, MS Teams integration, and MS Graph integration -- are deployed as multi-tenant OAuth applications in customers' Microsoft 365 / Entra ID environments. These applications hold pre-authorized, high-privilege permissions (delegated or application-level) to access customer data, directories, and services. Because they are trusted third-party integrations installed via admin consent, they can authenticate as service principals without interactive user sign-in, making them a high-value target for supply chain compromise.

The ARTEX framework is an open-source agentic AI penetration testing tool written in Go with a Next.js frontend. It uses multi-agent LLM systems to run autonomous penetration tests from reconnaissance through data exfiltration with minimal human input. Agents build a graph of discovered assets and vulnerabilities and can work in parallel. Zscaler analysis found ARTEX configurations using DeepSeek models through OpenAI-compatible gateways, with models reviewing each other's findings (GLM reviewing DeepSeek and its subagents). A Claude Code prompt history was also found in one deployment. The framework's UI supports English, Korean, Mandarin, Spanish, and Japanese. ARTEX was previously linked to breaches of Korean financial institutions before being made closed-source.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2021 (ongoing) | Storm-0940 begins operations; first detailed by Microsoft in November 2024 in connection with the Quad7 / CovertNetwork-1658 botnet |
| 2026-08-17 | Recorded Future (TAG-217) observes Storm-0940 testing remote-access infrastructure and running internet scans |
| 2026-09 (early) | Storm-0940 begins using ARTEX against hundreds of organizations across multiple sectors |
| 2026-10-10 | Password-spray campaign begins from 144.172.64[.]99 targeting Microsoft 365 and Exchange Online |
| 2026-10-11 | Peak spray activity: ~2,900 failed logons per minute |
| 2026-10-14 | Password-spray campaign ends; 151,000+ failed logons, 327 accounts, 8 organizations; no successful authentication observed |
| 2026-10-15 | Storm-0940 gains control of ConnectWise cloud application identities; begins authenticating to customer tenants; ARTEX agents attempt sign-ins to 2,250+ tenants |
| 2026-10-15 to 16 | Post-authentication activity observed: Graph reconnaissance, credential additions, role assignments, Key Vault access; VPN IPs 187.15.88[.]186, 187.15.89[.]186, 187.15.90[.]217 used |
| 2026-10-16 | ConnectWise issues initial advisory |
| 2026-10-17 | ConnectWise temporarily shuts down services |
| 2026-10-21 | Microsoft publishes full analysis; ConnectWise begins phased service restoration |
| 2026-10-23 | Wiz and Zscaler publish supplementary analyses |

## Root Cause: Supply Chain Compromise of ConnectWise OAuth Application Credentials

The initial access vector was the compromise of ConnectWise cloud application authentication material (OAuth client credentials). Microsoft's blog does not detail how the credentials were stolen, deferring to ConnectWise's own advisories and technical remediation guide. Once in possession of the application credentials, Storm-0940 authenticated as the ConnectWise service principals in customer tenants -- applications that customers had already granted high-privilege access to -- bypassing the need for interactive user sign-in.

The same infrastructure (144.172.64[.]0/24 range) was used for both the preceding password-spray campaign and the subsequent application credential abuse, suggesting unified operational infrastructure. The transition from brute-force credential attacks to supply chain exploitation indicates a deliberate escalation in TTPs when the spray campaign failed to achieve successful authentication.

## Technical Analysis of the Malicious Payload

### 1. ARTEX Agentic AI Framework Deployment

Storm-0940 deployed ARTEX as the primary automation engine. Key characteristics:

- **Architecture:** Multi-agent LLM system in Go with Next.js frontend
- **Model configuration:** DeepSeek via OpenAI-compatible gateway; GLM and Grok also referenced; models configured to review each other's findings
- **Capabilities observed:** Autonomous reconnaissance, password spraying, OAuth application abuse, parallel breach-path execution
- **Speed:** 2,900 sign-in attempts per minute; 200+ sign-ins in under 4 minutes using 4 application credentials; privileged access achieved in under 3 hours in some cases
- **Session behavior (Wiz):** Sessions lasted 24-30 hours; IPs rotated within minutes when blocked

### 2. Password-Spray Campaign (Oct 10-14)

- **Source IP:** 144.172.64[.]99
- **Targets:** 327 Microsoft 365 and Exchange Online accounts across 8 organizations
- **Volume:** 151,000+ failed logons; 48 accounts received 1,000+ failures each
- **Peak rate:** ~2,900 failures per minute (Oct 11)
- **Result:** 98% lockout responses; no successful authentication observed
- **User-Agents observed:** `Python-urllib/3.12`, `python-requests/2.31.0`, `python-requests/2.34.2`, `curl/7.88.1`, `azure-toolkit/1.0`

### 3. ConnectWise Application Credential Abuse (Oct 15+)

The actor leveraged stolen credentials for three (possibly four) ConnectWise OAuth applications:

| Application | App ID |
|-------------|--------|
| ConnectWise Cloud Backup | `506e08f9-6e9a-4da4-942b-a099a03644ae` |
| ConnectWise - MS Teams | `24205314-2b89-4e07-a2a4-579e898a5640` |
| ConnectWise - MS Graph | `0de14c77-b9b0-4137-9360-34878a929827` |

These applications had pre-existing high-privilege permissions in customer tenants. Authentication as these service principals required no interactive user sign-in and granted access beyond the applications' originally intended purpose.

### 4. Post-Authentication Activity (Microsoft Graph and Directory Operations)

After authentication, ARTEX agents performed:

- **Reconnaissance:** Microsoft Graph API enumeration, directory and permission listing, cloud infrastructure mapping
- **Persistence:** Adding credentials to existing OAuth applications (survives removal of the original compromised app); adding new application owners
- **Privilege Escalation:** Self-assignment of Global Administrator role from a ConnectWise management application; app-role assignments; consent grant modifications
- **Credential Harvesting:** Bulk Azure Key Vault secret reads (20+ SecretGet calls across 3+ vaults in 15-minute windows)
- **Data Access:** Email/mailbox access via Graph, Teams Messages folder access via email client, SharePoint enumeration
- **Identity Manipulation:** Changes to users, groups, authentication methods, Conditional Access policies

### 5. Extended TTPs Observed by Wiz

Wiz researchers (Sapir Federovsky and Rami McCarthy) observed additional behaviors:

- API route discovery and repeated sign-in flow initiation
- Probing SSO and Microsoft 365 endpoints
- Password spraying against corporate Okta and Entra ID
- Abuse of password-reset and account-recovery endpoints
- Registration with throwaway email addresses
- Scanning for broken access controls and cross-tenant data access

### 6. Anti-Forensics / Evasion Techniques

- IP rotation within minutes of being blocked
- Use of VPN infrastructure (Brazilian IPs 187.15.x.x) to obscure origin
- Leveraging trusted third-party application identities to blend with legitimate traffic
- Distributed sessions lasting 24-30 hours across rotating infrastructure

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `144.172.64[.]99`)
> - URLs: `hxxps://` (e.g., `hxxps://evil[.]com/payload`)

### Package / Software Level

| Package / Component | Compromised Version | Description |
|---------------------|-------------------|-------------|
| ConnectWise Cloud Backup | App ID: `506e08f9-6e9a-4da4-942b-a099a03644ae` | OAuth application credentials compromised; used to access customer M365 tenants |
| ConnectWise - MS Teams | App ID: `24205314-2b89-4e07-a2a4-579e898a5640` | OAuth application credentials compromised |
| ConnectWise - MS Graph | App ID: `0de14c77-b9b0-4137-9360-34878a929827` | OAuth application credentials compromised |

### File System

No file system indicators were published in the source reporting. This is a cloud-native attack leveraging OAuth application credentials and Microsoft Graph APIs without deploying file-based payloads.

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 144.172.64[.]99 | Password-spray infrastructure (Oct 10-14); also matches ConnectWise advisory IOC |
| IP | 144.172.64[.]60 | Service principal sign-ins and Graph API activity in customer environments |
| IP | 144.172.64[.]128 | Service principal sign-ins and Graph API activity in customer environments |
| IP | 187.15.88[.]186 | VPN IP used to access Graph via compromised apps (transient, relevant Oct 15-16) |
| IP | 187.15.89[.]186 | VPN IP used to access Graph via compromised apps (transient, relevant Oct 15-16) |
| IP | 187.15.90[.]217 | VPN IP used to access Graph via compromised apps (transient, relevant Oct 15-16) |

### Behavioral

**User-Agent strings observed in ARTEX/Storm-0940 tooling:**
- `Python-urllib/3.12`
- `python-requests/2.31.0`
- `python-requests/2.34.2`
- `curl/7.88.1`
- `azure-toolkit/1.0`

**Authentication patterns:**
- Service principal sign-ins using ConnectWise application IDs without interactive user sign-in
- 200+ sign-ins in under 4 minutes using 4 application credentials
- Self-assignment of Global Administrator role by a service principal
- Bulk Azure Key Vault secret access (20+ reads across 3+ vaults in 15-minute windows)

**Post-authentication indicators:**
- Application credential additions to existing OAuth apps (persistence)
- App-role assignment changes by service principals to themselves
- Newly added OAuth applications accessing Teams Messages folder via email client
- Graph SharePoint enumeration from suspicious OAuth app context

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1595 | Active Scanning | Scanning cloud resources to find targets; API route discovery |
| T1078.004 | Valid Accounts: Cloud Accounts | Authenticating using compromised ConnectWise cloud application credentials |
| T1195 | Supply Chain Compromise | Compromising a multi-tenant OAuth application to access downstream customers |
| T1199 | Trusted Relationship | Using pre-authorized ConnectWise apps' trust in customer tenants |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Self-assignment of Global Administrator from ConnectWise management app |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Adding credentials to existing OAuth applications for persistence |
| T1528 | Steal Application Access Token | Compromising OAuth application authentication material |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Bulk secret reads from Azure Key Vaults |
| T1087.004 | Account Discovery: Cloud Account | Identifying privileged accounts via Graph and directory enumeration |
| T1580 | Cloud Infrastructure Discovery | Mapping cloud infrastructure, enumerating storage and ARM resources |
| T1110.003 | Brute Force: Password Spraying | 151,000+ spray attempts against M365/Exchange Online accounts |

## Impact Assessment

- **Breadth:** 2,250+ Microsoft 365 tenants targeted; 327 accounts across 8 organizations hit in the spray campaign; hundreds of organizations across 15+ sectors targeted since September 2026
- **Sectors:** Aerospace/defense, automotive, chemicals, energy, financial services, government, healthcare-adjacent, legal, manufacturing, media, military, semiconductor, software, technology, think tanks/non-profits
- **Depth:** Privileged cloud access achieved in some tenants in under 3 hours; Global Administrator role obtained via self-assignment; bulk Key Vault secrets harvested; email, Teams, and SharePoint data accessed
- **Persistence risk:** Application credential additions survive removal of the original compromised application, requiring explicit credential audit and rotation
- **Stealth:** Legitimate ConnectWise application identities used, blending with normal third-party service traffic; VPN and IP rotation to evade blocking

## Detection & Remediation

### Immediate Detection

**Check for ConnectWise application presence (search by App ID, not display name):**

```kql
OAuthAppInfo
| where OAuthAppId in (
    "506e08f9-6e9a-4da4-942b-a099a03644ae",
    "24205314-2b89-4e07-a2a4-579e898a5640",
    "0de14c77-b9b0-4137-9360-34878a929827"
)
| project AppName, OAuthAppId, ServicePrincipalId, AppStatus, PrivilegeLevel, IsAdminConsented
```

**Review service principal sign-ins and Graph activity (Defender XDR):**

```kql
let Apps = dynamic([
    "506e08f9-6e9a-4da4-942b-a099a03644ae",
    "24205314-2b89-4e07-a2a4-579e898a5640",
    "0de14c77-b9b0-4137-9360-34878a929827"
]);
let IPs = dynamic(["144.172.64.60", "144.172.64.99", "144.172.64.128"]);
union kind=outer
    (EntraIdSpnSignInEvents | extend EventType = "Sign-in"),
    (GraphAPIAuditEvents | extend EventType = "Graph API", IPAddress = IpAddress)
| where Timestamp >= datetime(2026-10-13)
| where ApplicationId in (Apps)
| where IPAddress in (IPs)
| order by Timestamp asc
```

**Review service principal sign-ins (Sentinel):**

```kql
let ConnectWiseApps = dynamic([
    "506e08f9-6e9a-4da4-942b-a099a03644ae",
    "24205314-2b89-4e07-a2a4-579e898a5640",
    "0de14c77-b9b0-4137-9360-34878a929827"
]);
SigninLogs
| where TimeGenerated >= datetime(2026-10-13)
| where AppId in (ConnectWiseApps)
| project TimeGenerated, AppId, ServicePrincipalName, ResourceDisplayName, IPAddress
| order by TimeGenerated asc
```

**Detect bulk Key Vault secret reads:**

```kql
CloudKeyVaultEvents
| where Timestamp > ago(14d)
| where ActivityName == "SecretGet" and HttpStatusCode == 200
| summarize SecretGets = count(), VaultCount = dcount(AzureResourceId), IPs = make_set(IPAddress, 20)
    by bin(Timestamp, 15m), AccountObjectId, AccountTenantId
| where SecretGets >= 20 and VaultCount >= 3
```

### Remediation

1. **Keep ConnectWise app connections disabled** until ConnectWise issues formal restoration instructions
2. **Preserve evidence first** -- do not delete enterprise applications before capturing configuration and audit logs
3. **Search every tenant for the three application IDs** (not display names) and record each local service-principal Object ID, including tenants where the integration is no longer used
4. **Review Entra sign-in and audit logs** from at least October 15 (October 1 where records exist): credential additions, new apps/owners, app-role assignments, consent grants, privileged role changes, Conditional Access modifications
5. **Review M365 audit records** for unusual mail/file access, forwarding rules, inbox rules, delegated mailbox permissions, and SharePoint enumeration from unusual IPs
6. **Remove unauthorized artifacts:** credentials, grants, owners, assignments, and identities added by the threat actor; revoke excess permissions and rotate credentials
7. **Verify vendor remediation** removed all unauthorized access and assess impact on backup/restore workflows

### Long-Term Hardening

- Apply least privilege to multi-tenant app permissions and admin consent
- Monitor credential additions, privilege assignments, and app-only activity for highly privileged applications
- Implement Conditional Access policies restricting service principal sign-ins by IP, location, and risk
- Review and audit third-party OAuth application permissions regularly
- Deploy Microsoft Defender for Cloud Apps alerts for suspicious OAuth application activity
- Consider workload identity protection with Entra Workload ID

### Microsoft Defender Alerts (Pre-built)

**Defender XDR:**
- Unusual Microsoft Graph activity associated with compromised ConnectWise application
- Application self-assigned Global Administrator role
- Graph API activity from a Microsoft threat intelligence IP address
- Suspicious sign-in from verified nation-state threat actor infrastructure

**Defender for Cloud Apps:**
- Suspicious addition of app role assignments to service principal
- Suspicious mail access activity by OAuth application following role assignment
- Newly added OAuth application accessing Teams Messages folder via email client
- Suspicious addition of application role assignments by service principal to itself
- High-privilege application roles assigned to a service principal

**Defender for Key Vault:**
- KV_AccountVolumeAccessDeniedAnomaly

## Detection Rules

These detections target the Storm-0940 ConnectWise supply chain attack at PoC/advisory-specific altitude. The Sigma rules focus on Azure/Entra cloud audit logs where the primary detection value lies; Snort/Suricata rules cover the known attacker IPs at the network level. All Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; `sigma check` could not run due to MITRE ATT&CK data fetch restrictions in this environment. Compiles does not equal fires -- verify in your pipeline with the KQL hunting queries above.

### Sigma: Compromised ConnectWise OAuth Application Sign-in Activity

Detects service principal sign-ins from the three ConnectWise OAuth application IDs compromised in the Storm-0940 supply chain attack.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Fields: AppId is standard Azure SigninLogs field. High confidence: keys on exact compromised application IDs published by Microsoft; no benign overlap while apps are supposed to be disabled. -->
```yaml
title: Compromised ConnectWise OAuth Application Sign-in Activity
id: 7c3e8b4a-1f5d-4a9e-b2c6-8d0f3e7a5b19
status: experimental
description: >
    Detects service principal sign-ins from ConnectWise Cloud Backup, MS Teams,
    or MS Graph OAuth applications compromised in the October 2026 Storm-0940
    supply chain attack. These application IDs should be disabled per Microsoft
    and ConnectWise guidance until formal restoration instructions are issued.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/26
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
            - '24205314-2b89-4e07-a2a4-579e898a5640'
            - '0de14c77-b9b0-4137-9360-34878a929827'
    condition: selection_app
falsepositives:
    - Legitimate ConnectWise service operations after vendor confirms remediation is complete
level: high
```

### Sigma: Sign-in from Known Storm-0940 Infrastructure IP Addresses

Detects sign-in events from IP addresses attributed by Microsoft to Storm-0940 infrastructure used in the ConnectWise compromise and password-spray campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Fields: IPAddress is standard Azure SigninLogs field. IPs include 3 primary (144.172.64.x) and 3 transient VPN (187.15.x.x, relevant Oct 15-16). High confidence: IPs directly attributed to Storm-0940 by Microsoft TI. Transient VPN IPs may age out; review periodically. -->
```yaml
title: Sign-in from Known Storm-0940 Infrastructure IP Addresses
id: 9a2f1c8d-3e6b-4d7a-a5c0-2b9e4f8d6a1c
status: experimental
description: >
    Detects sign-in events originating from IP addresses attributed to Storm-0940
    infrastructure used in the ConnectWise supply chain compromise and associated
    password-spray campaign (October 2026).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1078.004
    - attack.t1195
logsource:
    product: azure
    service: signinlogs
detection:
    selection_ip:
        IPAddress:
            - '144.172.64.99'
            - '144.172.64.60'
            - '144.172.64.128'
            - '187.15.88.186'
            - '187.15.89.186'
            - '187.15.90.217'
    condition: selection_ip
falsepositives:
    - Unlikely given direct attribution to Storm-0940 operational infrastructure
level: critical
```

### Sigma: ARTEX-Associated Automated User-Agent in Azure Service Principal Sign-in

Detects Azure sign-in events using the specific User-Agent strings observed in ARTEX tooling and Storm-0940 operations.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Fields: UserAgent is standard Azure SigninLogs field. Medium confidence: python-requests and curl UAs are common in legitimate automation; azure-toolkit/1.0 and the specific version combinations are more distinctive. Best paired with the ConnectWise app ID rule for higher fidelity. -->
```yaml
title: ARTEX-Associated Automated User-Agent in Azure Service Principal Sign-in
id: b4d7e2a1-5c9f-4b3e-8a6d-1f0c2e8b7d3a
status: experimental
description: >
    Detects Azure service principal sign-in events using User-Agent strings
    observed in ARTEX agentic AI framework tooling and Storm-0940 operations
    during the ConnectWise supply chain compromise.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection_ua:
        UserAgent:
            - 'Python-urllib/3.12'
            - 'python-requests/2.31.0'
            - 'python-requests/2.34.2'
            - 'curl/7.88.1'
            - 'azure-toolkit/1.0'
    condition: selection_ua
falsepositives:
    - Legitimate automation scripts and developer tooling using Python requests, urllib, or curl for Azure API operations
level: medium
```

### Sigma: Service Principal Self-Assignment of Privileged Directory Role

Detects a service principal adding itself to a privileged directory role, as observed in the Storm-0940 attack where a ConnectWise management app self-assigned Global Administrator.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked (MITRE ATT&CK data 403); splunk convert exit 0; log_scale convert exit 0. Fields: OperationName and InitiatedBy are standard Azure AuditLogs fields; however, InitiatedBy is a nested JSON object in raw logs. The |contains modifier matches the string "ServicePrincipal" within the serialized field. Pipeline-specific field mapping may be needed. Medium confidence: field structure varies by SIEM normalization. -->
```yaml
title: Service Principal Self-Assignment of Privileged Directory Role
id: e1a3c5f8-7d2b-4e9a-b6c4-3f8d0a2e5c7b
status: experimental
description: >
    Detects a service principal adding itself to a privileged directory role
    such as Global Administrator. Storm-0940 used a ConnectWise management
    application to self-assign Global Administrator in compromised tenants.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
author: Actioner
date: 2026/10/26
tags:
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection_operation:
        OperationName|contains: 'Add member to role'
    selection_actor:
        InitiatedBy|contains: 'ServicePrincipal'
    condition: selection_operation and selection_actor
falsepositives:
    - Automated provisioning systems with legitimate privileged role assignments
level: high
```

### Snort: Traffic to/from Storm-0940 Infrastructure IPs

Detects any IP traffic to or from the three primary Storm-0940 infrastructure addresses attributed by Microsoft. Scope to environments where these IPs should never appear in network traffic.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 with minimal config including classification.config and reference.config. Snort 2.9.20. Rules use IP header matching only; no payload inspection needed. High confidence: exact IP match on attributed infrastructure. Limited network-level applicability since the attack is cloud-native (OAuth/Graph API abuse to Microsoft endpoints), but catches any direct probing or scanning from these IPs. -->
```snort
alert ip [144.172.64.60,144.172.64.99,144.172.64.128] any -> $HOME_NET any (msg:"Actioner - Inbound Traffic from Storm-0940 Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; sid:2100001; rev:1;)
alert ip $HOME_NET any -> [144.172.64.60,144.172.64.99,144.172.64.128] any (msg:"Actioner - Outbound Traffic to Storm-0940 Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; sid:2100002; rev:1;)
```

### Suricata: Traffic to/from Storm-0940 Infrastructure IPs

Detects any IP traffic to or from the three primary Storm-0940 infrastructure addresses attributed by Microsoft.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 with Suricata 7.0.3. Rules use IP header matching; no payload inspection needed. Same applicability note as Snort: cloud-native attack with limited network IDS visibility, but provides coverage for direct infrastructure contact. -->
```suricata
alert ip [144.172.64.60,144.172.64.99,144.172.64.128] any -> $HOME_NET any (msg:"Actioner - Inbound Traffic from Storm-0940 Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created_at 2026-10-26; sid:2200001; rev:1;)
alert ip $HOME_NET any -> [144.172.64.60,144.172.64.99,144.172.64.128] any (msg:"Actioner - Outbound Traffic to Storm-0940 Infrastructure"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise; metadata:author Actioner, created_at 2026-10-26; sid:2200002; rev:1;)
```

### YARA: N/A

No file-level indicators (hashes, string patterns, byte sequences) were published in the source reporting. This is a cloud-native attack leveraging OAuth credential abuse and Microsoft Graph API calls without deploying file-based malware.

## Lessons Learned

1. **Multi-tenant OAuth applications are a supply chain risk multiplier.** A single compromised application with high-privilege permissions can cascade to thousands of downstream tenants. Organizations should apply least-privilege principles to third-party OAuth consent and regularly audit application permissions.

2. **Agentic AI dramatically accelerates adversary operations.** ARTEX enabled Storm-0940 to reach 2,250+ tenants at machine speed (2,900 attempts/minute), perform parallel reconnaissance and privilege escalation, and achieve full compromise in under 3 hours. This collapses the defender's response window and requires automated detection and response capabilities.

3. **Application credential persistence outlasts app removal.** Credentials added by the attacker to existing OAuth applications survive deletion of the original compromised application. Remediation must explicitly audit and remove all unauthorized credentials, not just disable the compromised app.

4. **Cloud-native attacks require cloud-native detection.** Traditional network IDS has limited visibility into OAuth/Graph API abuse. Detection must focus on cloud audit logs (Entra sign-in/audit logs, Microsoft Graph activity logs, Purview audit) with rules keying on service principal behavior, application IDs, and anomalous Graph activity patterns.

5. **Search by application ID, not display name.** Display names can be changed; application IDs are immutable identifiers. All hunting and remediation should use the specific application IDs published by Microsoft.

## Sources

- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) -- Primary technical analysis with IOCs, MITRE ATT&CK mappings, KQL hunting queries, and detection guidance
- [CyberScoop](https://cyberscoop.com/microsoft-attributes-connectwise-supply-chain-attack-china-storm-0940/) -- Attribution reporting with timeline and ConnectWise service status details
- [The Hacker News](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html) -- Supplementary reporting including Wiz, Recorded Future (TAG-217), and Zscaler findings on ARTEX configurations and extended TTPs
- [SecurityWeek](https://www.securityweek.com/china-apt-uses-ai-pentest-tool-artex-in-connectwise-attacks/) -- Coverage of Huntress, Zscaler, and CrowdStrike supplementary analyses

---
*Report generated by Actioner*
