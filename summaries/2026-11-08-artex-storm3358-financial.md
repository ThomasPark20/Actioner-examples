# Technical Analysis Report: ARTEX Framework / Storm-3358 Financial Sector Campaign (2026-11-08)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-08
Version: 1.0

## Executive Summary

Storm-3358, a Cambodia-based financially motivated threat actor, has significantly expanded operations using the ARTEX agentic AI hacking framework to target financial institutions across Southeast Asia. Microsoft, Hunt.io, and Security Affairs independently disclosed overlapping aspects of the campaign in early November 2026. The actor leverages ARTEX for automated credential abuse, cloud resource enumeration, Azure AI workload hijacking, and network reconnaissance against banking targets — notably breaching multiple South Korean banks. Separately, six backdoored Docker images impersonating ARTEX AI tooling have been distributed via Docker Hub, embedding an unauthenticated root shell via a `verifyCaptcha()` function in the login handler.

The campaign combines exposed-secret scanning at scale (GitHub, GitLab, Pastebin), automated sign-in with stolen Azure/Entra credentials, lateral movement via WISP RAT and vshell, and AI-resource hijacking (LLMjacking) through an AI reseller domain (xcai[.]pro) that proxies requests to DeepSeek and other backends. Hunt.io's investigation traced ARTEX console and jump server infrastructure across five IPs, including one geolocated to Seoul used for SMB reconnaissance with a distinctive probe artifact (`artex_probe_11876.txt`).

## Background: ARTEX Framework and Targeted Financial Infrastructure

ARTEX is an agentic AI-powered hacking toolkit used by Storm-3358 to automate the attack lifecycle from credential harvesting through lateral movement to objective execution. Unlike conventional C2 frameworks, ARTEX integrates AI backends (routed through xcai[.]pro) to make autonomous decisions during post-exploitation — selecting targets, choosing exploitation paths, and adapting to defensive responses.

The targeted sector is Southeast Asian financial services, with confirmed breaches at South Korean banks. The framework's modular architecture supports multiple RATs (WISP, vshell, AdaptixC2) and can pivot between cloud and on-premises targets. The campaign was publicly disclosed across four independent sources between November 5-8, 2026.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026 (ongoing) | Storm-3358 operates ARTEX framework for automated credential abuse and cloud enumeration |
| 2026-11-05 | Microsoft publishes blog on Storm-3358 secret scanning and ARTEX abuse of exposed secrets |
| 2026-11-06 | Microsoft publishes expanded blog on ARTEX targeting financial sector |
| 2026-11-07 | The Hacker News reports on backdoored Docker images impersonating ARTEX AI tooling |
| 2026-11-08 | Security Affairs publishes Hunt.io investigation linking ARTEX to South Korean bank breaches |

## Root Cause: Exposed Secrets and Credential Abuse

Storm-3358 harvests exposed secrets from public repositories (GitHub, GitLab) and paste sites using automated scanning infrastructure. Stolen credentials — primarily Azure/Entra ID service principal secrets and API keys — are validated through automated sign-in from dedicated infrastructure IPs. Successful credentials are used for Azure resource enumeration, AI workload discovery, and lateral movement into financial networks. The ARTEX framework automates the entire chain from secret discovery through exploitation.

## Technical Analysis of the Malicious Payload

### 1. Credential Harvesting and Secret Scanning

Storm-3358 operates dedicated secret-scanning infrastructure at four known IPs (199.19.77[.]84, 199.19.77[.]18, 65.87.223[.]26, 157.22.126[.]128). These scanners monitor public code repositories and paste sites for exposed cloud credentials, API keys, and service principal secrets. One node (199.19.77[.]18) is a known Tor exit node, providing attribution obfuscation. Validated credentials feed into the ARTEX framework for automated exploitation.

### 2. ARTEX AI-Driven Exploitation

The ARTEX framework uses AI backends routed through xcai[.]pro to orchestrate post-exploitation. After successful credential validation, ARTEX automatically:
- Enumerates Azure subscriptions and resource groups
- Discovers AI/ML workloads (Azure OpenAI, Cognitive Services)
- Hijacks AI compute for LLMjacking (proxying through xcai[.]pro to DeepSeek and other backends)
- Performs credential rotation and persistence via T1098.001 (Additional Cloud Credentials)
- Scans internal networks for lateral movement targets

### 3. C2 Infrastructure

**WISP RAT C2 Cluster:**
- 199.19.95[.]66 (Node 1)
- 199.19.95[.]67 (Node 2)
- 199.19.95[.]68 (Node 3)

**ARTEX Framework Servers:**
- 91.92.240[.]238 (Framework Server 1)
- 85.11.168[.]45 (Framework Server 2)
- 85.11.167[.]52 (C2 Server)
- 178.16.54[.]129 (Framework Server 3)
- 31.77.229[.]35 (Framework Server 4)

**Console and Jump Server Infrastructure (Hunt.io):**
- 38.244.50[.]120 (ARTEX Console)
- 23.248.226[.]250 (Jump Server)
- 154.201.79[.]246 (Rotating Proxy Exit)
- 130.94.31[.]86 (Seoul — SMB Reconnaissance)
- 156.251.11[.]39 (SMB Recon / Probing)

**AI Reseller Domain:**
- xcai[.]pro — proxies AI requests to DeepSeek and other backends for LLMjacking

**Additional RATs observed:** vshell, AdaptixC2

### 4. Backdoored Docker Images

Six Docker Hub images impersonate ARTEX AI tooling and contain a backdoored login handler:

| Docker Image | Description |
|-------------|-------------|
| tomicdd/artex | Backdoored ARTEX image |
| congdonglinux/artex | Backdoored ARTEX image |
| mianhuatang11/artex | Backdoored ARTEX image |
| andy1099zz/artex | Backdoored ARTEX image |
| dgddw/artex | Backdoored ARTEX image |
| ylh440104/artex | Backdoored ARTEX image |

The backdoor injects a `verifyCaptcha()` function into the login handler that provides unauthenticated root shell access to the container host. This is a supply-chain vector separate from the Storm-3358 intrusion campaign but exploiting the same ARTEX brand.

### 5. SMB Reconnaissance Probe

The ARTEX framework deploys a distinctive probe artifact during network scanning: `artex_probe_11876.txt`. This file is written to SMB shares during reconnaissance and serves as a connectivity/write-access test. Its presence on a file share is a high-confidence indicator of ARTEX scanning activity.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IP addresses: `[.]` replacing dots (e.g., `199.19.95[.]66`)
> - Domains: `[.]` replacing dots (e.g., `xcai[.]pro`)

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 199.19.95[.]66 | WISP RAT C2 Node 1 |
| IP | 199.19.95[.]67 | WISP RAT C2 Node 2 |
| IP | 199.19.95[.]68 | WISP RAT C2 Node 3 |
| IP | 91.92.240[.]238 | ARTEX Framework Server 1 |
| IP | 85.11.168[.]45 | ARTEX Framework Server 2 |
| IP | 85.11.167[.]52 | ARTEX C2 Server |
| IP | 178.16.54[.]129 | ARTEX Framework Server 3 |
| IP | 31.77.229[.]35 | ARTEX Framework Server 4 |
| IP | 38.244.50[.]120 | ARTEX Console (Hunt.io) |
| IP | 23.248.226[.]250 | Jump Server (Hunt.io) |
| IP | 154.201.79[.]246 | Rotating Proxy Exit (Hunt.io) |
| IP | 130.94.31[.]86 | Seoul SMB Recon (Hunt.io) |
| IP | 156.251.11[.]39 | SMB Recon / Probing (Hunt.io) |
| IP | 199.19.77[.]84 | Secret Scanning Infrastructure |
| IP | 199.19.77[.]18 | Secret Scanning (Tor Exit) |
| IP | 65.87.223[.]26 | Secret Scanning Infrastructure |
| IP | 157.22.126[.]128 | Secret Scanning Infrastructure |
| Domain | xcai[.]pro | AI Reseller (LLMjacking proxy) |

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| tomicdd/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |
| congdonglinux/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |
| mianhuatang11/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |
| andy1099zz/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |
| dgddw/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |
| ylh440104/artex | latest | Backdoored Docker image with root shell via verifyCaptcha() |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | artex_probe_11876.txt | N/A | SMB reconnaissance probe artifact |

### Behavioral

- Outbound connections to WISP C2 /24 block (199.19.95.64/26) from internal hosts
- DNS queries for xcai[.]pro from enterprise networks
- Azure/Entra ID sign-in anomalies from secret-scanning IPs
- Presence of `artex_probe_11876.txt` on SMB shares
- `verifyCaptcha()` function in Docker container login handlers
- Automated Azure resource enumeration following credential validation
- AI workload discovery and proxy traffic to DeepSeek backends

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of exposed services and cloud endpoints |
| T1505.003 | Server Software Component: Web Shell | Backdoored Docker login handler providing root shell |
| T1105 | Ingress Tool Transfer | WISP RAT and additional tooling delivery to compromised hosts |
| T1110.003 | Brute Force: Password Spraying | Automated credential testing against Azure/Entra ID |
| T1552.001 | Unsecured Credentials: Credentials In Files | Scanning public repos for exposed secrets and API keys |
| T1078.004 | Valid Accounts: Cloud Accounts | Sign-in with harvested Azure/Entra credentials |
| T1071 | Application Layer Protocol | C2 communications over standard protocols |
| T1595.002 | Active Scanning: Vulnerability Scanning | SMB reconnaissance with artex_probe_11876.txt probe |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Token-based access to Azure resources |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence via additional Azure service principal credentials |
| T1580 | Cloud Infrastructure Discovery | Azure subscription and resource group enumeration |
| T1530 | Data from Cloud Storage Object | Access to cloud storage via compromised credentials |
| T1651 | Cloud Administration Command | Execution of Azure management commands |
| T1496 | Resource Hijacking | LLMjacking — hijacking AI compute via xcai[.]pro proxy |
| T1593.003 | Search Open Technical Databases | Scanning GitHub/GitLab/Pastebin for exposed secrets |

## Impact Assessment

The campaign impacts Southeast Asian financial institutions with confirmed breaches at multiple South Korean banks. The combination of automated credential harvesting, AI-driven exploitation, and multiple C2 channels (WISP, vshell, AdaptixC2) creates a persistent, adaptive threat. The backdoored Docker images represent a separate supply-chain risk to any organization pulling ARTEX-branded containers from Docker Hub. LLMjacking via xcai[.]pro imposes compute costs on victims while funding the actor's AI-assisted operations.

## Detection & Remediation

### Immediate Detection

- Search network logs for connections to any of the 17 IOC IPs listed above
- Search DNS logs for queries to `xcai.pro`
- Search file shares for `artex_probe_11876.txt`
- Audit Docker images for any of the six backdoored image names
- Search container images for `verifyCaptcha` function in login handlers
- Review Azure/Entra ID sign-in logs for authentications from the four secret-scanning IPs

### Remediation

1. **Block** all 17 IOC IPs at perimeter firewalls and proxy
2. **Block** DNS resolution for xcai[.]pro
3. **Rotate** all Azure/Entra service principal credentials and API keys, especially any found in public repositories
4. **Remove** any of the six backdoored Docker images from container registries and running workloads
5. **Audit** Azure subscriptions for unauthorized service principals, resource groups, and AI workload deployments
6. **Review** GitHub/GitLab repositories for accidentally committed secrets and enable secret scanning

### Long-Term Hardening

- Implement automated secret scanning in CI/CD pipelines to prevent credential leaks
- Enforce conditional access policies restricting Azure sign-ins to known networks
- Deploy container image signing and admission control to prevent unauthorized images
- Monitor for anomalous AI compute usage patterns (LLMjacking indicator)

## Detection Rules

These 12 rules cover Storm-3358/ARTEX network infrastructure (WISP C2, framework servers, secret-scanning IPs, Hunt.io infrastructure, xcai[.]pro DNS) and file-level artifacts (SMB probe, backdoored Docker images). The one caveat: IP-based rules require periodic review as infrastructure rotates; the YARA and DNS rules are more durable indicators.

### Sigma: Storm-3358 ARTEX WISP C2 Server Communication
Detects outbound connections to WISP RAT C2 nodes.
- **Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: Storm-3358 ARTEX WISP C2 Server Communication
id: 3a7e1f2b-8c4d-4e6a-b9f1-2d3e4f5a6b7c
status: experimental
description: Detects outbound network connections to known WISP RAT C2 IP addresses used by Storm-3358 in ARTEX-driven financial sector attacks (November 2026).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/
author: Actioner
date: 2026/11/08
tags:
    - attack.t1071
    - attack.t1105
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|startswith:
            - '199.19.95.66'
            - '199.19.95.67'
            - '199.19.95.68'
    condition: selection
falsepositives:
    - Legitimate services hosted on these IPs (verify ownership before suppressing)
level: high
```

<!-- audit: sigma check passes (MITRE tag fetch blocked by proxy 403, non-blocking); sigma convert --target splunk exit 0; sigma convert --target log_scale exit 0; IPs sourced from Microsoft blog 2026-11-06; no encoding concerns for network_connection logsource -->

### Sigma: Storm-3358 ARTEX Infrastructure Communication
Detects outbound connections to ARTEX framework and C2 servers.
- **Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: Storm-3358 ARTEX Infrastructure Communication
id: 90b3236e-9cf6-4604-955e-2cf5fc93f64d
status: experimental
description: Detects outbound network connections to known ARTEX C2 infrastructure IPs used by Storm-3358 for reconnaissance and command delivery in financial sector attacks (November 2026).
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/
author: Actioner
date: 2026/11/08
tags:
    - attack.t1071
    - attack.t1595.002
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|startswith:
            - '91.92.240.238'
            - '85.11.168.45'
            - '85.11.167.52'
            - '178.16.54.129'
            - '31.77.229.35'
    condition: selection
falsepositives:
    - Legitimate services on these IPs (unlikely given hosting profile)
level: high
```

<!-- audit: sigma check passes (MITRE tag fetch blocked by proxy 403, non-blocking); sigma convert --target splunk exit 0; sigma convert --target log_scale exit 0; IPs sourced from Microsoft blog 2026-11-06; five distinct IPs across different ASNs -->

### Sigma: Storm-3358 ARTEX Secret Scanning Infrastructure Communication
Detects connections to IPs used for cloud credential abuse and secret scanning.
- **Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: Storm-3358 ARTEX Secret Scanning Infrastructure Communication
id: 1585c802-51b1-4597-9c34-fb43c5491860
status: experimental
description: Detects network connections to IPs used by Storm-3358 for cloud credential abuse and secret scanning via ARTEX framework, including sign-ins, Azure resource enumeration, and AI workload reconnaissance.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
author: Actioner
date: 2026/11/08
tags:
    - attack.t1078.004
    - attack.t1552.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|startswith:
            - '199.19.77.84'
            - '199.19.77.18'
            - '65.87.223.26'
            - '157.22.126.128'
    condition: selection
falsepositives:
    - Tor exit node traffic (199.19.77.18 is a known Tor exit)
level: high
```

<!-- audit: sigma check passes; sigma convert --target splunk exit 0; sigma convert --target log_scale exit 0; IPs sourced from Microsoft blog 2026-11-05; 199.19.77.18 known Tor exit noted in FP -->

### Sigma: ARTEX Console and Jump Server Infrastructure Communication
Detects connections to ARTEX infrastructure IPs identified by Hunt.io.
- **Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ARTEX Console and Jump Server Infrastructure Communication
id: 0b9752c8-3e55-48e9-8283-90de78980efe
status: experimental
description: Detects network connections to ARTEX console and jump server IPs identified by Hunt.io in their investigation of Korean bank breaches linked to the ARTEX framework.
references:
    - https://securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html
author: Actioner
date: 2026/11/08
tags:
    - attack.t1071
    - attack.t1190
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|startswith:
            - '38.244.50.120'
            - '23.248.226.250'
            - '154.201.79.246'
            - '130.94.31.86'
            - '156.251.11.39'
    condition: selection
falsepositives:
    - Rotating proxy exit IPs may generate noise (154.201.79.246); correlate with other indicators
level: high
```

<!-- audit: sigma check passes; sigma convert --target splunk exit 0; sigma convert --target log_scale exit 0; IPs sourced from Hunt.io investigation via Security Affairs; 154.201.79.246 noted as rotating proxy exit -->

### Sigma: ARTEX xcai AI Reseller Domain DNS Query
Detects DNS queries to the AI reseller domain used by ARTEX for LLMjacking.
- **Compile status:** ✅ compiles | **Confidence:** high

```yaml
title: ARTEX xcai AI Reseller Domain DNS Query
id: 8c6fdaa6-84e3-47dd-a6a7-f997ca4a1806
status: experimental
description: Detects DNS queries to xcai.pro, the AI model reseller domain used by the ARTEX operator to route requests to DeepSeek and other AI backends.
references:
    - https://securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html
author: Actioner
date: 2026/11/08
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'xcai.pro'
    condition: selection
falsepositives:
    - Legitimate use of the xcai.pro AI reseller service (unlikely in enterprise environments)
level: high
```

<!-- audit: sigma check passes; sigma convert --target splunk exit 0; sigma convert --target log_scale exit 0; domain sourced from Hunt.io investigation; endswith catches subdomains -->

### YARA: ARTEX SMB Probe File Artifact
Detects the distinctive ARTEX network scanning probe file.
- **Compile status:** ✅ compiles | **Confidence:** high

```yara
rule ARTEX_Probe_File_Artifact
{
    meta:
        description = "Detects the ARTEX SMB reconnaissance probe file artifact (artex_probe_11876.txt) written by the framework's test scripts during network scanning"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $probe = "artex_probe_11876" ascii wide nocase

    condition:
        $probe
}
```

<!-- audit: yarac exit 0; string sourced from Hunt.io investigation of SMB reconnaissance; nocase+wide for encoding variants; high specificity due to unique probe ID -->

### YARA: ARTEX Backdoored Docker Login Handler
Detects backdoored Docker images with unauthenticated root shell.
- **Compile status:** ✅ compiles | **Confidence:** high

```yara
rule ARTEX_Backdoored_Docker_Login_Handler
{
    meta:
        description = "Detects the backdoored ARTEX Docker image login handler containing the verifyCaptcha() function that provides unauthenticated root shell access"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $func = "verifyCaptcha" ascii wide
        $docker1 = "tomicdd/artex" ascii wide
        $docker2 = "congdonglinux/artex" ascii wide
        $docker3 = "mianhuatang11/artex" ascii wide
        $docker4 = "andy1099zz/artex" ascii wide
        $docker5 = "dgddw/artex" ascii wide
        $docker6 = "ylh440104/artex" ascii wide

    condition:
        $func or any of ($docker*)
}
```

<!-- audit: yarac exit 0; verifyCaptcha sourced from THN Docker backdoor report; six image names from same source; OR condition catches either indicator independently; "verifyCaptcha" is distinctive enough to avoid FP in non-ARTEX contexts -->

### Snort: Storm-3358 WISP RAT C2 Communication
Alerts on traffic to WISP RAT C2 nodes.
- **Compile status:** ✅ compiles | **Confidence:** high

```
alert ip $HOME_NET any -> 199.19.95.66 any (msg:"ARTEX Storm-3358 WISP RAT C2 Node 1"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100050; rev:1;)
alert ip $HOME_NET any -> 199.19.95.67 any (msg:"ARTEX Storm-3358 WISP RAT C2 Node 2"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100051; rev:1;)
alert ip $HOME_NET any -> 199.19.95.68 any (msg:"ARTEX Storm-3358 WISP RAT C2 Node 3"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100052; rev:1;)
```

<!-- audit: snort -T exit 0 via /etc/snort/rules/local.rules; Snort 2.9.20; IPs from Microsoft blog; one rule per IP for granular alerting -->

### Snort: Storm-3358 ARTEX Infrastructure Communication
Alerts on traffic to ARTEX framework and C2 servers.
- **Compile status:** ✅ compiles | **Confidence:** high

```
alert ip $HOME_NET any -> 91.92.240.238 any (msg:"ARTEX Storm-3358 Framework Server 1"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100053; rev:1;)
alert ip $HOME_NET any -> 85.11.168.45 any (msg:"ARTEX Storm-3358 Framework Server 2"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100054; rev:1;)
alert ip $HOME_NET any -> 85.11.167.52 any (msg:"ARTEX Storm-3358 C2 Server"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100055; rev:1;)
alert ip $HOME_NET any -> 178.16.54.129 any (msg:"ARTEX Storm-3358 Framework Server 3"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100056; rev:1;)
alert ip $HOME_NET any -> 31.77.229.35 any (msg:"ARTEX Storm-3358 Framework Server 4"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; sid:2100057; rev:1;)
```

<!-- audit: snort -T exit 0 via /etc/snort/rules/local.rules; Snort 2.9.20; IPs from Microsoft blog; five framework/C2 IPs across different ASNs -->

### Suricata: Storm-3358 WISP RAT C2 Communication
Alerts on established connections to WISP C2 cluster.
- **Compile status:** ✅ compiles | **Confidence:** high

```
alert ip $HOME_NET any -> [199.19.95.66,199.19.95.67,199.19.95.68] any (msg:"Actioner - Storm-3358 WISP RAT C2 Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; metadata:author Actioner, created_at 2026-11-08; sid:2200050; rev:1;)
```

<!-- audit: suricata -T exit 0; Suricata 7.0.3; IP group syntax for compact rule; flow:established,to_server reduces noise -->

### Suricata: Storm-3358 ARTEX Infrastructure Communication
Alerts on established connections to ARTEX framework servers.
- **Compile status:** ✅ compiles | **Confidence:** high

```
alert ip $HOME_NET any -> [91.92.240.238,85.11.168.45,85.11.167.52,178.16.54.129,31.77.229.35] any (msg:"Actioner - Storm-3358 ARTEX Infrastructure Communication"; flow:established,to_server; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/; metadata:author Actioner, created_at 2026-11-08; sid:2200051; rev:1;)
```

<!-- audit: suricata -T exit 0; Suricata 7.0.3; IP group syntax; five framework/C2 IPs -->

### Suricata: ARTEX xcai.pro AI Reseller DNS Query
Alerts on DNS queries to the ARTEX AI reseller domain.
- **Compile status:** ✅ compiles | **Confidence:** high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - ARTEX xcai.pro AI Reseller DNS Query"; dns.query; content:"xcai.pro"; endswith; nocase; classtype:trojan-activity; reference:url,securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html; metadata:author Actioner, created_at 2026-11-08; sid:2200052; rev:1;)
```

<!-- audit: suricata -T exit 0; Suricata 7.0.3; dns.query keyword with endswith catches subdomains; nocase for case-insensitive matching -->

## Lessons Learned

This campaign demonstrates the operational maturity of agentic AI in offensive tooling. ARTEX represents a shift from AI-assisted to AI-driven attack automation, where the framework makes autonomous post-exploitation decisions. The combination of mass credential harvesting, automated cloud exploitation, and AI-resource hijacking (LLMjacking) collapses the time from initial access to objective. Defenders should prioritize secret scanning in CI/CD, conditional access policies for cloud workloads, and container image provenance controls.

## Sources

- [Microsoft Security Blog — Secret Scanning](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/) — Storm-3358 secret scanning infrastructure IPs and credential abuse TTPs
- [Microsoft Security Blog — Financial Sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) — ARTEX expansion, WISP C2 IPs, framework server infrastructure
- [Security Affairs / Hunt.io Investigation](https://securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html) — Hunt.io console/jump server IPs, Seoul SMB recon, xcai.pro AI reseller, South Korean bank breaches
- [The Hacker News — Backdoored Docker Images](https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html) — Six backdoored Docker images, verifyCaptcha() backdoor function

---
*Report generated by Actioner*
