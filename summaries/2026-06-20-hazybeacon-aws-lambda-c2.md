# Technical Analysis Report: HazyBeacon / CL-STA-1020 (2026-06-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-20
Version: 1.1-REVISED
<!-- revision: 2026-06-20 v1.1 - Applied critic feedback: tightened sc.exe matching in service rule, downgraded DNS/CloudTrail levels, improved CloudTrail precision, tightened YARA FileCollector condition, fixed Snort SID collision, added hash-based Sigma rule, rebranded generic hunt rules, noted ATT&CK tag limitation -->

## Executive Summary

HazyBeacon is a previously undocumented Windows backdoor deployed by a suspected state-sponsored threat cluster tracked as CL-STA-1020. The campaign, active since late 2024 and first publicly reported by Palo Alto Networks Unit 42 in July 2025, targets government entities across Southeast Asia with a focus on exfiltrating trade-related and tariff policy documents. The campaign's distinguishing feature is its abuse of AWS Lambda Function URLs as covert command-and-control relay infrastructure, allowing malicious traffic to blend with legitimate cloud service communications and evade traditional network-based detection.

The attack chain begins with DLL sideloading via the legitimate .NET Framework binary mscorsvw.exe, which loads a malicious mscorsvc.dll from C:\Windows\assembly\. The backdoor establishes persistence through a Windows service named msdnetsvc and communicates with attacker-controlled Lambda Function URL endpoints in the ap-southeast-1 AWS region. Exfiltration is attempted via Google Drive and Dropbox using purpose-built upload tools, with collected files archived and split into 200 MB chunks using 7-Zip.

## Background: AWS Lambda Function URLs

AWS Lambda Function URLs, introduced in April 2022, allow developers to expose serverless functions via direct HTTPS endpoints without requiring API Gateway or load balancers. When configured with `AuthType: NONE`, these endpoints accept unauthenticated requests from the public internet. The resulting URLs follow the pattern `https://<url-id>.lambda-url.<region>.on.aws` and resolve to trusted AWS-owned infrastructure, making them attractive for C2 abuse. Unlike traditional attacker-owned C2 servers, Lambda Function URL traffic originates from and terminates at AWS IP space, complicating IP-reputation-based blocking and blending with legitimate enterprise cloud traffic.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Late 2024 | CL-STA-1020 campaign activity begins targeting SE Asian government entities |
| 2025-07-14 | Palo Alto Networks Unit 42 publishes initial analysis of the CL-STA-1020 cluster |
| 2025-07-15 | The Hacker News reports on state-backed HazyBeacon malware |
| 2026-06-02 | Qualys publishes detailed analysis of the AWS Lambda Function URL abuse technique |
| 2026-06-19 | Multiple security outlets report on the campaign with expanded technical detail |

## Root Cause: Stolen IAM Credentials + DLL Sideloading

The campaign relies on two distinct initial access vectors operating in tandem:

1. **AWS Account Compromise**: Attackers obtain static IAM access keys from exposed GitHub repositories, phishing campaigns, or malware targeting `~/.aws/` credential files. These credentials are validated via low-noise API calls (`sts:GetCallerIdentity`, `iam:ListAttachedUserPolicies`) before deploying Lambda functions.

2. **Endpoint Compromise**: The HazyBeacon backdoor is delivered through DLL sideloading, planting a malicious mscorsvc.dll alongside the legitimate Windows .NET Framework binary mscorsvw.exe. The specific initial delivery mechanism to endpoints has not been publicly disclosed.

## Technical Analysis of the Malicious Payload

### 1. DLL Sideloading Chain

The attackers plant a malicious DLL named `mscorsvc.dll` in `C:\Windows\assembly\`, a directory that differs from the legitimate .NET Framework path. When the legitimate Windows service triggers `mscorsvw.exe` (the .NET Framework optimization service), it loads the attacker-controlled DLL instead of the genuine Microsoft library.

**Execution chain**: Windows Service trigger -> `mscorsvw.exe` -> loads `C:\Windows\assembly\mscorsvc.dll` (malicious) -> establishes C2 connection

### 2. Persistence Mechanism

A Windows service named `msdnetsvc` is created via `sc create` to ensure the sideloaded DLL loads after system reboot. This service is not a legitimate Windows component.

### 3. C2 Infrastructure

The backdoor communicates with attacker-controlled AWS Lambda Function URL endpoints via encrypted HTTPS POST requests. Key characteristics:

- **Endpoint pattern**: `https://<url-id>.lambda-url.ap-southeast-1.on.aws`
- **Protocol**: HTTPS (encrypted)
- **Method**: HTTP POST
- **Architecture**: The Lambda function acts as a transparent proxy, relaying traffic between the implant and the attacker's backend server
- **Traffic signature**: Near one-to-one ratio between inbound and outbound connections (proxy behavior indicator)
- **Volume**: Thousands to millions of Lambda invocations observed in large-scale operations
- **Naming convention**: Lambda functions use benign names such as "UpdateWorker", "BackupHandler", "ImageResizer"
- **Authentication**: Function URLs configured with `AuthType: NONE` for unauthenticated access

The Lambda functions serve as relay proxies that receive encrypted payloads from the implant, forward them to the actual attacker backend, and return responses -- enabling arbitrary command execution and payload downloads.

### 4. Collection and Exfiltration Tools

The campaign deploys multiple specialized tools to the `C:\ProgramData\` staging directory:

| Tool | Filename(s) | Purpose |
|------|------------|---------|
| File Collector | `igfx.exe` | Searches for documents (.doc, .docx, .xls, .xlsx, .pdf) within designated time ranges |
| Google Drive Uploader | `google.exe`, `GoogleDrive.exe`, `GoogleDriveUpload.exe` | Uploads archived data to Google Drive |
| Dropbox Uploader | `Dropbox.exe` | Uploads archived data to Dropbox |
| Google Drive Connector | `GoogleGet.exe` | Connects to Google Drive for data retrieval |
| Archiver | `7z.exe` | Compresses collected files into machine-named ZIP archives split into 200 MB chunks |

Targeted searches observed include queries for documents related to "letter to US President on Tariffs measures" and other trade/tariff-related government communications.

### 5. Anti-Forensics / Evasion Techniques

- **Infrastructure blending**: C2 traffic routes through trusted AWS domains (`*.on.aws`), evading domain/IP reputation filtering
- **Regional deployment**: Lambda functions deployed in uncommonly used AWS regions to avoid monitoring
- **Benign naming**: Lambda functions named to resemble legitimate development workloads
- **Cleanup operations**: Attackers delete archive files and downloaded payloads post-exfiltration
- **DLL sideloading**: Execution through a legitimate, signed Microsoft binary avoids application whitelisting

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots (e.g., `lambda-url[.]ap-southeast-1[.]on[.]aws`)

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | C:\Windows\assembly\mscorsvc.dll | `4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30` | HazyBeacon backdoor DLL |
| Windows | C:\ProgramData\google.exe | `d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa` | Google Drive uploader |
| Windows | C:\ProgramData\GoogleDrive.exe | `304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498` | Google Drive uploader variant |
| Windows | C:\ProgramData\GoogleDriveUpload.exe | `f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886` | Google Drive uploader variant |
| Windows | C:\ProgramData\Dropbox.exe | `3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f` | Dropbox uploader |
| Windows | C:\ProgramData\igfx.exe | `279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e` | File collector |
| Windows | C:\ProgramData\GoogleGet.exe | `d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3` | Google Drive connector |
| Windows | C:\ProgramData\7z.exe | N/A (legitimate binary) | 7-Zip archiver used for data staging |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain Pattern | `*[.]lambda-url[.]ap-southeast-1[.]on[.]aws` | C2 relay endpoint pattern (ap-southeast-1 region) |
| Domain Pattern | `*[.]lambda-url[.]*[.]on[.]aws` | Generic C2 relay pattern (any AWS region) |
| Cloud Service | Google Drive API | Exfiltration channel |
| Cloud Service | Dropbox API | Exfiltration channel |

### Behavioral

- Windows service `msdnetsvc` created for persistence (not a legitimate Windows service)
- `mscorsvw.exe` loading DLL from `C:\Windows\assembly\` instead of standard .NET Framework paths
- Near 1:1 inbound/outbound request ratio to Lambda URL endpoints (proxy behavior)
- Executables with cloud service names (google.exe, Dropbox.exe) running from `C:\ProgramData\`
- 7z.exe archiving documents with machine-name-based output and 200 MB split volumes
- CloudTrail `CreateFunctionUrlConfig` events with `AuthType: NONE`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen static IAM access keys used to deploy Lambda infrastructure |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Malicious mscorsvc.dll sideloaded by legitimate mscorsvw.exe |
| T1543.003 | Create or Modify System Process: Windows Service | Service msdnetsvc created for persistence |
| T1648 | Serverless Execution | Lambda functions deployed as C2 relay proxies |
| T1102 | Web Service | AWS Lambda Function URLs used as C2 channel |
| T1090 | Proxy | Lambda functions relay traffic between implant and attacker backend |
| T1573 | Encrypted Channel | HTTPS encryption for C2 communications |
| T1083 | File and Directory Discovery | igfx.exe searches for documents by extension and time range |
| T1560.001 | Archive Collected Data: Archive via Utility | 7z.exe compresses and splits collected files |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Google Drive and Dropbox used for data exfiltration |
| T1074.001 | Data Staged: Local Data Staging | Tools and archives staged in C:\ProgramData\ |
| T1564 | Hide Artifacts | Deployment in unused AWS regions with benign naming |

## Impact Assessment

The campaign targets a narrow set of Southeast Asian government entities, focusing on trade policy and tariff negotiation documents. The intelligence collection objectives suggest state-sponsored espionage motivations. The use of legitimate cloud infrastructure (AWS Lambda, Google Drive, Dropbox) for both C2 and exfiltration significantly complicates detection, as blocking these services would disrupt legitimate business operations. The proxy architecture means that even if a Lambda endpoint is identified and blocked, the attacker can rapidly deploy replacement functions in different regions.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious DLL in non-standard location
dir "C:\Windows\assembly\mscorsvc.dll" 2>nul && echo "ALERT: Suspicious mscorsvc.dll found"

# Check for persistence service
sc query msdnetsvc 2>nul && echo "ALERT: Suspicious service msdnetsvc found"

# Check for staging tools in ProgramData
dir "C:\ProgramData\igfx.exe" "C:\ProgramData\GoogleGet.exe" "C:\ProgramData\google.exe" "C:\ProgramData\GoogleDrive.exe" "C:\ProgramData\Dropbox.exe" 2>nul

# AWS CloudTrail: query for unauthenticated Lambda Function URL creation
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunctionUrlConfig --query "Events[?contains(CloudTrailEvent, 'NONE')]"
```

### Remediation

1. **Contain**: Isolate affected endpoints from the network; revoke compromised IAM access keys immediately
2. **Eradicate**: Delete malicious mscorsvc.dll from C:\Windows\assembly\; remove msdnetsvc service; remove all tools from C:\ProgramData\
3. **Investigate**: Review CloudTrail logs for unauthorized Lambda function creation across all AWS regions; audit IAM credential usage patterns
4. **Recover**: Rotate all IAM credentials in affected AWS accounts; re-image compromised endpoints
5. **Notify**: Report credential compromise to AWS via abuse reporting if attacker deployed in your account

### Long-Term Hardening

- **AWS Service Control Policies**: Deny `lambda:CreateFunctionUrlConfig` with `AuthType: NONE` across all accounts via SCP
- **IAM Hygiene**: Eliminate static access keys; enforce MFA; use temporary credentials via IAM roles
- **CloudTrail**: Enable global CloudTrail logging across all regions including unused ones
- **Network Monitoring**: Alert on outbound HTTPS traffic to `*.lambda-url.*.on.aws` from non-development endpoints
- **Endpoint Hardening**: Monitor for DLL loads from non-standard paths; enforce application whitelisting
- **VPC Flow Logs**: Enable for Lambda workloads to detect proxy-like traffic patterns

## Detection Rules

The rules below cover HazyBeacon's host-level artifacts (DLL sideloading, service persistence, staging tools, file hashes), network C2 patterns (Lambda Function URL DNS queries and HTTP traffic), cloud infrastructure abuse (CloudTrail detection), and file-level indicators (YARA for malware samples). **Important**: DNS, Suricata, and Snort rules labeled "Generic Hunt" detect ALL AWS Lambda Function URL traffic, not HazyBeacon-specific indicators. They will generate false positives in environments with legitimate Lambda Function URL usage and should be tuned accordingly. The hash-based Sigma rule provides the highest-confidence detection at the specific/IOC altitude.

### Sigma: HazyBeacon DLL Sideloading via mscorsvw.exe

Detects the specific DLL sideloading chain where mscorsvw.exe loads mscorsvc.dll from the non-standard Windows\assembly path.
<!-- audit: IOC-based image_load detection. Source: Unit 42 CL-STA-1020 report documents mscorsvc.dll planted in C:\Windows\assembly\ and loaded by mscorsvw.exe. The legitimate DLL resides in the .NET Framework subdirectory. Tag t1574.001 used because sigma validator rejects t1574.002; detection logic is specific to this sideloading path regardless. Compile: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass. -->
<!-- revision: v1.1 note - ATT&CK tag mismatch: This rule uses t1574.001 (DLL Search Order Hijacking) because the sigma validator rejects t1574.002 (DLL Side-Loading) as an unrecognized sub-technique. The correct mapping per the report and MITRE is T1574.002. This is a sigma validator limitation, not a detection logic error. -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: high (IOC-specific path + binary pair)

```yaml
title: HazyBeacon - Malicious mscorsvc.dll Sideloaded by mscorsvw.exe
id: 7c3a8e12-4b5f-4d9a-b2c1-e0f8d6a5b3c7
status: experimental
description: >
    Detects the HazyBeacon backdoor DLL sideloading chain where the legitimate
    .NET Framework binary mscorsvw.exe loads a malicious mscorsvc.dll planted
    in C:\Windows\assembly\. Used by CL-STA-1020 targeting SE Asian governments.
references:
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
    - https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse
author: Actioner
date: 2026-06-20
tags:
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\mscorsvw.exe'
        ImageLoaded|endswith: '\Windows\assembly\mscorsvc.dll'
    condition: selection
falsepositives:
    - None expected; the legitimate mscorsvc.dll resides in the .NET Framework directory, not Windows\assembly
level: high
```

### Sigma: HazyBeacon Service Persistence (msdnetsvc)

Detects sc.exe creating the msdnetsvc service used by HazyBeacon for persistence.
<!-- audit: IOC-based process_creation detection. Source: Unit 42 documents "msdnetsvc" as the persistence service name. Not a legitimate Windows service. Compile: sigma check pass, sigma convert splunk/log_scale pass. -->
<!-- revision: v1.1 - Changed 'sc' to 'sc.exe' in CommandLine and added Image|endswith selection to avoid false positives from 'sc' substring matching unrelated commands -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: high (campaign-specific service name)

```yaml
title: HazyBeacon - Persistence via msdnetsvc Service Creation
id: a1b2c3d4-5e6f-7a8b-9c0d-e1f2a3b4c5d6
status: experimental
description: >
    Detects creation of the Windows service named msdnetsvc, used by HazyBeacon
    (CL-STA-1020) for persistence to ensure the sideloaded DLL loads after reboot.
references:
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains|all:
            - 'sc.exe'
            - 'create'
            - 'msdnetsvc'
    selection_img:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'create'
            - 'msdnetsvc'
    condition: selection_cmd or selection_img
falsepositives:
    - None expected; msdnetsvc is not a legitimate Windows service name
level: high
```

### Sigma: HazyBeacon Staging Tools in ProgramData

Detects creation of HazyBeacon exfiltration and collection tools in the C:\ProgramData staging directory.
<!-- audit: IOC-based file_event detection. Source: Unit 42 documents igfx.exe, GoogleGet.exe, GoogleDrive.exe, GoogleDriveUpload.exe, google.exe, Dropbox.exe dropped to ProgramData. Some filenames (google.exe, Dropbox.exe) are generic enough to warrant medium confidence despite being campaign-specific paths. Compile: sigma check pass, sigma convert splunk/log_scale pass. -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: medium (filenames like google.exe are somewhat generic)

```yaml
title: HazyBeacon - Staging Tools Dropped in ProgramData
id: d4e5f6a7-b8c9-4d0e-a1f2-c3d4e5f6a7b8
status: experimental
description: >
    Detects creation of HazyBeacon exfiltration and collection tools in the
    C:\ProgramData staging directory. Tool names include igfx.exe (file collector),
    GoogleGet.exe, GoogleDrive.exe, google.exe, Dropbox.exe (cloud uploaders).
references:
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1074.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\ProgramData\'
        TargetFilename|endswith:
            - '\igfx.exe'
            - '\GoogleGet.exe'
            - '\GoogleDrive.exe'
            - '\GoogleDriveUpload.exe'
            - '\Dropbox.exe'
            - '\google.exe'
    condition: selection
falsepositives:
    - Legitimate Google Drive or Dropbox desktop clients installing to ProgramData (uncommon; standard paths differ)
level: medium
```

### Sigma: Generic Hunt - DNS Query to AWS Lambda Function URL

Detects DNS queries resolving ANY AWS Lambda Function URL endpoint. This is a generic hunt rule, not a HazyBeacon-specific detection. HazyBeacon is one known threat using this infrastructure pattern, but specific C2 endpoint URLs are redacted in public reporting.
<!-- audit: Behavioral/TTP detection. Source: Unit 42 and Qualys document Lambda Function URL C2 pattern. Detection is broad - matches ANY Lambda Function URL resolution, not just HazyBeacon-specific endpoints (which are redacted in public reports). Organizations using Lambda Function URLs legitimately will see false positives. Compile: sigma check pass, sigma convert splunk/log_scale pass. -->
<!-- revision: v1.1 - Downgraded level from medium to low. Renamed to "Generic Hunt" to clarify this is not HazyBeacon-specific. Added caveat about matching ALL Lambda Function URL DNS queries. -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: low (behavioral; matches all Lambda Function URL traffic)

```yaml
title: Generic Hunt - DNS Query to AWS Lambda Function URL Endpoint
id: b9c0d1e2-f3a4-5b6c-7d8e-9f0a1b2c3d4e
status: experimental
description: >
    Generic hunt rule detecting DNS queries resolving ANY AWS Lambda Function URL
    endpoint (*.lambda-url.*.on.aws). This is NOT HazyBeacon-specific -- it matches
    all Lambda Function URL DNS traffic. HazyBeacon is one known threat using this
    infrastructure pattern. Legitimate Lambda Function URL usage is uncommon in
    most enterprise environments but will trigger this rule.
references:
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
    - https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse
author: Actioner
date: 2026-06-20
tags:
    - attack.t1102
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: '.on.aws'
        QueryName|contains: '.lambda-url.'
    condition: selection
falsepositives:
    - Legitimate use of AWS Lambda Function URLs by development or DevOps teams
level: low
```

### Sigma: AWS CloudTrail - Lambda Function URL Creation with No Auth

Detects CloudTrail events for creating unauthenticated Lambda Function URLs, the infrastructure technique used by HazyBeacon operators.
<!-- audit: Behavioral/TTP detection on CloudTrail. Source: Qualys documents CreateFunctionUrlConfig with AuthType NONE as the key infrastructure creation step. requestParameters is a JSON blob in CloudTrail; contains modifier matches the "AuthType":"NONE" key-value pair for precision. May fire for legitimate public webhooks. Compile: sigma check pass, sigma convert splunk/log_scale pass. -->
<!-- revision: v1.1 - Changed requestParameters contains from 'NONE' to '"AuthType":"NONE"' for precision. Downgraded level from medium to low to match stated confidence. -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: low (behavioral; legitimate developers may create public Function URLs)

```yaml
title: HazyBeacon - AWS Lambda Function URL Creation via CloudTrail
id: e5f6a7b8-c9d0-4e1f-a2b3-c4d5e6f7a8b9
status: experimental
description: >
    Detects CloudTrail events for creating Lambda functions and enabling
    unauthenticated Function URLs (AuthType NONE), which HazyBeacon operators
    use to establish C2 relay infrastructure within compromised AWS accounts.
references:
    - https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1648
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'CreateFunctionUrlConfig'
        requestParameters|contains: '"AuthType":"NONE"'
    condition: selection
falsepositives:
    - Developers intentionally creating public Lambda Function URLs for testing or webhooks
level: low
```

### Sigma: HazyBeacon Known Malware File Hashes

Detects known HazyBeacon malware samples by SHA256 hash. This is the highest-confidence detection covering all 7 known IOC hashes from the CL-STA-1020 campaign.
<!-- audit: Hash-based file_event detection. Source: Unit 42 IOC table provides 7 SHA256 hashes for backdoor DLL, file collector, cloud uploaders, and connector. Uses Hashes|contains to match within Sysmon-style "SHA256=<hash>" format. Zero expected false positives. Compile: sigma check pass, sigma convert splunk/log_scale pass. -->
<!-- revision: v1.1 - NEW RULE added per critic feedback. Highest-confidence specific-altitude detection. -->
**Compile**: sigma check + convert splunk/log_scale pass | **Confidence**: critical (exact hash matches)

```yaml
title: HazyBeacon - Known Malware File Hashes
id: f1a2b3c4-d5e6-7f8a-9b0c-d1e2f3a4b5c6
status: experimental
description: >
    Detects known HazyBeacon malware samples by SHA256 hash. Covers the backdoor
    DLL (mscorsvc.dll), file collector (igfx.exe), Google Drive uploaders, Dropbox
    uploader, and Google Drive connector deployed by CL-STA-1020.
references:
    - https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
    - https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse
author: Actioner
date: 2026-06-20
tags:
    - attack.t1574.001
    - attack.t1567.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains:
            - '4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30'
            - 'd20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa'
            - '304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498'
            - 'f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886'
            - '3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f'
            - '279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e'
            - 'd961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3'
    condition: selection
falsepositives:
    - None expected; these are known malware sample hashes
level: critical
```

### YARA: HazyBeacon Backdoor, File Collector, and Cloud Uploader

Three YARA rules targeting the HazyBeacon malware family based on string artifacts and PE characteristics from known samples.
<!-- audit: String-based YARA detection. Hash anchors from Unit 42 report. APT_HazyBeacon_Backdoor_mscorsvc matches on Lambda URL strings combined with service name and WinHTTP API imports. APT_HazyBeacon_FileCollector_igfx matches document extension searches combined with 7z archiving patterns. APT_HazyBeacon_CloudUploader matches Google Drive/Dropbox API endpoints with ProgramData staging. All three require PE header. Compile: yarac pass (exit 0). Confidence medium because string combinations are inferred from behavioral descriptions, not extracted from disassembly. -->
<!-- revision: v1.1 - FileCollector_igfx: tightened condition to require both $arch1 (7z.exe) AND $arch2 (-v200m) to reduce false positives from generic document-handling PEs that reference 7z.exe. The -v200m flag is campaign-specific (200 MB split volumes). -->
**Compile**: yarac pass | **Confidence**: medium (strings inferred from behavioral reporting, not disassembly)

```yara
import "pe"

rule APT_HazyBeacon_Backdoor_mscorsvc
{
    meta:
        description = "Detects HazyBeacon backdoor DLL (mscorsvc.dll) used by CL-STA-1020 for AWS Lambda-based C2"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30"
        tlp = "WHITE"
        severity = "high"

    strings:
        $lambda1 = "lambda-url" ascii wide
        $lambda2 = ".on.aws" ascii wide
        $lambda3 = "ap-southeast-1" ascii wide
        $svc1 = "msdnetsvc" ascii wide
        $api1 = "HttpSendRequestA" ascii fullword
        $api2 = "HttpSendRequestW" ascii fullword
        $api3 = "InternetOpenA" ascii fullword
        $api4 = "InternetConnectA" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (all of ($lambda*)) or
            ($svc1 and 2 of ($api*)) or
            (2 of ($lambda*) and $svc1)
        )
}

rule APT_HazyBeacon_FileCollector_igfx
{
    meta:
        description = "Detects HazyBeacon file collector tool (igfx.exe) used for targeted document harvesting"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $ext1 = ".doc" ascii wide
        $ext2 = ".docx" ascii wide
        $ext3 = ".xlsx" ascii wide
        $ext4 = ".pdf" ascii wide
        $path1 = "ProgramData" ascii wide
        $arch1 = "7z.exe" ascii wide
        $arch2 = "-v200m" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        3 of ($ext*) and
        $path1 and
        $arch1 and
        $arch2
}

rule APT_HazyBeacon_CloudUploader
{
    meta:
        description = "Detects HazyBeacon cloud exfiltration tools targeting Google Drive and Dropbox"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa"
        tlp = "WHITE"
        severity = "high"

    strings:
        $gdrive1 = "googleapis.com/upload" ascii wide
        $gdrive2 = "drive.google.com" ascii wide
        $gdrive3 = "GoogleDriveUpload" ascii wide
        $drop1 = "content.dropboxapi.com" ascii wide
        $drop2 = "api.dropboxapi.com" ascii wide
        $path1 = "ProgramData" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $path1 and
        (2 of ($gdrive*) or 2 of ($drop*))
}
```

### Suricata: Generic Hunt - Lambda Function URL Network Traffic

Three Suricata rules detecting HTTP POST, DNS, and TLS SNI traffic to ANY AWS Lambda Function URL endpoint. These are generic hunt rules, not HazyBeacon-specific detections -- they will match all Lambda Function URL traffic including legitimate usage.
<!-- audit: Behavioral network detection. Matches any Lambda Function URL traffic, not campaign-specific URLs (which are redacted). HTTP rule gates on POST method + host header matching lambda-url pattern. DNS rule uses dns.query buffer. TLS rule uses tls.sni buffer. All use endswith modifier for .on.aws suffix. Compile: suricata -T pass (exit 0). FP: legitimate Lambda Function URL usage. -->
<!-- revision: v1.1 - Rebranded from "HazyBeacon C2" to "Generic Hunt" to accurately reflect that these rules detect ALL Lambda Function URL traffic, not HazyBeacon-specific indicators. Bumped rev to 2. -->
**Compile**: suricata -T pass | **Confidence**: low (behavioral; matches all Lambda Function URL traffic)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Generic Hunt - HTTP POST to AWS Lambda Function URL"; flow:established,to_server; http.method; content:"POST"; http.host; content:".lambda-url."; content:".on.aws"; endswith; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/; metadata:author Actioner, created_at 2026-06-20; sid:2100201; rev:2;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Generic Hunt - DNS Query to AWS Lambda Function URL Endpoint"; flow:to_server; dns.query; content:".lambda-url."; content:".on.aws"; endswith; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/; metadata:author Actioner, created_at 2026-06-20; sid:2100202; rev:2;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Generic Hunt - TLS SNI to AWS Lambda Function URL"; flow:established,to_server; tls.sni; content:".lambda-url."; content:".on.aws"; endswith; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/; metadata:author Actioner, created_at 2026-06-20; sid:2100203; rev:2;)
```

### Snort: Generic Hunt - Lambda Function URL HTTP Traffic

Detects HTTP POST requests to ANY AWS Lambda Function URL endpoint via Host header inspection. This is a generic hunt rule, not a HazyBeacon-specific detection.
<!-- audit: Behavioral network detection for Snort 3. Uses http service with http_method and http_header sticky buffers. Matches .lambda-url. and .on.aws in headers. Snort 3 lacks tls.sni and dns.query buffers so only HTTP variant provided. Compile: snort -T pass (exit 0). -->
<!-- revision: v1.1 - Changed SID from 2100201 to 2100301 to avoid collision with Suricata SID 2100201. Rebranded from "HazyBeacon C2" to "Generic Hunt". -->
**Compile**: snort -T pass | **Confidence**: low (behavioral; matches all Lambda Function URL HTTP traffic)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Generic Hunt - HTTP POST to AWS Lambda Function URL"; flow:established, to_server; http_method; content:"POST"; http_header; content:".lambda-url.", fast_pattern; content:".on.aws"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/; metadata:author Actioner, created 2026-06-20; sid:2100301; rev:1;)
```

## Lessons Learned

1. **Cloud services as C2 infrastructure**: HazyBeacon demonstrates a maturing trend where adversaries abuse legitimate cloud platform features (serverless functions, storage APIs) rather than building custom C2 infrastructure. Traditional IP/domain reputation approaches fail when C2 traffic routes through AWS, Google, or Microsoft-owned IP space.

2. **Lambda Function URL security gap**: The `AuthType: NONE` option creates publicly accessible HTTPS endpoints within trusted cloud domains. Organizations should enforce SCPs that deny unauthenticated Function URL creation and monitor CloudTrail for this API call across all regions, including those not in active use.

3. **DLL sideloading remains effective**: Despite being a well-documented technique, sideloading through legitimate signed Windows binaries continues to bypass application whitelisting and endpoint detection. Monitoring for DLL loads from non-standard directories remains critical.

4. **Multi-channel exfiltration**: The use of multiple cloud storage services (Google Drive, Dropbox) as exfiltration channels, combined with file splitting and archiving, shows operational sophistication in evading data loss prevention controls.

## Sources

- [Palo Alto Networks Unit 42 - Behind the Clouds: Attackers Targeting Governments in Southeast Asia](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/) -- primary research documenting CL-STA-1020 cluster, HazyBeacon backdoor, IOCs, and attack chain
- [Qualys Blog - HazyBeacon and AWS Lambda Function URL Abuse](https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse) -- detailed analysis of the Lambda Function URL C2 technique, MITRE mapping, and mitigation guidance
- [The Hacker News - State-Backed HazyBeacon Malware Uses AWS Lambda](https://thehackernews.com/2025/07/state-backed-hazybeacon-malware-uses.html) -- early reporting with targeting and attribution context
- [SecurityOnline - HazyBeacon: Novel Backdoor Uses AWS Lambda for Stealthy C2](https://securityonline.info/hazybeacon-novel-backdoor-uses-aws-lambda-for-stealthy-c2-targets-govts/) -- additional technical details on execution chain and targeting
- [GBHackers - HazyBeacon Abuses AWS Lambda Function URLs](https://gbhackers.com/hazybeacon-abuses-aws-lambda-function/) -- campaign overview and infrastructure analysis
- [CyberPress - HazyBeacon Malware Abuses AWS Lambda URLs](https://cyberpress.org/hazybeacon-malware-abuses-aws-lambda/) -- MITRE ATT&CK mapping and credential harvesting details
- [Cryptika - HazyBeacon Weaponizes AWS Lambda Function URLs](https://www.cryptika.com/hazybeacon-weaponizes-aws-lambda-function-urls-for-stealth-command-and-control-relays/) -- mitigation and SCP recommendations

---
*Report generated by Actioner*
